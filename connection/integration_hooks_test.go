package connection_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

type retainedCloseCarrier struct {
	ordered.MessageIO
	entered, release chan struct{}
	once             sync.Once
}

func (c *retainedCloseCarrier) Close() error {
	c.once.Do(func() { _ = c.MessageIO.Close(); close(c.entered) })
	<-c.release
	return nil
}

func TestTerminalCauseSurvivesCloseBeforeJoinedDone(t *testing.T) {
	cc, server := fixture(t, hostConfig(), connection.ServerOptions{})
	a, b := recordPair()
	carrier := &retainedCloseCarrier{MessageIO: a, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(carrier.release) })
	accepted := make(chan error, 1)
	go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
	client, err := connection.Connect(context.Background(), carrier, cc, syntra.ClientConfig{Credential: []byte("explicit")}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	// This is an invalid authenticated-record tag, rather than a carrier error.
	a.in <- make([]byte, 17)
	await(t, carrier.entered)
	if err := client.TerminalError(); !errors.Is(err, securechannel.ErrRecord) {
		t.Fatal("kernel failure flattened during close", err)
	}
	closed := make(chan error, 1)
	go func() { closed <- client.Close() }()
	select {
	case <-client.Done():
		t.Fatal("Done preceded retained carrier cleanup")
	default:
	}
	release.Do(func() { close(carrier.release) })
	if err := join(t, closed); err != nil {
		t.Fatal(err)
	}
	if err := client.Wait(context.Background()); !errors.Is(err, securechannel.ErrRecord) {
		t.Fatal("local close masked terminal cause", err)
	}
	join(t, accepted)
}

func TestSuspendIsPromptWithRetainedCarrierCleanup(t *testing.T) {
	cc, server := fixture(t, hostConfig(), connection.ServerOptions{})
	a, b := recordPair()
	carrier := &retainedCloseCarrier{MessageIO: a, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(carrier.release) })
	opts, _ := clockOptions(t)
	accepted := make(chan error, 1)
	go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
	client, err := connection.Connect(context.Background(), carrier, cc, syntra.ClientConfig{Credential: []byte("explicit")}, opts)
	if err != nil {
		t.Fatal(err)
	}
	returned := make(chan struct{})
	go func() { client.Suspend(); close(returned) }()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Suspend waited for carrier shutdown")
	}
	if !client.IsClosed() || opts.Budget.Check() != context.DeadlineExceeded {
		t.Fatal("Suspend did not fence admission and clock continuity")
	}
	await(t, carrier.entered)
	select {
	case <-client.Done():
		t.Fatal("Suspend relinquished retained cleanup")
	default:
	}
	release.Do(func() { close(carrier.release) })
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	join(t, accepted)
}

func TestDeferredRecoveryCompletionKeepsConnectionBudget(t *testing.T) {
	for _, complete := range []bool{false, true} {
		t.Run(map[bool]string{false: "timeout", true: "complete"}[complete], func(t *testing.T) {
			cc, server := fixture(t, hostConfig(), connection.ServerOptions{})
			opts, age := clockOptions(t)
			finish, err := opts.Budget.DeferCompletion()
			if err != nil {
				t.Fatal(err)
			}
			a, b := recordPair()
			accepted := make(chan error, 1)
			go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
			client, err := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{Credential: []byte("explicit")}, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if complete {
				if err := finish(); err != nil {
					t.Fatal(err)
				}
				age.Store(int64(2 * time.Second))
				echo(t, client)
				_ = client.Close()
			} else {
				age.Store(int64(2 * time.Second))
				await(t, client.Done())
				if finish() != context.DeadlineExceeded || client.TerminalError() != context.DeadlineExceeded {
					t.Fatal("deferred recovery timeout was retired at Ready")
				}
			}
			join(t, accepted)
		})
	}
}
