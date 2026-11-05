package connection_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func TestLocalStopCleanAcross100Connections(t *testing.T) {
	cc, server := fixture(t, hostConfig(), connection.ServerOptions{})
	for i := 0; i < 100; i++ {
		a, b := recordPair()
		accepted := make(chan error, 1)
		go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
		c, err := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{Credential: []byte("explicit")}, testOptions())
		if err != nil {
			t.Fatal(err)
		}
		closed := make(chan error, 4)
		for j := 0; j < cap(closed); j++ {
			go func() { closed <- c.Close() }()
		}
		for j := 0; j < cap(closed); j++ {
			if err := join(t, closed); err != nil {
				t.Fatalf("iteration %d: Close = %v", i, err)
			}
		}
		if err := c.Wait(context.Background()); err != nil {
			t.Fatalf("iteration %d: local Wait = %v", i, err)
		}
		if err := c.TerminalError(); err != nil {
			t.Fatalf("iteration %d: local terminal = %v", i, err)
		}
		if err := c.Client.TerminalError(); err != nil {
			t.Fatalf("iteration %d: root recorded a local interruption: %v", i, err)
		}
		join(t, accepted)
	}
}

// The active read starts before local stop and returns its own source outcome
// afterwards, independently of context cancellation and carrier interruption.
type localStopSourceCarrier struct {
	ordered.MessageIO
	reads                   atomic.Int32
	reading, finish, closed chan struct{}
	failure                 error
	once                    sync.Once
}

func (c *localStopSourceCarrier) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	if c.reads.Add(1) < 3 {
		return c.MessageIO.ReadMessage(ctx, dst)
	}
	close(c.reading)
	<-c.finish
	return nil, c.failure
}

func (c *localStopSourceCarrier) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.MessageIO.Close()
}

func TestLocalStopPreservesSourceFailureAcrossCompletion(t *testing.T) {
	for _, stop := range []string{"close", "suspend"} {
		for _, prior := range []bool{false, true} {
			phase := "overlap"
			if prior {
				phase = "prior"
			}
			for _, tc := range []struct {
				name string
				err  error
			}{
				{"authentication", securechannel.ErrAuth},
				{"record", securechannel.ErrRecord},
				{"protocol", ordered.ErrProtocol},
				{"unauthenticated", syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "private source diagnostic")},
				{"auth-and-cancellation", errors.Join(context.Canceled, securechannel.ErrAuth)},
				{"cancellation", context.Canceled},
				{"closed", ordered.ErrClosed},
				{"unavailable", syntra.NewRpcError(syntra.ErrorCodeUnavailable, "private source diagnostic")},
			} {
				t.Run(stop+"/"+phase+"/"+tc.name, func(t *testing.T) {
					cc, server := fixture(t, hostConfig(), connection.ServerOptions{})
					a, b := recordPair()
					carrier := &localStopSourceCarrier{MessageIO: a, reading: make(chan struct{}), finish: make(chan struct{}), closed: make(chan struct{}), failure: tc.err}
					var finish sync.Once
					defer finish.Do(func() { close(carrier.finish) })
					accepted := make(chan error, 1)
					go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
					c, err := connection.Connect(context.Background(), carrier, cc, syntra.ClientConfig{Credential: []byte("explicit")}, testOptions())
					if err != nil {
						t.Fatal(err)
					}
					await(t, carrier.reading)
					var original error
					if prior {
						finish.Do(func() { close(carrier.finish) })
						await(t, carrier.closed)
						original = c.TerminalError()
						if original == nil {
							t.Fatal("source failure was not available before retirement")
						}
					}
					closed := make(chan error, 1)
					if stop == "suspend" {
						c.Suspend()
					}
					go func() { closed <- c.Close() }()
					await(t, carrier.closed)
					finish.Do(func() { close(carrier.finish) })
					if err := join(t, closed); err != nil {
						t.Fatal(err)
					}
					got := c.Wait(context.Background())
					if prior && got != original {
						t.Fatalf("preexisting terminal changed: %v -> %v", original, got)
					}
					switch tc.name {
					case "authentication", "auth-and-cancellation":
						if !errors.Is(got, securechannel.ErrAuth) {
							t.Fatal("authentication failure lost", got)
						}
					case "record", "protocol":
						if !errors.Is(got, tc.err) {
							t.Fatal("typed source failure lost", got)
						}
					case "unauthenticated":
						var rpc *syntra.RpcError
						if !errors.As(got, &rpc) || rpc.Code != syntra.ErrorCodeUnauthenticated || rpc.Message == "private source diagnostic" {
							t.Fatal("source admission failure lost or unsanitized", got)
						}
					default:
						if !prior && got != nil {
							t.Fatal("local interruption became terminal", got)
						}
					}
					if got != c.TerminalError() {
						t.Fatal("Wait and TerminalError disagree")
					}
					join(t, accepted)
				})
			}
		}
	}
}

func TestLocalCloseTimeoutRetainsCarrierJoin(t *testing.T) {
	cc, server := fixture(t, hostConfig(), connection.ServerOptions{})
	a, b := recordPair()
	carrier := &retainedCloseCarrier{MessageIO: a, entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	defer release.Do(func() { close(carrier.release) })
	accepted := make(chan error, 1)
	go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
	c, err := connection.Connect(context.Background(), carrier, cc, syntra.ClientConfig{Credential: []byte("explicit")}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	await(t, carrier.entered)
	select {
	case err := <-closed:
		if err != connection.ErrShutdownTimeout {
			t.Fatal("retained close did not time out", err)
		}
	case <-time.After(connection.ShutdownTimeout + time.Second):
		t.Fatal("Close waited directly on a custom carrier")
	}
	select {
	case <-c.Done():
		t.Fatal("Close timeout discarded carrier ownership")
	default:
	}
	if c.TerminalError() != nil {
		t.Fatal("local timeout recorded a session failure", c.TerminalError())
	}
	release.Do(func() { close(carrier.release) })
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	join(t, accepted)
}
