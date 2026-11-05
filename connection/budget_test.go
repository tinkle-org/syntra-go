package connection_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func clockOptions(t *testing.T) (ordered.Options, *atomic.Int64) {
	t.Helper()
	age := new(atomic.Int64)
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) {
		return time.Duration(age.Load()), true
	}))
	budget, err := ordered.NewEstablishmentBudget(clock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return ordered.Options{Budget: budget}, age
}

func TestProvidedBudgetIncludesCarrierSetup(t *testing.T) {
	cc, sc, err := channelConfigs(securechannel.Returning)
	if err != nil {
		t.Fatal(err)
	}
	host, err := syntra.OpenHost(hostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	for _, side := range []string{"client", "host"} {
		t.Run(side, func(t *testing.T) {
			opts, age := clockOptions(t)
			setupCtx, stop := opts.Budget.Context(context.Background())
			defer stop()
			// Carrier setup used the entire absolute attempt. Passing a fresh
			// context into the SDK must not renew it.
			a, b := recordPair()
			defer a.Close()
			defer b.Close()
			age.Store(int64(time.Second))
			await(t, setupCtx.Done())
			if side == "client" {
				client, err := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{}, opts)
				if client != nil || !errors.Is(err, context.DeadlineExceeded) || a.closes.Load() != 1 {
					t.Fatalf("expired Connect = %v, %v; closes = %d", client, err, a.closes.Load())
				}
			} else {
				err := connection.Accept(context.Background(), b, sc, host, opts)
				if !errors.Is(err, context.DeadlineExceeded) || b.closes.Load() != 1 {
					t.Fatalf("expired Accept = %v; closes = %d", err, b.closes.Load())
				}
			}
		})
	}
}

func TestOriginalBudgetBoundsReadinessPolicy(t *testing.T) {
	for _, side := range []string{"client", "host"} {
		t.Run(side, func(t *testing.T) {
			opts, age := clockOptions(t)
			// Account for work before the carrier becomes available.
			age.Store(int64(750 * time.Millisecond))
			entered, exited := make(chan struct{}), make(chan struct{})
			cfg := hostConfig()
			cfg.ChannelPolicy = func(ctx context.Context, _ syntra.ChannelIdentity, _ []byte) (string, error) {
				close(entered)
				defer close(exited)
				<-ctx.Done()
				return "", ctx.Err()
			}
			cc, server := fixture(t, cfg, connection.ServerOptions{})
			a, b := recordPair()
			clientOpts, hostOpts := testOptions(), testOptions()
			if side == "client" {
				clientOpts = opts
			} else {
				hostOpts = opts
			}
			accepted, connected := make(chan error, 1), make(chan error, 1)
			go func() { accepted <- server.Accept(context.Background(), b, hostOpts) }()
			go func() {
				client, err := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{Credential: []byte("explicit")}, clientOpts)
				if client != nil {
					_ = client.Close()
					connected <- errors.New("readiness unexpectedly succeeded")
					return
				}
				connected <- err
			}()
			await(t, entered)
			age.Store(int64(time.Second + time.Nanosecond))
			clientErr := join(t, connected)
			hostErr := join(t, accepted)
			if clientErr == nil || hostErr == nil {
				t.Fatalf("readiness errors = %v, %v", clientErr, hostErr)
			}
			localErr := clientErr
			if side == "host" {
				localErr = hostErr
			}
			if !errors.Is(localErr, context.DeadlineExceeded) {
				t.Fatalf("local attempt error = %v", localErr)
			}
			await(t, exited)
			if a.closes.Load() != 1 || b.closes.Load() != 1 {
				t.Fatalf("close counts = %d, %d", a.closes.Load(), b.closes.Load())
			}
		})
	}
}

func TestReadinessRetiresAttemptWithoutEndingSession(t *testing.T) {
	cc, server := fixture(t, hostConfig(), connection.ServerOptions{})
	clientOpts, clientAge := clockOptions(t)
	hostOpts, hostAge := clockOptions(t)
	a, b := recordPair()
	accepted := make(chan error, 1)
	go func() { accepted <- server.Accept(context.Background(), b, hostOpts) }()
	client, err := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{Credential: []byte("explicit")}, clientOpts)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	// Client readiness can precede the server's Ready write completion and
	// budget release. A round trip proves both peers have retired setup before
	// advancing either clock past its cutoff.
	echo(t, client)
	clientAge.Store(int64(2 * time.Second))
	hostAge.Store(int64(2 * time.Second))
	// Exercise the transport's synchronous time check after the original
	// attempt deadline, then allow its asynchronous deadline watcher to run.
	echo(t, client)
	time.Sleep(30 * time.Millisecond)
	echo(t, client)
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	join(t, accepted)
	await(t, client.Done())
}

func TestCancelConnectDuringReadiness(t *testing.T) {
	entered, exited := make(chan struct{}), make(chan struct{})
	cfg := hostConfig()
	cfg.ChannelPolicy = func(ctx context.Context, _ syntra.ChannelIdentity, _ []byte) (string, error) {
		close(entered)
		defer close(exited)
		<-ctx.Done()
		return "", ctx.Err()
	}
	cc, server := fixture(t, cfg, connection.ServerOptions{})
	a, b := recordPair()
	accepted, connected := make(chan error, 1), make(chan error, 1)
	go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		client, err := connection.Connect(ctx, a, cc, syntra.ClientConfig{Credential: []byte("explicit")}, testOptions())
		if client != nil {
			_ = client.Close()
		}
		connected <- err
	}()
	await(t, entered)
	cancel()
	if err := join(t, connected); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled readiness = %v", err)
	}
	if a.closes.Load() != 1 {
		t.Fatal("Connect returned before closing its carrier")
	}
	// Server.Close cancels an application policy independently of peer I/O.
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	join(t, accepted)
	await(t, exited)
}
