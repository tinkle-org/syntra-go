package ordered_test

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

type regressionCarrier struct {
	in, out chan []byte
	done    chan struct{}
	once    *sync.Once
	writes  atomic.Int32
}

func regressionPair() (*regressionCarrier, *regressionCarrier) {
	a, b := make(chan []byte, 8), make(chan []byte, 8)
	done, once := make(chan struct{}), new(sync.Once)
	return &regressionCarrier{in: a, out: b, done: done, once: once}, &regressionCarrier{in: b, out: a, done: done, once: once}
}

func (m *regressionCarrier) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, ordered.ErrClosed
	case p := <-m.in:
		if len(p) > cap(dst) {
			return nil, ordered.ErrProtocol
		}
		return append(dst[:0], p...), nil
	}
}

func (m *regressionCarrier) WriteMessage(ctx context.Context, p []byte) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return ordered.ErrClosed
	case m.out <- append([]byte(nil), p...):
		m.writes.Add(1)
		return nil
	}
}

func (m *regressionCarrier) Close() error { m.once.Do(func() { close(m.done) }); return nil }

func regressionConfigs(t *testing.T) (securechannel.ClientConfig, securechannel.ServerConfig) {
	t.Helper()
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	return securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Bootstrap, Scope: "regression", Carrier: securechannel.TCP}, ServerPublicKey: key.Public()},
		securechannel.ServerConfig{StaticKey: key, Scope: "regression", Carrier: securechannel.TCP, AllowBootstrap: true}
}

func regressionJoin(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("connection did not join")
		return nil
	}
}

func TestRejectedInitialAuthorizationHasNoReadinessOrRPCEffects(t *testing.T) {
	cc, sc := regressionConfigs(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	var callbacks, policies, effects atomic.Int32
	sc.Authorize = func(context.Context, securechannel.VerifiedIdentity) error {
		if callbacks.Add(1) == 1 {
			close(entered)
		}
		<-release
		return securechannel.ErrAuth
	}
	host, err := syntra.OpenHost(syntra.HostConfig{
		ChannelPolicy: func(context.Context, syntra.ChannelIdentity, []byte) (string, error) {
			policies.Add(1)
			return "principal", nil
		},
		Authorize: syntra.AllowAllAuthorize,
		Handler: func(context.Context, *syntra.RpcRequest) (*syntra.RpcResult, error) {
			effects.Add(1)
			return syntra.NewSuccessResult(nil), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	a, b := regressionPair()
	defer a.Close()
	accepted, connected := make(chan error, 1), make(chan error, 1)
	go func() { accepted <- connection.Accept(context.Background(), b, sc, host, ordered.Options{}) }()
	go func() {
		client, err := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{}, ordered.Options{})
		if client != nil {
			_, _ = client.Call(context.Background(), "/example.Echo/Echo", nil, 0)
			_ = client.Close()
		}
		connected <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("initial authorization did not run")
	}
	select {
	case err := <-connected:
		t.Fatalf("Connect passed authorization barrier: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	if callbacks.Load() != 1 || policies.Load() != 0 || effects.Load() != 0 || b.writes.Load() != 1 {
		t.Fatalf("effects before authorization: callbacks=%d policy=%d RPC=%d writes=%d", callbacks.Load(), policies.Load(), effects.Load(), b.writes.Load())
	}
	unblock.Do(func() { close(release) })
	if err := regressionJoin(t, accepted); err == nil {
		t.Fatal("rejected connection accepted")
	}
	if err := regressionJoin(t, connected); err == nil {
		t.Fatal("rejected connection reached Ready")
	}
	if policies.Load() != 0 || effects.Load() != 0 || b.writes.Load() != 1 {
		t.Fatal("rejection permitted Ready or RPC effects")
	}
}

func TestRuntimeHandshakePhaseUsesTrustedClockAfterPolicy(t *testing.T) {
	for _, side := range []string{"client", "host"} {
		t.Run(side, func(t *testing.T) {
			cc, sc := regressionConfigs(t)
			var elapsed atomic.Int64
			clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(elapsed.Load()), true }))
			budget, err := ordered.NewEstablishmentBudget(clock, 15*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			hostTimeout, clientTimeout := 5*time.Second, 5*time.Second
			clientOptions, hostOptions := ordered.Options{}, ordered.Options{}
			if side == "host" {
				hostTimeout = 100 * time.Millisecond
				hostOptions.Budget = budget
			} else {
				clientTimeout = 100 * time.Millisecond
				clientOptions.Budget = budget
			}
			host, err := syntra.OpenHost(syntra.HostConfig{HandshakeTimeout: hostTimeout,
				ChannelPolicy: func(context.Context, syntra.ChannelIdentity, []byte) (string, error) {
					elapsed.Store(int64(time.Second))
					return "principal", nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			a, b := regressionPair()
			accepted := make(chan error, 1)
			go func() { accepted <- connection.Accept(context.Background(), b, sc, host, hostOptions) }()
			client, connectErr := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{HandshakeTimeout: clientTimeout}, clientOptions)
			if client != nil {
				_ = client.Close()
				t.Error("trusted-clock phase expiry reached readiness")
			}
			hostErr := regressionJoin(t, accepted)
			localErr := connectErr
			if side == "host" {
				localErr = hostErr
				if b.writes.Load() != 1 {
					t.Fatal("expired ChannelPolicy emitted Ready")
				}
			}
			if !errors.Is(localErr, context.DeadlineExceeded) {
				t.Fatalf("expired %s phase = %v (client %v, host %v)", side, localErr, connectErr, hostErr)
			}
		})
	}
}
