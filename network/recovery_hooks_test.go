package network

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
)

func managedRecovery(t *testing.T, n *Network, source syntra.RecoverySource) (*Listener, securechannel.ClientConfig, RecoveryFactory) {
	t.Helper()
	cc, sc := trust(t, securechannel.TCP)
	service, err := syntra.NewRecoveryService(source, syntra.DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	server := listenerConfig(sc)
	server.Host.Recovery = service
	l, err := n.ListenTCP(server)
	if err != nil {
		t.Fatal(err)
	}
	store, err := syntra.NewMemoryRecoveryStore(syntra.DefaultRecoveryStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewRecoveryFactory("device", store, syntra.DefaultRecoveryLimits(), &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: syntra.RecoveryCapability})
	if err != nil {
		t.Fatal(err)
	}
	return l, cc, factory
}

func TestDefaultRecoveryCompletionRetainsThenReleasesRealBudget(t *testing.T) {
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "released-after-negotiation", true: "expired-before-negotiation"}[expire], func(t *testing.T) {
			n := testNetwork(t, DefaultConfig())
			l, security, factory := managedRecovery(t, n, negotiationSource{})
			var elapsed atomic.Int64
			prepared := make(chan *gatedRecovery, 1)
			budgets := make(chan *ordered.EstablishmentBudget, 1)
			cfg := reconnectConfig()
			cfg.MaxAttempts = 1
			cfg.ClockFactory = func() *securechannel.Clock {
				return securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(elapsed.Load()), true }))
			}
			cfg.RecoveryFactory = func(core *syntra.Client) (RecoverySession, error) {
				r, e := factory(core)
				if e != nil {
					return nil, e
				}
				g := &gatedRecovery{RecoverySession: r, gate: make(chan struct{})}
				prepared <- g
				return g, nil
			}
			c, err := n.ClientWithSetup(cfg, func(ctx context.Context, b *ordered.EstablishmentBudget, prepare func(*syntra.Client) error) (*connection.Client, error) {
				budgets <- b
				return tcp.Dial(ctx, l.LocalAddr().String(), security, syntra.ClientConfig{Prepare: prepare}, ordered.Options{Budget: b})
			})
			if err != nil {
				t.Fatal(err)
			}
			profile := <-prepared
			b := <-budgets
			phase(t, c, CoreReady)
			if expire {
				elapsed.Store(int64(2 * time.Second))
				if err := b.Check(); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("core readiness released a required recovery gate: %v", err)
				}
				phase(t, c, Exhausted)
				if _, err := c.RecoveryClient(); err == nil {
					t.Fatal("expired profile exposed")
				}
			} else {
				close(profile.gate)
				phase(t, c, RecoveryNegotiated)
				elapsed.Store(int64(2 * time.Second))
				if err := b.Check(); err != nil {
					t.Fatalf("negotiated budget not released: %v", err)
				}
				value, err := c.Call(testContext(t), "/test.Service/Echo", []byte("after original cutoff"), 1000)
				if err != nil || string(value.Value) != "after original cutoff" {
					t.Fatalf("result=%+v err=%v status=%+v", value, err, c.Snapshot())
				}
			}
		})
	}
}

type blockingRecoverySource struct {
	syntra.RecoverySource
	entered, release chan struct{}
	once             sync.Once
}

func (s *blockingRecoverySource) Authorize(_ context.Context, _ string, _ []byte, hook syntra.RecoveryHook) error {
	if hook == syntra.RecoveryHookEmit {
		s.once.Do(func() { close(s.entered) })
		<-s.release
	}
	return nil
}
func (*blockingRecoverySource) Capture(context.Context, string, []byte) (syntra.RecoveryProviderStream, error) {
	return syntra.RecoveryProviderStream{Identity: []byte("stream"), Generation: 1, Boundary: []byte("a")}, nil
}
func (*blockingRecoverySource) CurrentGeneration(context.Context, string, []byte) (uint64, error) {
	return 1, nil
}
func (*blockingRecoverySource) ValidateIssued(context.Context, string, syntra.RecoveryProviderStream, []byte) error {
	return nil
}

func TestManagedRecoverySourceRetainedBeyondServe(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CloseTimeout = 20 * time.Millisecond
	cfg.MaxConnections = 1
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	source := &blockingRecoverySource{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(source.release) }); n.Shutdown(testContext(t)) })
	l, security, factory := managedRecovery(t, n, source)
	reconnect := reconnectConfig()
	reconnect.RecoveryFactory = factory
	c, err := n.ClientWithSetup(reconnect, func(ctx context.Context, b *ordered.EstablishmentBudget, prepare func(*syntra.Client) error) (*connection.Client, error) {
		return tcp.Dial(ctx, l.LocalAddr().String(), security, syntra.ClientConfig{Prepare: prepare}, ordered.Options{Budget: b})
	})
	if err != nil {
		t.Fatal(err)
	}
	phase(t, c, RecoveryNegotiated)
	bound, err := c.RecoveryClient()
	if err != nil {
		t.Fatal(err)
	}
	profile := bound.Value.(*RecoveryProfile).RecoveryClient
	sub, err := profile.Subscribe(testContext(t), &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("selector")}, []byte("stable"), syntra.RecoveryInitialLiveOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = profile.CatchUp(testContext(t), &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: sub.Response.SubscriptionHandle}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("source did not enter idle recovery egress")
	}
	report := n.Shutdown(context.Background())
	if report.Complete || report.LiveConnections != 1 || report.LiveExecutions == 0 {
		t.Fatalf("lost source execution ownership: %+v", report)
	}
	// Serve's bounded drain may finish, but Host.Wait must retain the admission.
	time.Sleep(300 * time.Millisecond)
	select {
	case <-l.Done():
		t.Fatal("listener dropped retained source")
	default:
	}
	if n.admission.Available() != 0 {
		t.Fatal("source released shared admission early")
	}
	release.Do(func() { close(source.release) })
	select {
	case <-n.Done():
	case <-time.After(3 * time.Second):
		t.Fatalf("source completion not joined: %+v", n.Snapshot())
	}
	if n.admission.Available() != 1 {
		t.Fatal("admission not released after Host.Wait")
	}
}
