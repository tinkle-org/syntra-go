package network

import (
	"context"
	"errors"
	"net"
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

// Negotiation does not allocate a subscription or access application state.
type negotiationSource struct{ syntra.RecoverySource }

type gatedRecovery struct {
	RecoverySession
	gate   chan struct{}
	closed atomic.Bool
}

func (p *gatedRecovery) Negotiate(ctx context.Context) error {
	select {
	case <-p.gate:
	case <-ctx.Done():
		return ctx.Err()
	}
	return p.RecoverySession.Negotiate(ctx)
}
func (p *gatedRecovery) Close() { p.closed.Store(true); p.RecoverySession.Close() }

func TestRecoveryPreparedBeforeRunAndFreshNegotiationEachGeneration(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	service, err := syntra.NewRecoveryService(negotiationSource{}, syntra.DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	hostcfg := listenerConfig(sc).Host
	hostcfg.Recovery = service
	host, err := syntra.OpenHost(hostcfg)
	if err != nil {
		t.Fatal(err)
	}
	listen, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(testContext(t))
	var workers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			raw, e := listen.Accept()
			if e != nil {
				return
			}
			workers.Add(1)
			go func() { defer workers.Done(); _ = tcp.Accept(ctx, raw, sc, host, ordered.Options{}) }()
		}
	}()
	defer func() { cancel(); _ = listen.Close(); <-acceptDone; workers.Wait(); _ = host.Close() }()
	store, err := syntra.NewMemoryRecoveryStore(syntra.DefaultRecoveryStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewRecoveryFactory("device", store, syntra.DefaultRecoveryLimits(), &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: syntra.RecoveryCapability})
	if err != nil {
		t.Fatal(err)
	}
	prepared := make(chan *gatedRecovery, 4)
	cfg := reconnectConfig()
	cfg.RecoveryFactory = func(core *syntra.Client) (RecoverySession, error) {
		profile, e := factory(core)
		if e != nil {
			return nil, e
		}
		g := &gatedRecovery{RecoverySession: profile, gate: make(chan struct{})}
		prepared <- g
		return g, nil
	}
	var completed atomic.Int32
	cfg.DeferCompletion = func(*ordered.EstablishmentBudget) (func() error, error) {
		return func() error { completed.Add(1); return nil }, nil
	}
	c, err := n.ClientWithSetup(cfg, func(ctx context.Context, b *ordered.EstablishmentBudget, prepare func(*syntra.Client) error) (*connection.Client, error) {
		return tcp.Dial(ctx, listen.Addr().String(), cc, syntra.ClientConfig{Prepare: prepare}, ordered.Options{Budget: b})
	})
	if err != nil {
		t.Fatal(err)
	}
	var previous uint64
	for i := 0; i < 2; i++ {
		var profile *gatedRecovery
		select {
		case profile = <-prepared:
		case <-time.After(time.Second):
			t.Fatal("missing profile preparer")
		}
		core := phase(t, c, CoreReady)
		if core.Generation <= previous {
			t.Fatal("generation reused")
		}
		if completed.Load() != int32(i) {
			t.Fatal("completion released before negotiation")
		}
		if _, err := c.Call(testContext(t), "/test.Service/Echo", nil, 1000); err == nil {
			t.Fatal("call admitted before required negotiation")
		}
		if err := host.NotifyAll([]byte("before negotiation")); err != nil {
			t.Fatal(err)
		}
		until(t, func() bool { return c.Snapshot().QueuedNotifications == 1 })
		close(profile.gate)
		ready := phase(t, c, RecoveryNegotiated)
		if completed.Load() != int32(i+1) {
			t.Fatal("missing completion")
		}
		bound, err := c.RecoveryClient()
		if err != nil || bound.Generation != ready.Generation || bound.Value != profile {
			t.Fatalf("profile=%+v error=%v", bound, err)
		}
		push, err := c.NextNotification(testContext(t))
		if err != nil || string(push.Value.Payload) != "before negotiation" {
			t.Fatalf("push=%+v error=%v", push, err)
		}
		previous = ready.Generation
		if i == 0 {
			c.PlatformWake()
			if c.IsGenerationCurrent(previous) {
				t.Fatal("old profile generation remained current")
			}
			until(t, profile.closed.Load)
		}
	}
	c.Stop()
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("recovery owner did not stop")
	}
}

func TestRecoveryPreparerCannotBeOmittedOrAttachedAfterRun(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	l, err := n.ListenTCP(listenerConfig(sc))
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
	cfg := reconnectConfig()
	cfg.RecoveryFactory = factory
	if _, err := NewClient(cfg, tcpConnector(l.LocalAddr().String(), cc)); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	c, err := n.ClientWithSetup(cfg, func(ctx context.Context, b *ordered.EstablishmentBudget, _ func(*syntra.Client) error) (*connection.Client, error) {
		return tcpConnector(l.LocalAddr().String(), cc)(ctx, b)
	})
	if err != nil {
		t.Fatal(err)
	}
	if s := phase(t, c, Blocked); s.Failure != FailureConfiguration {
		t.Fatalf("missing preparer accepted: %+v", s)
	}
}
