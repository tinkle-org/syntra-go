package network

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

func managedHTTP(t *testing.T, n *Network, secure bool, handler syntra.HandlerFunc) (*HTTPListener, Connector) {
	t.Helper()
	carrier := securechannel.HTTP
	if secure {
		carrier = securechannel.HTTPS
	}
	cc, sc := trust(t, carrier)
	cc.AllowHTTPCandidate = true
	sc.AllowHTTPCandidate = true
	authority, err := syntrahttp.NewAuthority("localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	cfg := syntrahttp.ServerConfig{Address: "127.0.0.1:0", Authority: authority, Security: sc, Host: listenerConfig(sc).Host}
	if handler != nil {
		cfg.Host.Handler = handler
	}
	var provider tlsstream.Provider
	var l *HTTPListener
	if secure {
		provider = tlsProvider(t)
		cfg.TLS = provider
		l, err = n.ListenHTTPS(cfg)
	} else {
		l, err = n.ListenHTTP(cfg)
	}
	if err != nil {
		t.Fatal(err)
	}
	connector := func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
		return syntrahttp.Dial(ctx, netip.MustParseAddrPort(l.LocalAddr().String()), authority, provider, cc, syntra.ClientConfig{}, ordered.Options{Budget: b})
	}
	return l, connector
}

func TestManagedHTTPAndHTTPSIdlePushLossPauseResume(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[secure], func(t *testing.T) {
			n := testNetwork(t, DefaultConfig())
			l, connector := managedHTTP(t, n, secure, nil)
			var elapsed atomic.Int64
			cfg := reconnectConfig()
			cfg.NotificationCapacity = 1
			cfg.NotificationBytes = 64
			cfg.ClockFactory = func() *securechannel.Clock {
				return securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(elapsed.Load()), true }))
			}
			c, err := n.Client(cfg, connector)
			if err != nil {
				t.Fatal(err)
			}
			first := phase(t, c, CoreReady).Generation
			// No RPC drives the download lane, even after the setup cutoff retires.
			elapsed.Store(int64(2 * time.Second))
			if err := l.NotifyAll([]byte("idle push")); err != nil {
				t.Fatal(err)
			}
			push, err := c.NextNotification(testContext(t))
			if err != nil || push.Generation != first || string(push.Value.Payload) != "idle push" {
				t.Fatalf("push=%+v error=%v status=%+v", push, err, c.Snapshot())
			}
			for i := 0; i < 8; i++ {
				if err := l.NotifyAll([]byte("overflow")); err != nil {
					t.Fatal(err)
				}
			}
			until(t, func() bool { return c.Snapshot().DroppedCount >= 7 })
			if c.Snapshot().QueuedNotifications != 1 || c.Snapshot().DroppedBytes < 56 {
				t.Fatalf("loss status %+v", c.Snapshot())
			}
			if _, err := c.NextNotification(testContext(t)); err != nil {
				t.Fatal(err)
			}
			n.Pause()
			if c.IsGenerationCurrent(first) {
				t.Fatal("parent pause did not fence HTTP generation")
			}
			if err := l.NotifyAll(nil); !errors.Is(err, ErrClosed) {
				t.Fatal("paused listener emitted a notification")
			}
			until(t, func() bool { s := l.Snapshot().Server; return s.Paused && s.Associations == 0 && s.Sockets == 0 })
			n.Resume()
			second := phase(t, c, CoreReady).Generation
			if second <= first {
				t.Fatal("HTTP generation was reused")
			}
			if c.Snapshot().DroppedCount != 0 {
				t.Fatal("loss counters migrated to replacement generation")
			}
			if err := l.NotifyAll([]byte("fresh")); err != nil {
				t.Fatal(err)
			}
			push, err = c.NextNotification(testContext(t))
			if err != nil || push.Generation != second || string(push.Value.Payload) != "fresh" {
				t.Fatalf("replacement push=%+v error=%v", push, err)
			}
			n.NetworkAvailable(false)
			phase(t, c, Offline)
			until(t, func() bool { return l.Snapshot().Server.Paused })
			n.NetworkAvailable(true)
			if phase(t, c, CoreReady).Generation <= second {
				t.Fatal("offline transition reused generation")
			}
		})
	}
}

func TestManagedHTTPMutationNeverReplayed(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[secure], func(t *testing.T) {
			n := testNetwork(t, DefaultConfig())
			entered := make(chan struct{}, 1)
			var effects atomic.Int32
			_, connector := managedHTTP(t, n, secure, func(ctx context.Context, _ *syntra.RpcRequest) (*syntra.RpcResult, error) {
				effects.Add(1)
				entered <- struct{}{}
				<-ctx.Done()
				return nil, ctx.Err()
			})
			c, err := n.Client(reconnectConfig(), connector)
			if err != nil {
				t.Fatal(err)
			}
			first := phase(t, c, CoreReady).Generation
			result := make(chan error, 1)
			go func() {
				_, err := c.Call(context.Background(), "/test.Service/Mutation", []byte("once"), 2000)
				result <- err
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("HTTP handler not invoked")
			}
			n.PlatformWake()
			var call *CallError
			if err := <-result; !errors.As(err, &call) || call.Generation != first || !call.OutcomeUnknown {
				t.Fatalf("unfenced HTTP result: %v", err)
			}
			if phase(t, c, CoreReady).Generation <= first {
				t.Fatal("missing HTTP successor")
			}
			if effects.Load() != 1 {
				t.Fatal("HTTP mutation replayed")
			}
		})
	}
}

func TestManagedHTTPIncompleteShutdownRetainsCallbackAndNativeOwner(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CloseTimeout = 20 * time.Millisecond
	cfg.MaxConnections = 1
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }); n.Shutdown(testContext(t)) })
	l, connector := managedHTTP(t, n, true, func(context.Context, *syntra.RpcRequest) (*syntra.RpcResult, error) {
		close(entered)
		<-release
		return syntra.NewSuccessResult(nil), nil
	})
	c, err := n.Client(reconnectConfig(), connector)
	if err != nil {
		t.Fatal(err)
	}
	phase(t, c, CoreReady)
	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		_, _ = c.Call(context.Background(), "/test.Service/Mutation", nil, 1000)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("HTTPS handler not invoked")
	}
	report := n.Shutdown(context.Background())
	if report.Complete || report.LiveCallbacks != 1 || report.PendingOperations == 0 {
		t.Fatalf("HTTP callback owner lost: %+v", report)
	}
	select {
	case <-l.Done():
		t.Fatal("HTTP listener completed before callback returned")
	default:
	}
	releaseOnce.Do(func() { close(release) })
	<-callDone
	select {
	case <-n.Done():
	case <-time.After(3 * time.Second):
		t.Fatalf("HTTP shutdown did not complete: %+v", n.Snapshot())
	}
	s := l.Snapshot().Server
	if s.Associations != 0 || s.Sockets != 0 || s.ReservedBytes != 0 || !s.Stopped {
		t.Fatalf("HTTP reservations survived shutdown: %+v", s)
	}
}

func TestManagedHTTPSRetainsRecoverySourceAfterNativeRunReturns(t *testing.T) {
	cfg := DefaultConfig()
	cfg.CloseTimeout = 20 * time.Millisecond
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	source := &blockingRecoverySource{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(source.release) }); n.Shutdown(testContext(t)) })
	service, err := syntra.NewRecoveryService(source, syntra.DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	cc, sc := trust(t, securechannel.HTTPS)
	cc.AllowHTTPCandidate = true
	sc.AllowHTTPCandidate = true
	authority, err := syntrahttp.NewAuthority("localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	provider := tlsProvider(t)
	hostcfg := listenerConfig(sc).Host
	hostcfg.Recovery = service
	var associationReleases atomic.Int32
	l, err := n.ListenHTTPS(syntrahttp.ServerConfig{Address: "127.0.0.1:0", Authority: authority, Security: sc, TLS: provider, Host: hostcfg, AdmitAssociation: func(context.Context, *ordered.EstablishmentBudget) (func(), error) {
		return func() { associationReleases.Add(1) }, nil
	}})
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
	reconnect := reconnectConfig()
	reconnect.RecoveryFactory = factory
	c, err := n.ClientWithSetup(reconnect, func(ctx context.Context, b *ordered.EstablishmentBudget, prepare func(*syntra.Client) error) (*connection.Client, error) {
		return syntrahttp.Dial(ctx, netip.MustParseAddrPort(l.LocalAddr().String()), authority, provider, cc, syntra.ClientConfig{Prepare: prepare}, ordered.Options{Budget: b})
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
		t.Fatal("HTTPS source did not enter")
	}
	report := n.Shutdown(context.Background())
	if report.Complete || report.LiveExecutions == 0 {
		t.Fatalf("lost HTTPS source ownership: %+v", report)
	}
	time.Sleep(300 * time.Millisecond)
	if associationReleases.Load() != 0 {
		t.Fatal("application association release ran before recovery source cleanup")
	}
	select {
	case <-l.Done():
		t.Fatal("HTTP listener released a retained recovery Host")
	default:
	}
	release.Do(func() { close(source.release) })
	select {
	case <-n.Done():
	case <-time.After(3 * time.Second):
		t.Fatalf("HTTPS source did not join: %+v", n.Snapshot())
	}
	if associationReleases.Load() != 1 {
		t.Fatal("application association release did not run exactly once after source cleanup")
	}
}
