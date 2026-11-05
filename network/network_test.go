package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
)

func reconnectConfig() ReconnectConfig {
	return ReconnectConfig{AttemptTimeout: time.Second, ReconnectBudget: 3 * time.Second, MaxAttempts: 4, BaseBackoff: time.Millisecond, MaxBackoff: 20 * time.Millisecond, CloseTimeout: 200 * time.Millisecond, InitialNetworkAvailable: true}
}
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
func until(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	for !predicate() {
		select {
		case <-deadline.C:
			t.Fatal("condition did not settle")
		case <-time.After(time.Millisecond):
		}
	}
}
func phase(t *testing.T, c *Client, want Phase) Status {
	t.Helper()
	ctx := testContext(t)
	for {
		s := c.Snapshot()
		if s.Phase == want {
			return s
		}
		if _, err := c.WaitChange(ctx, s.Revision); err != nil {
			t.Fatalf("waiting for phase %d: status=%+v error=%v", want, c.Snapshot(), err)
		}
	}
}
func testNetwork(t *testing.T, cfg Config) *Network {
	t.Helper()
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if report := n.Shutdown(testContext(t)); !report.Complete {
			t.Errorf("incomplete cleanup: %+v", report)
		}
	})
	return n
}
func trust(t *testing.T, carrier securechannel.Carrier) (securechannel.ClientConfig, securechannel.ServerConfig) {
	t.Helper()
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	return securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Bootstrap, Carrier: carrier, Scope: "managed"}, ServerPublicKey: key.Public()},
		securechannel.ServerConfig{StaticKey: key, Carrier: carrier, Scope: "managed", AllowBootstrap: true}
}
func listenerConfig(sc securechannel.ServerConfig) ListenerConfig {
	return ListenerConfig{Address: "127.0.0.1:0", MaxConnections: 4, Security: sc, Host: syntra.HostConfig{
		ChannelPolicy: func(context.Context, syntra.ChannelIdentity, []byte) (string, error) { return "device", nil }, Authorize: syntra.AllowAllAuthorize,
		Handler: func(_ context.Context, r *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return syntra.NewSuccessResult(r.GetPayload()), nil
		},
	}}
}
func tcpConnector(address string, security securechannel.ClientConfig) Connector {
	return func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
		return tcp.Dial(ctx, address, security, syntra.ClientConfig{}, ordered.Options{Budget: b})
	}
}

func TestManagedTCPPushCallsAndGenerationFences(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	l, err := n.ListenTCP(listenerConfig(sc))
	if err != nil {
		t.Fatal(err)
	}
	c, err := n.Client(reconnectConfig(), tcpConnector(l.LocalAddr().String(), cc))
	if err != nil {
		t.Fatal(err)
	}
	first := phase(t, c, CoreReady).Generation
	if err := l.NotifyAll([]byte("unsolicited")); err != nil {
		t.Fatal(err)
	}
	push, err := c.NextNotification(testContext(t))
	if err != nil || push.Generation != first || string(push.Value.Payload) != "unsolicited" {
		t.Fatalf("push=%+v error=%v", push, err)
	}
	response, err := c.Call(testContext(t), "/test.Service/Echo", []byte("echo"), 1000)
	if err != nil || string(response.Value) != "echo" || response.Generation != first {
		t.Fatalf("response=%+v error=%v", response, err)
	}
	c.mu.Lock()
	retiredClock := c.active.clock
	c.mu.Unlock()
	n.Pause()
	if c.IsGenerationCurrent(first) {
		t.Fatal("pause did not fence synchronously")
	}
	if retiredClock.Check() != securechannel.ErrLimit {
		t.Fatal("pause did not retire the actual record clock")
	}
	c.Retry()
	if _, err := c.Call(testContext(t), "/test.Service/Echo", nil, 1000); err == nil {
		t.Fatal("paused call admitted")
	}
	n.Resume()
	second := phase(t, c, CoreReady).Generation
	if second <= first {
		t.Fatal("generation was reused")
	}
	n.NetworkAvailable(false)
	if c.IsGenerationCurrent(second) {
		t.Fatal("offline update did not fence synchronously")
	}
	phase(t, c, Offline)
	n.NetworkAvailable(true)
	third := phase(t, c, CoreReady).Generation
	if third <= second {
		t.Fatal("generation did not advance")
	}
	n.PlatformWake()
	if c.IsGenerationCurrent(third) {
		t.Fatal("wake did not fence synchronously")
	}
	phase(t, c, CoreReady)
}

func TestNotificationQueueLossVisibleAndBounded(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	l, err := n.ListenTCP(listenerConfig(sc))
	if err != nil {
		t.Fatal(err)
	}
	cfg := reconnectConfig()
	cfg.NotificationCapacity = 1
	cfg.NotificationBytes = 4
	c, err := n.Client(cfg, tcpConnector(l.LocalAddr().String(), cc))
	if err != nil {
		t.Fatal(err)
	}
	phase(t, c, CoreReady)
	for i := 0; i < 12; i++ {
		if err := l.NotifyAll([]byte("push")); err != nil {
			t.Fatal(err)
		}
	}
	until(t, func() bool { return c.Snapshot().DroppedCount >= 11 })
	s := c.Snapshot()
	if s.QueuedNotifications != 1 || s.DroppedBytes < 44 {
		t.Fatalf("loss status %+v", s)
	}
	note, err := c.NextNotification(testContext(t))
	if err != nil || string(note.Value.Payload) != "push" || note.Value.DroppedCount < 11 {
		t.Fatalf("notification=%+v error=%v", note, err)
	}
}

func TestNotificationWaitCannotMoveIntoSuccessorGeneration(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	l, err := n.ListenTCP(listenerConfig(sc))
	if err != nil {
		t.Fatal(err)
	}
	c, err := n.Client(reconnectConfig(), tcpConnector(l.LocalAddr().String(), cc))
	if err != nil {
		t.Fatal(err)
	}
	first := phase(t, c, CoreReady).Generation
	result := make(chan error, 1)
	go func() { _, err := c.NextNotification(context.Background()); result <- err }()
	until(t, func() bool { c.mu.Lock(); defer c.mu.Unlock(); return c.calls == 1 })
	c.PlatformWake()
	second := phase(t, c, CoreReady).Generation
	if second <= first {
		t.Fatal("missing successor")
	}
	if err := l.NotifyAll([]byte("new generation")); err != nil {
		t.Fatal(err)
	}
	var call *CallError
	if err := <-result; !errors.As(err, &call) || call.Generation != first {
		t.Fatalf("notification wait crossed generation: %v", err)
	}
	push, err := c.NextNotification(testContext(t))
	if err != nil || push.Generation != second || string(push.Value.Payload) != "new generation" {
		t.Fatalf("successor push=%+v error=%v", push, err)
	}
}

func TestFailedInflightCallIsUnknownAndNeverReplayed(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	entered := make(chan struct{}, 2)
	var effects atomic.Int32
	cfg := listenerConfig(sc)
	cfg.Host.Handler = func(ctx context.Context, r *syntra.RpcRequest) (*syntra.RpcResult, error) {
		effects.Add(1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	l, err := n.ListenTCP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	c, err := n.Client(reconnectConfig(), tcpConnector(l.LocalAddr().String(), cc))
	if err != nil {
		t.Fatal(err)
	}
	first := phase(t, c, CoreReady).Generation
	result := make(chan error, 1)
	go func() {
		_, err := c.Call(testContext(t), "/test.Service/Mutation", []byte("once"), 3000)
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("handler did not enter")
	}
	c.PlatformWake()
	err = <-result
	var call *CallError
	if !errors.As(err, &call) || call.Generation != first || !call.OutcomeUnknown {
		t.Fatalf("wrong call failure %v %+v", err, call)
	}
	if phase(t, c, CoreReady).Generation <= first {
		t.Fatal("no successor")
	}
	if effects.Load() != 1 {
		t.Fatalf("request replayed: %d", effects.Load())
	}
}

func TestExplicitFiniteAttemptsAndBlockedRetry(t *testing.T) {
	for _, failure := range []error{ordered.ErrIO, securechannel.ErrAuth, ordered.ErrProtocol, ErrConfig} {
		t.Run(fmt.Sprint(Classify(failure)), func(t *testing.T) {
			var calls atomic.Int32
			cfg := reconnectConfig()
			cfg.MaxAttempts = 2
			c, err := NewClient(cfg, func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error) {
				calls.Add(1)
				return nil, failure
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			want := Blocked
			count := int32(1)
			if Classify(failure).Retryable() {
				want = Exhausted
				count = 2
			}
			phase(t, c, want)
			c.Pause()
			c.Resume()
			c.NetworkAvailable(true)
			phase(t, c, want)
			if calls.Load() != count {
				t.Fatal("controls cleared terminal policy")
			}
			c.Retry()
			until(t, func() bool { return calls.Load() > count })
			phase(t, c, want)
		})
	}
}

func TestElapsedOutageIncludesInitialPauseOfflineAndBackoff(t *testing.T) {
	for _, paused := range []bool{true, false} {
		var elapsed atomic.Int64
		var calls atomic.Int32
		cfg := reconnectConfig()
		cfg.StartPaused = paused
		cfg.InitialNetworkAvailable = false
		cfg.ReconnectBudget = time.Second
		cfg.ClockFactory = func() *securechannel.Clock {
			return securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(elapsed.Load()), true }))
		}
		c, err := NewClient(cfg, func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error) {
			calls.Add(1)
			return nil, ordered.ErrIO
		})
		if err != nil {
			t.Fatal(err)
		}
		elapsed.Store(int64(2 * time.Second))
		phase(t, c, Exhausted)
		c.Resume()
		phase(t, c, Exhausted)
		if calls.Load() != 0 {
			t.Fatal("outage budget excluded initial pause/offline")
		}
		c.Retry()
		until(t, func() bool { return calls.Load() == 1 })
		c.Close()
	}
}

func TestAttemptTimeoutAndNoParallelStaleConnector(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	cfg := reconnectConfig()
	cfg.AttemptTimeout = 20 * time.Millisecond
	cfg.CloseTimeout = 20 * time.Millisecond
	c, err := NewClient(cfg, func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error) {
		calls.Add(1)
		close(entered)
		<-release
		return nil, ordered.ErrIO
	})
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	phase(t, c, ShutdownIncomplete)
	c.Retry()
	c.Resume()
	if calls.Load() != 1 {
		t.Fatal("replacement ran while stale connector was live")
	}
	if err := c.CloseContext(testContext(t)); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatal(err)
	}
	select {
	case <-c.Done():
		t.Fatal("ownership lost before blocked connector returned")
	default:
	}
	close(release)
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("owner did not finish")
	}
}

func TestStaleSuccessfulDialNeverActivated(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	l, err := n.ListenTCP(listenerConfig(sc))
	if err != nil {
		t.Fatal(err)
	}
	connected := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	c, err := n.Client(reconnectConfig(), func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
		calls.Add(1)
		raw, e := tcpConnector(l.LocalAddr().String(), cc)(ctx, b)
		if e != nil {
			return raw, e
		}
		close(connected)
		<-release
		return raw, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	<-connected
	c.Pause()
	close(release)
	phase(t, c, Paused)
	if c.Snapshot().Generation != 0 || calls.Load() != 1 {
		t.Fatal("stale dial became active")
	}
	if _, err := c.Call(testContext(t), "/test.Service/Echo", nil, 1000); err == nil {
		t.Fatal("stale dial admitted call")
	}
}

func TestManagedAdmissionAndNoncooperativeCallbacksRetainOwnership(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConnections = 1
	cfg.CloseTimeout = 20 * time.Millisecond
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cc, sc := trust(t, securechannel.TCP)
	server := listenerConfig(sc)
	entered := make(chan struct{})
	release := make(chan struct{})
	server.Host.Handler = func(context.Context, *syntra.RpcRequest) (*syntra.RpcResult, error) {
		close(entered)
		<-release
		return syntra.NewSuccessResult(nil), nil
	}
	l, err := n.ListenTCP(server)
	if err != nil {
		t.Fatal(err)
	}
	c, err := n.Client(reconnectConfig(), tcpConnector(l.LocalAddr().String(), cc))
	if err != nil {
		t.Fatal(err)
	}
	phase(t, c, CoreReady)
	callDone := make(chan struct{})
	go func() {
		defer close(callDone)
		_, _ = c.Call(context.Background(), "/test.Service/Mutation", nil, 1000)
	}()
	<-entered
	r := n.Shutdown(context.Background())
	if r.Complete || r.LiveCallbacks != 1 || r.LiveConnections != 1 {
		t.Fatalf("lost ownership: %+v", r)
	}
	select {
	case <-n.Done():
		t.Fatal("done before callback returned")
	default:
	}
	close(release)
	<-callDone
	select {
	case <-n.Done():
	case <-time.After(3 * time.Second):
		t.Fatalf("did not complete %+v", n.Snapshot())
	}
	if r := n.Shutdown(context.Background()); !r.Complete || r.LiveCallbacks != 0 || r.LiveConnections != 0 {
		t.Fatalf("final report %+v", r)
	}
}

func TestFIFOSharedAdmissionAndIdleListenerDoesNotHoard(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConnections = 1
	n := testNetwork(t, cfg)
	cc, sc := trust(t, securechannel.TCP)
	first, err := n.ListenTCP(listenerConfig(sc))
	if err != nil {
		t.Fatal(err)
	}
	second, err := n.ListenTCP(listenerConfig(sc))
	if err != nil {
		t.Fatal(err)
	}
	if n.admission.Available() != 1 {
		t.Fatal("idle listener hoarded permit")
	}
	active, err := n.Client(reconnectConfig(), tcpConnector(second.LocalAddr().String(), cc))
	if err != nil {
		t.Fatal(err)
	}
	phase(t, active, CoreReady)
	waiting, err := n.Client(reconnectConfig(), tcpConnector(first.LocalAddr().String(), cc))
	if err != nil {
		t.Fatal(err)
	}
	until(t, func() bool { return first.Snapshot().WaitingAdmission == 1 })
	active.Stop()
	phase(t, waiting, CoreReady)
	if first.Snapshot().Admitted != 1 {
		t.Fatal("waiting listener was not admitted")
	}
}

func TestCreatedWhilePausedAndOperationAdmission(t *testing.T) {
	cfg := DefaultConfig()
	cfg.StartPaused = true
	cfg.MaxOperations = 1
	n := testNetwork(t, cfg)
	var calls atomic.Int32
	c, err := n.Client(reconnectConfig(), func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error) {
		calls.Add(1)
		return nil, securechannel.ErrAuth
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Retry()
	phase(t, c, Paused)
	if calls.Load() != 0 {
		t.Fatal("managed pause bypassed")
	}
	if _, err := n.Client(reconnectConfig(), func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error) { return nil, nil }); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	n.Resume()
	phase(t, c, Blocked)
}

func TestFailureClassificationPreservesTypedErrorsAndDropsDiagnostics(t *testing.T) {
	var nilRPC *syntra.RpcError
	for _, test := range []struct {
		err  error
		want Failure
	}{
		{nil, FailureNone}, {nilRPC, FailureRuntime},
		{fmt.Errorf("private diagnostics: %w", securechannel.ErrAuth), FailureAuthentication},
		{ordered.ErrProtocol, FailureProtocol}, {securechannel.ErrRecord, FailureFraming},
		{syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "secret"), FailureAuthentication},
		{syntra.NewRpcError(syntra.ErrorCodeDeadlineExceeded, "secret"), FailureTimeout},
		{errors.New("secret"), FailureRuntime},
	} {
		if got := Classify(test.err); got != test.want {
			t.Fatalf("classification got %v want %v", got, test.want)
		} else if strings.Contains(got.Error(), "secret") {
			t.Fatal("diagnostic leaked")
		}
	}
	wrapped := Sanitize(fmt.Errorf("secret: %w", ordered.ErrProtocol))
	if !errors.Is(wrapped, ordered.ErrProtocol) || strings.Contains(wrapped.Error(), "secret") {
		t.Fatal("lost stable sentinel")
	}
	var rpc *syntra.RpcError
	if !errors.As(Sanitize(syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "secret")), &rpc) || rpc.Code != syntra.ErrorCodeUnauthenticated || strings.Contains(rpc.Message, "secret") {
		t.Fatal("lost sanitized RPC code")
	}
}

type zeroRandom struct{}

func (zeroRandom) Read(p []byte) (int, error) { clear(p); return len(p), nil }

type delayedCloseConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *delayedCloseConn) Close() error {
	c.once.Do(func() { close(c.started); <-c.release; _ = c.Conn.Close() })
	return nil
}

func TestCoreTerminationFencedBeforeTransportDone(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	l, err := n.ListenTCP(listenerConfig(sc))
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseClose := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseClose)
	c, err := n.Client(reconnectConfig(), func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
		raw, e := (&net.Dialer{}).DialContext(ctx, "tcp", l.LocalAddr().String())
		if e != nil {
			return nil, e
		}
		return tcp.Connect(ctx, &delayedCloseConn{Conn: raw, started: started, release: release}, cc, syntra.ClientConfig{}, ordered.Options{Budget: b})
	})
	if err != nil {
		t.Fatal(err)
	}
	first := phase(t, c, CoreReady).Generation
	c.mu.Lock()
	conn := c.active.conn
	c.mu.Unlock()
	coreClosed := make(chan struct{})
	go func() { _ = conn.Client.Close(); close(coreClosed) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("transport close did not start")
	}
	select {
	case <-conn.Done():
		t.Fatal("transport completed before close was released")
	default:
	}
	if c.IsGenerationCurrent(first) {
		t.Fatal("closed core remained current while transport was joining")
	}
	if _, err := c.Call(testContext(t), "/test.Service/Echo", nil, 1000); err == nil {
		t.Fatal("closed core admitted a call")
	}
	c.Stop()
	releaseClose()
	<-coreClosed
}

func TestRetryPreservesBackoffExponentUntilReadiness(t *testing.T) {
	cfg := reconnectConfig()
	cfg.MaxAttempts = 2
	cfg.BaseBackoff = 100 * time.Millisecond
	cfg.MaxBackoff = time.Second
	cfg.Random = zeroRandom{}
	var calls atomic.Int32
	c, err := NewClient(cfg, func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error) {
		if calls.Add(1) == 2 {
			return nil, securechannel.ErrAuth
		}
		return nil, ordered.ErrIO
	})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	first := phase(t, c, Backoff).Backoff
	phase(t, c, Blocked)
	c.Retry()
	second := phase(t, c, Backoff).Backoff
	if second <= first {
		t.Fatalf("retry reset backoff: first=%v second=%v", first, second)
	}
}

func TestManagedOpenRetainsBlockedStreamHostUntilReturn(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	left, right := net.Pipe()
	defer right.Close()
	cfg := DefaultConfig()
	cfg.CloseTimeout = 20 * time.Millisecond
	cfg.StreamHost = StreamHostFunc(func(context.Context, string) (net.Conn, error) { close(entered); <-release; return left, nil })
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ordered.NewEstablishmentBudget(nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	returned := make(chan error, 1)
	go func() { _, err := n.Open(context.Background(), "blocked", b); returned <- err }()
	<-entered
	if report := n.Shutdown(context.Background()); report.Complete || report.PendingOperations != 1 || report.LiveCallbacks != 1 {
		t.Fatalf("lost stream host ownership: %+v", report)
	}
	close(release)
	if err := <-returned; Classify(err) != FailureClosed {
		t.Fatalf("stale stream accepted: %v", err)
	}
	select {
	case <-n.Done():
	case <-time.After(time.Second):
		t.Fatal("stream host completion was not joined")
	}
	if _, err := right.Read(make([]byte, 1)); err == nil {
		t.Fatal("stale supplied stream was not closed")
	}
}

func TestInvalidReconnectPolicyAndConfiguration(t *testing.T) {
	cfg := reconnectConfig()
	cfg.MaxAttempts = 0
	if _, err := NewClient(cfg, tcpConnector("unused", securechannel.ClientConfig{})); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	cfg = reconnectConfig()
	cfg.AttemptTimeout = 16 * time.Second
	if err := cfg.Validate(); err == nil {
		t.Fatal("unbounded attempt accepted")
	}
	cfg = reconnectConfig()
	cfg.ReconnectBudget = 25 * time.Hour
	if err := cfg.Validate(); err == nil {
		t.Fatal("unbounded outage accepted")
	}
}

func TestAdmissionCancellationDoesNotLeakOrSkipFIFO(t *testing.T) {
	a, _ := NewAdmission(1)
	release, err := a.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		r, e := a.acquire(ctx)
		if r != nil {
			r()
		}
		result <- e
	}()
	until(t, func() bool { a.mu.Lock(); defer a.mu.Unlock(); return len(a.waiters) == 1 })
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	release()
	if a.Available() != 1 {
		t.Fatal("permit leaked")
	}
}

// A caller-provided connected stream is accepted without assuming a TCP socket.
func TestApplicationStreamHostUsesExactConnection(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	left, right := net.Pipe()
	var opens atomic.Int32
	host, err := syntra.OpenHost(listenerConfig(sc).Host)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	serverCtx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- tcp.Accept(serverCtx, right, sc, host, ordered.Options{}) }()
	n.cfg.StreamHost = StreamHostFunc(func(context.Context, string) (net.Conn, error) { opens.Add(1); return left, nil })
	c, err := n.Client(reconnectConfig(), func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
		raw, e := n.Open(ctx, "application-address", b)
		if e != nil {
			return nil, e
		}
		return tcp.Connect(ctx, raw, cc, syntra.ClientConfig{}, ordered.Options{Budget: b})
	})
	if err != nil {
		t.Fatal(err)
	}
	phase(t, c, CoreReady)
	result, err := c.Call(testContext(t), "/test.Service/Echo", []byte("custom"), 1000)
	if err != nil || string(result.Value) != "custom" || opens.Load() != 1 {
		t.Fatalf("result=%+v err=%v opens=%d", result, err, opens.Load())
	}
	c.Stop()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("custom stream server did not finish")
	}
}
