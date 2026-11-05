package syntra

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
)

// No serve loop runs in this fixture: withdrawal cannot accidentally pass the
// dispatch tests by cancelling their context before the new Revoked guards run.
func newWithdrawalReviewConnection(t *testing.T, cfg HostConfig) (*Host, *hostConn, context.Context) {
	t.Helper()
	host, err := OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	core, err := newHostCore(host.cfg)
	if err != nil {
		t.Fatal(err)
	}
	hello := mustMarshal(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if _, err := core.acceptHello(hello); err != nil {
		t.Fatal(err)
	}
	raw, err := core.authComplete("alice")
	if err != nil {
		t.Fatal(err)
	}
	ready, err := UnmarshalFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	a, b := LoopbackPair()
	connection := &hostConn{
		core: core, cancels: make(map[uint64]*callCancel), wake: make(chan struct{}, 1),
		stop: stop, completed: make(chan *callCancel, host.cfg.maxPending),
		principal: "alice", version: 1, connectionID: ready.GetReady().GetConnectionId(), transport: a,
	}
	if cfg.Recovery != nil {
		connection.recovery, err = cfg.Recovery.OpenConnection(RecoveryConnection{ID: connection.connectionID, Principal: "alice", Version: 1})
		if err != nil {
			t.Fatal(err)
		}
	}
	host.conns[connection] = struct{}{}
	t.Cleanup(func() {
		stop()
		_ = a.Close()
		_ = b.Close()
		host.cancelHandlers(connection, nil, true)
		host.drainHandlers(connection)
		if connection.recovery != nil {
			connection.recovery.Close()
		}
		_ = core.close()
	})
	return host, connection, ctx
}

func TestRuntimeWithdrawalGuardsOrdinaryDispatchWithoutContextCancellation(t *testing.T) {
	for _, beforeDispatch := range []bool{true, false} {
		t.Run(map[bool]string{true: "before-dispatch", false: "authorize-returns-nil-after-source-withdrawal"}[beforeDispatch], func(t *testing.T) {
			service, err := NewRecoveryService(recoveryRejectSource{}, DefaultRecoveryLimits())
			if err != nil {
				t.Fatal(err)
			}
			var authorizations, effects atomic.Int32
			sourceErrors := make(chan error, 1)
			authorizeContext := make(chan error, 1)
			cfg := testHostConfig()
			cfg.Recovery = service
			cfg.Authorize = func(ctx context.Context, principal, _ string) error {
				authorizations.Add(1)
				sourceErrors <- service.source.Authorize(ctx, principal, []byte("withdraw"), RecoveryHookSubscribe)
				authorizeContext <- ctx.Err()
				return nil
			}
			cfg.Handler = func(context.Context, *RpcRequest) (*RpcResult, error) {
				effects.Add(1)
				return NewSuccessResult(nil), nil
			}
			host, connection, ctx := newWithdrawalReviewConnection(t, cfg)
			request := &RpcRequest{Method: "/example.Echo/Ordinary", TimeoutMs: 5000}
			if _, _, fatal := connection.core.onFrame(mustMarshal(NewRequestFrame(1, 1, request))); fatal != nil {
				t.Fatal(fatal)
			}
			id, admitted, ok := connection.core.takePending()
			if !ok || id != 1 {
				t.Fatal("ordinary request was not admitted")
			}
			if beforeDispatch {
				alignmentCode(t, service.source.Authorize(ctx, "alice", []byte("withdraw"), RecoveryHookSubscribe), ErrorCodeUnauthenticated)
				alignmentCode(t, host.dispatch(ctx, connection.transport, connection, id, admitted), ErrorCodeUnauthenticated)
				if authorizations.Load() != 0 || connection.workers != 0 {
					t.Fatal("revoked dispatch started an authorizer or worker")
				}
			} else {
				if err := host.dispatch(ctx, connection.transport, connection, id, admitted); err != nil {
					t.Fatal(err)
				}
				select {
				case completed := <-connection.completed:
					connection.workers--
					result := <-completed.result
					if result.GetError().GetCode() != ErrorCodeUnauthenticated || !completed.authRevoked.Load() {
						t.Fatalf("withdrawal after nil authorization = %v", result)
					}
				case <-time.After(time.Second):
					t.Fatal("withdrawn dispatch did not complete")
				}
				alignmentCode(t, <-sourceErrors, ErrorCodeUnauthenticated)
				if err := <-authorizeContext; err != nil {
					t.Fatalf("context cancellation masked the Revoked guard: %v", err)
				}
				if authorizations.Load() != 1 {
					t.Fatalf("authorizations = %d, want 1", authorizations.Load())
				}
			}
			if !connection.recovery.Revoked() || ctx.Err() != nil || effects.Load() != 0 {
				t.Fatalf("dispatch fence: revoked=%v context=%v effects=%d", connection.recovery.Revoked(), ctx.Err(), effects.Load())
			}
		})
	}
}

type withdrawalReviewRecvProbe struct {
	Transport
	reads  atomic.Int32
	active chan context.Context
}

func (p *withdrawalReviewRecvProbe) Recv(ctx context.Context) ([]byte, error) {
	if p.reads.Add(1) == 2 {
		p.active <- ctx
	}
	return p.Transport.Recv(ctx)
}

type withdrawalReviewBlockedSource struct {
	*recoveryTestSource
	armed   atomic.Bool
	once    sync.Once
	entered chan context.Context
	release chan struct{}
}

func (s *withdrawalReviewBlockedSource) Authorize(ctx context.Context, principal string, selector []byte, hook RecoveryHook) error {
	if string(selector) == "withdraw" {
		return NewRpcError(ErrorCodeUnauthenticated, "principal withdrawn")
	}
	if string(selector) == "blocked" {
		if hook == RecoveryHookCatchUp {
			s.armed.Store(true)
		}
		if hook == RecoveryHookEmit && s.armed.Load() {
			s.once.Do(func() { s.entered <- ctx })
			<-s.release // Deliberately retain the callback after its context ends.
			return nil
		}
	}
	return s.recoveryTestSource.Authorize(ctx, principal, selector, hook)
}

func withdrawalReviewContext(t *testing.T, ch <-chan context.Context, name string) context.Context {
	t.Helper()
	select {
	case ctx := <-ch:
		return ctx
	case <-time.After(time.Second):
		t.Fatalf("%s did not start", name)
		return nil
	}
}

func withdrawalReviewCancelled(t *testing.T, ctx context.Context, name string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("%s waited for noncooperative egress instead of source withdrawal", name)
	}
}

func TestRuntimeWithdrawalCancelsSiblingAndIdleContextsBeforeEgressReturns(t *testing.T) {
	source := &withdrawalReviewBlockedSource{recoveryTestSource: newRecoveryTestSource(), entered: make(chan context.Context, 1), release: make(chan struct{})}
	var release sync.Once
	unblock := func() { release.Do(func() { close(source.release) }) }
	t.Cleanup(unblock)
	service, err := NewRecoveryService(source, DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	var effects atomic.Int32
	observed := make(chan error, 1)
	handlerStarted := make(chan context.Context, 1)
	handlerCancelled := make(chan struct{})
	cfg := testHostConfig()
	cfg.Policy = StaticPolicy("alice", true)
	cfg.Recovery = service
	cfg.ExecutionBudget, _ = NewExecutionBudget(8)
	cfg.Authorize = func(ctx context.Context, principal, method string) error {
		if method == "/example.Withdraw/Now" {
			observed <- service.source.Authorize(ctx, principal, []byte("withdraw"), RecoveryHookSubscribe)
		}
		return nil
	}
	cfg.Handler = func(ctx context.Context, request *RpcRequest) (*RpcResult, error) {
		if request.GetMethod() == "/example.Wait/Withdrawal" {
			handlerStarted <- ctx
			<-ctx.Done()
			close(handlerCancelled)
			return nil, ctx.Err()
		}
		if request.GetMethod() == "/example.Withdraw/Now" {
			effects.Add(1)
		}
		return echoHandler(ctx, request)
	}
	open := func(config HostConfig) (*rawSessionPeer, context.Context) {
		probe := &withdrawalReviewRecvProbe{active: make(chan context.Context, 1)}
		peer := newRawSessionPeer(t, config, func(tr Transport) Transport { probe.Transport = tr; return probe })
		return peer, withdrawalReviewContext(t, probe.active, "active receive loop")
	}
	blocked, blockedRead := open(cfg)
	runtimeRecoveryRPC(t, blocked, 1, RecoveryNegotiate, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}, new(pb.RecoveryNegotiateResponse))
	subscription := new(pb.RecoverySubscribeResponse)
	runtimeRecoveryRPC(t, blocked, 2, RecoverySubscribe, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("blocked")}, subscription)
	runtimeRecoveryRPC(t, blocked, 3, RecoveryCatchUp, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: subscription.SubscriptionHandle}, new(pb.RecoveryCatchUpAccepted))
	egressCtx := withdrawalReviewContext(t, source.entered, "noncooperative egress")
	blocked.host.mu.Lock()
	var connection *hostConn
	for current := range blocked.host.conns {
		connection = current
	}
	blocked.host.mu.Unlock()
	if connection == nil {
		t.Fatal("blocked connection missing")
	}
	blocked.request(t, 4, "/example.Wait/Withdrawal")
	handlerCtx := withdrawalReviewContext(t, handlerStarted, "ordinary sibling handler")
	origin, originRead := open(cfg)
	idle, idleRead := open(cfg)
	otherConfig := cfg
	otherConfig.Policy = StaticPolicy("bob", true)
	other, otherRead := open(otherConfig)
	for _, ctx := range []context.Context{blockedRead, handlerCtx, egressCtx, originRead, idleRead, otherRead} {
		if ctx.Err() != nil {
			t.Fatalf("fixture expired before withdrawal: %v", ctx.Err())
		}
	}
	origin.request(t, 1, "/example.Withdraw/Now")
	select {
	case err := <-observed:
		alignmentCode(t, err, ErrorCodeUnauthenticated)
	case <-time.After(time.Second):
		t.Fatal("source withdrawal blocked behind sibling egress")
	}
	withdrawalReviewCancelled(t, blockedRead, "blocked sibling receive context")
	withdrawalReviewCancelled(t, handlerCtx, "ordinary handler context")
	withdrawalReviewCancelled(t, egressCtx, "noncooperative provider context")
	withdrawalReviewCancelled(t, originRead, "withdrawal-origin receive context")
	withdrawalReviewCancelled(t, idleRead, "idle same-principal receive context")
	awaitSignal(t, handlerCancelled, "ordinary handler cancellation")
	select {
	case <-connection.recoveryDone:
		t.Fatal("egress unexpectedly returned before release")
	default:
	}
	for _, peer := range []*rawSessionPeer{origin, idle, blocked} {
		err := runtimeAwait(t, peer.done)
		peer.done <- err
		alignmentCode(t, err, ErrorCodeUnauthenticated)
	}
	if effects.Load() != 0 {
		t.Fatalf("nil-returning authorizer permitted %d handler effects", effects.Load())
	}
	core := connection.core.(*goHostCore)
	core.mu.Lock()
	closed := core.closed
	core.mu.Unlock()
	if closed {
		t.Fatal("core destroyed before its noncooperative egress joined")
	}
	if otherRead.Err() != nil || runtimeRecoverySession(t, other).Revoked() {
		t.Fatal("withdrawal crossed principal scope")
	}
	other.request(t, 1, "/example.Echo/Echo")
	if result := other.recv(t); result.GetRequestId() != 1 || !validSuccess(result.GetResult()) {
		t.Fatalf("unrelated principal stopped dispatching: %v", result)
	}
	unblock()
	until := time.Now().Add(time.Second)
	for {
		core.mu.Lock()
		closed = core.closed
		core.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(until) {
			t.Fatal("retained core cleanup did not finish after egress returned")
		}
		time.Sleep(time.Millisecond)
	}
}
