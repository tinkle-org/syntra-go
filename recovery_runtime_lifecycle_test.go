package syntra

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
)

func TestRecoveryRuntimeAuthorizePrecedesDispatch(t *testing.T) {
	service, err := NewRecoveryService(newRecoveryTestSource(), DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	var allow atomic.Bool
	var fallback atomic.Int32
	cfg := testHostConfig()
	cfg.Recovery = service
	cfg.Authorize = func(context.Context, string, string) error {
		if !allow.Load() {
			return NewRpcError(ErrorCodePermissionDenied, "private denial")
		}
		return nil
	}
	cfg.Handler = func(context.Context, *RpcRequest) (*RpcResult, error) {
		fallback.Add(1)
		return NewSuccessResult(nil), nil
	}
	p := newRawSessionPeer(t, cfg, nil)
	payload := recoveryTestEncode(t, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability})
	p.send(t, NewRequestFrame(1, 1, &RpcRequest{Method: RecoveryNegotiate, Payload: payload}))
	assertTerminalCode(t, p.recv(t), 1, ErrorCodePermissionDenied)
	session := runtimeRecoverySession(t, p)
	if err := session.lock(p.ctx); err != nil {
		t.Fatal(err)
	}
	negotiated := session.negotiated
	session.unlock()
	if negotiated {
		t.Fatal("service ran before authorization")
	}
	allow.Store(true)
	p.send(t, NewRequestFrame(1, 2, &RpcRequest{Method: RecoveryMethodPrefix + "Future"}))
	assertTerminalCode(t, p.recv(t), 2, ErrorCodeUnimplemented)
	runtimeRecoveryRPC(t, p, 3, RecoveryNegotiate, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}, new(pb.RecoveryNegotiateResponse))
	if fallback.Load() != 0 {
		t.Fatal("profile dispatch reached application fallback")
	}
}

type recoveryReadyFailure struct {
	Transport
	service *RecoveryService
	bound   bool
}

func (r *recoveryReadyFailure) Send(ctx context.Context, raw []byte) error {
	f, err := UnmarshalFrame(raw)
	if err == nil && f.GetReady() != nil {
		r.service.mu.Lock()
		session := r.service.sessions[f.GetReady().GetConnectionId()]
		r.bound = session != nil && session.connection.Principal == "alice" && session.connection.Version == f.GetVersion()
		r.service.mu.Unlock()
		return errors.New("ready send failed")
	}
	return r.Transport.Send(ctx, raw)
}

func TestRecoveryRuntimeFailedReadyUnwindsServiceConnection(t *testing.T) {
	service, err := NewRecoveryService(newRecoveryTestSource(), DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testHostConfig()
	cfg.Policy = StaticPolicy("alice", true)
	cfg.Recovery = service
	h, err := OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	a, peer := LoopbackPair()
	defer peer.Close()
	failure := &recoveryReadyFailure{Transport: a, service: service}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx, failure) }()
	if err := peer.Send(ctx, mustMarshal(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))); err != nil {
		t.Fatal(err)
	}
	alignmentCode(t, runtimeAwait(t, done), ErrorCodeUnavailable)
	if !failure.bound {
		t.Fatal("Ready was sent before exact service binding")
	}
	service.mu.Lock()
	defer service.mu.Unlock()
	if len(service.sessions) != 0 || len(service.principals) != 0 || len(service.subscriptions) != 0 {
		t.Fatal("failed handshake leaked recovery quota")
	}
}

type recoveryBlockingEmitter struct {
	*recoveryTestSource
	entered            chan struct{}
	release            chan struct{}
	once               sync.Once
	ignoreCancellation bool
	armed              atomic.Bool
}

func (s *recoveryBlockingEmitter) Authorize(ctx context.Context, principal string, selector []byte, hook RecoveryHook) error {
	if hook == RecoveryHookCatchUp {
		s.armed.Store(true)
	}
	if hook == RecoveryHookEmit && s.armed.Load() {
		s.once.Do(func() { close(s.entered) })
		if s.ignoreCancellation {
			<-s.release
		} else {
			<-ctx.Done()
		}
		return ctx.Err()
	}
	return s.recoveryTestSource.Authorize(ctx, principal, selector, hook)
}

func runtimeStartBlockedRecovery(t *testing.T, source RecoverySource) (*rawSessionPeer, *RecoveryService, *hostConn) {
	t.Helper()
	service, err := NewRecoveryService(source, DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testHostConfig()
	cfg.Policy = StaticPolicy("alice", true)
	cfg.Recovery = service
	cfg.ExecutionBudget, _ = NewExecutionBudget(8)
	p := newRawSessionPeer(t, cfg, nil)
	runtimeRecoveryRPC(t, p, 1, RecoveryNegotiate, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}, new(pb.RecoveryNegotiateResponse))
	sub := new(pb.RecoverySubscribeResponse)
	runtimeRecoveryRPC(t, p, 2, RecoverySubscribe, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}, sub)
	p.send(t, NewRequestFrame(1, 3, &RpcRequest{Method: RecoveryCatchUp, Payload: recoveryTestEncode(t, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle})}))
	if result := p.recv(t); result.GetRequestId() != 3 || result.GetResult().GetError() != nil {
		t.Fatalf("catch-up result = %v", result)
	}
	p.host.mu.Lock()
	defer p.host.mu.Unlock()
	for connection := range p.host.conns {
		return p, service, connection
	}
	t.Fatal("connection missing")
	return nil, nil, nil
}

func TestRecoveryRuntimeManagedWorkerCancellationAndRetainedCleanup(t *testing.T) {
	for _, ignore := range []bool{false, true} {
		t.Run(map[bool]string{false: "cooperative", true: "noncooperative"}[ignore], func(t *testing.T) {
			source := &recoveryBlockingEmitter{recoveryTestSource: newRecoveryTestSource(), entered: make(chan struct{}), release: make(chan struct{}), ignoreCancellation: ignore}
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(source.release) }) })
			p, service, connection := runtimeStartBlockedRecovery(t, source)
			awaitSignal(t, source.entered, "recovery egress provider")
			if err := p.host.Close(); err != nil {
				t.Fatal(err)
			}
			err := runtimeAwait(t, p.done)
			p.done <- err
			core := connection.core.(*goHostCore)
			if ignore {
				alignmentCode(t, err, ErrorCodeUnavailable)
				core.mu.Lock()
				closed := core.closed
				core.mu.Unlock()
				if closed || p.host.cfg.executions.Live() == 0 {
					t.Fatal("cleanup destroyed core or released a live egress execution")
				}
			} else if err != nil {
				t.Fatal(err)
			}
			release.Do(func() { close(source.release) })
			until := time.Now().Add(time.Second)
			for {
				core.mu.Lock()
				closed := core.closed
				core.mu.Unlock()
				service.mu.Lock()
				remaining := len(service.sessions)
				service.mu.Unlock()
				if closed && remaining == 0 && p.host.cfg.executions.Live() == 0 {
					break
				}
				if time.Now().After(until) {
					t.Fatal("retained cleanup did not finish after provider returned")
				}
				time.Sleep(time.Millisecond)
			}
		})
	}
}

type recoveryFailingEmitter struct {
	*recoveryTestSource
	fail atomic.Bool
}

func (s *recoveryFailingEmitter) CurrentGeneration(ctx context.Context, principal string, identity []byte) (uint64, error) {
	if s.fail.Load() {
		return 0, NewRpcError(ErrorCodeInternal, "provider failed")
	}
	return s.recoveryTestSource.CurrentGeneration(ctx, principal, identity)
}

func TestRecoveryRuntimeManagedWorkerFailureTerminatesSession(t *testing.T) {
	source := &recoveryFailingEmitter{recoveryTestSource: newRecoveryTestSource()}
	service, err := NewRecoveryService(source, DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testHostConfig()
	cfg.Recovery = service
	p := newRawSessionPeer(t, cfg, nil)
	runtimeRecoveryRPC(t, p, 1, RecoveryNegotiate, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}, new(pb.RecoveryNegotiateResponse))
	runtimeRecoveryRPC(t, p, 2, RecoverySubscribe, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}, new(pb.RecoverySubscribeResponse))
	session := runtimeRecoverySession(t, p)
	source.fail.Store(true)
	session.signal()
	err = runtimeAwait(t, p.done)
	p.done <- err
	alignmentCode(t, err, ErrorCodeInternal)
	runtimeAssertPeerClosed(t, p.peer)
}

func TestRuntimeDefaultExecutionBudgetIsProcessWide(t *testing.T) {
	first, err := resolveHostConfig(HostConfig{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := resolveHostConfig(HostConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if first.executions != second.executions || cap(first.executions.slots) != 1024 {
		t.Fatal("default execution budget is not process-wide 1024")
	}
}

type recoveryContextSource struct {
	*recoveryTestSource
	bound chan *RecoveryHostSession
}

func (s *recoveryContextSource) Capture(ctx context.Context, principal string, selector []byte) (RecoveryProviderStream, error) {
	session, ok := RecoveryHostSessionFromContext(ctx)
	if !ok {
		return RecoveryProviderStream{}, errors.New("missing runtime binding")
	}
	s.bound <- session
	return s.recoveryTestSource.Capture(ctx, principal, selector)
}

func TestRecoveryRuntimeSuppliesPublicationHandleToSource(t *testing.T) {
	source := &recoveryContextSource{recoveryTestSource: newRecoveryTestSource(), bound: make(chan *RecoveryHostSession, 1)}
	service, err := NewRecoveryService(source, DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	cfg := testHostConfig()
	cfg.Recovery = service
	p := newRawSessionPeer(t, cfg, nil)
	runtimeRecoveryRPC(t, p, 1, RecoveryNegotiate, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}, new(pb.RecoveryNegotiateResponse))
	runtimeRecoveryRPC(t, p, 2, RecoverySubscribe, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}, new(pb.RecoverySubscribeResponse))
	select {
	case session := <-source.bound:
		if session != runtimeRecoverySession(t, p) {
			t.Fatal("source received another connection's publication handle")
		}
	case <-time.After(time.Second):
		t.Fatal("source did not receive runtime binding")
	}
}
