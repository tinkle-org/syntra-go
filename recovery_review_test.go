package syntra

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
)

type recoveryRejectSource struct{}

func (recoveryRejectSource) Authorize(context.Context, string, []byte, RecoveryHook) error {
	return NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
}
func (recoveryRejectSource) Capture(context.Context, string, []byte) (RecoveryProviderStream, error) {
	return RecoveryProviderStream{}, NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
}
func (recoveryRejectSource) CurrentGeneration(context.Context, string, []byte) (uint64, error) {
	return 0, NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
}
func (recoveryRejectSource) ValidateIssued(context.Context, string, RecoveryProviderStream, []byte) error {
	return NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
}
func (recoveryRejectSource) Replay(context.Context, string, RecoveryProviderStream, []byte, []byte, RecoveryPageBudget) (RecoveryProviderPage, error) {
	return RecoveryProviderPage{}, NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
}
func (recoveryRejectSource) Snapshot(context.Context, string, RecoveryProviderStream) (RecoveryProviderSnapshot, error) {
	return RecoveryProviderSnapshot{}, NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
}
func (recoveryRejectSource) SnapshotPage(context.Context, string, RecoveryProviderStream, RecoveryProviderSnapshot, uint32) ([]byte, error) {
	return nil, NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
}

func TestRecoverySourceWithdrawalEveryCallbackAndPrincipalIsolation(t *testing.T) {
	callbacks := map[string]func(RecoverySource) error{
		"authorize": func(s RecoverySource) error { return s.Authorize(context.Background(), "alice", nil, RecoveryHookEmit) },
		"capture":   func(s RecoverySource) error { _, e := s.Capture(context.Background(), "alice", nil); return e },
		"generation": func(s RecoverySource) error {
			_, e := s.CurrentGeneration(context.Background(), "alice", nil)
			return e
		},
		"issued": func(s RecoverySource) error {
			return s.ValidateIssued(context.Background(), "alice", RecoveryProviderStream{}, nil)
		},
		"replay": func(s RecoverySource) error {
			_, e := s.Replay(context.Background(), "alice", RecoveryProviderStream{}, nil, nil, RecoveryPageBudget{})
			return e
		},
		"snapshot": func(s RecoverySource) error {
			_, e := s.Snapshot(context.Background(), "alice", RecoveryProviderStream{})
			return e
		},
		"page": func(s RecoverySource) error {
			_, e := s.SnapshotPage(context.Background(), "alice", RecoveryProviderStream{}, RecoveryProviderSnapshot{}, 0)
			return e
		},
	}
	for name, callback := range callbacks {
		t.Run(name, func(t *testing.T) {
			s, err := NewRecoveryService(recoveryRejectSource{}, DefaultRecoveryLimits())
			if err != nil {
				t.Fatal(err)
			}
			open := func(id, p string) *RecoveryHostSession {
				h, e := s.OpenConnection(RecoveryConnection{id, p, 1})
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(h.Close)
				return h
			}
			a, b, other := open("a", "alice"), open("b", "alice"), open("other", "bob")
			if err := b.lock(context.Background()); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- callback(s.source) }()
			select {
			case err := <-done:
				if recoveryErrorCode(err) != ErrorCodeUnauthenticated {
					t.Error(err)
				}
			case <-time.After(time.Second):
				b.unlock()
				t.Fatal("withdrawal waited for another callback gate")
			}
			// A revoked gate waiter must wake even while the owner is still working.
			_, err = b.NextNotification(context.Background())
			b.unlock()
			if recoveryErrorCode(err) != ErrorCodeUnauthenticated {
				t.Fatal(err)
			}
			if !a.Revoked() || !b.Revoked() || other.Revoked() || other.Err() != nil {
				t.Fatal("principal withdrawal scope")
			}
			_, err = a.Handler(context.Background(), &RpcRequest{Method: RecoveryNegotiate, Payload: recoveryTestEncode(t, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability})})
			if recoveryErrorCode(err) != ErrorCodeUnauthenticated {
				t.Fatal(err)
			}
			a.Close()
			if !a.Revoked() || recoveryErrorCode(a.Err()) != ErrorCodeUnauthenticated {
				t.Fatal("withdrawal was not sticky")
			}
			fresh := open("fresh", "alice")
			if fresh.Revoked() {
				t.Fatal("new authenticated binding inherited old withdrawal")
			}
		})
	}
}

type recoveryReviewSource struct {
	*recoveryTestSource
	authorize  func(context.Context, string, []byte, RecoveryHook) error
	capture    func(context.Context, string, []byte) (RecoveryProviderStream, error)
	validate   func(context.Context, string, RecoveryProviderStream, []byte) error
	generation func(context.Context, string, []byte) (uint64, error)
	replay     func(context.Context, string, RecoveryProviderStream, []byte, []byte, RecoveryPageBudget) (RecoveryProviderPage, error)
}

func (s *recoveryReviewSource) Authorize(ctx context.Context, p string, selector []byte, hook RecoveryHook) error {
	if s.authorize != nil {
		return s.authorize(ctx, p, selector, hook)
	}
	return s.recoveryTestSource.Authorize(ctx, p, selector, hook)
}
func (s *recoveryReviewSource) Capture(ctx context.Context, p string, selector []byte) (RecoveryProviderStream, error) {
	if s.capture != nil {
		return s.capture(ctx, p, selector)
	}
	return s.recoveryTestSource.Capture(ctx, p, selector)
}
func (s *recoveryReviewSource) ValidateIssued(ctx context.Context, p string, stream RecoveryProviderStream, checkpoint []byte) error {
	if s.validate != nil {
		return s.validate(ctx, p, stream, checkpoint)
	}
	return s.recoveryTestSource.ValidateIssued(ctx, p, stream, checkpoint)
}

func (s *recoveryReviewSource) CurrentGeneration(ctx context.Context, p string, identity []byte) (uint64, error) {
	if s.generation != nil {
		return s.generation(ctx, p, identity)
	}
	return s.recoveryTestSource.CurrentGeneration(ctx, p, identity)
}

func (s *recoveryReviewSource) Replay(ctx context.Context, p string, stream RecoveryProviderStream, from, marker []byte, budget RecoveryPageBudget) (RecoveryProviderPage, error) {
	if s.replay != nil {
		return s.replay(ctx, p, stream, from, marker, budget)
	}
	return s.recoveryTestSource.Replay(ctx, p, stream, from, marker, budget)
}

func recoveryReviewHost(t *testing.T, source RecoverySource) *RecoveryHostSession {
	t.Helper()
	service, err := NewRecoveryService(source, DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	h, err := service.OpenConnection(RecoveryConnection{"review", "alice", 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	recoveryTestNegotiate(t, h)
	return h
}

func TestRecoveryWithdrawalSurvivesExpiredHandlerDeadline(t *testing.T) {
	source := &recoveryReviewSource{recoveryTestSource: newRecoveryTestSource(), capture: func(ctx context.Context, _ string, _ []byte) (RecoveryProviderStream, error) {
		<-ctx.Done()
		return RecoveryProviderStream{}, NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
	}}
	h := recoveryReviewHost(t, source)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err := h.Handler(ctx, &RpcRequest{Method: RecoverySubscribe, Payload: recoveryTestEncode(t, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("stream")})})
	if !h.Revoked() || recoveryErrorCode(err) != ErrorCodeUnauthenticated {
		t.Fatal("deadline masked source withdrawal", err)
	}
}

func TestRecoveryPublishTailRetryAndPartialFanout(t *testing.T) {
	var validations atomic.Int32
	base := newRecoveryTestSource()
	source := &recoveryReviewSource{recoveryTestSource: base}
	source.validate = func(ctx context.Context, p string, stream RecoveryProviderStream, checkpoint []byte) error {
		if validations.Add(1) == 2 {
			return NewRpcError(ErrorCodeUnavailable, "retry publication")
		}
		return base.ValidateIssued(ctx, p, stream, checkpoint)
	}
	h := recoveryReviewHost(t, source)
	a := recoveryTestSubscribeHost(t, h, "")
	b := recoveryTestSubscribeHost(t, h, "")
	batch := RecoveryStoredBatch{7, []byte("c"), []byte("d"), []byte("CD")}
	if err := h.Publish(context.Background(), []byte("stable"), batch); recoveryErrorCode(err) != ErrorCodeUnavailable {
		t.Fatal(err)
	}
	if err := h.Publish(context.Background(), []byte("stable"), batch); err != nil {
		t.Fatal("partial fanout retry", err)
	}
	if err := h.Publish(context.Background(), []byte("stable"), batch); err != nil {
		t.Fatal("identical tail retry", err)
	}
	for _, sub := range []*pb.RecoverySubscribeResponse{a, b} {
		slot := h.slots[string(sub.SubscriptionHandle)]
		if slot.retired || len(slot.held) != 1 || !bytes.Equal(slot.liveTail, []byte("d")) {
			t.Fatal("retry terminated or duplicated an accepted publication")
		}
	}
	if validations.Load() != 6 {
		t.Fatal("tail retry skipped issued validation", validations.Load())
	}
}

func newRecoveryReviewLoopback(t *testing.T, source RecoverySource) *recoveryLoopback {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	service, err := NewRecoveryService(source, DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	host, err := OpenHost(HostConfig{Policy: StaticPolicy("alice", true), Authorize: AllowAllAuthorize, Recovery: service})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := OpenClient(ClientConfig{NotifyBuffer: 1})
	if err != nil {
		t.Fatal(err)
	}
	store := recoveryTestStore(t)
	client, err := NewRecoveryClient(raw, "alice", store, DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	a, b := LoopbackPair()
	done := make(chan error, 2)
	go func() { done <- host.Serve(ctx, a) }()
	go func() { done <- raw.Run(ctx, b) }()
	t.Cleanup(func() {
		cancel()
		client.Close()
		_ = raw.Close()
		_ = host.Close()
		_ = a.Close()
		_ = b.Close()
		for index := 0; index < 2; index++ {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("runtime did not stop")
			}
		}
	})
	if _, err := client.Negotiate(ctx, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}); err != nil {
		t.Fatal(err)
	}
	host.mu.Lock()
	var session *RecoveryHostSession
	for c := range host.conns {
		session = c.recovery
	}
	host.mu.Unlock()
	if session == nil {
		t.Fatal("missing binding")
	}
	return &recoveryLoopback{client: client, host: session, store: store, ctx: ctx}
}

func recoveryReviewDistinctSource() *recoveryReviewSource {
	base := newRecoveryTestSource()
	source := &recoveryReviewSource{recoveryTestSource: base}
	source.capture = func(ctx context.Context, p string, selector []byte) (RecoveryProviderStream, error) {
		stream, err := base.Capture(ctx, p, selector)
		stream.Identity = bytes.Clone(selector)
		return stream, err
	}
	source.validate = func(ctx context.Context, p string, stream RecoveryProviderStream, checkpoint []byte) error {
		stream.Identity = []byte("stable")
		return base.ValidateIssued(ctx, p, stream, checkpoint)
	}
	return source
}

func recoveryReviewLive(t *testing.T, p *recoveryLoopback, selector string) []byte {
	t.Helper()
	sub, err := p.client.Subscribe(p.ctx, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte(selector)}, []byte(selector), RecoveryInitialLiveOnly)
	if err != nil {
		t.Fatal(err)
	}
	handle := sub.Response.SubscriptionHandle
	if _, err := p.client.CatchUp(p.ctx, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: handle}); err != nil {
		t.Fatal(err)
	}
	if event, err := p.client.NextEvent(p.ctx, handle); err != nil || !event.CaughtUp {
		t.Fatal(event, err)
	}
	return handle
}

func recoveryAwaitConsumer(t *testing.T, c *RecoveryClient, handle []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for {
		if err := c.enter(ctx, false); err != nil {
			t.Fatal("idle consumer retained operation gate", err)
		}
		reading := c.rounds[string(handle)].consumer.Load()
		c.leave()
		if reading {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("consumer did not start")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestRecoveryIdleConsumerDoesNotBlockOtherHandleOrUnsubscribe(t *testing.T) {
	p := newRecoveryReviewLoopback(t, recoveryReviewDistinctSource())
	a := recoveryReviewLive(t, p, "a")
	b := recoveryReviewLive(t, p, "b")
	idle := make(chan error, 1)
	go func() { _, err := p.client.NextEvent(p.ctx, a); idle <- err }()
	recoveryAwaitConsumer(t, p.client, a)
	second, cancel := context.WithTimeout(p.ctx, 100*time.Millisecond)
	defer cancel()
	if _, err := p.client.NextEvent(second, a); recoveryErrorCode(err) != ErrorCodeFailedPrecondition {
		t.Fatal("two consumers aliased one handle", err)
	}
	if err := p.host.Publish(p.ctx, []byte("b"), RecoveryStoredBatch{7, []byte("c"), []byte("d"), []byte("CD")}); err != nil {
		t.Fatal(err)
	}
	recoveryPersistConfirm(t, p, b, "d")
	select {
	case err := <-idle:
		t.Fatal("idle handle unexpectedly completed", err)
	default:
	}
	if _, err := p.client.Unsubscribe(p.ctx, &pb.RecoveryUnsubscribeRequest{ProfileVersion: 1, SubscriptionHandle: a}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-idle:
		if recoveryErrorCode(err) != ErrorCodeFailedPrecondition {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("unsubscribe stranded idle consumer")
	}
	ctx, cancelIdle := context.WithCancel(p.ctx)
	waiting := make(chan error, 1)
	go func() { _, err := p.client.NextEvent(ctx, b); waiting <- err }()
	recoveryAwaitConsumer(t, p.client, b)
	cancelIdle()
	select {
	case err := <-waiting:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("consumer cancellation stranded")
	}
}

func TestRecoveryRuntimeTargetedRevalidationDenialKeepsOtherHandle(t *testing.T) {
	source := recoveryReviewDistinctSource()
	var denied atomic.Bool
	source.authorize = func(ctx context.Context, p string, selector []byte, hook RecoveryHook) error {
		if string(selector) == "a" && hook == RecoveryHookEmit {
			if session, ok := RecoveryHostSessionFromContext(ctx); ok {
				for _, slot := range session.slots {
					if string(slot.selector) == "a" && len(slot.offered) > 0 {
						denied.Store(true)
						return NewRpcError(ErrorCodePermissionDenied, "target revoked")
					}
				}
			}
		}
		return source.recoveryTestSource.Authorize(ctx, p, selector, hook)
	}
	p := newRecoveryReviewLoopback(t, source)
	a := recoveryReviewLive(t, p, "a")
	b := recoveryReviewLive(t, p, "b")
	if err := p.host.Publish(p.ctx, []byte("a"), RecoveryStoredBatch{7, []byte("c"), []byte("d"), []byte("CD")}); err != nil {
		t.Fatal(err)
	}
	event, err := p.client.NextEvent(p.ctx, a)
	if err != nil || event.Trailer == nil || !event.Trailer.GetTerminated() || !denied.Load() {
		t.Fatal("target control lost", event, err)
	}
	if p.host.Revoked() {
		t.Fatal("target denial withdrew principal")
	}
	if err := p.host.Publish(p.ctx, []byte("b"), RecoveryStoredBatch{7, []byte("c"), []byte("d"), []byte("CD")}); err != nil {
		t.Fatal(err)
	}
	recoveryPersistConfirm(t, p, b, "d")
}

func TestRecoveryPoppedUnitsLoseEligibilityAcrossSnapshotTransition(t *testing.T) {
	for _, completion := range []bool{false, true} {
		t.Run(map[bool]string{false: "batch", true: "completion"}[completion], func(t *testing.T) {
			h := recoveryReviewHost(t, newRecoveryTestSource())
			start := "a"
			if completion {
				start = ""
			}
			sub := recoveryTestSubscribeHost(t, h, start)
			ctx := context.Background()
			if _, err := h.Handle(ctx, RecoveryCatchUp, recoveryTestEncode(t, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle})); err != nil {
				t.Fatal(err)
			}
			popped, err := h.PopNotification(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.RevalidateNotification(ctx, popped); err != nil {
				t.Fatal("fresh popped unit invalid", err)
			}
			transition := make(chan error, 1)
			offer := recoveryTestEncode(t, &pb.RecoverySnapshotOfferRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, Generation: 7})
			go func() {
				_, err := h.Handle(ctx, RecoverySnapshotOffer, offer)
				transition <- err
			}()
			if err := <-transition; err != nil {
				t.Fatal(err)
			}
			err = h.RevalidateNotification(ctx, popped)
			if recoveryErrorCode(err) != ErrorCodeFailedPrecondition || !recoveryTargetedEgressError(ctx, h, err) {
				t.Fatal("superseded unit retained eligibility", err)
			}
			slot := h.slots[string(sub.SubscriptionHandle)]
			if len(slot.offered) != 0 || slot.completion != nil || slot.mode != "snapshot" {
				t.Fatal("snapshot did not clear old issuance")
			}
			x := slot.snapshot.descriptor
			for index := uint32(0); index < x.TotalPages; index++ {
				if _, err := h.Handle(ctx, RecoverySnapshotFetch, recoveryTestEncode(t, &pb.RecoverySnapshotFetchRequest{ProfileVersion: 1, SnapshotHandle: x.SnapshotHandle, PageIndex: index})); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.Handle(ctx, RecoverySnapshotConfirm, recoveryTestEncode(t, &pb.RecoverySnapshotConfirmRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, Generation: 7, BoundaryCheckpoint: x.BoundaryCheckpoint})); err != nil {
				t.Fatal(err)
			}
			if err := h.RevalidateNotification(ctx, popped); recoveryErrorCode(err) != ErrorCodeFailedPrecondition {
				t.Fatal("installation revived superseded unit", err)
			}
			if err := h.Publish(ctx, []byte("stable"), RecoveryStoredBatch{7, []byte("snapshot"), []byte("d"), []byte("new-live")}); err != nil {
				t.Fatal(err)
			}
			live, err := h.PopNotification(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.RevalidateNotification(ctx, live); err != nil {
				t.Fatal("new snapshot suffix rejected", err)
			}
		})
	}
}

func TestRecoveryNotificationAdmissionSerializesSnapshotTransition(t *testing.T) {
	h := recoveryReviewHost(t, newRecoveryTestSource())
	sub := recoveryTestSubscribeHost(t, h, "a")
	ctx := context.Background()
	if _, err := h.Handle(ctx, RecoveryCatchUp, recoveryTestEncode(t, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle})); err != nil {
		t.Fatal(err)
	}
	payload, err := h.PopNotification(ctx)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	admitted := make(chan error, 1)
	go func() {
		admitted <- h.admitNotification(ctx, payload, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	if len(h.gate) != 1 {
		close(release)
		<-admitted
		t.Fatal("phase guard released before admission")
	}
	offer := recoveryTestEncode(t, &pb.RecoverySnapshotOfferRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, Generation: 7})
	transition := make(chan error, 1)
	go func() { _, err := h.Handle(ctx, RecoverySnapshotOffer, offer); transition <- err }()
	close(release)
	if err := <-admitted; err != nil {
		t.Fatal(err)
	}
	if err := <-transition; err != nil {
		t.Fatal(err)
	}
	if err := h.RevalidateNotification(ctx, payload); recoveryErrorCode(err) != ErrorCodeFailedPrecondition {
		t.Fatal("snapshot transition did not supersede old unit", err)
	}
}

func TestRecoveryRuntimeSourceWithdrawalClosesAllPrincipalConnections(t *testing.T) {
	source := &recoveryReviewSource{recoveryTestSource: newRecoveryTestSource()}
	source.capture = func(ctx context.Context, p string, selector []byte) (RecoveryProviderStream, error) {
		if p == "alice" && string(selector) == "withdraw" {
			<-ctx.Done()
			return RecoveryProviderStream{}, NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
		}
		return source.recoveryTestSource.Capture(ctx, p, selector)
	}
	service, err := NewRecoveryService(source, DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	host, err := OpenHost(HostConfig{Policy: func(_ context.Context, credential []byte) (string, error) { return string(credential), nil }, Authorize: AllowAllAuthorize, Handler: echoHandler, Recovery: service})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(func() { cancel(); _ = host.Close() })
	open := func(principal string) *RecoveryClient {
		raw, err := OpenClient(ClientConfig{Credential: []byte(principal)})
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewRecoveryClient(raw, principal, recoveryTestStore(t), DefaultRecoveryLimits())
		if err != nil {
			t.Fatal(err)
		}
		a, b := LoopbackPair()
		done := make(chan error, 2)
		go func() { done <- host.Serve(ctx, a) }()
		go func() { done <- raw.Run(ctx, b) }()
		t.Cleanup(func() {
			client.Close()
			_ = raw.Close()
			_ = a.Close()
			_ = b.Close()
			for index := 0; index < 2; index++ {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("principal runtime failed to stop")
				}
			}
		})
		if _, err := client.Negotiate(ctx, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}); err != nil {
			t.Fatal(err)
		}
		return client
	}
	a, b, other := open("alice"), open("alice"), open("bob")
	service.mu.Lock()
	sessions := make([]*RecoveryHostSession, 0, len(service.sessions))
	for _, session := range service.sessions {
		sessions = append(sessions, session)
	}
	service.mu.Unlock()
	requestCtx, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if _, err := a.Subscribe(requestCtx, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("withdraw")}, []byte("stream"), RecoveryInitialLiveOnly); err == nil {
		t.Fatal("withdrawn subscription succeeded")
	}
	for _, client := range []*RecoveryClient{a, b} {
		select {
		case <-client.client.done:
		case <-time.After(time.Second):
			t.Fatal("withdrawn principal connection remained open")
		}
	}
	for _, session := range sessions {
		if session.connection.Principal == "alice" {
			if !session.Revoked() || recoveryErrorCode(session.Err()) != ErrorCodeUnauthenticated {
				t.Fatal("source signal lost during teardown")
			}
		} else if session.Revoked() {
			t.Fatal("withdrawal crossed principal scope")
		}
	}
	if out, err := other.client.Call(ctx, "/example.Echo/Echo", []byte("bob usable"), 1000); err != nil || string(out) != "bob usable" {
		t.Fatal("unrelated principal was closed", err)
	}
}

func TestRecoveryTargetedGenerationFailureDrainsControlAndOtherHandle(t *testing.T) {
	for _, code := range []ErrorCode{ErrorCodePermissionDenied, ErrorCodeFailedPrecondition} {
		t.Run(ErrorCodeName(code), func(t *testing.T) {
			source := &recoveryReviewSource{recoveryTestSource: newRecoveryTestSource()}
			var fail atomic.Bool
			source.generation = func(ctx context.Context, p string, identity []byte) (uint64, error) {
				if fail.Swap(false) {
					return 0, NewRpcError(code, "target unavailable")
				}
				return source.recoveryTestSource.CurrentGeneration(ctx, p, identity)
			}
			h := recoveryReviewHost(t, source)
			a := recoveryTestSubscribeHost(t, h, "")
			b := recoveryTestSubscribeHost(t, h, "")
			ctx := context.Background()
			for _, sub := range []*pb.RecoverySubscribeResponse{a, b} {
				if _, err := h.Handle(ctx, RecoveryCatchUp, recoveryTestEncode(t, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle})); err != nil {
					t.Fatal(err)
				}
			}
			for index := 0; index < 2; index++ {
				if _, err := h.PopNotification(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if err := h.Publish(ctx, []byte("stable"), RecoveryStoredBatch{7, []byte("c"), []byte("d"), nil}); err != nil {
				t.Fatal(err)
			}
			popped, err := h.PopNotification(ctx)
			if err != nil {
				t.Fatal(err)
			}
			fail.Store(true)
			if err := h.RevalidateNotification(ctx, popped); !recoveryTargetedEgressError(ctx, h, err) {
				t.Fatal("target error classified fatal", err)
			}
			seenData, seenControl := false, false
			for index := 0; index < 2; index++ {
				next, err := h.PopNotification(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if err := h.RevalidateNotification(ctx, next); err != nil {
					t.Fatal(err)
				}
				n := new(pb.RecoveryNotification)
				if err := DecodeRecovery(next, n); err != nil {
					t.Fatal(err)
				}
				if batch := n.GetBatch(); batch != nil {
					seenData = bytes.Equal(batch.SubscriptionHandle, b.SubscriptionHandle)
				}
				if trailer := n.GetTrailer(); trailer != nil {
					seenControl = trailer.GetTerminated() && bytes.Equal(trailer.SubscriptionHandle, a.SubscriptionHandle)
				}
			}
			if !seenData || !seenControl || h.Revoked() {
				t.Fatal("target failure lost control or damaged other handle")
			}
		})
	}
}

func TestRecoveryCatchUpProviderDenialEndsOnlyTarget(t *testing.T) {
	source := &recoveryReviewSource{recoveryTestSource: newRecoveryTestSource()}
	var denied atomic.Int32
	source.replay = func(ctx context.Context, p string, stream RecoveryProviderStream, from, marker []byte, budget RecoveryPageBudget) (RecoveryProviderPage, error) {
		if string(from) == "b" {
			denied.Add(1)
			return RecoveryProviderPage{}, NewRpcError(ErrorCodePermissionDenied, "target denied")
		}
		return source.recoveryTestSource.Replay(ctx, p, stream, from, marker, budget)
	}
	h := recoveryReviewHost(t, source)
	a := recoveryTestSubscribeHost(t, h, "a")
	b := recoveryTestSubscribeHost(t, h, "")
	ctx := context.Background()
	for _, sub := range []*pb.RecoverySubscribeResponse{a, b} {
		if _, err := h.Handle(ctx, RecoveryCatchUp, recoveryTestEncode(t, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle})); err != nil {
			t.Fatal(err)
		}
	}
	for index := 0; index < 3; index++ {
		payload, err := h.PopNotification(ctx)
		if err != nil {
			t.Fatal("targeted provider error escaped to connection", err)
		}
		if err := h.RevalidateNotification(ctx, payload); err != nil {
			t.Fatal(err)
		}
	}
	if denied.Load() != 1 {
		t.Fatal("provider denial was retried indefinitely")
	}
	if err := h.Publish(ctx, []byte("stable"), RecoveryStoredBatch{7, []byte("c"), []byte("d"), nil}); err != nil {
		t.Fatal(err)
	}
	payload, err := h.PopNotification(ctx)
	if err != nil {
		t.Fatal(err)
	}
	n := new(pb.RecoveryNotification)
	if err := DecodeRecovery(payload, n); err != nil {
		t.Fatal(err)
	}
	if n.GetBatch() == nil || !bytes.Equal(n.GetBatch().SubscriptionHandle, b.SubscriptionHandle) {
		t.Fatal("healthy handle did not continue")
	}
}
