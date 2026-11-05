package syntra

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/proto"
)

func TestRecoveryRuntimeAllNineOperations(t *testing.T) {
	p := newRecoveryLoopback(t, true, false)
	// Negotiate was performed by the integrated loopback constructor.
	sub := p.subscribe(t, true)
	for _, page := range []struct{ from, marker, result string }{
		{"a", "", "b"}, {"b", "next", "c"},
	} {
		_, err := p.client.Replay(p.ctx, &pb.RecoveryReplayRequest{
			ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle,
			FromCheckpoint: []byte(page.from), ContinuationMarker: []byte(page.marker), MaxBatches: 1, MaxBytes: 4096,
		})
		if err != nil {
			t.Fatal(err)
		}
		recoveryPersistConfirm(t, p, sub.SubscriptionHandle, page.result)
	}
	if event, err := p.client.NextEvent(p.ctx, sub.SubscriptionHandle); err != nil || !event.CaughtUp {
		t.Fatalf("replay completion = %v, %v", event, err)
	}
	if _, err := p.client.Unsubscribe(p.ctx, &pb.RecoveryUnsubscribeRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle}); err != nil {
		t.Fatal(err)
	}
	live, err := p.client.Subscribe(p.ctx, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}, []byte("live"), RecoveryInitialLiveOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.CatchUp(p.ctx, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: live.Response.SubscriptionHandle}); err != nil {
		t.Fatal(err)
	}
	if event, err := p.client.NextEvent(p.ctx, live.Response.SubscriptionHandle); err != nil || !event.CaughtUp || string(event.InitialLiveBaseline) != "c" {
		t.Fatalf("catch-up completion = %v, %v", event, err)
	}
	if err := p.host.Publish(p.ctx, []byte("stable"), RecoveryStoredBatch{7, []byte("c"), []byte("d"), []byte("CD")}); err != nil {
		t.Fatal(err)
	}
	recoveryPersistConfirm(t, p, live.Response.SubscriptionHandle, "d")
	if _, err := p.client.Unsubscribe(p.ctx, &pb.RecoveryUnsubscribeRequest{ProfileVersion: 1, SubscriptionHandle: live.Response.SubscriptionHandle}); err != nil {
		t.Fatal(err)
	}
	snapshot, err := p.client.Subscribe(p.ctx, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}, []byte("snapshot"), RecoverySnapshotCurrentGeneration)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := p.client.SnapshotOffer(p.ctx, &pb.RecoverySnapshotOfferRequest{ProfileVersion: 1, SubscriptionHandle: snapshot.Response.SubscriptionHandle, Generation: 7})
	if err != nil {
		t.Fatal(err)
	}
	for page := uint32(0); page < descriptor.TotalPages; page++ {
		if _, err := p.client.SnapshotFetch(p.ctx, &pb.RecoverySnapshotFetchRequest{ProfileVersion: 1, SnapshotHandle: descriptor.SnapshotHandle, PageIndex: page}); err != nil {
			t.Fatal(err)
		}
	}
	state, err := p.client.SnapshotBytes(p.ctx, snapshot.Response.SubscriptionHandle)
	if err != nil || string(state) != "whole-state" {
		t.Fatalf("snapshot = %q, %v", state, err)
	}
	if err := p.client.Persist(p.ctx, snapshot.Response.SubscriptionHandle, state); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.SnapshotConfirm(p.ctx, &pb.RecoverySnapshotConfirmRequest{ProfileVersion: 1, SubscriptionHandle: snapshot.Response.SubscriptionHandle, Generation: 7, BoundaryCheckpoint: descriptor.BoundaryCheckpoint}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.Unsubscribe(p.ctx, &pb.RecoveryUnsubscribeRequest{ProfileVersion: 1, SubscriptionHandle: snapshot.Response.SubscriptionHandle}); err != nil {
		t.Fatal(err)
	}
	saved, err := p.store.Load(p.ctx, PersistenceScope{"alice", "snapshot"})
	if err != nil || saved == nil || string(saved.ApplicationState) != "whole-state" || string(saved.Checkpoint) != "snapshot" {
		t.Fatalf("durable snapshot = %v, %v", saved, err)
	}
	if dropped, bytes := p.client.client.LossTotals(); dropped != 0 || bytes != 0 {
		t.Fatalf("recovery traversed lossy queues: %d, %d", dropped, bytes)
	}
	select {
	case notification := <-p.client.client.Notifications():
		t.Fatalf("profile notification reached generic queue: %v", notification)
	default:
	}
}

func TestRecoveryRuntimeAttachmentIsImmutable(t *testing.T) {
	c, err := OpenClient(ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r, err := NewRecoveryClient(c, "alice", recoveryTestStore(t), DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRecoveryClient(c, "alice", recoveryTestStore(t), DefaultRecoveryLimits()); err == nil {
		t.Fatal("second attachment accepted")
	}
	r.Close()
	if _, err := NewRecoveryClient(c, "bob", recoveryTestStore(t), DefaultRecoveryLimits()); err == nil {
		t.Fatal("retired attachment was replaced")
	}
	p := newPair(t, testClientConfig(), testHostConfig())
	if _, err := NewRecoveryClient(p.client, "alice", recoveryTestStore(t), DefaultRecoveryLimits()); err == nil {
		t.Fatal("attachment accepted after Run")
	}
}

func TestRecoveryRuntimeFactoryPreparationAndFailureCleanup(t *testing.T) {
	var recovery *RecoveryClient
	p := newPair(t, ClientConfig{Prepare: func(c *Client) error {
		var err error
		recovery, err = NewRecoveryClient(c, "alice", recoveryTestStore(t), DefaultRecoveryLimits())
		return err
	}}, testHostConfig())
	if recovery == nil || recovery.client != p.client || p.client.recoveryInbox != recovery.Inbox() {
		t.Fatal("factory preparation did not attach recovery before Run")
	}
	var failed *Client
	var failedRecovery *RecoveryClient
	sentinel := errors.New("preparation failed")
	client, err := OpenClient(ClientConfig{Credential: []byte("private"), Prepare: func(c *Client) error {
		failed = c
		var err error
		failedRecovery, err = NewRecoveryClient(c, "alice", recoveryTestStore(t), DefaultRecoveryLimits())
		if err != nil {
			return err
		}
		return sentinel
	}})
	if client != nil || !errors.Is(err, sentinel) || failed == nil || failedRecovery == nil {
		t.Fatalf("failed preparation = %v, %v", client, err)
	}
	if !failed.closed || len(failed.cfg.credential) != 0 {
		t.Fatal("failed preparation retained session or credential")
	}
	_, closed := failedRecovery.Inbox().ingressState()
	if !closed || !failed.core.(*goClientCore).closed {
		t.Fatal("failed preparation leaked profile or core")
	}
}

func TestRecoveryRuntimeWithoutServiceNeverFallsBack(t *testing.T) {
	var effects atomic.Int32
	cfg := testHostConfig()
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		effects.Add(1)
		return echoHandler(ctx, req)
	}
	p := newPair(t, testClientConfig(), cfg)
	before := effects.Load()
	for _, method := range []string{RecoveryNegotiate, RecoveryMethodPrefix + "Future"} {
		_, err := p.client.Call(context.Background(), method, nil, 1000)
		alignmentCode(t, err, ErrorCodeUnimplemented)
	}
	if effects.Load() != before {
		t.Fatal("recovery method fell through to application handler")
	}
	if err := p.host.NotifyAll([]byte("generic")); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-p.client.Notifications():
		if string(n.GetPayload()) != "generic" {
			t.Fatalf("generic notification = %v", n)
		}
	case <-time.After(time.Second):
		t.Fatal("generic notification was not delivered")
	}
}

func TestRecoveryRuntimeNegotiationEnablesBeforeNextFrame(t *testing.T) {
	for _, wrongVersion := range []bool{false, true} {
		t.Run(map[bool]string{false: "profile-validation", true: "envelope-validation"}[wrongVersion], func(t *testing.T) {
			c, err := OpenClient(ClientConfig{NotifyBuffer: 1})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewRecoveryClient(c, "alice", recoveryTestStore(t), DefaultRecoveryLimits()); err != nil {
				t.Fatal(err)
			}
			a, peer := LoopbackPair()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			done := make(chan error, 1)
			go func() { done <- c.Run(ctx, a) }()
			t.Cleanup(func() { cancel(); _ = c.Close(); _ = peer.Close() })
			alignmentRecv(t, ctx, peer)
			if err := peer.Send(ctx, mustMarshal(NewReadyFrame(1, &ServerReady{ConnectionId: "ordered-ingress"}))); err != nil {
				t.Fatal(err)
			}
			call := make(chan error, 1)
			go func() {
				// Deliberately use Call: no RecoveryClient continuation can enable
				// the inbox. The ordered receive hook must perform that transition.
				_, err := c.Call(ctx, RecoveryNegotiate, recoveryTestEncode(t, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}), 1000)
				call <- err
			}()
			request := alignmentRecv(t, ctx, peer)
			response := recoveryTestEncode(t, &pb.RecoveryNegotiateResponse{ProfileVersion: 1, SelectedVersion: 1, MaxSubscriptionsPerConnection: 1, MaxPendingRpcsPerConnection: 1, MaxPageBytes: 4096, MaxSnapshotPages: 1})
			if err := peer.Send(ctx, mustMarshal(NewResultFrame(1, request.GetRequestId(), NewSuccessResult(response)))); err != nil {
				t.Fatal(err)
			}
			version := uint32(1)
			if wrongVersion {
				version = 2
			}
			if err := peer.Send(ctx, mustMarshal(NewNotificationFrame(version, &Notification{Payload: []byte("invalid-profile")}))); err != nil {
				t.Fatal(err)
			}
			if err := <-call; err != nil {
				t.Fatal(err)
			}
			alignmentCode(t, runtimeAwait(t, done), ErrorCodeFailedPrecondition)
			for n := range c.Notifications() {
				t.Fatalf("unvalidated recovery notification fell through: %v", n)
			}
		})
	}
}

type recoveryReadyRecorder struct {
	Transport
	mu sync.Mutex
	id string
}

func (r *recoveryReadyRecorder) Send(ctx context.Context, raw []byte) error {
	if frame, err := UnmarshalFrame(raw); err == nil && frame.GetReady() != nil {
		r.mu.Lock()
		r.id = frame.GetReady().GetConnectionId()
		r.mu.Unlock()
	}
	return r.Transport.Send(ctx, raw)
}

func runtimeRecoverySession(t *testing.T, p *rawSessionPeer) *RecoveryHostSession {
	t.Helper()
	p.host.mu.Lock()
	defer p.host.mu.Unlock()
	for connection := range p.host.conns {
		if connection.recovery != nil {
			return connection.recovery
		}
	}
	t.Fatal("runtime recovery session missing")
	return nil
}

func runtimeRecoveryRPC(t *testing.T, p *rawSessionPeer, id uint64, method string, request, response proto.Message) {
	t.Helper()
	p.send(t, NewRequestFrame(1, id, &RpcRequest{Method: method, Payload: recoveryTestEncode(t, request), TimeoutMs: 1000}))
	f := p.recv(t)
	if f.GetRequestId() != id || f.GetResult().GetError() != nil {
		t.Fatalf("%s result = %v", method, f)
	}
	if err := DecodeRecovery(f.GetResult().GetPayload(), response); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryRuntimeBindsReadyAndIsolatesConnections(t *testing.T) {
	service, err := NewRecoveryService(newRecoveryTestSource(), DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	var peers []*rawSessionPeer
	var sessions []*RecoveryHostSession
	var subscriptions []*pb.RecoverySubscribeResponse
	for _, principal := range []string{"alice", "alice", "bob"} {
		cfg := testHostConfig()
		cfg.Policy = StaticPolicy(principal, true)
		cfg.Recovery = service
		recorder := &recoveryReadyRecorder{}
		p := newRawSessionPeer(t, cfg, func(tr Transport) Transport { recorder.Transport = tr; return recorder })
		session := runtimeRecoverySession(t, p)
		recorder.mu.Lock()
		id := recorder.id
		recorder.mu.Unlock()
		if session.connection.ID != id || session.connection.Principal != principal || session.connection.Version != 1 {
			t.Fatalf("Ready binding = %+v, sent %q", session.connection, id)
		}
		runtimeRecoveryRPC(t, p, 1, RecoveryNegotiate, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}, new(pb.RecoveryNegotiateResponse))
		sub := new(pb.RecoverySubscribeResponse)
		runtimeRecoveryRPC(t, p, 2, RecoverySubscribe, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}, sub)
		p.send(t, NewRequestFrame(1, 3, &RpcRequest{Method: RecoveryCatchUp, Payload: recoveryTestEncode(t, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle})}))
		result, notification := false, false
		for i := 0; i < 2; i++ {
			f := p.recv(t)
			if f.GetNotification() != nil {
				notification = true
			} else if f.GetRequestId() == 3 && f.GetResult().GetError() == nil {
				result = true
			}
		}
		if !result || !notification {
			t.Fatal("missing catch-up result or completion")
		}
		peers = append(peers, p)
		sessions = append(sessions, session)
		subscriptions = append(subscriptions, sub)
	}
	for _, p := range peers[1:] {
		p.send(t, NewRequestFrame(1, 4, &RpcRequest{Method: RecoveryConfirm, Payload: recoveryTestEncode(t, &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: subscriptions[0].SubscriptionHandle, Generation: 7, Checkpoint: []byte("d")})}))
		assertTerminalCode(t, p.recv(t), 4, ErrorCodeFailedPrecondition)
	}
	if err := sessions[0].Publish(peers[0].ctx, []byte("stable"), RecoveryStoredBatch{7, []byte("c"), []byte("d"), []byte("private")}); err != nil {
		t.Fatal(err)
	}
	if frame := peers[0].recv(t); frame.GetNotification() == nil {
		t.Fatalf("owner did not receive notification: %v", frame)
	}
	for _, p := range peers[1:] {
		ctx, cancel := context.WithTimeout(p.ctx, 30*time.Millisecond)
		_, err := p.peer.Recv(ctx)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("notification crossed connection or principal: %v", err)
		}
	}
}
