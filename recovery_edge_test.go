package syntra

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestRecoveryMandatoryOnlyRemainsUsable(t *testing.T) {
	rawClient, err := OpenClient(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewRecoveryClient(rawClient, "alice", recoveryTestStore(t), DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	host, err := OpenHost(testHostConfig())
	if err != nil {
		t.Fatal(err)
	}
	a, b := LoopbackPair()
	done := make(chan error, 2)
	go func() { done <- host.Serve(ctx, a) }()
	go func() { done <- rawClient.Run(ctx, b) }()
	t.Cleanup(func() {
		cancel()
		_ = rawClient.Close()
		_ = host.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("mandatory-only session did not stop")
			}
		}
	})
	_, err = c.Negotiate(ctx, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability})
	if recoveryErrorCode(err) != ErrorCodeUnimplemented || c.Inbox().Enabled() {
		t.Fatal("mandatory-only negotiation", err)
	}
	if _, err := rawClient.Call(ctx, "/example.Echo/Echo", []byte("still usable"), 1000); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryHostRetryBudgetExpiryAndGenerationFencing(t *testing.T) {
	l := DefaultRecoveryLimits()
	l.ReplyRetries = 1
	l.ReplyTTL = 10 * time.Millisecond
	src := newRecoveryTestSource()
	h := recoveryTestHost(t, src, l)
	recoveryTestNegotiate(t, h)
	sub := recoveryTestSubscribeHost(t, h, "a")
	q := recoveryTestEncode(t, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096})
	for i := 0; i < 2; i++ {
		if _, err := h.Handle(context.Background(), RecoveryReplay, q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := h.Handle(context.Background(), RecoveryReplay, q); err == nil {
		t.Fatal("unbounded retries")
	}
	if src.replays != 1 {
		t.Fatal("retry provider effects")
	}
	h2 := recoveryTestHost(t, newRecoveryTestSource(), l)
	recoveryTestNegotiate(t, h2)
	sub2 := recoveryTestSubscribeHost(t, h2, "a")
	q = recoveryTestEncode(t, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: sub2.SubscriptionHandle, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096})
	if _, err := h2.Handle(context.Background(), RecoveryReplay, q); err != nil {
		t.Fatal(err)
	}
	time.Sleep(15 * time.Millisecond)
	if _, err := h2.Handle(context.Background(), RecoveryReplay, q); err == nil {
		t.Fatal("expired retry accepted")
	}
	// An exact retained reply cannot bypass a scoped continuity change.
	src.mu.Lock()
	src.generation = 8
	src.mu.Unlock()
	if _, err := h.Handle(context.Background(), RecoveryReplay, recoveryTestEncode(t, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096})); err == nil {
		t.Fatal("old generation replay")
	}
	b, err := h.PopNotification(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	n := new(pb.RecoveryNotification)
	if err := DecodeRecovery(b, n); err != nil {
		t.Fatal(err)
	}
	if n.GetTrailer().Generation != 7 || n.GetTrailer().GetNextGeneration() != 8 {
		t.Fatal("scoped continuity control")
	}
}

func TestRecoveryHostLocalOverflowAndPrincipalQuota(t *testing.T) {
	l := DefaultRecoveryLimits()
	l.QueuedMessagesPerStream = 1
	l.SubscriptionsPerPrincipal = 1
	src := newRecoveryTestSource()
	h := recoveryTestHost(t, src, l)
	recoveryTestNegotiate(t, h)
	sub := recoveryTestSubscribeHost(t, h, "")
	other, err := h.service.OpenConnection(RecoveryConnection{"other", "alice", 1})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	recoveryTestNegotiate(t, other)
	_, err = other.Handle(context.Background(), RecoverySubscribe, recoveryTestEncode(t, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}))
	if recoveryErrorCode(err) != ErrorCodeResourceExhausted {
		t.Fatal("principal quota", err)
	}
	for index, b := range []RecoveryStoredBatch{{7, []byte("c"), []byte("d"), nil}, {7, []byte("d"), []byte("b"), nil}} {
		err = h.Publish(context.Background(), []byte("stable"), b)
		if index == 0 && err != nil {
			t.Fatal(err)
		}
		if index == 1 && recoveryErrorCode(err) != ErrorCodeResourceExhausted {
			t.Fatal("queue overflow", err)
		}
	}
	n := new(pb.RecoveryNotification)
	payload, err := h.PopNotification(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := DecodeRecovery(payload, n); err != nil {
		t.Fatal(err)
	}
	trailer := n.GetTrailer()
	if trailer == nil || !bytes.Equal(trailer.SubscriptionHandle, sub.SubscriptionHandle) || trailer.Generation != 7 || trailer.GetNextGeneration() != 0 || string(trailer.TerminateReason) != "local-queue-exhausted" {
		t.Fatal("local overflow rebased")
	}
	// Targeted termination releases the principal quota without changing G.
	newSub := recoveryTestSubscribeHost(t, other, "")
	if newSub.Generation != 7 || bytes.Equal(sub.SubscriptionHandle, newSub.SubscriptionHandle) {
		t.Fatal("fresh delivery identity")
	}
}

func TestRecoverySnapshotHostImmutableRetryAndStaleConfirm(t *testing.T) {
	src := newRecoveryTestSource()
	h := recoveryTestHost(t, src, DefaultRecoveryLimits())
	recoveryTestNegotiate(t, h)
	sub := recoveryTestSubscribeHost(t, h, "a")
	ctx := context.Background()
	q := recoveryTestEncode(t, &pb.RecoverySnapshotOfferRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, Generation: 7})
	first, err := h.Handle(ctx, RecoverySnapshotOffer, q)
	if err != nil {
		t.Fatal(err)
	}
	again, err := h.Handle(ctx, RecoverySnapshotOffer, q)
	if err != nil || !bytes.Equal(first, again) || src.snapshots != 1 {
		t.Fatal("offer not immutable", err)
	}
	d := new(pb.RecoverySnapshotDescriptor)
	if err := DecodeRecovery(first, d); err != nil {
		t.Fatal(err)
	}
	confirm := &pb.RecoverySnapshotConfirmRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, Generation: 7, BoundaryCheckpoint: d.BoundaryCheckpoint}
	if _, err := h.Handle(ctx, RecoverySnapshotConfirm, recoveryTestEncode(t, confirm)); err == nil {
		t.Fatal("incomplete snapshot accepted")
	}
	for index := uint32(0); index < 2; index++ {
		fetch := recoveryTestEncode(t, &pb.RecoverySnapshotFetchRequest{ProfileVersion: 1, SnapshotHandle: d.SnapshotHandle, PageIndex: index})
		for repeat := 0; repeat < 2; repeat++ {
			if _, err := h.Handle(ctx, RecoverySnapshotFetch, fetch); err != nil {
				t.Fatal(err)
			}
		}
	}
	if src.fetches != 2 {
		t.Fatal("snapshot fetch retry invoked provider")
	}
	if _, err := h.Handle(ctx, RecoverySnapshotConfirm, recoveryTestEncode(t, confirm)); err != nil {
		t.Fatal(err)
	}
	src.mu.Lock()
	src.generation = 8
	src.mu.Unlock()
	if _, err := h.Handle(ctx, RecoverySnapshotConfirm, recoveryTestEncode(t, confirm)); err == nil {
		t.Fatal("stale retained install accepted")
	}
}

func TestRecoveryCodecUnknownGroupDepthAndReplayContinuity(t *testing.T) {
	message := &pb.RecoveryBatch{ProfileVersion: 1, SubscriptionHandle: []byte("h"), Generation: 7, ResultCheckpoint: []byte("b")}
	base := recoveryTestEncode(t, message)
	group := protowire.AppendTag(bytes.Clone(base), 100, protowire.StartGroupType)
	group = protowire.AppendTag(group, 101, protowire.VarintType)
	group = protowire.AppendVarint(group, 5)
	group = protowire.AppendTag(group, 100, protowire.EndGroupType)
	if err := DecodeRecovery(group, new(pb.RecoveryBatch)); err != nil {
		t.Fatal(err)
	}
	deep := bytes.Clone(base)
	for i := 0; i < 34; i++ {
		deep = protowire.AppendTag(deep, 100, protowire.StartGroupType)
	}
	for i := 0; i < 34; i++ {
		deep = protowire.AppendTag(deep, 100, protowire.EndGroupType)
	}
	if DecodeRecovery(deep, new(pb.RecoveryBatch)) == nil {
		t.Fatal("unbounded unknown nesting")
	}
	page := &pb.RecoveryReplayPage{ProfileVersion: 1, SubscriptionHandle: []byte("h"), PredecessorCheckpoint: []byte("a"), ResultCheckpoint: []byte("b"), CatchupBoundary: []byte("b"), BatchPayloads: [][]byte{base}}
	if ValidateRecovery(page) == nil {
		t.Fatal("broken replay predecessor")
	}
	message.PredecessorCheckpoint = []byte("a")
	page.BatchPayloads = [][]byte{recoveryTestEncode(t, message)}
	if err := ValidateRecovery(page); err != nil {
		t.Fatal(err)
	}
	page.ContinuationMarker = []byte("extra")
	if ValidateRecovery(page) == nil {
		t.Fatal("marker after boundary")
	}
}

func TestRecoveryClientSuppressesDurableDuplicateAndRejectsChangedGeneration(t *testing.T) {
	p := newRecoveryLoopback(t, true, false)
	sub := p.subscribe(t, true)
	handle := sub.SubscriptionHandle
	page, err := p.client.Replay(p.ctx, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: handle, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096})
	if err != nil {
		t.Fatal(err)
	}
	recoveryPersistConfirm(t, p, handle, "b")
	if err := p.client.Inbox().Push(recoveryTestEncode(t, recoveryNotification(&pb.RecoveryBatch{ProfileVersion: 1, SubscriptionHandle: handle, Generation: 7, PredecessorCheckpoint: []byte("a"), ResultCheckpoint: []byte("b"), BatchPayload: []byte("duplicate")}))); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.Replay(p.ctx, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: handle, FromCheckpoint: page.ResultCheckpoint, ContinuationMarker: page.ContinuationMarker, MaxBatches: 1, MaxBytes: 4096}); err != nil {
		t.Fatal(err)
	}
	recoveryPersistConfirm(t, p, handle, "c")
	if _, err := p.client.NextEvent(p.ctx, handle); err != nil {
		t.Fatal(err)
	}
	// The stale duplicate is discarded before waiting for another live update.
	short, cancel := context.WithTimeout(p.ctx, 10*time.Millisecond)
	defer cancel()
	if _, err := p.client.NextEvent(short, handle); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("duplicate reoffered", err)
	}
	bad := recoveryTestEncode(t, recoveryNotification(&pb.RecoveryBatch{ProfileVersion: 1, SubscriptionHandle: handle, Generation: 8, PredecessorCheckpoint: []byte("a"), ResultCheckpoint: []byte("b")}))
	if p.client.Inbox().Push(bad) == nil {
		t.Fatal("changed G reached duplicate cache")
	}
}

type recoveryBlockingStore struct {
	RecoveryPersistence
	started, release chan struct{}
	once             sync.Once
}

func (s *recoveryBlockingStore) Commit(ctx context.Context, scope PersistenceScope, expected *ExpectedPosition, r DurableRecord) error {
	s.once.Do(func() { close(s.started) })
	<-s.release
	return s.RecoveryPersistence.Commit(ctx, scope, expected, r)
}
func TestRecoveryIngressFencesCommitInFlightWithoutLosingDurableEvidence(t *testing.T) {
	p := newRecoveryLoopback(t, true, false)
	sub := p.subscribe(t, true)
	handle := sub.SubscriptionHandle
	if _, err := p.client.Replay(p.ctx, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: handle, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.NextEvent(p.ctx, handle); err != nil {
		t.Fatal(err)
	}
	store := &recoveryBlockingStore{RecoveryPersistence: p.store, started: make(chan struct{}), release: make(chan struct{})}
	p.client.store = store
	done := make(chan error, 1)
	go func() { done <- p.client.Persist(p.ctx, handle, []byte("full-state")) }()
	<-store.started
	trailer := recoveryNotification(&pb.RecoveryBatchTrailer{ProfileVersion: 1, SubscriptionHandle: handle, Generation: 7, Outcome: &pb.RecoveryBatchTrailer_Terminated{Terminated: true}, TerminateReason: []byte("revoked")})
	if err := p.client.Inbox().Push(recoveryTestEncode(t, trailer)); err != nil {
		t.Fatal(err)
	}
	close(store.release)
	var unknown *CommitUnknown
	if err := <-done; !errors.As(err, &unknown) {
		t.Fatal("commit race not fenced", err)
	}
	saved, err := p.store.Load(p.ctx, PersistenceScope{"alice", "stable"})
	if err != nil || string(saved.Checkpoint) != "b" || string(saved.ApplicationState) != "full-state" {
		t.Fatal("durable evidence lost", err)
	}
	if _, err := p.client.Confirm(p.ctx, &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: handle, Generation: 7, Checkpoint: []byte("b")}); err == nil {
		t.Fatal("terminal commit confirmed")
	}
}

func TestRecoveryTypedStagingIdentityAndLocalCompletion(t *testing.T) {
	stage, err := NewStagedSnapshot([]byte("x"), []byte("boundary"), 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	chunk := &pb.RecoverySnapshotChunk{ProfileVersion: 1, SnapshotHandle: []byte("wrong"), BoundaryCheckpoint: []byte("boundary"), PageBytes: []byte("opaque")}
	if stage.StageChunk(chunk) == nil {
		t.Fatal("cross snapshot chunk")
	}
	chunk.SnapshotHandle = []byte("x")
	if err := stage.StageChunk(chunk); err != nil {
		t.Fatal(err)
	}
	if err := stage.StageChunk(chunk); err != nil {
		t.Fatal(err)
	}
	complete, err := stage.Completion()
	if err != nil || complete.TotalPages != 1 || complete.TotalBytes != 6 {
		t.Fatal(complete, err)
	}
	if err := ValidateRecovery(complete); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryPersistenceFailureRetainsPendingOffer(t *testing.T) {
	p := newRecoveryLoopback(t, true, false)
	sub := p.subscribe(t, true)
	handle := sub.SubscriptionHandle
	if _, err := p.client.Replay(p.ctx, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: handle, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.NextEvent(p.ctx, handle); err != nil {
		t.Fatal(err)
	}
	p.store.FailNextCommit()
	if err := p.client.Persist(p.ctx, handle, []byte("full-state")); err != PersistenceUnavailable {
		t.Fatal(err)
	}
	progress, err := p.client.Progress(p.ctx, handle)
	if err != nil || string(progress.LocallyDurable.Checkpoint) != "a" || progress.ConfirmSent != nil || progress.PeerAcknowledged != nil {
		t.Fatal("failed write advanced progress", err)
	}
	q := &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: handle, Generation: 7, Checkpoint: []byte("b")}
	if _, err := p.client.Confirm(p.ctx, q); err == nil {
		t.Fatal("failed write confirmed")
	}
	if err := p.client.Persist(p.ctx, handle, []byte("full-state")); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.Confirm(p.ctx, q); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryLostConfirmResponseKeepsIndependentProgress(t *testing.T) {
	p := newRecoveryLoopback(t, true, true)
	sub := p.subscribe(t, true)
	handle := sub.SubscriptionHandle
	if _, err := p.client.Replay(p.ctx, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: handle, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.NextEvent(p.ctx, handle); err != nil {
		t.Fatal(err)
	}
	if err := p.client.Persist(p.ctx, handle, []byte("full-state")); err != nil {
		t.Fatal(err)
	}
	p.drop.mu.Lock()
	p.drop.method = RecoveryConfirm
	p.drop.dropID = 0
	p.drop.dropped = false
	p.drop.ids = nil
	p.drop.mu.Unlock()
	q := &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: handle, Generation: 7, Checkpoint: []byte("b")}
	short, cancel := context.WithTimeout(p.ctx, 15*time.Millisecond)
	defer cancel()
	if _, err := p.client.Confirm(short, q); err == nil {
		t.Fatal("lost response was acknowledged")
	}
	progress, err := p.client.Progress(p.ctx, handle)
	if err != nil || string(progress.LocallyDurable.Checkpoint) != "b" || progress.ConfirmSent == nil || string(progress.ConfirmSent.Checkpoint) != "b" || progress.PeerAcknowledged != nil {
		t.Fatal("progress observations conflated", err)
	}
	if _, err := p.client.Confirm(p.ctx, q); err != nil {
		t.Fatal("exact confirmation retry", err)
	}
	progress, err = p.client.Progress(p.ctx, handle)
	if err != nil || string(progress.PeerAcknowledged.Checkpoint) != "b" {
		t.Fatal("ack not retained", err)
	}
	p.drop.mu.Lock()
	ids := append([]uint64(nil), p.drop.ids...)
	p.drop.mu.Unlock()
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatal("retry did not get fresh request ID", ids)
	}
	if p.source.replays != 1 {
		t.Fatal("confirmation replayed application effects")
	}
}

func TestRecoverySnapshotBoundaryResumesWithoutSnapshotConfirm(t *testing.T) {
	src := newRecoveryTestSource()
	h := recoveryTestHost(t, src, DefaultRecoveryLimits())
	recoveryTestNegotiate(t, h)
	sub := recoveryTestSubscribeHost(t, h, "a")
	b, err := h.Handle(context.Background(), RecoverySnapshotOffer, recoveryTestEncode(t, &pb.RecoverySnapshotOfferRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, Generation: 7}))
	if err != nil {
		t.Fatal(err)
	}
	d := new(pb.RecoverySnapshotDescriptor)
	if err := DecodeRecovery(b, d); err != nil {
		t.Fatal(err)
	}
	h.Close()
	fresh, err := h.service.OpenConnection(RecoveryConnection{"fresh", "alice", 1})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	recoveryTestNegotiate(t, fresh)
	resumed := recoveryTestSubscribeHost(t, fresh, string(d.BoundaryCheckpoint))
	if resumed.Generation != 7 || bytes.Equal(sub.SubscriptionHandle, resumed.SubscriptionHandle) {
		t.Fatal("snapshot depended on old reply cache")
	}
}

func TestRecoveryServiceHandlerRequiresConnectionBinding(t *testing.T) {
	h := recoveryTestHost(t, newRecoveryTestSource(), DefaultRecoveryLimits())
	request := &RpcRequest{Method: RecoveryNegotiate, Payload: recoveryTestEncode(t, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability})}
	if _, err := h.service.Handler(context.Background(), request); recoveryErrorCode(err) != ErrorCodeUnimplemented {
		t.Fatal("missing binding accepted", err)
	}
	if _, err := h.service.Handler(WithRecoveryHostSession(context.Background(), h), request); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryClosedIngressNeverFallsBackToGenericQueue(t *testing.T) {
	i, err := NewRecoveryInbox(DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := i.Enable(); err != nil {
		t.Fatal(err)
	}
	i.Close()
	a, b := LoopbackPair()
	defer a.Close()
	defer b.Close()
	transport := WrapRecoveryTransport(a, nil, i)
	if _, err := transport.Recv(context.Background()); recoveryErrorCode(err) != ErrorCodeUnavailable {
		t.Fatal("closed profile ingress fell through", err)
	}
}
