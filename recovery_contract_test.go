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
	"google.golang.org/protobuf/proto"
)

type recoveryTestSource struct {
	mu                          sync.Mutex
	generation                  uint64
	boundary                    string
	replays, snapshots, fetches int
	denied                      bool
	retention                   bool
	badPage                     bool
	principals                  []string
}

func newRecoveryTestSource() *recoveryTestSource {
	return &recoveryTestSource{generation: 7, boundary: "c"}
}
func (s *recoveryTestSource) Authorize(ctx context.Context, p string, _ []byte, _ RecoveryHook) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.principals = append(s.principals, p)
	if s.denied {
		return NewRpcError(ErrorCodePermissionDenied, "denied")
	}
	return ctx.Err()
}
func (s *recoveryTestSource) Capture(_ context.Context, _ string, _ []byte) (RecoveryProviderStream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return RecoveryProviderStream{[]byte("stable"), s.generation, []byte(s.boundary)}, nil
}
func (s *recoveryTestSource) CurrentGeneration(_ context.Context, _ string, _ []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation, nil
}
func (s *recoveryTestSource) ValidateIssued(_ context.Context, p string, stream RecoveryProviderStream, cp []byte) error {
	if p != "alice" || string(stream.Identity) != "stable" || stream.Generation != 7 {
		return recoveryInvalid()
	}
	switch string(cp) {
	case "a", "b", "c", "d", "snapshot":
		return nil
	}
	return recoveryInvalid()
}
func (s *recoveryTestSource) Replay(_ context.Context, _ string, stream RecoveryProviderStream, from, marker []byte, budget RecoveryPageBudget) (RecoveryProviderPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replays++
	if s.retention {
		return RecoveryProviderPage{}, ErrRecoveryRetentionMiss
	}
	if s.badPage {
		return RecoveryProviderPage{Result: []byte("c"), Batches: []RecoveryStoredBatch{{7, []byte("wrong"), []byte("c"), []byte("x")}}}, nil
	}
	if string(stream.Boundary) != "c" {
		return RecoveryProviderPage{}, recoveryInvalid()
	}
	switch string(from) {
	case "a":
		if len(marker) != 0 {
			return RecoveryProviderPage{}, recoveryInvalid()
		}
		return RecoveryProviderPage{Batches: []RecoveryStoredBatch{{7, []byte("a"), []byte("b"), []byte("AB")}}, Result: []byte("b"), Marker: []byte("next")}, nil
	case "b":
		if string(marker) != "next" {
			return RecoveryProviderPage{}, recoveryInvalid()
		}
		return RecoveryProviderPage{Batches: []RecoveryStoredBatch{{7, []byte("b"), []byte("c"), []byte("BC")}}, Result: []byte("c")}, nil
	case "c":
		return RecoveryProviderPage{Result: []byte("c")}, nil
	}
	return RecoveryProviderPage{}, recoveryInvalid()
}
func (s *recoveryTestSource) Snapshot(_ context.Context, _ string, _ RecoveryProviderStream) (RecoveryProviderSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshots++
	return RecoveryProviderSnapshot{[]byte("source-key"), []byte("snapshot"), 2, 32}, nil
}
func (s *recoveryTestSource) SnapshotPage(_ context.Context, _ string, _ RecoveryProviderStream, _ RecoveryProviderSnapshot, index uint32) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fetches++
	if index == 0 {
		return []byte("whole-"), nil
	}
	return []byte("state"), nil
}

func recoveryTestStore(t *testing.T) *MemoryRecoveryStore {
	t.Helper()
	s, err := NewMemoryRecoveryStore(DefaultRecoveryStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func recoveryTestEncode(t *testing.T, m proto.Message) []byte {
	t.Helper()
	b, err := EncodeRecovery(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func recoveryTestHost(t *testing.T, src *recoveryTestSource, l RecoveryLimits) *RecoveryHostSession {
	t.Helper()
	service, err := NewRecoveryService(src, l)
	if err != nil {
		t.Fatal(err)
	}
	h, err := service.OpenConnection(RecoveryConnection{"connection", "alice", 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h
}
func recoveryTestNegotiate(t *testing.T, h *RecoveryHostSession) {
	t.Helper()
	_, err := h.Handle(context.Background(), RecoveryNegotiate, recoveryTestEncode(t, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}))
	if err != nil {
		t.Fatal(err)
	}
}
func recoveryTestSubscribeHost(t *testing.T, h *RecoveryHostSession, start string) *pb.RecoverySubscribeResponse {
	t.Helper()
	b, err := h.Handle(context.Background(), RecoverySubscribe, recoveryTestEncode(t, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias"), StartCheckpoint: []byte(start)}))
	if err != nil {
		t.Fatal(err)
	}
	r := new(pb.RecoverySubscribeResponse)
	if err := DecodeRecovery(b, r); err != nil {
		t.Fatal(err)
	}
	return r
}
func recoveryErrorCode(err error) ErrorCode {
	var rpc *RpcError
	if errors.As(err, &rpc) {
		return rpc.Code
	}
	return ErrorCodeUnknown
}

func TestRecoveryCodecForwardCompatibilityAndRouting(t *testing.T) {
	m := &pb.RecoveryBatch{ProfileVersion: 1, SubscriptionHandle: []byte("H"), Generation: 7, ResultCheckpoint: []byte("b")}
	b := recoveryTestEncode(t, m)
	b = protowire.AppendTag(b, 123, protowire.BytesType)
	b = protowire.AppendBytes(b, []byte("future"))
	if err := DecodeRecovery(b, new(pb.RecoveryBatch)); err != nil {
		t.Fatal(err)
	}
	for _, m := range []proto.Message{&pb.RecoveryBatch{ProfileVersion: 1, Generation: 7, ResultCheckpoint: []byte("b")}, &pb.RecoveryNotification{ProfileVersion: 1}, &pb.RecoveryBatchTrailer{ProfileVersion: 1, SubscriptionHandle: []byte("H"), Generation: 7}, &pb.RecoveryBatchTrailer{ProfileVersion: 1, SubscriptionHandle: []byte("H"), Generation: 7, Outcome: &pb.RecoveryBatchTrailer_Terminated{Terminated: false}, TerminateReason: []byte("reason")}} {
		if ValidateRecovery(m) == nil {
			t.Fatalf("accepted invalid %T", m)
		}
	}
	bad := protowire.AppendTag(nil, 1, protowire.BytesType)
	bad = protowire.AppendBytes(bad, []byte("x"))
	if DecodeRecovery(bad, new(pb.RecoveryBatch)) == nil {
		t.Fatal("wrong known wire type")
	}
	b = recoveryTestEncode(t, m)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendBytes(b, make([]byte, 257))
	if DecodeRecovery(b, new(pb.RecoveryBatch)) == nil {
		t.Fatal("oversize shadowed field")
	}
	// Defined oneofs use protobuf last-value semantics, while an unset arm fails.
	n := recoveryTestEncode(t, recoveryNotification(m))
	n = protowire.AppendTag(n, 100, protowire.VarintType)
	n = protowire.AppendVarint(n, 1)
	if err := DecodeRecovery(n, new(pb.RecoveryNotification)); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryPersistenceCASFullStateBoundsAndScope(t *testing.T) {
	s, err := NewMemoryRecoveryStore(RecoveryStoreLimits{MaxRecords: 2, MaxStateBytes: 16, MaxTotalBytes: 512})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	scope := PersistenceScope{"alice", "stream"}
	r := DurableRecord{7, []byte("a"), []byte("whole-state")}
	if err := s.Commit(ctx, scope, nil, r); err != nil {
		t.Fatal(err)
	}
	r.ApplicationState[0] = 'X'
	got, _ := s.Load(ctx, scope)
	if string(got.ApplicationState) != "whole-state" {
		t.Fatal("commit alias")
	}
	got.ApplicationState[0] = 'Y'
	again, _ := s.Load(ctx, scope)
	if string(again.ApplicationState) != "whole-state" {
		t.Fatal("load alias")
	}
	if err := s.Commit(ctx, scope, nil, *again); err != nil {
		t.Fatal("exact duplicate with stale expected", err)
	}
	if err := s.Commit(ctx, scope, nil, DurableRecord{7, []byte("b"), []byte("other")}); err != PersistenceConflict {
		t.Fatal(err)
	}
	s.FailNextCommit()
	if err := s.Commit(ctx, scope, again.Position(), DurableRecord{7, []byte("b"), []byte("other")}); err != PersistenceUnavailable {
		t.Fatal(err)
	}
	saved, _ := s.Load(ctx, scope)
	if string(saved.Checkpoint) != "a" {
		t.Fatal("failure advanced")
	}
	if saved, _ := s.Load(ctx, PersistenceScope{"bob", "stream"}); saved != nil {
		t.Fatal("cross principal state")
	}
	if err := s.Commit(ctx, PersistenceScope{"bob", "stream"}, nil, DurableRecord{7, []byte("a"), nil}); err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, PersistenceScope{"third", "stream"}, nil, DurableRecord{7, []byte("a"), nil}); err != PersistenceOverLimit {
		t.Fatal(err)
	}
	if err := s.Commit(ctx, scope, again.Position(), DurableRecord{7, []byte("b"), make([]byte, 17)}); err != PersistenceOverLimit {
		t.Fatal(err)
	}
}

func TestRecoveryHostNegotiationIsolationAndBounds(t *testing.T) {
	src := newRecoveryTestSource()
	l := DefaultRecoveryLimits()
	l.SubscriptionsPerConnection = 1
	l.HandlesPerConnection = 3
	h := recoveryTestHost(t, src, l)
	_, err := h.Handle(context.Background(), RecoverySubscribe, recoveryTestEncode(t, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}))
	if recoveryErrorCode(err) != ErrorCodeUnimplemented {
		t.Fatal(err)
	}
	_, err = h.Handle(context.Background(), RecoveryNegotiate, recoveryTestEncode(t, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: "unknown-capability"}))
	if recoveryErrorCode(err) != ErrorCodeUnimplemented {
		t.Fatal(err)
	}
	_, err = h.Handle(context.Background(), RecoveryMethodPrefix+"Future", nil)
	if recoveryErrorCode(err) != ErrorCodeUnimplemented {
		t.Fatal(err)
	}
	recoveryTestNegotiate(t, h)
	sub := recoveryTestSubscribeHost(t, h, "a")
	_, err = h.Handle(context.Background(), RecoverySubscribe, recoveryTestEncode(t, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}))
	if recoveryErrorCode(err) != ErrorCodeResourceExhausted {
		t.Fatal(err)
	}
	other, err := h.service.OpenConnection(RecoveryConnection{"other", "alice", 1})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	recoveryTestNegotiate(t, other)
	_, err = other.Handle(context.Background(), RecoveryConfirm, recoveryTestEncode(t, &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, Generation: 7, Checkpoint: []byte("b")}))
	if err == nil {
		t.Fatal("cross connection handle")
	}
	for _, p := range src.principals {
		if p != "alice" {
			t.Fatal("identity not bound")
		}
	}
}

func TestRecoveryHostFixedBoundaryExactRetriesAndModeExclusion(t *testing.T) {
	src := newRecoveryTestSource()
	h := recoveryTestHost(t, src, DefaultRecoveryLimits())
	recoveryTestNegotiate(t, h)
	sub := recoveryTestSubscribeHost(t, h, "a")
	ctx := context.Background()
	req := &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096}
	payload := recoveryTestEncode(t, req)
	a, err := h.Handle(ctx, RecoveryReplay, payload)
	if err != nil {
		t.Fatal(err)
	}
	// Unknown fields do not change the semantic retry key.
	unknown := protowire.AppendTag(bytes.Clone(payload), 99, protowire.VarintType)
	unknown = protowire.AppendVarint(unknown, 1)
	b, err := h.Handle(ctx, RecoveryReplay, unknown)
	if err != nil || !bytes.Equal(a, b) || src.replays != 1 {
		t.Fatalf("retry effects: %v %d", err, src.replays)
	}
	_, err = h.Handle(ctx, RecoveryCatchUp, recoveryTestEncode(t, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle}))
	if err == nil {
		t.Fatal("mixed recovery modes")
	}
	req.FromCheckpoint = []byte("b")
	req.ContinuationMarker = []byte("wrong")
	if _, err = h.Handle(ctx, RecoveryReplay, recoveryTestEncode(t, req)); err == nil {
		t.Fatal("wrong marker")
	}
	req.ContinuationMarker = []byte("next")
	b, err = h.Handle(ctx, RecoveryReplay, recoveryTestEncode(t, req))
	if err != nil {
		t.Fatal(err)
	}
	page := new(pb.RecoveryReplayPage)
	if err := DecodeRecovery(b, page); err != nil {
		t.Fatal(err)
	}
	if string(page.CatchupBoundary) != "c" {
		t.Fatal("moved boundary")
	}
	completion, err := h.PopNotification(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.Handle(ctx, RecoveryReplay, recoveryTestEncode(t, req)); err != nil {
		t.Fatal(err)
	}
	completion2, err := h.PopNotification(ctx)
	if err != nil || !bytes.Equal(completion, completion2) {
		t.Fatal("completion retry changed", err)
	}
	req.FromCheckpoint = []byte("a")
	req.ContinuationMarker = nil
	if _, err = h.Handle(ctx, RecoveryReplay, recoveryTestEncode(t, req)); err == nil {
		t.Fatal("same handle second round")
	}
	if src.replays != 2 {
		t.Fatal("provider repeated", src.replays)
	}
	_, err = h.Handle(ctx, RecoveryConfirm, recoveryTestEncode(t, &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, Generation: 7, Checkpoint: []byte("c")}))
	if err == nil {
		t.Fatal("out-of-order confirm")
	}
	for _, cp := range []string{"b", "c"} {
		q := recoveryTestEncode(t, &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: sub.SubscriptionHandle, Generation: 7, Checkpoint: []byte(cp)})
		if _, err := h.Handle(ctx, RecoveryConfirm, q); err != nil {
			t.Fatal(err)
		}
		if _, err := h.Handle(ctx, RecoveryConfirm, q); err != nil {
			t.Fatal("confirm retry", err)
		}
	}
}

type recoveryDropTransport struct {
	Transport
	mu      sync.Mutex
	ids     []uint64
	dropID  uint64
	dropped bool
	method  string
}

func (d *recoveryDropTransport) Send(ctx context.Context, raw []byte) error {
	f, err := UnmarshalFrame(raw)
	if err == nil && f.GetRequest() != nil {
		d.mu.Lock()
		method := d.method
		if method == "" {
			method = RecoveryReplay
		}
		if f.GetRequest().Method == method {
			d.ids = append(d.ids, f.RequestId)
			if d.dropID == 0 {
				d.dropID = f.RequestId
			}
		}
		d.mu.Unlock()
	}
	return d.Transport.Send(ctx, raw)
}
func (d *recoveryDropTransport) Recv(ctx context.Context) ([]byte, error) {
	for {
		raw, err := d.Transport.Recv(ctx)
		if err != nil {
			return nil, err
		}
		f, err := UnmarshalFrame(raw)
		if err == nil && f.GetResult() != nil {
			d.mu.Lock()
			drop := !d.dropped && f.RequestId == d.dropID && d.dropID != 0
			if drop {
				d.dropped = true
			}
			d.mu.Unlock()
			if drop {
				continue
			}
		}
		return raw, nil
	}
}

type recoveryLoopback struct {
	client *RecoveryClient
	host   *RecoveryHostSession
	source *recoveryTestSource
	store  *MemoryRecoveryStore
	ctx    context.Context
	drop   *recoveryDropTransport
}

func newRecoveryLoopback(t *testing.T, resume, drop bool) *recoveryLoopback {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	src := newRecoveryTestSource()
	l := DefaultRecoveryLimits()
	service, err := NewRecoveryService(src, l)
	if err != nil {
		t.Fatal(err)
	}
	h, err := OpenHost(HostConfig{MinVersion: 1, MaxVersion: 1, Policy: StaticPolicy("alice", true), Authorize: AllowAllAuthorize, Recovery: service})
	if err != nil {
		t.Fatal(err)
	}
	ccfg := testClientConfig()
	ccfg.NotifyBuffer = 1
	rawClient, err := OpenClient(ccfg)
	if err != nil {
		t.Fatal(err)
	}
	store := recoveryTestStore(t)
	if resume {
		if err := store.Commit(ctx, PersistenceScope{"alice", "stable"}, nil, DurableRecord{7, []byte("a"), []byte("A")}); err != nil {
			t.Fatal(err)
		}
	}
	clientLimits := l
	if drop {
		clientLimits.DefaultDeadline = 50 * time.Millisecond
	}
	c, err := NewRecoveryClient(rawClient, "alice", store, clientLimits)
	if err != nil {
		t.Fatal(err)
	}
	a, b := LoopbackPair()
	d := &recoveryDropTransport{Transport: b}
	var clientTransport Transport = b
	if drop {
		clientTransport = d
	}
	done := make(chan error, 2)
	go func() { done <- h.Serve(ctx, a) }()
	go func() { done <- rawClient.Run(ctx, clientTransport) }()
	t.Cleanup(func() {
		cancel()
		c.Close()
		_ = rawClient.Close()
		_ = h.Close()
		_ = a.Close()
		_ = b.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("loopback worker did not stop")
			}
		}
	})
	if _, err := c.Negotiate(ctx, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	var hs *RecoveryHostSession
	for connection := range h.conns {
		hs = connection.recovery
	}
	h.mu.Unlock()
	if hs == nil {
		t.Fatal("missing runtime recovery binding")
	}
	return &recoveryLoopback{c, hs, src, store, ctx, d}
}
func (p *recoveryLoopback) subscribe(t *testing.T, resume bool) *pb.RecoverySubscribeResponse {
	t.Helper()
	req := &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("alias")}
	intent := RecoveryInitialLiveOnly
	if resume {
		req.StartCheckpoint = []byte("a")
		intent = RecoveryResumeDurable
	}
	s, err := p.client.Subscribe(p.ctx, req, []byte("stable"), intent)
	if err != nil {
		t.Fatal(err)
	}
	return s.Response
}
func recoveryPersistConfirm(t *testing.T, p *recoveryLoopback, h []byte, want string) {
	t.Helper()
	event, err := p.client.NextEvent(p.ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	if event.Batch == nil || string(event.Batch.ResultCheckpoint) != want {
		t.Fatalf("unexpected batch %#v", event)
	}
	before, err := p.client.Progress(p.ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	q := &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: h, Generation: 7, Checkpoint: []byte(want)}
	if _, err := p.client.Confirm(p.ctx, q); err == nil {
		t.Fatal("confirmed before persistence")
	}
	if err := p.client.Persist(p.ctx, h, []byte("state-"+want)); err != nil {
		t.Fatal(err)
	}
	progress, _ := p.client.Progress(p.ctx, h)
	if string(progress.LocallyDurable.Checkpoint) != want || progress.ConfirmSent != nil && (before.ConfirmSent == nil || !bytes.Equal(progress.ConfirmSent.Checkpoint, before.ConfirmSent.Checkpoint)) {
		t.Fatal("persistence changed sent observation")
	}
	if _, err := p.client.Confirm(p.ctx, q); err != nil {
		t.Fatal(err)
	}
	progress, _ = p.client.Progress(p.ctx, h)
	if string(progress.PeerAcknowledged.Checkpoint) != want {
		t.Fatal("ack not recorded")
	}
}

func TestRecoveryTypedLoopbackReplayAndFreshRequestRetry(t *testing.T) {
	p := newRecoveryLoopback(t, true, true)
	sub := p.subscribe(t, true)
	h := sub.SubscriptionHandle
	q := &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: h, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096}
	page, err := p.client.Replay(p.ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if p.source.replays != 1 {
		t.Fatal("retry reran provider")
	}
	p.drop.mu.Lock()
	ids := append([]uint64(nil), p.drop.ids...)
	p.drop.mu.Unlock()
	if len(ids) != 2 || ids[0] == ids[1] || ids[0] == 0 {
		t.Fatalf("request IDs %v", ids)
	}
	recoveryPersistConfirm(t, p, h, "b")
	q.FromCheckpoint = page.ResultCheckpoint
	q.ContinuationMarker = page.ContinuationMarker
	if _, err := p.client.Replay(p.ctx, q); err != nil {
		t.Fatal(err)
	}
	recoveryPersistConfirm(t, p, h, "c")
	event, err := p.client.NextEvent(p.ctx, h)
	if err != nil || !event.CaughtUp {
		t.Fatal("completion", event, err)
	}
	if _, err := p.client.Unsubscribe(p.ctx, &pb.RecoveryUnsubscribeRequest{ProfileVersion: 1, SubscriptionHandle: h}); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryTypedLoopbackCatchUpHeldLiveAndInitial(t *testing.T) {
	p := newRecoveryLoopback(t, true, false)
	sub := p.subscribe(t, true)
	h := sub.SubscriptionHandle
	if err := p.host.Publish(p.ctx, []byte("stable"), RecoveryStoredBatch{7, []byte("c"), []byte("d"), []byte("CD")}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.CatchUp(p.ctx, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: h}); err != nil {
		t.Fatal(err)
	}
	recoveryPersistConfirm(t, p, h, "b")
	recoveryPersistConfirm(t, p, h, "c")
	event, err := p.client.NextEvent(p.ctx, h)
	if err != nil || !event.CaughtUp {
		t.Fatal("held live escaped boundary", event, err)
	}
	recoveryPersistConfirm(t, p, h, "d")
	if d, _ := p.client.client.LossTotals(); d != 0 {
		t.Fatal("recovery used generic lossy queue")
	}
	initial := newRecoveryLoopback(t, false, false)
	live := initial.subscribe(t, false)
	if _, err := initial.client.CatchUp(initial.ctx, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: live.SubscriptionHandle}); err != nil {
		t.Fatal(err)
	}
	event, err = initial.client.NextEvent(initial.ctx, live.SubscriptionHandle)
	if err != nil || string(event.InitialLiveBaseline) != "c" {
		t.Fatal(event, err)
	}
	progress, _ := initial.client.Progress(initial.ctx, live.SubscriptionHandle)
	if progress.LocallyDurable != nil {
		t.Fatal("initial baseline claimed durable history")
	}
	if initial.source.replays != 0 {
		t.Fatal("initial replayed")
	}
}

func TestRecoveryTypedLoopbackSnapshotPreservesBoundaryGeneration(t *testing.T) {
	p := newRecoveryLoopback(t, true, false)
	p.source.mu.Lock()
	p.source.retention = true
	p.source.mu.Unlock()
	sub := p.subscribe(t, true)
	h := sub.SubscriptionHandle
	if _, err := p.client.CatchUp(p.ctx, &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: h}); err == nil {
		t.Fatal("retention accepted")
	}
	event, err := p.client.NextEvent(p.ctx, h)
	if err != nil || event.Trailer == nil || !event.Trailer.GetSnapshotRequired() {
		t.Fatal(event, err)
	}
	d, err := p.client.SnapshotOffer(p.ctx, &pb.RecoverySnapshotOfferRequest{ProfileVersion: 1, SubscriptionHandle: h, Generation: 7})
	if err != nil {
		t.Fatal(err)
	}
	q := &pb.RecoverySnapshotConfirmRequest{ProfileVersion: 1, SubscriptionHandle: h, Generation: 7, BoundaryCheckpoint: d.BoundaryCheckpoint}
	if _, err := p.client.SnapshotConfirm(p.ctx, q); err == nil {
		t.Fatal("unpersisted snapshot confirmed")
	}
	for _, index := range []uint32{1, 0, 1} {
		if _, err := p.client.SnapshotFetch(p.ctx, &pb.RecoverySnapshotFetchRequest{ProfileVersion: 1, SnapshotHandle: d.SnapshotHandle, PageIndex: index}); err != nil {
			t.Fatal(err)
		}
	}
	if p.source.fetches != 2 {
		t.Fatal("fetch retry repeated provider", p.source.fetches)
	}
	state, err := p.client.SnapshotBytes(p.ctx, h)
	if err != nil || string(state) != "whole-state" {
		t.Fatal(string(state), err)
	}
	if err := p.client.Persist(p.ctx, h, state); err != nil {
		t.Fatal(err)
	}
	out, err := p.client.SnapshotConfirm(p.ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if out.Generation != 7 || !bytes.Equal(out.BoundaryCheckpoint, d.BoundaryCheckpoint) {
		t.Fatal("snapshot rebased")
	}
	if _, err := p.client.SnapshotConfirm(p.ctx, q); err != nil {
		t.Fatal("snapshot confirm retry", err)
	}
	saved, _ := p.store.Load(p.ctx, PersistenceScope{"alice", "stable"})
	if saved.Generation != 7 || string(saved.Checkpoint) != "snapshot" || string(saved.ApplicationState) != "whole-state" {
		t.Fatal("full state not persisted")
	}
	if err := p.host.Publish(p.ctx, []byte("stable"), RecoveryStoredBatch{7, []byte("snapshot"), []byte("d"), []byte("live")}); err != nil {
		t.Fatal(err)
	}
	recoveryPersistConfirm(t, p, h, "d")
	if _, err := p.client.SnapshotConfirm(p.ctx, q); err != nil {
		t.Fatal("retained snapshot retry", err)
	}
	progress, err := p.client.Progress(p.ctx, h)
	if err != nil || string(progress.LocallyDurable.Checkpoint) != "d" || string(progress.PeerAcknowledged.Checkpoint) != "d" {
		t.Fatal("snapshot retry rewound live progress", err)
	}
}

func TestRecoveryInboxOverflowReservedControlsAndIsolation(t *testing.T) {
	l := DefaultRecoveryLimits()
	l.QueuedMessagesPerStream = 1
	i, err := NewRecoveryInbox(l)
	if err != nil {
		t.Fatal(err)
	}
	if err := i.Enable(); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"a", "b"} {
		if err := i.begin(); err != nil {
			t.Fatal(err)
		}
		if err := i.register([]byte(h), 7, h); err != nil {
			t.Fatal(err)
		}
	}
	batch := func(h, result string) []byte {
		return recoveryTestEncode(t, recoveryNotification(&pb.RecoveryBatch{ProfileVersion: 1, SubscriptionHandle: []byte(h), Generation: 7, ResultCheckpoint: []byte(result)}))
	}
	if err := i.Push(batch("a", "one")); err != nil {
		t.Fatal(err)
	}
	if err := i.Push(batch("b", "other")); err != nil {
		t.Fatal(err)
	}
	if err := i.Push(batch("a", "two")); err != nil {
		t.Fatal(err)
	}
	n, err := i.pop(context.Background(), []byte("a"), true, true)
	if err != nil {
		t.Fatal(err)
	}
	if n.GetTrailer() == nil || string(n.GetTrailer().TerminateReason) != "local-queue-exhausted" || n.GetTrailer().Generation != 7 || n.GetTrailer().GetNextGeneration() != 0 {
		t.Fatal("wrong local overflow control")
	}
	n, err = i.pop(context.Background(), []byte("b"), true, true)
	if err != nil || string(n.GetBatch().ResultCheckpoint) != "other" {
		t.Fatal("other stream damaged", err)
	}
	i.retire([]byte("a"))
	if err := i.Push(batch("a", "late")); err != nil {
		t.Fatal(err)
	}
	if i.Counts().DataMessages != 0 {
		t.Fatal("retired delivery retained")
	}
}

type recoveryUnknownStore struct{ RecoveryPersistence }

func (s recoveryUnknownStore) Commit(context.Context, PersistenceScope, *ExpectedPosition, DurableRecord) error {
	return &CommitUnknown{}
}
func TestRecoveryCommitUnknownNeverConfirms(t *testing.T) {
	p := newRecoveryLoopback(t, true, false)
	sub := p.subscribe(t, true)
	h := sub.SubscriptionHandle
	if _, err := p.client.Replay(p.ctx, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: h, FromCheckpoint: []byte("a"), MaxBatches: 1, MaxBytes: 4096}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.NextEvent(p.ctx, h); err != nil {
		t.Fatal(err)
	}
	p.client.store = recoveryUnknownStore{p.store}
	err := p.client.Persist(p.ctx, h, []byte("full-state"))
	var unknown *CommitUnknown
	if !errors.As(err, &unknown) {
		t.Fatal(err)
	}
	if _, err := p.client.Confirm(p.ctx, &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: h, Generation: 7, Checkpoint: []byte("b")}); err == nil {
		t.Fatal("unknown commit confirmed")
	}
	saved, _ := p.store.Load(p.ctx, PersistenceScope{"alice", "stable"})
	if string(saved.Checkpoint) != "a" {
		t.Fatal("advanced unknown state")
	}
}
