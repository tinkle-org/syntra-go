package syntra

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/proto"
)

type RecoveryHook string

const (
	RecoveryHookSubscribe       RecoveryHook = "subscribe"
	RecoveryHookReplay          RecoveryHook = "replay"
	RecoveryHookCatchUp         RecoveryHook = "catch-up"
	RecoveryHookConfirm         RecoveryHook = "confirm"
	RecoveryHookSnapshotOffer   RecoveryHook = "snapshot-offer"
	RecoveryHookSnapshotFetch   RecoveryHook = "snapshot-fetch"
	RecoveryHookSnapshotConfirm RecoveryHook = "snapshot-confirm"
	RecoveryHookUnsubscribe     RecoveryHook = "unsubscribe"
	RecoveryHookEmit            RecoveryHook = "emit"
)

// ErrRecoveryRetentionMiss requests snapshot fallback without changing continuity.
var ErrRecoveryRetentionMiss = errors.New("syntra: recovery retention unavailable")

type RecoveryProviderStream struct {
	Identity   []byte
	Generation uint64
	Boundary   []byte
}
type RecoveryStoredBatch struct {
	Generation                   uint64
	Predecessor, Result, Payload []byte
}
type RecoveryPageBudget struct{ MaxBatches, MaxEntryTotalBytes, MaxEntryBytes int }
type RecoveryProviderPage struct {
	Batches        []RecoveryStoredBatch
	Result, Marker []byte
}
type RecoveryProviderSnapshot struct {
	Key, Boundary    []byte
	Pages, PageBytes int
}

// RecoverySource is application-owned. Callbacks must be bounded, honor context,
// and must not reenter the session. Capture serializes publication at fixed B.
// ValidateIssued binds checkpoints to principal/stable stream/G independently of
// volatile reply caches and ordinary retention pruning, including after restart.
// Snapshot establishes the recoverable boundary/content binding before returning.
// Sources bound their own history and immutable snapshots in count, bytes and age.
type RecoverySource interface {
	Authorize(context.Context, string, []byte, RecoveryHook) error
	Capture(context.Context, string, []byte) (RecoveryProviderStream, error)
	CurrentGeneration(context.Context, string, []byte) (uint64, error)
	ValidateIssued(context.Context, string, RecoveryProviderStream, []byte) error
	Replay(context.Context, string, RecoveryProviderStream, []byte, []byte, RecoveryPageBudget) (RecoveryProviderPage, error)
	Snapshot(context.Context, string, RecoveryProviderStream) (RecoveryProviderSnapshot, error)
	SnapshotPage(context.Context, string, RecoveryProviderStream, RecoveryProviderSnapshot, uint32) ([]byte, error)
}

// RecoveryConnection is supplied only from the authenticated ACTIVE session.
type RecoveryConnection struct {
	ID, Principal string
	Version       uint32
}

type RecoveryService struct {
	source        RecoverySource
	limits        RecoveryLimits
	mu            sync.Mutex
	sessions      map[string]*RecoveryHostSession
	principals    map[string]int
	subscriptions map[string]int
}

func NewRecoveryService(source RecoverySource, l RecoveryLimits) (*RecoveryService, error) {
	if source == nil {
		return nil, recoveryInvalid()
	}
	if err := l.Validate(); err != nil {
		return nil, err
	}
	s := &RecoveryService{limits: l, sessions: make(map[string]*RecoveryHostSession), principals: make(map[string]int), subscriptions: make(map[string]int)}
	s.source = &recoveryObservedSource{source: source, service: s}
	return s, nil
}
func (s *RecoveryService) OpenConnection(c RecoveryConnection) (*RecoveryHostSession, error) {
	if c.Version != 1 || len(c.ID) == 0 || len(c.ID) > 128 || len(c.Principal) == 0 || len(c.Principal) > 1024 {
		return nil, recoveryInvalid()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[c.ID]; ok {
		return nil, recoveryInvalid()
	}
	if len(s.sessions) >= s.limits.MaxConnections || s.principals[c.Principal] >= s.limits.MaxConnectionsPerPrincipal {
		return nil, recoveryLimit()
	}
	prefix, err := NewConnectionID()
	if err != nil {
		return nil, recoverySanitize(err)
	}
	h := &RecoveryHostSession{service: s, connection: c, prefix: []byte(prefix), gate: make(chan struct{}, 1), pending: make(chan struct{}, s.limits.PendingRPCsPerConnection), wake: make(chan struct{}, 1), revokedDone: make(chan struct{}), slots: make(map[string]*recoveryHostSlot)}
	s.sessions[c.ID] = h
	s.principals[c.Principal]++
	return h, nil
}
func (s *RecoveryService) reserve(p string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscriptions[p] >= s.limits.SubscriptionsPerPrincipal {
		return recoveryLimit()
	}
	s.subscriptions[p]++
	return nil
}
func (s *RecoveryService) release(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.subscriptions[p]--
	if s.subscriptions[p] <= 0 {
		delete(s.subscriptions, p)
	}
}

type recoveryReply struct {
	key, data []byte
	expires   time.Time
	retries   int
}
type recoveryHostSnapshot struct {
	descriptor *pb.RecoverySnapshotDescriptor
	source     RecoveryProviderSnapshot
	fetched    [256]bool
	installed  bool
}
type recoveryHostSlot struct {
	handle, selector                []byte
	stream                          RecoveryProviderStream
	start, cursor, marker, liveTail []byte
	mode                            string
	complete, retired, quota        bool
	data, held                      []*pb.RecoveryNotification
	completion, terminal            *pb.RecoveryNotification
	terminalIssued                  *pb.RecoveryNotification
	completionPending               bool
	offered                         [][]byte
	lastConfirm                     []byte
	snapshot                        *recoveryHostSnapshot
	replies                         map[string]*recoveryReply
}

// RecoveryHostSession owns exactly one connection's negotiation and handle space.
// The parent calls Handler for admitted RPCs, drains NextNotification through its
// bounded ordered writer, and calls Close on every teardown path.
type RecoveryHostSession struct {
	service       *RecoveryService
	connection    RecoveryConnection
	gate, pending chan struct{}
	wake          chan struct{}
	closed        atomic.Bool
	revoked       atomic.Bool
	revokedDone   chan struct{}
	negotiated    bool
	serial        uint64
	prefix        []byte
	slots         map[string]*recoveryHostSlot
	order         []string
	roundRobin    int
}

func (h *RecoveryHostSession) lock(ctx context.Context) error {
	if err := h.Err(); err != nil {
		return err
	}
	select {
	case h.gate <- struct{}{}:
	case <-h.revokedDone:
		return h.Err()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := h.Err(); err != nil {
		<-h.gate
		return err
	}
	return nil
}
func (h *RecoveryHostSession) unlock() { <-h.gate }
func (h *RecoveryHostSession) signal() {
	select {
	case h.wake <- struct{}{}:
	default:
	}
}
func (h *RecoveryHostSession) Close() {
	if h.closed.Swap(true) {
		return
	}
	h.signal()
	h.gate <- struct{}{}
	defer h.unlock()
	for _, slot := range h.slots {
		h.release(slot)
	}
	h.slots = nil
	h.order = nil
	s := h.service
	s.mu.Lock()
	delete(s.sessions, h.connection.ID)
	s.principals[h.connection.Principal]--
	if s.principals[h.connection.Principal] <= 0 {
		delete(s.principals, h.connection.Principal)
	}
	s.mu.Unlock()
}
func (h *RecoveryHostSession) release(s *recoveryHostSlot) {
	if s.quota {
		s.quota = false
		h.service.release(h.connection.Principal)
	}
}
func (h *RecoveryHostSession) handle() ([]byte, error) {
	if h.serial >= uint64(h.service.limits.HandlesPerConnection) {
		return nil, recoveryLimit()
	}
	h.serial++
	b := make([]byte, len(h.prefix)+8)
	copy(b, h.prefix)
	binary.BigEndian.PutUint64(b[len(h.prefix):], h.serial)
	return b, nil
}
func recoveryStreamCopy(s RecoveryProviderStream) RecoveryProviderStream {
	return RecoveryProviderStream{bytes.Clone(s.Identity), s.Generation, bytes.Clone(s.Boundary)}
}
func recoverySnapshotCopy(s RecoveryProviderSnapshot) RecoveryProviderSnapshot {
	return RecoveryProviderSnapshot{bytes.Clone(s.Key), bytes.Clone(s.Boundary), s.Pages, s.PageBytes}
}
func (h *RecoveryHostSession) check(ctx context.Context, s *recoveryHostSlot, hook RecoveryHook) error {
	if err := h.Err(); err != nil {
		return err
	}
	if s.retired {
		return recoveryInvalid()
	}
	if err := h.service.source.Authorize(ctx, h.connection.Principal, bytes.Clone(s.selector), hook); err != nil {
		h.terminate(s, "authorization-ended", 0)
		return err
	}
	g, err := h.service.source.CurrentGeneration(ctx, h.connection.Principal, bytes.Clone(s.stream.Identity))
	if err != nil {
		if recoveryTargetedEgressCode(err) {
			h.terminate(s, "provider-binding-lost", 0)
		}
		return err
	}
	if g != s.stream.Generation {
		if g > s.stream.Generation {
			h.terminate(s, "", g)
		} else {
			h.terminate(s, "continuity-invalid", 0)
		}
		return recoveryInvalid()
	}
	if err := h.Err(); err != nil {
		return err
	}
	return ctx.Err()
}
func (h *RecoveryHostSession) terminate(s *recoveryHostSlot, reason string, next uint64) {
	t := &pb.RecoveryBatchTrailer{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), Generation: s.stream.Generation, BoundaryCheckpoint: bytes.Clone(s.stream.Boundary)}
	if next > 0 {
		t.Outcome = &pb.RecoveryBatchTrailer_NextGeneration{NextGeneration: next}
	} else {
		t.Outcome = &pb.RecoveryBatchTrailer_Terminated{Terminated: true}
		t.TerminateReason = []byte(reason)
	}
	s.terminal = recoveryNotification(t)
	s.terminalIssued = s.terminal
	s.retired = true
	s.data = nil
	s.held = nil
	s.offered = nil
	s.replies = nil
	s.completion = nil
	s.snapshot = nil
	h.release(s)
	h.signal()
}
func (h *RecoveryHostSession) retention(s *recoveryHostSlot) {
	s.data = nil
	s.offered = nil
	s.mode = "snapshot-needed"
	s.complete = false
	s.lastConfirm = nil
	s.replies = make(map[string]*recoveryReply)
	s.completion = nil
	s.completionPending = false
	s.terminal = recoveryNotification(&pb.RecoveryBatchTrailer{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), Generation: s.stream.Generation, Outcome: &pb.RecoveryBatchTrailer_SnapshotRequired{SnapshotRequired: true}})
	s.terminalIssued = s.terminal
	h.signal()
}
func (h *RecoveryHostSession) finish(s *recoveryHostSlot) {
	s.complete = true
	if s.mode == "catchup" {
		s.completion = recoveryNotification(&pb.RecoveryBatchTrailer{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), Generation: s.stream.Generation, BoundaryCheckpoint: bytes.Clone(s.stream.Boundary), Outcome: &pb.RecoveryBatchTrailer_CatchupComplete{CatchupComplete: true}})
	} else {
		s.completion = recoveryNotification(&pb.RecoveryReplayComplete{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), Generation: s.stream.Generation, LiveBoundaryCheckpoint: bytes.Clone(s.stream.Boundary)})
	}
	s.completionPending = true
	h.signal()
}

func (h *RecoveryHostSession) Handler(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
	if err := h.Err(); err != nil {
		return nil, err
	}
	if req == nil {
		return nil, recoveryInvalid()
	}
	b, err := h.Handle(ctx, req.Method, req.Payload)
	if err != nil {
		return nil, err
	}
	return NewSuccessResult(b), nil
}

// Handle accepts profile payloads only after the parent has admitted the RPC.
func (h *RecoveryHostSession) Handle(ctx context.Context, method string, payload []byte) (result []byte, resultErr error) {
	defer func() {
		if h.Revoked() {
			result = nil
			resultErr = h.Err()
		}
		resultErr = recoverySanitize(resultErr)
	}()
	if err := ValidateMethod(method); err != nil {
		return nil, err
	}
	m := recoveryRequest(method)
	if m == nil {
		return nil, recoveryUnsupported()
	}
	ctx, cancel := context.WithTimeout(ctx, h.service.limits.DefaultDeadline)
	defer cancel()
	select {
	case h.pending <- struct{}{}:
		defer func() { <-h.pending }()
	default:
		return nil, recoveryLimit()
	}
	if err := h.lock(ctx); err != nil {
		return nil, err
	}
	defer h.unlock()
	if !h.negotiated && method != RecoveryNegotiate {
		return nil, recoveryUnsupported()
	}
	if err := DecodeRecovery(payload, m); err != nil {
		return nil, err
	}
	key, err := EncodeRecovery(m)
	if err != nil {
		return nil, err
	}
	if v, ok := m.(*pb.RecoveryNegotiateRequest); ok {
		if v.Capability != RecoveryCapability {
			return nil, recoveryUnsupported()
		}
		if h.negotiated || v.MinVersion > 1 || v.MaxVersion < 1 {
			return nil, recoveryInvalid()
		}
		l := h.service.limits
		out, err := EncodeRecovery(&pb.RecoveryNegotiateResponse{ProfileVersion: 1, SelectedVersion: 1, MaxSubscriptionsPerConnection: uint32(l.SubscriptionsPerConnection), MaxPendingRpcsPerConnection: uint32(l.PendingRPCsPerConnection), MaxPageBytes: uint32(l.ReplayBytes), MaxSnapshotPages: uint32(l.SnapshotPages)})
		if err == nil {
			h.negotiated = true
		}
		return out, err
	}
	if v, ok := m.(*pb.RecoverySubscribeRequest); ok {
		return h.subscribe(ctx, v)
	}
	r := m.ProtoReflect()
	field := r.Descriptor().Fields().ByName("subscription_handle")
	var s *recoveryHostSlot
	if field != nil {
		s = h.slots[string(r.Get(field).Bytes())]
	} else if v, ok := m.(*pb.RecoverySnapshotFetchRequest); ok {
		for _, candidate := range h.slots {
			if candidate.snapshot != nil && bytes.Equal(candidate.snapshot.descriptor.SnapshotHandle, v.SnapshotHandle) {
				s = candidate
				break
			}
		}
	}
	if s == nil {
		return nil, recoveryInvalid()
	}
	hook := map[string]RecoveryHook{RecoveryReplay: RecoveryHookReplay, RecoveryCatchUp: RecoveryHookCatchUp, RecoveryConfirm: RecoveryHookConfirm, RecoverySnapshotOffer: RecoveryHookSnapshotOffer, RecoverySnapshotFetch: RecoveryHookSnapshotFetch, RecoverySnapshotConfirm: RecoveryHookSnapshotConfirm, RecoveryUnsubscribe: RecoveryHookUnsubscribe}[method]
	if err := h.check(ctx, s, hook); err != nil {
		return nil, err
	}
	if method == RecoverySnapshotFetch && s.snapshot != nil && s.snapshot.installed {
		return nil, recoveryInvalid()
	}
	cacheID := method
	if v, ok := m.(*pb.RecoverySnapshotFetchRequest); ok {
		cacheID += string(rune(v.PageIndex))
	}
	if reply := s.replies[cacheID]; reply != nil && bytes.Equal(reply.key, key) {
		if time.Now().After(reply.expires) || reply.retries >= h.service.limits.ReplyRetries {
			return nil, recoveryInvalid()
		}
		reply.retries++
		if s.complete && (method == RecoveryReplay || method == RecoveryCatchUp) {
			s.completionPending = true
			h.signal()
		}
		return bytes.Clone(reply.data), nil
	}
	// Reserve cache headroom before invoking a provider. Entries are never silently
	// evicted and recomputed: exhaustion retires the affected delivery instance.
	count, size := h.replyCounts()
	if count >= h.service.limits.RetainedReplies || size+len(key) > h.service.limits.RetainedReplyBytes {
		h.terminate(s, "local-queue-exhausted", 0)
		return nil, recoveryLimit()
	}
	out, err := h.dispatch(ctx, s, m)
	if errors.Is(err, ErrRecoveryRetentionMiss) {
		if err := h.check(ctx, s, hook); err != nil {
			return nil, err
		}
		if method == RecoveryReplay || method == RecoveryCatchUp {
			h.retention(s)
		} else {
			h.terminate(s, "provider-retention-unavailable", 0)
		}
		return nil, recoveryInvalid()
	}
	if err != nil {
		return nil, err
	}
	// Retain an already-computed effect before returning a deadline. A later exact
	// retry revalidates authority and returns it without invoking the provider again.
	if ctx.Err() == nil && method != RecoveryUnsubscribe {
		if err = h.check(ctx, s, hook); err != nil {
			return nil, err
		}
	}
	data, err := EncodeRecovery(out)
	if err != nil {
		h.terminate(s, "provider-invalid", 0)
		return nil, err
	}
	if method == RecoveryUnsubscribe {
		return data, nil
	}
	if size+len(key)+len(data) > h.service.limits.RetainedReplyBytes {
		h.terminate(s, "local-queue-exhausted", 0)
		return nil, recoveryLimit()
	}
	s.replies[cacheID] = &recoveryReply{bytes.Clone(key), bytes.Clone(data), time.Now().Add(h.service.limits.ReplyTTL), 0}
	if err := h.enforce(s); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func (h *RecoveryHostSession) replyCounts() (int, int) {
	count, size := 0, 0
	for _, s := range h.slots {
		for _, r := range s.replies {
			count++
			size += len(r.key) + len(r.data)
		}
	}
	return count, size
}
func (h *RecoveryHostSession) subscribe(ctx context.Context, r *pb.RecoverySubscribeRequest) ([]byte, error) {
	active := 0
	for _, s := range h.slots {
		if !s.retired {
			active++
		}
	}
	if active >= h.service.limits.SubscriptionsPerConnection {
		return nil, recoveryLimit()
	}
	if h.serial >= uint64(h.service.limits.HandlesPerConnection) {
		return nil, recoveryLimit()
	}
	if err := h.service.reserve(h.connection.Principal); err != nil {
		return nil, err
	}
	reserved := true
	defer func() {
		if reserved {
			h.service.release(h.connection.Principal)
		}
	}()
	p := h.connection.Principal
	src := h.service.source
	if err := src.Authorize(ctx, p, bytes.Clone(r.StreamSelector), RecoveryHookSubscribe); err != nil {
		return nil, err
	}
	stream, err := src.Capture(ctx, p, bytes.Clone(r.StreamSelector))
	if err != nil {
		return nil, err
	}
	if !recoveryOpaque(stream.Identity, 1024, true) || stream.Generation == 0 || !recoveryCP(stream.Boundary) {
		return nil, recoveryInvalid()
	}
	stream = recoveryStreamCopy(stream)
	if len(r.StartCheckpoint) > 0 {
		if err := src.ValidateIssued(ctx, p, recoveryStreamCopy(stream), bytes.Clone(r.StartCheckpoint)); err != nil {
			return nil, err
		}
	}
	handle, err := h.handle()
	if err != nil {
		return nil, err
	}
	s := &recoveryHostSlot{handle: handle, selector: bytes.Clone(r.StreamSelector), stream: stream, start: bytes.Clone(r.StartCheckpoint), cursor: bytes.Clone(r.StartCheckpoint), liveTail: bytes.Clone(stream.Boundary), replies: make(map[string]*recoveryReply)}
	if len(s.cursor) == 0 {
		s.cursor = bytes.Clone(stream.Boundary)
	}
	if err := h.check(ctx, s, RecoveryHookSubscribe); err != nil {
		return nil, err
	}
	h.slots[string(handle)] = s
	s.quota = true
	h.order = append(h.order, string(handle))
	reserved = false
	return EncodeRecovery(&pb.RecoverySubscribeResponse{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(handle), Generation: stream.Generation, CatchupBoundary: bytes.Clone(stream.Boundary)})
}

func (h *RecoveryHostSession) page(ctx context.Context, s *recoveryHostSlot, maxBatches, maxBytes int) (*pb.RecoveryReplayPage, error) {
	p, err := h.service.source.Replay(ctx, h.connection.Principal, recoveryStreamCopy(s.stream), bytes.Clone(s.cursor), bytes.Clone(s.marker), RecoveryPageBudget{maxBatches, maxBytes, maxBytes})
	if err != nil {
		return nil, err
	}
	if len(p.Batches) > maxBatches || !recoveryCP(p.Result) || len(p.Marker) > 4096 {
		return nil, recoveryInvalid()
	}
	out := &pb.RecoveryReplayPage{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), PredecessorCheckpoint: bytes.Clone(s.cursor), ResultCheckpoint: bytes.Clone(p.Result), ContinuationMarker: bytes.Clone(p.Marker), CatchupBoundary: bytes.Clone(s.stream.Boundary)}
	total := 0
	for _, b := range p.Batches {
		if b.Generation != s.stream.Generation || !recoveryStoredBatchValid(b) {
			return nil, recoveryInvalid()
		}
		if err := h.service.source.ValidateIssued(ctx, h.connection.Principal, recoveryStreamCopy(s.stream), bytes.Clone(b.Result)); err != nil {
			return nil, err
		}
		entry, err := EncodeRecovery(h.batch(s, b))
		if err != nil {
			return nil, err
		}
		total += len(entry)
		if total > maxBytes {
			return nil, recoveryLimit()
		}
		out.BatchPayloads = append(out.BatchPayloads, entry)
	}
	if len(p.Marker) > 0 && bytes.Equal(p.Result, s.cursor) {
		return nil, recoveryInvalid()
	}
	if err := ValidateRecovery(out); err != nil {
		return nil, err
	}
	return out, nil
}
func (h *RecoveryHostSession) batch(s *recoveryHostSlot, b RecoveryStoredBatch) *pb.RecoveryBatch {
	return &pb.RecoveryBatch{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), Generation: b.Generation, PredecessorCheckpoint: bytes.Clone(b.Predecessor), ResultCheckpoint: bytes.Clone(b.Result), BatchPayload: bytes.Clone(b.Payload)}
}

func recoveryStoredBatchValid(b RecoveryStoredBatch) bool {
	return b.Generation > 0 && len(b.Predecessor) <= 4096 && recoveryCP(b.Result) && len(b.Payload) <= 262144
}
func (h *RecoveryHostSession) offer(s *recoveryHostSlot, cp []byte) error {
	l := h.service.limits
	size := 0
	for _, c := range s.offered {
		size += len(c)
	}
	if len(s.offered) >= l.QueuedMessagesPerStream || size+len(cp) > l.QueuedBytesPerStream {
		h.terminate(s, "local-queue-exhausted", 0)
		return recoveryLimit()
	}
	s.offered = append(s.offered, bytes.Clone(cp))
	return nil
}
func (h *RecoveryHostSession) stage(s *recoveryHostSlot, p *pb.RecoveryReplayPage) error {
	for _, entry := range p.BatchPayloads {
		b := new(pb.RecoveryBatch)
		if err := DecodeRecovery(entry, b); err != nil {
			return err
		}
		s.data = append(s.data, recoveryNotification(b))
	}
	s.cursor = bytes.Clone(p.ResultCheckpoint)
	s.marker = bytes.Clone(p.ContinuationMarker)
	if len(s.marker) == 0 {
		h.finish(s)
	}
	h.signal()
	return h.enforce(s)
}

func (h *RecoveryHostSession) dispatch(ctx context.Context, s *recoveryHostSlot, m proto.Message) (proto.Message, error) {
	src, p := h.service.source, h.connection.Principal
	l := h.service.limits
	switch r := m.(type) {
	case *pb.RecoveryReplayRequest:
		if s.mode == "catchup" || s.mode == "snapshot" || s.mode == "snapshot-needed" || len(s.start) == 0 || s.complete || !bytes.Equal(r.FromCheckpoint, s.cursor) || !bytes.Equal(r.ContinuationMarker, s.marker) || int(r.MaxBatches) > l.ReplayBatches || int(r.MaxBytes) > l.ReplayBytes {
			return nil, recoveryInvalid()
		}
		page, err := h.page(ctx, s, int(r.MaxBatches), int(r.MaxBytes))
		if err != nil {
			return nil, err
		}
		if err = h.check(ctx, s, RecoveryHookReplay); err != nil {
			return nil, err
		}
		for _, entry := range page.BatchPayloads {
			b := new(pb.RecoveryBatch)
			if err := DecodeRecovery(entry, b); err != nil {
				return nil, err
			}
			if err := h.offer(s, b.ResultCheckpoint); err != nil {
				return nil, err
			}
		}
		s.mode = "replay"
		s.cursor = bytes.Clone(page.ResultCheckpoint)
		s.marker = bytes.Clone(page.ContinuationMarker)
		if len(s.marker) == 0 {
			h.finish(s)
		}
		return page, nil
	case *pb.RecoveryCatchUpRequest:
		if s.mode != "" {
			return nil, recoveryInvalid()
		}
		var page *pb.RecoveryReplayPage
		var err error
		if !bytes.Equal(s.cursor, s.stream.Boundary) {
			page, err = h.page(ctx, s, l.ReplayBatches, l.ReplayBytes)
			if err != nil {
				return nil, err
			}
		}
		if err = h.check(ctx, s, RecoveryHookCatchUp); err != nil {
			return nil, err
		}
		s.mode = "catchup"
		if page != nil {
			if err := h.stage(s, page); err != nil {
				return nil, err
			}
		} else {
			h.finish(s)
		}
		return &pb.RecoveryCatchUpAccepted{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), Generation: s.stream.Generation, CatchupBoundary: bytes.Clone(s.stream.Boundary)}, nil
	case *pb.RecoveryConfirmRequest:
		if r.Generation != s.stream.Generation || s.mode == "snapshot-needed" || (s.mode == "snapshot" && !s.snapshot.installed) {
			return nil, recoveryInvalid()
		}
		if !bytes.Equal(r.Checkpoint, s.lastConfirm) {
			if len(s.offered) == 0 || !bytes.Equal(s.offered[0], r.Checkpoint) {
				return nil, recoveryInvalid()
			}
			if err := src.ValidateIssued(ctx, p, recoveryStreamCopy(s.stream), bytes.Clone(r.Checkpoint)); err != nil {
				return nil, err
			}
			if err := h.check(ctx, s, RecoveryHookConfirm); err != nil {
				return nil, err
			}
			s.offered = s.offered[1:]
			s.lastConfirm = bytes.Clone(r.Checkpoint)
		}
		return &pb.RecoveryConfirmResponse{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), Generation: s.stream.Generation, ConfirmedCheckpoint: bytes.Clone(r.Checkpoint)}, nil
	case *pb.RecoverySnapshotOfferRequest:
		if r.Generation != s.stream.Generation || s.snapshot != nil {
			return nil, recoveryInvalid()
		}
		x, err := src.Snapshot(ctx, p, recoveryStreamCopy(s.stream))
		if err != nil {
			return nil, err
		}
		if !recoveryHandle(x.Key) || !recoveryCP(x.Boundary) || x.Pages < 1 || x.Pages > l.SnapshotPages || x.PageBytes < 1 || x.PageBytes > l.SnapshotPageBytes {
			return nil, recoveryInvalid()
		}
		x = recoverySnapshotCopy(x)
		if err := src.ValidateIssued(ctx, p, recoveryStreamCopy(s.stream), bytes.Clone(x.Boundary)); err != nil {
			return nil, err
		}
		handle, err := h.handle()
		if err != nil {
			return nil, err
		}
		d := &pb.RecoverySnapshotDescriptor{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), SnapshotHandle: handle, BoundaryCheckpoint: bytes.Clone(x.Boundary), TotalPages: uint32(x.Pages), PageBytesMax: uint32(x.PageBytes)}
		s.snapshot = &recoveryHostSnapshot{descriptor: d, source: x}
		s.mode = "snapshot"
		s.complete = false
		s.completion = nil
		s.completionPending = false
		s.terminal = nil
		s.terminalIssued = nil
		s.data = nil
		s.offered = nil
		s.lastConfirm = nil
		s.replies = make(map[string]*recoveryReply)
		return d, nil
	case *pb.RecoverySnapshotFetchRequest:
		x := s.snapshot
		if x == nil || x.installed || int(r.PageIndex) >= x.source.Pages || !bytes.Equal(r.SnapshotHandle, x.descriptor.SnapshotHandle) {
			return nil, recoveryInvalid()
		}
		page, err := src.SnapshotPage(ctx, p, recoveryStreamCopy(s.stream), recoverySnapshotCopy(x.source), r.PageIndex)
		if err != nil {
			return nil, err
		}
		if len(page) == 0 || len(page) > x.source.PageBytes {
			return nil, recoveryInvalid()
		}
		if err := h.check(ctx, s, RecoveryHookSnapshotFetch); err != nil {
			return nil, err
		}
		x.fetched[r.PageIndex] = true
		return &pb.RecoverySnapshotChunk{ProfileVersion: 1, SnapshotHandle: bytes.Clone(r.SnapshotHandle), PageIndex: r.PageIndex, PageBytes: bytes.Clone(page), BoundaryCheckpoint: bytes.Clone(x.source.Boundary)}, nil
	case *pb.RecoverySnapshotConfirmRequest:
		x := s.snapshot
		if x == nil || x.installed || r.Generation != s.stream.Generation || !bytes.Equal(r.BoundaryCheckpoint, x.source.Boundary) {
			return nil, recoveryInvalid()
		}
		for i := 0; i < x.source.Pages; i++ {
			if !x.fetched[i] {
				return nil, recoveryInvalid()
			}
		}
		if err := src.ValidateIssued(ctx, p, recoveryStreamCopy(s.stream), bytes.Clone(r.BoundaryCheckpoint)); err != nil {
			return nil, err
		}
		if err := h.snapshotCut(s, r.BoundaryCheckpoint); err != nil {
			h.terminate(s, "snapshot-chain-gap", 0)
			return nil, err
		}
		x.installed = true
		s.complete = true
		s.cursor = bytes.Clone(r.BoundaryCheckpoint)
		s.marker = nil
		s.data = nil
		s.offered = nil
		s.lastConfirm = nil
		s.completion = nil
		s.completionPending = false
		h.signal()
		return &pb.RecoverySnapshotInstalled{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), Generation: s.stream.Generation, BoundaryCheckpoint: bytes.Clone(r.BoundaryCheckpoint)}, nil
	case *pb.RecoveryUnsubscribeRequest:
		out := &pb.RecoveryUnsubscribeResponse{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(s.handle), Generation: s.stream.Generation}
		h.terminate(s, "unsubscribed", 0)
		return out, nil
	}
	return nil, recoveryUnsupported()
}

func (h *RecoveryHostSession) snapshotCut(s *recoveryHostSlot, boundary []byte) error {
	if len(s.held) == 0 {
		s.liveTail = bytes.Clone(boundary)
		return nil
	}
	cut := -1
	if bytes.Equal(s.held[0].GetBatch().PredecessorCheckpoint, boundary) {
		cut = 0
	}
	for i, n := range s.held {
		if bytes.Equal(n.GetBatch().ResultCheckpoint, boundary) {
			cut = i + 1
		}
	}
	if cut < 0 {
		return recoveryInvalid()
	}
	s.held = s.held[cut:]
	return nil
}

func (h *RecoveryHostSession) enforce(affected *recoveryHostSlot) error {
	l := h.service.limits
	total := 0
	for _, s := range h.slots {
		size, count := 0, len(s.data)+len(s.held)
		for _, n := range s.data {
			size += proto.Size(n) + 32
		}
		for _, n := range s.held {
			size += proto.Size(n) + 32
		}
		total += size
		if size > l.QueuedBytesPerStream || count > l.QueuedMessagesPerStream {
			h.terminate(s, "local-queue-exhausted", 0)
			return recoveryLimit()
		}
	}
	if total > l.QueuedBytesPerConnection {
		h.terminate(affected, "local-queue-exhausted", 0)
		return recoveryLimit()
	}
	return nil
}

// Publish targets this authenticated connection's subscriptions for stable S.
// Publication and Capture must share the application's ordering boundary.
func (h *RecoveryHostSession) Publish(ctx context.Context, identity []byte, b RecoveryStoredBatch) (resultErr error) {
	defer func() {
		if h.Revoked() {
			resultErr = h.Err()
		}
	}()
	if !recoveryOpaque(identity, 1024, true) || !recoveryStoredBatchValid(b) {
		return recoveryInvalid()
	}
	if err := h.lock(ctx); err != nil {
		return err
	}
	defer h.unlock()
	defer h.signal()
	for _, key := range h.order {
		s := h.slots[key]
		if s.retired || !bytes.Equal(s.stream.Identity, identity) {
			continue
		}
		if err := h.check(ctx, s, RecoveryHookEmit); err != nil {
			if s.retired && !h.Revoked() && ctx.Err() == nil {
				continue
			}
			return err
		}
		batch := h.batch(s, b)
		if err := ValidateRecovery(batch); err != nil {
			return err
		}
		if err := h.service.source.ValidateIssued(ctx, h.connection.Principal, recoveryStreamCopy(s.stream), bytes.Clone(b.Result)); err != nil {
			return err
		}
		if err := h.check(ctx, s, RecoveryHookEmit); err != nil {
			if s.retired && !h.Revoked() && ctx.Err() == nil {
				continue
			}
			return err
		}
		if b.Generation == s.stream.Generation && bytes.Equal(b.Result, s.liveTail) {
			continue
		}
		if b.Generation != s.stream.Generation || !bytes.Equal(b.Predecessor, s.liveTail) {
			h.terminate(s, "live-chain-gap", 0)
			continue
		}
		s.liveTail = bytes.Clone(b.Result)
		s.held = append(s.held, recoveryNotification(batch))
		if err := h.enforce(s); err != nil {
			return err
		}
	}
	return nil
}

func (h *RecoveryHostSession) PopNotification(ctx context.Context) (result []byte, resultErr error) {
	defer func() {
		if h.Revoked() {
			result = nil
			resultErr = h.Err()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, h.service.limits.DefaultDeadline)
	defer cancel()
	if err := h.lock(ctx); err != nil {
		return nil, err
	}
	defer h.unlock()
	n := len(h.order)
	for offset := 0; offset < n; offset++ {
		i := (h.roundRobin + offset) % n
		s := h.slots[h.order[i]]
		if s.terminal != nil {
			out := s.terminal
			s.terminal = nil
			h.roundRobin = (i + 1) % n
			return EncodeRecovery(out)
		}
		if s.retired {
			continue
		}
		if err := h.check(ctx, s, RecoveryHookEmit); err != nil {
			return h.egressFailure(s, err)
		}
		if s.mode == "catchup" && !s.complete && len(s.data) == 0 {
			p, err := h.page(ctx, s, h.service.limits.ReplayBatches, h.service.limits.ReplayBytes)
			if errors.Is(err, ErrRecoveryRetentionMiss) {
				if err := h.check(ctx, s, RecoveryHookEmit); err != nil {
					return h.egressFailure(s, err)
				}
				h.retention(s)
				out := s.terminal
				s.terminal = nil
				return EncodeRecovery(out)
			}
			if err != nil {
				return h.egressFailure(s, err)
			}
			if err := h.stage(s, p); err != nil {
				return h.egressFailure(s, err)
			}
		}
		if err := h.check(ctx, s, RecoveryHookEmit); err != nil {
			return h.egressFailure(s, err)
		}
		var out *pb.RecoveryNotification
		if len(s.data) > 0 {
			out = s.data[0]
			s.data = s.data[1:]
		} else if s.completionPending {
			s.completionPending = false
			out = s.completion
		} else if s.complete && len(s.held) > 0 {
			out = s.held[0]
			s.held = s.held[1:]
		}
		if out != nil {
			if b := out.GetBatch(); b != nil {
				if err := h.offer(s, b.ResultCheckpoint); err != nil {
					return h.egressFailure(s, err)
				}
			}
			h.roundRobin = (i + 1) % n
			return EncodeRecovery(out)
		}
	}
	return nil, nil
}

func (h *RecoveryHostSession) egressFailure(s *recoveryHostSlot, err error) ([]byte, error) {
	if h.Revoked() {
		return nil, h.Err()
	}
	if !s.retired && recoveryTargetedEgressCode(err) {
		h.terminate(s, "provider-recovery-ended", 0)
	}
	if s.terminal != nil {
		out := s.terminal
		s.terminal = nil
		return EncodeRecovery(out)
	}
	return nil, err
}
func (h *RecoveryHostSession) NextNotification(ctx context.Context) (result []byte, resultErr error) {
	defer func() {
		if h.Revoked() {
			result = nil
			resultErr = h.Err()
		}
	}()
	for {
		b, err := h.PopNotification(ctx)
		if err != nil || b != nil {
			return b, err
		}
		select {
		case <-h.revokedDone:
			return nil, h.Err()
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-h.wake:
		}
	}
}

// RevalidateNotification is called immediately before ordered writer admission.
func (h *RecoveryHostSession) RevalidateNotification(ctx context.Context, payload []byte) error {
	return h.admitNotification(ctx, payload, nil)
}

// Keep phase validation and bounded writer admission in the same operation so
// a snapshot transition cannot invalidate the unit between those two steps.
func (h *RecoveryHostSession) admitNotification(ctx context.Context, payload []byte, admit func() error) (resultErr error) {
	defer func() {
		if h.Revoked() {
			resultErr = h.Err()
		}
	}()
	n := new(pb.RecoveryNotification)
	if err := DecodeRecovery(payload, n); err != nil {
		return err
	}
	handle, g := recoveryIdentity(n)
	if err := h.lock(ctx); err != nil {
		return err
	}
	defer h.unlock()
	if err := h.revalidateNotification(n, handle, g, ctx); err != nil {
		return err
	}
	if err := h.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if admit != nil {
		return admit()
	}
	return nil
}

func (h *RecoveryHostSession) revalidateNotification(n *pb.RecoveryNotification, handle []byte, g uint64, ctx context.Context) error {
	s := h.slots[string(handle)]
	if s == nil || g != s.stream.Generation {
		return recoveryInvalid()
	}
	if s.retired {
		if proto.Equal(n, s.terminalIssued) {
			return nil
		}
		return recoveryInvalid()
	}
	if err := h.check(ctx, s, RecoveryHookEmit); err != nil {
		return err
	}
	if b := n.GetBatch(); b != nil {
		if s.mode == "snapshot-needed" || (s.mode == "snapshot" && (s.snapshot == nil || !s.snapshot.installed)) {
			return recoveryInvalid()
		}
		for _, checkpoint := range s.offered {
			if bytes.Equal(checkpoint, b.ResultCheckpoint) {
				return nil
			}
		}
		return recoveryInvalid()
	}
	if proto.Equal(n, s.completion) && s.complete {
		return nil
	}
	if s.mode == "snapshot-needed" && proto.Equal(n, s.terminalIssued) {
		return nil
	}
	return recoveryInvalid()
}
