package syntra

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/proto"
)

type RecoverySubscribeIntent uint8

const (
	RecoveryInitialLiveOnly RecoverySubscribeIntent = iota + 1
	RecoveryResumeDurable
	RecoverySnapshotCurrentGeneration
)

type RecoverySubscription struct {
	Response *pb.RecoverySubscribeResponse
	Restored *DurableRecord
}
type RecoveryEvent struct {
	Batch               *pb.RecoveryBatch
	CaughtUp            bool
	InitialLiveBaseline []byte
	Trailer             *pb.RecoveryBatchTrailer
}
type recoveryClientCall struct {
	method   string
	key      []byte
	started  time.Time
	attempts int
	response []byte
}
type recoveryClientRound struct {
	scope                        PersistenceScope
	response                     *pb.RecoverySubscribeResponse
	initial                      bool
	mode                         string
	cursor, replayCursor, marker []byte
	progress                     RecoveryProgress
	expected                     *ExpectedPosition
	pending                      *pb.RecoveryBatch
	pendingDurable               bool
	snapshot                     *pb.RecoverySnapshotDescriptor
	stage                        *StagedSnapshot
	snapshotDurable              bool
	retired, retentionMiss       bool
	lastReplayKey                []byte
	calls                        map[string]*recoveryClientCall
	duplicates                   *DuplicateCache
	consumer                     atomic.Bool
}

// RecoveryClient binds one authenticated connection and application persistence
// namespace. Methods serialize stop-and-wait work; ingress is independently bounded.
// Construction attaches one immutable inbox before Client.Run. Close the
// connection when replacing identity context.
type RecoveryClient struct {
	client                                        *Client
	principal                                     string
	store                                         RecoveryPersistence
	limits                                        RecoveryLimits
	inbox                                         *RecoveryInbox
	gate                                          chan struct{}
	mu                                            sync.Mutex
	negotiationAttempted, negotiated, interrupted bool
	bounds                                        *pb.RecoveryNegotiateResponse
	rounds                                        map[string]*recoveryClientRound
}

func NewRecoveryClient(c *Client, principalScope string, store RecoveryPersistence, l RecoveryLimits) (*RecoveryClient, error) {
	if c == nil || store == nil || len(principalScope) == 0 || len(principalScope) > 1024 {
		return nil, recoveryInvalid()
	}
	inbox, err := NewRecoveryInbox(l)
	if err != nil {
		return nil, err
	}
	if err := c.attachRecoveryInbox(inbox); err != nil {
		inbox.Close()
		return nil, err
	}
	return &RecoveryClient{client: c, principal: principalScope, store: store, limits: l, inbox: inbox, gate: make(chan struct{}, 1), rounds: make(map[string]*recoveryClientRound)}, nil
}
func (c *RecoveryClient) Inbox() *RecoveryInbox { return c.inbox }
func (c *RecoveryClient) Close()                { c.inbox.Close(); c.mu.Lock(); c.interrupted = true; c.mu.Unlock() }
func (c *RecoveryClient) enter(ctx context.Context, negotiation bool) error {
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	c.mu.Lock()
	interrupted := c.interrupted
	c.mu.Unlock()
	if interrupted || (!negotiation && !c.negotiated) {
		<-c.gate
		return recoveryInvalid()
	}
	select {
	case <-c.client.done:
		<-c.gate
		return NewRpcError(ErrorCodeUnavailable, "syntra: recovery connection closed")
	default:
	}
	return nil
}
func (c *RecoveryClient) leave() { <-c.gate }
func (c *RecoveryClient) fence() { c.mu.Lock(); c.interrupted = true; c.mu.Unlock(); c.inbox.Close() }
func (c *RecoveryClient) round(handle []byte) (*recoveryClientRound, error) {
	r := c.rounds[string(handle)]
	if r == nil || r.retired {
		return nil, recoveryInvalid()
	}
	_, ok := c.inbox.status(handle)
	if !ok {
		return nil, recoveryInvalid()
	}
	return r, nil
}
func (c *RecoveryClient) retire(r *recoveryClientRound) {
	r.retired = true
	r.pending = nil
	r.stage = nil
	r.calls = nil
	c.inbox.retire(r.response.SubscriptionHandle)
}
func recoveryRetryable(err error) bool {
	var rpc *RpcError
	if errors.As(err, &rpc) {
		return rpc.Code == ErrorCodeUnavailable || rpc.Code == ErrorCodeDeadlineExceeded
	}
	return errors.Is(err, context.DeadlineExceeded)
}

// call retries only exact profile requests, each submitted through Client.Call
// with a fresh request ID. The original absolute budget is retained across calls.
// Allocation and application-state writes are never automatically retried.
func (c *RecoveryClient) call(ctx context.Context, r *recoveryClientRound, method string, request, response proto.Message, retry bool) error {
	key, err := EncodeRecovery(request)
	if err != nil {
		return err
	}
	call := &recoveryClientCall{method: method, key: key, started: time.Now()}
	if r != nil && retry {
		if old := r.calls[method]; old != nil && bytes.Equal(old.key, key) {
			call = old
		} else {
			if old != nil && old.response == nil {
				return recoveryInvalid()
			}
			r.calls[method] = call
		}
	}
	for {
		if r != nil {
			if _, ok := c.inbox.status(r.response.SubscriptionHandle); !ok {
				return recoveryInvalid()
			}
		}
		remaining := c.limits.ReplyTTL - time.Since(call.started)
		if call.attempts >= c.limits.ReplyRetries || remaining <= 0 {
			if r != nil {
				c.retire(r)
			}
			return recoveryInvalid()
		}
		budget := c.limits.DefaultDeadline
		if remaining < budget {
			budget = remaining
		}
		attempt, cancel := context.WithTimeout(ctx, budget)
		call.attempts++
		out, err := c.client.Call(attempt, method, key, roundUpToMs(budget))
		cancel()
		if err == nil {
			if err = DecodeRecovery(out, response); err != nil {
				if r != nil {
					c.retire(r)
				} else {
					c.fence()
				}
				return err
			}
			if r != nil && method != RecoveryUnsubscribe {
				if _, ok := c.inbox.status(r.response.SubscriptionHandle); !ok {
					return recoveryInvalid()
				}
			}
			canonical, err := EncodeRecovery(response)
			if err != nil {
				return err
			}
			if call.response != nil && !bytes.Equal(call.response, canonical) {
				if r != nil {
					c.retire(r)
				}
				return recoveryInvalid()
			}
			call.response = canonical
			return nil
		}
		if !retry || !recoveryRetryable(err) || ctx.Err() != nil {
			return recoverySanitize(err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *RecoveryClient) Negotiate(ctx context.Context, request *pb.RecoveryNegotiateRequest) (*pb.RecoveryNegotiateResponse, error) {
	if err := c.enter(ctx, true); err != nil {
		return nil, err
	}
	defer c.leave()
	if c.negotiationAttempted {
		return nil, recoveryInvalid()
	}
	// The explicit negotiation begins only after the mandatory handshake.
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.client.done:
		return nil, recoveryInvalid()
	case <-c.client.activated:
	}
	if err := ValidateRecovery(request); err != nil {
		return nil, err
	}
	c.negotiationAttempted = true
	out := new(pb.RecoveryNegotiateResponse)
	if err := c.call(ctx, nil, RecoveryNegotiate, request, out, false); err != nil {
		return nil, err
	}
	if request.Capability != RecoveryCapability || request.MinVersion > out.SelectedVersion || request.MaxVersion < out.SelectedVersion {
		return nil, recoveryInvalid()
	}
	c.bounds = proto.Clone(out).(*pb.RecoveryNegotiateResponse)
	c.negotiated = true
	if err := c.inbox.Enable(); err != nil {
		return nil, err
	}
	return out, nil
}

// Subscribe binds the typed request to the loaded full-state record. The stable
// stream label is application-resolved; selectors and handles are not identities.
func (c *RecoveryClient) Subscribe(ctx context.Context, request *pb.RecoverySubscribeRequest, stableStream []byte, intent RecoverySubscribeIntent) (*RecoverySubscription, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	defer c.leave()
	if err := ValidateRecovery(request); err != nil {
		return nil, err
	}
	scope := PersistenceScope{c.principal, string(stableStream)}
	if err := scope.validate(); err != nil {
		return nil, err
	}
	active := 0
	for _, r := range c.rounds {
		if !r.retired {
			active++
		}
	}
	if active >= c.limits.SubscriptionsPerConnection || active >= int(c.bounds.MaxSubscriptionsPerConnection) || len(c.rounds) >= c.limits.HandlesPerConnection {
		return nil, recoveryLimit()
	}
	saved, err := c.store.Load(ctx, scope)
	if err != nil {
		return nil, err
	}
	switch intent {
	case RecoveryInitialLiveOnly:
		if len(request.StartCheckpoint) != 0 || saved != nil {
			return nil, recoveryInvalid()
		}
	case RecoveryResumeDurable:
		if saved == nil || !bytes.Equal(saved.Checkpoint, request.StartCheckpoint) || !recoveryCP(saved.Checkpoint) || saved.Generation == 0 {
			return nil, recoveryInvalid()
		}
	case RecoverySnapshotCurrentGeneration:
		if len(request.StartCheckpoint) != 0 {
			return nil, recoveryInvalid()
		}
	default:
		return nil, recoveryInvalid()
	}
	if err := c.inbox.begin(); err != nil {
		return nil, err
	}
	defer c.inbox.cancelRegistration()
	out := new(pb.RecoverySubscribeResponse)
	if err := c.call(ctx, nil, RecoverySubscribe, request, out, false); err != nil {
		c.fence()
		return nil, err
	}
	if _, exists := c.rounds[string(out.SubscriptionHandle)]; exists {
		c.fence()
		return nil, recoveryInvalid()
	}
	if intent == RecoveryResumeDurable && saved.Generation != out.Generation {
		c.fence()
		return nil, recoveryInvalid()
	}
	if err := c.inbox.register(out.SubscriptionHandle, out.Generation, scope.Stream); err != nil {
		c.fence()
		return nil, err
	}
	r := &recoveryClientRound{scope: scope, response: proto.Clone(out).(*pb.RecoverySubscribeResponse), initial: intent == RecoveryInitialLiveOnly, cursor: bytes.Clone(request.StartCheckpoint), replayCursor: bytes.Clone(request.StartCheckpoint), calls: make(map[string]*recoveryClientCall), duplicates: NewDuplicateCache(c.limits.QueuedMessagesPerStream)}
	if len(r.cursor) == 0 {
		r.cursor = bytes.Clone(out.CatchupBoundary)
	}
	if saved != nil {
		r.expected = saved.Position()
		r.progress.LocallyDurable = saved.Position()
	}
	if intent == RecoverySnapshotCurrentGeneration {
		r.mode = "snapshot-needed"
	}
	c.rounds[string(out.SubscriptionHandle)] = r
	return &RecoverySubscription{out, saved}, nil
}

func (c *RecoveryClient) Replay(ctx context.Context, request *pb.RecoveryReplayRequest) (*pb.RecoveryReplayPage, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	defer c.leave()
	if err := ValidateRecovery(request); err != nil {
		return nil, err
	}
	r, err := c.round(request.SubscriptionHandle)
	if err != nil {
		return nil, err
	}
	key, _ := EncodeRecovery(request)
	repeat := bytes.Equal(r.lastReplayKey, key)
	if r.initial || r.mode == "catchup" || r.mode == "snapshot" || r.mode == "snapshot-needed" || (r.mode == "live" && !repeat) || r.pending != nil {
		return nil, recoveryInvalid()
	}
	if !repeat && (!bytes.Equal(request.FromCheckpoint, r.replayCursor) || !bytes.Equal(request.ContinuationMarker, r.marker) || !bytes.Equal(r.cursor, r.replayCursor)) {
		return nil, recoveryInvalid()
	}
	if int(request.MaxBatches) > c.limits.ReplayBatches || request.MaxBytes > c.bounds.MaxPageBytes {
		return nil, recoveryLimit()
	}
	out := new(pb.RecoveryReplayPage)
	if err := c.call(ctx, r, RecoveryReplay, request, out, true); err != nil {
		return nil, err
	}
	if !bytes.Equal(out.SubscriptionHandle, r.response.SubscriptionHandle) || !bytes.Equal(out.CatchupBoundary, r.response.CatchupBoundary) || !bytes.Equal(out.PredecessorCheckpoint, request.FromCheckpoint) || len(out.BatchPayloads) > int(request.MaxBatches) {
		c.retire(r)
		return nil, recoveryInvalid()
	}
	total := 0
	for _, entry := range out.BatchPayloads {
		b := new(pb.RecoveryBatch)
		if err := DecodeRecovery(entry, b); err != nil {
			return nil, err
		}
		if b.Generation != r.response.Generation {
			c.retire(r)
			return nil, recoveryInvalid()
		}
		total += len(entry)
	}
	if total > int(request.MaxBytes) {
		c.retire(r)
		return nil, recoveryLimit()
	}
	if !repeat {
		if err := c.inbox.pushReplay(out); err != nil {
			return nil, err
		}
		r.lastReplayKey = bytes.Clone(key)
		r.replayCursor = bytes.Clone(out.ResultCheckpoint)
		r.marker = bytes.Clone(out.ContinuationMarker)
		r.mode = "replay"
	}
	return out, nil
}
func (c *RecoveryClient) CatchUp(ctx context.Context, request *pb.RecoveryCatchUpRequest) (*pb.RecoveryCatchUpAccepted, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	defer c.leave()
	if err := ValidateRecovery(request); err != nil {
		return nil, err
	}
	r, err := c.round(request.SubscriptionHandle)
	if err != nil {
		return nil, err
	}
	if r.mode != "" && r.mode != "catchup" {
		return nil, recoveryInvalid()
	}
	out := new(pb.RecoveryCatchUpAccepted)
	if err := c.call(ctx, r, RecoveryCatchUp, request, out, true); err != nil {
		return nil, err
	}
	if !bytes.Equal(out.SubscriptionHandle, r.response.SubscriptionHandle) || out.Generation != r.response.Generation || !bytes.Equal(out.CatchupBoundary, r.response.CatchupBoundary) {
		c.retire(r)
		return nil, recoveryInvalid()
	}
	r.mode = "catchup"
	return out, nil
}

// NextEvent offers at most one batch until Persist and Confirm complete. Terminal
// controls take precedence over pending work and never manufacture a generation.
// One consumer may wait per handle; idle waits release the client operation gate.
func (c *RecoveryClient) NextEvent(ctx context.Context, handle []byte) (*RecoveryEvent, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	held := true
	defer func() {
		if held {
			c.leave()
		}
	}()
	handle = bytes.Clone(handle)
	r := c.rounds[string(handle)]
	if r == nil || r.retired || !r.consumer.CompareAndSwap(false, true) {
		return nil, recoveryInvalid()
	}
	defer r.consumer.Store(false)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if c.rounds[string(handle)] != r || r.retired {
			return nil, recoveryInvalid()
		}
		event, wake, err := c.nextEvent(handle)
		if event != nil || err != nil {
			return event, err
		}
		if wake == nil {
			continue
		}
		c.leave()
		held = false
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wake:
		}
		if err := c.enter(ctx, false); err != nil {
			return nil, err
		}
		held = true
	}
}

func (c *RecoveryClient) nextEvent(handle []byte) (*RecoveryEvent, <-chan struct{}, error) {
	r := c.rounds[string(handle)]
	if r == nil || r.retired {
		return nil, nil, recoveryInvalid()
	}
	if r.pending != nil {
		if _, ok := c.inbox.status(handle); ok {
			return nil, nil, recoveryInvalid()
		}
	}
	atBoundary := bytes.Equal(r.cursor, r.response.CatchupBoundary)
	recovering := r.mode == "replay" || r.mode == "catchup"
	n, wake, err := c.inbox.tryPop(handle, r.pending == nil && (r.mode == "live" || (recovering && !atBoundary)), r.pending == nil && atBoundary && recovering)
	if err != nil {
		return nil, nil, err
	}
	if n == nil {
		return nil, wake, nil
	}
	if t := n.GetTrailer(); t != nil && !t.GetCatchupComplete() {
		r.pending = nil
		r.stage = nil
		r.pendingDurable = false
		if t.GetSnapshotRequired() {
			r.mode = "snapshot-needed"
			r.retentionMiss = true
		} else {
			r.retired = true
		}
		return &RecoveryEvent{Trailer: proto.Clone(t).(*pb.RecoveryBatchTrailer)}, nil, nil
	}
	if b := n.GetBatch(); b != nil {
		if b.Generation != r.response.Generation {
			c.retire(r)
			return nil, nil, recoveryInvalid()
		}
		// Scope, handle, version and generation are checked before duplicate lookup.
		durable := r.progress.LocallyDurable
		if r.duplicates.Contains(b.ResultCheckpoint) || (durable != nil && durable.Generation == b.Generation && bytes.Equal(durable.Checkpoint, b.ResultCheckpoint)) {
			c.inbox.release(handle)
			return nil, nil, nil
		}
		if !bytes.Equal(b.PredecessorCheckpoint, r.cursor) {
			c.retire(r)
			return nil, nil, recoveryInvalid()
		}
		r.pending = proto.Clone(b).(*pb.RecoveryBatch)
		r.pendingDurable = false
		return &RecoveryEvent{Batch: proto.Clone(b).(*pb.RecoveryBatch)}, nil, nil
	}
	if !atBoundary || !bytes.Equal(recoveryCompletionBoundary(n), r.response.CatchupBoundary) {
		c.retire(r)
		return nil, nil, recoveryInvalid()
	}
	r.mode = "live"
	event := &RecoveryEvent{CaughtUp: true}
	if r.initial {
		event.InitialLiveBaseline = bytes.Clone(r.response.CatchupBoundary)
	}
	return event, nil, nil
}

// Persist commits the pending offer with full application state. It never sends
// Confirm. Failure leaves the offer pending; CommitUnknown fences the connection.
func (c *RecoveryClient) Persist(ctx context.Context, handle, state []byte) error {
	if err := c.enter(ctx, false); err != nil {
		return err
	}
	defer c.leave()
	r, err := c.round(handle)
	if err != nil {
		return err
	}
	var checkpoint []byte
	if r.pending != nil {
		if r.pendingDurable {
			return recoveryInvalid()
		}
		checkpoint = r.pending.ResultCheckpoint
	} else if r.stage != nil {
		if r.snapshotDurable {
			return recoveryInvalid()
		}
		if _, err := r.stage.Completion(); err != nil {
			return err
		}
		checkpoint = r.snapshot.BoundaryCheckpoint
	} else {
		return recoveryInvalid()
	}
	revision, ok := c.inbox.status(handle)
	if !ok {
		return recoveryInvalid()
	}
	record := DurableRecord{r.response.Generation, bytes.Clone(checkpoint), bytes.Clone(state)}
	err = c.store.Commit(ctx, r.scope, cloneRecoveryPosition(r.expected), record)
	if err != nil {
		if recoveryCommitUnknown(err) {
			c.fence()
		}
		return err
	}
	r.expected = record.Position()
	r.progress.LocallyDurable = record.Position()
	current, ok := c.inbox.status(handle)
	if !ok || current != revision || ctx.Err() != nil {
		c.fence()
		return &CommitUnknown{}
	}
	if r.pending != nil {
		r.pendingDurable = true
	} else {
		r.snapshotDurable = true
	}
	return nil
}

func (c *RecoveryClient) Confirm(ctx context.Context, request *pb.RecoveryConfirmRequest) (*pb.RecoveryConfirmResponse, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	defer c.leave()
	if err := ValidateRecovery(request); err != nil {
		return nil, err
	}
	r, err := c.round(request.SubscriptionHandle)
	if err != nil {
		return nil, err
	}
	p := r.progress.LocallyDurable
	ack := r.progress.PeerAcknowledged
	duplicate := r.pending == nil && ack != nil && ack.Generation == request.Generation && bytes.Equal(ack.Checkpoint, request.Checkpoint)
	if p == nil || (!duplicate && (!r.pendingDurable || r.pending == nil)) || request.Generation != p.Generation || !bytes.Equal(request.Checkpoint, p.Checkpoint) {
		return nil, recoveryInvalid()
	}
	r.progress.ConfirmSent = cloneRecoveryPosition(p)
	out := new(pb.RecoveryConfirmResponse)
	if err := c.call(ctx, r, RecoveryConfirm, request, out, true); err != nil {
		return nil, err
	}
	if !bytes.Equal(out.SubscriptionHandle, request.SubscriptionHandle) || out.Generation != request.Generation || !bytes.Equal(out.ConfirmedCheckpoint, request.Checkpoint) {
		c.retire(r)
		return nil, recoveryInvalid()
	}
	if _, ok := c.inbox.status(request.SubscriptionHandle); !ok {
		return nil, recoveryInvalid()
	}
	r.progress.PeerAcknowledged = cloneRecoveryPosition(p)
	r.duplicates.Insert(p.Checkpoint)
	r.cursor = bytes.Clone(p.Checkpoint)
	r.pending = nil
	r.pendingDurable = false
	c.inbox.release(request.SubscriptionHandle)
	return out, nil
}

func (c *RecoveryClient) SnapshotOffer(ctx context.Context, request *pb.RecoverySnapshotOfferRequest) (*pb.RecoverySnapshotDescriptor, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	defer c.leave()
	if err := ValidateRecovery(request); err != nil {
		return nil, err
	}
	r, err := c.round(request.SubscriptionHandle)
	if err != nil {
		return nil, err
	}
	if request.Generation != r.response.Generation || r.pending != nil || (r.mode != "snapshot-needed" && r.mode != "snapshot") {
		return nil, recoveryInvalid()
	}
	out := new(pb.RecoverySnapshotDescriptor)
	if err := c.call(ctx, r, RecoverySnapshotOffer, request, out, true); err != nil {
		return nil, err
	}
	if !bytes.Equal(out.SubscriptionHandle, request.SubscriptionHandle) || out.TotalPages > c.bounds.MaxSnapshotPages || int(out.TotalPages) > c.limits.SnapshotPages || int(out.PageBytesMax) > c.limits.SnapshotPageBytes {
		c.retire(r)
		return nil, recoveryInvalid()
	}
	if r.snapshot != nil {
		if !proto.Equal(out, r.snapshot) {
			c.retire(r)
			return nil, recoveryInvalid()
		}
		return out, nil
	}
	stage, err := NewStagedSnapshot(out.SnapshotHandle, out.BoundaryCheckpoint, int(out.TotalPages), int(out.PageBytesMax))
	if err != nil {
		return nil, err
	}
	r.snapshot = proto.Clone(out).(*pb.RecoverySnapshotDescriptor)
	r.stage = stage
	r.mode = "snapshot"
	return out, nil
}
func (c *RecoveryClient) SnapshotFetch(ctx context.Context, request *pb.RecoverySnapshotFetchRequest) (*pb.RecoverySnapshotChunk, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	defer c.leave()
	if err := ValidateRecovery(request); err != nil {
		return nil, err
	}
	var r *recoveryClientRound
	for _, candidate := range c.rounds {
		if !candidate.retired && candidate.snapshot != nil && bytes.Equal(candidate.snapshot.SnapshotHandle, request.SnapshotHandle) {
			r = candidate
			break
		}
	}
	if r == nil || r.snapshotDurable || request.PageIndex >= r.snapshot.TotalPages {
		return nil, recoveryInvalid()
	}
	out := new(pb.RecoverySnapshotChunk)
	if err := c.call(ctx, r, RecoverySnapshotFetch, request, out, true); err != nil {
		return nil, err
	}
	if !bytes.Equal(out.SnapshotHandle, request.SnapshotHandle) || out.PageIndex != request.PageIndex || !bytes.Equal(out.BoundaryCheckpoint, r.snapshot.BoundaryCheckpoint) || len(out.PageBytes) > int(r.snapshot.PageBytesMax) {
		c.retire(r)
		return nil, recoveryInvalid()
	}
	if err := r.stage.StagePage(int(out.PageIndex), out.PageBytes, out.BoundaryCheckpoint); err != nil {
		return nil, err
	}
	return out, nil
}

// SnapshotBytes returns the complete opaque transfer for application installation.
func (c *RecoveryClient) SnapshotBytes(ctx context.Context, handle []byte) ([]byte, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	defer c.leave()
	r, err := c.round(handle)
	if err != nil {
		return nil, err
	}
	if r.stage == nil {
		return nil, recoveryInvalid()
	}
	return r.stage.Install()
}

func (c *RecoveryClient) SnapshotConfirm(ctx context.Context, request *pb.RecoverySnapshotConfirmRequest) (*pb.RecoverySnapshotInstalled, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	defer c.leave()
	if err := ValidateRecovery(request); err != nil {
		return nil, err
	}
	r, err := c.round(request.SubscriptionHandle)
	if err != nil {
		return nil, err
	}
	if !r.snapshotDurable || r.snapshot == nil || request.Generation != r.response.Generation || !bytes.Equal(request.BoundaryCheckpoint, r.snapshot.BoundaryCheckpoint) {
		return nil, recoveryInvalid()
	}
	duplicate := r.stage == nil
	position := &ExpectedPosition{request.Generation, bytes.Clone(request.BoundaryCheckpoint)}
	if !duplicate && (r.progress.LocallyDurable == nil || r.progress.LocallyDurable.Generation != request.Generation || !bytes.Equal(r.progress.LocallyDurable.Checkpoint, request.BoundaryCheckpoint)) {
		return nil, recoveryInvalid()
	}
	r.progress.ConfirmSent = cloneRecoveryPosition(position)
	out := new(pb.RecoverySnapshotInstalled)
	if err := c.call(ctx, r, RecoverySnapshotConfirm, request, out, true); err != nil {
		return nil, err
	}
	if !bytes.Equal(out.SubscriptionHandle, request.SubscriptionHandle) || out.Generation != request.Generation || !bytes.Equal(out.BoundaryCheckpoint, request.BoundaryCheckpoint) {
		c.retire(r)
		return nil, recoveryInvalid()
	}
	if _, ok := c.inbox.status(request.SubscriptionHandle); !ok {
		return nil, recoveryInvalid()
	}
	// A retained installation response cannot rewind later live progress.
	if duplicate {
		return out, nil
	}
	r.progress.PeerAcknowledged = cloneRecoveryPosition(position)
	r.cursor = bytes.Clone(out.BoundaryCheckpoint)
	r.mode = "live"
	r.stage = nil
	return out, nil
}
func (c *RecoveryClient) Unsubscribe(ctx context.Context, request *pb.RecoveryUnsubscribeRequest) (*pb.RecoveryUnsubscribeResponse, error) {
	if err := c.enter(ctx, false); err != nil {
		return nil, err
	}
	defer c.leave()
	if err := ValidateRecovery(request); err != nil {
		return nil, err
	}
	r := c.rounds[string(request.SubscriptionHandle)]
	if r == nil {
		return nil, recoveryInvalid()
	}
	// Remote teardown has one bounded attempt. Local retirement is immediate,
	// even when the peer result is lost or the handle was already locally fenced.
	c.retire(r)
	out := new(pb.RecoveryUnsubscribeResponse)
	err := c.call(ctx, nil, RecoveryUnsubscribe, request, out, false)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(out.SubscriptionHandle, request.SubscriptionHandle) || out.Generation != r.response.Generation {
		return nil, recoveryInvalid()
	}
	return out, nil
}
func (c *RecoveryClient) Progress(ctx context.Context, handle []byte) (RecoveryProgress, error) {
	if err := c.enter(ctx, false); err != nil {
		return RecoveryProgress{}, err
	}
	defer c.leave()
	r := c.rounds[string(handle)]
	if r == nil {
		return RecoveryProgress{}, recoveryInvalid()
	}
	return cloneRecoveryProgress(r.progress), nil
}
