package syntra

import (
	"bytes"
	"context"
	"sync"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
)

type recoveryInboxEntry struct {
	message *pb.RecoveryNotification
	size    int
}
type recoveryInboxSlot struct {
	generation           uint64
	stable               string
	registered, fenced   bool
	revision             uint64
	data, replay         []recoveryInboxEntry
	bytes, leased        int
	completion, terminal *pb.RecoveryNotification
}

// RecoveryInbox routes before the generic lossy notification queue. Once enabled,
// it owns profile notifications; mixed protocols require explicit demultiplexing.
// It never calls application code. Retired handles remain bounded tombstones.
type RecoveryInbox struct {
	mu                       sync.Mutex
	limits                   RecoveryLimits
	enabled, closed, pending bool
	slots                    map[string]*recoveryInboxSlot
	wake                     chan struct{}
}
type RecoveryInboxCounts struct{ Handles, DataMessages, DataBytes, ControlMessages int }

func NewRecoveryInbox(l RecoveryLimits) (*RecoveryInbox, error) {
	if err := l.Validate(); err != nil {
		return nil, err
	}
	return &RecoveryInbox{limits: l, slots: make(map[string]*recoveryInboxSlot), wake: make(chan struct{})}, nil
}
func (i *RecoveryInbox) signal() { close(i.wake); i.wake = make(chan struct{}) }
func (i *RecoveryInbox) Enable() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return recoveryInvalid()
	}
	i.enabled = true
	return nil
}
func (i *RecoveryInbox) Enabled() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.enabled && !i.closed
}

func (i *RecoveryInbox) ingressState() (bool, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.enabled, i.closed
}
func (i *RecoveryInbox) Close() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.closed {
		i.closed = true
		i.slots = nil
		i.signal()
	}
}
func (i *RecoveryInbox) begin() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.enabled || i.closed || i.pending {
		return recoveryInvalid()
	}
	i.pending = true
	return nil
}
func (i *RecoveryInbox) register(handle []byte, g uint64, stable string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.pending || i.closed {
		return recoveryInvalid()
	}
	i.pending = false
	s := i.slots[string(handle)]
	if s == nil {
		if len(i.slots) >= i.limits.HandlesPerConnection {
			return recoveryLimit()
		}
		s = &recoveryInboxSlot{generation: g}
		i.slots[string(handle)] = s
	}
	if s.registered || s.generation != g {
		return recoveryInvalid()
	}
	s.registered = true
	s.stable = stable
	for key, candidate := range i.slots {
		if !candidate.registered {
			delete(i.slots, key)
		}
	}
	return nil
}
func (i *RecoveryInbox) cancelRegistration() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.pending = false
	for key, s := range i.slots {
		if !s.registered {
			delete(i.slots, key)
		}
	}
}
func (i *RecoveryInbox) retire(handle []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if s := i.slots[string(handle)]; s != nil {
		s.fenced = true
		s.revision++
		s.data = nil
		s.replay = nil
		s.bytes = 0
		s.leased = 0
		s.completion = nil
		s.terminal = nil
	}
	i.signal()
}
func (i *RecoveryInbox) counts() RecoveryInboxCounts {
	c := RecoveryInboxCounts{Handles: len(i.slots)}
	for _, s := range i.slots {
		c.DataMessages += len(s.data) + len(s.replay)
		c.DataBytes += s.bytes
		if s.completion != nil {
			c.ControlMessages++
		}
		if s.terminal != nil {
			c.ControlMessages++
		}
	}
	return c
}
func (i *RecoveryInbox) Counts() RecoveryInboxCounts {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.counts()
}
func (i *RecoveryInbox) overflow(handle []byte, s *recoveryInboxSlot) {
	s.data = nil
	s.replay = nil
	s.bytes = 0
	s.leased = 0
	s.completion = nil
	s.fenced = true
	s.revision++
	s.terminal = recoveryNotification(&pb.RecoveryBatchTrailer{ProfileVersion: 1, SubscriptionHandle: bytes.Clone(handle), Generation: s.generation, Outcome: &pb.RecoveryBatchTrailer_Terminated{Terminated: true}, TerminateReason: []byte("local-queue-exhausted")})
}
func (i *RecoveryInbox) pushLocked(n *pb.RecoveryNotification, size int, replay bool) error {
	h, g := recoveryIdentity(n)
	key := string(h)
	s := i.slots[key]
	if s == nil {
		if !i.pending {
			return nil
		}
		if len(i.slots) >= i.limits.HandlesPerConnection {
			return recoveryLimit()
		}
		s = &recoveryInboxSlot{generation: g}
		i.slots[key] = s
	}
	if s.fenced {
		return nil
	}
	if s.generation != g {
		return recoveryInvalid()
	}
	if n.GetBatch() != nil {
		// Allow one valid batch on an empty stream despite accounting overhead.
		// Leased entries remain accounted in s.bytes until released.
		if (s.bytes > 0 && s.bytes+size > i.limits.QueuedBytesPerStream) || i.counts().DataBytes+size > i.limits.QueuedBytesPerConnection || len(s.data)+len(s.replay)+boolInt(s.leased > 0) >= i.limits.QueuedMessagesPerStream {
			i.overflow(h, s)
		} else {
			s.bytes += size
			e := recoveryInboxEntry{n, size}
			if replay {
				s.replay = append(s.replay, e)
			} else {
				s.data = append(s.data, e)
			}
		}
	} else if t := n.GetTrailer(); t != nil && !t.GetCatchupComplete() {
		s.data = nil
		s.replay = nil
		s.bytes = 0
		s.leased = 0
		s.completion = nil
		s.revision++
		s.fenced = !t.GetSnapshotRequired()
		s.terminal = n
		if next := t.GetNextGeneration(); next > 0 && s.registered {
			for k, other := range i.slots {
				if other != s && other.registered && !other.fenced && other.stable == s.stable && other.generation < next {
					other.data = nil
					other.replay = nil
					other.bytes = 0
					other.leased = 0
					other.completion = nil
					other.fenced = true
					other.revision++
					other.terminal = recoveryNotification(&pb.RecoveryBatchTrailer{ProfileVersion: 1, SubscriptionHandle: []byte(k), Generation: other.generation, Outcome: &pb.RecoveryBatchTrailer_NextGeneration{NextGeneration: next}})
				}
			}
		}
	} else {
		if s.completion != nil && !bytes.Equal(recoveryCompletionBoundary(s.completion), recoveryCompletionBoundary(n)) {
			i.overflow(h, s)
		} else {
			s.completion = n
		}
	}
	return nil
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
func recoveryCompletionBoundary(n *pb.RecoveryNotification) []byte {
	if c := n.GetReplayComplete(); c != nil {
		return c.LiveBoundaryCheckpoint
	}
	if t := n.GetTrailer(); t != nil {
		return t.BoundaryCheckpoint
	}
	return nil
}

// Push is called only for authenticated, ACTIVE, validated envelope payloads.
// Invalid profile bytes fail closed, rather than falling through to another queue.
func (i *RecoveryInbox) Push(payload []byte) error {
	n := new(pb.RecoveryNotification)
	if err := DecodeRecovery(payload, n); err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.enabled || i.closed {
		return recoveryInvalid()
	}
	err := i.pushLocked(n, len(payload)+32, false)
	i.signal()
	return err
}
func (i *RecoveryInbox) pushReplay(page *pb.RecoveryReplayPage) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return recoveryInvalid()
	}
	for _, entry := range page.BatchPayloads {
		b := new(pb.RecoveryBatch)
		if err := DecodeRecovery(entry, b); err != nil {
			return err
		}
		if err := i.pushLocked(recoveryNotification(b), len(entry)+32, true); err != nil {
			return err
		}
	}
	i.signal()
	return nil
}
func (i *RecoveryInbox) status(handle []byte) (uint64, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	s := i.slots[string(handle)]
	if s == nil {
		return 0, false
	}
	return s.revision, !i.closed && !s.fenced && s.terminal == nil
}
func (i *RecoveryInbox) release(handle []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if s := i.slots[string(handle)]; s != nil {
		s.bytes -= s.leased
		s.leased = 0
	}
	i.signal()
}
func (i *RecoveryInbox) pop(ctx context.Context, handle []byte, allowData, allowCompletion bool) (*pb.RecoveryNotification, error) {
	for {
		n, wake, err := i.tryPop(handle, allowData, allowCompletion)
		if n != nil || err != nil {
			return n, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-wake:
		}
	}
}

// Capture the wait channel with the empty-queue observation. The client releases
// its operation gate before waiting, then recomputes phase eligibility on wake.
func (i *RecoveryInbox) tryPop(handle []byte, allowData, allowCompletion bool) (*pb.RecoveryNotification, <-chan struct{}, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	s := i.slots[string(handle)]
	if i.closed || s == nil {
		return nil, nil, recoveryInvalid()
	}
	if s.terminal != nil {
		n := s.terminal
		s.terminal = nil
		return n, nil, nil
	}
	if allowCompletion && s.completion != nil {
		n := s.completion
		s.completion = nil
		return n, nil, nil
	}
	if allowData && s.leased == 0 {
		var e recoveryInboxEntry
		if len(s.replay) > 0 {
			e = s.replay[0]
			s.replay = s.replay[1:]
		} else if len(s.data) > 0 {
			e = s.data[0]
			s.data = s.data[1:]
		}
		if e.message != nil {
			s.leased = e.size
			return e.message, nil, nil
		}
	}
	if s.fenced {
		return nil, nil, recoveryInvalid()
	}
	return nil, i.wake, nil
}

// WrapRecoveryTransport is a compatibility adapter for an inbox already attached
// by NewRecoveryClient. Client.Run owns ordered validation and pre-queue routing;
// callers may pass their transport directly to Run.
func WrapRecoveryTransport(t Transport, c *Client, inbox *RecoveryInbox) Transport {
	return &recoveryIngressTransport{Transport: t, client: c, inbox: inbox}
}

type recoveryIngressTransport struct {
	Transport
	client *Client
	inbox  *RecoveryInbox
}

func (t *recoveryIngressTransport) Recv(ctx context.Context) ([]byte, error) {
	if t.inbox == nil {
		return nil, recoveryInvalid()
	}
	_, closed := t.inbox.ingressState()
	if closed {
		return nil, NewRpcError(ErrorCodeUnavailable, "syntra: recovery ingress closed")
	}
	if t.client == nil {
		return nil, recoveryInvalid()
	}
	t.client.mu.Lock()
	attached := t.client.recoveryInbox == t.inbox
	t.client.mu.Unlock()
	if !attached {
		return nil, recoveryInvalid()
	}
	return t.Transport.Recv(ctx)
}
func (t *recoveryIngressTransport) Close() error {
	if t.inbox != nil {
		t.inbox.Close()
	}
	return t.Transport.Close()
}
func (t *recoveryIngressTransport) ChannelIdentity() (ChannelIdentity, bool) {
	if p, ok := t.Transport.(ChannelIdentityProvider); ok {
		return p.ChannelIdentity()
	}
	return ChannelIdentity{}, false
}
