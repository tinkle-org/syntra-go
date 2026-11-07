// File frame_receipt.go carries local receive timing atomically with each frame.
package syntra

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"
)

// FrameReceipt is trusted local timing supplied by a transport, never wire data.
// Capture it before synchronous assembly of a completing batch and retain the
// same value for every frame completed by that batch, including fragmented frames.
// Its zero value is invalid. It conveys timing only, not identity or authority.
type FrameReceipt struct{ receipt requestReceipt }

// CaptureFrameReceipt samples trusted elapsed time FIRST and scheduler time
// SECOND. Suspension between the samples can shorten but never renew a budget.
// clock may be nil for scheduler-only custom transports; it must otherwise be the
// transport's original trusted suspend-inclusive clock, not a reconstructed one.
func CaptureFrameReceipt(clock TerminalClock) FrameReceipt {
	r := requestReceipt{clock: clock}
	if clock != nil {
		r.age = clock.Age()
		r.invalid = r.age < 0 || clock.Check() != nil
	}
	r.at = time.Now()
	return FrameReceipt{receipt: r}
}

// ReceivedAt returns the original scheduler timestamp, not the delivery time.
func (r FrameReceipt) ReceivedAt() time.Time { return r.receipt.at }

// ElapsedAge returns the original trusted age, for driver assembly cutoffs. It is
// meaningful only on the clock supplied to CaptureFrameReceipt, with valid continuity.
func (r FrameReceipt) ElapsedAge() time.Duration { return r.receipt.age }

// Publish associates this receipt with frame in the SDK's current receive call.
// Trusted drivers call it before returning the owned buffer from Recv (or
// RecvWithReceipt). Outside an SDK receive it is a no-op. Forward the receive
// context through wrappers; the root always calls the outer Recv, never an
// optional method that embedding could promote past that wrapper's checks.
//
// Correlation requires the same buffer, length and contents. A wrapper that copies
// or transforms a frame must explicitly publish its original receipt for the new
// buffer; it must not recapture time. Wrappers buffering across calls must retain
// and publish the original receipt when returning the buffered frame.
// Use the package-level RecvWithReceipt helper to obtain the inner receipt while
// preserving the inner transport's ordinary Recv policy.
// Only the most recent 32 publications per call are retained. An unmatched or
// evicted frame fails closed if any metadata was published, rather than receiving
// a fresh delivery-time budget. Publication is synchronized, but the caller must
// own frame while publishing and returning it. Empty or oversized publications
// disable fallback but are not hashed or retained; closed receives ignore them.
func (r FrameReceipt) Publish(ctx context.Context, frame []byte) {
	if sink, ok := ctx.Value(frameReceiptKey{}).(*frameReceiptSink); ok {
		sink.publish(frame, r)
	}
}

// FrameReceiptTransport returns a frame and its original timing in ONE receive
// operation for direct SDK consumers. Implementations must serialize queue
// removal with its metadata and Publish the pair to ctx for root SDK receives.
// The root does not detect this interface: Recv must preserve receive policy and
// publish metadata itself (it may delegate to its own RecvWithReceipt).
// Legacy Recv-only transports remain supported, but their unavailable assembly
// and buffering timing cannot be inferred: capture occurs after Recv returns.
type FrameReceiptTransport interface {
	Transport
	// RecvWithReceipt returns the next frame and its completing-batch origin.
	// Error returns must not expose a frame; successful receipts must be nonzero.
	RecvWithReceipt(context.Context) ([]byte, FrameReceipt, error)
}

// RecvWithReceipt calls t.Recv and returns its frame with correlated local timing.
// It never dispatches an optional RecvWithReceipt method that embedding could
// promote past a wrapper's Recv policy. A nil transport returns InvalidArgument.
//
// The call is synchronous and propagates ctx cancellation, deadline and values;
// t.Recv must honor cancellation. Metadata capture is bounded and scoped to this
// call, closes on return, and forwards its matched receipt to any enclosing SDK
// receive. Copying or buffering wrappers can retain the returned receipt and
// Publish it with their returned buffer into that outer receive's context.
//
// Receipts are trusted SDK-local transport metadata, never peer-supplied timing.
// This helper grants no identity, authorization or terminal capability. For
// legacy transports publishing no metadata, it captures delivery timing only;
// unavailable assembly and buffering timing cannot be inferred.
func RecvWithReceipt(ctx context.Context, t Transport) ([]byte, FrameReceipt, error) {
	if t == nil {
		return nil, FrameReceipt{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: nil transport")
	}
	return recvWithReceipt(ctx, t)
}

// frameReceiptKey scopes metadata to one outer Recv, including all filtered reads.
type frameReceiptKey struct{}

// maxFrameReceiptEntries bounds the filter correlation window, not receive count.
const maxFrameReceiptEntries = 32

// frameReceiptEntry identifies an owned buffer and detects in-place changes.
// Retaining the pointer prevents address reuse while its receipt is retained.
type frameReceiptEntry struct {
	first   *byte
	size    int
	digest  [sha256.Size]byte
	receipt FrameReceipt
}

// frameReceiptSink bounds metadata even if a filter consumes arbitrarily many
// frames. Concurrent receives have independent sinks, not a last-received slot.
type frameReceiptSink struct {
	mu       sync.Mutex
	entries  []frameReceiptEntry
	next     int
	observed bool
	closed   bool
}

// publish records only bounded metadata, never a copy of the frame payload.
func (s *frameReceiptSink) publish(frame []byte, receipt FrameReceipt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.observed = true
	if len(frame) == 0 || len(frame) > MaxFrameBytes {
		return
	}
	entry := frameReceiptEntry{first: &frame[0], size: len(frame), digest: sha256.Sum256(frame), receipt: receipt}
	if s.entries == nil {
		s.entries = make([]frameReceiptEntry, 0, maxFrameReceiptEntries)
	}
	if len(s.entries) < maxFrameReceiptEntries {
		s.entries = append(s.entries, entry)
		s.next = len(s.entries) % maxFrameReceiptEntries
		return
	}
	s.entries[s.next] = entry
	s.next = (s.next + 1) % len(s.entries)
}

// finish closes publication, releases retained buffers and matches the exact
// returned frame. Observed metadata or invalid frame sizes forbid fresh fallback.
func (s *frameReceiptSink) finish(frame []byte) (FrameReceipt, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	defer func() { s.entries = nil }()
	if len(frame) == 0 || len(frame) > MaxFrameBytes {
		return FrameReceipt{}, true
	}
	if len(s.entries) == 0 {
		return FrameReceipt{}, s.observed
	}
	digest := sha256.Sum256(frame)
	// Inspect the ring newest first, including explicit wrapper transfers.
	start := (s.next + len(s.entries) - 1) % len(s.entries)
	for offset := range len(s.entries) {
		entry := s.entries[(start-offset+len(s.entries))%len(s.entries)]
		if entry.first == &frame[0] && entry.size == len(frame) && entry.digest == digest {
			return entry.receipt, true
		}
	}
	return FrameReceipt{}, s.observed
}

// recvWithReceipt always respects the outer Recv and preserves only metadata
// correlated to its returned frame. No metadata means legacy delivery timing.
func recvWithReceipt(ctx context.Context, t Transport) ([]byte, FrameReceipt, error) {
	sink := &frameReceiptSink{}
	raw, err := t.Recv(context.WithValue(ctx, frameReceiptKey{}, sink))
	if err != nil {
		sink.finish(nil)
		return nil, FrameReceipt{}, err
	}
	receipt, observed := sink.finish(raw)
	if observed && receipt.ReceivedAt().IsZero() {
		return nil, FrameReceipt{}, NewRpcError(ErrorCodeInternal, "syntra: frame receipt mismatch")
	}
	if !observed {
		receipt = FrameReceipt{receipt: captureRequestReceipt(t)}
	}
	// A direct SDK wrapper receive may itself be nested in another outer Recv.
	receipt.Publish(ctx, raw)
	return raw, receipt, nil
}

// RecvWithReceipt forwards the exact frame/timing pair through session ownership.
func (t *ownedTransport) RecvWithReceipt(ctx context.Context) ([]byte, FrameReceipt, error) {
	return recvWithReceipt(ctx, t.Transport)
}
