// File frame_receipt.go carries local receive timing atomically with each frame.
package syntra

import (
	"context"
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

// FrameReceiptTransport optionally returns a frame and its original timing in
// ONE receive operation. Implementations must serialize queue removal with its
// metadata: a separate "last received" accessor cannot safely implement this
// contract. Wrappers overriding Recv must also preserve this method's behavior.
// Legacy transports remain supported, but their unavailable assembly/buffering
// timing cannot be inferred: the SDK captures only after their Recv returns.
type FrameReceiptTransport interface {
	Transport
	// RecvWithReceipt returns the next frame and its completing-batch origin.
	// Error returns must not expose a frame; successful receipts must be nonzero.
	RecvWithReceipt(context.Context) ([]byte, FrameReceipt, error)
}

// recvWithReceipt preserves optional metadata, or captures a legacy delivery
// origin after Recv. It never recovers missing timing from another frame's read.
func recvWithReceipt(ctx context.Context, t Transport) ([]byte, FrameReceipt, error) {
	if timed, ok := t.(FrameReceiptTransport); ok {
		return timed.RecvWithReceipt(ctx)
	}
	raw, err := t.Recv(ctx)
	if err != nil {
		return nil, FrameReceipt{}, err
	}
	return raw, FrameReceipt{receipt: captureRequestReceipt(t)}, nil
}

// RecvWithReceipt forwards the exact frame/timing pair through session ownership.
func (t *ownedTransport) RecvWithReceipt(ctx context.Context) ([]byte, FrameReceipt, error) {
	return recvWithReceipt(ctx, t.Transport)
}
