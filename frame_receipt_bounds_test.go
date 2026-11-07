// File frame_receipt_bounds_test.go checks receipt capture resource bounds.
package syntra

import (
	"context"
	"errors"
	"strconv"
	"testing"
)

// TestReceiptPublicationBounds requires invalid publications to disable fallback
// without retaining a buffer or allocating correlation entries.
func TestReceiptPublicationBounds(t *testing.T) {
	for _, size := range []int{0, MaxFrameBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			invalid := make([]byte, size)
			original := CaptureFrameReceipt(nil)
			sink := &frameReceiptSink{}
			ctx := context.WithValue(context.Background(), frameReceiptKey{}, sink)
			original.Publish(ctx, invalid)
			if !sink.observed || sink.entries != nil {
				t.Errorf("invalid publication retained metadata: observed=%v entries=%d", sink.observed, len(sink.entries))
			}
			receipt, observed := sink.finish([]byte("unmatched"))
			if !observed || receipt != (FrameReceipt{}) || sink.entries != nil {
				t.Fatal("invalid publication permitted fresh fallback or retained entries")
			}
			wrapper := &receiptFilteringWrapper{recv: func(ctx context.Context) ([]byte, error) {
				original.Publish(ctx, invalid)
				return []byte("unmatched"), nil
			}}
			if raw, receipt, err := recvWithReceipt(context.Background(), wrapper); err == nil || raw != nil || receipt != (FrameReceipt{}) {
				t.Fatal("root renewed a frame after an invalid publication")
			}
		})
	}
}

// TestReceiptMaximumFrameAccepted preserves the inclusive frame-size boundary.
func TestReceiptMaximumFrameAccepted(t *testing.T) {
	original := CaptureFrameReceipt(nil)
	driver := &receiptTransportFixture{frame: make([]byte, MaxFrameBytes), receipt: original}
	raw, receipt, err := recvWithReceipt(context.Background(), driver)
	if err != nil || len(raw) != MaxFrameBytes || &raw[0] != &driver.frame[0] || receipt != original {
		t.Fatal("maximum valid frame lost its original receipt")
	}
}

// TestReceiptFinishWithoutEntries fails closed when an invalid publication was
// observed but no valid frame metadata exists; ring lookup must not divide by zero.
func TestReceiptFinishWithoutEntries(t *testing.T) {
	sink := &frameReceiptSink{observed: true}
	receipt, observed := sink.finish([]byte("unmatched"))
	if !observed || receipt != (FrameReceipt{}) || !sink.closed || sink.entries != nil {
		t.Fatal("empty invalid-publication sink did not close and fail closed")
	}
}

// TestReceiptReturnedFrameBounds rejects invalid sizes even on legacy receive,
// rather than granting them a fresh delivery receipt.
func TestReceiptReturnedFrameBounds(t *testing.T) {
	for _, size := range []int{0, MaxFrameBytes + 1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			legacy := &legacyReceiptFixture{&receiptTransportFixture{frame: make([]byte, size)}}
			raw, receipt, err := recvWithReceipt(context.Background(), legacy)
			if err == nil || raw != nil || receipt != (FrameReceipt{}) {
				t.Fatalf("invalid legacy frame granted receipt: size=%d err=%v", size, err)
			}
		})
	}
}

// TestReceiptClosedPublicationIsIgnored ensures retained contexts cannot reopen
// a sink, including when a late driver publishes an oversized buffer.
func TestReceiptClosedPublicationIsIgnored(t *testing.T) {
	sink := &frameReceiptSink{}
	ctx := context.WithValue(context.Background(), frameReceiptKey{}, sink)
	sink.finish(nil)
	observed := sink.observed
	for _, frame := range [][]byte{nil, []byte("late"), make([]byte, MaxFrameBytes+1)} {
		CaptureFrameReceipt(nil).Publish(ctx, frame)
	}
	if sink.entries != nil || sink.observed != observed || !sink.closed {
		t.Fatal("late publication changed a closed sink")
	}
}

// TestReceiptRecvErrorClearsCapture preserves the receive error, discards its
// unusable buffer and closes the sink even when valid metadata preceded it.
func TestReceiptRecvErrorClearsCapture(t *testing.T) {
	denied := errors.New("receive failed")
	var sink *frameReceiptSink
	wrapper := &receiptFilteringWrapper{recv: func(ctx context.Context) ([]byte, error) {
		sink = ctx.Value(frameReceiptKey{}).(*frameReceiptSink)
		CaptureFrameReceipt(nil).Publish(ctx, []byte("prior frame"))
		return make([]byte, MaxFrameBytes+1), denied
	}}
	raw, receipt, err := recvWithReceipt(context.Background(), wrapper)
	if !errors.Is(err, denied) || raw != nil || receipt != (FrameReceipt{}) || !sink.closed || sink.entries != nil {
		t.Fatal("receive error exposed a buffer/receipt or retained capture state")
	}
}
