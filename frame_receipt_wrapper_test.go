// File frame_receipt_wrapper_test.go checks receive policy and receipt correlation.
package syntra

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

// receiptRejectingWrapper inherits the optional method but owns receive policy.
type receiptRejectingWrapper struct {
	FrameReceiptTransport
	calls int
	err   error
}

// receiptFilteringWrapper overrides only Recv while inheriting the timed method.
type receiptFilteringWrapper struct {
	FrameReceiptTransport
	recv func(context.Context) ([]byte, error)
}

// Recv applies the outer wrapper's filtering/transforming policy.
func (t *receiptFilteringWrapper) Recv(ctx context.Context) ([]byte, error) {
	return t.recv(ctx)
}

// receiptSequenceTransport assigns different original receipts to owned frames.
type receiptSequenceTransport struct {
	Transport
	mu   sync.Mutex
	next int
}

// Recv delegates to the driver's own atomic receive and publication.
func (t *receiptSequenceTransport) Recv(ctx context.Context) ([]byte, error) {
	raw, _, err := t.RecvWithReceipt(ctx)
	return raw, err
}

// RecvWithReceipt publishes metadata while the frame and its origin are owned.
func (t *receiptSequenceTransport) RecvWithReceipt(ctx context.Context) ([]byte, FrameReceipt, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	raw := []byte(fmt.Sprint(t.next))
	clock := &terminalReviewClock{}
	clock.elapsed.Store(int64(time.Duration(t.next) * time.Millisecond))
	receipt := CaptureFrameReceipt(clock)
	receipt.Publish(ctx, raw)
	return raw, receipt, nil
}

// TestReceiptFilterReturnsExactFrame checks multiple reads, earlier selected
// frames and concurrent outer receives without any cross-call last-frame state.
func TestReceiptFilterReturnsExactFrame(t *testing.T) {
	for _, selectFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(selectFirst), func(t *testing.T) {
			driver := &receiptSequenceTransport{}
			wrapper := &receiptFilteringWrapper{FrameReceiptTransport: driver}
			wrapper.recv = func(ctx context.Context) ([]byte, error) {
				first, err := driver.Recv(ctx)
				if err != nil {
					return nil, err
				}
				last, err := driver.Recv(ctx)
				if selectFirst {
					return first, err
				}
				return last, err
			}
			var calls sync.WaitGroup
			for range 16 {
				calls.Add(1)
				go func() {
					defer calls.Done()
					raw, receipt, err := recvWithReceipt(context.Background(), &ownedTransport{Transport: wrapper})
					if err != nil || string(raw) != fmt.Sprint(int64(receipt.ElapsedAge()/time.Millisecond)) {
						t.Errorf("selected frame lost original receipt: raw=%q age=%v err=%v", raw, receipt.ElapsedAge(), err)
					}
				}()
			}
			calls.Wait()
		})
	}
}

// TestReceiptFilterLargeReadWindow accepts recent selected frames after many
// discarded reads, but fails closed once the selected metadata was evicted.
func TestReceiptFilterLargeReadWindow(t *testing.T) {
	for _, behind := range []int{0, 31, 32} {
		t.Run(fmt.Sprint(behind), func(t *testing.T) {
			driver := &receiptSequenceTransport{}
			wrapper := &receiptFilteringWrapper{FrameReceiptTransport: driver}
			wrapper.recv = func(ctx context.Context) ([]byte, error) {
				var selected []byte
				for i := 1; i <= 1000; i++ {
					raw, err := driver.Recv(ctx)
					if err != nil {
						return nil, err
					}
					if i == 1000-behind {
						selected = raw
					}
				}
				return selected, nil
			}
			raw, receipt, err := recvWithReceipt(context.Background(), wrapper)
			if behind == 32 {
				if err == nil || raw != nil || receipt != (FrameReceipt{}) {
					t.Fatalf("evicted receipt renewed: raw=%q receipt=%v err=%v", raw, receipt, err)
				}
				return
			}
			if err != nil || string(raw) != fmt.Sprint(1000-behind) || receipt.ElapsedAge() != time.Duration(1000-behind)*time.Millisecond {
				t.Fatalf("retained receipt mismatch: raw=%q age=%v err=%v", raw, receipt.ElapsedAge(), err)
			}
		})
	}
}

// TestReceiptEqualContentsRemainDistinct ensures metadata belongs to the returned
// owned buffer, not the last frame or another frame with identical contents.
func TestReceiptEqualContentsRemainDistinct(t *testing.T) {
	clock := &terminalReviewClock{}
	original := CaptureFrameReceipt(clock)
	driver := &receiptTransportFixture{frame: []byte("same"), receipt: original}
	wrapper := &receiptFilteringWrapper{FrameReceiptTransport: driver, recv: func(ctx context.Context) ([]byte, error) {
		raw, err := driver.Recv(ctx)
		if err != nil {
			return nil, err
		}
		clock.elapsed.Store(int64(time.Millisecond))
		CaptureFrameReceipt(clock).Publish(ctx, append([]byte(nil), raw...))
		return raw, nil
	}}
	raw, receipt, err := recvWithReceipt(context.Background(), wrapper)
	if err != nil || string(raw) != "same" || receipt != original {
		t.Fatalf("identical later frame replaced selected origin: raw=%q receipt=%v err=%v", raw, receipt, err)
	}
}

// TestReceiptFrameMismatchDoesNotRenew covers copied, replaced, mutated and
// evicted buffers, and verifies explicit transfer of an existing receipt.
func TestReceiptFrameMismatchDoesNotRenew(t *testing.T) {
	for _, mode := range []string{"copy", "replace", "mutate", "zero", "evicted", "explicit-copy", "explicit-transform"} {
		t.Run(mode, func(t *testing.T) {
			original := CaptureFrameReceipt(nil)
			driver := &receiptTransportFixture{frame: []byte("original"), receipt: original}
			if mode == "zero" {
				driver.receipt = FrameReceipt{}
			}
			wrapper := &receiptFilteringWrapper{FrameReceiptTransport: driver}
			wrapper.recv = func(ctx context.Context) ([]byte, error) {
				raw, err := driver.Recv(ctx)
				if err != nil {
					return nil, err
				}
				switch mode {
				case "copy", "explicit-copy":
					raw = append([]byte(nil), raw...)
				case "replace", "explicit-transform":
					raw = []byte("replacement")
				case "mutate":
					raw[0] = 'X'
				case "evicted":
					for range 1000 {
						original.Publish(ctx, []byte("discarded"))
					}
				}
				if mode == "explicit-copy" || mode == "explicit-transform" {
					original.Publish(ctx, raw)
				}
				return raw, nil
			}
			raw, receipt, err := recvWithReceipt(context.Background(), wrapper)
			if mode == "explicit-copy" || mode == "explicit-transform" {
				if err != nil || raw == nil || receipt != original {
					t.Fatalf("explicit transfer lost origin: raw=%q receipt=%v err=%v", raw, receipt, err)
				}
				return
			}
			if err == nil || raw != nil || receipt != (FrameReceipt{}) {
				t.Fatalf("mismatched metadata received fresh fallback: raw=%q receipt=%v err=%v", raw, receipt, err)
			}
		})
	}
}

// TestReceiptCaptureBoundAndLifetime verifies filters cannot grow the receipt
// window or retain payload references by keeping an old receive context alive.
func TestReceiptCaptureBoundAndLifetime(t *testing.T) {
	sink := &frameReceiptSink{}
	ctx := context.WithValue(context.Background(), frameReceiptKey{}, sink)
	receipt := CaptureFrameReceipt(nil)
	for range 1000 {
		receipt.Publish(ctx, []byte("discarded"))
	}
	if len(sink.entries) > 32 || cap(sink.entries) > 32 {
		t.Fatalf("unbounded receipt window: len=%d cap=%d", len(sink.entries), cap(sink.entries))
	}
	sink.finish(nil)
	receipt.Publish(ctx, []byte("late"))
	if sink.entries != nil {
		t.Fatal("finished receive retained a late publication")
	}
}

// TestReceiptErrorDoesNotLeakMetadata requires wrapper errors to discard even
// previously published frames and leaves the next legacy receive independent.
func TestReceiptErrorDoesNotLeakMetadata(t *testing.T) {
	denied := errors.New("filtered")
	driver := &receiptSequenceTransport{}
	wrapper := &receiptFilteringWrapper{FrameReceiptTransport: driver}
	wrapper.recv = func(ctx context.Context) ([]byte, error) {
		raw, _ := driver.Recv(ctx)
		return raw, denied
	}
	raw, receipt, err := recvWithReceipt(context.Background(), wrapper)
	if raw != nil || receipt != (FrameReceipt{}) || !errors.Is(err, denied) {
		t.Fatalf("failed Recv exposed metadata: raw=%q receipt=%v err=%v", raw, receipt, err)
	}
	legacy := &legacyReceiptFixture{&receiptTransportFixture{frame: []byte("legacy")}}
	raw, receipt, err = recvWithReceipt(context.Background(), legacy)
	if err != nil || string(raw) != "legacy" || receipt.ReceivedAt().IsZero() || receipt.receipt.clock != nil {
		t.Fatalf("legacy fallback inherited another receive: raw=%q receipt=%v err=%v", raw, receipt, err)
	}
}

// Recv rejects before consulting the embedded transport.
func (t *receiptRejectingWrapper) Recv(context.Context) ([]byte, error) {
	t.calls++
	return nil, t.err
}

// TestReceiptPromotedMethodCannotBypassRecv requires the root to enter the outer
// policy even when embedding promotes a perfectly valid RecvWithReceipt method.
func TestReceiptPromotedMethodCannotBypassRecv(t *testing.T) {
	denied := errors.New("receive denied")
	inner := &receiptTransportFixture{frame: []byte("forbidden"), receipt: CaptureFrameReceipt(nil)}
	wrapper := &receiptRejectingWrapper{FrameReceiptTransport: inner, err: denied}
	raw, receipt, err := recvWithReceipt(context.Background(), wrapper)
	if !errors.Is(err, denied) || raw != nil || receipt != (FrameReceipt{}) || wrapper.calls != 1 || inner.received {
		t.Fatalf("outer Recv bypassed: raw=%q receipt=%v err=%v policy calls=%d underlying Recv=%v", raw, receipt, err, wrapper.calls, inner.received)
	}
}
