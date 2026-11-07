// File frame_receipt_api_test.go exercises receipt wrappers using only public API.
package syntra_test

import (
	"context"
	"errors"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
)

// receiptAPIDriver publishes trusted local timing through ordinary Recv.
type receiptAPIDriver struct {
	syntra.Transport
	receipt               syntra.FrameReceipt
	last                  []byte
	recvCalls, timedCalls int
	check                 func(context.Context)
}

// Recv owns and publishes each returned buffer, honoring the caller's context.
func (d *receiptAPIDriver) Recv(ctx context.Context) ([]byte, error) {
	d.recvCalls++
	if d.check != nil {
		d.check(ctx)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d.last = []byte("accepted frame")
	d.receipt.Publish(ctx, d.last)
	return d.last, nil
}

// RecvWithReceipt exposes accidental dispatch past an embedding wrapper's policy.
func (d *receiptAPIDriver) RecvWithReceipt(context.Context) ([]byte, syntra.FrameReceipt, error) {
	d.timedCalls++
	return []byte("policy bypass"), d.receipt, nil
}

// receiptAPIFilter promotes the timed method while owning ordinary receive policy.
type receiptAPIFilter struct {
	syntra.FrameReceiptTransport
	calls int
	deny  error
}

// Recv rejects before reading, or delegates through the ordinary receive method.
func (f *receiptAPIFilter) Recv(ctx context.Context) ([]byte, error) {
	f.calls++
	if f.deny != nil {
		return nil, f.deny
	}
	return f.FrameReceiptTransport.Recv(ctx)
}

// receiptAPICopyWrapper transfers metadata to a new buffer without SDK internals.
type receiptAPICopyWrapper struct{ syntra.Transport }

// Recv uses the safe package helper, not a potentially promoted optional method.
func (w *receiptAPICopyWrapper) Recv(ctx context.Context) ([]byte, error) {
	raw, receipt, err := syntra.RecvWithReceipt(ctx, w.Transport)
	if err != nil {
		return nil, err
	}
	copied := append([]byte(nil), raw...)
	receipt.Publish(ctx, copied)
	return copied, nil
}

// TestReceiptPublicCopyWrapperHonorsInnerRecv proves an external copying wrapper
// preserves the original receipt without bypassing a promoted-method guard.
func TestReceiptPublicCopyWrapperHonorsInnerRecv(t *testing.T) {
	for _, deny := range []bool{false, true} {
		name := "accepted"
		if deny {
			name = "denied"
		}
		t.Run(name, func(t *testing.T) {
			original := syntra.CaptureFrameReceipt(nil)
			driver := &receiptAPIDriver{receipt: original}
			filter := &receiptAPIFilter{FrameReceiptTransport: driver}
			denied := errors.New("inner receive denied")
			if deny {
				filter.deny = denied
			}
			wrapper := &receiptAPICopyWrapper{Transport: filter}
			raw, receipt, err := syntra.RecvWithReceipt(context.Background(), wrapper)
			if filter.calls != 1 || driver.timedCalls != 0 {
				t.Fatalf("inner Recv bypassed: filter=%d optional=%d", filter.calls, driver.timedCalls)
			}
			if deny {
				if !errors.Is(err, denied) || raw != nil || receipt != (syntra.FrameReceipt{}) || driver.recvCalls != 0 {
					t.Fatal("rejected receive exposed a frame or read the underlying driver")
				}
				return
			}
			if err != nil || string(raw) != "accepted frame" || &raw[0] == &driver.last[0] || receipt != original || driver.recvCalls != 1 {
				t.Fatalf("copy lost original receipt: raw=%q same receipt=%v err=%v", raw, receipt == original, err)
			}
		})
	}
}

// receiptAPIBufferWrapper prefetches one owned frame and retains only its receipt.
type receiptAPIBufferWrapper struct {
	syntra.Transport
	pending []byte
	receipt syntra.FrameReceipt
}

// Recv republishes buffered metadata into the new call's context, never an old one.
func (w *receiptAPIBufferWrapper) Recv(ctx context.Context) ([]byte, error) {
	if w.pending != nil {
		raw, receipt := w.pending, w.receipt
		w.pending, w.receipt = nil, syntra.FrameReceipt{}
		receipt.Publish(ctx, raw)
		return raw, nil
	}
	raw, _, err := syntra.RecvWithReceipt(ctx, w.Transport)
	if err != nil {
		return nil, err
	}
	next, receipt, err := syntra.RecvWithReceipt(ctx, w.Transport)
	if err != nil {
		return nil, err
	}
	w.pending, w.receipt = append([]byte(nil), next...), receipt
	return raw, nil
}

// TestReceiptPublicBufferAcrossCalls preserves each frame's distinct original
// receipt across prefetch and cancellation, without rereading or recapturing time.
func TestReceiptPublicBufferAcrossCalls(t *testing.T) {
	// Drive elapsed time so the two origins differ even if scheduler samples match.
	var elapsed time.Duration
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) {
		return elapsed, true
	}))
	firstOriginal := syntra.CaptureFrameReceipt(clock)
	elapsed = time.Millisecond
	secondOriginal := syntra.CaptureFrameReceipt(clock)
	if firstOriginal == secondOriginal {
		t.Fatal("fixture must supply distinct original receipts")
	}
	driver := &receiptAPIDriver{receipt: firstOriginal}
	driver.check = func(context.Context) {
		if driver.recvCalls == 2 {
			driver.receipt = secondOriginal
		}
	}
	filter := &receiptAPIFilter{FrameReceiptTransport: driver}
	wrapper := &receiptAPIBufferWrapper{Transport: filter}
	firstCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, receipt, err := syntra.RecvWithReceipt(firstCtx, wrapper)
	if err != nil || string(first) != "accepted frame" || receipt != firstOriginal {
		t.Fatalf("prefetch lost first original receipt: same receipt=%v err=%v", receipt == firstOriginal, err)
	}
	cancel()
	second, receipt, err := syntra.RecvWithReceipt(context.Background(), wrapper)
	if err != nil || string(second) != "accepted frame" || receipt != secondOriginal || &second[0] == &driver.last[0] {
		t.Fatalf("buffered copy lost second original receipt: same receipt=%v err=%v", receipt == secondOriginal, err)
	}
	if filter.calls != 2 || driver.recvCalls != 2 || driver.timedCalls != 0 || wrapper.pending != nil {
		t.Fatal("buffered delivery reread the driver, bypassed policy or retained the buffer")
	}
}

// TestReceiptPublicContextAndNilTransport checks public cancellation, deadline,
// context-value propagation and nil-interface validation without private helpers.
func TestReceiptPublicContextAndNilTransport(t *testing.T) {
	type contextKey struct{}
	base := context.WithValue(context.Background(), contextKey{}, "caller")
	ctx, cancel := context.WithTimeout(base, time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	driver := &receiptAPIDriver{check: func(got context.Context) {
		if when, ok := got.Deadline(); !ok || when != deadline || got.Value(contextKey{}) != "caller" {
			t.Error("helper replaced the caller's context scope")
		}
	}}
	cancel()
	if raw, receipt, err := syntra.RecvWithReceipt(ctx, driver); !errors.Is(err, context.Canceled) || raw != nil || receipt != (syntra.FrameReceipt{}) {
		t.Fatal("helper did not propagate receive cancellation")
	}
	if driver.recvCalls != 1 || driver.timedCalls != 0 {
		t.Fatal("helper did not delegate cancellation to ordinary Recv")
	}
	raw, receipt, err := syntra.RecvWithReceipt(context.Background(), nil)
	var rpc *syntra.RpcError
	if raw != nil || receipt != (syntra.FrameReceipt{}) || !errors.As(err, &rpc) || rpc.Code != syntra.ErrorCodeInvalidArgument {
		t.Fatalf("nil transport not rejected: err=%v", err)
	}
}
