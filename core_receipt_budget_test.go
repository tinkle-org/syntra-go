// File core_receipt_budget_test.go checks trusted expiry before core dispatch.
package syntra

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

// TestCoreReceiptExpiryPrecedesAdmissionErrors charges buffered trusted time
// before selecting a semantic or concurrency error, without invoking policy.
func TestCoreReceiptExpiryPrecedesAdmissionErrors(t *testing.T) {
	for _, rejection := range []string{"malformed-method", "concurrency"} {
		t.Run(rejection, func(t *testing.T) {
			core := newActiveFindingHost(t, HostConfig{MaxConcurrent: MaxConcurrentRPCs})
			id := uint64(1)
			method := "malformed"
			if rejection == "concurrency" {
				method = "/example.Echo/Echo"
				for ; id <= uint64(core.cfg.maxPending); id++ {
					if _, _, fatal := core.onFrame(mustMarshal(NewRequestFrame(1, id, &RpcRequest{Method: method, TimeoutMs: 1000}))); fatal != nil {
						t.Fatal(fatal)
					}
				}
			}
			clock := &terminalReviewClock{}
			receipt := CaptureFrameReceipt(clock).receipt
			raw, err := proto.Marshal(NewRequestFrame(1, id, &RpcRequest{Method: method, TimeoutMs: 40}))
			if err != nil {
				t.Fatal(err)
			}
			clock.elapsed.Store(int64(80 * time.Millisecond))
			if !time.Now().Before(receipt.at.Add(40 * time.Millisecond)) {
				t.Fatal("fixture must expire trusted time without exhausting Go time")
			}
			pending := len(core.pending)
			if _, _, fatal := core.onFrameReceipt(raw, receipt); fatal != nil {
				t.Fatal(fatal)
			}
			response, ok := core.nextOutbound()
			if !ok {
				t.Fatal("missing expired request result")
			}
			frame, err := UnmarshalFrame(response)
			if err != nil {
				t.Fatal(err)
			}
			assertTerminalCode(t, frame, id, ErrorCodeDeadlineExceeded)
			if len(core.pending) != pending || core.outstanding[id] != nil || core.highwater != id {
				t.Fatal("expired request changed pending work or failed to consume its ID")
			}
			if _, _, fatal := core.onFrameReceipt(raw, receipt); fatal == nil || fatal.Code != ErrorCodeFailedPrecondition {
				t.Fatalf("expiry hid replay rejection: %v", fatal)
			}
		})
	}
}

// TestCoreReceiptBudgetProtectsPendingBeforeSelector binds each original timeout
// source at admission, so reaping and terminal selection cannot await dispatch.
func TestCoreReceiptBudgetProtectsPendingBeforeSelector(t *testing.T) {
	for _, source := range []string{"wire", "default", "maximum"} {
		t.Run(source, func(t *testing.T) {
			cfg := HostConfig{DefaultTimeout: time.Second, MaxTimeout: time.Second}
			wire := uint32(40)
			if source == "default" {
				cfg.DefaultTimeout, wire = 40*time.Millisecond, 0
			}
			if source == "maximum" {
				cfg.MaxTimeout, wire = 40*time.Millisecond, 1000
			}
			core := newActiveFindingHost(t, cfg)
			clock := &terminalReviewClock{}
			receipt := CaptureFrameReceipt(clock).receipt
			if _, _, fatal := core.onFrameReceipt(mustMarshal(NewRequestFrame(1, 1, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: wire})), receipt); fatal != nil {
				t.Fatal(fatal)
			}
			call := core.outstanding[1]
			if call == nil {
				t.Fatal("live request was not admitted")
			}
			if call.budget == nil || call.budget.receipt != receipt || call.budget.until != 40*time.Millisecond {
				t.Error("pending request lacks the original receipt-bound budget")
			}
			clock.elapsed.Store(int64(80 * time.Millisecond))
			if core.terminalPending(1) {
				t.Error("expired pending call remains eligible for terminal reservation")
			}
			if ids := core.reapExpired(time.Now()); len(ids) != 1 || ids[0] != 1 {
				t.Fatalf("trusted expiry before selector was ignored: ids=%v", ids)
			}
			if _, _, ok := core.takePending(); ok {
				t.Fatal("reaped request remains queued for selector/authorization")
			}
			raw, ok := core.nextOutbound()
			if !ok {
				t.Fatal("missing deadline result")
			}
			frame, err := UnmarshalFrame(raw)
			if err != nil {
				t.Fatal(err)
			}
			assertTerminalCode(t, frame, 1, ErrorCodeDeadlineExceeded)
		})
	}
}

// TestCoreReceiptExpiryPreservesHeaderAndIDPrecedence keeps structural/session
// failures ahead of per-request timing, including fatal replay and output bounds.
func TestCoreReceiptExpiryPreservesHeaderAndIDPrecedence(t *testing.T) {
	for _, failure := range []string{"malformed-wire", "zero-id", "version", "replay", "output-capacity"} {
		t.Run(failure, func(t *testing.T) {
			core := newActiveFindingHost(t, HostConfig{})
			clock := &terminalReviewClock{}
			receipt := CaptureFrameReceipt(clock).receipt
			frame := NewRequestFrame(1, 1, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 40})
			want, highwater := ErrorCodeInvalidArgument, uint64(0)
			switch failure {
			case "zero-id":
				frame.RequestId = 0
			case "version":
				frame.Version, want = 2, ErrorCodeFailedPrecondition
			case "replay":
				if _, _, fatal := core.onFrame(mustMarshal(frame)); fatal != nil {
					t.Fatal(fatal)
				}
				want, highwater = ErrorCodeFailedPrecondition, 1
			case "output-capacity":
				core.outbound = make([][]byte, core.cfg.writerCapacity+core.cfg.maxPending)
				want, highwater = ErrorCodeResourceExhausted, 1
			}
			raw, err := proto.Marshal(frame)
			if err != nil {
				t.Fatal(err)
			}
			if failure == "malformed-wire" {
				raw = []byte{0xff}
			}
			outbound := len(core.outbound)
			clock.elapsed.Store(int64(80 * time.Millisecond))
			_, _, fatal := core.onFrameReceipt(raw, receipt)
			if fatal == nil || fatal.Code != want || core.highwater != highwater || len(core.outbound) != outbound {
				t.Fatalf("trusted expiry changed header/ID precedence: fatal=%v highwater=%d outbound=%d", fatal, core.highwater, len(core.outbound))
			}
		})
	}
}
