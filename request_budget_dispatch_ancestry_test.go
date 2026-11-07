// File request_budget_dispatch_ancestry_test.go pins serving-context timing inheritance.
package syntra

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/internal/elapsedctx"
)

// TestRequestBudgetSelectorRetainsServingAncestors covers every selector exit
// with independent inherited and declared clocks, before and after selection.
func TestRequestBudgetSelectorRetainsServingAncestors(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		for _, fault := range []string{"expiry", "discontinuity"} {
			for _, early := range []bool{false, true} {
				for _, branch := range []string{"nil", "recovery", "declined", "short", "long", "zero", "negative", "canceled", "invalid"} {
					name := branch + "/" + fault
					if inherited {
						name += "/inherited"
					}
					if early {
						name += "/before-selection"
					}
					t.Run(name, func(t *testing.T) {
						ancestor := &requestBudgetFaultClock{}
						ancestor.elapsed.Store(int64(100 * time.Second))
						parentReceipt := CaptureFrameReceipt(ancestor).receipt
						parentBudget := requestBudgetAt(parentReceipt, parentReceipt.at.Add(time.Minute))
						ctx := context.Background()
						var cancel context.CancelFunc
						if inherited {
							ctx, cancel = context.WithDeadline(context.WithValue(ctx, requestBudgetKey{}, parentBudget), parentBudget.Deadline())
						} else {
							ctx, cancel = elapsedctx.WithDeadline(ctx, ancestor, parentBudget.until, parentBudget.Deadline())
						}
						defer cancel()
						fail := func() {
							if fault == "expiry" {
								ancestor.elapsed.Store(int64(parentBudget.until))
								return
							}
							ancestor.failed.Store(true)
						}
						if early {
							fail()
						}
						clock := &terminalReviewClock{}
						clock.elapsed.Store(int64(1000 * time.Second))
						receipt := CaptureFrameReceipt(clock).receipt
						original := requestBudgetAt(receipt, receipt.at.Add(2*time.Minute))
						req := &RpcRequest{Method: "/example.Echo/Echo"}
						var calls int
						choose := RequestBudgetFunc(func(string, string, []byte) (time.Duration, bool) {
							calls++
							if branch == "declined" {
								return -1, false
							}
							if branch == "zero" {
								return 0, true
							}
							if branch == "negative" {
								return -1, true
							}
							if branch == "long" {
								return time.Duration(math.MaxInt64), true
							}
							return 30 * time.Second, true
						})
						if branch == "nil" {
							choose = nil
						}
						if branch == "recovery" {
							req.Method = RecoveryNegotiate
						}
						if branch == "canceled" {
							cancel()
						}
						if branch == "invalid" {
							receipt.invalid = true
						}
						b := selectRequestBudget(receipt, original.Deadline(), ctx, choose, "alice", req)
						wantCalls := 1
						if early || branch == "nil" || branch == "recovery" || branch == "canceled" || branch == "invalid" {
							wantCalls = 0
						}
						if calls != wantCalls {
							t.Errorf("selector calls=%d want=%d", calls, wantCalls)
						}
						if b.parents == nil || b.receipt != receipt || b.Deadline().After(original.Deadline()) {
							t.Error("selector exit discarded ancestry, replaced receipt or extended deadline")
						}
						if !early && branch != "zero" && branch != "negative" && branch != "canceled" && branch != "invalid" && b.Err() != nil {
							t.Fatal("live independent ancestor prevented admission")
						}
						fail()
						if original.Err() != nil || branch != "canceled" && ctx.Err() != nil {
							t.Fatal("fixture expired the child clock or Go scheduler")
						}
						if b.Err() == nil {
							t.Fatal("dispatch budget outlived its independent serving ancestor")
						}
					})
				}
			}
		}
	}
}

// TestRequestBudgetSelectedCapKeepsProjectedPlainAncestor preserves a plain
// bound hidden beneath SDK declarations when selecting a later application cap.
func TestRequestBudgetSelectedCapKeepsProjectedPlainAncestor(t *testing.T) {
	for _, schedulerOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "elapsed", true: "scheduler-only"}[schedulerOnly], func(t *testing.T) {
			clock := &terminalReviewClock{}
			var receiptClock TerminalClock = clock
			if schedulerOnly {
				receiptClock = nil
			}
			receipt := CaptureFrameReceipt(receiptClock).receipt
			plain, stop := context.WithDeadline(context.Background(), receipt.at.Add(30*time.Second))
			defer stop()
			other := &terminalReviewClock{}
			declared, cancel := elapsedctx.WithDeadline(plain, other, 2*time.Minute, receipt.at.Add(2*time.Minute))
			defer cancel()
			// Keep trusted declarations but hide the effective Go deadline to isolate the
			// plain bound recorded inside that lineage from ordinary deadline clamping.
			ctx := context.WithoutCancel(declared)
			b := selectRequestBudget(receipt, receipt.at.Add(3*time.Minute), ctx,
				func(string, string, []byte) (time.Duration, bool) { return time.Minute, true }, "alice", &RpcRequest{Method: "/example.Echo/Echo"})
			if b.Err() != nil {
				t.Fatal("live projected plain ancestor prevented admission")
			}
			if schedulerOnly {
				deadline, _ := plain.Deadline()
				if b.Deadline().After(deadline) {
					t.Fatal("scheduler-only budget discarded a hidden plain deadline")
				}
				return
			}
			clock.elapsed.Store(int64(30 * time.Second))
			if other.Age() != 0 || plain.Err() != nil || b.Err() == nil {
				t.Fatal("selected cap discarded the tighter receipt-projected plain cutoff")
			}
		})
	}
}

// TestRequestBudgetNestedServeRetainsOuterCutoff holds the outer reaper so that
// only inner dispatch, not scheduler cancellation, can reject an expired ancestor.
func TestRequestBudgetNestedServeRetainsOuterCutoff(t *testing.T) {
	for _, stage := range []string{"authorization", "completion"} {
		t.Run(stage, func(t *testing.T) {
			ancestor, child := &terminalReviewClock{}, &terminalReviewClock{}
			var effects atomic.Int32
			var outerBudget RequestBudget
			cfg := testHostConfig()
			cfg.Authorize = func(ctx context.Context, _, _ string) error {
				if stage == "authorization" {
					ancestor.elapsed.Store(int64(outerBudget.until))
					if ctx.Err() != nil || outerBudget.Err() == nil {
						t.Error("fixture must expire trusted ancestry before scheduler cancellation")
					}
				}
				return nil
			}
			cfg.Handler = func(context.Context, *RpcRequest) (*RpcResult, error) {
				effects.Add(1)
				ancestor.elapsed.Store(int64(outerBudget.until))
				return NewSuccessResult([]byte("late")), nil
			}
			inner, err := OpenHost(cfg)
			if err != nil {
				t.Fatal(err)
			}
			a, b := LoopbackPair()
			t.Cleanup(func() {
				_ = inner.Close()
				_ = b.Close()
				ctx, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := inner.Wait(ctx); err != nil {
					t.Error(err)
				}
			})
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			cfg = testHostConfig()
			cfg.RequestBudget = func(_, method string, _ []byte) (time.Duration, bool) {
				if method == "/example.Gate/Hold" {
					close(entered)
					<-release
				}
				return 0, false
			}
			cfg.Handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
				outerBudget, _ = RequestBudgetFromContext(ctx)
				err := inner.Serve(ctx, &terminalReviewDriver{Transport: a, clock: child})
				return NewSuccessResult(nil), err
			}
			outer := newRawSessionPeer(t, cfg, func(tr Transport) Transport {
				return &terminalReviewDriver{Transport: tr, clock: ancestor}
			})
			outer.request(t, 1, "/example.Nested/Serve")
			peer := &rawSessionPeer{peer: b, ctx: outer.ctx}
			peer.send(t, NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
			if BodyKindOf(peer.recv(t)) != BodyKindReady {
				t.Fatal("nested host did not complete handshake")
			}
			outer.request(t, 2, "/example.Gate/Hold")
			hostWriterSignal(t, entered, "outer reaper barrier")
			peer.request(t, 1, "/example.Echo/Echo")
			assertTerminalCode(t, peer.recv(t), 1, ErrorCodeDeadlineExceeded)
			want := int32(0)
			if stage == "completion" {
				want = 1
			}
			if effects.Load() != want || child.Age() != 0 {
				t.Fatalf("nested effects=%d want=%d child age=%v", effects.Load(), want, child.Age())
			}
		})
	}
}
