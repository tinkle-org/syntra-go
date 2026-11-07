// File elapsed_parent_provenance_test.go pins trusted deadline lineage and plain parent clamps.
package syntra

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/internal/elapsedctx"
)

// declaredParentClock intentionally has a noncomparable dynamic value. Provenance
// must use remaining duration, not reflection or interface equality assumptions.
type declaredParentClock struct {
	age *atomic.Int64
	_   []byte
}

// Age reports this independent clock's absolute age.
func (c declaredParentClock) Age() time.Duration { return time.Duration(c.age.Load()) }

// Check leaves continuity intact for independent-origin conversion tests.
func (declaredParentClock) Check() error { return nil }

// TestTerminalDeclaredParentLineage distinguishes actual declared projections
// from plain earlier deadlines, including plain parents hidden by a later phase.
func TestTerminalDeclaredParentLineage(t *testing.T) {
	for _, test := range []struct {
		name       string
		plain      bool
		nested     bool
		dominating bool
	}{
		{name: "fresh-driver"},
		{name: "outer-declared-wins", nested: true},
		{name: "inner-declared-wins", nested: true, dominating: true},
		{name: "plain-child", plain: true},
		{name: "plain-between-declarations", plain: true, nested: true},
		{name: "plain-hidden-by-inner-projection", plain: true, nested: true, dominating: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := &requestBudgetFaultClock{}
			receipt := CaptureFrameReceipt(clock).receipt
			original := requestBudgetAt(receipt, receipt.at.Add(3*time.Second))
			p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline}
			clock.elapsed.Store(int64(500 * time.Millisecond))
			parent, stop := elapsedctx.WithDeadline(context.Background(), clock, 700*time.Millisecond, time.Now().Add(200*time.Millisecond))
			defer stop()
			if test.plain {
				var cancel context.CancelFunc
				parent, cancel = context.WithDeadline(parent, receipt.at.Add(100*time.Millisecond))
				defer cancel()
			}
			wantUntil := 700 * time.Millisecond
			if test.nested {
				until, projection := 2*time.Second, time.Now().Add(time.Second)
				if test.dominating {
					until, projection = 550*time.Millisecond, time.Now().Add(50*time.Millisecond)
					wantUntil = until
				}
				var cancel context.CancelFunc
				parent, cancel = elapsedctx.WithDeadline(parent, clock, until, projection)
				defer cancel()
			}
			ctx, cancel, b := p.authorityContext(parent, time.Second)
			defer cancel()
			if test.plain {
				if ctx.Err() != context.DeadlineExceeded || b.Remaining() != 0 || b.until > 100*time.Millisecond {
					t.Fatalf("plain parent renewed: err=%v until=%v remaining=%v", ctx.Err(), b.until, b.Remaining())
				}
			} else {
				if ctx.Err() != nil || b.Remaining() == 0 || b.until > wantUntil {
					t.Fatalf("declared lineage remapped or extended: err=%v until=%v remaining=%v", ctx.Err(), b.until, b.Remaining())
				}
				clock.elapsed.Store(int64(wantUntil))
				_, stopExpired, expired := p.authorityContext(parent, time.Second)
				defer stopExpired()
				if expired.Remaining() != 0 {
					t.Fatal("declared absolute cutoff renewed on reattachment")
				}
			}
			if b.receipt != original.receipt || p.budget != original {
				t.Fatal("parent intersection replaced original receipt or permit budget")
			}
		})
	}
}

// TestTerminalDeclaredParentIndependentOrigins intersects durations even with
// unrelated origins and noncomparable Clock values; no raw until can be shared.
func TestTerminalDeclaredParentIndependentOrigins(t *testing.T) {
	clock := &terminalReviewClock{}
	clock.elapsed.Store(int64(10 * time.Second))
	receipt := CaptureFrameReceipt(clock).receipt
	original := requestBudgetAt(receipt, receipt.at.Add(3*time.Second))
	p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline}
	clock.elapsed.Store(int64(10500 * time.Millisecond))
	var other atomic.Int64
	other.Store(int64(100 * time.Second))
	parent, stop := elapsedctx.WithDeadline(context.Background(), declaredParentClock{age: &other}, 100*time.Second+200*time.Millisecond, time.Now().Add(200*time.Millisecond))
	defer stop()
	ctx, cancel, b := p.authorityContext(parent, time.Second)
	defer cancel()
	if ctx.Err() != nil || b.Remaining() == 0 || b.until > 10700*time.Millisecond {
		t.Fatalf("independent origins misconverted: err=%v until=%v remaining=%v", ctx.Err(), b.until, b.Remaining())
	}
	other.Store(int64(100*time.Second + 200*time.Millisecond))
	_, stopExpired, expired := p.authorityContext(parent, time.Second)
	defer stopExpired()
	if expired.Remaining() != 0 {
		t.Fatal("independent declared cutoff renewed")
	}
}

// TestTerminalDeclaredParentOriginalBoundsWin preserves request and operation
// cutoffs, sticky continuity loss and cancellation despite fresh driver metadata.
func TestTerminalDeclaredParentOriginalBoundsWin(t *testing.T) {
	for _, fault := range []string{"rpc", "operation", "discontinuity", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			clock := &requestBudgetFaultClock{}
			receipt := CaptureFrameReceipt(clock).receipt
			original := requestBudgetAt(receipt, receipt.at.Add(time.Second))
			p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline}
			parent, stop := elapsedctx.WithDeadline(context.Background(), clock, 5*time.Second, time.Now().Add(5*time.Second))
			defer stop()
			switch fault {
			case "rpc":
				clock.elapsed.Store(int64(time.Second))
			case "operation":
				p.until = 500 * time.Millisecond
				clock.elapsed.Store(int64(p.until))
			case "discontinuity":
				clock.failed.Store(true)
			case "cancel":
				stop()
			}
			ctx, cancel, b := p.authorityContext(parent, time.Second)
			defer cancel()
			if b.Remaining() != 0 && ctx.Err() == nil {
				t.Fatal("declared metadata extended original bound or cleared cancellation")
			}
		})
	}
}

// TestTerminalDeclaredCallbackLineage retains an earlier root-created SDK timer
// through later driver phases and nested authority callbacks after suspension.
func TestTerminalDeclaredCallbackLineage(t *testing.T) {
	clock := &terminalReviewClock{}
	receipt := CaptureFrameReceipt(clock).receipt
	original := requestBudgetAt(receipt, receipt.at.Add(3*time.Second))
	p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline}
	clock.elapsed.Store(int64(2500 * time.Millisecond))
	write, stop, writeBudget := p.authorityContext(context.Background(), 0)
	defer stop()
	driver, stopDriver := elapsedctx.WithDeadline(write, clock, 2900*time.Millisecond, time.Now().Add(400*time.Millisecond))
	defer stopDriver()
	callback, stopCallback, first := p.authorityContext(driver, 100*time.Millisecond)
	defer stopCallback()
	_, stopNested, nested := p.authorityContext(callback, time.Second)
	defer stopNested()
	if nested.Remaining() == 0 || nested.until > first.until || first.until > writeBudget.until {
		t.Fatalf("root/driver lineage reprojected: write=%v first=%v nested=%v remaining=%v", writeBudget.until, first.until, nested.until, nested.Remaining())
	}
}

// TestTerminalDeclaredForeignClockDiscontinuity rejects an invalid parent clock
// even while the original request's different clock and scheduler timer are live.
func TestTerminalDeclaredForeignClockDiscontinuity(t *testing.T) {
	clock := &terminalReviewClock{}
	receipt := CaptureFrameReceipt(clock).receipt
	original := requestBudgetAt(receipt, receipt.at.Add(3*time.Second))
	p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline}
	other := &requestBudgetFaultClock{}
	parent, stop := elapsedctx.WithDeadline(context.Background(), other, time.Second, time.Now().Add(time.Second))
	defer stop()
	other.failed.Store(true)
	ctx, cancel, b := p.authorityContext(parent, time.Second)
	defer cancel()
	if original.Remaining() == 0 || parent.Err() != nil {
		t.Fatal("fixture must keep original timing and parent scheduler live")
	}
	if ctx.Err() != context.DeadlineExceeded || b.Remaining() != 0 {
		t.Fatal("foreign declared clock failure admitted a read")
	}
}

// TestTerminalDeadlineLookalikeCannotDeclareProvenance keeps application or wire
// lookalikes from exempting a plain earlier deadline. Only internal SDK keys count.
func TestTerminalDeadlineLookalikeCannotDeclareProvenance(t *testing.T) {
	clock := &terminalReviewClock{}
	receipt := CaptureFrameReceipt(clock).receipt
	original := requestBudgetAt(receipt, receipt.at.Add(3*time.Second))
	p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline}
	type lookalike struct {
		Clock     TerminalClock
		Until     time.Duration
		Projected time.Time
	}
	// Arbitrary context values are not internal declarations or proof.
	type applicationKey struct{}
	base := context.WithValue(context.Background(), applicationKey{}, lookalike{Clock: clock, Until: 2 * time.Second, Projected: receipt.at.Add(100 * time.Millisecond)})
	parent, stop := context.WithDeadline(base, receipt.at.Add(100*time.Millisecond))
	defer stop()
	clock.elapsed.Store(int64(500 * time.Millisecond))
	_, cancel, b := p.authorityContext(parent, time.Second)
	defer cancel()
	if b.Remaining() != 0 || b.until > 100*time.Millisecond {
		t.Fatal("application metadata renewed an expired plain deadline")
	}
}

// TestTerminalDeclaredEarlierCaller reserves from a real handler with an earlier
// SDK-declared timer created after suspension, without forgiving its own expiry.
func TestTerminalDeclaredEarlierCaller(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "live", true: "expired"}[expired], func(t *testing.T) {
			h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
			policy := h.cfg.terminalMethods[terminalReviewMethod]
			policy.ObservationTimeout = 5 * time.Millisecond
			h.cfg.terminalMethods[terminalReviewMethod] = policy
			result := make(chan error, 1)
			h.cfg.handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
				driver.clock.elapsed.Store(int64(500 * time.Millisecond))
				caller, cancel := elapsedctx.WithDeadline(ctx, driver.clock, 700*time.Millisecond, time.Now().Add(200*time.Millisecond))
				defer cancel()
				if expired {
					driver.clock.elapsed.Store(int64(700 * time.Millisecond))
				}
				err := CompleteTerminalReceipt(caller, "operation", 1)
				result <- err
				return nil, err
			}
			dispatchBudgetTerminal(t, h, hc)
			joinBudgetTerminal(t, hc)
			err := <-result
			if expired {
				if err == nil || authority.commits.Load() != 0 || driver.handoffs.Load() != 0 || hc.terminalFenced.Load() {
					t.Fatalf("expired declared caller admitted: err=%v commits=%d handoffs=%d", err, authority.commits.Load(), driver.handoffs.Load())
				}
				return
			}
			if err != nil || authority.commits.Load() != 1 || driver.handoffs.Load() != 1 {
				t.Fatalf("live declared caller remapped: err=%v commits=%d handoffs=%d", err, authority.commits.Load(), driver.handoffs.Load())
			}
		})
	}
}
