// File budget_ancestor_retention_test.go checks nonbinding projection and live ancestor constraints.
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

// TestTerminalNonbindingParentCannotOverflowProjection keeps a distant plain
// parent from invalidating an otherwise live, short request/operation budget.
func TestTerminalNonbindingParentCannotOverflowProjection(t *testing.T) {
	clock := &terminalReviewClock{}
	clock.elapsed.Store(int64(10 * time.Second))
	receipt := CaptureFrameReceipt(clock).receipt
	original := requestBudgetAt(receipt, receipt.at.Add(500*time.Millisecond))
	p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline}
	far := time.Date(9999, time.December, 31, 0, 0, 0, 0, time.UTC)
	if far.Sub(receipt.at) != time.Duration(math.MaxInt64) {
		t.Fatal("fixture must saturate time.Duration before adding a positive clock age")
	}
	parent, cancel := context.WithDeadline(context.Background(), far)
	defer cancel()
	ctx, stop, b := p.authorityContext(parent, time.Second)
	defer stop()
	if ctx.Err() != nil || b.Err() != nil || b.invalid || b.until > original.until || b.Remaining() > 500*time.Millisecond {
		t.Fatalf("nonbinding parent poisoned live operation: ctx=%v budget=%v invalid=%v until=%v", ctx.Err(), b.Err(), b.invalid, b.until)
	}
	if original != p.budget || b.receipt != receipt {
		t.Fatal("projection mutated the original receipt budget")
	}
}

// TestTerminalEffectiveProjectionOverflowStillFailsClosed preserves failure when
// the selected deadline itself cannot be represented on the original clock.
func TestTerminalEffectiveProjectionOverflowStillFailsClosed(t *testing.T) {
	clock := &terminalReviewClock{}
	clock.elapsed.Store(math.MaxInt64 - int64(100*time.Millisecond))
	receipt := CaptureFrameReceipt(clock).receipt
	original := requestBudgetAt(receipt, receipt.at.Add(500*time.Millisecond))
	if !original.invalid {
		t.Fatal("fixture must overflow its effective elapsed cutoff")
	}
	p := &TerminalPermit{valid: true, clock: clock, budget: original, until: time.Duration(math.MaxInt64), wallUntil: receipt.at.Add(500 * time.Millisecond)}
	ctx, stop, b := p.authorityContext(context.Background(), time.Second)
	defer stop()
	if ctx.Err() != context.DeadlineExceeded || b.Err() == nil {
		t.Fatal("effective overflow was repaired by parent intersection")
	}
}

// ancestorPermit creates a request on clock B and a declared parent on independent
// clock A. The parent has no elapsed watchdog of its own to mask missing checks.
func ancestorPermit(t *testing.T, inherited bool) (*TerminalPermit, context.Context, *requestBudgetFaultClock, RequestBudget) {
	t.Helper()
	clock := &terminalReviewClock{}
	receipt := CaptureFrameReceipt(clock).receipt
	original := requestBudgetAt(receipt, receipt.at.Add(3*time.Second))
	p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline,
		transition: TerminalTransition{ExpectedRevision: 1}, policy: TerminalMethodPolicy{ObservationTimeout: time.Second}}
	ancestor := &requestBudgetFaultClock{}
	ancestor.elapsed.Store(int64(100 * time.Second))
	var parent context.Context
	var stop context.CancelFunc
	if inherited {
		receiptA := CaptureFrameReceipt(ancestor).receipt
		budgetA := requestBudgetAt(receiptA, receiptA.at.Add(time.Second))
		parent, stop = context.WithDeadline(context.WithValue(context.Background(), requestBudgetKey{}, budgetA), budgetA.deadline)
	} else {
		parent, stop = elapsedctx.WithDeadline(context.Background(), ancestor, 101*time.Second, time.Now().Add(time.Second))
	}
	t.Cleanup(stop)
	return p, parent, ancestor, original
}

// failAncestor changes only clock A, without advancing clock B or Go timers.
func failAncestor(clock *requestBudgetFaultClock, fault string) {
	if fault == "expiry" {
		clock.elapsed.Store(int64(101 * time.Second))
		return
	}
	clock.failed.Store(true)
}

// TestTerminalAncestorFailureDuringProof rejects otherwise owned-looking evidence
// after an independent declared ancestor expires or loses clock continuity.
func TestTerminalAncestorFailureDuringProof(t *testing.T) {
	for _, test := range []struct {
		fault     string
		inherited bool
	}{
		{fault: "expiry"}, {fault: "discontinuity"},
		{fault: "expiry", inherited: true}, {fault: "discontinuity", inherited: true},
	} {
		name := test.fault
		if test.inherited {
			name += "/inherited-budget"
		}
		t.Run(name, func(t *testing.T) {
			p, parent, ancestor, original := ancestorPermit(t, test.inherited)
			p.policy.Authority = &terminalReviewAuthority{observe: func(ctx context.Context, tr TerminalTransition) (TerminalObservation, error) {
				if ctx.Err() != nil {
					t.Error("callback was already canceled before ancestor failure")
				}
				failAncestor(ancestor, test.fault)
				if original.Err() != nil || parent.Err() != nil {
					t.Error("fixture must leave clock B and the parent scheduler timer live")
				}
				b, ok := RequestBudgetFromContext(ctx)
				if !ok || b.Err() == nil {
					t.Error("derived read budget forgot the failed ancestor")
				}
				// Strip only the new ancestry to prove this read's own domain
				// is still live; failure must come from retained clock A.
				b.parents = nil
				if b.Err() != nil {
					t.Error("fixture unexpectedly expired the read's own clock")
				}
				return TerminalObservation{State: TerminalOwnedCommitted, Transition: tr, Revision: 2}, nil
			}}
			state, err := p.Observe(parent, true)
			if err == nil || state != TerminalUnknown || p.owned || p.CheckTime() == nil || p.Handoff() == nil {
				t.Fatalf("ancestor failure accepted owned proof: state=%v err=%v owned=%v", state, err, p.owned)
			}
			// A fresh unbounded observer cannot clear the previously observed failure.
			if _, err := p.Observe(context.Background(), true); err == nil {
				t.Fatal("ancestor failure was not sticky")
			}
		})
	}
}

// TestTerminalAncestorWatchdogInterruptsBlockedObserver requires independent
// ancestor failure to cancel the callback and stop I/O before it returns.
func TestTerminalAncestorWatchdogInterruptsBlockedObserver(t *testing.T) {
	for _, fault := range []string{"expiry", "discontinuity"} {
		t.Run(fault, func(t *testing.T) {
			p, parent, ancestor, original := ancestorPermit(t, false)
			entered := make(chan context.Context, 1)
			release, stopped := make(chan struct{}), make(chan struct{})
			var releaseOnce, stopOnce sync.Once
			p.stopIO = func() { stopOnce.Do(func() { close(stopped) }) }
			p.policy.Authority = &terminalReviewAuthority{observe: func(ctx context.Context, tr TerminalTransition) (TerminalObservation, error) {
				entered <- ctx
				<-release // Deliberately ignore cancellation until actual owner joins.
				return TerminalObservation{State: TerminalOwnedCommitted, Transition: tr, Revision: 2}, nil
			}}
			done := make(chan error, 1)
			go func() { _, err := p.Observe(parent, true); done <- err }()
			defer func() { releaseOnce.Do(func() { close(release) }); <-done }()
			ctx := <-entered
			failAncestor(ancestor, fault)
			select {
			case <-stopped:
			case <-time.After(250 * time.Millisecond):
				t.Fatal("ancestor failure did not interrupt I/O while observer was blocked")
			}
			if original.Err() != nil || parent.Err() != nil || ctx.Err() == nil || p.CheckTime() == nil {
				t.Fatal("watchdog must cancel from ancestor failure, not original or Go timer expiry")
			}
		})
	}
}

// TestTerminalCallerAncestorSurvivesReservation exercises caller-only provenance
// across Begin, Commit, proof, and the final Handoff rather than scope.ctx alone.
func TestTerminalCallerAncestorSurvivesReservation(t *testing.T) {
	for _, stage := range []string{"begin", "commit", "proof", "handoff"} {
		t.Run(stage, func(t *testing.T) {
			h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
			ancestor := &requestBudgetFaultClock{}
			var failingBudgetLive atomic.Bool
			fail := func(ctx context.Context) {
				ancestor.failed.Store(true)
				if b, ok := RequestBudgetFromContext(ctx); ok && b.Err() == nil {
					failingBudgetLive.Store(true)
				}
			}
			if stage == "begin" {
				driver.afterBegin = func(ctx context.Context, _ *TerminalPermit) { fail(ctx) }
			}
			authority.commit = func(ctx context.Context, tr TerminalTransition) error {
				if stage == "commit" {
					fail(ctx)
				}
				authority.mu.Lock()
				authority.owner = &tr
				authority.mu.Unlock()
				return nil // Durable work is not rolled back by receipt denial.
			}
			authority.observe = func(ctx context.Context, tr TerminalTransition) (TerminalObservation, error) {
				authority.mu.Lock()
				owned := authority.owner != nil
				authority.mu.Unlock()
				if !owned {
					return TerminalObservation{State: TerminalActive, Transition: tr, Revision: 1}, nil
				}
				if stage == "proof" {
					fail(ctx)
				}
				return TerminalObservation{State: TerminalOwnedCommitted, Transition: tr, Revision: 2}, nil
			}
			if stage == "handoff" {
				driver.beforeSend = func() { ancestor.failed.Store(true) }
			}
			result := make(chan error, 1)
			h.cfg.handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
				caller, stop := elapsedctx.WithDeadline(ctx, ancestor, 2*time.Second, time.Now().Add(2*time.Second))
				defer stop()
				err := CompleteTerminalReceipt(caller, "operation", 1)
				result <- err
				return nil, err
			}
			dispatchBudgetTerminal(t, h, hc)
			joinBudgetTerminal(t, hc)
			if err := <-result; err == nil || driver.handoffs.Load() != 0 || failingBudgetLive.Load() {
				t.Fatalf("caller ancestor forgotten at %s: err=%v handoffs=%d callbackBudgetLive=%v", stage, err, driver.handoffs.Load(), failingBudgetLive.Load())
			}
			if stage == "begin" && authority.commits.Load() != 0 {
				t.Fatal("ancestor failure before Commit admitted mutation")
			}
			if stage != "begin" && authority.commits.Load() != 1 {
				t.Fatal("fixture must retain one admitted durable mutation, not claim rollback")
			}
		})
	}
}

// ancestorStopDriver exposes the real permit watchdog's prompt nonjoining stop
// without relying on a custom driver's own elapsed polling or callback cancel.
type ancestorStopDriver struct {
	*terminalReviewDriver
	stopped chan struct{}
	once    sync.Once
}

// TerminalReceiptDriver keeps terminal ownership on this stop-observing wrapper.
func (d *ancestorStopDriver) TerminalReceiptDriver() TerminalReceiptDriver { return d }

// StopTerminal records interruption without joining or releasing durable work.
func (d *ancestorStopDriver) StopTerminal() { d.once.Do(func() { close(d.stopped) }) }

// TestTerminalCallerAncestorStopsBlockedCommit checks the reservation watchdog
// and Commit budget even when caller-only clock failure occurs during durable work.
func TestTerminalCallerAncestorStopsBlockedCommit(t *testing.T) {
	h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
	wrapped := &ancestorStopDriver{terminalReviewDriver: driver, stopped: make(chan struct{})}
	hc.transport = wrapped
	ancestor := &requestBudgetFaultClock{}
	entered := make(chan context.Context, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	authority.commit = func(ctx context.Context, tr TerminalTransition) error {
		entered <- ctx
		<-release
		authority.mu.Lock()
		authority.owner = &tr
		authority.mu.Unlock()
		return nil // Late durable success cannot restore receipt eligibility.
	}
	result := make(chan error, 1)
	h.cfg.handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
		caller, stop := elapsedctx.WithDeadline(ctx, ancestor, 2*time.Second, time.Now().Add(2*time.Second))
		defer stop()
		err := CompleteTerminalReceipt(caller, "operation", 1)
		result <- err
		return nil, err
	}
	dispatchBudgetTerminal(t, h, hc)
	defer func() {
		releaseOnce.Do(func() { close(release) })
		joinBudgetTerminal(t, hc)
		if err := <-result; err == nil || driver.handoffs.Load() != 0 || authority.commits.Load() != 1 {
			t.Errorf("late Commit restored receipt: err=%v handoffs=%d commits=%d", err, driver.handoffs.Load(), authority.commits.Load())
		}
	}()
	ctx := <-entered
	ancestor.failed.Store(true)
	select {
	case <-wrapped.stopped:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("caller ancestor failure did not interrupt I/O during blocked Commit")
	}
	b, ok := RequestBudgetFromContext(ctx)
	if ctx.Err() == nil || !ok || b.Err() == nil {
		t.Fatal("blocked Commit retained eligibility after caller ancestor failure")
	}
}
