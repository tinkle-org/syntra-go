// File terminal_callback_budget_test.go checks exact authority callback budgets,
// including observations made without a request-scoped driver context.
package syntra

import (
	"context"
	"testing"
	"time"
)

// TestTerminalObserveDerivesBudgetWithoutRequestContext exercises manual permits
// and refresh contexts with each possible earlier cutoff independently dominant.
func TestTerminalObserveDerivesBudgetWithoutRequestContext(t *testing.T) {
	for _, cutoff := range []string{"elapsed", "permit-wall", "read", "parent", "parent-elapsed"} {
		t.Run(cutoff, func(t *testing.T) {
			clock := &terminalReviewClock{}
			clock.elapsed.Store(int64(10 * time.Second))
			p := &TerminalPermit{valid: true, clock: clock, until: 12 * time.Second, wallUntil: time.Now().Add(2 * time.Second)}
			p.policy.ObservationTimeout = time.Second
			ctx := context.Background() // driver refresh has no root SDK budget
			limit := 80 * time.Millisecond
			switch cutoff {
			case "elapsed":
				p.until = 10*time.Second + limit
			case "permit-wall":
				p.wallUntil = time.Now().Add(limit)
			case "read":
				p.policy.ObservationTimeout = limit
			case "parent":
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, limit)
				defer cancel()
			case "parent-elapsed":
				parentBudget := RequestBudget{deadline: time.Now().Add(2 * time.Second), receipt: requestReceipt{clock: clock, age: 10 * time.Second}, until: 10*time.Second + limit}
				ctx = context.WithValue(ctx, requestBudgetKey{}, parentBudget)
			}
			called := false
			p.policy.Authority = &terminalReviewAuthority{observe: func(readCtx context.Context, tr TerminalTransition) (TerminalObservation, error) {
				called = true
				b, ok := RequestBudgetFromContext(readCtx)
				if !ok {
					t.Error("driver refresh observer lacks SDK budget")
					return TerminalObservation{State: TerminalActive, Transition: tr}, nil
				}
				d, hasDeadline := readCtx.Deadline()
				before := time.Until(d)
				left := b.Remaining()
				if !hasDeadline || !b.Deadline().Equal(d) || d.After(p.wallUntil) || before > limit || left <= 0 || left > before || left > p.until-clock.Age() || b.until > p.until {
					t.Errorf("observer escaped %s cutoff: context=%v budget=%v remaining=%v until=%v", cutoff, before, b.Deadline(), left, b.until)
				}
				if b.receipt.clock != clock {
					t.Error("observer lost the permit's original clock")
				}
				return TerminalObservation{State: TerminalActive, Transition: tr}, nil
			}}
			if _, err := p.Observe(ctx, false); err != nil || !called {
				t.Fatalf("manual permit observation failed: called=%v err=%v", called, err)
			}
		})
	}
}

// TestTerminalCommitBudgetExcludesTail checks real request scope and confirms
// mutation sees the permit cutoff rather than the larger original root budget.
func TestTerminalCommitBudgetExcludesTail(t *testing.T) {
	h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
	policy := h.cfg.terminalMethods[terminalReviewMethod]
	policy.ObservationTimeout = 10 * time.Millisecond
	h.cfg.terminalMethods[terminalReviewMethod] = policy
	h.cfg.requestBudget = func(string, string, []byte) (time.Duration, bool) { return time.Second, true }
	var permit *TerminalPermit
	var original RequestBudget
	driver.afterBegin = func(_ context.Context, p *TerminalPermit) { permit = p }
	authority.commit = func(ctx context.Context, tr TerminalTransition) error {
		b, ok := RequestBudgetFromContext(ctx)
		d, hasDeadline := ctx.Deadline()
		before := time.Until(d)
		if !ok || !hasDeadline || !b.Deadline().Equal(d) || d.After(permit.wallUntil) || b.until > permit.until || b.Remaining() > before {
			t.Errorf("Commit retained root allowance: ok=%v context=%v budget=%v until=%v permit=%v", ok, d, b.Deadline(), b.until, permit.until)
		}
		if !b.receipt.at.Equal(original.receipt.at) || b.receipt.age != original.receipt.age || b.receipt.clock != original.receipt.clock {
			t.Error("Commit derived a new receipt/clock origin")
		}
		authority.mu.Lock()
		authority.owner = &tr
		authority.mu.Unlock()
		return nil
	}
	result := make(chan error, 1)
	h.cfg.handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
		original, _ = RequestBudgetFromContext(ctx)
		err := CompleteTerminalReceipt(ctx, "operation", 1)
		result <- err
		return nil, err
	}
	dispatchBudgetTerminal(t, h, hc)
	joinBudgetTerminal(t, hc)
	if err := <-result; err != nil || driver.handoffs.Load() != 1 {
		t.Fatalf("healthy derived Commit budget failed: %v", err)
	}
}

// TestTerminalObservePreservesParentCancellation checks that a derived refresh
// context remains a direct cancellation child rather than waiting for polling.
func TestTerminalObservePreservesParentCancellation(t *testing.T) {
	clock := &terminalReviewClock{}
	p := &TerminalPermit{valid: true, clock: clock, until: time.Second, wallUntil: time.Now().Add(time.Second)}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.policy.ObservationTimeout = 500 * time.Millisecond
	p.policy.Authority = &terminalReviewAuthority{observe: func(ctx context.Context, tr TerminalTransition) (TerminalObservation, error) {
		cancel()
		if ctx.Err() != context.Canceled {
			t.Error("observer lost synchronous parent cancellation")
		}
		return TerminalObservation{State: TerminalActive, Transition: tr}, nil
	}}
	if _, err := p.Observe(parent, false); err == nil {
		t.Fatal("cancelled observation regained eligibility")
	}
}
