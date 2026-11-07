// File request_budget.go retains request timing from complete-frame receipt.
package syntra

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/tinkle-org/syntra-go/internal/elapsedctx"
)

// RequestBudgetFunc optionally selects a host cap for one validated request,
// before Authorize. Built-in recovery and already-expired or invalid original
// budgets skip this selector. The cap starts at complete-frame receipt, not at
// callback entry. False leaves the wire/default/MaxTimeout budget unchanged;
// true with zero expires immediately, and negative durations fail closed.
// A larger cap never extends an existing deadline. Implementations must be pure,
// prompt, bounded and concurrency-safe: no authorization, storage or network I/O.
// Payload is untrusted opaque borrowed data; do not mutate or retain it.
type RequestBudgetFunc func(principal, method string, payload []byte) (time.Duration, bool)

// RequestBudget is a read-only SDK budget shared by authorization, handlers and
// terminal authority adapters. Its zero value is expired. Remaining also checks
// trusted suspend-inclusive elapsed time when the transport supports it; Deadline
// alone is a Go context deadline and may not account for machine suspension.
// Dispatch and terminal budgets also recheck retained ancestor clocks and cutoffs.
// Expiry cancels eligibility, not durable effects already admitted externally.
type RequestBudget struct {
	deadline time.Time
	receipt  requestReceipt
	until    time.Duration // absolute age on receipt.clock, never reconstructed later
	invalid  bool
	parents  *requestBudgetParents // immutable timing-only ancestry; keeps the value comparable
}

// Deadline returns the selected absolute Go deadline, including an earlier
// serving-context deadline. Terminal authority callbacks receive the narrower
// operation/read deadline. It never renews the allowance.
func (b RequestBudget) Deadline() time.Time { return b.deadline }

// Remaining returns nonnegative time left under the original timing domains and
// all retained ancestor constraints, resampling each declared clock in its domain.
// Invalid continuity or duration arithmetic returns zero (fail closed).
func (b RequestBudget) Remaining() time.Duration {
	if b.invalid || b.deadline.IsZero() {
		return 0
	}
	remaining := time.Until(b.deadline)
	if b.receipt.clock != nil {
		if b.receipt.clock.Check() != nil {
			return 0
		}
		age := b.receipt.clock.Age()
		if age < b.receipt.age || age >= b.until {
			return 0
		}
		remaining = min(remaining, b.until-age)
	}
	if b.parents != nil {
		remaining = min(remaining, b.parents.remaining())
	}
	return max(0, remaining)
}

// Err reports context.DeadlineExceeded once the SDK budget is exhausted or
// invalid. Callers must also honor their context's cancellation independently.
func (b RequestBudget) Err() error {
	if b.Remaining() == 0 {
		return context.DeadlineExceeded
	}
	return nil
}

// RequestBudgetFromContext returns the SDK-selected budget, when called from
// Authorize, a handler, or a terminal authority callback. It grants no authority.
// Every terminal Commit/Observe callback, including driver refresh observations,
// gets a derived budget bounded by its operation/read cutoff and parent context.
// A child context may impose an earlier deadline; adapters must honor that too.
func RequestBudgetFromContext(ctx context.Context) (RequestBudget, bool) {
	b, ok := ctx.Value(requestBudgetKey{}).(RequestBudget)
	return b, ok
}

// requestBudgetKey prevents callers from manufacturing SDK timing scope.
type requestBudgetKey struct{}

// requestBudgetParents retains only SDK timing values, never user contexts or
// context callbacks. Plain bounds are projected once into the derived clock;
// declared and inherited budget clocks keep their original absolute cutoffs.
type requestBudgetParents struct {
	declared     elapsedctx.Constraints
	inherited    RequestBudget
	hasInherited bool
	previous     *requestBudgetParents
}

// remaining dynamically intersects retained domains without renewing any cutoff.
// Only trusted, prompt Clock methods are invoked, so no context callback can run
// when a permit rechecks these constraints at its serialized handoff decision.
func (p *requestBudgetParents) remaining() time.Duration {
	remaining := p.declared.Remaining()
	if p.hasInherited {
		remaining = min(remaining, p.inherited.Remaining())
	}
	if p.previous != nil {
		remaining = min(remaining, p.previous.remaining())
	}
	return remaining
}

// clampParentRequest preserves explicit SDK elapsed provenance while charging
// plain deadlines against the original receipt, including pre-attachment suspend.
// Known cutoffs from unrelated clocks intersect by remaining duration, never age.
// The returned budget also retains exact receipt-projected plain absolute bounds.
func clampParentRequest(ctx context.Context, b RequestBudget) (RequestBudget, time.Duration) {
	parent, hasParent := RequestBudgetFromContext(ctx)
	remaining := elapsedctx.Remaining(ctx, func(d time.Time) time.Duration {
		if hasParent && d.Equal(parent.deadline) {
			return parent.Remaining()
		}
		if !b.receipt.at.IsZero() && b.receipt.clock != nil {
			// A distant nonbinding parent must not overflow projection of an
			// otherwise valid short budget. Effective overflow still fails closed.
			projected := requestBudgetAt(b.receipt, minTime(d, b.deadline))
			b.until = min(b.until, projected.until)
			b.invalid = b.invalid || projected.invalid
			return projected.Remaining()
		}
		// Scheduler-only receipts must retain plain bounds hidden in SDK lineage too.
		b.deadline = minTime(b.deadline, d)
		return time.Until(d)
	})
	if hasParent {
		remaining = min(remaining, parent.Remaining())
	}
	b.parents = &requestBudgetParents{declared: elapsedctx.Capture(ctx), inherited: parent, hasInherited: hasParent, previous: b.parents}
	return b, remaining
}

// requestReceipt captures both origins before the received frame is queued.
type requestReceipt struct {
	at      time.Time
	clock   TerminalClock
	age     time.Duration
	invalid bool
}

// captureRequestReceipt samples the driver's original clock outside protocol
// locks and raw I/O. A missing clock leaves ordinary wall-only requests supported.
func captureRequestReceipt(t Transport) requestReceipt {
	var clock TerminalClock
	if provider, ok := t.(TerminalReceiptProvider); ok {
		if driver := provider.TerminalReceiptDriver(); driver != nil {
			clock = driver.TerminalClock()
		}
	}
	return CaptureFrameReceipt(clock).receipt
}

// selectRequestBudget clamps immutable receipt timing and retains serving-context
// ancestry before every selector exit and authorization. Caps preserve existing
// parent projections; even a maximum cap cannot overflow or extend that budget.
func selectRequestBudget(receipt requestReceipt, deadline time.Time, ctx context.Context, choose RequestBudgetFunc, principal string, req *RpcRequest) RequestBudget {
	if d, ok := ctx.Deadline(); ok {
		deadline = minTime(deadline, d)
	}
	b := requestBudgetAt(receipt, deadline)
	b, _ = clampParentRequest(ctx, b)
	// Application policy cannot change reserved recovery behavior or run on
	// exhausted/invalid original timing. Still expose and enforce that budget.
	if choose == nil || strings.HasPrefix(req.GetMethod(), RecoveryMethodPrefix) || ctx.Err() != nil || b.Err() != nil {
		return b
	}
	cap, selected := choose(principal, req.GetMethod(), req.GetPayload())
	if !selected {
		return b
	}
	if cap < 0 {
		b.invalid = true
		b.deadline = minTime(b.deadline, receipt.at)
		return b
	}
	capped := requestBudgetAt(receipt, minTime(b.deadline, receipt.at.Add(cap)))
	capped.parents = b.parents
	capped.until = min(capped.until, b.until)
	capped.invalid = capped.invalid || b.invalid
	return capped
}

// requestBudgetAt binds an absolute deadline to the original trusted receipt
// age. Invalid arithmetic cannot be repaired by a later application selector.
func requestBudgetAt(receipt requestReceipt, deadline time.Time) RequestBudget {
	b := RequestBudget{deadline: deadline, receipt: receipt, invalid: receipt.invalid || receipt.at.IsZero()}
	if receipt.clock != nil {
		duration := b.deadline.Sub(receipt.at)
		if duration <= 0 || receipt.age > time.Duration(math.MaxInt64)-duration {
			b.invalid = true
		} else {
			b.until = receipt.age + duration
		}
	}
	if b.invalid {
		b.deadline = minTime(b.deadline, receipt.at)
	}
	return b
}
