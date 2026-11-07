// File request_budget.go retains request timing from complete-frame receipt.
package syntra

import (
	"context"
	"math"
	"strings"
	"time"
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
// Expiry cancels eligibility, not durable effects already admitted externally.
type RequestBudget struct {
	deadline time.Time
	receipt  requestReceipt
	until    time.Duration // absolute age on receipt.clock, never reconstructed later
	invalid  bool
}

// Deadline returns the selected absolute Go deadline, including an earlier
// serving-context deadline. Terminal authority callbacks receive the narrower
// operation/read deadline. It never renews the allowance.
func (b RequestBudget) Deadline() time.Time { return b.deadline }

// Remaining returns nonnegative time left under both original timing domains.
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
	r := requestReceipt{at: time.Now()}
	if provider, ok := t.(TerminalReceiptProvider); ok {
		if driver := provider.TerminalReceiptDriver(); driver != nil {
			r.clock = driver.TerminalClock()
			if r.clock != nil {
				r.age = r.clock.Age()
				r.invalid = r.age < 0 || r.clock.Check() != nil
			}
		}
	}
	return r
}

// selectRequestBudget clamps immutable receipt timing before any authorization.
// Arithmetic uses only the already-bounded effective duration, so even a maximum
// positive host cap cannot overflow an elapsed addition or extend the peer cap.
func selectRequestBudget(receipt requestReceipt, deadline time.Time, ctx context.Context, choose RequestBudgetFunc, principal string, req *RpcRequest) RequestBudget {
	if d, ok := ctx.Deadline(); ok {
		deadline = minTime(deadline, d)
	}
	b := requestBudgetAt(receipt, deadline)
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
	return requestBudgetAt(receipt, minTime(deadline, receipt.at.Add(cap)))
}

// requestBudgetAt binds an absolute deadline to the original trusted receipt
// age. Invalid arithmetic cannot be repaired by a later application selector.
func requestBudgetAt(receipt requestReceipt, deadline time.Time) RequestBudget {
	b := RequestBudget{deadline: deadline, receipt: receipt, invalid: receipt.invalid}
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
