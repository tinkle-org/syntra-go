// Package elapsedctx retains trusted SDK elapsed cutoffs behind scheduler timers.
// These declarations are local SDK timing provenance, never peer-supplied values
// or authority. Clock methods must be prompt, concurrency-safe and fail sticky on
// discontinuity. Absolute ages from different clocks must never be compared.
package elapsedctx

import (
	"context"
	"math"
	"time"
)

// Clock is the trusted local elapsed origin used by a declared SDK cutoff.
type Clock interface {
	// Age returns elapsed time in this clock's domain.
	Age() time.Duration
	// Check rejects discontinuity or invalidation.
	Check() error
}

// deadlineKey is inaccessible to applications outside this SDK's internal tree.
type deadlineKey struct{}

// deadline records the OWN projected timer, not the deadline after parent clamp.
// parentDeadline preserves an intervening plain parent's bound even if a later
// SDK phase dominates the Go timer. Immutable lineage retains outer declarations.
type deadline struct {
	clock          Clock
	until          time.Duration
	projected      time.Time
	parentDeadline time.Time
	parent         *deadline
}

// WithDeadline declares an SDK-owned absolute elapsed cutoff and its own Go
// scheduler projection BEFORE parent clamp. It preserves parent cancellation and
// timing lineage; it does not renew or infer an elapsed origin for plain parents.
// Only trusted SDK code may declare timing here. Callers must cancel and enforce
// their elapsed cutoff while blocked as well as after synchronous operations.
func WithDeadline(parent context.Context, clock Clock, until time.Duration, projected time.Time) (context.Context, context.CancelFunc) {
	ancestor, _ := parent.Value(deadlineKey{}).(*deadline)
	d, _ := parent.Deadline()
	timed, cancel := context.WithDeadline(parent, projected)
	return context.WithValue(timed, deadlineKey{}, &deadline{clock: clock, until: until, projected: projected, parentDeadline: d, parent: ancestor}), cancel
}

// Remaining intersects all declared cutoffs using each bound clock's remaining
// duration, never raw ages or interface identity. For every effective or retained
// parent deadline not matching an SDK declaration in its ancestry, plain supplies
// the conservative allowance (including any known root request-budget deadline).
// No constraints returns MaxInt64. This function grants no timing beyond a bound;
// callers must also enforce context cancellation and their original request cap.
func Remaining(ctx context.Context, plain func(time.Time) time.Duration) time.Duration {
	lineage, _ := ctx.Value(deadlineKey{}).(*deadline)
	remaining := time.Duration(math.MaxInt64)
	if d, ok := ctx.Deadline(); ok {
		remaining = min(remaining, schedulerRemaining(d, lineage, plain))
	}
	for node := lineage; node != nil; node = node.parent {
		if node.clock == nil || node.clock.Check() != nil {
			return 0
		}
		age := node.clock.Age()
		if age < 0 || age >= node.until {
			return 0
		}
		remaining = min(remaining, node.until-age, time.Until(node.projected))
		if !node.parentDeadline.IsZero() {
			remaining = min(remaining, schedulerRemaining(node.parentDeadline, node.parent, plain))
		}
	}
	return max(0, remaining)
}

// schedulerRemaining recognizes only an explicitly declared own projection;
// inheriting metadata alone must never exempt a new plain deadline from charging.
func schedulerRemaining(d time.Time, lineage *deadline, plain func(time.Time) time.Duration) time.Duration {
	for node := lineage; node != nil; node = node.parent {
		if d.Equal(node.projected) {
			return time.Until(d)
		}
	}
	return min(time.Until(d), plain(d))
}
