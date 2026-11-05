package securechannel

import (
	"sync"
	"time"
)

// ElapsedSource reports trusted local time including idle and system suspension.
// Samples share an origin and cannot regress. False means unknown continuity.
// Elapsed must be concurrency-safe, prompt, nonblocking and non-reentrant; it is
// sampled under a lock.
type ElapsedSource interface{ Elapsed() (time.Duration, bool) }

type ElapsedFunc func() (time.Duration, bool)

func (f ElapsedFunc) Elapsed() (time.Duration, bool) {
	if f == nil {
		return 0, false
	}
	return f()
}

// Clock owns one establishment origin and sticky retirement state. Share its
// pointer across establishment and channel use; never copy a Clock.
type Clock struct {
	mu               sync.Mutex
	source           ElapsedSource
	origin, previous time.Duration
	failed           bool
}

// NewClock uses a suspend-inclusive platform clock. Unsupported platforms fail
// closed; their owners must supply an explicit trusted source.
func NewClock() *Clock { return NewClockWithSource(ElapsedFunc(nativeElapsed)) }

func NewClockWithSource(source ElapsedSource) *Clock {
	c := &Clock{source: source, failed: true}
	if source != nil {
		now, ok := source.Elapsed()
		if ok && now >= 0 {
			c.origin, c.previous, c.failed = now, now, false
		}
	}
	return c
}

// Age returns MaxAge after expiry, invalidation, missing time or regression.
func (c *Clock) Age() time.Duration {
	if c == nil {
		return MaxAge
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.failed {
		now, ok := c.source.Elapsed()
		if ok && now >= c.previous && now-c.origin < MaxAge {
			c.previous = now
			return now - c.origin
		}
	}
	c.failed = true
	return MaxAge
}

func (c *Clock) Check() error {
	if c.Age() >= MaxAge {
		return ErrLimit
	}
	return nil
}

// Invalidate retires the origin before buffered work resumes after continuity loss.
func (c *Clock) Invalidate() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.failed = true
	c.mu.Unlock()
}
