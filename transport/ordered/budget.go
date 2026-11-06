package ordered

import (
	"context"
	"sync"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
)

// EstablishmentBudget carries one origin and absolute attempt deadline from
// carrier setup through readiness. Create it before carrier establishment and
// use Context to bound that work, then pass it in Options.Budget. Do not copy it.
type EstablishmentBudget struct {
	mu        sync.Mutex
	clock     *securechannel.Clock
	started   time.Duration
	until     time.Duration
	claimed   bool
	released  bool
	coreReady bool
	deferred  bool
	failure   error
}

func NewEstablishmentBudget(clock *securechannel.Clock, timeout time.Duration) (*EstablishmentBudget, error) {
	if timeout <= 0 || timeout > 15*time.Second {
		return nil, ErrOptions
	}
	if clock == nil {
		clock = securechannel.NewClock()
	}
	age := clock.Age()
	if age >= securechannel.MaxAge {
		return nil, context.DeadlineExceeded
	}
	return &EstablishmentBudget{clock: clock, started: age, until: min(securechannel.MaxAge, age+timeout)}, nil
}

func (b *EstablishmentBudget) Context(parent context.Context) (context.Context, context.CancelFunc) {
	b.mu.Lock()
	until := b.until
	b.mu.Unlock()
	return elapsedContext(parent, b.clock, until)
}

// Check samples the shared origin synchronously. Release retires only the setup
// cutoff; clock continuity and maximum age remain mandatory for active I/O.
func (b *EstablishmentBudget) Check() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.checkLocked()
}

func (b *EstablishmentBudget) checkLocked() error {
	age := b.clock.Age()
	if b.failure == nil && (age >= securechannel.MaxAge || !b.released && age >= b.until) {
		b.failure = context.DeadlineExceeded
	}
	return b.failure
}

// Cap shortens the cutoff relative to the original start, before transport claim.
// It never replaces the budget or extends a previously selected cutoff.
func (b *EstablishmentBudget) Cap(maximum time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if maximum <= 0 || b.claimed || b.released {
		return ErrOptions
	}
	if maximum < b.until-b.started {
		b.until = b.started + maximum
	}
	return b.checkLocked()
}

// Release records validated core readiness. An expired budget stays failed;
// deferred completion keeps the same cutoff until its continuation succeeds.
func (b *EstablishmentBudget) Release() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.checkLocked() != nil {
		return
	}
	b.coreReady = true
	if !b.deferred {
		b.released = true
	}
}

// DeferCompletion retains the raw-I/O gate through required recovery work.
// Call before handing the budget to a connection. The returned continuation
// atomically checks the cutoff and releases it only after core readiness.
func (b *EstablishmentBudget) DeferCompletion() (func() error, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.claimed || b.deferred || b.released {
		return nil, ErrOptions
	}
	if err := b.checkLocked(); err != nil {
		return nil, err
	}
	b.deferred = true
	return func() error {
		b.mu.Lock()
		defer b.mu.Unlock()
		if err := b.checkLocked(); err != nil {
			return err
		}
		if !b.coreReady {
			return ErrOptions
		}
		b.released = true
		return nil
	}, nil
}

func (b *EstablishmentBudget) cutoff() (time.Duration, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.until, !b.released
}

func (b *EstablishmentBudget) claim(o Options) (*securechannel.Clock, time.Duration, time.Duration, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.claimed || b.released {
		return nil, 0, 0, ErrOptions
	}
	b.claimed = true
	if err := b.checkLocked(); err != nil {
		return nil, 0, 0, err
	}
	age := b.clock.Age()
	attempt := min(b.until, b.started+o.AttemptTimeout, o.Lifetime)
	b.until = attempt
	phase := min(attempt, age+o.HandshakeTimeout)
	if age >= phase {
		return nil, 0, 0, context.DeadlineExceeded
	}
	return b.clock, attempt, phase, nil
}

// elapsedContext uses timers for prompt cancellation and samples the trusted
// elapsed domain while blocked. The caller must also check after synchronous
// dependencies return: cancellation cannot preempt a Go function.
func elapsedContext(parent context.Context, clock *securechannel.Clock, until time.Duration) (context.Context, context.CancelFunc) {
	until = min(until, securechannel.MaxAge)
	remaining := until - clock.Age()
	timed, stopTimer := context.WithTimeout(parent, max(0, remaining))
	ctx, retire := context.WithCancelCause(timed)
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			if clock.Age() >= until {
				retire(context.DeadlineExceeded)
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	return ctx, func() { retire(context.Canceled); stopTimer(); <-done }
}

func elapsedError(ctx context.Context, clock *securechannel.Clock, until time.Duration) error {
	if clock.Age() >= until {
		return context.DeadlineExceeded
	}
	if ctx.Err() != nil {
		if context.Cause(ctx) == context.DeadlineExceeded {
			return context.DeadlineExceeded
		}
		return ctx.Err()
	}
	return nil
}

func (t *Transport) establish(attempt, hello time.Duration, responder bool) {
	t.mu.Lock()
	t.attemptDeadline, t.helloDeadline = attempt, hello
	t.establishing, t.helloPending, t.responder = true, true, responder
	t.mu.Unlock()
}

func (t *Transport) operationDeadline(timeout time.Duration) time.Duration {
	until := min(t.opts.Lifetime, t.channel.Age()+timeout)
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.establishing {
		until = min(until, t.attemptDeadline)
		if t.readinessStarted {
			until = min(until, t.readinessDeadline)
		}
	}
	if t.helloPending {
		until = min(until, t.helloDeadline)
	}
	until = min(until, t.lastRecordAt+t.opts.RecordTimeout)
	return until
}

func (t *Transport) checkTime() error {
	t.mu.Lock()
	closed := t.closed
	permit := t.terminalPermit
	t.mu.Unlock()
	if closed {
		// Cipher retirement during owned cleanup is not a new security failure.
		return ErrClosed
	}
	if permit != nil {
		if err := permit.CheckTime(); err != nil {
			return err
		}
	}
	if t.opts.Budget != nil {
		if err := t.opts.Budget.Check(); err != nil {
			return err
		}
	}
	// Record budgets are checked when committing a new record. Rechecking them
	// here would discard the final permitted ciphertext after its nonce commit.
	if err := t.channel.CheckLive(); err != nil {
		if err == securechannel.ErrClosed {
			if cause := t.channel.TerminalError(); cause != nil && cause != securechannel.ErrLimit {
				return cause
			}
			return t.channelError(err)
		}
		return context.DeadlineExceeded
	}
	until := t.operationDeadline(securechannel.MaxAge)
	if t.channel.Age() >= until {
		return context.DeadlineExceeded
	}
	return nil
}

func (t *Transport) checkOperation(ctx context.Context, until time.Duration) error {
	if err := elapsedError(ctx, t.channel.Clock(), until); err != nil {
		return err
	}
	t.mu.Lock()
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return ErrClosed
	}
	return t.checkTime()
}

func (t *Transport) helloComplete(sending bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if sending != t.responder {
		t.helloPending = false
	} else {
		t.establishing = false
	}
}

// EstablishmentContext bounds application readiness by the original attempt
// and any retained application phase deadline. Client's first inbound frame
// and server's first outbound frame end transport establishment; application
// policy can retain this context longer or resample after synchronous work.
func (t *Transport) EstablishmentContext(parent context.Context) (context.Context, context.CancelFunc) {
	t.mu.Lock()
	until := t.attemptDeadline
	if t.readinessStarted {
		until = min(until, t.readinessDeadline)
	}
	t.mu.Unlock()
	return elapsedContext(parent, t.channel.Clock(), until)
}

// EstablishmentContextWithTimeout starts the application hello/policy/Ready
// phase after Noise. The trusted-clock deadline is capped by the original
// attempt and retained for synchronous transport checks and later resampling.
// Repeated calls can shorten the phase but never renew it. Zero selects 5s.
func (t *Transport) EstablishmentContextWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	now := t.channel.Age()
	t.mu.Lock()
	until := min(t.attemptDeadline, now+max(0, min(timeout, securechannel.MaxAge)))
	if t.readinessStarted {
		until = min(until, t.readinessDeadline)
	}
	t.readinessDeadline = until
	t.readinessStarted = true
	t.mu.Unlock()
	return elapsedContext(parent, t.channel.Clock(), until)
}
