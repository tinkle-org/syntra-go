package network

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math"
	"sync"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
)

// Connector returns an already Core-ready connection produced by Connect. It
// must not return an unstarted core or construct a connection.Client directly.
type Connector func(ctx context.Context, budget *ordered.EstablishmentBudget) (*connection.Client, error)

// ConnectorWithSetup must install prepare as ClientConfig.Prepare (composed
// with any application preparer) before opening the client. It must call it
// exactly once for the returned client, before Run, and propagate its error.
type ConnectorWithSetup func(context.Context, *ordered.EstablishmentBudget, func(*syntra.Client) error) (*connection.Client, error)

// RecoverySession is fresh per connection. Negotiate must perform the exact
// profile exchange; success must not mean fallback to a core-only connection.
// Methods honor context. Close must be prompt and nonblocking.
type RecoverySession interface {
	Negotiate(context.Context) error
	Close()
}
type RecoveryFactory func(*syntra.Client) (RecoverySession, error)

// CompletionFactory optionally injects additional completion checks. The real
// budget completion guard is always retained independently, so an injected
// function cannot substitute for or bypass it. Functions must be prompt.
type CompletionFactory func(*ordered.EstablishmentBudget) (func() error, error)

// ReconnectConfig has no implicit retry policy. All durations must be explicit.
// ClockFactory must return a fresh origin sampling the same trusted elapsed
// source (including suspension). Nil selects the platform elapsed clock.
// Random, if supplied, must be concurrency-safe and prompt; it is read only by
// the sole supervisor. Nil selects crypto/rand.Reader.
type ReconnectConfig struct {
	AttemptTimeout          time.Duration
	ReconnectBudget         time.Duration
	MaxAttempts             uint32
	BaseBackoff             time.Duration
	MaxBackoff              time.Duration
	CloseTimeout            time.Duration
	StartPaused             bool
	InitialNetworkAvailable bool
	NotificationCapacity    int
	NotificationBytes       int
	MaxCalls                int
	ClockFactory            func() *securechannel.Clock
	Random                  io.Reader
	RecoveryFactory         RecoveryFactory
	DeferCompletion         CompletionFactory
}

func (cfg ReconnectConfig) Validate() error {
	if cfg.MaxAttempts == 0 || cfg.AttemptTimeout > 15*time.Second || cfg.CloseTimeout > connection.ShutdownTimeout || cfg.BaseBackoff > cfg.MaxBackoff {
		return ErrConfig
	}
	for _, d := range []time.Duration{cfg.AttemptTimeout, cfg.ReconnectBudget, cfg.BaseBackoff, cfg.MaxBackoff, cfg.CloseTimeout} {
		if d <= 0 || d > 24*time.Hour {
			return ErrConfig
		}
	}
	if cfg.NotificationCapacity < 0 || cfg.NotificationCapacity > 1024 || cfg.NotificationBytes < 0 || cfg.NotificationBytes > 64<<20 || cfg.MaxCalls < 0 || cfg.MaxCalls > 1024 {
		return ErrConfig
	}
	return nil
}

type Phase uint8

const (
	Starting Phase = iota
	Paused
	Offline
	Connecting
	Backoff
	CoreReady
	RecoveryNegotiated
	Blocked
	Exhausted
	Stopping
	Stopped
	ShutdownIncomplete
	Retired
)

// Status is a value snapshot, not an event log. Slow observers may skip states.
// Loss totals are local to Generation, not durable recovery progress.
type Status struct {
	Revision            uint64
	Phase               Phase
	Generation          uint64
	Attempts            uint32
	Failure             Failure
	Backoff             time.Duration
	DroppedCount        uint64
	DroppedBytes        uint64
	QueuedNotifications int
}

type Notification struct {
	Payload      []byte
	DroppedCount uint64
	DroppedBytes uint64
}

type generation struct {
	id                     uint64
	ready                  bool
	terminal               Failure
	conn                   *connection.Client
	clock                  *securechannel.Clock
	recovery               RecoverySession
	ctx                    context.Context
	cancel                 context.CancelFunc
	queue                  [][]byte
	bytes                  int
	dropped, droppedBytes  uint64
	coreDropped, coreBytes uint64
}

// Client owns exactly one supervisor and at most one outstanding connector.
// CloseContext bounds waiting, never transfers ownership of running work.
type Client struct {
	cfg                           ReconnectConfig
	connector                     Connector
	setup                         ConnectorWithSetup
	mu                            sync.Mutex
	active                        *generation
	paused, online, stopped       bool
	networkPaused, networkOffline bool
	revision, retry, permit       uint64
	status                        Status
	changed                       chan struct{}
	wake                          chan struct{}
	done                          chan struct{}
	completionErr                 error
	attemptCancel                 context.CancelFunc
	attemptClock                  *securechannel.Clock
	outage                        *securechannel.Clock
	calls                         int
	callsChanged                  chan struct{}
	owner                         *Network
}

func NewClient(cfg ReconnectConfig, connector Connector) (*Client, error) {
	if connector == nil || cfg.RecoveryFactory != nil {
		return nil, ErrConfig
	}
	return newClient(cfg, connector, nil)
}

func NewClientWithSetup(cfg ReconnectConfig, connector ConnectorWithSetup) (*Client, error) {
	if connector == nil || cfg.RecoveryFactory == nil {
		return nil, ErrConfig
	}
	return newClient(cfg, nil, connector)
}

func newClient(cfg ReconnectConfig, connector Connector, setup ConnectorWithSetup) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.NotificationCapacity == 0 {
		cfg.NotificationCapacity = 128
	}
	if cfg.NotificationBytes == 0 {
		cfg.NotificationBytes = 4 << 20
	}
	if cfg.MaxCalls == 0 {
		cfg.MaxCalls = 128
	}
	if cfg.ClockFactory == nil {
		cfg.ClockFactory = securechannel.NewClock
	}
	if cfg.Random == nil {
		cfg.Random = rand.Reader
	}
	c := &Client{cfg: cfg, connector: connector, setup: setup, paused: cfg.StartPaused, online: cfg.InitialNetworkAvailable,
		changed: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{}), callsChanged: make(chan struct{}), outage: cfg.ClockFactory()}
	c.status.Phase = Starting
	if c.paused {
		c.status.Phase = Paused
	} else if !c.online {
		c.status.Phase = Offline
	}
	go c.run()
	return c, nil
}

func (c *Client) publishLocked(s Status) {
	if c.completionErr != nil {
		s.Phase = ShutdownIncomplete
	}
	if c.status.Revision == math.MaxUint64 {
		c.stopped = true
		c.invalidateLocked()
		s.Phase = Retired
		s.Failure = FailureRevisionExhausted
	} else {
		s.Revision = c.status.Revision + 1
	}
	c.status = s
	close(c.changed)
	c.changed = make(chan struct{})
}
func (c *Client) publish(phase Phase, attempts uint32, failure Failure, delay time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.Phase == Stopped {
		return
	}
	if c.stopped && phase != Stopped && phase != ShutdownIncomplete && phase != Retired {
		return
	}
	s := c.status
	s.Phase = phase
	s.Attempts = attempts
	s.Failure = failure
	s.Backoff = delay
	c.publishLocked(s)
}

func (c *Client) publishRevision(revision uint64, phase Phase, attempts uint32, failure Failure, delay time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.revision != revision || c.stopped {
		return
	}
	s := c.status
	s.Phase, s.Attempts, s.Failure, s.Backoff = phase, attempts, failure, delay
	if phase != CoreReady && phase != RecoveryNegotiated {
		s.Generation = 0
		s.QueuedNotifications = 0
	}
	c.publishLocked(s)
}

func (c *Client) Snapshot() Status { c.mu.Lock(); defer c.mu.Unlock(); return c.status }
func (c *Client) WaitChange(ctx context.Context, revision uint64) (Status, error) {
	for {
		c.mu.Lock()
		s, ch := c.status, c.changed
		c.mu.Unlock()
		if s.Revision != revision {
			return s, nil
		}
		select {
		case <-ch:
		case <-c.done:
			return c.Snapshot(), ErrClosed
		case <-ctx.Done():
			return s, ctx.Err()
		}
	}
}
func (c *Client) Done() <-chan struct{} { return c.done }

func (c *Client) invalidateLocked() {
	if c.active != nil {
		c.active.terminal = Classify(c.active.conn.TerminalError())
		c.active.cancel()
		c.active.conn.Suspend()
		c.active = nil
		if c.outage == nil {
			c.outage = c.cfg.ClockFactory()
		}
	}
	if c.attemptCancel != nil {
		c.attemptClock.Invalidate()
		c.attemptCancel()
	}
}
func (c *Client) control(update func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopped {
		return
	}
	if c.revision == math.MaxUint64 {
		c.stopped = true
		c.invalidateLocked()
		c.publishLocked(Status{Phase: Retired, Failure: FailureRevisionExhausted})
	} else {
		c.revision++
		update()
		c.invalidateLocked()
		s := c.status
		s.Generation = 0
		s.QueuedNotifications = 0
		s.Phase = Starting
		if c.stopped {
			s.Phase = Stopping
		} else if c.paused || c.networkPaused {
			s.Phase = Paused
		} else if (!c.online || c.networkOffline) && c.permit != c.revision {
			s.Phase = Offline
		}
		c.publishLocked(s)
	}
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *Client) Pause() { c.control(func() { c.paused = true; c.permit = 0 }) }

// Resume grants one offline attempt, without clearing blocked/exhausted state.
func (c *Client) Resume() { c.control(func() { c.paused = false; c.permit = c.revision }) }
func (c *Client) NetworkAvailable(available bool) {
	c.control(func() { c.online = available; c.permit = 0 })
}
func (c *Client) PlatformWake() { c.control(func() { c.permit = 0 }) }

// Retry unblocks terminal errors and starts a fresh outage/attempt budget. The
// backoff exponent is retained until readiness. Managed offline/pause wins.
func (c *Client) Retry() {
	c.control(func() { c.paused = false; c.retry = c.revision; c.permit = c.revision; c.outage = c.cfg.ClockFactory() })
}
func (c *Client) Stop() { c.control(func() { c.stopped = true; c.permit = 0 }) }
func (c *Client) applyNetwork(paused, online, stopped bool) {
	c.control(func() { c.networkPaused = paused; c.networkOffline = !online; c.permit = 0; c.stopped = stopped })
}

// clientCloseOutcome distinguishes a caller's incomplete wait from the joined
// owner's sticky result. Only the latter can be a supervisor failure.
type clientCloseOutcome struct {
	complete bool
	err      error
}

func (c *Client) completionOutcome() clientCloseOutcome {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.done:
		return clientCloseOutcome{complete: true, err: c.completionErr}
	default:
		return clientCloseOutcome{err: ErrShutdownIncomplete}
	}
}

func (c *Client) closeOutcome(ctx context.Context) clientCloseOutcome {
	c.Stop()
	timer := time.NewTimer(c.cfg.CloseTimeout)
	defer timer.Stop()
	if outcome := c.completionOutcome(); outcome.complete {
		return outcome
	}
	select {
	case <-c.done:
	case <-ctx.Done():
	case <-timer.C:
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	// Completion and a caller deadline may race. Prefer the settled owner result
	// and never let a late waiter overwrite the final lifecycle status.
	select {
	case <-c.done:
		return clientCloseOutcome{complete: true, err: c.completionErr}
	default:
		s := c.status
		s.Phase = ShutdownIncomplete
		c.publishLocked(s)
		return clientCloseOutcome{err: ErrShutdownIncomplete}
	}
}

// CloseContext bounds the caller's wait. Failed or overdue owned teardown keeps
// returning ErrShutdownIncomplete even after Done closes; a wait timeout alone
// does not make an otherwise clean owner fail.
func (c *Client) CloseContext(ctx context.Context) error { return c.closeOutcome(ctx).err }
func (c *Client) Close() error                           { return c.CloseContext(context.Background()) }

func (c *Client) currentLocked(g *generation) bool {
	if g == nil || !g.ready || c.active != g || c.stopped || c.paused || c.networkPaused || g.ctx.Err() != nil {
		return false
	}
	if g.conn.IsClosed() {
		return false
	}
	select {
	case <-g.conn.Done():
		return false
	default:
		return true
	}
}
func (c *Client) IsGenerationCurrent(id uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active != nil && c.active.id == id && c.currentLocked(c.active)
}

func (c *Client) Call(ctx context.Context, method string, payload []byte, timeoutMs uint32) (GenerationValue[[]byte], error) {
	var zero GenerationValue[[]byte]
	c.mu.Lock()
	g := c.active
	if !c.currentLocked(g) {
		c.mu.Unlock()
		return zero, callError(0, FailureClosed, false)
	}
	if c.calls >= c.cfg.MaxCalls {
		c.mu.Unlock()
		return zero, callError(0, ErrBusy, false)
	}
	if c.owner != nil && !c.owner.reserveCall() {
		c.mu.Unlock()
		return zero, callError(0, ErrBusy, false)
	}
	c.calls++
	callctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(g.ctx, cancel)
	// AfterFunc need not have run yet when retirement preceded registration.
	if g.ctx.Err() != nil {
		cancel()
	}
	c.mu.Unlock()
	defer func() {
		stop()
		cancel()
		c.mu.Lock()
		c.calls--
		close(c.callsChanged)
		c.callsChanged = make(chan struct{})
		c.mu.Unlock()
		if c.owner != nil {
			c.owner.releaseCall()
		}
	}()
	value, err := g.conn.Call(callctx, method, payload, timeoutMs)
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked(g) {
		return zero, callError(g.id, FailureClosed, true)
	}
	if err != nil {
		return zero, callError(g.id, err, Classify(err).Retryable())
	}
	return GenerationValue[[]byte]{Generation: g.id, Value: value}, nil
}

// NextNotification snapshots once and waits only on that generation's queue.
// Loss-only changes return a nil Payload. Concurrent consumers share the queue.
func (c *Client) NextNotification(ctx context.Context) (GenerationValue[Notification], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g := c.active
	if !c.currentLocked(g) {
		return GenerationValue[Notification]{}, callError(0, FailureClosed, false)
	}
	if c.calls >= c.cfg.MaxCalls || c.owner != nil && !c.owner.reserveCall() {
		return GenerationValue[Notification]{}, callError(0, ErrBusy, false)
	}
	c.calls++
	defer func() {
		c.calls--
		close(c.callsChanged)
		c.callsChanged = make(chan struct{})
		if c.owner != nil {
			c.owner.releaseCall()
		}
	}()
	initialCount, initialBytes := g.dropped, g.droppedBytes
	for {
		if !c.currentLocked(g) {
			return GenerationValue[Notification]{}, callError(g.id, FailureClosed, true)
		}
		if len(g.queue) > 0 || g.dropped != initialCount || g.droppedBytes != initialBytes {
			n := Notification{DroppedCount: g.dropped, DroppedBytes: g.droppedBytes}
			if len(g.queue) > 0 {
				n.Payload = g.queue[0]
				g.bytes -= len(n.Payload)
				g.queue[0] = nil
				g.queue = g.queue[1:]
			}
			s := c.status
			s.QueuedNotifications = len(g.queue)
			c.publishLocked(s)
			return GenerationValue[Notification]{Generation: g.id, Value: n}, nil
		}
		ch := c.changed
		c.mu.Unlock()
		select {
		case <-ch:
		case <-g.ctx.Done():
		case <-ctx.Done():
			c.mu.Lock()
			return GenerationValue[Notification]{}, callError(g.id, ctx.Err(), false)
		}
		c.mu.Lock()
	}
}

// RecoveryClient returns a generation-bound profile. Check IsGenerationCurrent
// again before delivering application results from retained profile methods.
func (c *Client) RecoveryClient() (GenerationValue[RecoverySession], error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	g := c.active
	if !c.currentLocked(g) || g.recovery == nil {
		return GenerationValue[RecoverySession]{}, callError(0, FailureRecoveryUnavailable, false)
	}
	return GenerationValue[RecoverySession]{Generation: g.id, Value: g.recovery}, nil
}

func saturate(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}
func (c *Client) drain(g *generation, payload []byte, hasPayload bool) {
	d, b := g.conn.LossTotals()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active != g {
		return
	}
	if d >= g.coreDropped {
		g.dropped = saturate(g.dropped, d-g.coreDropped)
	}
	if b >= g.coreBytes {
		g.droppedBytes = saturate(g.droppedBytes, b-g.coreBytes)
	}
	g.coreDropped, g.coreBytes = d, b
	if hasPayload {
		if len(g.queue) >= c.cfg.NotificationCapacity || len(payload) > c.cfg.NotificationBytes-g.bytes {
			g.dropped = saturate(g.dropped, 1)
			g.droppedBytes = saturate(g.droppedBytes, uint64(len(payload)))
		} else {
			g.queue = append(g.queue, append([]byte{}, payload...))
			g.bytes += len(payload)
		}
	}
	s := c.status
	if hasPayload || s.DroppedCount != g.dropped || s.DroppedBytes != g.droppedBytes {
		s.DroppedCount = g.dropped
		s.DroppedBytes = g.droppedBytes
		s.QueuedNotifications = len(g.queue)
		c.publishLocked(s)
	}
}

type attemptResult struct {
	conn     *connection.Client
	recovery RecoverySession
	err      error
}

// invoke keeps synchronous application work off the supervisor, with exactly
// one charged worker. The supervisor joins it before starting another attempt.
func (c *Client) invoke(ctx context.Context, b *ordered.EstablishmentBudget) <-chan attemptResult {
	result := make(chan attemptResult, 1)
	if c.owner != nil && !c.owner.reserveCallback() {
		result <- attemptResult{err: ErrBusy}
		return result
	}
	if c.owner != nil {
		ctx = context.WithValue(ctx, callbackOwnerKey{}, c.owner)
	}
	go func() {
		r := attemptResult{err: FailureRuntime}
		defer func() {
			if recover() != nil {
				r.err = FailureRuntime
			}
			if c.owner != nil {
				c.owner.releaseCallback()
			}
			result <- r
		}()
		if ctx.Err() != nil {
			r.err = stream.ContextError(ctx)
			return
		}
		if c.setup == nil {
			r.conn, r.err = c.connector(ctx, b)
			return
		}
		var mu sync.Mutex
		var prepared *syntra.Client
		used := false
		prepare := func(core *syntra.Client) error {
			mu.Lock()
			defer mu.Unlock()
			if used || ctx.Err() != nil {
				return ErrConfig
			}
			used = true
			prepared = core
			var err error
			r.recovery, err = c.cfg.RecoveryFactory(core)
			if err == nil && r.recovery == nil {
				err = ErrConfig
			}
			return err
		}
		r.conn, r.err = c.setup(ctx, b, prepare)
		mu.Lock()
		defer mu.Unlock()
		if r.err == nil && (!used || r.conn == nil || r.conn.Client != prepared || r.recovery == nil) {
			r.err = ErrConfig
		}
	}()
	return result
}

func (c *Client) incomplete() {
	c.mu.Lock()
	c.completionErr = ErrShutdownIncomplete
	c.stopped = true
	c.invalidateLocked()
	s := c.status
	s.Phase = ShutdownIncomplete
	c.publishLocked(s)
	c.mu.Unlock()
}

// joinWorker retains ownership even after the bounded grace expires.
func (c *Client) joinWorker(result <-chan attemptResult, grace time.Duration) attemptResult {
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case r := <-result:
		return r
	case <-timer.C:
		c.incomplete()
		return <-result
	}
}
func (c *Client) retire(r attemptResult, grace time.Duration) bool {
	if r.conn == nil && r.recovery == nil {
		return true
	}
	finished := make(chan error, 1)
	go func() {
		var err error
		if r.conn != nil {
			err = retirementResult(r.conn.Close)
			// A Close timeout is not a join. Retain the entire connection until
			// the pump and carrier cleanup have actually returned.
			<-r.conn.Done()
		}
		if r.recovery != nil {
			if e := retirementResult(func() error { c.closeRecovery(r.recovery); return nil }); e != nil {
				err = e
			}
		}
		finished <- err
	}()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case err := <-finished:
		if err == nil {
			return true
		}
		c.incomplete()
		return false
	case <-timer.C:
		c.incomplete()
		<-finished
		return false
	}
}

// A cleanup callback may panic, but that must neither escape its worker nor
// discard other owned work. Never retain application panic diagnostics.
func retirementResult(close func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrShutdownIncomplete
		}
	}()
	return close()
}

func (c *Client) closeRecovery(profile RecoverySession) {
	if c.owner != nil {
		for !c.owner.reserveCallback() {
			time.Sleep(10 * time.Millisecond)
		}
		defer c.owner.releaseCallback()
	}
	profile.Close()
}

func (c *Client) jitter(failures uint32) (time.Duration, error) {
	cap := c.cfg.BaseBackoff
	for i := uint32(1); i < failures && cap < c.cfg.MaxBackoff; i++ {
		cap = min(c.cfg.MaxBackoff, cap*2)
	}
	cap = min(cap, c.cfg.MaxBackoff)
	lower := (cap + 1) / 2
	var p [8]byte
	if _, err := io.ReadFull(c.cfg.Random, p[:]); err != nil {
		return 0, FailureRuntime
	}
	return lower + time.Duration(binary.LittleEndian.Uint64(p[:])%uint64(cap-lower+1)), nil
}

func (c *Client) run() {
	defer func() {
		c.mu.Lock()
		c.stopped = true
		c.invalidateLocked()
		for c.calls != 0 {
			ch := c.callsChanged
			c.mu.Unlock()
			<-ch
			c.mu.Lock()
		}
		s := c.status
		if c.completionErr != nil {
			s.Phase = ShutdownIncomplete
		} else if s.Phase != Retired {
			s.Phase = Stopped
		}
		s.Generation = 0
		c.publishLocked(s)
		close(c.done)
		c.mu.Unlock()
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	var attempts, failures uint32
	var generationID, seenRetry, consumedPermit uint64
	var blocked, last Failure
	var next time.Duration
	// Check, account, and publish readiness under the same control lock. A
	// caller observing readiness must also observe its earned fresh allowance.
	acceptReady := func(g *generation) bool {
		if !c.currentLocked(g) {
			return false
		}
		c.outage = nil
		attempts, failures = 0, 0
		blocked, last = FailureNone, FailureNone
		next = 0
		return true
	}
	for {
		c.mu.Lock()
		if c.stopped {
			c.mu.Unlock()
			return
		}
		if c.retry != seenRetry {
			seenRetry = c.retry
			attempts = 0
			blocked = FailureNone
			next = 0
		}
		revision := c.revision
		paused := c.paused || c.networkPaused
		manual := c.permit != 0 && c.permit != consumedPermit && !c.networkPaused && !c.networkOffline
		online := (c.online && !c.networkOffline) || manual
		outage := c.outage
		if outage == nil {
			outage = c.cfg.ClockFactory()
			c.outage = outage
		}
		age := outage.Age()
		c.mu.Unlock()
		if age >= securechannel.MaxAge {
			c.publish(Retired, attempts, FailureElapsedContinuity, 0)
			return
		}
		phase := Starting
		if blocked != FailureNone {
			phase = Blocked
		} else if attempts >= c.cfg.MaxAttempts || age >= c.cfg.ReconnectBudget {
			phase = Exhausted
		} else if paused {
			phase = Paused
		} else if !online {
			phase = Offline
		} else if age < next {
			phase = Backoff
		}
		if phase != Starting {
			s := c.Snapshot()
			failure := blocked
			if phase == Backoff || phase == Exhausted {
				failure = last
			}
			if s.Phase != phase || s.Failure != failure {
				c.publishRevision(revision, phase, attempts, failure, max(0, next-age))
			}
			select {
			case <-c.wake:
			case <-tick.C:
			}
			continue
		}
		c.mu.Lock()
		if c.revision != revision || c.stopped {
			c.mu.Unlock()
			continue
		}
		if manual {
			consumedPermit = c.permit
		}
		timeout := min(c.cfg.AttemptTimeout, c.cfg.ReconnectBudget-age)
		attemptClock := c.cfg.ClockFactory()
		budget, err := ordered.NewEstablishmentBudget(attemptClock, timeout)
		if err != nil {
			c.mu.Unlock()
			blocked = Classify(err)
			continue
		}
		ctx, cancel := budget.Context(context.Background())
		c.attemptCancel = cancel
		c.attemptClock = attemptClock
		c.mu.Unlock()
		var complete func() error
		if c.cfg.RecoveryFactory != nil || c.cfg.DeferCompletion != nil {
			complete, err = budget.DeferCompletion()
			if err == nil && c.cfg.DeferCompletion != nil {
				var injected func() error
				injected, err = c.cfg.DeferCompletion(budget)
				if err == nil && injected == nil {
					err = ErrConfig
				}
				if err == nil {
					actual := complete
					complete = func() error {
						if e := injected(); e != nil {
							return e
						}
						return actual()
					}
				}
			}
			if err != nil || complete == nil {
				cancel()
				c.clearAttempt()
				blocked = FailureConfiguration
				continue
			}
		}
		attempts++
		c.publishRevision(revision, Connecting, attempts, last, 0)
		result := c.invoke(ctx, budget)
		var r attemptResult
		select {
		case r = <-result:
		case <-ctx.Done():
			cancel()
			r = c.joinWorker(result, min(c.cfg.CloseTimeout, max(time.Nanosecond, c.cfg.ReconnectBudget-outage.Age())))
		}
		c.mu.Lock()
		stale := c.revision != revision || c.stopped || c.paused || c.networkPaused
		c.mu.Unlock()
		cutoff := stream.ContextError(ctx)
		if cutoff == nil {
			cutoff = budget.Check()
		}
		if outage.Age() >= c.cfg.ReconnectBudget {
			cutoff = context.DeadlineExceeded
		}
		if r.err == nil && r.conn == nil {
			r.err = ErrConfig
		}
		if r.err == nil && r.conn.IsClosed() {
			r.err = r.conn.TerminalError()
			if r.err == nil {
				r.err = FailureClosed
			}
		}
		if r.err == nil && cutoff != nil {
			r.err = cutoff
		}
		if stale || r.err != nil {
			cancel()
			c.clearAttempt()
			c.retire(r, min(c.cfg.CloseTimeout, max(time.Nanosecond, c.cfg.ReconnectBudget-outage.Age())))
			if stale {
				failure := Classify(r.err)
				if failure != FailureNone && !failure.Retryable() {
					blocked, last = failure, failure
				}
				continue
			}
			last = Classify(r.err)
			if !last.Retryable() {
				blocked = last
			} else {
				if failures < math.MaxUint32 {
					failures++
				}
				delay, e := c.jitter(failures)
				if e != nil {
					blocked = Classify(e)
				} else {
					next = outage.Age() + delay
				}
			}
			continue
		}
		if generationID == math.MaxUint64 {
			cancel()
			c.clearAttempt()
			c.retire(r, c.cfg.CloseTimeout)
			c.publish(Retired, attempts, FailureGenerationExhausted, 0)
			return
		}
		generationID++
		gctx, gcancel := context.WithCancel(context.Background())
		g := &generation{id: generationID, ready: r.recovery == nil, conn: r.conn, clock: attemptClock, recovery: r.recovery, ctx: gctx, cancel: gcancel}
		c.mu.Lock()
		if c.revision != revision || c.stopped || ctx.Err() != nil || budget.Check() != nil || r.conn.IsClosed() {
			c.mu.Unlock()
			gcancel()
			cancel()
			c.clearAttempt()
			c.retire(r, c.cfg.CloseTimeout)
			continue
		}
		// A required profile is not callable until negotiation succeeds.
		if r.recovery == nil && complete != nil {
			if err = complete(); err != nil {
				c.mu.Unlock()
				gcancel()
				cancel()
				c.clearAttempt()
				c.retire(r, c.cfg.CloseTimeout)
				blocked = Classify(err)
				continue
			}
		}
		c.active = g
		if r.recovery != nil {
			c.publishLocked(Status{Phase: CoreReady, Generation: g.id, Attempts: attempts})
		} else if acceptReady(g) {
			c.publishLocked(Status{Phase: CoreReady, Generation: g.id})
		}
		c.mu.Unlock()
		if r.recovery != nil {
			negotiated := make(chan attemptResult, 1)
			callbackAdmitted := c.owner == nil || c.owner.reserveCallback()
			go func() {
				nr := attemptResult{err: FailureRecovery}
				defer func() {
					if recover() != nil {
						nr.err = FailureRecovery
					}
					if callbackAdmitted && c.owner != nil {
						c.owner.releaseCallback()
					}
					negotiated <- nr
				}()
				if callbackAdmitted {
					nr.err = r.recovery.Negotiate(ctx)
				} else {
					nr.err = ErrBusy
				}
			}()
			var nr attemptResult
		negotiating:
			for {
				select {
				case nr = <-negotiated:
					break negotiating
				case n, ok := <-r.conn.Notifications():
					if !ok {
						cancel()
					} else if n != nil {
						c.drain(g, n.GetPayload(), true)
					}
				case <-tick.C:
					if r.conn.IsClosed() {
						cancel()
					}
					c.drain(g, nil, false)
				case <-ctx.Done():
					cancel()
					nr = c.joinWorker(negotiated, min(c.cfg.CloseTimeout, max(time.Nanosecond, c.cfg.ReconnectBudget-outage.Age())))
					break negotiating
				}
			}
			c.mu.Lock()
			stale = c.revision != revision || c.stopped
			if nr.err == nil {
				nr.err = stream.ContextError(ctx)
			}
			if nr.err == nil {
				nr.err = budget.Check()
			}
			if terminal := r.conn.TerminalError(); terminal != nil && !Classify(terminal).Retryable() {
				nr.err = terminal
			}
			if nr.err == nil && outage.Age() >= c.cfg.ReconnectBudget {
				nr.err = FailureTimeout
			}
			if nr.err == nil && r.conn.IsClosed() {
				nr.err = r.conn.TerminalError()
				if nr.err == nil {
					nr.err = FailureClosed
				}
			}
			if !stale && nr.err == nil && complete != nil {
				nr.err = complete()
			}
			if nr.err == nil && r.conn.IsClosed() {
				nr.err = r.conn.TerminalError()
				if nr.err == nil {
					nr.err = FailureClosed
				}
			}
			if !stale && nr.err == nil {
				g.ready = true
				c.active = g
				if acceptReady(g) {
					c.publishLocked(Status{Phase: RecoveryNegotiated, Generation: g.id, DroppedCount: g.dropped, DroppedBytes: g.droppedBytes, QueuedNotifications: len(g.queue)})
				} else {
					nr.err = r.conn.TerminalError()
					if nr.err == nil {
						nr.err = FailureClosed
					}
				}
			} else if nr.err == nil {
				nr.err = FailureTimeout
			}
			c.mu.Unlock()
			if stale || nr.err != nil {
				c.mu.Lock()
				if c.active == g {
					c.invalidateLocked()
				}
				c.mu.Unlock()
				gcancel()
				cancel()
				c.clearAttempt()
				c.retire(r, c.cfg.CloseTimeout)
				if !stale {
					last = Classify(nr.err)
					if !last.Retryable() {
						blocked = last
					} else {
						if failures < math.MaxUint32 {
							failures++
						}
						delay, e := c.jitter(failures)
						if e != nil {
							blocked = Classify(e)
						} else {
							next = outage.Age() + delay
						}
					}
				} else if failure := Classify(nr.err); failure != FailureNone && !failure.Retryable() {
					blocked, last = failure, failure
				}
				continue
			}
		}
		cancel()
		c.clearAttempt()
		notifications := r.conn.Notifications()
	active:
		for {
			select {
			case <-g.ctx.Done():
				break active
			case <-r.conn.Done():
				break active
			case n, ok := <-notifications:
				if !ok {
					break active
				}
				if n != nil {
					c.drain(g, n.GetPayload(), true)
				}
			case <-tick.C:
				if r.conn.IsClosed() {
					break active
				}
				c.drain(g, nil, false)
			}
		}
		c.mu.Lock()
		stale = c.revision != revision || c.stopped
		if c.active == g {
			c.invalidateLocked()
		}
		outage = c.outage
		if outage == nil {
			outage = c.cfg.ClockFactory()
			c.outage = outage
		}
		c.mu.Unlock()
		terminal := r.conn.TerminalError()
		if !stale {
			// Join a remotely ended pump before local Close can mask its reason.
			wait, stop := context.WithTimeout(context.Background(), min(c.cfg.CloseTimeout, max(time.Nanosecond, c.cfg.ReconnectBudget-outage.Age())))
			joined := r.conn.Wait(wait)
			if wait.Err() != nil {
				select {
				case <-r.conn.Done():
				default:
					c.incomplete()
				}
			}
			if terminal == nil || Classify(joined) != FailureNone && !Classify(joined).Retryable() {
				terminal = joined
			}
			stop()
		}
		c.retire(r, min(c.cfg.CloseTimeout, max(time.Nanosecond, c.cfg.ReconnectBudget-outage.Age())))
		reason := Classify(terminal)
		if g.terminal != FailureNone && !g.terminal.Retryable() {
			reason = g.terminal
		}
		if final := Classify(r.conn.TerminalError()); final != FailureNone && !final.Retryable() {
			reason = final
		}
		if reason == FailureNone {
			reason = FailureClosed
		}
		if !reason.Retryable() {
			blocked = reason
			last = reason
		} else if !stale {
			last = reason
			if failures < math.MaxUint32 {
				failures++
			}
			delay, e := c.jitter(failures)
			if e != nil {
				blocked = Classify(e)
			} else {
				next = outage.Age() + delay
			}
		}
	}
}

func (c *Client) clearAttempt() {
	c.mu.Lock()
	c.attemptCancel = nil
	c.attemptClock = nil
	c.mu.Unlock()
}
