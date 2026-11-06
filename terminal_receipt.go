// File terminal_receipt.go implements opt-in, request-owned terminal retirement.
package syntra

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

// TerminalAuthorityState classifies a fresh operation-aware authority read.
type TerminalAuthorityState uint8

const (
	// TerminalUnknown includes unresolved causes, stale reads, and missing state.
	TerminalUnknown TerminalAuthorityState = iota
	// TerminalActive means the exact expected authorization revision is active.
	TerminalActive
	// TerminalOwnedCommitted means this reservation owns the conditional commit.
	TerminalOwnedCommitted
	// TerminalDenied means external withdrawal, expiry, or superseding hard denial.
	TerminalDenied
)

// TerminalTransition is private authority-adapter input, never wire data. The
// adapter must atomically compare ExpectedRevision and record the complete value
// with its application transition. ReservationID is fresh SDK randomness, not a
// diagnostic connection ID. Do not log, expose, or accept these fields from peers.
type TerminalTransition struct {
	ReservationID    [32]byte
	Principal        string
	Channel          ChannelIdentity
	ServerKeyID      uint32
	HandshakeHash    [32]byte
	Method           string
	Operation        string
	ExpectedRevision uint64
}

// TerminalObservation is authoritative evidence, not callback success. Active
// requires Revision == ExpectedRevision. OwnedCommitted requires a strictly newer
// revision and an exact Transition match, including reservation and operation.
// The adapter must report later external denial even after an owned commit.
type TerminalObservation struct {
	State      TerminalAuthorityState
	Transition TerminalTransition
	Revision   uint64
}

// TerminalAuthority owns application persistence. Commit must atomically record
// ownership from the expected active revision and all fixed-receipt conditions.
// Observe must be a fresh, authoritative read covering expiry, key/enrollment and
// application authority, including superseding denial; caches/replicas unable to
// establish that are unsupported. Both methods must honor cancellation and return
// within the configured ObservationTimeout (Commit within its context budget).
// Returning nil from Commit is never commit evidence. The SDK cannot prove an
// adapter's durability or make its transaction atomic with carrier I/O.
// A terminal callback may request Host.Close or Host.DisconnectPrincipal; the
// terminal connection's close join is retained rather than awaited on that
// callback's stack. Do not await Host.Wait/Done or the serving result inside a
// callback: joined cleanup necessarily includes the callback's own return.
type TerminalAuthority interface {
	Commit(context.Context, TerminalTransition) error
	Observe(context.Context, TerminalTransition) (TerminalObservation, error)
}

// TerminalMethodPolicy explicitly enables one authorized method. SuccessPayload
// must be fixed, non-sensitive bytes; OpenHost copies it. The complete correlated
// Frame has an immutable 1024-byte ceiling. ObservationTimeout is a declared read
// bound, must be positive and at most one second, and never renews the total budget.
// Each read is bounded independently in both trusted elapsed and context time;
// exceeding it retires I/O even if the observer has not returned.
type TerminalMethodPolicy struct {
	SuccessPayload     []byte
	Authority          TerminalAuthority
	ObservationTimeout time.Duration
}

// TerminalClock is a driver's trusted suspend-inclusive elapsed origin. Check
// must fail sticky on discontinuity; Age and Check must be prompt and safe
// concurrently. Unsupported drivers must not supply an untrusted wall clock.
type TerminalClock interface {
	Age() time.Duration
	Check() error
}

// TerminalReceiptDriver is the optional trusted ordered-driver contract. It is
// not a generic graceful-drain capability. BeginTerminal must establish the full
// frame boundary, install the shared authority classifier across ALL reader,
// writer and idle checks, and reject unsupported carriers before mutation.
// SendTerminal must freshly validate owned evidence and consume the exact permit
// at the serialized ciphertext handoff, repoll blocked I/O, and abort on any
// failure without replay. StopTerminal interrupts I/O without joining itself.
// Custom drivers must implement the whole contract or return no capability.
type TerminalReceiptDriver interface {
	TerminalClock() TerminalClock
	TerminalBinding() (TerminalChannelBinding, bool)
	BeginTerminal(context.Context, *TerminalPermit) error
	ValidateTerminal(context.Context, *TerminalPermit, bool) error
	SendTerminal(context.Context, *TerminalPermit) error
	StopTerminal()
}

// TerminalChannelBinding is confirmed transport evidence for the authority
// adapter. It is not a peer-supplied ID or a transferable receipt capability.
type TerminalChannelBinding struct {
	Identity      ChannelIdentity
	ServerKeyID   uint32
	HandshakeHash [32]byte
}

// TerminalReceiptProvider forwards the capability to the actual transport owner.
// Wrappers must preserve owner identity; nil means unsupported/default-disabled.
type TerminalReceiptProvider interface {
	TerminalReceiptDriver() TerminalReceiptDriver
}

// TerminalPermit is an SDK-created, connection-private one-use permission. Its
// zero value grants nothing. Applications cannot create it through the handler
// API. Exported methods exist only for trusted driver integration, not policy or
// peer assertions; do not store permits across connections or expose them.
type TerminalPermit struct {
	mu            sync.Mutex
	transition    TerminalTransition
	policy        TerminalMethodPolicy
	clock         TerminalClock
	until         time.Duration
	wallUntil     time.Time
	frame         []byte
	valid         bool
	owned         bool
	revision      uint64
	selected      bool
	consumed      bool
	failure       error
	owner         *terminalRequest
	failureCtx    context.Context
	failureCancel context.CancelFunc
	failed        chan struct{}
	stopIO        func() // immutable, prompt and nonjoining driver interrupt
}

func terminalFailure() error {
	return NewRpcError(ErrorCodeFailedPrecondition, "syntra: terminal receipt unavailable")
}

// CheckTime enforces the original write budget in both elapsed and request time.
func (p *TerminalPermit) CheckTime() error {
	if p == nil || !p.valid || p.clock == nil {
		return terminalFailure()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checkTimeLocked()
	return p.failure
}

// checkTimeLocked samples both clocks at a serialized decision, not before a
// potentially delayed lock acquisition. It never invokes application I/O.
func (p *TerminalPermit) checkTimeLocked() {
	if p.clock.Check() != nil || p.clock.Age() >= p.until || !time.Now().Before(p.wallUntil) {
		p.failLocked(context.DeadlineExceeded)
	}
}

// Fail installs an irreversible failure and synchronously cancels an admitted
// Commit's context before returning. It never joins carrier I/O. Late callback or
// read success cannot clear the failure or restore delivery eligibility.
func (p *TerminalPermit) Fail(err error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.failLocked(err)
}

// failLocked publishes failure and synchronously cancels any admitted Commit's
// context. Carrier interruption is handled by nonjoining watchdogs; invoking a
// driver here could recurse from that driver's own retirement lock.
func (p *TerminalPermit) failLocked(err error) {
	if p.failure == nil {
		p.failure = terminalFailure()
		if errors.Is(err, context.DeadlineExceeded) {
			p.failure = context.DeadlineExceeded
		}
		if p.failureCancel != nil {
			p.failureCancel()
		}
		if p.failed != nil {
			close(p.failed)
		}
	}
}

// Observe validates fresh typed evidence. Drivers serialize observations; no
// local mutex is held across authority I/O. Unknown/error/mismatch is sticky.
// Active never permits a receipt or ordinary traffic on the fenced connection.
// Once committed, a stale Active read cannot resurrect state.
func (p *TerminalPermit) Observe(ctx context.Context, requireCommit bool) (TerminalAuthorityState, error) {
	if err := p.CheckTime(); err != nil {
		return TerminalUnknown, err
	}
	readStart := p.clock.Age()
	readUntil := min(p.until, readStart+p.policy.ObservationTimeout)
	readCtx, cancel := context.WithTimeout(ctx, p.policy.ObservationTimeout)
	defer cancel()
	finished, watched := make(chan struct{}), make(chan struct{})
	// This owner is independent of the authority callback and the serialized
	// driver observer gate. A callback ignoring cancellation retains its charge,
	// but cannot postpone read cutoff or carrier interruption until its return.
	go func() {
		defer close(watched)
		tick := time.NewTicker(terminalPollInterval)
		defer tick.Stop()
		abort := func(err error) {
			p.Fail(err)
			cancel()
			if p.stopIO != nil {
				p.stopIO()
			}
		}
		for {
			if p.clock.Check() != nil || p.clock.Age() >= readUntil {
				abort(context.DeadlineExceeded)
				return
			}
			select {
			case <-finished:
				return
			case <-p.failed:
				cancel()
				if p.stopIO != nil {
					p.stopIO()
				}
				return
			case <-readCtx.Done():
				select {
				case <-finished:
					return
				default:
				}
				abort(readCtx.Err())
				return
			case <-tick.C:
			}
		}
	}()
	observation, err := p.policy.Authority.Observe(readCtx, p.transition)
	close(finished)
	<-watched
	if err != nil || readCtx.Err() != nil || p.clock.Check() != nil || p.clock.Age() >= readUntil {
		if err == nil {
			err = context.DeadlineExceeded
		}
		p.Fail(err)
		if p.stopIO != nil {
			p.stopIO()
		}
		return TerminalUnknown, terminalFailure()
	}
	if err := p.CheckTime(); err != nil {
		return TerminalUnknown, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failure != nil {
		return TerminalUnknown, p.failure
	}
	valid := observation.Transition == p.transition
	switch observation.State {
	case TerminalActive:
		valid = valid && !p.owned && observation.Revision == p.transition.ExpectedRevision && !requireCommit
	case TerminalOwnedCommitted:
		valid = valid && observation.Revision > p.transition.ExpectedRevision && (!p.owned || observation.Revision == p.revision)
	default:
		valid = false
	}
	if !valid {
		p.failLocked(terminalFailure())
		return TerminalUnknown, p.failure
	}
	if observation.State == TerminalOwnedCommitted {
		p.owned, p.revision = true, observation.Revision
	}
	return observation.State, nil
}

// Frame returns an owned copy of the sole predeclared result for the driver.
func (p *TerminalPermit) Frame() []byte {
	if p == nil || !p.valid {
		return nil
	}
	return append([]byte(nil), p.frame...)
}

// MatchesChannel checks exact authenticated enrollment scope for a trusted driver.
func (p *TerminalPermit) MatchesChannel(binding TerminalChannelBinding) bool {
	return p != nil && p.valid && p.transition.Channel == binding.Identity && p.transition.ServerKeyID == binding.ServerKeyID && p.transition.HandshakeHash == binding.HandshakeHash
}

// Handoff consumes the permit once after fresh driver validation. Concurrent
// locally observed denial serialized before this point wins. Remote denial after
// the last observation may race the first bytes; handed-off bytes cannot be recalled.
func (p *TerminalPermit) Handoff() error {
	if err := p.CheckTime(); err != nil {
		return err
	}
	if p.owner == nil {
		return terminalFailure()
	}
	h, hc, cc := p.owner.host, p.owner.conn, p.owner.call
	h.mu.Lock()
	defer h.mu.Unlock()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.checkTimeLocked()
	if h.closed || hc.closing || hc.authorizationRevoked || hc.terminal != p || hc.cancels[cc.id] != cc {
		p.failLocked(terminalFailure())
	}
	if p.failure != nil {
		return p.failure
	}
	if !p.selected || !p.owned || p.consumed {
		return terminalFailure()
	}
	p.consumed = true
	return nil
}

type terminalRequestKey struct{}

// terminalRequest is minted only after method authorization, for the exact live
// callback pointer. Public/diagnostic request IDs cannot manufacture this scope.
type terminalRequest struct {
	host   *Host
	conn   *hostConn
	call   *callCancel
	ctx    context.Context
	method string
}

// CompleteTerminalReceipt reserves, fences, conditionally commits, validates,
// selects and attempts the configured fixed result for this authorized handler.
// It must be called BEFORE application mutation; only the configured authority's
// Commit performs the terminal transition. No payload or caller-created permit
// is accepted. It writes independently of handler return, then closes this
// connection on every reserved path. Return nil means complete LOCAL write, not
// client receipt, durable client storage, or joined cleanup. Loss is unknown and
// must never trigger automatic mutation replay. A surviving Commit remains
// charged to the original callback until it actually returns.
func CompleteTerminalReceipt(ctx context.Context, operation string, expectedRevision uint64) error {
	scope, ok := ctx.Value(terminalRequestKey{}).(*terminalRequest)
	if !ok || scope == nil || operation == "" || len(operation) > 256 || expectedRevision == 0 || expectedRevision == ^uint64(0) || ctx.Err() != nil {
		return terminalFailure()
	}
	h, hc, cc := scope.host, scope.conn, scope.call
	// Recovery sources have independent authority callbacks. Until those callbacks
	// participate in this coordinator, reject rather than inherit partial support.
	if hc.recovery != nil {
		return terminalFailure()
	}
	policy, enabled := h.cfg.terminalMethods[scope.method]
	provider, supported := hc.transport.(TerminalReceiptProvider)
	if !enabled || !supported {
		return terminalFailure()
	}
	driver := provider.TerminalReceiptDriver()
	if driver == nil {
		return terminalFailure()
	}
	clock := driver.TerminalClock()
	if clock == nil || clock.Check() != nil {
		return terminalFailure()
	}
	wallStart := time.Now()
	start := clock.Age()
	deadline, ok := scope.ctx.Deadline()
	if !ok {
		return terminalFailure()
	}
	if callerDeadline, ok := ctx.Deadline(); ok {
		deadline = minTime(deadline, callerDeadline)
	}
	initialRemaining := min(deadline.Sub(wallStart), 5*time.Second)
	remaining := min(time.Until(deadline), 5*time.Second-time.Since(wallStart))
	tail := min(initialRemaining/4, 250*time.Millisecond)
	if tail < 2*terminalPollInterval || remaining-tail <= policy.ObservationTimeout {
		return terminalFailure()
	}
	frame, err := MarshalFrame(NewResultFrame(hc.version, cc.id, NewSuccessResult(policy.SuccessPayload)))
	if err != nil || len(frame) > 1024 {
		return terminalFailure()
	}
	failureCtx, failureCancel := context.WithCancel(scope.ctx)
	defer failureCancel()
	p := &TerminalPermit{policy: policy, clock: clock, until: start + remaining - tail,
		owner: scope, failureCtx: failureCtx, failureCancel: failureCancel, failed: make(chan struct{}), stopIO: driver.StopTerminal,
		wallUntil: minTime(deadline, wallStart.Add(5*time.Second)).Add(-tail), frame: frame, valid: true,
		transition: TerminalTransition{Principal: hc.principal, Method: scope.method, Operation: operation, ExpectedRevision: expectedRevision}}
	p.policy.Authority = terminalChargedAuthority{host: h, authority: policy.Authority}
	if _, err := rand.Read(p.transition.ReservationID[:]); err != nil {
		return terminalFailure()
	}
	binding, confirmed := driver.TerminalBinding()
	if !confirmed || binding.Identity.Mode != "returning" {
		return terminalFailure()
	}
	p.transition.Channel = binding.Identity
	p.transition.ServerKeyID = binding.ServerKeyID
	p.transition.HandshakeHash = binding.HandshakeHash
	h.mu.Lock()
	if h.closed || hc.closing || hc.authorizationRevoked || hc.terminalFenced.Load() || hc.cancels[cc.id] != cc || scope.ctx.Err() != nil || !hc.core.terminalPending(cc.id) {
		h.mu.Unlock()
		return terminalFailure()
	}
	hc.terminal = p
	hc.writer.fence()
	hc.core.fenceTerminal()
	hc.terminalFenced.Store(true)
	for id, sibling := range hc.cancels {
		if sibling != cc {
			sibling.stop()
			delete(hc.cancels, id)
		}
	}
	h.mu.Unlock()
	// Install close ownership BEFORE any application transaction. This timer
	// interrupts I/O without joining a writer/authority callback from itself.
	writeCtx, cancel := context.WithDeadline(context.WithoutCancel(scope.ctx), p.wallUntil)
	defer cancel()
	watchDone := make(chan struct{})
	h.owned.Add(1)
	go func() {
		defer h.owned.Done()
		defer close(watchDone)
		tick := time.NewTicker(terminalPollInterval)
		defer tick.Stop()
		for {
			p.mu.Lock()
			cancelled := !p.selected && (scope.ctx.Err() != nil || ctx.Err() != nil)
			if cancelled && p.failure == nil {
				p.failLocked(terminalFailure())
			}
			p.mu.Unlock()
			if cancelled {
				driver.StopTerminal()
				hc.stop()
				return
			}
			if p.CheckTime() != nil {
				driver.StopTerminal()
				hc.stop()
				return
			}
			select {
			case <-p.failed:
				driver.StopTerminal()
				hc.stop()
				return
			case <-writeCtx.Done():
				p.Fail(writeCtx.Err())
				driver.StopTerminal()
				hc.stop()
				return
			case <-tick.C:
			}
		}
	}()
	defer func() { cancel(); <-watchDone; driver.StopTerminal(); hc.stop() }()
	if err := hc.writer.quiesce(writeCtx); err != nil {
		p.Fail(err)
		return err
	}
	if err := driver.BeginTerminal(writeCtx, p); err != nil {
		p.Fail(err)
		return err
	}
	commitCtx, commitCancel := context.WithDeadline(p.failureCtx, p.wallUntil)
	defer commitCancel()
	// Linearize Commit admission against already-published failures, withdrawal,
	// ownership and both deadlines. No mutex is held across the application call.
	// A subsequent failure synchronously cancels commitCtx; it cannot roll back
	// application effects already admitted at this decision point.
	h.mu.Lock()
	p.mu.Lock()
	p.checkTimeLocked()
	if p.failure != nil || writeCtx.Err() != nil || commitCtx.Err() != nil || scope.ctx.Err() != nil || ctx.Err() != nil || h.closed || hc.closing || hc.authorizationRevoked || hc.terminal != p || hc.cancels[cc.id] != cc || !hc.core.terminalPending(cc.id) {
		p.failLocked(terminalFailure())
		p.mu.Unlock()
		h.mu.Unlock()
		return terminalFailure()
	}
	p.mu.Unlock()
	h.mu.Unlock()
	err = policy.Authority.Commit(commitCtx, p.transition)
	commitCancel()
	if err != nil {
		p.Fail(err)
		return terminalFailure()
	}
	if err := driver.ValidateTerminal(writeCtx, p, true); err != nil {
		p.Fail(err)
		return err
	}
	h.mu.Lock()
	p.mu.Lock()
	p.checkTimeLocked()
	if p.failure != nil || scope.ctx.Err() != nil || ctx.Err() != nil || hc.cancels[cc.id] != cc || h.closed || hc.closing || hc.authorizationRevoked || !hc.core.terminalPending(cc.id) {
		p.mu.Unlock()
		h.mu.Unlock()
		p.Fail(context.Canceled)
		return terminalFailure()
	}
	selected, _, err := hc.core.answer(cc.id, NewSuccessResult(policy.SuccessPayload))
	if err == nil && bytes.Equal(selected, frame) {
		p.selected = true
	} else {
		err = terminalFailure()
		if p.failure == nil {
			p.failLocked(err)
		}
	}
	p.mu.Unlock()
	h.mu.Unlock()
	if err != nil {
		return err
	}
	return driver.SendTerminal(writeCtx, p)
}

// terminalPollInterval bounds elapsed-deadline/continuity detection while even a
// pre-mutation ordinary frame is blocked. Two ticks must fit the teardown tail.
const terminalPollInterval = 10 * time.Millisecond

// terminalChargedAuthority retains actual observer execution ownership even when
// a deadline closes the socket before a misbehaving callback returns. Commit is
// already charged to the initiating handler; it is never spawned or replayed.
type terminalChargedAuthority struct {
	host      *Host
	authority TerminalAuthority
}

func (a terminalChargedAuthority) Commit(ctx context.Context, transition TerminalTransition) error {
	return a.authority.Commit(ctx, transition)
}

func (a terminalChargedAuthority) Observe(ctx context.Context, transition TerminalTransition) (TerminalObservation, error) {
	if !a.host.cfg.executions.acquire() {
		return TerminalObservation{}, terminalFailure()
	}
	a.host.owned.Add(1)
	defer a.host.owned.Done()
	defer a.host.cfg.executions.release()
	return a.authority.Observe(ctx, transition)
}

func (t *ownedTransport) TerminalReceiptDriver() TerminalReceiptDriver {
	if provider, ok := t.Transport.(TerminalReceiptProvider); ok {
		return provider.TerminalReceiptDriver()
	}
	return nil
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// quiesce drops unstarted snapshots and waits only for the active full frame.
// No cancellation of a partial ordinary frame followed by a receipt is allowed.
func (w *hostWriter) quiesce(ctx context.Context) error {
	idle := w.fence()
	select {
	case <-idle:
		return w.err()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fence seals admission synchronously with the host's reservation decision.
func (w *hostWriter) fence() <-chan struct{} {
	w.mu.Lock()
	w.fenced = true
	w.accepting = false
	for len(w.frames) > 0 {
		frame := <-w.frames
		w.count--
		w.bytes -= len(frame)
		if w.count == 0 {
			close(w.idle)
		}
	}
	idle := w.idle
	w.mu.Unlock()
	return idle
}
