// File terminal_review_regression_test.go pins denial publication, commit
// admission, and per-observation elapsed bounds independently of cancellation.
package syntra

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// terminalReviewMethod identifies the test-only terminal handler.
const terminalReviewMethod = "/example.Authority/Retire"

// terminalReviewClock permits race-safe jumps without waiting for wall deadlines.
type terminalReviewClock struct{ elapsed atomic.Int64 }

// Age samples the injected elapsed time.
func (c *terminalReviewClock) Age() time.Duration { return time.Duration(c.elapsed.Load()) }

// Check leaves continuity valid so tests isolate elapsed cutoff.
func (c *terminalReviewClock) Check() error { return nil }

// terminalReviewAuthority records owned state or delegates to a barrier-controlled hook.
type terminalReviewAuthority struct {
	mu      sync.Mutex
	owner   *TerminalTransition
	commits atomic.Int32
	observe func(context.Context, TerminalTransition) (TerminalObservation, error)
	commit  func(context.Context, TerminalTransition) error
}

// Commit counts conditional mutation admission and optionally stalls its return.
func (a *terminalReviewAuthority) Commit(ctx context.Context, transition TerminalTransition) error {
	a.commits.Add(1)
	if a.commit != nil {
		return a.commit(ctx, transition)
	}
	a.mu.Lock()
	a.owner = &transition
	a.mu.Unlock()
	return ctx.Err()
}

// Observe returns owned evidence or the exact injected failure scenario.
func (a *terminalReviewAuthority) Observe(ctx context.Context, transition TerminalTransition) (TerminalObservation, error) {
	if a.observe != nil {
		return a.observe(ctx, transition)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.owner != nil {
		return TerminalObservation{State: TerminalOwnedCommitted, Transition: *a.owner, Revision: 2}, nil
	}
	return TerminalObservation{State: TerminalActive, Transition: transition, Revision: 1}, nil
}

// terminalReviewDriver is an explicitly coordinated test driver. Hooks run after
// Begin's successful Active validation; Stop deliberately does not cancel the
// handler, so request-context propagation cannot mask a missing failure gate.
type terminalReviewDriver struct {
	Transport
	clock      *terminalReviewClock
	afterBegin func(context.Context, *TerminalPermit)
	beforeSend func()
	handoffs   atomic.Int32
}

// TerminalReceiptDriver preserves the test driver's exact owner.
func (d *terminalReviewDriver) TerminalReceiptDriver() TerminalReceiptDriver { return d }

// TerminalClock returns the barrier-controlled elapsed origin.
func (d *terminalReviewDriver) TerminalClock() TerminalClock { return d.clock }

// TerminalBinding supplies fixed confirmed evidence, independent of request IDs.
func (d *terminalReviewDriver) TerminalBinding() (TerminalChannelBinding, bool) {
	return TerminalChannelBinding{Identity: ChannelIdentity{Mode: "returning", Scope: "review", Epoch: 1, Handle: [8]byte{1}}, ServerKeyID: 1, HandshakeHash: [32]byte{1}}, true
}

// BeginTerminal validates Active state before running the post-begin barrier.
func (d *terminalReviewDriver) BeginTerminal(ctx context.Context, p *TerminalPermit) error {
	if _, err := p.Observe(ctx, false); err != nil {
		return err
	}
	if d.afterBegin != nil {
		d.afterBegin(ctx, p)
	}
	return nil
}

// ValidateTerminal uses the real permit classifier for injected authority evidence.
func (d *terminalReviewDriver) ValidateTerminal(ctx context.Context, p *TerminalPermit, committed bool) error {
	_, err := p.Observe(ctx, committed)
	return err
}

// SendTerminal counts only handoffs that survive the real permit's final gate.
func (d *terminalReviewDriver) SendTerminal(_ context.Context, p *TerminalPermit) error {
	if d.beforeSend != nil {
		d.beforeSend()
	}
	if err := p.Handoff(); err != nil {
		return err
	}
	d.handoffs.Add(1)
	return nil
}

// StopTerminal intentionally leaves the request live to isolate failure publication.
func (d *terminalReviewDriver) StopTerminal() {}

// terminalReviewRequest creates a live core call and its exact authorized handler scope.
func terminalReviewRequest(t *testing.T, h *Host, hc *hostConn, id uint64) context.Context {
	t.Helper()
	request := &RpcRequest{Method: terminalReviewMethod, TimeoutMs: 3000}
	if _, _, fatal := hc.core.onFrame(mustMarshal(NewRequestFrame(1, id, request))); fatal != nil {
		t.Fatal(fatal)
	}
	got, _, ok := hc.core.takePending()
	if !ok || got != id {
		t.Fatal("request was not admitted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	cc := &callCancel{id: id, stop: cancel, result: make(chan *RpcResult, 1)}
	h.mu.Lock()
	hc.cancels[id] = cc
	h.mu.Unlock()
	return context.WithValue(ctx, terminalRequestKey{}, &terminalRequest{host: h, conn: hc, call: cc, ctx: ctx, method: terminalReviewMethod})
}

// terminalReviewConnection installs a coordinated driver and owned writer for policy tests.
func terminalReviewConnection(t *testing.T, authorize AuthorizeFunc) (*Host, *hostConn, *terminalReviewAuthority, *terminalReviewDriver) {
	t.Helper()
	authority := &terminalReviewAuthority{}
	cfg := testHostConfig()
	cfg.Authorize = authorize
	cfg.TerminalMethods = map[string]TerminalMethodPolicy{terminalReviewMethod: {SuccessPayload: []byte("retired"), Authority: authority, ObservationTimeout: time.Second}}
	h, hc, _ := newWithdrawalReviewConnection(t, cfg)
	d := &terminalReviewDriver{Transport: hc.transport, clock: &terminalReviewClock{}}
	hc.transport = d
	hc.writer = newHostWriter(d, time.Second)
	t.Cleanup(func() { _ = hc.writer.shutdown() })
	return h, hc, authority, d
}

// TestTerminalReviewUnusableRevisionRejectsBeforeFence pins the common
// nonzero/nonexhausted preflight contract without relying on adapter rejection.
func TestTerminalReviewUnusableRevisionRejectsBeforeFence(t *testing.T) {
	for _, revision := range []uint64{0, ^uint64(0)} {
		t.Run(fmt.Sprint(revision), func(t *testing.T) {
			h, hc, authority, _ := terminalReviewConnection(t, AllowAllAuthorize)
			authority.observe = func(_ context.Context, tr TerminalTransition) (TerminalObservation, error) {
				return TerminalObservation{State: TerminalActive, Transition: tr, Revision: tr.ExpectedRevision}, nil
			}
			ctx := terminalReviewRequest(t, h, hc, 1)
			if CompleteTerminalReceipt(ctx, "operation", revision) == nil {
				t.Fatal("unusable revision accepted")
			}
			if authority.commits.Load() != 0 || hc.terminalFenced.Load() {
				t.Fatal("unusable revision reached fencing or mutation")
			}
		})
	}
}

// TestTerminalReviewPublishedAuthorizationDenialPreventsReservation keeps a
// sibling's denial completion unprocessed while testing immediate revocation.
func TestTerminalReviewPublishedAuthorizationDenialPreventsReservation(t *testing.T) {
	h, hc, authority, driver := terminalReviewConnection(t, func(context.Context, string, string) error { return NewRpcError(ErrorCodeUnauthenticated, "withdrawn") })
	request := &RpcRequest{Method: "/example.Authority/Sibling", TimeoutMs: 3000}
	if _, _, fatal := hc.core.onFrame(mustMarshal(NewRequestFrame(1, 1, request))); fatal != nil {
		t.Fatal(fatal)
	}
	id, admitted, ok := hc.core.takePending()
	if !ok {
		t.Fatal("sibling not admitted")
	}
	if err := h.dispatch(context.Background(), driver, hc, id, admitted); err != nil {
		t.Fatal(err)
	}
	// Deliberately hold the completed callback without processing it in Serve.
	completed := <-hc.completed
	hc.workers--
	if !completed.authRevoked.Load() {
		t.Fatal("sibling did not observe revocation")
	}
	ctx := terminalReviewRequest(t, h, hc, 2)
	_ = CompleteTerminalReceipt(ctx, "operation", 1)
	if authority.commits.Load() != 0 || driver.handoffs.Load() != 0 {
		t.Fatalf("published denial lost before completion processing: commits=%d handoffs=%d", authority.commits.Load(), driver.handoffs.Load())
	}
}

// TestTerminalReviewFailureAfterBeginPreventsCommitWithoutRequestCancel checks
// sticky failure, lost ownership and elapsed cutoff independently of cancellation.
func TestTerminalReviewFailureAfterBeginPreventsCommitWithoutRequestCancel(t *testing.T) {
	for _, fault := range []string{"unknown", "ownership", "elapsed-deadline"} {
		t.Run(fault, func(t *testing.T) {
			h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
			hc.stop = func() {} // hold request cancellation propagation independently
			driver.afterBegin = func(_ context.Context, p *TerminalPermit) {
				switch fault {
				case "unknown":
					p.Fail(terminalFailure())
				case "ownership":
					h.mu.Lock()
					delete(hc.cancels, 1)
					h.mu.Unlock()
				case "elapsed-deadline":
					driver.clock.elapsed.Store(int64(5 * time.Second))
				}
			}
			ctx := terminalReviewRequest(t, h, hc, 1)
			_ = CompleteTerminalReceipt(ctx, "operation", 1)
			if authority.commits.Load() != 0 {
				t.Fatal("Commit invoked after Begin failure with request still live")
			}
		})
	}
}

// TestTerminalReviewObservationChecksItsOwnElapsedDeadline rejects a read that
// exceeds its own trusted elapsed allowance despite a longer total budget.
func TestTerminalReviewObservationChecksItsOwnElapsedDeadline(t *testing.T) {
	clock := &terminalReviewClock{}
	authority := &terminalReviewAuthority{observe: func(_ context.Context, tr TerminalTransition) (TerminalObservation, error) {
		clock.elapsed.Store(int64(100 * time.Millisecond))
		return TerminalObservation{State: TerminalActive, Transition: tr, Revision: 1}, nil
	}}
	p := &TerminalPermit{valid: true, clock: clock, until: 5 * time.Second, wallUntil: time.Now().Add(5 * time.Second), transition: TerminalTransition{ExpectedRevision: 1}, policy: TerminalMethodPolicy{Authority: authority, ObservationTimeout: 10 * time.Millisecond}}
	if _, err := p.Observe(context.Background(), false); err == nil {
		t.Fatal("10ms observation accepted after 100ms trusted elapsed time")
	}
}

// TestTerminalReviewFailureDirectlyCancelsAdmittedCommit verifies cancellation
// is visible synchronously at Fail's return, without request teardown or polling.
func TestTerminalReviewFailureDirectlyCancelsAdmittedCommit(t *testing.T) {
	h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
	hc.stop = func() {} // cancellation cannot arrive through connection teardown
	permit := make(chan *TerminalPermit, 1)
	driver.afterBegin = func(_ context.Context, p *TerminalPermit) { permit <- p }
	entered, release := make(chan context.Context, 1), make(chan struct{})
	authority.commit = func(ctx context.Context, _ TerminalTransition) error { entered <- ctx; <-release; return ctx.Err() }
	ctx := terminalReviewRequest(t, h, hc, 1)
	done := make(chan error, 1)
	go func() { done <- CompleteTerminalReceipt(ctx, "operation", 1) }()
	commitCtx := <-entered
	(<-permit).Fail(terminalFailure())
	// Err must be visible synchronously at Fail's return, not after a watcher
	// tick or eventual cancellation of the original handler context.
	if commitCtx.Err() == nil {
		close(release)
		<-done
		t.Fatal("permit failure did not directly cancel Commit context")
	}
	if ctx.Err() != nil {
		close(release)
		<-done
		t.Fatal("request cancellation masked direct Commit cancellation")
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("failed Commit produced success")
	}
}

// TestTerminalReviewExpiredWriteContextPreventsCommit stalls Begin until its
// write context expires and verifies no authority mutation starts afterward.
func TestTerminalReviewExpiredWriteContextPreventsCommit(t *testing.T) {
	h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
	hc.stop = func() {}
	policy := h.cfg.terminalMethods[terminalReviewMethod]
	policy.ObservationTimeout = 10 * time.Millisecond
	h.cfg.terminalMethods[terminalReviewMethod] = policy
	var began bool
	driver.afterBegin = func(ctx context.Context, _ *TerminalPermit) { began = true; <-ctx.Done() }
	ctx, cancel := context.WithTimeout(terminalReviewRequest(t, h, hc, 1), 200*time.Millisecond)
	defer cancel()
	_ = CompleteTerminalReceipt(ctx, "operation", 1)
	if !began {
		t.Fatal("did not reach Begin's post-validation barrier")
	}
	if authority.commits.Load() != 0 {
		t.Fatal("expired write context invoked Commit")
	}
}

// TestTerminalReviewPublishedDenialPreventsSelectedHandoff publishes sibling
// revocation after result selection, independently of completion processing.
func TestTerminalReviewPublishedDenialPreventsSelectedHandoff(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	h, hc, authority, driver := terminalReviewConnection(t, func(context.Context, string, string) error {
		<-release
		return NewRpcError(ErrorCodeUnauthenticated, "withdrawn")
	})
	request := &RpcRequest{Method: "/example.Authority/Sibling", TimeoutMs: 3000}
	if _, _, fatal := hc.core.onFrame(mustMarshal(NewRequestFrame(1, 1, request))); fatal != nil {
		t.Fatal(fatal)
	}
	id, admitted, ok := hc.core.takePending()
	if !ok {
		t.Fatal("sibling not admitted")
	}
	if err := h.dispatch(context.Background(), driver, hc, id, admitted); err != nil {
		t.Fatal(err)
	}
	driver.beforeSend = func() {
		releaseOnce.Do(func() { close(release) })
		completed := <-hc.completed // selected receipt, but denial completion remains unprocessed
		hc.workers--
		if !completed.authRevoked.Load() {
			t.Error("missing sibling withdrawal")
		}
	}
	ctx := terminalReviewRequest(t, h, hc, 2)
	if err := CompleteTerminalReceipt(ctx, "operation", 1); err == nil {
		t.Fatal("published sibling denial allowed selected receipt")
	}
	if authority.commits.Load() != 1 || driver.handoffs.Load() != 0 {
		t.Fatalf("denial handoff: commits=%d handoffs=%d", authority.commits.Load(), driver.handoffs.Load())
	}
}
