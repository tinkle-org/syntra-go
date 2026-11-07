// File receipt_timing_regression_test.go checks conservative paired clock capture.
package syntra

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"
)

// receiptPairClock jumps trusted time after sampling without advancing Go timers.
type receiptPairClock struct {
	terminalReviewClock
	afterSample time.Time
}

// receiptTransportFixture makes outer Recv dispatch and receipt publication observable.
type receiptTransportFixture struct {
	Transport
	frame    []byte
	receipt  FrameReceipt
	received bool
}

// Recv publishes original timing while preserving the ordinary receive entry point.
func (f *receiptTransportFixture) Recv(ctx context.Context) ([]byte, error) {
	f.received = true
	raw, _, err := f.RecvWithReceipt(ctx)
	return raw, err
}

// RecvWithReceipt returns the frame and its immutable original timing together.
func (f *receiptTransportFixture) RecvWithReceipt(ctx context.Context) ([]byte, FrameReceipt, error) {
	f.receipt.Publish(ctx, f.frame)
	return f.frame, f.receipt, nil
}

// legacyReceiptFixture deliberately supplies no receive metadata.
type legacyReceiptFixture struct{ *receiptTransportFixture }

// Recv exposes only legacy delivery timing, with no receipt publication.
func (f *legacyReceiptFixture) Recv(context.Context) ([]byte, error) {
	f.received = true
	return f.frame, nil
}

// TestReceiptSDKWrappersAndLegacyFallback checks ownership and recovery wrappers
// without permitting a capability forwarder to bypass recovery ingress checks.
func TestReceiptSDKWrappersAndLegacyFallback(t *testing.T) {
	clock := &terminalReviewClock{}
	original := CaptureFrameReceipt(clock)
	fixture := &receiptTransportFixture{frame: []byte("frame"), receipt: original}
	for _, wrapper := range []string{"owned", "recovery", "hidden-optional", "legacy", "closed-recovery"} {
		t.Run(wrapper, func(t *testing.T) {
			fixture.received = false
			var transport Transport = &ownedTransport{Transport: fixture}
			switch wrapper {
			case "recovery", "closed-recovery":
				inbox, err := NewRecoveryInbox(DefaultRecoveryLimits())
				if err != nil {
					t.Fatal(err)
				}
				client := &Client{recoveryInbox: inbox}
				transport = WrapRecoveryTransport(transport, client, inbox)
				if wrapper == "closed-recovery" {
					inbox.Close()
				}
			case "hidden-optional":
				// Hiding optional methods must not hide context-carried metadata.
				transport = &ownedTransport{Transport: struct{ Transport }{fixture}}
			case "legacy":
				transport = &ownedTransport{Transport: &legacyReceiptFixture{fixture}}
			}
			raw, receipt, err := recvWithReceipt(context.Background(), transport)
			if wrapper == "closed-recovery" {
				if err == nil || raw != nil || fixture.received {
					t.Fatal("timed receive bypassed closed ingress")
				}
				return
			}
			if err != nil || string(raw) != "frame" {
				t.Fatalf("wrapper receive: raw=%q err=%v", raw, err)
			}
			if wrapper == "legacy" {
				if !fixture.received || receipt.ReceivedAt().Before(original.ReceivedAt()) || receipt.receipt.clock != nil {
					t.Fatal("legacy fallback manufactured unavailable original timing")
				}
			} else if !fixture.received || receipt != original {
				t.Fatal("wrapper lost the atomic original frame receipt")
			}
		})
	}
}

// TestReceiptInvalidClockAndExactExpiry rejects missing metadata, bad continuity,
// arithmetic overflow and exact elapsed ties instead of renewing at delivery.
func TestReceiptInvalidClockAndExactExpiry(t *testing.T) {
	for _, fault := range []string{"zero", "negative", "discontinuity", "regression", "overflow", "tie"} {
		t.Run(fault, func(t *testing.T) {
			clock := &requestBudgetFaultClock{}
			if fault == "negative" {
				clock.elapsed.Store(-1)
			}
			if fault == "overflow" {
				clock.elapsed.Store(math.MaxInt64 - 1)
			}
			receipt := CaptureFrameReceipt(clock)
			switch fault {
			case "zero":
				receipt = FrameReceipt{}
			case "discontinuity":
				clock.failed.Store(true)
			case "regression":
				clock.elapsed.Store(-1)
			case "tie":
				clock.elapsed.Store(int64(80 * time.Millisecond))
			}
			b := requestBudgetAt(receipt.receipt, receipt.ReceivedAt().Add(80*time.Millisecond))
			if b.Remaining() != 0 {
				t.Fatal("invalid original receipt granted time")
			}
		})
	}
}

// deadlineAdvanceContext simulates suspension during the parent's Deadline read.
type deadlineAdvanceContext struct {
	context.Context
	once sync.Once
	jump func()
}

// Deadline advances trusted time once without changing the parent's Go deadline.
func (c *deadlineAdvanceContext) Deadline() (time.Time, bool) {
	c.once.Do(c.jump)
	return c.Context.Deadline()
}

// TestTerminalParentProjectionDoesNotResampleElapsed ensures an inter-sample
// suspension is charged, original receipt metadata is retained, and continuity
// failure cannot produce a usable derived callback budget.
func TestTerminalParentProjectionDoesNotResampleElapsed(t *testing.T) {
	for _, fault := range []string{"suspend", "discontinuity"} {
		t.Run(fault, func(t *testing.T) {
			clock := &requestBudgetFaultClock{}
			clock.elapsed.Store(int64(10 * time.Second))
			receipt := CaptureFrameReceipt(clock).receipt
			original := requestBudgetAt(receipt, receipt.at.Add(2*time.Second))
			p := &TerminalPermit{valid: true, clock: clock, budget: original, until: 12 * time.Second, wallUntil: original.deadline}
			parent, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			ctx := &deadlineAdvanceContext{Context: parent, jump: func() {
				clock.elapsed.Store(int64(10*time.Second + 80*time.Millisecond))
				if fault == "discontinuity" {
					clock.failed.Store(true)
				}
			}}
			_, stop, b := p.authorityContext(ctx, time.Second)
			defer stop()
			if b.Remaining() != 0 || b.until > 10*time.Second+80*time.Millisecond {
				t.Fatalf("projection resampled allowance: until=%v remaining=%v", b.until, b.Remaining())
			}
			if b.receipt != original.receipt || p.budget != original {
				t.Fatal("projection replaced the original receipt or mutated the permit budget")
			}
		})
	}
}

// Age captures the old age and then models suspension before scheduler sampling.
func (c *receiptPairClock) Age() time.Duration {
	age := c.terminalReviewClock.Age()
	c.afterSample = time.Now()
	c.elapsed.Store(int64(80 * time.Millisecond))
	return age
}

// TestReceiptCaptureElapsedPrecedesScheduler prevents paired sampling from
// forgiving suspension between the trusted origin and the Go scheduler origin.
func TestReceiptCaptureElapsedPrecedesScheduler(t *testing.T) {
	clock := &receiptPairClock{}
	driver := &requestBudgetClockDriver{origin: clock}
	r := captureRequestReceipt(driver)
	if r.at.Before(clock.afterSample) || r.age != 0 {
		t.Fatalf("receipt sampled scheduler before trusted age: at=%v age=%v sampled=%v", r.at, r.age, clock.afterSample)
	}
	b := requestBudgetAt(r, r.at.Add(40*time.Millisecond))
	if b.Remaining() != 0 {
		t.Fatal("suspension between paired captures renewed the request")
	}
}

// TestTerminalParentDeadlineExpiresInElapsedDomain rejects a fresh-looking
// authority proof after the earlier parent elapsed bound, without a Go timer tick.
func TestTerminalParentDeadlineExpiresInElapsedDomain(t *testing.T) {
	clock := &terminalReviewClock{}
	clock.elapsed.Store(int64(10 * time.Second))
	p := &TerminalPermit{valid: true, clock: clock, until: 12 * time.Second, wallUntil: time.Now().Add(2 * time.Second)}
	parent, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	readCtx, stop, b := p.authorityContext(parent, time.Second)
	defer stop()
	if b.until > 10*time.Second+80*time.Millisecond {
		t.Errorf("parent deadline not projected into trusted clock: until=%v", b.until)
	}
	clock.elapsed.Store(int64(10*time.Second + 80*time.Millisecond))
	if parent.Err() != nil || readCtx.Err() != nil {
		t.Fatal("fixture must expire trusted time independently of Go timers")
	}
	if b.Remaining() != 0 {
		t.Error("earlier parent elapsed cutoff still grants callback time")
	}
	// The same projection must be enforced by Observe, not just its accessor.
	clock.elapsed.Store(int64(10 * time.Second))
	p.policy.ObservationTimeout = time.Second
	p.policy.Authority = &terminalReviewAuthority{observe: func(ctx context.Context, tr TerminalTransition) (TerminalObservation, error) {
		clock.elapsed.Store(int64(10*time.Second + 80*time.Millisecond))
		budget, ok := RequestBudgetFromContext(ctx)
		if !ok || budget.Remaining() != 0 {
			t.Error("observer retained expired parent allowance")
		}
		return TerminalObservation{State: TerminalOwnedCommitted, Transition: tr, Revision: 2}, nil
	}}
	if state, err := p.Observe(parent, true); err == nil || state != TerminalUnknown || p.owned {
		t.Fatalf("expired parent accepted owned proof: state=%v err=%v owned=%v", state, err, p.owned)
	}
}

// TestTerminalParentExpiredBeforeAuthorityAttachment charges suspension before
// callback attachment against the original SDK receipt, not a new parent origin.
func TestTerminalParentExpiredBeforeAuthorityAttachment(t *testing.T) {
	for _, test := range []struct {
		name      string
		observe   bool
		inherited bool
		elapsed   time.Duration
	}{
		{"context-at-cutoff", false, false, 80 * time.Millisecond},
		{"context-after-cutoff", false, false, 120 * time.Millisecond},
		{"observe-at-cutoff", true, false, 80 * time.Millisecond},
		{"inherited-context", false, true, 80 * time.Millisecond},
		{"inherited-observe", true, true, 80 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			clock := &terminalReviewClock{}
			clock.elapsed.Store(int64(10 * time.Second))
			receipt := CaptureFrameReceipt(clock).receipt
			original := requestBudgetAt(receipt, receipt.at.Add(2*time.Second))
			p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline}
			base := context.Background()
			if test.inherited {
				base = context.WithValue(base, requestBudgetKey{}, original)
			}
			parent, cancel := context.WithDeadline(base, receipt.at.Add(80*time.Millisecond))
			defer cancel()
			clock.elapsed.Store(int64(10*time.Second + test.elapsed))
			if parent.Err() != nil || original.Remaining() == 0 {
				t.Fatal("fixture must retain Go parent time and the wider original request budget")
			}
			if !test.observe {
				callbackCtx, stop, b := p.authorityContext(parent, time.Second)
				defer stop()
				if b.Remaining() != 0 || b.until > 10*time.Second+80*time.Millisecond || callbackCtx.Err() != context.DeadlineExceeded {
					t.Errorf("pre-attachment suspension renewed parent: until=%v remaining=%v ctx=%v", b.until, b.Remaining(), callbackCtx.Err())
				}
				if b.receipt != original.receipt || p.budget != original {
					t.Error("parent clamp replaced the receipt or mutated the original budget")
				}
				return
			}
			called := false
			p.policy.ObservationTimeout = time.Second
			p.policy.Authority = &terminalReviewAuthority{observe: func(context.Context, TerminalTransition) (TerminalObservation, error) {
				called = true
				return TerminalObservation{State: TerminalOwnedCommitted, Transition: p.transition, Revision: 2}, nil
			}}
			state, err := p.Observe(parent, true)
			if err == nil || state != TerminalUnknown || called || p.owned || p.CheckTime() == nil {
				t.Fatalf("expired parent admitted proof: state=%v err=%v called=%v owned=%v", state, err, called, p.owned)
			}
		})
	}
}

// TestTerminalSDKParentCutoffIsNotProjectedTwice preserves an SDK-derived read
// timer's known elapsed bound across attachment, then rejects its exact expiry.
func TestTerminalSDKParentCutoffIsNotProjectedTwice(t *testing.T) {
	clock := &terminalReviewClock{}
	clock.elapsed.Store(int64(10 * time.Second))
	receipt := CaptureFrameReceipt(clock).receipt
	original := requestBudgetAt(receipt, receipt.at.Add(2*time.Second))
	p := &TerminalPermit{valid: true, clock: clock, budget: original, until: original.until, wallUntil: original.deadline}
	clock.elapsed.Store(int64(10500 * time.Millisecond))
	parent, stop, parentBudget := p.authorityContext(context.Background(), 80*time.Millisecond)
	defer stop()
	child, cancel, b := p.authorityContext(parent, time.Second)
	defer cancel()
	if child.Err() != nil || b.Remaining() <= 0 || b.until > parentBudget.until || b.receipt != original.receipt || p.budget != original {
		t.Fatalf("SDK timer was reprojected or widened: until=%v parent=%v remaining=%v err=%v", b.until, parentBudget.until, b.Remaining(), child.Err())
	}
	clock.elapsed.Store(int64(parentBudget.until))
	_, stopExpired, expired := p.authorityContext(parent, time.Second)
	defer stopExpired()
	if expired.Remaining() != 0 || expired.until > parentBudget.until {
		t.Fatal("expired SDK parent was renewed on reattachment")
	}
}

// TestTerminalExpiredCallerCannotMintWriteBudget rejects an earlier caller
// deadline exhausted in trusted time before reservation can create SDK timing.
func TestTerminalExpiredCallerCannotMintWriteBudget(t *testing.T) {
	h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
	policy := h.cfg.terminalMethods[terminalReviewMethod]
	policy.ObservationTimeout = 5 * time.Millisecond
	h.cfg.terminalMethods[terminalReviewMethod] = policy
	result := make(chan error, 1)
	h.cfg.handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
		budget, ok := RequestBudgetFromContext(ctx)
		if !ok {
			t.Error("handler missing original request budget")
		}
		child, cancel := context.WithDeadline(ctx, budget.receipt.at.Add(200*time.Millisecond))
		defer cancel()
		driver.clock.elapsed.Store(int64(budget.receipt.age + 200*time.Millisecond))
		if child.Err() != nil {
			t.Error("fixture must not expire the caller's Go timer")
		}
		err := CompleteTerminalReceipt(child, "operation", 1)
		result <- err
		return nil, err
	}
	dispatchBudgetTerminal(t, h, hc)
	joinBudgetTerminal(t, hc)
	if err := <-result; err == nil || authority.commits.Load() != 0 || driver.handoffs.Load() != 0 || hc.terminalFenced.Load() {
		t.Fatalf("expired caller minted terminal allowance: err=%v commits=%d handoffs=%d fenced=%v", err, authority.commits.Load(), driver.handoffs.Load(), hc.terminalFenced.Load())
	}
}
