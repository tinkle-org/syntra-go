// File request_budget_terminal_test.go verifies shared timing across reservation,
// durable work, proof and handoff without relying on application cancellation.
package syntra

import (
	"context"
	"sync"
	"testing"
	"time"
)

// dispatchBudgetTerminal enters the real authorized runtime with captured timing.
func dispatchBudgetTerminal(t *testing.T, h *Host, hc *hostConn) {
	t.Helper()
	transport := hc.transport
	request := &RpcRequest{Method: terminalReviewMethod, TimeoutMs: 120000}
	if _, _, fatal := hc.core.onFrameReceipt(mustMarshal(NewRequestFrame(1, 1, request)), captureRequestReceipt(transport)); fatal != nil {
		t.Fatal(fatal)
	}
	id, req, ok := hc.core.takePending()
	if !ok {
		t.Fatal("terminal request not admitted")
	}
	if err := h.dispatch(context.Background(), transport, hc, id, req); err != nil {
		t.Fatal(err)
	}
}

// joinBudgetTerminal receives published completion, not an actual ownership join.
func joinBudgetTerminal(t *testing.T, hc *hostConn) {
	t.Helper()
	select {
	case <-hc.completed:
		hc.workers--
	case <-time.After(time.Second):
		t.Fatal("terminal callback did not return")
	}
}

// TestRequestBudgetTerminalOriginalOriginAndAdapters keeps preauthorization
// suspend in the terminal permit and exposes the SDK budget to every adapter.
func TestRequestBudgetTerminalOriginalOriginAndAdapters(t *testing.T) {
	for _, lateSend := range []bool{false, true} {
		t.Run(map[bool]string{false: "healthy", true: "expired-handoff"}[lateSend], func(t *testing.T) {
			h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
			policy := h.cfg.terminalMethods[terminalReviewMethod]
			policy.ObservationTimeout = 10 * time.Millisecond
			h.cfg.terminalMethods[terminalReviewMethod] = policy
			h.cfg.requestBudget = func(string, string, []byte) (time.Duration, bool) { return 3 * time.Second, true }
			h.cfg.authorize = func(ctx context.Context, _, _ string) error {
				b, ok := RequestBudgetFromContext(ctx)
				if !ok || b.Remaining() <= 2*time.Second {
					t.Error("initial authorization missing full original budget")
				}
				driver.clock.elapsed.Store(int64(2500 * time.Millisecond))
				return nil
			}
			var adapterCalls int
			checkAdapter := func(ctx context.Context) {
				adapterCalls++
				b, ok := RequestBudgetFromContext(ctx)
				if !ok || b.Remaining() <= 0 || b.Remaining() > 500*time.Millisecond {
					t.Errorf("adapter lost receipt-origin suspend: ok=%v remaining=%v", ok, b.Remaining())
				}
				if d, ok := ctx.Deadline(); !ok || d.After(b.Deadline()) {
					t.Error("adapter context extended request deadline")
				}
			}
			authority.commit = func(ctx context.Context, tr TerminalTransition) error {
				checkAdapter(ctx)
				authority.mu.Lock()
				authority.owner = &tr
				authority.mu.Unlock()
				return nil
			}
			authority.observe = func(ctx context.Context, tr TerminalTransition) (TerminalObservation, error) {
				checkAdapter(ctx)
				authority.mu.Lock()
				defer authority.mu.Unlock()
				if authority.owner != nil {
					return TerminalObservation{State: TerminalOwnedCommitted, Transition: tr, Revision: 2}, nil
				}
				return TerminalObservation{State: TerminalActive, Transition: tr, Revision: 1}, nil
			}
			driver.afterBegin = func(_ context.Context, p *TerminalPermit) {
				if p.until > 3*time.Second || p.until <= 2500*time.Millisecond {
					t.Errorf("permit renewed trusted elapsed deadline: %v", p.until)
				}
			}
			if lateSend {
				driver.beforeSend = func() { driver.clock.elapsed.Store(int64(3 * time.Second)) }
			}
			result := make(chan error, 1)
			h.cfg.handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
				err := CompleteTerminalReceipt(ctx, "operation", 1)
				result <- err
				return nil, err
			}
			dispatchBudgetTerminal(t, h, hc)
			joinBudgetTerminal(t, hc)
			err := <-result
			wantHandoffs := int32(1)
			if lateSend {
				wantHandoffs = 0
			}
			if (err != nil) != lateSend || authority.commits.Load() != 1 || driver.handoffs.Load() != wantHandoffs || adapterCalls < 3 {
				t.Fatalf("terminal result=%v commits=%d handoffs=%d adapters=%d", err, authority.commits.Load(), driver.handoffs.Load(), adapterCalls)
			}
		})
	}
}

// TestRequestBudgetTerminalLateExternalWorkKeepsCharges refuses late Commit or
// proof success without pretending that timeout rolled back the durable commit.
func TestRequestBudgetTerminalLateExternalWorkKeepsCharges(t *testing.T) {
	for _, stage := range []string{"commit", "proof"} {
		t.Run(stage, func(t *testing.T) {
			h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
			budget, err := NewExecutionBudget(4)
			if err != nil {
				t.Fatal(err)
			}
			h.cfg.executions = budget
			policy := h.cfg.terminalMethods[terminalReviewMethod]
			policy.ObservationTimeout = 20 * time.Millisecond
			h.cfg.terminalMethods[terminalReviewMethod] = policy
			h.cfg.requestBudget = func(string, string, []byte) (time.Duration, bool) { return 300 * time.Millisecond, true }
			entered := make(chan context.Context, 1)
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			authority.commit = func(ctx context.Context, tr TerminalTransition) error {
				if stage == "commit" {
					entered <- ctx
					<-release // admitted durable work ignores cancellation
				}
				authority.mu.Lock()
				authority.owner = &tr
				authority.mu.Unlock()
				return nil
			}
			authority.observe = func(ctx context.Context, tr TerminalTransition) (TerminalObservation, error) {
				authority.mu.Lock()
				committed := authority.owner != nil
				authority.mu.Unlock()
				if !committed {
					return TerminalObservation{State: TerminalActive, Transition: tr, Revision: 1}, nil
				}
				if stage == "proof" {
					entered <- ctx
					<-release // fresh-looking evidence is too late
				}
				return TerminalObservation{State: TerminalOwnedCommitted, Transition: tr, Revision: 2}, nil
			}
			result := make(chan error, 1)
			h.cfg.handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
				err := CompleteTerminalReceipt(ctx, "operation", 1)
				result <- err
				return nil, err
			}
			dispatchBudgetTerminal(t, h, hc)
			callbackCtx := <-entered
			select {
			case <-callbackCtx.Done():
			case <-time.After(time.Second):
				t.Fatal("selected budget failed to cancel external callback")
			}
			wantCharge := 1
			if stage == "proof" {
				wantCharge = 2 // handler plus actual authority observer
			}
			if budget.Live() != wantCharge {
				t.Fatalf("late external work escaped accounting: %d want %d", budget.Live(), wantCharge)
			}
			once.Do(func() { close(release) })
			joinBudgetTerminal(t, hc)
			// Completion precedes deferred charge release; join all actual owners.
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			t.Cleanup(cancel)
			if err := h.Wait(ctx); err != nil {
				t.Fatalf("terminal ownership did not exit: %v", err)
			}
			if err := <-result; err == nil || authority.commits.Load() != 1 || driver.handoffs.Load() != 0 || budget.Live() != 0 {
				t.Fatalf("late %s: err=%v commits=%d handoffs=%d charge=%d", stage, err, authority.commits.Load(), driver.handoffs.Load(), budget.Live())
			}
			authority.mu.Lock()
			committed := authority.owner != nil
			authority.mu.Unlock()
			if !committed {
				t.Fatal("fixture must retain durable effect despite receipt refusal")
			}
		})
	}
}

// TestRequestBudgetTerminalEarlierCallerDeadline retains a handler child's
// stricter allowance through reservation, mutation, proof and terminal send.
func TestRequestBudgetTerminalEarlierCallerDeadline(t *testing.T) {
	h, hc, authority, driver := terminalReviewConnection(t, AllowAllAuthorize)
	policy := h.cfg.terminalMethods[terminalReviewMethod]
	policy.ObservationTimeout = 5 * time.Millisecond
	h.cfg.terminalMethods[terminalReviewMethod] = policy
	h.cfg.requestBudget = func(string, string, []byte) (time.Duration, bool) { return 3 * time.Second, true }
	var callerDeadline time.Time
	authority.commit = func(ctx context.Context, tr TerminalTransition) error {
		if d, ok := ctx.Deadline(); !ok || !d.Before(callerDeadline) {
			t.Error("Commit did not preserve caller deadline and teardown tail")
		}
		authority.mu.Lock()
		authority.owner = &tr
		authority.mu.Unlock()
		return nil
	}
	driver.afterBegin = func(ctx context.Context, p *TerminalPermit) {
		if p.wallUntil.After(callerDeadline) || p.until > 200*time.Millisecond {
			t.Error("reservation extended earlier caller deadline")
		}
	}
	result := make(chan error, 1)
	h.cfg.handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
		child, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		callerDeadline, _ = child.Deadline()
		err := CompleteTerminalReceipt(child, "operation", 1)
		result <- err
		return nil, err
	}
	dispatchBudgetTerminal(t, h, hc)
	joinBudgetTerminal(t, hc)
	if err := <-result; err != nil || driver.handoffs.Load() != 1 {
		t.Fatalf("healthy earlier caller failed: %v", err)
	}
}
