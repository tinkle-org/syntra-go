// File request_budget_test.go pins receipt-origin budgets before authorization.
package syntra

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/proto"
)

// requestBudgetFaultClock injects discontinuity and observes original receipt
// sampling without exposing mutable timing state through the SDK accessor.
type requestBudgetFaultClock struct {
	terminalReviewClock
	failed         atomic.Bool
	samples        atomic.Int32
	second         chan struct{}
	receiptPending atomic.Bool
}

// Check reports a sticky fixture continuity failure.
func (c *requestBudgetFaultClock) Check() error {
	if c.failed.Load() {
		return context.DeadlineExceeded
	}
	return nil
}

// Age signals only driver receipt samples, not checks of remaining time. It
// samples before signaling so a simulated suspend cannot alter this origin.
func (c *requestBudgetFaultClock) Age() time.Duration {
	age := c.terminalReviewClock.Age()
	if c.receiptPending.Swap(false) && c.samples.Add(1) == 2 && c.second != nil {
		close(c.second)
	}
	return age
}

// requestBudgetClockDriver supplies an injectable original clock on a full driver.
type requestBudgetClockDriver struct {
	terminalReviewDriver
	origin TerminalClock
}

// TerminalClock returns the fixture's trusted original clock.
func (d *requestBudgetClockDriver) TerminalClock() TerminalClock {
	if clock, ok := d.origin.(*requestBudgetFaultClock); ok {
		clock.receiptPending.Store(true)
	}
	return d.origin
}

// TerminalReceiptDriver retains this wrapper as the exact coordinated owner.
func (d *requestBudgetClockDriver) TerminalReceiptDriver() TerminalReceiptDriver { return d }

// TestRequestBudgetPreauthorization bounds initial authority work even when the
// peer requests 120 seconds; it must not start a fresh budget at handler entry.
func TestRequestBudgetPreauthorization(t *testing.T) {
	cfg := testHostConfig()
	cfg.MaxTimeout = 120 * time.Second
	cfg.RequestBudget = func(string, string, []byte) (time.Duration, bool) { return 50 * time.Millisecond, true }
	seen := make(chan time.Duration, 1)
	cfg.Authorize = func(ctx context.Context, _, _ string) error {
		deadline, _ := ctx.Deadline()
		seen <- time.Until(deadline)
		return nil
	}
	p := newRawSessionPeer(t, cfg, nil)
	p.send(t, NewRequestFrame(1, 1, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 120000}))
	remaining := <-seen
	if remaining <= 0 || remaining > 50*time.Millisecond {
		t.Fatalf("initial authorization got %v; host cap must apply before it", remaining)
	}
	_ = p.recv(t)
}

// TestRequestBudgetSelectionAndCoreCoherence checks caps against each earlier
// source and proves a late successful callback cannot bypass core selection.
func TestRequestBudgetSelectionAndCoreCoherence(t *testing.T) {
	for _, test := range []struct {
		name     string
		cap      time.Duration
		selected bool
		wire     uint32
		want     time.Duration
		parent   time.Duration
	}{
		{"shorter", 400 * time.Millisecond, true, 120000, 400 * time.Millisecond, 0},
		{"larger", 2 * time.Second, true, 700, 700 * time.Millisecond, 0},
		{"maximum-duration", time.Duration(math.MaxInt64), true, 700, 700 * time.Millisecond, 0},
		{"no-override", 0, false, 700, 700 * time.Millisecond, 0},
		{"unselected-negative", -1, false, 700, 700 * time.Millisecond, 0},
		{"default", 2 * time.Second, true, 0, 900 * time.Millisecond, 0},
		{"max-timeout", 2 * time.Second, true, 120000, time.Second, 0},
		{"parent", time.Second, true, 120000, 500 * time.Millisecond, 500 * time.Millisecond},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := testHostConfig()
			cfg.DefaultTimeout, cfg.MaxTimeout = 900*time.Millisecond, time.Second
			var h *Host
			var hc *hostConn
			cfg.RequestBudget = func(principal, method string, payload []byte) (time.Duration, bool) {
				if principal != "alice" || method != "/example.Echo/Echo" || string(payload) != "opaque" {
					t.Errorf("selector inputs: %q %q %q", principal, method, payload)
				}
				// Both mutexes must be available during application selection.
				h.mu.Lock()
				closed := h.closed
				h.mu.Unlock()
				if closed {
					t.Error("host closed during request budget selection")
				}
				_, _ = hc.core.callDeadline(1)
				return test.cap, test.selected
			}
			seen := make(chan RequestBudget, 1)
			release := make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			cfg.Authorize = func(ctx context.Context, _, _ string) error {
				b, ok := RequestBudgetFromContext(ctx)
				d, _ := ctx.Deadline()
				coreDeadline, pending := hc.core.callDeadline(1)
				if !ok || !pending || !coreDeadline.Equal(d) || !b.Deadline().Equal(d) {
					t.Error("core, authorization and SDK budgets disagree")
				}
				seen <- b
				<-release
				return nil
			}
			h, hc, _ = newWithdrawalReviewConnection(t, cfg)
			receipt := time.Now()
			parent := context.Background()
			if test.parent != 0 {
				var stop context.CancelFunc
				parent, stop = context.WithDeadline(parent, receipt.Add(test.parent))
				defer stop()
			}
			request := &RpcRequest{Method: "/example.Echo/Echo", Payload: []byte("opaque"), TimeoutMs: test.wire}
			_, _, fatal := hc.core.onFrameAt(mustMarshal(NewRequestFrame(1, 1, request)), receipt)
			if fatal != nil {
				t.Fatal(fatal)
			}
			id, req, _ := hc.core.takePending()
			if err := h.dispatch(parent, hc.transport, hc, id, req); err != nil {
				t.Fatal(err)
			}
			b := <-seen
			if got := b.Deadline().Sub(receipt); got != test.want {
				t.Fatalf("selected duration=%v want=%v", got, test.want)
			}
			// Ignore the callback's context entirely: core alone must expire.
			expired := hc.core.reapExpired(b.Deadline())
			if len(expired) != 1 || expired[0] != id {
				t.Fatalf("selected core deadline did not expire: %v", expired)
			}
			raw, ok := hc.core.nextOutbound()
			if !ok {
				t.Fatal("missing core deadline result")
			}
			f, _ := UnmarshalFrame(raw)
			assertTerminalCode(t, f, id, ErrorCodeDeadlineExceeded)
			h.cancelHandlers(hc, expired, false)
			once.Do(func() { close(release) })
			<-hc.completed
			hc.workers--
		})
	}
}

// TestRequestBudgetZeroAndInvalidSkipAuthorization exercises immediate expiry
// and a wrapped duration without permitting any authorization or handler effect.
func TestRequestBudgetZeroAndInvalidSkipAuthorization(t *testing.T) {
	for _, cap := range []time.Duration{0, -1, time.Duration(math.MinInt64)} {
		t.Run(cap.String(), func(t *testing.T) {
			var authorizations, handlers atomic.Int32
			cfg := testHostConfig()
			cfg.RequestBudget = func(string, string, []byte) (time.Duration, bool) { return cap, true }
			cfg.Authorize = func(context.Context, string, string) error { authorizations.Add(1); return nil }
			cfg.Handler = func(context.Context, *RpcRequest) (*RpcResult, error) {
				handlers.Add(1)
				return NewSuccessResult(nil), nil
			}
			p := newRawSessionPeer(t, cfg, nil)
			p.request(t, 1, "/example.Echo/Echo")
			assertTerminalCode(t, p.recv(t), 1, ErrorCodeDeadlineExceeded)
			if authorizations.Load() != 0 || handlers.Load() != 0 {
				t.Fatal("expired cap started application work")
			}
		})
	}
}

// TestRequestBudgetQueueAndSelectorTime ensures neither queued frames nor time
// spent selecting a cap receive a fresh allowance. Both keep receipt-origin D.
func TestRequestBudgetQueueAndSelectorTime(t *testing.T) {
	for _, delay := range []string{"queue", "selector"} {
		t.Run(delay, func(t *testing.T) {
			cfg := testHostConfig()
			var calls atomic.Int32
			cfg.RequestBudget = func(string, string, []byte) (time.Duration, bool) {
				if delay == "selector" {
					time.Sleep(30 * time.Millisecond)
				}
				return 20 * time.Millisecond, true
			}
			cfg.Authorize = func(context.Context, string, string) error { calls.Add(1); return nil }
			h, hc, ctx := newWithdrawalReviewConnection(t, cfg)
			probe := newWriterProbe()
			close(probe.release)
			hc.writer = newHostWriter(probe, time.Second)
			t.Cleanup(func() { _ = hc.writer.shutdown() })
			received := time.Now()
			if delay == "queue" {
				received = received.Add(-30 * time.Millisecond)
			}
			hc.core.onFrameAt(mustMarshal(NewRequestFrame(1, 1, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 120000})), received)
			id, req, _ := hc.core.takePending()
			if err := h.dispatch(ctx, probe, hc, id, req); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 0 || hc.workers != 0 {
				t.Fatal("queue/selector time was renewed before authorization")
			}
			select {
			case raw := <-probe.sent:
				f, _ := UnmarshalFrame(raw)
				assertTerminalCode(t, f, 1, ErrorCodeDeadlineExceeded)
			case <-time.After(time.Second):
				t.Fatal("missing expiry result")
			}
		})
	}
}

// TestRequestBudgetNoncooperativeAuthorizationRetainsCharge isolates concurrent
// calls and keeps expired external work charged without allowing late effects.
func TestRequestBudgetNoncooperativeAuthorizationRetainsCharge(t *testing.T) {
	for _, test := range []struct {
		name string
		cap  time.Duration
		peer uint32
	}{
		{"host-shorter-than-120s-peer", 40 * time.Millisecond, 120000},
		{"peer-shorter-than-host", 3 * time.Second, 40},
	} {
		t.Run(test.name, func(t *testing.T) { checkBudgetNoncooperativeAuthorization(t, test.cap, test.peer) })
	}
}

// checkBudgetNoncooperativeAuthorization waits past the selected host/peer cap
// while retaining the authorizer and proving a second request remains isolated.
func checkBudgetNoncooperativeAuthorization(t *testing.T, cap time.Duration, peer uint32) {
	t.Helper()
	cfg := testHostConfig()
	cfg.MaxTimeout = 120 * time.Second
	budget, err := NewExecutionBudget(4)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ExecutionBudget = budget
	cfg.RequestBudget = func(_, method string, _ []byte) (time.Duration, bool) {
		return cap, method == "/example.Auth/Hold"
	}
	entered, release := make(chan context.Context, 1), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var effects atomic.Int32
	cfg.Authorize = func(ctx context.Context, _, method string) error {
		if method == "/example.Auth/Hold" {
			entered <- ctx
			<-release // deliberately ignores cancellation
		}
		return nil
	}
	cfg.Handler = func(context.Context, *RpcRequest) (*RpcResult, error) {
		effects.Add(1)
		return NewSuccessResult(nil), nil
	}
	p := newRawSessionPeer(t, cfg, nil)
	p.send(t, NewRequestFrame(1, 1, &RpcRequest{Method: "/example.Auth/Hold", TimeoutMs: peer}))
	authCtx := <-entered
	assertTerminalCode(t, p.recv(t), 1, ErrorCodeDeadlineExceeded)
	if authCtx.Err() == nil || budget.Live() != 1 {
		t.Fatalf("noncooperative auth: ctx=%v charge=%d", authCtx.Err(), budget.Live())
	}
	p.request(t, 2, "/example.Echo/Echo")
	if f := p.recv(t); f.GetRequestId() != 2 || !validSuccess(f.GetResult()) {
		t.Fatalf("unrelated method inherited cap: %v", f)
	}
	once.Do(func() { close(release) })
	deadline := time.After(time.Second)
	for budget.Live() != 0 {
		select {
		case <-deadline:
			t.Fatal("authorization charge not released after return")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if effects.Load() != 1 {
		t.Fatal("late authorizer started expired handler")
	}
	ctx, stop := context.WithTimeout(p.ctx, 30*time.Millisecond)
	defer stop()
	if _, err := p.peer.Recv(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late duplicate output or close: %v", err)
	}
}

// TestRequestBudgetRecoveryAndValidationPreserved ensures malformed methods and
// built-in recovery bypass the application selector but retain authorization.
func TestRequestBudgetRecoveryAndValidationPreserved(t *testing.T) {
	service, err := NewRecoveryService(newRecoveryTestSource(), DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	var selected, authorized atomic.Int32
	cfg := testHostConfig()
	cfg.Policy = StaticPolicy("alice", true)
	cfg.Recovery = service
	cfg.RequestBudget = func(string, string, []byte) (time.Duration, bool) { selected.Add(1); return 0, true }
	cfg.Authorize = func(ctx context.Context, _, _ string) error {
		authorized.Add(1)
		if b, ok := RequestBudgetFromContext(ctx); !ok || b.Err() != nil {
			t.Error("recovery authorization lost SDK budget")
		}
		return nil
	}
	cfg.Handler = func(context.Context, *RpcRequest) (*RpcResult, error) {
		t.Error("application handler intercepted built-in recovery")
		return NewSuccessResult(nil), nil
	}
	p := newRawSessionPeer(t, cfg, nil)
	raw, err := proto.Marshal(NewRequestFrame(1, 1, &RpcRequest{Method: "malformed", TimeoutMs: 120000}))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.peer.Send(p.ctx, raw); err != nil {
		t.Fatal(err)
	}
	assertTerminalCode(t, p.recv(t), 1, ErrorCodeInvalidArgument)
	if selected.Load() != 0 || authorized.Load() != 0 {
		t.Fatal("selector or authorization preceded method bounds")
	}
	runtimeRecoveryRPC(t, p, 2, RecoveryNegotiate, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: RecoveryCapability}, new(pb.RecoveryNegotiateResponse))
	if selected.Load() != 0 || authorized.Load() != 1 {
		t.Fatalf("built-in recovery: selectors=%d authorizations=%d", selected.Load(), authorized.Load())
	}
}

// TestRequestBudgetExpiredReceiptSkipsSelector rejects exhausted or invalid
// original timing before application policy can run, even if it offers more time.
func TestRequestBudgetExpiredReceiptSkipsSelector(t *testing.T) {
	for _, fault := range []string{"wall", "elapsed", "discontinuity", "overflow", "parent"} {
		t.Run(fault, func(t *testing.T) {
			now := time.Now()
			clock := &requestBudgetFaultClock{}
			receipt := requestReceipt{at: now.Add(-time.Second), clock: clock}
			deadline := receipt.at.Add(2 * time.Second)
			ctx := context.Background()
			switch fault {
			case "wall":
				deadline = receipt.at.Add(time.Second)
			case "elapsed":
				clock.elapsed.Store(int64(2 * time.Second))
			case "discontinuity":
				clock.failed.Store(true)
			case "overflow":
				receipt.age = math.MaxInt64 - 1
				clock.elapsed.Store(int64(receipt.age))
			case "parent":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, now.Add(-time.Millisecond))
				defer cancel()
			}
			var selected int
			b := selectRequestBudget(receipt, deadline, ctx, func(string, string, []byte) (time.Duration, bool) {
				selected++
				return time.Hour, true
			}, "alice", &RpcRequest{Method: "/example.Echo/Echo"})
			if selected != 0 || b.Err() == nil {
				t.Fatalf("original %s expiry ran selector or regained time: calls=%d err=%v", fault, selected, b.Err())
			}
		})
	}
}

// TestRequestBudgetRecoveryRetainsTrustedOrigin skips the application cap for
// the whole reserved prefix while retaining the original trusted elapsed limit.
func TestRequestBudgetRecoveryRetainsTrustedOrigin(t *testing.T) {
	clock := &terminalReviewClock{}
	receipt := requestReceipt{at: time.Now(), clock: clock, age: time.Second}
	clock.elapsed.Store(int64(1500 * time.Millisecond))
	deadline := receipt.at.Add(time.Second)
	for _, method := range []string{RecoveryNegotiate, RecoverySubscribe, RecoveryMethodPrefix + "Unknown"} {
		b := selectRequestBudget(receipt, deadline, context.Background(), func(string, string, []byte) (time.Duration, bool) {
			t.Error("built-in recovery invoked application selector")
			return 0, true
		}, "alice", &RpcRequest{Method: method})
		if !b.Deadline().Equal(deadline) || b.until != 2*time.Second || b.Err() != nil || b.Remaining() > 500*time.Millisecond {
			t.Fatalf("recovery lost original budget: deadline=%v until=%v remaining=%v", b.Deadline(), b.until, b.Remaining())
		}
		clock.elapsed.Store(int64(2 * time.Second))
		if b.Err() == nil {
			t.Fatal("recovery skipped trusted elapsed enforcement")
		}
		clock.elapsed.Store(int64(1500 * time.Millisecond))
	}
}

// TestRequestBudgetAccessorAndElapsedArithmetic checks safe adapter access,
// absent scope, clock discontinuity, and overflow near the elapsed clock limit.
func TestRequestBudgetAccessorAndElapsedArithmetic(t *testing.T) {
	if _, ok := RequestBudgetFromContext(context.Background()); ok {
		t.Fatal("ordinary context manufactured SDK timing")
	}
	if (RequestBudget{}).Remaining() != 0 || (RequestBudget{}).Err() == nil {
		t.Fatal("zero budget grants time")
	}
	clock := &terminalReviewClock{}
	now := time.Now()
	receipt := requestReceipt{at: now, clock: clock}
	b := selectRequestBudget(receipt, now.Add(3*time.Second), context.Background(), nil, "alice", nil)
	clock.elapsed.Store(int64(2500 * time.Millisecond))
	if left := b.Remaining(); left <= 0 || left > 500*time.Millisecond {
		t.Fatalf("suspend not included in adapter remaining budget: %v", left)
	}
	clock.elapsed.Store(int64(4 * time.Second))
	if b.Err() == nil {
		t.Fatal("elapsed expiry not reported")
	}
	receipt.age = time.Duration(math.MaxInt64) - time.Second
	b = selectRequestBudget(receipt, now.Add(3*time.Second), context.Background(), nil, "alice", nil)
	if b.Err() == nil {
		t.Fatal("elapsed addition overflow granted time")
	}
}

// TestRequestBudgetNoOverrideAndLongCapKeepElapsedDeadline verifies that nil,
// false and nonextending caps retain both original timing domains. In particular,
// a maximum positive cap must not overflow when the effective peer budget fits.
func TestRequestBudgetNoOverrideAndLongCapKeepElapsedDeadline(t *testing.T) {
	for _, name := range []string{"nil", "false", "long", "maximum-positive"} {
		t.Run(name, func(t *testing.T) {
			clock := &terminalReviewClock{}
			receipt := requestReceipt{at: time.Now(), clock: clock, age: 100 * time.Second}
			clock.elapsed.Store(int64(100*time.Second + 500*time.Millisecond))
			deadline := receipt.at.Add(2 * time.Second)
			var choose RequestBudgetFunc
			if name != "nil" {
				choose = func(string, string, []byte) (time.Duration, bool) {
					switch name {
					case "false":
						return time.Duration(math.MinInt64), false
					case "long":
						return time.Hour, true
					default:
						return time.Duration(math.MaxInt64), true
					}
				}
			}
			b := selectRequestBudget(receipt, deadline, context.Background(), choose, "alice", &RpcRequest{Method: "/example.Echo/Echo"})
			if !b.Deadline().Equal(deadline) || b.until != 102*time.Second || b.Remaining() != 1500*time.Millisecond {
				t.Fatalf("nonextending cap changed original timing: deadline=%v until=%v remaining=%v", b.Deadline(), b.until, b.Remaining())
			}
		})
	}
}

// TestRequestBudgetReceiveQueueCapturesClockBeforeDispatch holds only a test
// selector while another complete frame queues, then simulates host suspension.
// Both requests must retain their pre-suspend receipt ages, not dispatch ages.
func TestRequestBudgetReceiveQueueCapturesClockBeforeDispatch(t *testing.T) {
	t.Run("original-live", func(t *testing.T) { checkBudgetReceiveQueue(t, 2*time.Second, 2) })
	t.Run("original-expired", func(t *testing.T) { checkBudgetReceiveQueue(t, 6*time.Second, 1) })
}

// checkBudgetReceiveQueue distinguishes expiry under an application cap from
// original peer expiry, which must skip the queued request's application selector.
func checkBudgetReceiveQueue(t *testing.T, elapsed time.Duration, wantSelected int32) {
	t.Helper()
	clock := &requestBudgetFaultClock{second: make(chan struct{})}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	var selected, authorized atomic.Int32
	cfg := testHostConfig()
	cfg.RequestBudget = func(string, string, []byte) (time.Duration, bool) {
		if selected.Add(1) == 1 {
			close(entered)
			<-release
		}
		return time.Second, true
	}
	cfg.Authorize = func(context.Context, string, string) error { authorized.Add(1); return nil }
	p := newRawSessionPeer(t, cfg, func(tr Transport) Transport {
		return &requestBudgetClockDriver{terminalReviewDriver: terminalReviewDriver{Transport: tr}, origin: clock}
	})
	p.request(t, 1, "/example.Echo/Echo")
	hostWriterSignal(t, entered, "selector entry")
	p.request(t, 2, "/example.Echo/Echo")
	hostWriterSignal(t, clock.second, "second frame original receipt sample")
	clock.elapsed.Store(int64(elapsed))
	once.Do(func() { close(release) })
	assertTerminalCode(t, p.recv(t), 1, ErrorCodeDeadlineExceeded)
	assertTerminalCode(t, p.recv(t), 2, ErrorCodeDeadlineExceeded)
	if selected.Load() != wantSelected || authorized.Load() != 0 {
		t.Fatalf("queue renewed timing: selectors=%d authorizers=%d", selected.Load(), authorized.Load())
	}
}

// TestRequestBudgetClockFailureBeforeAuthorization rejects discontinuity,
// negative ages, elapsed overflow, and regression before any authority effect.
func TestRequestBudgetClockFailureBeforeAuthorization(t *testing.T) {
	for _, fault := range []string{"discontinuity", "negative-age", "overflow", "regression"} {
		t.Run(fault, func(t *testing.T) {
			clock := &requestBudgetFaultClock{}
			switch fault {
			case "discontinuity":
				clock.failed.Store(true)
			case "negative-age":
				clock.elapsed.Store(-1)
			case "overflow":
				clock.elapsed.Store(math.MaxInt64 - 1)
			case "regression":
				clock.elapsed.Store(int64(time.Second))
			}
			var authorized atomic.Int32
			cfg := testHostConfig()
			cfg.RequestBudget = func(string, string, []byte) (time.Duration, bool) {
				if fault == "regression" {
					clock.elapsed.Store(0)
				}
				return time.Second, true
			}
			cfg.Authorize = func(context.Context, string, string) error { authorized.Add(1); return nil }
			p := newRawSessionPeer(t, cfg, func(tr Transport) Transport {
				return &requestBudgetClockDriver{terminalReviewDriver: terminalReviewDriver{Transport: tr}, origin: clock}
			})
			p.request(t, 1, "/example.Echo/Echo")
			assertTerminalCode(t, p.recv(t), 1, ErrorCodeDeadlineExceeded)
			if authorized.Load() != 0 {
				t.Fatal("invalid elapsed origin reached authorization")
			}
		})
	}
}

// TestRequestBudgetLateHandlerCannotBeatCoreSelection returns a valid success
// after trusted elapsed expiry, without waiting for a reap or context timer.
func TestRequestBudgetLateHandlerCannotBeatCoreSelection(t *testing.T) {
	clock := &terminalReviewClock{}
	cfg := testHostConfig()
	cfg.RequestBudget = func(string, string, []byte) (time.Duration, bool) { return time.Second, true }
	cfg.Handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
		clock.elapsed.Store(int64(2 * time.Second))
		return NewSuccessResult([]byte("late")), nil
	}
	p := newRawSessionPeer(t, cfg, func(tr Transport) Transport {
		return &terminalReviewDriver{Transport: tr, clock: clock}
	})
	p.request(t, 1, "/example.Echo/Echo")
	assertTerminalCode(t, p.recv(t), 1, ErrorCodeDeadlineExceeded)
}

// TestRequestBudgetRetainsEarlierTerminalSelection preserves an outcome already
// selected before cancellation or later budget exhaustion, independent of ticks.
func TestRequestBudgetRetainsEarlierTerminalSelection(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "success-first", true: "cancel-first"}[cancelled], func(t *testing.T) {
			_, hc, _ := newWithdrawalReviewConnection(t, testHostConfig())
			req := &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 120000}
			hc.core.onFrame(mustMarshal(NewRequestFrame(1, 1, req)))
			hc.core.takePending()
			receipt, deadline, _ := hc.core.callReceipt(1)
			b := selectRequestBudget(receipt, deadline, context.Background(), nil, "alice", req)
			hc.core.setRequestBudget(1, b)
			if cancelled {
				hc.core.onFrame(mustMarshal(NewCancelFrame(1, 1)))
			} else {
				hc.core.selectResult(1, NewSuccessResult([]byte("first")))
			}
			expired := selectRequestBudget(receipt, deadline, context.Background(), func(string, string, []byte) (time.Duration, bool) { return 0, true }, "alice", req)
			hc.core.setRequestBudget(1, expired)
			hc.core.onFrame(mustMarshal(NewCancelFrame(1, 1)))
			raw, _, err := hc.core.answer(1, NewSuccessResult([]byte("late")))
			if err != nil {
				t.Fatal(err)
			}
			f, _ := UnmarshalFrame(raw)
			if cancelled {
				assertTerminalCode(t, f, 1, ErrorCodeCancelled)
			} else if !validSuccess(f.GetResult()) || string(f.GetResult().GetPayload()) != "first" {
				t.Fatalf("earlier selected result overwritten: %v", f)
			}
		})
	}
}

// TestRequestBudgetDefaultAuthorizationRemainsDenyAll proves a selector grants
// no authority and that leaving it nil preserves an ordinary successful request.
func TestRequestBudgetDefaultAuthorizationRemainsDenyAll(t *testing.T) {
	cfg := testHostConfig()
	cfg.RequestBudget = func(string, string, []byte) (time.Duration, bool) { return time.Second, true }
	cfg.Authorize = nil
	p := newRawSessionPeer(t, cfg, nil)
	p.request(t, 1, "/example.Echo/Echo")
	assertTerminalCode(t, p.recv(t), 1, ErrorCodePermissionDenied)
	cfg.Authorize, cfg.RequestBudget = AllowAllAuthorize, nil
	q := newRawSessionPeer(t, cfg, nil)
	q.request(t, 1, "/example.Echo/Echo")
	if f := q.recv(t); !validSuccess(f.GetResult()) {
		t.Fatalf("unconfigured budget changed ordinary success: %v", f)
	}
}

// TestRequestBudgetReceiptClockBeforeAuthorization prevents suspend time spent
// inside initial authorization from being renewed at terminal reservation.
func TestRequestBudgetReceiptClockBeforeAuthorization(t *testing.T) {
	clock := &terminalReviewClock{}
	authority := &terminalReviewAuthority{}
	var effects atomic.Int32
	cfg := testHostConfig()
	cfg.MaxTimeout = 120 * time.Second
	cfg.Authorize = func(context.Context, string, string) error {
		clock.elapsed.Store(int64(121 * time.Second))
		return nil
	}
	cfg.TerminalMethods = map[string]TerminalMethodPolicy{terminalReviewMethod: {SuccessPayload: []byte("retired"), Authority: authority, ObservationTimeout: time.Millisecond}}
	cfg.Handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
		effects.Add(1)
		return nil, CompleteTerminalReceipt(ctx, "operation", 1)
	}
	p := newRawSessionPeer(t, cfg, func(tr Transport) Transport {
		return &terminalReviewDriver{Transport: tr, clock: clock}
	})
	p.send(t, NewRequestFrame(1, 1, &RpcRequest{Method: terminalReviewMethod, TimeoutMs: 120000}))
	deadline := time.After(time.Second)
	for p.host.cfg.executions.Live() != 0 {
		select {
		case <-deadline:
			t.Fatal("authorization did not return")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	// Receiving either a result or close joins the dispatch decision.
	_, _ = p.peer.Recv(p.ctx)
	if effects.Load() != 0 || authority.commits.Load() != 0 {
		t.Fatalf("suspend renewed request: handlers=%d commits=%d", effects.Load(), authority.commits.Load())
	}
}
