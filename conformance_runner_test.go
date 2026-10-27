// Shared conformance runner — Go legs (pairings `go-pure`, `go-ffi`,
// `interop`).
//
// Exercises selected cases described in conformance/runner/scenarios.yaml
// with the pure-Go or production Rust FFI core. Recovery tests run separately.
// Interop compares executed Rust/Go decodes of shared corpus bytes; it does
// not establish a live cross-language connection.
package syntra

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type runnerRecordedTransport struct {
	Transport
	sent       [][]byte
	failSecond bool
}

func (r *runnerRecordedTransport) Send(_ context.Context, raw []byte) error {
	r.sent = append(r.sent, append([]byte(nil), raw...))
	if r.failSecond && len(r.sent) == 2 {
		return errors.New("second send failed")
	}
	return nil
}

func runnerDuplicateFaults(t *testing.T) *seededFaults {
	t.Helper()
	f := newSeededFaults(0x5EED1234)
	for i := 0; i < 100000; i++ {
		n := f.n
		drop := f.drop()
		if f.duplicate() && !drop {
			return &seededFaults{state: f.state, n: n}
		}
	}
	t.Fatal("seed did not reach duplicate branch")
	return nil
}

func TestRunnerFaultTransportOnlyDuplicatesRequestsAndResults(t *testing.T) {
	for _, frame := range []*Frame{
		NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1),
		NewNotificationFrame(1, &Notification{Payload: []byte("event")}),
	} {
		raw, err := MarshalFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		recorded := &runnerRecordedTransport{}
		ft := &faultTransport{Transport: recorded, faults: runnerDuplicateFaults(t)}
		if err := ft.Send(context.Background(), raw); err != nil {
			t.Fatal(err)
		}
		if len(recorded.sent) != 1 {
			t.Fatalf("non-RPC frame duplicated %d times", len(recorded.sent))
		}
	}
}

func TestRunnerFaultTransportDuplicateSendFailureVisible(t *testing.T) {
	raw, err := MarshalFrame(NewResultFrame(1, 7, NewSuccessResult([]byte("echo"))))
	if err != nil {
		t.Fatal(err)
	}
	recorded := &runnerRecordedTransport{failSecond: true}
	ft := &faultTransport{Transport: recorded, faults: runnerDuplicateFaults(t)}
	if err := ft.Send(context.Background(), raw); err == nil {
		t.Fatal("duplicate send failure hidden")
	}
}

// seededFaults is a deterministic xorshift64* PRNG (seed 0x5EED1234).
type seededFaults struct {
	state uint64
	n     uint64
}

func newSeededFaults(seed uint64) *seededFaults { return &seededFaults{state: seed} }

func (s *seededFaults) next() uint64 {
	x := s.state + s.n*0x9E3779B97F4A7C15
	s.n++
	x ^= x >> 12
	x ^= x << 25
	x ^= x >> 27
	return x * 0x2545F4914F6CDD1D
}

func (s *seededFaults) drop() bool      { return s.next()%64 == 0 }
func (s *seededFaults) duplicate() bool { return s.next()%128 == 0 }

// faultTransport wraps a Transport with deterministic send faults.
type faultTransport struct {
	Transport
	mu                sync.Mutex
	faults            *seededFaults
	drops             int
	requestDups       int
	resultDups        int
	notificationSends chan struct{}
}

func (f *faultTransport) Send(ctx context.Context, frame []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fr, err := UnmarshalFrame(frame)
	if err != nil {
		return err
	}
	kind := BodyKindOf(fr)
	if kind == BodyKindNotification && f.notificationSends != nil {
		defer func() { f.notificationSends <- struct{}{} }()
	}
	if f.faults.drop() {
		if kind == BodyKindNotification {
			f.drops++
			return nil
		}
	}
	if err := f.Transport.Send(ctx, frame); err != nil {
		return err
	}
	// Always consume the seeded draw; only request/result copies are delivered.
	if f.faults.duplicate() && (kind == BodyKindRequest || kind == BodyKindResult) {
		cp := append([]byte(nil), frame...)
		if err := f.Transport.Send(ctx, cp); err != nil {
			return err
		}
		if kind == BodyKindRequest {
			f.requestDups++
		} else {
			f.resultDups++
		}
	}
	return nil
}

func (f *faultTransport) counts() (drops, requests, results int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.drops, f.requestDups, f.resultDups
}

func runnerHostConfig(handler HandlerFunc) HostConfig {
	cfg := testHostConfig()
	if handler != nil {
		cfg.Handler = handler
	}
	return cfg
}

func TestRunnerEcho(t *testing.T) {
	p := newPair(t, testClientConfig(), runnerHostConfig(nil))
	defer p.Cleanup()
	for _, payload := range [][]byte{{}, []byte("hello"), make([]byte, 64<<10)} {
		got, err := p.client.Call(context.Background(), "/example.Echo/Echo", payload, 2000)
		if err != nil {
			t.Fatalf("echo: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("opaque bytes not preserved (%d vs %d)", len(got), len(payload))
		}
	}
}

func TestRunnerConcurrent16(t *testing.T) {
	p := newPair(t, testClientConfig(), runnerHostConfig(nil))
	defer p.Cleanup()
	var wg sync.WaitGroup
	errs := make([]error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			msg := []byte{byte(i), byte(i >> 8)}
			out, err := p.client.Call(context.Background(), "/example.Echo/Echo", msg, 5000)
			if err != nil {
				errs[i] = err
				return
			}
			if string(out) != string(msg) {
				errs[i] = errors.New("payload mismatch")
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
}

func TestRunnerEchoWithFaultInjection(t *testing.T) {
	// Seeded notification loss with a real echo. Separate tests below force
	// the PRNG's request/result duplicate branches with observable outcomes.
	a, b := LoopbackPair()
	clientFault := &faultTransport{Transport: b, faults: newSeededFaults(0x5EED1234)}
	hostFault := &faultTransport{Transport: a, faults: newSeededFaults(0x5EED1234), notificationSends: make(chan struct{}, 64)}
	cfg := testClientConfig()
	cfg.NotifyBuffer = 128
	c, err := OpenClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	h, err := OpenHost(runnerHostConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(ctx, clientFault) }()
	serveDone := make(chan error, 1)
	go func() { serveDone <- h.Serve(ctx, hostFault) }()
	t.Cleanup(func() {
		cancel()
		_ = a.Close()
		_ = b.Close()
		for _, done := range []chan error{runDone, serveDone} {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("fault pump did not stop")
			}
		}
	})
	warm, wcancel := context.WithTimeout(ctx, 3*time.Second)
	defer wcancel()
	if _, err := c.Call(warm, "/example.Echo/Echo", []byte("warmup"), 1000); err != nil {
		t.Fatalf("handshake not ready: %v", err)
	}
	for i := 0; i < 64; i++ {
		if err := h.NotifyAll([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 64; i++ {
		select {
		case <-hostFault.notificationSends:
		case <-ctx.Done():
			t.Fatal("notifications not sent")
		}
	}
	drops, _, _ := hostFault.counts()
	if drops == 0 {
		t.Fatal("no seeded notification drops")
	}
	for i := 0; i < 64-drops; i++ {
		select {
		case <-c.Notifications():
		case <-ctx.Done():
			t.Fatal("non-dropped notification missing")
		}
	}
	got, err := c.Call(ctx, "/example.Echo/Echo", []byte("hello-fault"), 2000)
	if err != nil {
		t.Fatalf("echo under faults: %v", err)
	}
	if string(got) != "hello-fault" {
		t.Fatalf("opaque bytes not preserved under faults: %q", got)
	}
	select {
	case extra := <-c.Notifications():
		t.Fatalf("extra notification after sent-minus-dropped count: %v", extra)
	default:
	}
	if c.DroppedNotifications() != 0 {
		t.Fatal("client overflow must not hide transport loss accounting")
	}
	t.Logf("seeded notification drops=%d, delivered=%d", drops, 64-drops)
}

func runnerSend(t *testing.T, ctx context.Context, transport Transport, frame *Frame) {
	t.Helper()
	raw, err := MarshalFrame(frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.Send(ctx, raw); err != nil {
		t.Fatal(err)
	}
}

func runnerRecv(t *testing.T, ctx context.Context, transport Transport) *Frame {
	t.Helper()
	raw, err := transport.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := UnmarshalFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestRunnerDuplicateRequestThroughTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	a, b := LoopbackPair()
	started, release := make(chan struct{}, 2), make(chan struct{})
	var dispatched atomic.Int32
	h, err := OpenHost(runnerHostConfig(func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		dispatched.Add(1)
		if string(req.GetPayload()) == "held" {
			started <- struct{}{}
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return NewSuccessResult(req.GetPayload()), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx, a) }()
	t.Cleanup(func() {
		cancel()
		_ = h.Close()
		_ = a.Close()
		_ = b.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("host pump did not stop")
		}
	})
	runnerSend(t, ctx, b, NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if runnerRecv(t, ctx, b).GetReady() == nil {
		t.Fatal("no ready")
	}
	ft := &faultTransport{Transport: b, faults: runnerDuplicateFaults(t)}
	runnerSend(t, ctx, ft, NewRequestFrame(1, 7, &RpcRequest{Method: "/example.Echo/Echo", Payload: []byte("held"), TimeoutMs: 4000}))
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("handler did not start")
	}
	rejected := runnerRecv(t, ctx, b)
	if rejected.GetRequestId() != 7 || rejected.GetResult().GetError().GetCode() != ErrorCodeFailedPrecondition {
		t.Fatalf("duplicate rejection = %v", rejected)
	}
	if dispatched.Load() != 1 {
		t.Fatal("duplicate request dispatched twice")
	}
	close(release)
	original := runnerRecv(t, ctx, b)
	if original.GetRequestId() != 7 || string(original.GetResult().GetPayload()) != "held" {
		t.Fatalf("original = %v", original)
	}
	runnerSend(t, ctx, b, NewRequestFrame(1, 8, &RpcRequest{Method: "/example.Echo/Echo", Payload: []byte("follow"), TimeoutMs: 4000}))
	follow := runnerRecv(t, ctx, b)
	if follow.GetRequestId() != 8 || string(follow.GetResult().GetPayload()) != "follow" {
		t.Fatalf("follow-up = %v", follow)
	}
	_, requests, results := ft.counts()
	if requests != 1 || results != 0 || dispatched.Load() != 2 {
		t.Fatalf("duplicates req=%d result=%d dispatch=%d", requests, results, dispatched.Load())
	}
	quiet, stop := context.WithTimeout(ctx, 20*time.Millisecond)
	defer stop()
	if raw, err := b.Recv(quiet); err == nil {
		t.Fatalf("extra terminal: %x", raw)
	}
}

func TestRunnerDuplicateResultThroughTransport(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	a, b := LoopbackPair()
	c, err := OpenClient(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, b) }()
	t.Cleanup(func() {
		cancel()
		_ = c.Close()
		_ = a.Close()
		_ = b.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("client pump did not stop")
		}
	})
	if runnerRecv(t, ctx, a).GetHello() == nil {
		t.Fatal("no hello")
	}
	runnerSend(t, ctx, a, NewReadyFrame(1, &ServerReady{ConnectionId: "runner-conn"}))
	type outcome struct {
		payload []byte
		err     error
	}
	call := func(payload string) <-chan outcome {
		ch := make(chan outcome, 1)
		go func() { p, err := c.Call(ctx, "/example.Echo/Echo", []byte(payload), 4000); ch <- outcome{p, err} }()
		return ch
	}
	first := call("first")
	req := runnerRecv(t, ctx, a)
	ft := &faultTransport{Transport: a, faults: runnerDuplicateFaults(t)}
	result := NewResultFrame(1, req.GetRequestId(), NewSuccessResult(req.GetRequest().GetPayload()))
	runnerSend(t, ctx, ft, result)
	select {
	case got := <-first:
		if got.err != nil || string(got.payload) != "first" {
			t.Fatalf("first = %v %q", got.err, got.payload)
		}
	case <-ctx.Done():
		t.Fatal("first result missing")
	}
	follow := call("follow")
	next := runnerRecv(t, ctx, a)
	if next.GetRequestId() == req.GetRequestId() {
		t.Fatal("request id reused")
	}
	runnerSend(t, ctx, a, result) // late duplicate while another call is pending
	runnerSend(t, ctx, a, NewNotificationFrame(1, &Notification{Payload: []byte("barrier")}))
	select {
	case <-c.Notifications():
	case <-ctx.Done():
		t.Fatal("pump barrier missing")
	}
	select {
	case got := <-follow:
		t.Fatalf("duplicate settled follow-up: %v", got)
	default:
	}
	c.mu.Lock()
	pending := len(c.waiters)
	c.mu.Unlock()
	if pending != 1 {
		t.Fatalf("pending waiters = %d", pending)
	}
	if _, ok := c.core.takeOutcome(req.GetRequestId()); ok {
		t.Fatal("duplicate retained a second outcome")
	}
	runnerSend(t, ctx, a, NewResultFrame(1, next.GetRequestId(), NewSuccessResult(next.GetRequest().GetPayload())))
	select {
	case got := <-follow:
		if got.err != nil || string(got.payload) != "follow" {
			t.Fatalf("follow-up = %v %q", got.err, got.payload)
		}
	case <-ctx.Done():
		t.Fatal("follow-up missing")
	}
	_, requests, results := ft.counts()
	if requests != 0 || results != 1 {
		t.Fatalf("duplicates req=%d result=%d", requests, results)
	}
	c.mu.Lock()
	pending = len(c.waiters)
	c.mu.Unlock()
	if pending != 0 {
		t.Fatalf("settled calls retained %d waiters", pending)
	}
}

func TestRunnerDuplicateResultDeduped(t *testing.T) {
	// A duplicated terminal result frame is delivered exactly once: the
	// client core ignores the second terminal for one request id and the
	// waiter observes a single outcome.
	cfg, err := resolveClientConfig(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	core, err := newClientCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	hello, err := core.helloFrame()
	if err != nil {
		t.Fatal(err)
	}
	ready, err := MarshalFrame(NewReadyFrame(1, &ServerReady{ConnectionId: "conn-1"}))
	if err != nil {
		t.Fatal(err)
	}
	_ = hello
	if _, err := core.activate(ready); err != nil {
		t.Fatal(err)
	}
	reqFrame, err := core.beginCall(77, "/example.Echo/Echo", []byte("dup-me"), 5000)
	if err != nil {
		t.Fatal(err)
	}
	_ = reqFrame
	resFrame, err := MarshalFrame(NewResultFrame(1, 77, NewSuccessResult([]byte("dup-me"))))
	if err != nil {
		t.Fatal(err)
	}
	terminal, _, fatal := core.onFrame(resFrame)
	if fatal != nil {
		t.Fatal(fatal)
	}
	if len(terminal) != 1 || terminal[0] != 77 {
		t.Fatalf("first result terminal = %v, want [77]", terminal)
	}
	dup, _, fatal := core.onFrame(append([]byte(nil), resFrame...))
	if fatal != nil {
		t.Fatal(fatal)
	}
	if len(dup) != 0 {
		t.Fatalf("duplicate result must be ignored, terminal = %v", dup)
	}
	res, ok := core.takeOutcome(77)
	if !ok || string(res.GetPayload()) != "dup-me" {
		t.Fatalf("outcome = %v %v", res, ok)
	}
	if _, ok := core.takeOutcome(77); ok {
		t.Fatal("duplicate result produced a second outcome")
	}
}

type stallSendTransport struct {
	Transport
	release chan struct{}
}

func (s *stallSendTransport) Send(ctx context.Context, frame []byte) error {
	// Stall request frames until release or ctx end (simulates a stalled
	// socket); handshake/ready already completed before wrapping.
	if fr, err := UnmarshalFrame(frame); err == nil && BodyKindOf(fr) == BodyKindRequest {
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Transport.Send(ctx, frame)
}

func TestRunnerCallBudgetBoundsStalledSend(t *testing.T) {
	// Stalled Send must respect the call budget (SNTR-RPC-004).
	c, err := OpenClient(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	a, b := LoopbackPair()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- c.Run(ctx, a) }()
	h, err := OpenHost(testHostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	serveDone := make(chan error, 1)
	go func() { serveDone <- h.Serve(ctx, b) }()
	warm, wcancel := context.WithTimeout(ctx, 3*time.Second)
	defer wcancel()
	if _, err := c.Call(warm, "/example.Echo/Echo", []byte("warmup"), 1000); err != nil {
		t.Fatalf("handshake not ready: %v", err)
	}
	// Wrap the client transport so the next request Send stalls.
	stalled, ok := c.transport.(*loopback)
	if !ok {
		t.Fatalf("client transport not loopback; cannot stall")
	}
	_ = stalled
	// Stall at the Transport level by replacing c.transport with a blocker.
	// c.transport is set during Run; swap it under lock for the test call.
	c.mu.Lock()
	orig := c.transport
	stall := &stallSendTransport{Transport: orig, release: make(chan struct{})}
	c.transport = stall
	c.mu.Unlock()
	defer func() {
		close(stall.release)
		c.mu.Lock()
		c.transport = orig
		c.mu.Unlock()
	}()
	start := time.Now()
	_, err = c.Call(context.Background(), "/example.Echo/Echo", []byte("x"), 100)
	if callCode(t, err) != ErrorCodeDeadlineExceeded {
		t.Fatalf("stalled send = %v, want DEADLINE_EXCEEDED", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("call budget not bounded: %v", elapsed)
	}
}

func TestRunnerNativeHostExpiryExactlyOnce(t *testing.T) {
	// Host expiry emits exactly one DEADLINE_EXCEEDED terminal result.
	cfg, err := resolveHostConfig(testHostConfig())
	if err != nil {
		t.Fatal(err)
	}
	core, err := newHostCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	hello, err := MarshalFrame(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.acceptHello(hello); err != nil {
		t.Fatal(err)
	}
	if _, err := core.authComplete("expiry-regression"); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalFrame(NewRequestFrame(1, 41, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, fatal := core.onFrame(raw); fatal != nil {
		t.Fatal(fatal)
	}
	time.Sleep(20 * time.Millisecond)
	ids := core.reapExpired(time.Now().Add(time.Hour))
	if len(ids) != 1 || ids[0] != 41 {
		t.Fatalf("reap = %v", ids)
	}
	// Exactly one terminal result queued.
	n := 0
	for {
		frame, ok := core.nextOutbound()
		if !ok {
			break
		}
		n++
		f, err := UnmarshalFrame(frame)
		if err != nil {
			t.Fatal(err)
		}
		if f.GetRequestId() != 41 || f.GetResult().GetError().GetCode() != ErrorCodeDeadlineExceeded {
			t.Fatalf("terminal = %v", f)
		}
	}
	if n != 1 {
		t.Fatalf("terminal results = %d, want exactly 1", n)
	}
	// Late answer reports expired without a second result: a late
	// result frame for the reaped id is tolerated with no new outbound,
	// and answering the reaped id reports unknown without emitting.
	late, err := MarshalFrame(NewResultFrame(1, 41, NewSuccessResult([]byte("late"))))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, fatal := core.onFrame(late); fatal != nil {
		// Native host rejects inbound result frames as invalid argument;
		// pure-Go tolerates them. Both mean no second result is emitted.
		if fatal.Code != ErrorCodeInvalidArgument {
			t.Fatalf("late result fatal = %v", fatal)
		}
	}
	if frame, ok := core.nextOutbound(); ok {
		t.Fatalf("late answer emitted second result: %v", frame)
	}
	if _, expired, err := core.answer(41, NewSuccessResult([]byte("late"))); err == nil && !expired {
		t.Fatal("late answer for reaped id accepted")
	}
	if frame, ok := core.nextOutbound(); ok {
		t.Fatalf("late answer emitted second result: %v", frame)
	}
}

func TestRunnerOversizeHandlerResultBounded(t *testing.T) {
	cfg := testHostConfig()
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		if string(req.GetPayload()) == "trigger-huge" {
			return NewSuccessResult(make([]byte, 2<<20)), nil
		}
		return echoHandler(ctx, req)
	}
	p := newPair(t, testClientConfig(), cfg)
	defer p.Cleanup()
	_, err := p.client.Call(context.Background(), "/example.Echo/Echo", []byte("trigger-huge"), 2000)
	if callCode(t, err) != ErrorCodeResourceExhausted {
		t.Fatalf("oversize handler = %v", err)
	}
	out, err := p.client.Call(context.Background(), "/example.Echo/Echo", []byte("ok"), 2000)
	if err != nil || string(out) != "ok" {
		t.Fatalf("usable after bounded failure: %v %q", err, out)
	}
}

func TestRunnerCloseAfterCompletedEcho(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	out, err := p.client.Call(context.Background(), "/example.Echo/Echo", []byte("before"), 1000)
	if err != nil || string(out) != "before" {
		t.Fatalf("pre-close: %v %q", err, out)
	}
	if err := p.host.Close(); err != nil {
		t.Fatal(err)
	}
	// Repeated Close and Serve on the closed Host fail fast.
	if err := p.host.Close(); callCode(t, err) != ErrorCodeFailedPrecondition {
		t.Fatalf("second Close = %v, want FAILED_PRECONDITION", err)
	}
	a, b := LoopbackPair()
	defer a.Close()
	defer b.Close()
	if err := p.host.Serve(context.Background(), a); callCode(t, err) != ErrorCodeFailedPrecondition {
		t.Fatalf("Serve after Close = %v, want FAILED_PRECONDITION", err)
	}
	// No queued result is held during close in this test.
	select {
	case err := <-p.serveErr:
		if err != nil {
			t.Fatalf("Serve after graceful drain = %v", err)
		}
		p.serveErr <- err
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not exit after graceful close")
	}
}

func TestRunnerFaultInjectionDeterministic(t *testing.T) {
	faults := newSeededFaults(0x5EED1234)
	drops := 0
	for i := 0; i < 64; i++ {
		if faults.drop() {
			drops++
		}
		_ = faults.duplicate()
	}
	if drops == 0 || drops > 8 {
		t.Fatalf("seeded drop count out of range: %d", drops)
	}
	// Same seed replays identically.
	f2 := newSeededFaults(0x5EED1234)
	drops2 := 0
	for i := 0; i < 64; i++ {
		if f2.drop() {
			drops2++
		}
		_ = f2.duplicate()
	}
	if drops != drops2 {
		t.Fatalf("nondeterministic faults: %d vs %d", drops, drops2)
	}
}

func TestRunnerWireInteropGolden(t *testing.T) {
	text, err := os.ReadFile("conformance/test-vectors/protobuf/vectors.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"GOLD-PROT-HELLO-01", "GOLD-PROT-REQ-01"} {
		selected := false
		var hexes []string
		for _, line := range strings.Split(string(text), "\n") {
			if strings.HasPrefix(line, "  - id: ") {
				selected = line == "  - id: "+id
			}
			if selected && strings.HasPrefix(line, "    frame_hex: ") {
				hexes = append(hexes, strings.Trim(strings.TrimPrefix(line, "    frame_hex: "), "\""))
			}
		}
		if len(hexes) != 1 {
			t.Fatalf("expected one corpus hex for %s, got %d", id, len(hexes))
		}
		f, err := UnmarshalFrame(mustHex(t, hexes[0]))
		if err != nil {
			t.Fatal(err)
		}
		sem := map[string]any{"version": f.GetVersion(), "request_id": f.GetRequestId()}
		if id == "GOLD-PROT-HELLO-01" {
			h := f.GetHello()
			if h == nil || f.GetVersion() != 1 || f.GetRequestId() != 0 || h.GetMinVersion() != 1 || h.GetMaxVersion() != 1 || string(h.GetCredential()) != "opaque-test-credential-A" {
				t.Fatalf("hello = %v", f)
			}
			sem["body"], sem["min_version"], sem["max_version"], sem["credential"] = "hello", h.GetMinVersion(), h.GetMaxVersion(), string(h.GetCredential())
		} else {
			r := f.GetRequest()
			if r == nil || f.GetVersion() != 1 || f.GetRequestId() != 7 || r.GetMethod() != "/example.Echo/Echo" || string(r.GetPayload()) != "hello" || r.GetTimeoutMs() != 500 {
				t.Fatalf("request = %v", f)
			}
			sem["body"], sem["method"], sem["payload"], sem["timeout_ms"] = "request", r.GetMethod(), string(r.GetPayload()), r.GetTimeoutMs()
		}
		record, err := json.Marshal(map[string]any{"id": id, "frame_hex": hexes[0], "semantic_fields": sem})
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("CORPUS %s", record)
	}
	// Error-code normalization (SNTR-ERR-005): unknown codes map to UNKNOWN.
	if got := NormalizeErrorCode(99); got != ErrorCodeUnknown {
		t.Fatalf("normalize(99) = %v", got)
	}
}
