package syntra

import (
	"context"
	"sync"
	"testing"
	"time"
)

func alignmentClient(t *testing.T, cfg ClientConfig, wrap func(Transport) Transport) (*Client, Transport, context.Context) {
	t.Helper()
	c, err := OpenClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, peer := LoopbackPair()
	if wrap != nil {
		a = wrap(a)
	}
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, a) }()
	t.Cleanup(func() {
		stop()
		_ = c.Close()
		_ = peer.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("client did not stop")
		}
	})
	if _, err := peer.Recv(ctx); err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalFrame(NewReadyFrame(1, &ServerReady{ConnectionId: "alignment"}))
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Send(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if err := c.WaitReady(ctx); err != nil {
		t.Fatal(err)
	}
	return c, peer, ctx
}

func alignmentRecv(t *testing.T, ctx context.Context, peer Transport) *Frame {
	t.Helper()
	raw, err := peer.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f, err := UnmarshalFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func alignmentReply(t *testing.T, ctx context.Context, peer Transport, id uint64) {
	t.Helper()
	raw, err := MarshalFrame(NewResultFrame(1, id, NewSuccessResult(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Send(ctx, raw); err != nil {
		t.Fatal(err)
	}
}

func TestAlignmentConcurrentRequestEmissionAndExhaustion(t *testing.T) {
	c, peer, ctx := alignmentClient(t, ClientConfig{MaxConcurrent: 128}, nil)
	const calls = 64
	results := make(chan error, calls)
	for i := 0; i < calls; i++ {
		go func() { _, err := c.Call(ctx, "/example.Echo/Echo", nil, 3000); results <- err }()
	}
	var previous uint64
	for i := 0; i < calls; i++ {
		f := alignmentRecv(t, ctx, peer)
		if f.GetRequestId() <= previous {
			t.Fatalf("emission order %d after %d", f.GetRequestId(), previous)
		}
		previous = f.GetRequestId()
		alignmentReply(t, ctx, peer, previous)
	}
	for i := 0; i < calls; i++ {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	c.nextID.Store(^uint64(0) - 2)
	c.mu.Unlock()
	for _, want := range []uint64{^uint64(0) - 1, ^uint64(0)} {
		go func() { _, err := c.Call(ctx, "/example.Echo/Echo", nil, 1000); results <- err }()
		f := alignmentRecv(t, ctx, peer)
		if f.GetRequestId() != want {
			t.Fatalf("id = %d, want %d", f.GetRequestId(), want)
		}
		alignmentReply(t, ctx, peer, want)
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		_, err := c.Call(ctx, "/example.Echo/Echo", nil, 1000)
		alignmentCode(t, err, ErrorCodeResourceExhausted)
	}
}

func TestAlignmentBudgetStartsBeforeReadiness(t *testing.T) {
	c, err := OpenClient(ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	_, err = c.Call(context.Background(), "/example.Echo/Echo", nil, 20)
	alignmentCode(t, err, ErrorCodeDeadlineExceeded)
	if time.Since(start) > time.Second {
		t.Fatal("readiness restarted or ignored budget")
	}
	if c.core.(*goClientCore).tracker.Pending() != 0 || len(c.waiters) != 0 {
		t.Fatal("pre-admission call leaked")
	}
}

type alignmentGatedSend struct {
	Transport
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *alignmentGatedSend) Send(ctx context.Context, raw []byte) error {
	f, err := UnmarshalFrame(raw)
	if err != nil {
		return err
	}
	if f.GetRequest() != nil {
		g.once.Do(func() {
			close(g.entered)
			select {
			case <-g.release:
			case <-ctx.Done():
			}
		})
	}
	return g.Transport.Send(ctx, raw)
}

func TestAlignmentQueuedExpiryBudgetDecrementAndCleanup(t *testing.T) {
	gate := &alignmentGatedSend{entered: make(chan struct{}), release: make(chan struct{})}
	c, peer, ctx := alignmentClient(t, ClientConfig{}, func(tr Transport) Transport { gate.Transport = tr; return gate })
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(gate.release) }) })
	first := make(chan error, 1)
	go func() { _, err := c.Call(ctx, "/example.Echo/First", nil, 3000); first <- err }()
	select {
	case <-gate.entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_, err := c.Call(ctx, "/example.Echo/Expired", nil, 25)
	alignmentCode(t, err, ErrorCodeDeadlineExceeded)
	cancelCtx, cancel := context.WithCancel(ctx)
	cancelled := make(chan error, 1)
	go func() { _, err := c.Call(cancelCtx, "/example.Echo/Cancelled", nil, 3000); cancelled <- err }()
	until := time.Now().Add(time.Second)
	for {
		c.mu.Lock()
		admitted := len(c.waiters) == 2
		c.mu.Unlock()
		if admitted {
			break
		}
		if time.Now().After(until) {
			cancel()
			t.Fatal("queued cancellation was not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	alignmentCode(t, <-cancelled, ErrorCodeCancelled)
	third := make(chan error, 1)
	go func() { _, err := c.Call(ctx, "/example.Echo/Third", nil, 3000); third <- err }()
	time.Sleep(60 * time.Millisecond)
	release.Do(func() { close(gate.release) })
	for i := 0; i < 2; i++ {
		f := alignmentRecv(t, ctx, peer)
		if f.GetCancel() != nil {
			t.Fatal("never-emitted request produced a Cancel")
		}
		if f.GetRequest().GetMethod() == "/example.Echo/Expired" {
			t.Fatal("expired queue entry emitted")
		}
		if i == 1 && f.GetRequest().GetTimeoutMs() >= 2970 {
			t.Fatalf("queue budget reset: %d", f.GetRequest().GetTimeoutMs())
		}
		alignmentReply(t, ctx, peer, f.GetRequestId())
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-third; err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	core := c.core.(*goClientCore)
	if core.tracker.Pending() != 0 || len(core.outcomes) != 0 || len(c.waiters) != 0 {
		t.Fatal("terminal calls leaked pending state")
	}
}

func TestAlignmentHandoffNeverResetsSubMillisecondBudget(t *testing.T) {
	f := NewRequestFrame(1, 9, &RpcRequest{Method: "/example.Echo/Echo", Payload: []byte("opaque"), TimeoutMs: 1000})
	for _, deadline := range []time.Time{time.Now().Add(-time.Second), time.Now().Add(500 * time.Microsecond)} {
		_, err := prepareCallFrame(f, deadline)
		alignmentCode(t, err, ErrorCodeDeadlineExceeded)
	}
	deadline := time.Now().Add(time.Second)
	raw, err := prepareCallFrame(f, deadline)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := UnmarshalFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.GetRequestId() != 9 || string(prepared.GetRequest().GetPayload()) != "opaque" || prepared.GetRequest().GetTimeoutMs() == 0 || prepared.GetRequest().GetTimeoutMs() >= 1000 {
		t.Fatalf("invalid handoff: %v", prepared)
	}
}

func TestAlignmentHostHighwaterAndTerminalGate(t *testing.T) {
	cfg, err := resolveHostConfig(HostConfig{})
	if err != nil {
		t.Fatal(err)
	}
	core, err := newHostCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	hello, _ := MarshalFrame(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if _, err := core.acceptHello(hello); err != nil {
		t.Fatal(err)
	}
	if _, err := core.authComplete("principal"); err != nil {
		t.Fatal(err)
	}
	g := core.(*goHostCore)
	request := func(id uint64) []byte {
		return mustMarshal(NewRequestFrame(1, id, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 1000}))
	}
	if _, _, fatal := g.onFrame(request(7)); fatal != nil {
		t.Fatal(fatal)
	}
	g.mu.Lock()
	g.outstanding[7].deadline = time.Now().Add(-time.Second)
	g.mu.Unlock()
	g.selectResult(7, NewSuccessResult(nil))
	raw, _, err := g.answer(7, NewSuccessResult(nil))
	if err != nil {
		t.Fatal(err)
	}
	f, err := UnmarshalFrame(raw)
	if err != nil || f.GetResult().GetError().GetCode() != ErrorCodeDeadlineExceeded {
		t.Fatalf("late candidate = %v, %v", f, err)
	}
	if _, _, fatal := g.onFrame(request(9)); fatal != nil {
		t.Fatal(fatal)
	}
	g.selectResult(9, NewSuccessResult([]byte("selected")))
	g.mu.Lock()
	g.outstanding[9].deadline = time.Now().Add(-time.Second)
	g.mu.Unlock()
	if ids := g.reapExpired(time.Now()); len(ids) != 0 {
		t.Fatalf("selected result reaped: %v", ids)
	}
	raw, _, err = g.answer(9, NewWireErrorResult(ErrorCodeCancelled, "late cancel"))
	if err != nil {
		t.Fatal(err)
	}
	f, err = UnmarshalFrame(raw)
	if err != nil || string(f.GetResult().GetPayload()) != "selected" {
		t.Fatalf("immutable terminal = %v, %v", f, err)
	}
	_, _, fatal := g.onFrame(request(8))
	alignmentCode(t, fatal, ErrorCodeFailedPrecondition)
	if _, ok := g.nextOutbound(); ok {
		t.Fatal("offending ID received a result")
	}
}

func TestAlignmentRuntimeLimits(t *testing.T) {
	c, err := resolveClientConfig(ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if c.maxPending != 32 || c.notifyBuffer != 256 || c.writerCapacity != 256 || c.timeout != 30*time.Second || c.maxTimeout != 120*time.Second || c.handshakeTimeout != 5*time.Second {
		t.Fatalf("defaults: %+v", c)
	}
	for _, capacity := range []int{16, 32, 1024} {
		if _, err := resolveClientConfig(ClientConfig{MaxConcurrent: capacity}); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveHostConfig(HostConfig{MaxConcurrent: capacity}); err != nil {
			t.Fatal(err)
		}
	}
	for _, cfg := range []ClientConfig{
		{MaxConcurrent: 15}, {MaxConcurrent: 1025}, {NotifyBuffer: 1025}, {WriterCapacity: 1025},
		{DefaultTimeout: 25 * time.Hour}, {MaxTimeout: -1}, {HandshakeTimeout: 25 * time.Hour},
	} {
		if _, err := resolveClientConfig(cfg); err == nil {
			t.Fatalf("invalid limits accepted: %+v", cfg)
		}
	}
}

func TestAlignmentClientTerminalSelectionAndRetiredIDs(t *testing.T) {
	cfg, err := resolveClientConfig(ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	core, err := newClientCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	if _, err := core.helloFrame(); err != nil {
		t.Fatal(err)
	}
	if _, err := core.activate(mustMarshal(NewReadyFrame(1, &ServerReady{ConnectionId: "terminal"}))); err != nil {
		t.Fatal(err)
	}
	if _, err := core.beginCall(1, "/example.Echo/Echo", nil, 1000); err != nil {
		t.Fatal(err)
	}
	core.setCallDeadline(1, time.Now().Add(-time.Second))
	terminal, _, fatal := core.onFrame(mustMarshal(NewResultFrame(1, 1, NewSuccessResult(nil))))
	if fatal != nil || len(terminal) != 1 {
		t.Fatalf("result selection = %v, %v", terminal, fatal)
	}
	result, ok := core.takeOutcome(1)
	if !ok || result.GetError().GetCode() != ErrorCodeDeadlineExceeded {
		t.Fatalf("late result beat deadline: %v", result)
	}
	if _, err := core.beginCall(1, "/example.Echo/Echo", nil, 1000); err == nil {
		t.Fatal("terminal ID was reused")
	}
	if _, err := core.beginCall(2, "/example.Echo/Echo", nil, 1000); err != nil {
		t.Fatal(err)
	}
	if _, _, fatal := core.onFrame(mustMarshal(NewResultFrame(1, 2, NewSuccessResult([]byte("first"))))); fatal != nil {
		t.Fatal(fatal)
	}
	result = core.failCall(2, NewWireErrorResult(ErrorCodeUnavailable, "later close"))
	if string(result.GetPayload()) != "first" {
		t.Fatalf("teardown replaced selected result: %v", result)
	}
	if ids, _, fatal := core.onFrame(mustMarshal(NewResultFrame(1, 2, NewSuccessResult(nil)))); fatal != nil || len(ids) != 0 {
		t.Fatalf("late unknown result = %v, %v", ids, fatal)
	}
	g := core.(*goClientCore)
	if g.tracker.Pending() != 0 || len(g.outcomes) != 0 {
		t.Fatal("terminal state leaked")
	}
}
