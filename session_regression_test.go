package syntra

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func TestConfigBounds(t *testing.T) {
	maxTimeout := time.Duration(MaxRPCTimeoutMs) * time.Millisecond
	for _, timeout := range []time.Duration{0, time.Nanosecond, maxTimeout} {
		if _, err := resolveClientConfig(ClientConfig{DefaultTimeout: timeout, MaxConcurrent: MaxConcurrentRPCs}); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveHostConfig(HostConfig{DefaultTimeout: timeout}); err != nil {
			t.Fatal(err)
		}
	}
	for _, timeout := range []time.Duration{maxTimeout + time.Nanosecond, time.Duration(1<<32) * time.Millisecond} {
		if _, err := resolveClientConfig(ClientConfig{DefaultTimeout: timeout}); callCode(t, err) != ErrorCodeOutOfRange {
			t.Fatalf("client timeout %v: %v", timeout, err)
		}
		if _, err := resolveHostConfig(HostConfig{DefaultTimeout: timeout}); callCode(t, err) != ErrorCodeOutOfRange {
			t.Fatalf("host timeout %v: %v", timeout, err)
		}
	}
	if _, err := resolveClientConfig(ClientConfig{MaxConcurrent: MaxConcurrentRPCs + 1}); callCode(t, err) != ErrorCodeOutOfRange {
		t.Fatalf("client concurrency: %v", err)
	}
}

func TestNilPayloadSuccess(t *testing.T) {
	if !validSuccess(NewSuccessResult(nil)) || !validSuccess(NewSuccessResult([]byte{})) {
		t.Fatal("selected empty payload must be success")
	}
	for _, res := range []*RpcResult{nil, {}, NewWireErrorResult(ErrorCodeCancelled, "cancelled")} {
		if validSuccess(res) {
			t.Fatalf("non-success accepted: %v", res)
		}
	}
	cfg := testHostConfig()
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		if req.GetMethod() == "/example.Echo/Empty" {
			return NewSuccessResult(nil), nil
		}
		return echoHandler(ctx, req)
	}
	p := newPair(t, testClientConfig(), cfg)
	defer p.Cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if out, err := p.client.Call(ctx, "/example.Echo/Empty", nil, 1000); err != nil || len(out) != 0 {
		t.Fatalf("empty success = %q, %v", out, err)
	}
}

func TestHostMalformedMethodIsPerRPCError(t *testing.T) {
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
	if _, err := core.authComplete("test-principal"); err != nil {
		t.Fatal(err)
	}
	for i, method := range []string{"", "not-a-method", "/example.Echo/With Space"} {
		id := uint64(i + 1)
		raw, err := proto.Marshal(NewRequestFrame(1, id, &RpcRequest{Method: method}))
		if err != nil {
			t.Fatal(err)
		}
		responses, _, fatal := core.onFrame(raw)
		if fatal != nil {
			t.Fatalf("method %q killed connection: %v", method, fatal)
		}
		for {
			frame, ok := core.nextOutbound()
			if !ok {
				break
			}
			responses = append(responses, frame)
		}
		if len(responses) != 1 {
			t.Fatalf("method %q: %d responses", method, len(responses))
		}
		f, err := UnmarshalFrame(responses[0])
		if err != nil {
			t.Fatal(err)
		}
		if f.GetRequestId() != id || f.GetResult().GetError().GetCode() != ErrorCodeInvalidArgument {
			t.Fatalf("method %q: response %v", method, f)
		}
		if _, _, ok := core.takePending(); ok {
			t.Fatal("malformed request queued for handler")
		}
	}
	valid, err := MarshalFrame(NewRequestFrame(1, 10, &RpcRequest{Method: "/example.Echo/Echo"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, fatal := core.onFrame(valid); fatal != nil {
		t.Fatal(fatal)
	}
	if id, _, ok := core.takePending(); !ok || id != 10 {
		t.Fatal("connection unusable after malformed methods")
	}
}

func TestLoopbackConcurrentSendClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		a, b := LoopbackPair()
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, endpoint := range []Transport{a, b} {
			wg.Add(2)
			go func(l Transport) {
				defer wg.Done()
				<-start
				for j := 0; j < loopbackBuffer*2; j++ {
					_ = l.Send(context.Background(), []byte("frame"))
				}
			}(endpoint)
			go func(l Transport) {
				defer wg.Done()
				<-start
				_ = l.Close()
			}(endpoint)
		}
		close(start)
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		awaitSignal(t, done, "loopback Send/Close")
	}
}

func TestLoopbackCancelledSendBeforeLock(t *testing.T) {
	a, b := LoopbackPair()
	defer a.Close()
	l := a.(*loopback)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l.mu.Lock()
	done := make(chan error, 1)
	go func() { done <- a.Send(ctx, []byte("frame")) }()
	select {
	case err := <-done:
		l.mu.Unlock()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Send = %v", err)
		}
	case <-time.After(time.Second):
		l.mu.Unlock()
		t.Fatal("cancelled Send waited for mutex")
	}
	// A full inbox must fail promptly without holding up Close.
	for i := 0; i < loopbackBuffer; i++ {
		if err := a.Send(context.Background(), []byte("frame")); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Send(context.Background(), nil); callCode(t, err) != ErrorCodeResourceExhausted {
		t.Fatalf("full inbox Send = %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < loopbackBuffer; i++ {
		if _, err := b.Recv(context.Background()); err != nil {
			t.Fatalf("buffered frame %d lost on Close: %v", i, err)
		}
	}
}

// waitingContext lets tests cancel or close only once Call is selecting
// on activation, rather than accidentally exercising its initial Err check.
type waitingContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *waitingContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func awaitSignal(t *testing.T, ch <-chan struct{}, operation string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("%s did not complete", operation)
	}
}

func TestCallActivationWaitCancellation(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			c, err := OpenClient(testClientConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			ctx, cancel := context.WithCancel(context.Background())
			want := ErrorCodeCancelled
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				want = ErrorCodeDeadlineExceeded
			}
			defer cancel()
			waiting := &waitingContext{Context: ctx, waiting: make(chan struct{})}
			done := make(chan error, 1)
			go func() { _, err := c.Call(waiting, "/example.Echo/Echo", nil, 1000); done <- err }()
			awaitSignal(t, waiting.waiting, "Call activation wait")
			if !deadline {
				cancel()
			}
			select {
			case err := <-done:
				if callCode(t, err) != want {
					t.Fatalf("Call = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Call ignored context during activation")
			}
		})
	}
}

func TestHandshakeTeardownWakesCall(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		t.Run(map[bool]string{false: "transport-failure", true: "Close"}[closeClient], func(t *testing.T) {
			c, err := OpenClient(testClientConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			a, b := LoopbackPair()
			defer a.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			runDone := make(chan struct{})
			go func() { defer close(runDone); _ = c.Run(ctx, a) }()
			if _, err := b.Recv(ctx); err != nil {
				t.Fatal(err)
			}
			if err := c.Run(ctx, a); callCode(t, err) != ErrorCodeFailedPrecondition {
				t.Fatalf("concurrent handshake Run = %v", err)
			}
			waiting := &waitingContext{Context: ctx, waiting: make(chan struct{})}
			callDone := make(chan error, 1)
			go func() { _, err := c.Call(waiting, "/example.Echo/Echo", nil, 1000); callDone <- err }()
			awaitSignal(t, waiting.waiting, "Call activation wait")
			if closeClient {
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				_ = b.Close()
			}
			awaitSignal(t, runDone, "Run handshake teardown")
			select {
			case err := <-callDone:
				if callCode(t, err) != ErrorCodeFailedPrecondition {
					t.Fatalf("Call = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("activation waiter not woken by teardown")
			}
			if _, ok := <-c.Notifications(); ok {
				t.Fatal("notification stream left open after handshake teardown")
			}
		})
	}
}

type blockedNotificationCore struct {
	clientCore
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (c *blockedNotificationCore) pollNotification() (*Notification, bool) {
	ntf, ok := c.clientCore.pollNotification()
	c.once.Do(func() {
		close(c.entered)
		<-c.release
	})
	return ntf, ok
}

func TestBlockedNotificationCorePollsRepeatedly(t *testing.T) {
	c, err := OpenClient(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	core := &blockedNotificationCore{clientCore: c.core, entered: make(chan struct{}), release: make(chan struct{}, 1)}
	defer close(core.release)
	poll := func(done chan struct{}) {
		defer close(done)
		if ntf, ok := core.pollNotification(); ntf != nil || ok {
			t.Errorf("empty notification poll = %v, %v", ntf, ok)
		}
	}
	first := make(chan struct{})
	go poll(first)
	awaitSignal(t, core.entered, "first notification poll")
	core.release <- struct{}{}
	awaitSignal(t, first, "first notification poll release")
	second := make(chan struct{})
	go poll(second)
	awaitSignal(t, second, "second notification poll without another release")
}

func TestCloseDuringNotificationDelivery(t *testing.T) {
	c, err := OpenClient(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	core := &blockedNotificationCore{clientCore: c.core, entered: make(chan struct{}), release: make(chan struct{})}
	c.core = core
	var release sync.Once
	defer release.Do(func() { close(core.release) })
	defer c.Close()
	h, err := OpenHost(testHostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	a, b := LoopbackPair()
	defer a.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	runDone, serveDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(runDone); _ = c.Run(ctx, a) }()
	go func() { defer close(serveDone); _ = h.Serve(ctx, b) }()
	if _, err := c.Call(ctx, "/example.Echo/Echo", nil, 1000); err != nil {
		t.Fatal(err)
	}
	if err := h.NotifyAll([]byte("notification")); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, core.entered, "notification polling")
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.Notifications():
		t.Fatal("notification channel closed while pump can still send")
	default:
	}
	release.Do(func() { close(core.release) })
	awaitSignal(t, runDone, "notification pump teardown")
	for range c.Notifications() {
	}
	cancel()
	awaitSignal(t, serveDone, "host teardown")
}
