// Session-lifecycle tests: handshake, echo RPCs, cancel, deadlines,
// context cancellation, notifications, concurrency, and deterministic
// close over a loopback transport. All method fixtures are neutral
// (/example.Echo/Echo, /example.KV/Get, /example.Slow/Wait); no
// messenger semantics appear here. Tests run on the pure-Go core in
// default builds (no -tags). The syntranative adapter is exercised by
// native_test.go under -tags syntranative; TestCoreBackend logs the
// linked selection.
package syntra

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	syntrav1 "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/proto"
)

// echoHandler is the neutral test dispatcher: echo returns the payload
// bit-identical, KV Get is always missing, Slow waits out short budgets,
// and anything else is unimplemented.
func echoHandler(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
	switch req.GetMethod() {
	case "/example.Echo/Echo":
		out := make([]byte, len(req.GetPayload()))
		copy(out, req.GetPayload())
		return NewSuccessResult(out), nil
	case "/example.KV/Get":
		return nil, NewRpcError(ErrorCodeNotFound, "test: no such key")
	case "/example.Slow/Wait":
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(300 * time.Millisecond):
			return NewSuccessResult([]byte("slow-ok")), nil
		}
	default:
		return nil, NewRpcError(ErrorCodeUnimplemented, "test: unknown method")
	}
}

func testClientConfig() ClientConfig {
	return ClientConfig{
		MinVersion:     1,
		MaxVersion:     1,
		Credential:     []byte("test-credential"),
		DefaultTimeout: 5 * time.Second,
	}
}

// TestDefaultTimeoutRoundsUpToWholeMs pins the shared rounding policy:
// sub-millisecond defaults round up at resolution so the pure-Go and
// native backends enforce the identical deadline, never a shorter one.
func TestDefaultTimeoutRoundsUpToWholeMs(t *testing.T) {
	if got := roundUpToMs(1500 * time.Microsecond); got != 2 {
		t.Fatalf("roundUpToMs(1.5ms) = %d, want 2", got)
	}
	if got := roundUpToMs(time.Millisecond); got != 1 {
		t.Fatalf("roundUpToMs(1ms) = %d, want 1", got)
	}
	cfg, err := resolveClientConfig(ClientConfig{
		MinVersion: 1, MaxVersion: 1, DefaultTimeout: 1500 * time.Microsecond,
	})
	if err != nil {
		t.Fatalf("resolveClientConfig: %v", err)
	}
	if cfg.timeout != 2*time.Millisecond {
		t.Fatalf("client timeout = %v, want 2ms", cfg.timeout)
	}
	host, err := resolveHostConfig(HostConfig{
		MinVersion: 1, MaxVersion: 1, DefaultTimeout: 1500 * time.Microsecond,
		Policy: StaticPolicy("test-principal", true), Handler: echoHandler,
	})
	if err != nil {
		t.Fatalf("resolveHostConfig: %v", err)
	}
	if host.timeout != 2*time.Millisecond {
		t.Fatalf("host timeout = %v, want 2ms", host.timeout)
	}
}

func testHostConfig() HostConfig {
	return HostConfig{
		MinVersion: 1,
		MaxVersion: 1,
		Policy:     StaticPolicy("test-principal", true),
		Handler:    echoHandler,
	}
}

// pair runs one client against one host over loopback. Callers MUST call
// Cleanup. The client is returned after its handshake completes.
type pair struct {
	client   *Client
	host     *Host
	runErr   chan error
	serveErr chan error
	cancel   context.CancelFunc
	a, b     Transport
	t        *testing.T
	cleanup  sync.Once
}

func newPair(t *testing.T, ccfg ClientConfig, hcfg HostConfig) *pair {
	t.Helper()
	host, err := OpenHost(hcfg)
	if err != nil {
		t.Fatal(err)
	}
	client, err := OpenClient(ccfg)
	if err != nil {
		t.Fatal(err)
	}
	a, b := LoopbackPair()
	ctx, cancel := context.WithCancel(context.Background())
	p := &pair{client: client, host: host, runErr: make(chan error, 1), serveErr: make(chan error, 1), cancel: cancel, a: a, b: b, t: t}
	t.Cleanup(p.Cleanup)
	go func() { p.serveErr <- host.Serve(ctx, a) }()
	go func() { p.runErr <- client.Run(ctx, b) }()
	warmupCtx, warmupStop := context.WithTimeout(ctx, 3*time.Second)
	defer warmupStop()
	for {
		out, err := client.Call(warmupCtx, "/example.Echo/Echo", []byte("warmup"), 1000)
		if err == nil && string(out) == "warmup" {
			return p
		}
		var rerr *RpcError
		if errors.As(err, &rerr) && IsFailedPrecondition(rerr.Code) {
			t.Fatalf("handshake failed: %v", err)
		}
		if warmupCtx.Err() != nil {
			t.Fatalf("handshake never completed: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Cleanup stops the session deterministically.
func (p *pair) Cleanup() {
	p.cleanup.Do(func() {
		p.cancel()
		_ = p.client.Close()
		_ = p.host.Close()
		_ = p.a.Close()
		_ = p.b.Close()
		for _, done := range []<-chan error{p.runErr, p.serveErr} {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				p.t.Error("session pump did not stop during cleanup")
			}
		}
	})
}

func callCode(t *testing.T, err error) ErrorCode {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var rerr *RpcError
	if !errors.As(err, &rerr) {
		t.Fatalf("not an RpcError: %v", err)
	}
	return rerr.Code
}

func TestCoreBackend(t *testing.T) {
	if err := CheckABI(); err != nil {
		t.Fatal(err)
	}
	t.Logf("native core linked: %v", NativeAvailable())
}

func TestHandshakeLifecycle(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	if p.client == nil || p.host == nil {
		t.Fatal("nil session")
	}
	// A second Run on the same client fails fast.
	if err := p.client.Run(context.Background(), p.b); err == nil {
		t.Fatal("second Run accepted")
	}
}

func TestHandshakeDenied(t *testing.T) {
	host, err := OpenHost(HostConfig{
		MinVersion: 1, MaxVersion: 1,
		Policy:  StaticPolicy("p", false), // empty credentials denied
		Handler: echoHandler,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	client, err := OpenClient(ClientConfig{MinVersion: 1, MaxVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	a, b := LoopbackPair()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- host.Serve(ctx, a) }()
	runErr := make(chan error, 1)
	go func() { runErr <- client.Run(ctx, b) }()
	select {
	case err := <-serveErr:
		if code := callCode(t, err); !IsUnauthenticated(code) {
			t.Fatalf("serve err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not reject the handshake")
	}
	// The client is stuck awaiting ready; cancelling releases it.
	cancel()
	select {
	case <-runErr:
	case <-time.After(3 * time.Second):
		t.Fatal("client Run did not return after cancel")
	}
}

func TestEchoRoundTrip(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	payloads := [][]byte{
		{},
		[]byte("hello"),
		func() []byte {
			b := make([]byte, 64<<10)
			for i := range b {
				b[i] = byte(i)
			}
			return b
		}(),
	}
	for i, want := range payloads {
		got, err := p.client.Call(context.Background(), "/example.Echo/Echo", want, 2000)
		if err != nil {
			t.Fatalf("payload %d: %v", i, err)
		}
		if string(got) != string(want) {
			t.Fatalf("payload %d: round trip differs (%d vs %d bytes)", i, len(got), len(want))
		}
	}
}

func TestAppErrors(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	if _, err := p.client.Call(context.Background(), "/example.Nope/Missing", nil, 1000); callCode(t, err) != ErrorCodeUnimplemented {
		t.Fatalf("unknown method err = %v", err)
	}
	if _, err := p.client.Call(context.Background(), "/example.KV/Get", []byte("k"), 1000); callCode(t, err) != ErrorCodeNotFound {
		t.Fatalf("kv get err = %v", err)
	}
	// The connection stays usable after application errors.
	out, err := p.client.Call(context.Background(), "/example.Echo/Echo", []byte("still-here"), 1000)
	if err != nil || string(out) != "still-here" {
		t.Fatalf("post-error call: %v %q", err, out)
	}
}

func TestMalformedMethodRejected(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	if _, err := p.client.Call(context.Background(), "not-a-method", nil, 1000); callCode(t, err) != ErrorCodeInvalidArgument {
		t.Fatalf("err = %v", err)
	}
}

func TestDuplicateIDCoreLevel(t *testing.T) {
	c, err := OpenClient(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	core := c.core
	ready, err := MarshalFrame(NewReadyFrame(1, &ServerReady{ConnectionId: "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.activate(ready); err != nil {
		t.Fatal(err)
	}
	if _, err := core.beginCall(7, "/example.Echo/Echo", []byte("a"), 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := core.beginCall(7, "/example.Echo/Echo", []byte("b"), 1000); err == nil {
		t.Fatal("duplicate outstanding id accepted")
	}
	if frame := core.cancelCall(999); frame != nil {
		t.Fatal("cancel of unknown id produced a frame")
	}
	if _, ok := core.takeOutcome(7); ok {
		t.Fatal("outcome before terminal result")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := core.beginCall(8, "/example.Echo/Echo", nil, 1000); err == nil {
		t.Fatal("call after close accepted")
	}
}

func TestCancel(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := p.client.Call(ctx, "/example.Slow/Wait", nil, 10000)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if code := callCode(t, err); !IsCancelled(code) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancelled call never returned")
	}
	// The session survives cancellation.
	out, err := p.client.Call(context.Background(), "/example.Echo/Echo", []byte("after-cancel"), 2000)
	if err != nil || string(out) != "after-cancel" {
		t.Fatalf("post-cancel call: %v %q", err, out)
	}
}

func TestCallDeadline(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	_, err := p.client.Call(context.Background(), "/example.Slow/Wait", nil, 100)
	if code := callCode(t, err); !IsDeadlineExceeded(code) {
		t.Fatalf("err = %v", err)
	}
}

func TestContextDeadline(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := p.client.Call(ctx, "/example.Slow/Wait", nil, 10000)
	if code := callCode(t, err); !IsDeadlineExceeded(code) {
		t.Fatalf("err = %v", err)
	}
}

func TestMissingOutcomeRejected(t *testing.T) {
	c, err := OpenClient(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	core := c.core
	ready, err := MarshalFrame(NewReadyFrame(1, &ServerReady{ConnectionId: "x"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.activate(ready); err != nil {
		t.Fatal(err)
	}
	// A result frame whose outcome wrapper is empty is never success.
	_, _, fatal := core.onFrame(mustHex(t, "080110076a00"))
	if fatal == nil || !IsInvalidArgument(fatal.Code) {
		t.Fatalf("fatal = %v", fatal)
	}
}

func TestNotificationFlow(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	if err := p.host.NotifyAll([]byte("event-1")); err != nil {
		t.Fatal(err)
	}
	if err := p.host.NotifyAll(nil); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"event-1", ""} {
		select {
		case ntf := <-p.client.Notifications():
			if string(ntf.GetPayload()) != want {
				t.Fatalf("notification = %q", ntf.GetPayload())
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("notification %q never arrived", want)
		}
	}
	// Notifications complete no RPC: an echo round trip is unaffected.
	out, err := p.client.Call(context.Background(), "/example.Echo/Echo", []byte("ping"), 1000)
	if err != nil || string(out) != "ping" {
		t.Fatalf("post-notify call: %v %q", err, out)
	}
	// Broadcast with no connections is a documented no-op.
	lone, err := OpenHost(testHostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer lone.Close()
	if err := lone.NotifyAll([]byte("nobody")); err != nil {
		t.Fatalf("notify with no conns: %v", err)
	}
}

func TestDeterministicClose(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.a.Close()
	defer p.b.Close()
	if err := p.client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.client.Close(); callCode(t, err) != ErrorCodeFailedPrecondition {
		t.Fatalf("second client Close: %v", err)
	}
	if _, err := p.client.Call(context.Background(), "/example.Echo/Echo", nil, 1000); callCode(t, err) != ErrorCodeFailedPrecondition {
		t.Fatalf("call after close: %v", err)
	}
	if err := p.host.Close(); err != nil {
		t.Fatal(err)
	}
	if err := p.host.Close(); callCode(t, err) != ErrorCodeFailedPrecondition {
		t.Fatalf("second host Close: %v", err)
	}
	if err := p.host.NotifyAll([]byte("x")); callCode(t, err) != ErrorCodeFailedPrecondition {
		t.Fatalf("notify after close: %v", err)
	}
}

func TestVersionMismatch(t *testing.T) {
	c, err := OpenClient(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Server selects outside the proposed range. The frame is encoded
	// with proto.Marshal directly because MarshalFrame would (correctly)
	// refuse to emit it.
	bad, err := proto.Marshal(&Frame{Version: 2, Body: &syntrav1.Frame_Ready{Ready: &ServerReady{ConnectionId: "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.core.activate(bad); err == nil {
		t.Fatal("out-of-range version accepted")
	}
	// Server side: hello range disjoint from the host range.
	hc, err := newHostCore(resolvedHostConfig{minVersion: 1, maxVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer hc.close()
	hello, err := MarshalFrame(NewHelloFrame(&ClientHello{MinVersion: 2, MaxVersion: 2, Credential: []byte("c")}, 2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hc.acceptHello(hello); err == nil {
		t.Fatal("disjoint hello accepted")
	}
}

func TestConcurrentCalls(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	const n = MaxConcurrentRPCs
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
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

func TestStaticPolicy(t *testing.T) {
	allow := StaticPolicy("principal-1", true)
	p, err := allow(context.Background(), nil)
	if err != nil || p != "principal-1" {
		t.Fatalf("allow-all: %v %q", err, p)
	}
	deny := StaticPolicy("principal-1", false)
	if _, err := deny(context.Background(), nil); err == nil {
		t.Fatal("empty credential accepted by strict policy")
	} else if code := callCode(t, err); !IsUnauthenticated(code) {
		t.Fatalf("wrong code: %v", err)
	}
	if _, err := StaticPolicy("", true)(context.Background(), []byte("c")); err == nil {
		t.Fatal("empty principal accepted")
	}
}
