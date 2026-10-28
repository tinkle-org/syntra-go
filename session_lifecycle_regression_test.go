package syntra

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Observe the actual I/O context without waiting five seconds for the
// default timer. Returning a sentinel also verifies the attempt terminates.
type handshakeDeadlineTransport struct {
	t *testing.T
	Transport
	phase  string
	parent context.Context
	hello  []byte
	seen   bool
}

var errHandshakeProbe = errors.New("handshake deadline probe")

func (p *handshakeDeadlineTransport) check(ctx context.Context) error {
	p.t.Helper()
	p.seen = true
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
		p.t.Errorf("handshake I/O must have a live deadline <= 5s: %v, %v", deadline, ok)
	}
	if parentDeadline, ok := p.parent.Deadline(); ok && deadline.After(parentDeadline) {
		p.t.Errorf("handshake extended caller deadline: %v > %v", deadline, parentDeadline)
	}
	return errHandshakeProbe
}

func (p *handshakeDeadlineTransport) Send(ctx context.Context, _ []byte) error {
	if p.phase == "send" {
		return p.check(ctx)
	}
	return nil
}

func (p *handshakeDeadlineTransport) Recv(ctx context.Context) ([]byte, error) {
	if p.phase == "recv" {
		return nil, p.check(ctx)
	}
	return p.hello, nil
}

func TestSessionHandshakeIODefaultDeadlines(t *testing.T) {
	for _, role := range []string{"client", "host"} {
		for _, phase := range []string{"send", "recv"} {
			for _, timeout := range []time.Duration{0, time.Second, time.Hour} {
				t.Run(role+"/"+phase+"/"+timeout.String(), func(t *testing.T) {
					ctx := context.Background()
					if timeout != 0 {
						var cancel context.CancelFunc
						ctx, cancel = context.WithTimeout(ctx, timeout)
						defer cancel()
					}
					probe := &handshakeDeadlineTransport{t: t, phase: phase, parent: ctx}
					var err error
					if role == "client" {
						c, openErr := OpenClient(testClientConfig())
						if openErr != nil {
							t.Fatal(openErr)
						}
						defer c.Close()
						err = c.Run(ctx, probe)
					} else {
						probe.hello, err = MarshalFrame(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
						if err != nil {
							t.Fatal(err)
						}
						h, openErr := OpenHost(testHostConfig())
						if openErr != nil {
							t.Fatal(openErr)
						}
						defer h.Close()
						err = h.Serve(ctx, probe)
					}
					if !probe.seen || err == nil {
						t.Fatalf("probe seen=%v, error=%v", probe.seen, err)
					}
				})
			}
		}
	}
}

func TestSessionSilentHandshakeTerminates(t *testing.T) {
	for _, role := range []string{"client", "host"} {
		for _, callerBound := range []bool{false, true} {
			t.Run(role+map[bool]string{false: "/default", true: "/caller"}[callerBound], func(t *testing.T) {
				t.Parallel()
				a, b := LoopbackPair()
				defer b.Close()
				ctx := context.Background()
				if callerBound {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
					defer cancel()
				}
				done := make(chan error, 1)
				if role == "client" {
					c, err := OpenClient(testClientConfig())
					if err != nil {
						t.Fatal(err)
					}
					defer c.Close()
					go func() { done <- c.Run(ctx, a) }()
				} else {
					h, err := OpenHost(testHostConfig())
					if err != nil {
						t.Fatal(err)
					}
					defer h.Close()
					go func() { done <- h.Serve(ctx, a) }()
				}
				limit := 7 * time.Second
				if callerBound {
					limit = time.Second
				}
				select {
				case err := <-done:
					if !errors.Is(err, context.DeadlineExceeded) {
						t.Fatalf("handshake expiry = %v", err)
					}
				case <-time.After(limit):
					_ = b.Close()
					t.Fatal("silent handshake never expired")
				}
			})
		}
	}
}

type handshakeContextTransport struct {
	Transport
	reads  chan context.Context
	writes chan context.Context
}

func (r *handshakeContextTransport) Recv(ctx context.Context) ([]byte, error) {
	r.reads <- ctx
	return r.Transport.Recv(ctx)
}

func (r *handshakeContextTransport) Send(ctx context.Context, raw []byte) error {
	r.writes <- ctx
	return r.Transport.Send(ctx, raw)
}

func TestSessionHandshakeBudgetCoversPolicyNotActiveLifetime(t *testing.T) {
	a, b := LoopbackPair()
	defer b.Close()
	tr := &handshakeContextTransport{Transport: a, reads: make(chan context.Context, 4), writes: make(chan context.Context, 4)}
	policyCtx := make(chan context.Context, 1)
	cfg := testHostConfig()
	cfg.Policy = func(ctx context.Context, _ []byte) (string, error) { policyCtx <- ctx; return "principal", nil }
	h, err := OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	defer stop()
	p := &rawSessionPeer{host: h, peer: b, ctx: ctx, done: make(chan error, 1)}
	go func() { p.done <- h.Serve(ctx, tr) }()
	p.send(t, NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	_ = p.recv(t)
	readCtx, authCtx, writeCtx := <-tr.reads, <-policyCtx, <-tr.writes
	d, ok := readCtx.Deadline()
	if !ok {
		t.Fatal("hello read has no deadline")
	}
	for _, c := range []context.Context{authCtx, writeCtx} {
		other, ok := c.Deadline()
		if !ok || !d.Equal(other) {
			t.Fatalf("handshake timer reset between phases: %v != %v", d, other)
		}
	}
	select {
	case active := <-tr.reads:
		got, ok := active.Deadline()
		want, _ := ctx.Deadline()
		if !ok || !got.Equal(want) || active.Err() != nil {
			t.Fatalf("handshake deadline leaked into active pump: %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("active read did not start")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit")
	}
}

// rawSessionPeer observes host wire results rather than Client.Call's local
// cancellation result, which could hide a missing host terminal response.
type rawSessionPeer struct {
	host *Host
	peer Transport
	ctx  context.Context
	done chan error
}

func newRawSessionPeer(t *testing.T, cfg HostConfig, wrap func(Transport) Transport) *rawSessionPeer {
	t.Helper()
	h, err := OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, b := LoopbackPair()
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
	p := &rawSessionPeer{host: h, peer: b, ctx: ctx, done: make(chan error, 1)}
	if wrap != nil {
		a = wrap(a)
	}
	go func() { p.done <- h.Serve(ctx, a) }()
	t.Cleanup(func() {
		stop()
		_ = h.Close()
		_ = b.Close()
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			t.Error("Serve failed to stop")
		}
	})
	p.send(t, NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if f := p.recv(t); BodyKindOf(f) != BodyKindReady {
		t.Fatalf("expected ready, got %v", f)
	}
	return p
}

func (p *rawSessionPeer) send(t *testing.T, f *Frame) {
	t.Helper()
	raw, err := MarshalFrame(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.peer.Send(p.ctx, raw); err != nil {
		t.Fatal(err)
	}
}

func (p *rawSessionPeer) request(t *testing.T, id uint64, method string) {
	t.Helper()
	p.send(t, NewRequestFrame(1, id, &RpcRequest{Method: method, TimeoutMs: 5000}))
}

func (p *rawSessionPeer) recv(t *testing.T) *Frame {
	t.Helper()
	ctx, stop := context.WithTimeout(p.ctx, time.Second)
	defer stop()
	raw, err := p.peer.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f, err := UnmarshalFrame(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func assertTerminalCode(t *testing.T, f *Frame, id uint64, want ErrorCode) {
	t.Helper()
	if BodyKindOf(f) != BodyKindResult || f.GetRequestId() != id || f.GetResult().GetError() == nil || f.GetResult().GetError().GetCode() != want {
		t.Fatalf("expected result %d code %v, got %v", id, want, f)
	}
}

type failingResultTransport struct {
	Transport
	fail      error
	attempted chan struct{}
	once      sync.Once
	kind      BodyKind // empty selects result
}

func (f *failingResultTransport) Send(ctx context.Context, raw []byte) error {
	frame, err := UnmarshalFrame(raw)
	if err != nil {
		return err
	}
	kind := f.kind
	if kind == "" {
		kind = BodyKindResult
	}
	if BodyKindOf(frame) == kind {
		f.once.Do(func() { close(f.attempted) })
		return f.fail
	}
	return f.Transport.Send(ctx, raw)
}

func TestSessionHandlerSendFailureTerminatesServe(t *testing.T) {
	for _, failure := range []error{errors.New("write failed"), context.DeadlineExceeded, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			attempted := make(chan struct{})
			p := newRawSessionPeer(t, testHostConfig(), func(tr Transport) Transport {
				return &failingResultTransport{Transport: tr, fail: failure, attempted: attempted}
			})
			p.request(t, 1, "/example.Echo/Echo")
			awaitSignal(t, attempted, "result send")
			select {
			case err := <-p.done:
				p.done <- err // cleanup also joins Serve
				if callCode(t, err) != ErrorCodeUnavailable {
					t.Fatalf("Serve = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("failed handler send left Serve running")
			}
		})
	}
}

func TestSessionQueuedSendFailureTerminatesServe(t *testing.T) {
	for _, failure := range []error{errors.New("write failed"), context.DeadlineExceeded, context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			attempted := make(chan struct{})
			p := newRawSessionPeer(t, testHostConfig(), func(tr Transport) Transport {
				return &failingResultTransport{Transport: tr, fail: failure, attempted: attempted, kind: BodyKindNotification}
			})
			if err := p.host.NotifyAll([]byte("queued notification")); err != nil {
				t.Fatal(err)
			}
			awaitSignal(t, attempted, "queued send")
			select {
			case err := <-p.done:
				p.done <- err
				if callCode(t, err) != ErrorCodeUnavailable {
					t.Fatalf("Serve = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("failed queued send left Serve running")
			}
		})
	}
}

func TestSessionPeerCancelNonCooperativeHandler(t *testing.T) {
	started, cancelled, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	cfg := testHostConfig()
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		if req.GetMethod() != "/example.Slow/Wait" {
			return echoHandler(ctx, req)
		}
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release // deliberately ignore cancellation before returning late success
		defer close(exited)
		return NewSuccessResult([]byte("late")), nil
	}
	p := newRawSessionPeer(t, cfg, nil)
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); awaitSignal(t, exited, "late handler exit") })
	p.request(t, 1, "/example.Slow/Wait")
	awaitSignal(t, started, "handler start")
	p.send(t, NewCancelFrame(1, 1))
	awaitSignal(t, cancelled, "handler cancellation")
	assertTerminalCode(t, p.recv(t), 1, ErrorCodeCancelled)
	once.Do(func() { close(release) })
	awaitSignal(t, exited, "late handler exit")
	// No duplicate terminal, including after the original callback returns.
	p.request(t, 2, "/example.Echo/Echo")
	f := p.recv(t)
	if f.GetRequestId() != 2 || !validSuccess(f.GetResult()) {
		t.Fatalf("late result or unusable connection: %v", f)
	}
}

func TestSessionHostCloseCancelsExistingConnections(t *testing.T) {
	for _, stage := range []string{"hello", "policy", "active", "handler"} {
		t.Run(stage, func(t *testing.T) {
			entered, cancelled := make(chan struct{}), make(chan struct{})
			cfg := testHostConfig()
			if stage == "policy" {
				cfg.Policy = func(ctx context.Context, _ []byte) (string, error) {
					close(entered)
					<-ctx.Done()
					close(cancelled)
					return "", ctx.Err()
				}
			}
			if stage == "handler" {
				cfg.Handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
					close(entered)
					<-ctx.Done()
					close(cancelled)
					return nil, ctx.Err()
				}
			}
			h, err := OpenHost(cfg)
			if err != nil {
				t.Fatal(err)
			}
			a, b := LoopbackPair()
			defer b.Close()
			ctx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			p := &rawSessionPeer{host: h, peer: b, ctx: ctx, done: make(chan error, 1)}
			go func() { p.done <- h.Serve(ctx, a) }()
			if stage != "hello" {
				p.send(t, NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
				if stage != "policy" {
					_ = p.recv(t)
				}
			}
			if stage == "handler" {
				p.request(t, 1, "/example.Slow/Wait")
			}
			if stage == "handler" || stage == "policy" {
				awaitSignal(t, entered, stage+" start")
			}
			if stage == "hello" {
				// Synchronize on registration, not a sleep or a goroutine-count guess.
				deadline := time.After(time.Second)
				for {
					h.mu.Lock()
					n := len(h.conns)
					h.mu.Unlock()
					if n == 1 {
						break
					}
					select {
					case <-deadline:
						t.Fatal("Serve did not register")
					default:
						time.Sleep(time.Millisecond)
					}
				}
			}
			if err := h.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-p.done:
			case <-time.After(time.Second):
				t.Fatal("Host.Close did not wake existing Serve")
			}
			if stage == "handler" || stage == "policy" {
				awaitSignal(t, cancelled, stage+" cancellation")
			}
			// The session must leave the caller-owned transport open.
			if err := b.Send(ctx, []byte("still owned")); err != nil {
				t.Fatalf("Host.Close closed transport: %v", err)
			}
			if err := h.Serve(ctx, a); callCode(t, err) != ErrorCodeFailedPrecondition {
				t.Fatalf("new Serve = %v", err)
			}
		})
	}
}

func TestSessionHostCloseRacesServeRegistration(t *testing.T) {
	h, err := OpenHost(testHostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	start := make(chan struct{})
	const n = 32
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		a, b := LoopbackPair()
		defer b.Close()
		go func() { <-start; results <- h.Serve(ctx, a) }()
	}
	close(start)
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for i := 0; i < n; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, context.Canceled) && callCode(t, err) != ErrorCodeFailedPrecondition {
				t.Fatalf("Serve racing Close = %v", err)
			}
		case <-timer.C:
			t.Fatal("Serve registered after Close without a shutdown signal")
		}
	}
	h.mu.Lock()
	remaining := len(h.conns)
	h.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("%d connections retained after Serve exited", remaining)
	}
}

// Freeze the Serve writer while callbacks finish, making completion and
// peer cancellation both ready without relying on scheduler timing.
type gatedNotificationTransport struct {
	Transport
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (g *gatedNotificationTransport) Send(ctx context.Context, raw []byte) error {
	f, err := UnmarshalFrame(raw)
	if err != nil {
		return err
	}
	if BodyKindOf(f) == BodyKindNotification {
		g.once.Do(func() { close(g.entered) })
		select {
		case <-g.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return g.Transport.Send(ctx, raw)
}

func TestSessionCompletionWinsReadyCancel(t *testing.T) {
	for _, appError := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "application-error"}[appError], func(t *testing.T) {
			started, releaseHandler := make(chan struct{}), make(chan struct{})
			gate := &gatedNotificationTransport{entered: make(chan struct{}), release: make(chan struct{})}
			cfg := testHostConfig()
			cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
				if req.GetMethod() != "/example.Slow/Wait" {
					return echoHandler(ctx, req)
				}
				close(started)
				select {
				case <-releaseHandler:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				if appError {
					return nil, NewRpcError(ErrorCodeNotFound, "missing")
				}
				return NewSuccessResult([]byte("winner")), nil
			}
			p := newRawSessionPeer(t, cfg, func(tr Transport) Transport { gate.Transport = tr; return gate })
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(gate.release) }) })
			p.request(t, 1, "/example.Slow/Wait")
			awaitSignal(t, started, "handler start")
			if err := p.host.NotifyAll([]byte("barrier")); err != nil {
				t.Fatal(err)
			}
			awaitSignal(t, gate.entered, "writer barrier")
			p.host.mu.Lock()
			var hc *hostConn
			for conn := range p.host.conns {
				hc = conn
			}
			p.host.mu.Unlock()
			if hc == nil {
				t.Fatal("missing active connection")
			}
			close(releaseHandler)
			select {
			case cc := <-hc.completed:
				hc.completed <- cc // restore the event before resuming Serve
			case <-time.After(time.Second):
				t.Fatal("handler did not publish completion")
			}
			p.send(t, NewCancelFrame(1, 1))
			release.Do(func() { close(gate.release) })
			if f := p.recv(t); BodyKindOf(f) != BodyKindNotification {
				t.Fatalf("barrier frame = %v", f)
			}
			f := p.recv(t)
			if appError {
				assertTerminalCode(t, f, 1, ErrorCodeNotFound)
			} else if f.GetRequestId() != 1 || string(f.GetResult().GetPayload()) != "winner" {
				t.Fatalf("completion lost to ready cancellation: %v", f)
			}
			p.send(t, NewCancelFrame(1, 1))
			p.request(t, 2, "/example.Echo/Echo")
			if f := p.recv(t); f.GetRequestId() != 2 || !validSuccess(f.GetResult()) {
				t.Fatalf("duplicate terminal: %v", f)
			}
		})
	}
}

func TestSessionHostCloseInterruptsBlockedWriter(t *testing.T) {
	gate := &gatedNotificationTransport{entered: make(chan struct{}), release: make(chan struct{})}
	p := newRawSessionPeer(t, testHostConfig(), func(tr Transport) Transport { gate.Transport = tr; return gate })
	if err := p.host.NotifyAll([]byte("blocked write")); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, gate.entered, "blocked writer")
	if err := p.host.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-p.done:
		p.done <- err
		if err != nil {
			t.Fatalf("Close during Send = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Host.Close did not interrupt Send")
	}
}

func TestSessionHostCloseBoundsNonCooperativeDrain(t *testing.T) {
	started, cancelled, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	cfg := testHostConfig()
	cfg.Handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		defer close(exited)
		return NewSuccessResult([]byte("late after shutdown")), nil
	}
	p := newRawSessionPeer(t, cfg, nil)
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); awaitSignal(t, exited, "abandoned callback exit") })
	p.request(t, 1, "/example.Slow/Wait")
	awaitSignal(t, started, "handler start")
	if err := p.host.Close(); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, cancelled, "handler cancellation")
	select {
	case err := <-p.done:
		p.done <- err
		if err != nil {
			t.Fatalf("Close = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve waited indefinitely for non-cooperative handler")
	}
	once.Do(func() { close(release) })
	awaitSignal(t, exited, "abandoned callback exit")
	ctx, stop := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer stop()
	if _, err := p.peer.Recv(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("late callback sent after Serve exited or closed caller transport: %v", err)
	}
}

func TestSessionCancelledWorkersStayBounded(t *testing.T) {
	started, cancelled, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	cfg := testHostConfig()
	cfg.MaxConcurrent = 1
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		if req.GetMethod() != "/example.Slow/Wait" {
			return echoHandler(ctx, req)
		}
		close(started)
		<-ctx.Done()
		close(cancelled)
		<-release
		defer close(exited)
		return NewSuccessResult([]byte("late")), nil
	}
	p := newRawSessionPeer(t, cfg, nil)
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }); awaitSignal(t, exited, "blocked worker exit") })
	p.request(t, 1, "/example.Slow/Wait")
	awaitSignal(t, started, "handler start")
	p.send(t, NewCancelFrame(1, 1))
	assertTerminalCode(t, p.recv(t), 1, ErrorCodeCancelled)
	awaitSignal(t, cancelled, "handler cancellation")
	// The wire RPC is terminal, but its callback still occupies the sole
	// worker slot. Repeated requests must not spawn replacement workers.
	for id := uint64(2); id < 18; id++ {
		p.request(t, id, "/example.Echo/Echo")
		assertTerminalCode(t, p.recv(t), id, ErrorCodeResourceExhausted)
	}
	once.Do(func() { close(release) })
	awaitSignal(t, exited, "blocked worker exit")
	// An echo may race the worker's final completion publication, so retry
	// only RESOURCE_EXHAUSTED under a fixed deadline, never wait unboundedly.
	for id := uint64(18); ; id++ {
		p.request(t, id, "/example.Echo/Echo")
		f := p.recv(t)
		if f.GetRequestId() != id {
			t.Fatalf("late callback emitted another result: %v", f)
		}
		if validSuccess(f.GetResult()) {
			break
		}
		assertTerminalCode(t, f, id, ErrorCodeResourceExhausted)
		if p.ctx.Err() != nil {
			t.Fatal("worker capacity did not recover")
		}
	}
}

func TestSessionLateCompletionCannotAnswerReusedID(t *testing.T) {
	oldStarted, newStarted, oldRelease, newRelease, oldExited := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	cfg := testHostConfig()
	cfg.MaxConcurrent = 2
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		switch req.GetMethod() {
		case "/example.Slow/Old":
			close(oldStarted)
			<-oldRelease
			defer close(oldExited)
			return NewSuccessResult([]byte("old")), nil
		case "/example.Slow/New":
			close(newStarted)
			select {
			case <-newRelease:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return NewSuccessResult([]byte("new")), nil
		default:
			return echoHandler(ctx, req)
		}
	}
	p := newRawSessionPeer(t, cfg, nil)
	var onceOld, onceNew sync.Once
	t.Cleanup(func() {
		onceOld.Do(func() { close(oldRelease) })
		onceNew.Do(func() { close(newRelease) })
		awaitSignal(t, oldExited, "old worker exit")
	})
	p.request(t, 7, "/example.Slow/Old")
	awaitSignal(t, oldStarted, "old worker start")
	p.send(t, NewCancelFrame(1, 7))
	assertTerminalCode(t, p.recv(t), 7, ErrorCodeCancelled)
	p.request(t, 7, "/example.Slow/New")
	awaitSignal(t, newStarted, "reused ID worker start")
	onceOld.Do(func() { close(oldRelease) })
	awaitSignal(t, oldExited, "old worker exit")
	onceNew.Do(func() { close(newRelease) })
	f := p.recv(t)
	if f.GetRequestId() != 7 || string(f.GetResult().GetPayload()) != "new" {
		t.Fatalf("old completion stole reused ID: %v", f)
	}
}

func TestHostAuthorizeDenyVsExplicitAllow(t *testing.T) {
	var effects int
	var mu sync.Mutex
	cfg := testHostConfig()
	cfg.Authorize = func(ctx context.Context, principal string, method string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if principal == "test-principal" && method == "/example.Echo/Echo" {
			return nil
		}
		return NewRpcError(ErrorCodePermissionDenied, "private-policy-details")
	}
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		mu.Lock()
		effects++
		mu.Unlock()
		return echoHandler(ctx, req)
	}
	p := newRawSessionPeer(t, cfg, nil)
	// Allowed method executes.
	p.request(t, 1, "/example.Echo/Echo")
	if f := p.recv(t); f.GetRequestId() != 1 || !validSuccess(f.GetResult()) {
		t.Fatalf("allowed call denied: %v", f)
	}
	// Denied method answers generic PermissionDenied without oracle and
	// without handler effects; connection stays usable.
	p.request(t, 2, "/example.KV/Put")
	f := p.recv(t)
	assertTerminalCode(t, f, 2, ErrorCodePermissionDenied)
	if msg := f.GetResult().GetError().GetMessage(); msg == "private-policy-details" || msg == "" {
		t.Fatalf("authorize leak or empty message: %q", msg)
	}
	mu.Lock()
	if effects != 1 {
		t.Fatalf("denied call executed handler effects: %d", effects)
	}
	mu.Unlock()
	p.request(t, 3, "/example.Echo/Echo")
	if f := p.recv(t); f.GetRequestId() != 3 || !validSuccess(f.GetResult()) {
		t.Fatalf("connection unusable after deny: %v", f)
	}
}

func TestHostAuthorizeUnauthenticatedMapsGeneric(t *testing.T) {
	cfg := testHostConfig()
	cfg.Authorize = func(ctx context.Context, principal string, method string) error {
		return NewRpcError(ErrorCodeUnauthenticated, "private-auth-details")
	}
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		t.Error("denied handler must not execute")
		return echoHandler(ctx, req)
	}
	p := newRawSessionPeer(t, cfg, nil)
	p.request(t, 1, "/example.Echo/Echo")
	f := p.recv(t)
	assertTerminalCode(t, f, 1, ErrorCodeUnauthenticated)
	if msg := f.GetResult().GetError().GetMessage(); msg == "private-auth-details" || msg == "" {
		t.Fatalf("authz leak or empty message: %q", msg)
	}
}

func TestHostAuthorizeNilLegacyAllowVsDenyAll(t *testing.T) {
	// Nil Authorize preserves the legacy allow-everything behavior for
	// backward compatibility (divergent from the Rust fail-closed default).
	p := newRawSessionPeer(t, testHostConfig(), nil)
	p.request(t, 1, "/example.Echo/Echo")
	if f := p.recv(t); !validSuccess(f.GetResult()) {
		t.Fatalf("nil Authorize must allow (legacy): %v", f)
	}
	// DenyAllAuthorize matches the Rust default explicitly.
	cfg := testHostConfig()
	cfg.Authorize = DenyAllAuthorize
	q := newRawSessionPeer(t, cfg, nil)
	q.request(t, 1, "/example.Echo/Echo")
	assertTerminalCode(t, q.recv(t), 1, ErrorCodePermissionDenied)
	// AllowAllAuthorize documents the explicit opt-in to allow.
	cfg.Authorize = AllowAllAuthorize
	r := newRawSessionPeer(t, cfg, nil)
	r.request(t, 1, "/example.Echo/Echo")
	if f := r.recv(t); !validSuccess(f.GetResult()) {
		t.Fatalf("AllowAllAuthorize must allow: %v", f)
	}
}

// hungRecvTransport violates the Transport.Recv context contract after the
// first (handshake) read: it blocks ignoring ctx until release. Teardown
// must still bound the wait instead of hanging Serve forever.
type hungRecvTransport struct {
	Transport
	calls   int
	mu      sync.Mutex
	release chan struct{}
}

func (h *hungRecvTransport) Recv(ctx context.Context) ([]byte, error) {
	h.mu.Lock()
	h.calls++
	first := h.calls == 1
	h.mu.Unlock()
	if first {
		return h.Transport.Recv(ctx)
	}
	<-h.release
	return nil, errors.New("hung released")
}

func TestServeTeardownBoundsNonCooperativeRecv(t *testing.T) {
	a, b := LoopbackPair()
	defer b.Close()
	hung := &hungRecvTransport{Transport: a, release: make(chan struct{})}
	defer close(hung.release)
	h, err := OpenHost(testHostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx, hung) }()
	hello, err := MarshalFrame(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Send(ctx, hello); err != nil {
		t.Fatal(err)
	}
	recvCtx, stop := context.WithTimeout(ctx, 2*time.Second)
	defer stop()
	raw, err := b.Recv(recvCtx)
	if err != nil {
		t.Fatalf("handshake ready missing: %v", err)
	}
	if f, err := UnmarshalFrame(raw); err != nil || BodyKindOf(f) != BodyKindReady {
		t.Fatalf("expected ready, got %v %v", f, err)
	}
	// Serve is now in its pump with a hung second Recv ignoring ctx.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("teardown with hung Recv = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve hung forever on Transport.Recv contract violation; teardown must be bounded by handlerShutdownGrace")
	}
}
