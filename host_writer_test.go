package syntra

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func awaitHostWriterState(t *testing.T, w *hostWriter, ready func(count, bytes int, accepting bool) bool) {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		w.mu.Lock()
		count, bytes, accepting := w.count, w.bytes, w.accepting
		w.mu.Unlock()
		if ready(count, bytes, accepting) {
			return
		}
		select {
		case <-timer.C:
			t.Fatalf("writer state did not settle: count=%d bytes=%d accepting=%v", count, bytes, accepting)
		case <-tick.C:
		}
	}
}

func hostWriterSignal(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatalf("%s did not progress while the writer was blocked", name)
	}
}

func activeHostWriter(t *testing.T, h *Host) *hostWriter {
	t.Helper()
	// Registration and ready precede creation of the writer. Synchronize by
	// sending an echo, or by waiting for a gated notification before this read.
	h.mu.Lock()
	defer h.mu.Unlock()
	for hc := range h.conns {
		return hc.writer
	}
	t.Fatal("missing host connection")
	return nil
}

func gatedHostWriterPeer(t *testing.T, cfg HostConfig) (*rawSessionPeer, *gatedNotificationTransport, func()) {
	t.Helper()
	gate := &gatedNotificationTransport{entered: make(chan struct{}), release: make(chan struct{})}
	p := newRawSessionPeer(t, cfg, func(tr Transport) Transport { gate.Transport = tr; return gate })
	var once sync.Once
	release := func() { once.Do(func() { close(gate.release) }) }
	t.Cleanup(release)
	if err := p.host.NotifyAll([]byte("writer gate")); err != nil {
		t.Fatal(err)
	}
	hostWriterSignal(t, gate.entered, "notification Send")
	return p, gate, release
}

func TestHostWriterLoopReapsCancelsAndDispatchesDuringStall(t *testing.T) {
	cancelStarted, cancelled := make(chan struct{}), make(chan struct{})
	deadlineStarted, expired := make(chan struct{}), make(chan struct{})
	fast := make(chan struct{}, 2)
	cfg := testHostConfig()
	cfg.WriteTimeout = 10 * time.Second
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		switch req.GetMethod() {
		case "/example.Wait/Cancel":
			close(cancelStarted)
			<-ctx.Done()
			close(cancelled)
			return nil, ctx.Err()
		case "/example.Wait/Deadline":
			close(deadlineStarted)
			<-ctx.Done()
			close(expired)
			return nil, ctx.Err()
		default:
			fast <- struct{}{}
			return NewSuccessResult([]byte("fast")), nil
		}
	}
	p, _, release := gatedHostWriterPeer(t, cfg)
	w := activeHostWriter(t, p.host)
	p.request(t, 1, "/example.Wait/Cancel")
	hostWriterSignal(t, cancelStarted, "first handler")
	p.send(t, NewCancelFrame(1, 1))
	hostWriterSignal(t, cancelled, "peer cancellation")
	awaitHostWriterState(t, w, func(count, _ int, _ bool) bool { return count == 2 })
	p.send(t, NewRequestFrame(1, 2, &RpcRequest{Method: "/example.Wait/Deadline", TimeoutMs: 30}))
	hostWriterSignal(t, deadlineStarted, "deadline handler")
	hostWriterSignal(t, expired, "handler deadline")
	// A terminal deadline frame admitted while Send is held proves that the
	// core/session expiry path progressed, not only the handler's context timer.
	awaitHostWriterState(t, w, func(count, _ int, _ bool) bool { return count == 3 })
	p.request(t, 3, "/example.Echo/Echo")
	hostWriterSignal(t, fast, "subsequent dispatch")
	awaitHostWriterState(t, w, func(count, _ int, _ bool) bool { return count == 4 })
	release()
	if f := p.recv(t); BodyKindOf(f) != BodyKindNotification {
		t.Fatalf("FIFO gate frame = %v", f)
	}
	assertTerminalCode(t, p.recv(t), 1, ErrorCodeCancelled)
	assertTerminalCode(t, p.recv(t), 2, ErrorCodeDeadlineExceeded)
	if f := p.recv(t); f.GetRequestId() != 3 || string(f.GetResult().GetPayload()) != "fast" {
		t.Fatalf("subsequent result = %v", f)
	}
	p.request(t, 4, "/example.Echo/Echo")
	if f := p.recv(t); f.GetRequestId() != 4 || !validSuccess(f.GetResult()) {
		t.Fatalf("duplicate terminal result or broken correlation: %v", f)
	}
}

// writerProbe holds the first Send and records actual completions. It does not
// parse frames, allowing exact byte/count boundary tests without codec overhead.
type writerProbe struct {
	entered chan struct{}
	release chan struct{}
	closed  chan struct{}
	sent    chan []byte
	enter   sync.Once
	close   sync.Once
	active  atomic.Int32
	peak    atomic.Int32
}

func newWriterProbe() *writerProbe {
	return &writerProbe{
		entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}),
		sent: make(chan []byte, hostWriterMaxFrames),
	}
}

func (p *writerProbe) Send(ctx context.Context, raw []byte) error {
	active := p.active.Add(1)
	defer p.active.Add(-1)
	for {
		peak := p.peak.Load()
		if active <= peak || p.peak.CompareAndSwap(peak, active) {
			break
		}
	}
	p.enter.Do(func() { close(p.entered) })
	select {
	case <-p.release:
	case <-p.closed:
		return errors.New("probe closed")
	case <-ctx.Done():
		return ctx.Err()
	}
	copyOfFrame := append([]byte(nil), raw...)
	select {
	case p.sent <- copyOfFrame:
		return nil
	case <-p.closed:
		return errors.New("probe closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *writerProbe) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-p.closed:
		return nil, errors.New("probe closed")
	}
}

func (p *writerProbe) Close() error {
	p.close.Do(func() { close(p.closed) })
	return nil
}

func TestHostWriterFIFOOwnsSnapshotsAndDrainsActualSends(t *testing.T) {
	probe := newWriterProbe()
	w := newHostWriter(probe, 10*time.Second)
	t.Cleanup(func() { _ = w.shutdown() })
	frame := []byte("first")
	if err := w.enqueue(frame); err != nil {
		t.Fatal(err)
	}
	hostWriterSignal(t, probe.entered, "first Send")
	frame[0] = 'X'
	for _, frame := range []string{"second", "third"} {
		if err := w.enqueue([]byte(frame)); err != nil {
			t.Fatal(err)
		}
	}
	drained := make(chan error, 1)
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	go func() { drained <- w.drain(ctx) }()
	awaitHostWriterState(t, w, func(count, _ int, accepting bool) bool { return count == 3 && !accepting })
	select {
	case err := <-drained:
		t.Fatalf("drain acknowledged enqueue before Send completed: %v", err)
	default:
	}
	if err := w.enqueue([]byte("late")); callCode(t, err) != ErrorCodeFailedPrecondition {
		t.Fatalf("sealed admission = %v", err)
	}
	close(probe.release)
	if err := runtimeAwait(t, drained); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"first", "second", "third"} {
		select {
		case got := <-probe.sent:
			if string(got) != want {
				t.Fatalf("FIFO/snapshot = %q, want %q", got, want)
			}
		default:
			t.Fatalf("drain returned before %q was sent", want)
		}
	}
	if probe.peak.Load() != 1 {
		t.Fatalf("concurrent Send calls = %d", probe.peak.Load())
	}
	if err := w.shutdown(); err != nil {
		t.Fatal(err)
	}
	hostWriterSignal(t, w.done, "writer join")
}

func TestHostWriterBoundsIncludeActiveFrameAndDiscardOnShutdown(t *testing.T) {
	for _, bound := range []string{"count", "bytes"} {
		t.Run(bound, func(t *testing.T) {
			probe := newWriterProbe()
			w := newHostWriter(probe, 10*time.Second)
			t.Cleanup(func() { _ = w.shutdown() })
			frame := []byte{1}
			admitted := hostWriterMaxFrames
			if bound == "bytes" {
				frame = make([]byte, MaxFrameBytes/2)
				admitted = hostWriterMaxBytes / len(frame)
			}
			if err := w.enqueue(frame); err != nil {
				t.Fatal(err)
			}
			hostWriterSignal(t, probe.entered, "active Send")
			for i := 1; i < admitted; i++ {
				if err := w.enqueue(frame); err != nil {
					t.Fatalf("frame %d rejected before cap: %v", i, err)
				}
			}
			awaitHostWriterState(t, w, func(count, bytes int, _ bool) bool {
				return count == admitted && bytes == admitted*len(frame)
			})
			if err := w.enqueue([]byte{2}); callCode(t, err) != ErrorCodeResourceExhausted {
				t.Fatalf("saturated admission = %v", err)
			}
			if err := runtimeAwait(t, w.fatal); callCode(t, err) != ErrorCodeResourceExhausted {
				t.Fatalf("saturation fatal = %v", err)
			}
			if err := w.shutdown(); err != nil {
				t.Fatal(err)
			}
			hostWriterSignal(t, w.done, "writer shutdown")
			awaitHostWriterState(t, w, func(count, bytes int, accepting bool) bool {
				return count == 0 && bytes == 0 && !accepting
			})
			if len(w.frames) != 0 || len(probe.sent) != 0 || probe.active.Load() != 0 {
				t.Fatal("shutdown retained or delivered discarded frames, or left Send running")
			}
		})
	}
}

func TestHostWriterSaturationTerminatesServeResourceExhausted(t *testing.T) {
	cfg := testHostConfig()
	cfg.WriteTimeout = 10 * time.Second
	p, _, _ := gatedHostWriterPeer(t, cfg)
	w := activeHostWriter(t, p.host)
	for i := 1; i <= hostWriterMaxFrames; i++ {
		p.request(t, uint64(i), "/example.Echo/Echo")
		if i < hostWriterMaxFrames {
			awaitHostWriterState(t, w, func(count, _ int, _ bool) bool { return count == i+1 })
		}
	}
	err := runtimeAwait(t, p.done)
	p.done <- err
	if callCode(t, err) != ErrorCodeResourceExhausted {
		t.Fatalf("saturation Serve result = %v", err)
	}
	hostWriterSignal(t, w.done, "saturated writer join")
	runtimeAssertPeerClosed(t, p.peer)
}

func TestHostWriterRevocationCancelsCallbacksBeforeBoundedDrain(t *testing.T) {
	for _, releaseWriter := range []bool{true, false} {
		t.Run(map[bool]string{true: "delivered", false: "drain-timeout"}[releaseWriter], func(t *testing.T) {
			authorizing, cancelled := make(chan struct{}), make(chan struct{})
			var effects atomic.Int32
			cfg := testHostConfig()
			cfg.WriteTimeout = 10 * time.Second
			cfg.Authorize = func(ctx context.Context, _, method string) error {
				if method == "/example.Auth/Hold" {
					close(authorizing)
					<-ctx.Done()
					close(cancelled)
					return nil // cancellation must still prevent handler effects
				}
				return NewRpcError(ErrorCodeUnauthenticated, "private revocation details")
			}
			cfg.Handler = func(context.Context, *RpcRequest) (*RpcResult, error) {
				effects.Add(1)
				return NewSuccessResult(nil), nil
			}
			p, _, release := gatedHostWriterPeer(t, cfg)
			w := activeHostWriter(t, p.host)
			p.request(t, 1, "/example.Auth/Hold")
			hostWriterSignal(t, authorizing, "in-flight authorizer")
			p.request(t, 2, "/example.Auth/Revoke")
			hostWriterSignal(t, cancelled, "revoked authorizer cancellation")
			if releaseWriter {
				release()
				if f := p.recv(t); BodyKindOf(f) != BodyKindNotification {
					t.Fatalf("FIFO notification = %v", f)
				}
				assertTerminalCode(t, p.recv(t), 2, ErrorCodeUnauthenticated)
			}
			err := runtimeAwait(t, p.done)
			p.done <- err
			want := ErrorCodeUnavailable
			if releaseWriter {
				want = ErrorCodeUnauthenticated
			}
			if callCode(t, err) != want {
				t.Fatalf("revocation drain = %v, want %v", err, want)
			}
			if effects.Load() != 0 {
				t.Fatal("revoked callback started handler effects")
			}
			hostWriterSignal(t, w.done, "revoked writer join")
			runtimeAssertPeerClosed(t, p.peer)
		})
	}
}

func TestHostWriterGracefulCancellationDrainsOrDiscardsWithinBound(t *testing.T) {
	for _, releaseWriter := range []bool{true, false} {
		t.Run(map[bool]string{true: "drained", false: "discarded"}[releaseWriter], func(t *testing.T) {
			cfg := testHostConfig()
			cfg.WriteTimeout = 10 * time.Second
			h, err := OpenHost(cfg)
			if err != nil {
				t.Fatal(err)
			}
			a, b := LoopbackPair()
			baseCtx, stopBase := context.WithTimeout(context.Background(), 3*time.Second)
			defer stopBase()
			serveCtx, stopServe := context.WithCancel(baseCtx)
			gate := &gatedNotificationTransport{Transport: a, entered: make(chan struct{}), release: make(chan struct{})}
			var once sync.Once
			release := func() { once.Do(func() { close(gate.release) }) }
			p := &rawSessionPeer{host: h, peer: b, ctx: baseCtx, done: make(chan error, 1)}
			t.Cleanup(func() {
				release()
				stopServe()
				_ = h.Close()
				_ = b.Close()
				_ = runtimeAwait(t, p.done)
			})
			go func() { p.done <- h.Serve(serveCtx, gate) }()
			p.send(t, NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
			if f := p.recv(t); BodyKindOf(f) != BodyKindReady {
				t.Fatalf("ready = %v", f)
			}
			if err := h.NotifyAll([]byte("graceful gate")); err != nil {
				t.Fatal(err)
			}
			hostWriterSignal(t, gate.entered, "graceful Send")
			w := activeHostWriter(t, h)
			p.request(t, 1, "/example.Echo/Echo")
			awaitHostWriterState(t, w, func(count, _ int, _ bool) bool { return count == 2 })
			stopServe()
			if releaseWriter {
				release()
				if f := p.recv(t); BodyKindOf(f) != BodyKindNotification {
					t.Fatalf("graceful FIFO = %v", f)
				}
				if f := p.recv(t); f.GetRequestId() != 1 || !validSuccess(f.GetResult()) {
					t.Fatalf("graceful terminal result = %v", f)
				}
			}
			err = runtimeAwait(t, p.done)
			p.done <- err
			if err != nil {
				t.Fatalf("graceful Serve = %v", err)
			}
			hostWriterSignal(t, w.done, "graceful writer join")
			runtimeAssertPeerClosed(t, b)
			if !releaseWriter {
				// Clean shutdown is not delivery acknowledgement: an unfinished
				// writer drain must still fail after its frames were discarded.
				if err := w.drain(context.Background()); callCode(t, err) != ErrorCodeUnavailable {
					t.Fatalf("discarded frames acknowledged as delivered: %v", err)
				}
			}
		})
	}
}
