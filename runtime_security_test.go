package syntra

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

type runtimeCloseTransport struct {
	Transport
	closes atomic.Int32
}

func (t *runtimeCloseTransport) Close() error {
	t.closes.Add(1)
	return t.Transport.Close()
}

type runtimeChannelTransport struct {
	Transport
	identity ChannelIdentity
	confirm  bool
	received atomic.Bool
}

func (t *runtimeChannelTransport) Recv(ctx context.Context) ([]byte, error) {
	raw, err := t.Transport.Recv(ctx)
	if err == nil {
		t.received.Store(true)
	}
	return raw, err
}

func (t *runtimeChannelTransport) ChannelIdentity() (ChannelIdentity, bool) {
	return t.identity, t.confirm && t.received.Load()
}

func runtimeAwait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("session failed to terminate")
		return nil
	}
}

func runtimeAssertPeerClosed(t *testing.T, peer Transport) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if raw, err := peer.Recv(ctx); err == nil || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("peer must observe terminal closure, got bytes=%d err=%v", len(raw), err)
	}
}

func TestRuntimeChannelPolicyRequiresFreshConfirmation(t *testing.T) {
	for _, scenario := range []string{"missing-provider", "unconfirmed", "confirmed", "empty-principal"} {
		t.Run(scenario, func(t *testing.T) {
			identity := ChannelIdentity{Mode: "device", Carrier: "test", Scope: "scope", Handle: [8]byte{1}, Epoch: 9, Principal: "device-principal"}
			a, b := LoopbackPair()
			defer b.Close()
			counted := &runtimeCloseTransport{Transport: a}
			var tr Transport = counted
			if scenario != "missing-provider" {
				tr = &runtimeChannelTransport{Transport: counted, identity: identity, confirm: scenario != "unconfirmed"}
			}
			var calls atomic.Int32
			cfg := testHostConfig()
			cfg.Policy = func(context.Context, []byte) (string, error) {
				t.Error("credential policy used despite configured channel policy")
				return "fallback", nil
			}
			cfg.ChannelPolicy = func(ctx context.Context, got ChannelIdentity, credential []byte) (string, error) {
				calls.Add(1)
				if got != identity || string(credential) != "explicit" || ctx.Err() != nil {
					t.Errorf("channel policy inputs = %+v, %q, %v", got, credential, ctx.Err())
				}
				if scenario == "empty-principal" {
					return "", nil
				}
				return "verified-principal", nil
			}
			h, err := OpenHost(cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer h.Close()
			ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			done := make(chan error, 1)
			go func() { done <- h.Serve(ctx, tr) }()
			raw, err := MarshalFrame(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1, Credential: []byte("explicit")}, 1))
			if err != nil {
				t.Fatal(err)
			}
			if err := b.Send(ctx, raw); err != nil {
				t.Fatal(err)
			}
			if scenario == "confirmed" {
				raw, err := b.Recv(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if f, err := UnmarshalFrame(raw); err != nil || BodyKindOf(f) != BodyKindReady {
					t.Fatalf("expected ready, got %v %v", f, err)
				}
				if err := h.DisconnectPrincipal("verified-principal"); err != nil {
					t.Fatal(err)
				}
				_ = runtimeAwait(t, done)
			} else if err := runtimeAwait(t, done); callCode(t, err) != ErrorCodeUnauthenticated {
				t.Fatalf("unconfirmed/invalid channel accepted: %v", err)
			}
			wantCalls := int32(0)
			if scenario == "confirmed" || scenario == "empty-principal" {
				wantCalls = 1
			}
			if calls.Load() != wantCalls || counted.closes.Load() != 1 {
				t.Fatalf("policy calls=%d closes=%d", calls.Load(), counted.closes.Load())
			}
			runtimeAssertPeerClosed(t, b)
		})
	}
}

func TestRuntimeEmptyCredentialDoesNotInferChannelPrincipal(t *testing.T) {
	var calls atomic.Int32
	cfg := testHostConfig()
	cfg.ChannelPolicy = nil
	cfg.Policy = func(_ context.Context, credential []byte) (string, error) {
		calls.Add(1)
		if len(credential) != 0 {
			t.Error("expected explicit empty credential")
		}
		return "", NewRpcError(ErrorCodeUnauthenticated, "credential required")
	}
	h, err := OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	a, b := LoopbackPair()
	defer b.Close()
	tr := &runtimeChannelTransport{Transport: a, identity: ChannelIdentity{Mode: "device", Principal: "must-not-bind"}, confirm: true}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx, tr) }()
	raw, _ := MarshalFrame(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if err := b.Send(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if err := runtimeAwait(t, done); callCode(t, err) != ErrorCodeUnauthenticated || calls.Load() != 1 {
		t.Fatalf("credential policy bypass: calls=%d err=%v", calls.Load(), err)
	}
	runtimeAssertPeerClosed(t, b)
}

func TestRuntimeNilAuthorizeHasNoHandlerEffects(t *testing.T) {
	var effects atomic.Int32
	cfg := testHostConfig()
	cfg.Authorize = nil
	cfg.Handler = func(context.Context, *RpcRequest) (*RpcResult, error) {
		effects.Add(1)
		return NewSuccessResult(nil), nil
	}
	p := newRawSessionPeer(t, cfg, nil)
	for id := uint64(1); id <= 2; id++ {
		p.request(t, id, "/example.Echo/Echo")
		assertTerminalCode(t, p.recv(t), id, ErrorCodePermissionDenied)
	}
	if effects.Load() != 0 {
		t.Fatal("nil authorization allowed handler effects")
	}
}

func TestRuntimeHandlerAcceptsErrorResult(t *testing.T) {
	cfg := testHostConfig()
	cfg.Handler = func(context.Context, *RpcRequest) (*RpcResult, error) {
		return NewWireErrorResult(ErrorCodeNotFound, "application result"), nil
	}
	p := newRawSessionPeer(t, cfg, nil)
	p.request(t, 1, "/example.Echo/Echo")
	f := p.recv(t)
	assertTerminalCode(t, f, 1, ErrorCodeNotFound)
	if f.GetResult().GetError().GetMessage() != "application result" {
		t.Fatalf("handler error result replaced: %v", f)
	}
}

func TestRuntimeHostWriteStallTerminatesAndClosesPeer(t *testing.T) {
	cfg := testHostConfig()
	cfg.WriteTimeout = 25 * time.Millisecond
	gate := &gatedNotificationTransport{entered: make(chan struct{}), release: make(chan struct{})}
	p := newRawSessionPeer(t, cfg, func(tr Transport) Transport { gate.Transport = tr; return gate })
	if err := p.host.NotifyAll([]byte("stalled")); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, gate.entered, "stalled host send")
	err := runtimeAwait(t, p.done)
	p.done <- err
	if callCode(t, err) != ErrorCodeUnavailable {
		t.Fatalf("stalled write = %v", err)
	}
	runtimeAssertPeerClosed(t, p.peer)
	if cfg, err := resolveHostConfig(HostConfig{}); err != nil || cfg.writeTimeout != 5*time.Second {
		t.Fatalf("default write timeout = %v, %v", cfg.writeTimeout, err)
	}
	if _, err := OpenHost(HostConfig{WriteTimeout: -time.Second}); callCode(t, err) != ErrorCodeInvalidArgument {
		t.Fatalf("negative write timeout = %v", err)
	}
}

func TestRuntimeHostTerminalPathsCloseExactlyOnce(t *testing.T) {
	for _, terminal := range []string{"fatal", "shutdown", "revoked"} {
		t.Run(terminal, func(t *testing.T) {
			cfg := testHostConfig()
			if terminal == "revoked" {
				cfg.Authorize = func(context.Context, string, string) error {
					return NewRpcError(ErrorCodeUnauthenticated, "private")
				}
			}
			var tr *runtimeCloseTransport
			p := newRawSessionPeer(t, cfg, func(base Transport) Transport {
				tr = &runtimeCloseTransport{Transport: base}
				return tr
			})
			switch terminal {
			case "fatal":
				p.send(t, NewReadyFrame(1, &ServerReady{ConnectionId: "forbidden"}))
			case "shutdown":
				if err := p.host.Close(); err != nil {
					t.Fatal(err)
				}
			case "revoked":
				p.request(t, 1, "/example.Echo/Echo")
				assertTerminalCode(t, p.recv(t), 1, ErrorCodeUnauthenticated)
			}
			err := runtimeAwait(t, p.done)
			p.done <- err
			runtimeAssertPeerClosed(t, p.peer)
			_ = p.host.Close()
			if tr.closes.Load() != 1 {
				t.Fatalf("terminal close count = %d", tr.closes.Load())
			}
		})
	}
}

func TestRuntimeClientTerminalPathsCloseExactlyOnce(t *testing.T) {
	for _, terminal := range []string{"bad-ready", "fatal", "cancel", "close"} {
		t.Run(terminal, func(t *testing.T) {
			c, err := OpenClient(testClientConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			a, b := LoopbackPair()
			defer b.Close()
			tr := &runtimeCloseTransport{Transport: a}
			ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
			defer stop()
			done := make(chan error, 1)
			go func() { done <- c.Run(ctx, tr) }()
			if _, err := b.Recv(ctx); err != nil {
				t.Fatal(err)
			}
			ready := NewReadyFrame(1, &ServerReady{ConnectionId: "test"})
			if terminal == "bad-ready" {
				ready = NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1)
			}
			raw, _ := MarshalFrame(ready)
			if err := b.Send(ctx, raw); err != nil {
				t.Fatal(err)
			}
			if terminal != "bad-ready" {
				awaitSignal(t, c.activated, "client activation")
				switch terminal {
				case "fatal":
					if err := b.Send(ctx, raw); err != nil {
						t.Fatal(err)
					}
				case "cancel":
					stop()
				case "close":
					if err := c.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			err = runtimeAwait(t, done)
			if terminal == "close" && err != nil {
				t.Fatalf("Client.Close must produce a clean Run shutdown: %v", err)
			}
			runtimeAssertPeerClosed(t, b)
			_ = c.Close()
			if tr.closes.Load() != 1 {
				t.Fatalf("terminal close count = %d", tr.closes.Load())
			}
		})
	}
}

func TestRuntimeDisconnectPrincipalClosesIdleAndActiveOnly(t *testing.T) {
	started, cancelled := make(chan struct{}), make(chan struct{})
	cfg := testHostConfig()
	cfg.Policy = func(_ context.Context, credential []byte) (string, error) { return string(credential), nil }
	cfg.Handler = func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
		if req.GetMethod() == "/example.Slow/Wait" {
			close(started)
			<-ctx.Done()
			close(cancelled)
			return nil, ctx.Err()
		}
		return echoHandler(ctx, req)
	}
	h, err := OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	var peers []Transport
	var done []chan error
	for _, principal := range []string{"alice", "alice", "bob"} {
		a, b := LoopbackPair()
		defer b.Close()
		ch := make(chan error, 1)
		done = append(done, ch)
		peers = append(peers, b)
		go func() { ch <- h.Serve(ctx, a) }()
		raw, _ := MarshalFrame(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1, Credential: []byte(principal)}, 1))
		if err := b.Send(ctx, raw); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Recv(ctx); err != nil {
			t.Fatal(err)
		}
	}
	active := &rawSessionPeer{peer: peers[1], ctx: ctx}
	active.request(t, 1, "/example.Slow/Wait")
	awaitSignal(t, started, "active handler")
	if err := h.DisconnectPrincipal("alice"); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, cancelled, "revoked handler cancellation")
	for i := 0; i < 2; i++ {
		_ = runtimeAwait(t, done[i])
		runtimeAssertPeerClosed(t, peers[i])
	}
	other := &rawSessionPeer{peer: peers[2], ctx: ctx}
	other.request(t, 1, "/example.Echo/Echo")
	if f := other.recv(t); !validSuccess(f.GetResult()) {
		t.Fatalf("unrelated principal disconnected: %v", f)
	}
	if err := h.NotifyDirected("bob", []byte("push")); err != nil {
		t.Fatal(err)
	}
	if f := other.recv(t); string(f.GetNotification().GetPayload()) != "push" {
		t.Fatalf("unrelated push failed: %v", f)
	}
	_ = h.Close()
	_ = runtimeAwait(t, done[2])
}

func TestRuntimeCredentialOwnershipAndRelease(t *testing.T) {
	credential := []byte("caller-owned")
	want := bytes.Clone(credential)
	c, err := OpenClient(ClientConfig{Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	credential[0] = 'X'
	if !bytes.Equal(c.cfg.credential, want) {
		t.Fatal("client retained caller credential buffer")
	}
	a, b := LoopbackPair()
	defer b.Close()
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx, a) }()
	raw, err := b.Recv(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f, err := UnmarshalFrame(raw)
	if err != nil || !bytes.Equal(f.GetHello().GetCredential(), want) {
		t.Fatalf("hello credential not owned: %v %v", f, err)
	}
	c.mu.Lock()
	retained := len(c.cfg.credential)
	c.mu.Unlock()
	if retained != 0 {
		t.Fatal("Client config retained credential after hello emission")
	}
	_ = c.Close()
	_ = runtimeAwait(t, done)
	if credential[0] != 'X' || !bytes.Equal(credential[1:], want[1:]) {
		t.Fatal("runtime wiped caller credential buffer")
	}
}

func TestRuntimeSessionVersionAndRehandshakeCodes(t *testing.T) {
	if _, err := NegotiateVersionRanges(2, 2, 1, 1); callCode(t, err) != ErrorCodeFailedPrecondition {
		t.Fatalf("disjoint version code = %v", err)
	}
	for _, f := range []*Frame{
		NewReadyFrame(2, &ServerReady{ConnectionId: "unsupported"}),
		NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1),
		NewReadyFrame(1, &ServerReady{ConnectionId: "repeated"}),
	} {
		raw, err := proto.Marshal(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateActiveSessionFrame(raw, 1); callCode(t, err) != ErrorCodeFailedPrecondition {
			t.Fatalf("active version/state code = %v", err)
		}
	}
	raw, _ := proto.Marshal(NewReadyFrame(2, &ServerReady{ConnectionId: "outside-proposal"}))
	if _, err := activateFrame(raw, 1, 1); callCode(t, err) != ErrorCodeFailedPrecondition {
		t.Fatalf("ready version code = %v", err)
	}
}

func TestRuntimePureGoCompletionTimestampSurvivesReap(t *testing.T) {
	if NativeAvailable() {
		t.Skip("native ABI v1 cannot accept callback completion timestamps")
	}
	cfg, err := resolveHostConfig(testHostConfig())
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
	for _, late := range []bool{false, true} {
		id := uint64(1)
		if late {
			id = 2
		}
		raw, _ := MarshalFrame(NewRequestFrame(1, id, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 1000}))
		if _, _, fatal := core.onFrame(raw); fatal != nil {
			t.Fatal(fatal)
		}
		at := time.Now()
		if late {
			at = at.Add(time.Hour)
		}
		core.(completionRecorder).recordCompletion(id, at)
		if !late {
			if ids := core.reapExpired(time.Now().Add(time.Hour)); len(ids) != 0 {
				t.Fatalf("on-time completion reaped: %v", ids)
			}
		}
		result := NewWireErrorResult(ErrorCodeNotFound, "completed")
		frame, expired, err := core.answer(id, result)
		if err != nil || expired != late {
			t.Fatalf("completion arbitration late=%v expired=%v err=%v", late, expired, err)
		}
		if !late {
			f, err := UnmarshalFrame(frame)
			if err != nil {
				t.Fatal(err)
			}
			assertTerminalCode(t, f, id, ErrorCodeNotFound)
		}
	}
}

func TestRuntimePureGoNotificationByteBacklogBound(t *testing.T) {
	if NativeAvailable() {
		t.Skip("pure-Go notification backlog admission")
	}
	cfg, err := resolveHostConfig(testHostConfig())
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
	payload := make([]byte, MaxFrameBytes/2)
	accepted := 0
	for accepted < 256 {
		err := core.notify(payload)
		if err != nil {
			if callCode(t, err) != ErrorCodeResourceExhausted {
				t.Fatal(err)
			}
			break
		}
		accepted++
	}
	if accepted == 0 || accepted == 256 {
		t.Fatalf("byte cap did not constrain admission before count cap: %d", accepted)
	}
	count, total := 0, 0
	for {
		frame, ok := core.nextOutbound()
		if !ok {
			break
		}
		count++
		total += len(frame)
	}
	if count != accepted || total > 8*MaxFrameBytes {
		t.Fatalf("backlog count=%d accepted=%d bytes=%d", count, accepted, total)
	}
	if err := core.notify(payload); err != nil {
		t.Fatalf("notification admission failed to recover after drain: %v", err)
	}
}

func TestRuntimePureGoPublishedCompletionSurvivesBlockedWriter(t *testing.T) {
	if NativeAvailable() {
		t.Skip("native ABI v1 arbitrates at answer time")
	}
	gate := &gatedNotificationTransport{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(gate.release) }) })
	started, returnResult := make(chan struct{}), make(chan struct{})
	cfg := testHostConfig()
	cfg.Handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
		close(started)
		select {
		case <-returnResult:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return NewWireErrorResult(ErrorCodeNotFound, "on-time"), nil
	}
	p := newRawSessionPeer(t, cfg, func(tr Transport) Transport { gate.Transport = tr; return gate })
	p.send(t, NewRequestFrame(1, 1, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 500}))
	awaitSignal(t, started, "handler start")
	if err := p.host.NotifyAll([]byte("gate")); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, gate.entered, "writer gate")
	p.host.mu.Lock()
	var hc *hostConn
	for conn := range p.host.conns {
		hc = conn
	}
	p.host.mu.Unlock()
	if hc == nil {
		t.Fatal("missing connection")
	}
	close(returnResult)
	awaitHostWriterState(t, hc.writer, func(count, _ int, _ bool) bool { return count == 2 })
	// Keep the writer blocked until the wire deadline is certainly in the past.
	timer := time.NewTimer(550 * time.Millisecond)
	defer timer.Stop()
	<-timer.C
	release.Do(func() { close(gate.release) })
	if f := p.recv(t); BodyKindOf(f) != BodyKindNotification {
		t.Fatalf("gate = %v", f)
	}
	assertTerminalCode(t, p.recv(t), 1, ErrorCodeNotFound)
}
