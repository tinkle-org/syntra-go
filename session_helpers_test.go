package syntra

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

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

// echoHandler supplies neutral application behavior for session tests.
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

func testHostConfig() HostConfig {
	return HostConfig{
		MinVersion: 1,
		MaxVersion: 1,
		Policy:     StaticPolicy("test-principal", true),
		Handler:    echoHandler,
		Authorize:  AllowAllAuthorize,
	}
}

// pair returns a handshaken client and host over loopback. Cleanup is also
// registered with the test so early failures join both session pumps.
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
