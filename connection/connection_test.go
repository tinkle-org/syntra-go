package connection_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

const echoMethod = "/example.Echo/Echo"

func hostConfig() syntra.HostConfig {
	return syntra.HostConfig{
		ChannelPolicy: func(_ context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			if id.Scope != "memory" || id.Principal != "device" || string(credential) != "explicit" {
				return "", syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "denied")
			}
			return "verified", nil
		},
		Authorize: syntra.AllowAllAuthorize,
		Handler: func(_ context.Context, request *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return syntra.NewSuccessResult(request.GetPayload()), nil
		},
	}
}

func fixture(t *testing.T, cfg syntra.HostConfig, options connection.ServerOptions) (securechannel.ClientConfig, *connection.Server) {
	t.Helper()
	cc, sc, err := channelConfigs(securechannel.Returning)
	if err != nil {
		t.Fatal(err)
	}
	s, err := connection.NewServer(cfg, sc, options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return cc, s
}

func join(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(4 * time.Second):
		t.Fatal("worker did not join")
		return nil
	}
}

func await(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(4 * time.Second):
		t.Fatal("signal did not arrive")
	}
}

func echo(t *testing.T, c *connection.Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := c.Call(ctx, echoMethod, []byte("echo"), 0)
	if err != nil || string(got) != "echo" {
		t.Fatalf("echo = %q, %v", got, err)
	}
}

func TestClientOwnedLifetime(t *testing.T) {
	cc, server := fixture(t, hostConfig(), connection.ServerOptions{})
	a, b := recordPair()
	accepted := make(chan error, 1)
	go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
	ctx, cancel := context.WithCancel(context.Background())
	client, err := connection.Connect(ctx, a, cc, syntra.ClientConfig{Credential: []byte("explicit")}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	cancel()
	echo(t, client)
	if err := server.Host.NotifyAll([]byte("push")); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-client.Notifications():
		if string(n.GetPayload()) != "push" {
			t.Fatal("wrong notification")
		}
	case <-time.After(time.Second):
		t.Fatal("missing notification")
	}
	waitCtx, stop := context.WithCancel(context.Background())
	stop()
	if err := client.Wait(waitCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait = %v", err)
	}
	echo(t, client)
	var closes sync.WaitGroup
	for i := 0; i < 8; i++ {
		closes.Add(1)
		go func() {
			defer closes.Done()
			if err := client.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	closes.Wait()
	await(t, client.Done())
	if err := client.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := <-client.Notifications(); ok {
		t.Fatal("notifications not closed")
	}
	if a.closes.Load() != 1 {
		t.Fatalf("carrier closed %d times", a.closes.Load())
	}
	join(t, accepted)
}

func TestConnectFailureOwnsCarrier(t *testing.T) {
	cc, _, err := channelConfigs(securechannel.Returning)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"canceled", "options", "core", "security", "handshake"} {
		t.Run(name, func(t *testing.T) {
			a, b := recordPair()
			defer b.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			options, core, security := testOptions(), syntra.ClientConfig{}, cc
			switch name {
			case "canceled":
				cancel()
			case "options":
				options.MaxPending = -1
			case "core":
				core.NotifyBuffer = -1
			case "security":
				security.ServerPublicKey = [32]byte{}
			case "handshake":
				options.HandshakeTimeout = 20 * time.Millisecond
			}
			client, err := connection.Connect(ctx, a, security, core, options)
			if client != nil || err == nil {
				t.Fatalf("Connect = %v, %v", client, err)
			}
			if a.closes.Load() != 1 {
				t.Fatalf("carrier closed %d times", a.closes.Load())
			}
			if name == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if name == "handshake" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
		})
	}
}

func TestReadinessFailureAndDefaultAuthorization(t *testing.T) {
	for _, name := range []string{"policy", "credential", "version", "authorization"} {
		t.Run(name, func(t *testing.T) {
			cfg := hostConfig()
			var handled atomic.Int32
			cfg.Handler = func(_ context.Context, request *syntra.RpcRequest) (*syntra.RpcResult, error) {
				handled.Add(1)
				return syntra.NewSuccessResult(request.GetPayload()), nil
			}
			if name == "policy" {
				cfg.ChannelPolicy = func(context.Context, syntra.ChannelIdentity, []byte) (string, error) {
					return "", errors.New("private-policy-diagnostic")
				}
			}
			if name == "authorization" {
				cfg.Authorize = nil
			}
			cc, server := fixture(t, cfg, connection.ServerOptions{})
			a, b := recordPair()
			accepted := make(chan error, 1)
			go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
			core := syntra.ClientConfig{Credential: []byte("explicit")}
			if name == "credential" {
				core.Credential = nil
			}
			if name == "version" {
				core.MinVersion, core.MaxVersion = 2, 2
			}
			client, err := connection.Connect(context.Background(), a, cc, core, testOptions())
			if name == "authorization" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = client.Call(context.Background(), echoMethod, nil, 0)
				var rpc *syntra.RpcError
				if !errors.As(err, &rpc) || rpc.Code != syntra.ErrorCodePermissionDenied || handled.Load() != 0 {
					t.Fatalf("authorization = %v, handler calls = %d", err, handled.Load())
				}
				_ = client.Close()
			} else if client != nil || err == nil {
				t.Fatalf("readiness unexpectedly succeeded: %v", err)
			}
			serverErr := join(t, accepted)
			if strings.Contains(err.Error(), "private-policy-diagnostic") || (serverErr != nil && strings.Contains(serverErr.Error(), "private-policy-diagnostic")) {
				t.Fatal("policy diagnostic escaped")
			}
			if a.closes.Load() != 1 || b.closes.Load() != 1 {
				t.Fatalf("close counts = %d, %d", a.closes.Load(), b.closes.Load())
			}
		})
	}
}

func TestServerAdmissionAndCloseDuringHandshake(t *testing.T) {
	_, server := fixture(t, hostConfig(), connection.ServerOptions{MaxConnections: 1})
	a, b := recordPair()
	defer a.Close()
	accepted := make(chan error, 1)
	go func() { accepted <- server.Accept(context.Background(), b, testOptions()) }()
	await(t, b.reading)
	c, d := recordPair()
	defer c.Close()
	if err := server.Accept(context.Background(), d, testOptions()); !errors.Is(err, ordered.ErrBusy) {
		t.Fatalf("admission = %v", err)
	}
	if d.closes.Load() != 1 {
		t.Fatal("rejected carrier not closed")
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	await(t, server.Done())
	join(t, accepted)
	if b.closes.Load() != 1 {
		t.Fatal("handshake carrier not closed exactly once")
	}
	e, f := recordPair()
	defer e.Close()
	if err := server.Accept(context.Background(), f, testOptions()); !errors.Is(err, connection.ErrClosed) || f.closes.Load() != 1 {
		t.Fatalf("closed admission = %v; closes = %d", err, f.closes.Load())
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptCancellationLeavesHostOwnedByCaller(t *testing.T) {
	cc, sc, err := channelConfigs(securechannel.Returning)
	if err != nil {
		t.Fatal(err)
	}
	host, err := syntra.OpenHost(hostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	for i := 0; i < 2; i++ {
		a, b := recordPair()
		ctx, cancel := context.WithCancel(context.Background())
		accepted := make(chan error, 1)
		go func() { accepted <- connection.Accept(ctx, b, sc, host, testOptions()) }()
		client, err := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{Credential: []byte("explicit")}, testOptions())
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		echo(t, client)
		cancel()
		join(t, accepted)
		await(t, client.Done())
		if err := client.Wait(context.Background()); err == nil {
			t.Fatal("remote shutdown was reported as local Close")
		}
		_ = client.Close()
	}
}

func TestAcceptFailureOwnsCarrier(t *testing.T) {
	_, sc, err := channelConfigs(securechannel.Returning)
	if err != nil {
		t.Fatal(err)
	}
	host, err := syntra.OpenHost(hostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	for _, name := range []string{"host", "options", "security", "canceled"} {
		t.Run(name, func(t *testing.T) {
			a, b := recordPair()
			defer a.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			h, security, opts := host, sc, testOptions()
			switch name {
			case "host":
				h = nil
			case "options":
				opts.MaxPending = -1
			case "security":
				security.Scope = ""
			case "canceled":
				cancel()
			}
			if err := connection.Accept(ctx, b, security, h, opts); err == nil || b.closes.Load() != 1 {
				t.Fatalf("Accept = %v; closes = %d", err, b.closes.Load())
			}
		})
	}
	if err := connection.Accept(context.Background(), nil, sc, host, testOptions()); !errors.Is(err, connection.ErrConfig) {
		t.Fatal(err)
	}
	if client, err := connection.Connect(context.Background(), nil, securechannel.ClientConfig{}, syntra.ClientConfig{}, testOptions()); client != nil || !errors.Is(err, connection.ErrConfig) {
		t.Fatalf("nil carrier Connect = %v, %v", client, err)
	}
}

func TestServerConfiguration(t *testing.T) {
	_, sc, err := channelConfigs(securechannel.Returning)
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []connection.ServerOptions{
		{MaxConnections: -1}, {MaxConnections: 4097},
		{ShutdownTimeout: -1}, {ShutdownTimeout: 6 * time.Second},
	} {
		if s, err := connection.NewServer(hostConfig(), sc, opts); s != nil || !errors.Is(err, connection.ErrConfig) {
			t.Fatalf("NewServer(%+v) = %v, %v", opts, s, err)
		}
	}
	cfg := hostConfig()
	cfg.ChannelPolicy = nil
	cfg.Policy = syntra.StaticPolicy("implicit", true)
	if s, err := connection.NewServer(cfg, sc, connection.ServerOptions{}); s != nil || !errors.Is(err, connection.ErrConfig) {
		t.Fatalf("missing channel policy = %v, %v", s, err)
	}
}

type heldCloseCarrier struct {
	ordered.MessageIO
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *heldCloseCarrier) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return c.MessageIO.Close()
}

func TestShutdownTimeoutRetainsJoinOwner(t *testing.T) {
	_, server := fixture(t, hostConfig(), connection.ServerOptions{ShutdownTimeout: 20 * time.Millisecond})
	a, b := recordPair()
	defer a.Close()
	held := &heldCloseCarrier{MessageIO: b, started: make(chan struct{}), release: make(chan struct{})}
	// Release even when an assertion fails, before fixture cleanup joins again.
	var released sync.Once
	release := func() { released.Do(func() { close(held.release) }) }
	defer release()
	accepted := make(chan error, 1)
	go func() { accepted <- server.Accept(context.Background(), held, testOptions()) }()
	await(t, b.reading)
	if err := server.Close(); !errors.Is(err, connection.ErrShutdownTimeout) {
		t.Fatalf("blocked Close = %v", err)
	}
	await(t, held.started)
	select {
	case <-server.Done():
		t.Fatal("Done closed before carrier cleanup joined")
	default:
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Wait = %v", err)
	}
	release()
	join(t, accepted)
	await(t, server.Done())
	if err := server.Close(); err != nil {
		t.Fatalf("completed Close = %v", err)
	}
	if b.closes.Load() != 1 {
		t.Fatalf("carrier closed %d times", b.closes.Load())
	}
}
