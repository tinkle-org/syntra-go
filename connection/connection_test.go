package connection

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wirews "github.com/coder/websocket"
	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	ws "github.com/tinkle-org/syntra-go/transport/websocket"
)

const echoMethod = "/example.Echo/Echo"

func configs(t *testing.T, carrier securechannel.Carrier) (securechannel.ClientConfig, securechannel.ServerConfig, syntra.HostConfig) {
	t.Helper()
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := securechannel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	client := securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Returning, Carrier: carrier, Scope: "connection-test", Epoch: 9, Handle: [8]byte{1}}, ServerPublicKey: key.Public(), AuthorizationKey: psk}
	server := securechannel.ServerConfig{StaticKey: key, Scope: client.Context.Scope, Carrier: carrier,
		Lookup: func(ctx context.Context, _ securechannel.Context) (securechannel.Enrollment, error) {
			if err := ctx.Err(); err != nil {
				return securechannel.Enrollment{}, err
			}
			return securechannel.Enrollment{Key: psk, Principal: "device", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}}
	host := syntra.HostConfig{
		ChannelPolicy: func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if id.Principal != "device" || id.Carrier != carrier.String() || id.Scope != client.Context.Scope || string(credential) != "explicit" {
				return "", errors.New("invalid binding")
			}
			return "verified", nil
		},
		Authorize: func(_ context.Context, principal, method string) error {
			if principal != "verified" || method != echoMethod {
				return syntra.NewRpcError(syntra.ErrorCodePermissionDenied, "denied")
			}
			return nil
		},
		Handler: func(_ context.Context, req *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return syntra.NewSuccessResult(req.GetPayload()), nil
		},
	}
	return client, server, host
}

func coreConfig() syntra.ClientConfig { return syntra.ClientConfig{Credential: []byte("explicit")} }

func newServer(t *testing.T, hc syntra.HostConfig, sc securechannel.ServerConfig, opts ServerOptions) *Server {
	t.Helper()
	s, err := NewServer(hc, sc, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}

func startTCP(t *testing.T, s *Server, ctx context.Context) (string, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- s.ServeTCP(ctx, l) }()
	return l.Addr().String(), done
}

func join(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not join")
		return nil
	}
}

func echo(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := c.Call(ctx, echoMethod, []byte("complete-echo"), 0)
	if err != nil || string(got) != "complete-echo" {
		t.Fatalf("echo = %q, %v", got, err)
	}
}

func requireCode(t *testing.T, err error, want syntra.ErrorCode) {
	t.Helper()
	var rpc *syntra.RpcError
	if !errors.As(err, &rpc) || rpc.Code != want {
		t.Fatalf("error = %v, want code %v", err, want)
	}
}

func requireDrained(t *testing.T, s *Server) {
	t.Helper()
	select {
	case <-s.Done():
	default:
		t.Fatal("Close returned before Done")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.conns) != 0 || len(s.listeners) != 0 || s.handshakes != 0 {
		t.Fatalf("not joined: connections=%d listeners=%d handshakes=%d", len(s.conns), len(s.listeners), s.handshakes)
	}
}

func TestDialEchoLifetimeAndClose(t *testing.T) {
	for _, carrier := range []securechannel.Carrier{securechannel.TCP, securechannel.WS, securechannel.WSS} {
		t.Run(carrier.String(), func(t *testing.T) {
			cc, sc, hc := configs(t, carrier)
			s := newServer(t, hc, sc, ServerOptions{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var c *Client
			var err error
			var tcpDone <-chan error
			requestCancels := make(chan context.CancelFunc, 1)
			if carrier == securechannel.TCP {
				address, done := startTCP(t, s, context.Background())
				tcpDone = done
				c, err = DialTCP(ctx, address, cc, coreConfig(), ordered.Options{})
			} else {
				handler := s.WebSocketHandler()
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requestCtx, requestCancel := context.WithCancel(r.Context())
					defer requestCancel()
					requestCancels <- requestCancel
					handler.ServeHTTP(w, r.WithContext(requestCtx))
				}))
				if carrier == securechannel.WSS {
					server.StartTLS()
				} else {
					server.Start()
				}
				t.Cleanup(server.Close)
				c, err = DialWebSocket(ctx, "ws"+strings.TrimPrefix(server.URL, "http"), cc, coreConfig(), ws.Options{HTTPClient: server.Client()})
			}
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Close() })
			cancel() // successful connections must outlive the dialing context
			if carrier != securechannel.TCP {
				// Request cancellation must not own an upgraded connection either.
				(<-requestCancels)()
			}
			if err := c.WaitReady(context.Background()); err != nil {
				t.Fatal(err)
			}
			echo(t, c)
			if err := s.Host.NotifyAll([]byte("push")); err != nil {
				t.Fatal(err)
			}
			select {
			case n := <-c.Notifications():
				if string(n.GetPayload()) != "push" {
					t.Fatal("incorrect notification")
				}
			case <-time.After(time.Second):
				t.Fatal("notification not delivered")
			}
			waitCtx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer stop()
			if err := c.Wait(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("live Wait = %v", err)
			}
			echo(t, c) // canceling Wait also must not cancel the connection
			var closes sync.WaitGroup
			for i := 0; i < 4; i++ {
				closes.Add(1)
				go func() {
					defer closes.Done()
					if err := c.Close(); err != nil {
						t.Error(err)
					}
				}()
			}
			closes.Wait()
			if err := c.Wait(context.Background()); err != nil {
				t.Fatal(err)
			}
			// Both activated and done are closed. This must never select ready.
			for i := 0; i < 100; i++ {
				requireCode(t, c.WaitReady(context.Background()), syntra.ErrorCodeFailedPrecondition)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			requireDrained(t, s)
			if tcpDone != nil {
				if err := join(t, tcpDone); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestWaitReadyBeforeRunAndAfterTermination(t *testing.T) {
	var nilClient *syntra.Client
	requireCode(t, nilClient.WaitReady(context.Background()), syntra.ErrorCodeFailedPrecondition)
	requireCode(t, new(syntra.Client).WaitReady(context.Background()), syntra.ErrorCodeFailedPrecondition)
	c, err := syntra.OpenClient(syntra.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := c.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireCode(t, c.WaitReady(context.Background()), syntra.ErrorCodeFailedPrecondition)
}

func TestFailClosed(t *testing.T) {
	t.Run("configuration", func(t *testing.T) {
		_, sc, hc := configs(t, securechannel.TCP)
		anonymous := hc
		anonymous.ChannelPolicy = nil
		anonymous.Policy = syntra.StaticPolicy("anonymous", true)
		if _, err := NewServer(anonymous, sc, ServerOptions{}); !errors.Is(err, ErrConfig) {
			t.Fatal(err)
		}
		for _, opts := range []ServerOptions{{MaxConnections: -1}, {MaxConnections: 4097}, {MaxHandshakes: -1}, {MaxHandshakes: 257}, {ShutdownTimeout: -1}, {ShutdownTimeout: 6 * time.Second}, {TCP: ordered.Options{HandshakeTimeout: 6 * time.Second}}} {
			if s, err := NewServer(hc, sc, opts); err == nil {
				_ = s.Close()
				t.Fatalf("invalid options accepted: %+v", opts)
			}
		}
	})
	for _, mode := range []string{"enrollment", "channel-policy", "authorize"} {
		t.Run(mode, func(t *testing.T) {
			cc, sc, hc := configs(t, securechannel.TCP)
			const secret = "private-policy-diagnostic"
			switch mode {
			case "enrollment":
				sc.Lookup = func(context.Context, securechannel.Context) (securechannel.Enrollment, error) {
					return securechannel.Enrollment{}, errors.New(secret)
				}
			case "channel-policy":
				hc.ChannelPolicy = func(context.Context, syntra.ChannelIdentity, []byte) (string, error) { return "", errors.New(secret) }
			case "authorize":
				hc.Authorize = nil
			}
			s := newServer(t, hc, sc, ServerOptions{})
			address, done := startTCP(t, s, context.Background())
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			c, err := DialTCP(ctx, address, cc, coreConfig(), ordered.Options{})
			if mode == "authorize" {
				if err != nil {
					t.Fatal(err)
				}
				_, err = c.Call(ctx, echoMethod, nil, 0)
				requireCode(t, err, syntra.ErrorCodePermissionDenied)
				_ = c.Close()
			} else if err == nil {
				_ = c.Close()
				t.Fatal("authentication failure accepted")
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatal("sensitive diagnostic exposed")
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := join(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A listener that injects net.Pipe endpoints, including silent and rejected
// sockets, without relying on the kernel listen backlog or socket timing.
type pipeListener struct {
	queue  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{queue: make(chan net.Conn), closed: make(chan struct{})}
}
func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.queue:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.TCPAddr{} }
func (l *pipeListener) inject(t *testing.T) net.Conn {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	select {
	case l.queue <- a:
	case <-time.After(time.Second):
		t.Fatal("Accept not running")
	}
	return b
}

func waitAdmission(t *testing.T, s *Server, count, handshakes int) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		s.mu.Lock()
		matched := len(s.conns) == count && s.handshakes == handshakes
		s.mu.Unlock()
		if matched {
			return
		}
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatal("admission state not reached")
		}
	}
}

func requireEOF(t *testing.T, c net.Conn) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	var scratch [1]byte
	if _, err := c.Read(scratch[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("socket not closed: %v", err)
	}
}

func TestTCPAdmissionAndSilentHandshakeCloseJoins(t *testing.T) {
	for _, limit := range []string{"connections", "handshakes"} {
		t.Run(limit, func(t *testing.T) {
			_, sc, hc := configs(t, securechannel.TCP)
			opts := ServerOptions{MaxConnections: 1, MaxHandshakes: 4}
			if limit == "handshakes" {
				opts.MaxConnections = 4
				opts.MaxHandshakes = 1
			}
			s := newServer(t, hc, sc, opts)
			l := newPipeListener()
			done := make(chan error, 1)
			go func() { done <- s.ServeTCP(context.Background(), l) }()
			first := l.inject(t)
			waitAdmission(t, s, 1, 1)
			rejected := l.inject(t)
			requireEOF(t, rejected)
			waitAdmission(t, s, 1, 1)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			requireEOF(t, first)
			requireDrained(t, s)
			if err := join(t, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHandshakeAdmissionIncludesCoreHello(t *testing.T) {
	cc, sc, hc := configs(t, securechannel.TCP)
	s := newServer(t, hc, sc, ServerOptions{MaxConnections: 4, MaxHandshakes: 1})
	l := newPipeListener()
	done := make(chan error, 1)
	go func() { done <- s.ServeTCP(context.Background(), l) }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	tr, err := tcp.Client(ctx, l.inject(t), cc, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	// SC1 is complete, but no ClientHello was sent: admission remains held.
	waitAdmission(t, s, 1, 1)
	requireEOF(t, l.inject(t))
	c, err := Connect(ctx, tr, coreConfig())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	waitAdmission(t, s, 1, 0)
	echo(t, c)
	// A second SC1 handshake is now admitted while the first session is live.
	tr2, err := tcp.Client(ctx, l.inject(t), cc, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tr2.Close() })
	waitAdmission(t, s, 2, 1)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	requireDrained(t, s)
	if err := join(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestSilentHandshakesExpireAndCloseJoins(t *testing.T) {
	for _, carrier := range []securechannel.Carrier{securechannel.TCP, securechannel.WS} {
		for _, closeEarly := range []bool{false, true} {
			name := carrier.String() + "/timeout"
			if closeEarly {
				name = carrier.String() + "/close"
			}
			t.Run(name, func(t *testing.T) {
				_, sc, hc := configs(t, carrier)
				limit := 40 * time.Millisecond
				if closeEarly {
					limit = 5 * time.Second
				}
				s := newServer(t, hc, sc, ServerOptions{TCP: ordered.Options{HandshakeTimeout: limit}, WebSocket: ws.Options{Limits: ordered.Options{HandshakeTimeout: limit}}})
				if carrier == securechannel.TCP {
					l := newPipeListener()
					done := make(chan error, 1)
					go func() { done <- s.ServeTCP(context.Background(), l) }()
					peer := l.inject(t)
					waitAdmission(t, s, 1, 1)
					if closeEarly {
						if err := s.Close(); err != nil {
							t.Fatal(err)
						}
					}
					requireEOF(t, peer)
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
					if err := join(t, done); err != nil {
						t.Fatal(err)
					}
				} else {
					httpServer := httptest.NewServer(s.WebSocketHandler())
					defer httpServer.Close()
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					peer, _, err := wirews.Dial(ctx, "ws"+strings.TrimPrefix(httpServer.URL, "http"), &wirews.DialOptions{Subprotocols: []string{ws.Subprotocol}})
					if err != nil {
						t.Fatal(err)
					}
					defer peer.CloseNow()
					waitAdmission(t, s, 1, 1)
					if closeEarly {
						if err := s.Close(); err != nil {
							t.Fatal(err)
						}
					}
					if _, _, err := peer.Read(ctx); err == nil {
						t.Fatal("silent peer kept alive")
					}
					if ctx.Err() != nil {
						t.Fatal("silent handshake did not terminate")
					}
					if err := s.Close(); err != nil {
						t.Fatal(err)
					}
				}
				requireDrained(t, s)
			})
		}
	}
}

func TestDialBudgetIncludesSC1AndCoreHello(t *testing.T) {
	cc, sc, hc := configs(t, securechannel.TCP)
	lookup := sc.Lookup
	sc.Lookup = func(ctx context.Context, wire securechannel.Context) (securechannel.Enrollment, error) {
		select {
		case <-time.After(40 * time.Millisecond):
			return lookup(ctx, wire)
		case <-ctx.Done():
			return securechannel.Enrollment{}, ctx.Err()
		}
	}
	policyEntered := make(chan struct{}, 1)
	policy := hc.ChannelPolicy
	hc.ChannelPolicy = func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
		policyEntered <- struct{}{}
		select {
		case <-time.After(100 * time.Millisecond):
			return policy(ctx, id, credential)
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	s := newServer(t, hc, sc, ServerOptions{})
	address, done := startTCP(t, s, context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	c, err := DialTCP(ctx, address, cc, coreConfig(), ordered.Options{})
	if c != nil {
		_ = c.Close()
		t.Fatal("dial exceeded shared budget and succeeded")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("cancellation did not bound dial")
	}
	select {
	case <-policyEntered:
	default:
		t.Fatal("did not reach core hello")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	requireDrained(t, s)
	if err := join(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestServeTCPCancelJoinsActiveAndHalfHandshake(t *testing.T) {
	cc, sc, hc := configs(t, securechannel.TCP)
	s := newServer(t, hc, sc, ServerOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	address, done := startTCP(t, s, ctx)
	dialCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	c, err := DialTCP(dialCtx, address, cc, coreConfig(), ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	waitAdmission(t, s, 2, 1)
	cancel()
	if err := join(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	requireEOF(t, raw)
	requireDrained(t, s)
	if err := c.Wait(dialCtx); err == nil {
		t.Fatal("server shutdown not observed")
	}
}

func TestEnrollmentRecheckFailureClosesIdleClient(t *testing.T) {
	cc, sc, hc := configs(t, securechannel.TCP)
	lookup := sc.Lookup
	var fail atomic.Bool
	sc.Lookup = func(ctx context.Context, wire securechannel.Context) (securechannel.Enrollment, error) {
		if fail.Load() {
			return securechannel.Enrollment{}, errors.New("secret-store-diagnostic")
		}
		return lookup(ctx, wire)
	}
	s := newServer(t, hc, sc, ServerOptions{})
	address, done := startTCP(t, s, context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c, err := DialTCP(ctx, address, cc, coreConfig(), ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	echo(t, c)
	fail.Store(true)
	err = c.Wait(ctx)
	if err == nil || ctx.Err() != nil || strings.Contains(err.Error(), "secret-store-diagnostic") {
		t.Fatalf("recheck did not fail closed: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	requireDrained(t, s)
	if err := join(t, done); err != nil {
		t.Fatal(err)
	}
}

type diagnosticTransport struct {
	syntra.Transport
	fail atomic.Bool
}

func (t *diagnosticTransport) Recv(ctx context.Context) ([]byte, error) {
	raw, err := t.Transport.Recv(ctx)
	if t.fail.Load() {
		return nil, errors.New("sensitive-transport-diagnostic")
	}
	return raw, err
}

func TestConnectOwnsRunAndSanitizesWatcherErrors(t *testing.T) {
	a, b := syntra.LoopbackPair()
	host, err := syntra.OpenHost(syntra.HostConfig{Policy: syntra.StaticPolicy("explicit-test", true), Authorize: syntra.AllowAllAuthorize})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	done := make(chan error, 1)
	go func() { done <- host.Serve(context.Background(), b) }()
	tr := &diagnosticTransport{Transport: a}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, err := Connect(ctx, tr, syntra.ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tr.fail.Store(true)
	if err := host.NotifyAll([]byte("wake")); err != nil {
		t.Fatal(err)
	}
	err = c.Wait(ctx)
	if ctx.Err() != nil {
		t.Fatal("watcher failed to join")
	}
	requireCode(t, err, syntra.ErrorCodeUnavailable)
	if strings.Contains(err.Error(), "sensitive") {
		t.Fatal("watcher leaked diagnostic")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	_ = join(t, done)
}

func TestWebSocketOriginAndSharedAdmission(t *testing.T) {
	_, sc, hc := configs(t, securechannel.WS)
	s := newServer(t, hc, sc, ServerOptions{MaxConnections: 1, WebSocket: ws.Options{OriginPatterns: []string{"allowed.example"}}})
	httpServer := httptest.NewServer(s.WebSocketHandler())
	defer httpServer.Close()
	url := "ws" + strings.TrimPrefix(httpServer.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	peer, _, err := wirews.Dial(ctx, url, &wirews.DialOptions{Subprotocols: []string{ws.Subprotocol}, HTTPHeader: http.Header{"Origin": {"https://allowed.example"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.CloseNow()
	second, response, err := wirews.Dial(ctx, url, &wirews.DialOptions{Subprotocols: []string{ws.Subprotocol}})
	if err == nil {
		second.CloseNow()
		t.Fatal("excess WebSocket upgraded")
	}
	if response == nil || response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("admission status = %v", response)
	}
	_ = peer.CloseNow()
	waitAdmission(t, s, 0, 0)
	denied, response, err := wirews.Dial(ctx, url, &wirews.DialOptions{Subprotocols: []string{ws.Subprotocol}, HTTPHeader: http.Header{"Origin": {"https://denied.example"}}})
	if err == nil {
		denied.CloseNow()
		t.Fatal("disallowed origin upgraded")
	}
	if response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("origin status = %v", response)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	requireDrained(t, s)
}

func TestShutdownBudgetWithUncooperativePolicy(t *testing.T) {
	cc, sc, hc := configs(t, securechannel.TCP)
	entered := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	hc.ChannelPolicy = func(context.Context, syntra.ChannelIdentity, []byte) (string, error) {
		close(entered)
		<-release // deliberate contract violation; shutdown must still be bounded
		return "verified", nil
	}
	s, err := NewServer(hc, sc, ServerOptions{ShutdownTimeout: 25 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	address, done := startTCP(t, s, context.Background())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	dialDone := make(chan error, 1)
	go func() {
		c, err := DialTCP(ctx, address, cc, coreConfig(), ordered.Options{})
		if c != nil {
			_ = c.Close()
		}
		dialDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("policy not entered")
	}
	start := time.Now()
	if err := s.Close(); !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("Close = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Close exceeded budget: %v", elapsed)
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("bounded shutdown did not signal Done")
	}
	if err := join(t, dialDone); err == nil {
		t.Fatal("half-handshake survived shutdown")
	}
	if err := join(t, done); !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("ServeTCP = %v", err)
	}
	releaseOnce.Do(func() { close(release) })
	waitAdmission(t, s, 0, 0) // even the violating callback eventually releases
}

func TestConnectCanceledAndInvalidConfigOwnTransport(t *testing.T) {
	for _, canceled := range []bool{true, false} {
		a, b := syntra.LoopbackPair()
		ctx, cancel := context.WithCancel(context.Background())
		cfg := syntra.ClientConfig{MinVersion: 2, MaxVersion: 1}
		if canceled {
			cancel()
			cfg = syntra.ClientConfig{}
		}
		c, err := Connect(ctx, a, cfg)
		cancel()
		if c != nil || err == nil {
			t.Fatal("invalid establishment accepted")
		}
		if canceled && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		readCtx, stop := context.WithTimeout(context.Background(), time.Second)
		_, recvErr := b.Recv(readCtx)
		stop()
		requireCode(t, recvErr, syntra.ErrorCodeUnavailable)
	}
}
