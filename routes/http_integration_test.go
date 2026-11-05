package routes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/proxy"
	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

func integrationSecurity(t *testing.T, mode securechannel.Mode, carrier securechannel.Carrier) (securechannel.ClientConfig, securechannel.ServerConfig) {
	t.Helper()
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	cc := securechannel.ClientConfig{Context: securechannel.Context{Mode: mode, Carrier: carrier, Scope: "route-http"}, ServerPublicKey: key.Public(), AllowHTTPCandidate: true}
	sc := securechannel.ServerConfig{StaticKey: key, Carrier: carrier, Scope: "route-http", AllowBootstrap: mode == securechannel.Bootstrap, AllowHTTPCandidate: true}
	if mode == securechannel.Returning {
		auth, err := securechannel.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		cc.AuthorizationKey = auth
		cc.Context.Epoch = 1
		cc.Context.Handle = [8]byte{1}
		sc.Lookup = func(ctx context.Context, c securechannel.Context) (securechannel.Enrollment, error) {
			if ctx.Err() != nil || c != cc.Context {
				return securechannel.Enrollment{}, securechannel.ErrAuth
			}
			return securechannel.Enrollment{Key: auth, Principal: "route-client", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}
	}
	return cc, sc
}

func integrationTLS(t *testing.T) tlsstream.Provider {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	p, err := tlsstream.NewStandardProvider(&tls.Config{RootCAs: roots}, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func integrationAuthority(t *testing.T) syntrahttp.Authority {
	t.Helper()
	a, err := syntrahttp.NewAuthority("localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func integrationHost(policyCalls *atomic.Int32) syntra.HostConfig {
	return syntra.HostConfig{
		ChannelPolicy: func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			policyCalls.Add(1)
			if ctx.Err() != nil || id.Scope != "route-http" || string(credential) != "protected-hello" {
				return "", securechannel.ErrAuth
			}
			return "route-client", nil
		},
		Authorize: syntra.AllowAllAuthorize,
		Handler: func(_ context.Context, r *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return syntra.NewSuccessResult(r.GetPayload()), nil
		},
	}
}

func integrationOrigin(t *testing.T, sc securechannel.ServerConfig, provider tlsstream.Provider, host syntra.HostConfig) *syntrahttp.Server {
	t.Helper()
	server, err := syntrahttp.Bind(syntrahttp.ServerConfig{Address: "127.0.0.1:0", Authority: integrationAuthority(t), Security: sc, TLS: provider, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Serve(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Error(err)
		}
		s := server.Status()
		if s.Sockets != 0 || s.Associations != 0 || s.ReservedBytes != 0 || s.UnboundStreams != 0 {
			t.Errorf("origin resources retained: %+v", s)
		}
	})
	return server
}

// loopbackProxy is a real, explicitly provisioned test hop. It owns and joins
// every accepted socket, upstream socket, and relay worker.
type loopbackProxy struct {
	listener net.Listener
	mu       sync.Mutex
	sockets  map[net.Conn]bool
	closed   bool
	failures []error
	wg       sync.WaitGroup
	requests atomic.Int32
	forwards atomic.Int32
}

func newLoopbackProxy(t *testing.T, handler func(*loopbackProxy, net.Conn) error) *loopbackProxy {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &loopbackProxy{listener: l, sockets: make(map[net.Conn]bool)}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			if !p.track(c) {
				continue
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer c.Close()
				if err := handler(p, c); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, net.ErrClosed) {
					p.mu.Lock()
					p.failures = append(p.failures, err)
					p.mu.Unlock()
				}
			}()
		}
	}()
	t.Cleanup(func() {
		p.mu.Lock()
		p.closed = true
		sockets := make([]net.Conn, 0, len(p.sockets))
		for c := range p.sockets {
			sockets = append(sockets, c)
		}
		p.mu.Unlock()
		_ = l.Close()
		for _, c := range sockets {
			_ = c.Close()
		}
		done := make(chan struct{})
		go func() { p.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("proxy workers did not join")
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, err := range p.failures {
			t.Error(err)
		}
	})
	return p
}
func (p *loopbackProxy) track(c net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return false
	}
	p.sockets[c] = true
	return true
}
func (p *loopbackProxy) address() netip.AddrPort { return p.listener.Addr().(*net.TCPAddr).AddrPort() }
func (p *loopbackProxy) upstream(address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if !p.track(c) {
		return nil, net.ErrClosed
	}
	return c, nil
}

func integrationReadHead(c net.Conn) ([]byte, error) {
	var scratch [syntrahttp.MaxHeaders]byte
	for n := 0; n < len(scratch); n++ {
		if _, err := io.ReadFull(c, scratch[n:n+1]); err != nil {
			return nil, err
		}
		if n >= 3 && bytes.Equal(scratch[n-3:n+1], []byte("\r\n\r\n")) {
			return append([]byte(nil), scratch[:n+1]...), nil
		}
	}
	return nil, ordered.ErrProtocol
}

func proxyConfiguration(t *testing.T, p *loopbackProxy, kind proxy.Kind) *proxy.ProxyConfig {
	t.Helper()
	c, err := proxy.NewCredentials([]byte("hop-user"), []byte("hop-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cfg, err := proxy.NewProxy(proxy.Config{Endpoint: p.address(), Kind: kind, Credentials: c})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cfg.Close() })
	return cfg
}

func relayTunnel(p *loopbackProxy, client net.Conn, origin string) error {
	upstream, err := p.upstream(origin)
	if err != nil {
		return err
	}
	defer upstream.Close()
	_ = client.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() { defer close(done); _, _ = io.Copy(client, upstream); _ = client.Close() }()
	_, _ = io.Copy(upstream, client)
	_ = upstream.Close()
	<-done
	return nil
}

func tunnelProxy(t *testing.T, kind proxy.Kind, origin string, authority syntrahttp.Authority) *loopbackProxy {
	t.Helper()
	return newLoopbackProxy(t, func(p *loopbackProxy, c net.Conn) error {
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if kind == proxy.HTTPConnect {
			head, err := integrationReadHead(c)
			if err != nil {
				return err
			}
			defer clear(head)
			want := "CONNECT " + authority.String() + " HTTP/1.1\r\nHost: " + authority.String() + "\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("hop-user:hop-password")) + "\r\n\r\n"
			if string(head) != want {
				return errors.New("unexpected CONNECT authority or hop credentials")
			}
			if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
				return err
			}
		} else {
			var greeting [3]byte
			if _, err := io.ReadFull(c, greeting[:]); err != nil {
				return err
			}
			if greeting != ([3]byte{5, 1, 2}) {
				return errors.New("unexpected proxy authentication method")
			}
			if err := stream.WriteAll(c, []byte{5, 2}); err != nil {
				return err
			}
			want := append([]byte{1, 8}, []byte("hop-user")...)
			want = append(want, 12)
			want = append(want, []byte("hop-password")...)
			auth := make([]byte, len(want))
			defer clear(auth)
			if _, err := io.ReadFull(c, auth); err != nil {
				return err
			}
			if !bytes.Equal(auth, want) {
				return errors.New("unexpected proxy credentials")
			}
			if err := stream.WriteAll(c, []byte{1, 0}); err != nil {
				return err
			}
			want = append([]byte{5, 1, 0, 3, 9}, []byte("localhost")...)
			want = binary.BigEndian.AppendUint16(want, 443)
			request := make([]byte, len(want))
			if _, err := io.ReadFull(c, request); err != nil {
				return err
			}
			if !bytes.Equal(request, want) {
				return errors.New("proxy destination was not remote hostname authority")
			}
			if err := stream.WriteAll(c, []byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1}); err != nil {
				return err
			}
		}
		p.requests.Add(1)
		return relayTunnel(p, c, origin)
	})
}

func forwardProxy(t *testing.T, origin string, authority syntrahttp.Authority) *loopbackProxy {
	t.Helper()
	return newLoopbackProxy(t, func(p *loopbackProxy, c net.Conn) error {
		upstream, err := p.upstream(origin)
		if err != nil {
			return err
		}
		defer upstream.Close()
		done := make(chan struct{})
		// This is an HTTP hop: the client-side persistent connection remains
		// owned by the proxy even when the origin retires its connection.
		go func() { defer close(done); _, _ = io.Copy(c, upstream) }()
		defer func() { _ = upstream.Close(); <-done }()
		for {
			head, err := integrationReadHead(c)
			if err != nil {
				return nil
			}
			lines := bytes.Split(head, []byte("\r\n"))
			requestLine := strings.Fields(string(lines[0]))
			if len(requestLine) != 3 || requestLine[0] != "POST" || requestLine[2] != "HTTP/1.1" || !strings.HasPrefix(requestLine[1], "http://"+authority.String()+"/") {
				clear(head)
				return errors.New("forward route did not send real absolute-form request")
			}
			path := strings.TrimPrefix(requestLine[1], "http://"+authority.String())
			originHead := make([]byte, 0, syntrahttp.MaxHeaders)
			originHead = append(originHead, "POST "...)
			originHead = append(originHead, path...)
			originHead = append(originHead, " HTTP/1.1\r\n"...)
			authCount := 0
			for _, line := range lines[1 : len(lines)-2] {
				if bytes.HasPrefix(bytes.ToLower(line), []byte("proxy-authorization:")) {
					authCount++
					expected := "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("hop-user:hop-password"))
					if string(line) != expected {
						clear(head)
						return errors.New("forward authentication mismatch")
					}
					continue
				}
				originHead = append(originHead, line...)
				originHead = append(originHead, '\r', '\n')
			}
			clear(head)
			if authCount != 1 {
				return errors.New("forward authentication missing or repeated")
			}
			originHead = append(originHead, '\r', '\n')
			parsed, err := syntrahttp.ParseRequest(originHead, authority, syntrahttp.OriginPolicy{})
			if err != nil {
				return errors.New("forwarded origin metadata rejected")
			}
			if bytes.Contains(originHead, []byte("hop-")) || bytes.Contains(bytes.ToLower(originHead), []byte("proxy-authorization")) {
				return errors.New("hop credentials crossed origin boundary")
			}
			p.requests.Add(1)
			p.forwards.Add(1)
			if err := stream.WriteAll(upstream, originHead); err != nil {
				return err
			}
			if _, err := io.CopyN(upstream, c, int64(parsed.BodyLen)); err != nil {
				return err
			}
		}
	})
}

func TestHTTPRouteIntegrations(t *testing.T) {
	for _, mode := range []securechannel.Mode{securechannel.Bootstrap, securechannel.Returning} {
		for _, tc := range []struct {
			name      string
			kind      Kind
			proxyKind proxy.Kind
		}{{"http", HTTP, 0}, {"https", HTTPS, 0}, {"http-connect", HTTPProxy, proxy.HTTPConnect}, {"http-socks", HTTPProxy, proxy.Socks5}, {"https-connect", HTTPSProxy, proxy.HTTPConnect}, {"https-socks", HTTPSProxy, proxy.Socks5}, {"http-forward", HTTPForward, proxy.HTTPConnect}} {
			t.Run(mode.String()+"/"+tc.name, func(t *testing.T) {
				carrier := securechannel.HTTP
				var provider tlsstream.Provider
				if tc.kind == HTTPS || tc.kind == HTTPSProxy {
					carrier = securechannel.HTTPS
					provider = integrationTLS(t)
				}
				cc, sc := integrationSecurity(t, mode, carrier)
				var policyCalls atomic.Int32
				origin := integrationOrigin(t, sc, provider, integrationHost(&policyCalls))
				authority := integrationAuthority(t)
				route := Route{Kind: tc.kind, Authority: authority, TLS: provider}
				var hop *loopbackProxy
				if tc.proxyKind == 0 {
					route.Address = netip.MustParseAddrPort(origin.Addr().String())
				} else {
					if tc.kind == HTTPForward {
						hop = forwardProxy(t, origin.Addr().String(), authority)
					} else {
						hop = tunnelProxy(t, tc.proxyKind, origin.Addr().String(), authority)
					}
					route.Proxy = proxyConfiguration(t, hop, tc.proxyKind)
					target, err := proxy.NewHostnameTarget("localhost", 443)
					if err != nil {
						t.Fatal(err)
					}
					route.Target = target
				}
				cfg := configFor(route)
				cfg.Options.AttemptTimeout = 3 * time.Second
				var inputs atomic.Int32
				var dialMu sync.Mutex
				var dialed []string
				cfg.Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
					dialMu.Lock()
					dialed = append(dialed, address)
					dialMu.Unlock()
					if _, err := netip.ParseAddrPort(address); err != nil {
						return nil, securechannel.ErrConfig
					}
					return (&net.Dialer{}).DialContext(ctx, network, address)
				}
				connector, err := New(cfg, func(ctx context.Context, e Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
					inputs.Add(1)
					if e != route.Endpoint() {
						return securechannel.ClientConfig{}, syntra.ClientConfig{}, securechannel.ErrConfig
					}
					return cc, syntra.ClientConfig{Credential: []byte("protected-hello")}, nil
				})
				if err != nil {
					t.Fatal(err)
				}
				var age atomic.Int64
				clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
				b, err := ordered.NewEstablishmentBudget(clock, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				client, err := connector(ctx, b)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				if inputs.Load() != 1 || policyCalls.Load() != 1 {
					t.Fatalf("inputs=%d policy=%d", inputs.Load(), policyCalls.Load())
				}
				dialMu.Lock()
				addresses := append([]string(nil), dialed...)
				dialMu.Unlock()
				if len(addresses) != 2 {
					t.Fatalf("pair did not use exactly two sockets: %v", addresses)
				}
				want := origin.Addr().String()
				if hop != nil {
					want = hop.address().String()
				}
				for _, got := range addresses {
					if got != want {
						t.Fatal("dial escaped configured socket")
					}
				}
				// Ready must release this exact gate; advancing its original clock
				// beyond the capped attempt must not retire the active session.
				age.Store(int64(4 * time.Second))
				if err := b.Check(); err != nil {
					t.Fatalf("Ready did not release owner budget: %v", err)
				}
				if err := origin.NotifyAll([]byte("unsolicited")); err != nil {
					t.Fatal(err)
				}
				select {
				case n := <-client.Notifications():
					if string(n.GetPayload()) != "unsolicited" {
						t.Fatal("wrong notification")
					}
				case <-ctx.Done():
					t.Fatal("no unsolicited notification")
				}
				for _, payload := range [][]byte{[]byte("echo"), bytes.Repeat([]byte{0x5a}, 96*1024)} {
					got, err := client.Call(ctx, "/route.Echo/Echo", payload, 0)
					if err != nil || !bytes.Equal(got, payload) {
						t.Fatalf("RPC bytes=%d err=%v", len(got), err)
					}
				}
				if hop != nil {
					if tc.kind == HTTPForward {
						if hop.forwards.Load() < 4 {
							t.Fatal("forward requests did not carry both lanes")
						}
					} else if hop.requests.Load() != 2 {
						t.Fatal("pair did not negotiate two tunnels")
					}
				}
				if err := client.Close(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
