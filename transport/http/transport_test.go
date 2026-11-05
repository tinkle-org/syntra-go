package syntrahttp

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

func securityConfigs(t *testing.T, mode securechannel.Mode, carrier securechannel.Carrier) (securechannel.ClientConfig, securechannel.ServerConfig) {
	t.Helper()
	static, e := securechannel.GenerateStaticKey()
	if e != nil {
		t.Fatal(e)
	}
	cc := securechannel.ClientConfig{Context: securechannel.Context{Mode: mode, Carrier: carrier, Scope: "http-test"}, ServerPublicKey: static.Public()}
	sc := securechannel.ServerConfig{StaticKey: static, Carrier: carrier, Scope: "http-test", AllowBootstrap: mode == securechannel.Bootstrap}
	cc.AllowHTTPCandidate = true
	sc.AllowHTTPCandidate = true
	if mode == securechannel.Returning {
		key, e := securechannel.GenerateKey()
		if e != nil {
			t.Fatal(e)
		}
		cc.Context.Epoch, cc.Context.Handle, cc.AuthorizationKey = 1, [8]byte{1}, key
		sc.Lookup = func(ctx context.Context, c securechannel.Context) (securechannel.Enrollment, error) {
			if ctx.Err() != nil || c != cc.Context {
				return securechannel.Enrollment{}, securechannel.ErrAuth
			}
			return securechannel.Enrollment{Key: key, Principal: "device", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}
	}
	return cc, sc
}
func hostConfig() syntra.HostConfig {
	return syntra.HostConfig{
		ChannelPolicy: func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			if ctx.Err() != nil || id.Scope != "http-test" || string(credential) != "explicit" {
				return "", securechannel.ErrAuth
			}
			return "principal", nil
		},
		Authorize: syntra.AllowAllAuthorize,
		Handler: func(_ context.Context, r *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return syntra.NewSuccessResult(r.GetPayload()), nil
		},
	}
}
func testProvider(t *testing.T) tlsstream.Provider {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, pub, priv)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	p, e := tlsstream.NewStandardProvider(&tls.Config{RootCAs: roots}, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}}})
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func startServer(t *testing.T, sc securechannel.ServerConfig, h syntra.HostConfig, provider tlsstream.Provider, limits ServerLimits) *Server {
	t.Helper()
	s, e := Bind(ServerConfig{Address: "127.0.0.1:0", Authority: testAuthority(t), Security: sc, Host: h, TLS: provider, Limits: limits})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Serve(context.Background()); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		if e := s.Close(); e != nil {
			t.Error(e)
		}
		st := s.Status()
		if st.Sockets != 0 || st.Associations != 0 || st.UnboundStreams != 0 || st.ReservedBytes != 0 || !st.Stopped {
			t.Errorf("retained resources after shutdown: %+v", st)
		}
	})
	return s
}
func connectTo(t *testing.T, s *Server, cc securechannel.ClientConfig, p tlsstream.Provider) *connection.Client {
	t.Helper()
	c, e := Dial(context.Background(), netip.MustParseAddrPort(s.Addr().String()), testAuthority(t), p, cc, syntra.ClientConfig{Credential: []byte("explicit")}, ordered.Options{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func awaitCondition(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for !fn() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}
func callEcho(t *testing.T, c *connection.Client, payload []byte) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 4*time.Second)
	defer stop()
	got, e := c.Call(ctx, "/example.Echo/Echo", payload, 0)
	if e != nil || !bytes.Equal(got, payload) {
		t.Fatalf("RPC: bytes=%d error=%v", len(got), e)
	}
}

func TestHTTPAndHTTPSFullConnections(t *testing.T) {
	for _, secure := range []bool{false, true} {
		for _, mode := range []securechannel.Mode{securechannel.Bootstrap, securechannel.Returning} {
			name := mode.String()
			carrier := securechannel.HTTP
			var provider tlsstream.Provider
			if secure {
				name = "https/" + name
				carrier = securechannel.HTTPS
				provider = testProvider(t)
			} else {
				name = "http/" + name
			}
			t.Run(name, func(t *testing.T) {
				cc, sc := securityConfigs(t, mode, carrier)
				s := startServer(t, sc, hostConfig(), provider, ServerLimits{})
				c := connectTo(t, s, cc, provider)
				// No Call precedes this notification: D must poll independently.
				if e := s.NotifyAll([]byte("unsolicited")); e != nil {
					t.Fatal(e)
				}
				select {
				case n := <-c.Notifications():
					if string(n.GetPayload()) != "unsolicited" {
						t.Fatal("wrong notification")
					}
				case <-time.After(time.Second):
					t.Fatal("notification required a call")
				}
				callEcho(t, c, []byte("echo"))
				callEcho(t, c, bytes.Repeat([]byte{0xa5}, (1<<20)-128))
				if e := c.Close(); e != nil {
					t.Fatal(e)
				}
				awaitCondition(t, func() bool { st := s.Status(); return st.Associations == 0 && st.Sockets == 0 && st.ReservedBytes == 0 })
			})
		}
	}
}

func TestAuthorityKeyCredentialAndOptInFailures(t *testing.T) {
	cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	s := startServer(t, sc, hostConfig(), nil, ServerLimits{})
	for _, which := range []string{"authority", "pin", "authorization-key", "credential", "opt-in"} {
		t.Run(which, func(t *testing.T) {
			security, core, authority := cc, syntra.ClientConfig{Credential: []byte("explicit")}, testAuthority(t)
			switch which {
			case "authority":
				authority, _ = NewAuthority("foreign:443")
			case "pin":
				security.ServerPublicKey[0] ^= 1
			case "authorization-key":
				security.AuthorizationKey[0] ^= 1
			case "credential":
				core.Credential = []byte("private-bad-credential")
			case "opt-in":
				security.AllowHTTPCandidate = false
			}
			c, e := Dial(context.Background(), netip.MustParseAddrPort(s.Addr().String()), authority, nil, security, core, ordered.Options{HandshakeTimeout: time.Second})
			if c != nil || e == nil {
				t.Fatalf("accepted %s", which)
			}
			if strings.Contains(e.Error(), "private") {
				t.Fatal("credential escaped in error")
			}
			awaitCondition(t, func() bool { return s.Status().Associations == 0 })
		})
	}
}

func TestNativeRejectionBeforeLookup(t *testing.T) {
	_, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	var lookups atomic.Int32
	sc.Lookup = func(context.Context, securechannel.Context) (securechannel.Enrollment, error) {
		lookups.Add(1)
		return securechannel.Enrollment{}, securechannel.ErrAuth
	}
	s := startServer(t, sc, hostConfig(), nil, ServerLimits{})
	a, r := testAuthority(t), testRoute(t)
	valid, _ := requestHeader(Open, a, Route{}, 0, 83)
	for _, tc := range []struct {
		raw    string
		status string
	}{
		{strings.Replace(string(valid), "localhost:443", "foreign:443", 1), "404"},
		{strings.Replace(string(valid), "\r\n\r\n", "\r\nOrigin: https://localhost\r\n\r\n", 1), "403"},
		{strings.Replace(string(valid), "POST ", "GET ", 1), "405"},
		{strings.Replace(string(valid), "HTTP/1.1", "HTTP/1.0", 1), "505"},
		{strings.Replace(string(valid), "Content-Length: 83", "Content-Length: 65536", 1), "413"},
		{strings.Replace(string(valid), "\r\n\r\n", "\r\nCookie: secret-cookie\r\n\r\n", 1), "400"},
	} {
		c, e := net.Dial("tcp", s.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		_ = c.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(c, tc.raw)
		h, e := readHeader(c)
		_ = c.Close()
		if e != nil || !strings.HasPrefix(string(h), "HTTP/1.1 "+tc.status+" ") || bytes.Contains(h, []byte("secret")) {
			t.Fatalf("rejection: %q %v", h, e)
		}
	}
	// Unknown selectors never allocate an association or consult credentials.
	c, e := net.Dial("tcp", s.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	h, _ := requestHeader(Poll, a, r, 0, 0)
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write(h)
	got, e := readHeader(c)
	if e != nil || !bytes.HasPrefix(got, []byte("HTTP/1.1 410")) {
		t.Fatalf("unknown selector: %q %v", got, e)
	}
	if lookups.Load() != 0 || s.Status().Associations != 0 {
		t.Fatal("pre-body rejection reached lookup")
	}
}

func TestPauseDisconnectCancelAndRetainedShutdown(t *testing.T) {
	cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	s := startServer(t, sc, hostConfig(), nil, ServerLimits{})
	c := connectTo(t, s, cc, nil)
	s.Pause()
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	_ = c.Wait(ctx)
	awaitCondition(t, func() bool { return s.Status().Associations == 0 })
	s.Resume()
	c = connectTo(t, s, cc, nil)
	callEcho(t, c, []byte("fresh"))
	_ = c.Close()
	// Cancellation of a blocked raw operation retires both owned sockets.
	u, up := net.Pipe()
	d, dp := net.Pipe()
	defer up.Close()
	defer dp.Close()
	p, e := ClientPair(u, d, testAuthority(t), ordered.Options{})
	if e != nil {
		t.Fatal(e)
	}
	cancelctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = p.ReadMessage(cancelctx, make([]byte, 0, 48)); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	for _, peer := range []net.Conn{up, dp} {
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		if _, e := peer.Read(make([]byte, 1)); !errors.Is(e, io.EOF) {
			t.Fatalf("other half not closed: %v", e)
		}
	}
	if e := s.Close(); e != nil {
		t.Fatal(e)
	}
}

func TestQuotaAndSlowPolicyOwnership(t *testing.T) {
	cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h := hostConfig()
	base := h.ChannelPolicy
	h.ChannelPolicy = func(ctx context.Context, id syntra.ChannelIdentity, b []byte) (string, error) {
		once.Do(func() { close(entered) })
		<-release
		return base(ctx, id, b)
	}
	s := startServer(t, sc, h, nil, ServerLimits{Associations: 1, Handshakes: 1, PrincipalAssociations: 1})
	done := make(chan error, 1)
	go func() {
		c, e := Dial(context.Background(), netip.MustParseAddrPort(s.Addr().String()), testAuthority(t), nil, cc, syntra.ClientConfig{Credential: []byte("explicit")}, ordered.Options{HandshakeTimeout: 300 * time.Millisecond})
		if c != nil {
			_ = c.Close()
		}
		done <- e
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("policy not reached")
	}
	s.Pause()
	ctx, stop := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer stop()
	if e := s.Wait(ctx); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("wait lost ownership")
	}
	st := s.Status()
	if st.Associations != 1 || st.ReservedBytes < s.reservation {
		t.Fatalf("reservation released before callback: %+v", st)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("client did not finish")
	}
	awaitCondition(t, func() bool { return s.Status().Associations == 0 })
}

type rawProvider struct{}

func (rawProvider) Connect(_ context.Context, c net.Conn, _ tlsstream.Authority) (tlsstream.Result, error) {
	return tlsstream.Result{Conn: c}, nil
}
func (rawProvider) Accept(_ context.Context, c net.Conn, _ tlsstream.Authority) (tlsstream.Result, error) {
	return tlsstream.Result{Conn: c}, nil
}
func TestHTTPSRequiresProofAndProvider(t *testing.T) {
	cc := securechannel.ClientConfig{Context: securechannel.Context{Carrier: securechannel.HTTPS}}
	if c, e := ConnectTLSPair(context.Background(), &tlsstream.Verified{}, &tlsstream.Verified{}, testAuthority(t), cc, syntra.ClientConfig{}, ordered.Options{}); c != nil || e == nil {
		t.Fatal("raw proof accepted")
	}
	u, up := net.Pipe()
	d, dp := net.Pipe()
	defer up.Close()
	defer dp.Close()
	b, _ := ordered.NewEstablishmentBudget(nil, time.Second)
	ta, _ := testAuthority(t).TLSAuthority()
	proof, e := tlsstream.Connect(context.Background(), u, rawProvider{}, ta, b)
	_ = d.Close()
	if proof != nil || e == nil {
		t.Fatal("raw provider accepted")
	}
	u, up2 := net.Pipe()
	d, dp2 := net.Pipe()
	defer up2.Close()
	defer dp2.Close()
	if c, e := ConnectStreams(context.Background(), u, d, testAuthority(t), cc, syntra.ClientConfig{}, ordered.Options{}); c != nil || e == nil {
		t.Fatal("raw HTTPS streams accepted")
	}
}

func TestHTTPSProofBudgetIdentity(t *testing.T) {
	provider := testProvider(t)
	a := testAuthority(t)
	ta, e := a.TLSAuthority()
	if e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	servers := make(chan error, 2)
	go func() {
		for i := 0; i < 2; i++ {
			raw, e := l.Accept()
			if e != nil {
				servers <- e
				continue
			}
			go func() {
				b, _ := ordered.NewEstablishmentBudget(nil, 3*time.Second)
				proof, e := tlsstream.Accept(context.Background(), raw, provider, ta, b)
				if e != nil {
					servers <- e
					return
				}
				defer proof.Close()
				c, e := proof.Consume(ta, tlsstream.Server, b)
				if e != nil {
					servers <- e
					return
				}
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				var one [1]byte
				n, e := c.Read(one[:])
				if n != 0 {
					servers <- errors.New("HTTP bytes preceded proof validation")
					return
				}
				if e == nil {
					servers <- errors.New("proof rejection did not close socket")
					return
				}
				servers <- nil
			}()
		}
	}()
	proofs := make([]*tlsstream.Verified, 2)
	for i := range proofs {
		raw, e := net.Dial("tcp", l.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		b, _ := ordered.NewEstablishmentBudget(nil, 3*time.Second)
		proofs[i], e = tlsstream.Connect(context.Background(), raw, provider, ta, b)
		if e != nil {
			t.Fatal(e)
		}
		defer proofs[i].Close()
	}
	cc, _ := securityConfigs(t, securechannel.Bootstrap, securechannel.HTTPS)
	if c, e := ConnectTLSPair(context.Background(), proofs[0], proofs[1], a, cc, syntra.ClientConfig{}, ordered.Options{}); c != nil || !errors.Is(e, securechannel.ErrConfig) {
		t.Fatal("independent budgets were combined")
	}
	for range proofs {
		select {
		case e := <-servers:
			if e != nil {
				t.Fatal(e)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("TLS owner did not join")
		}
	}
}

func TestOptInPrecedesSocketEffects(t *testing.T) {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	for _, carrier := range []securechannel.Carrier{securechannel.HTTP, securechannel.HTTPS} {
		cfg := securechannel.ClientConfig{Context: securechannel.Context{Carrier: carrier}}
		var provider tlsstream.Provider
		if carrier == securechannel.HTTPS {
			provider = rawProvider{}
		}
		if c, e := Dial(context.Background(), netip.MustParseAddrPort(l.Addr().String()), testAuthority(t), provider, cfg, syntra.ClientConfig{}, ordered.Options{}); c != nil || !errors.Is(e, securechannel.ErrConfig) {
			t.Fatal("missing opt-in accepted")
		}
	}
	_ = l.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Millisecond))
	if c, e := l.Accept(); e == nil {
		_ = c.Close()
		t.Fatal("denied candidate dialed a socket")
	}
}

func TestExactMiBOrderedFrame(t *testing.T) {
	cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	u, us := net.Pipe()
	d, ds := net.Pipe()
	defer us.Close()
	defer ds.Close()
	carrier, e := ClientPair(u, d, testAuthority(t), ordered.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer carrier.Close()
	a, r := testAuthority(t), testRoute(t)
	type accepted struct {
		transport *ordered.Transport
		pair      *serverPair
		err       error
	}
	ready := make(chan accepted, 1)
	attachDone := make(chan struct{})
	go func() {
		h, e := readHeader(us)
		if e != nil {
			ready <- accepted{err: e}
			return
		}
		head, e := ParseRequest(h, a, OriginPolicy{})
		if e != nil {
			ready <- accepted{err: e}
			return
		}
		body := make([]byte, head.BodyLen)
		if _, e = io.ReadFull(us, body); e != nil {
			ready <- accepted{err: e}
			return
		}
		b, _ := ordered.NewEstablishmentBudget(nil, 5*time.Second)
		pair := newServerPair(us, body, a, OriginPolicy{}, r, b)
		go pair.runDownload()
		go func() {
			defer close(attachDone)
			h, e := readHeader(ds)
			if e != nil {
				_ = pair.Close()
				return
			}
			head, e := ParseRequest(h, a, OriginPolicy{})
			if e == nil {
				e = pair.awaitOpen(context.Background())
			}
			if e != nil || !pair.attachDownload(ds, head) {
				_ = pair.Close()
			}
		}()
		tr, e := ordered.Server(context.Background(), pair, sc, ordered.Options{Budget: b})
		ready <- accepted{tr, pair, e}
	}()
	client, e := ordered.Client(context.Background(), carrier, cc, ordered.Options{})
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	server := <-ready
	if server.err != nil {
		t.Fatal(server.err)
	}
	defer server.transport.Close()
	frame := bytes.Repeat([]byte{0x5a}, 1<<20)
	result := make(chan error, 1)
	go func() {
		b, e := server.transport.Recv(context.Background())
		if e == nil && !bytes.Equal(b, frame) {
			e = errors.New("fragmented frame changed")
		}
		if e == nil {
			e = server.transport.Send(context.Background(), b)
		}
		result <- e
	}()
	if e := client.Send(context.Background(), frame); e != nil {
		t.Fatal(e)
	}
	got, e := client.Recv(context.Background())
	if e != nil || !bytes.Equal(got, frame) {
		t.Fatalf("exact MiB frame: %d %v", len(got), e)
	}
	if e := <-result; e != nil {
		t.Fatal(e)
	}
	_ = client.Close()
	_ = server.transport.Close()
	select {
	case <-server.pair.done:
	case <-time.After(time.Second):
		t.Fatal("download did not join")
	}
	select {
	case <-attachDone:
	case <-time.After(time.Second):
		t.Fatal("attachment did not join")
	}
}
