package routes

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
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
	"github.com/tinkle-org/syntra-go/transport/tcp"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

func localAddress(port uint16) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)
}
func configFor(rs ...Route) RouteConfig {
	es := make([]Endpoint, len(rs))
	for i, r := range rs {
		es[i] = r.Endpoint()
	}
	return RouteConfig{Routes: rs, Allowlist: es}
}
func newBudget(t *testing.T, timeout time.Duration) *ordered.EstablishmentBudget {
	t.Helper()
	b, err := ordered.NewEstablishmentBudget(nil, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func neverInputs(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
	panic("inputs before valid invocation")
}

type rejectingTLS struct{ calls atomic.Int32 }

func (p *rejectingTLS) Connect(context.Context, net.Conn, tlsstream.Authority) (tlsstream.Result, error) {
	p.calls.Add(1)
	return tlsstream.Result{}, securechannel.ErrAuth
}
func (p *rejectingTLS) Accept(context.Context, net.Conn, tlsstream.Authority) (tlsstream.Result, error) {
	p.calls.Add(1)
	return tlsstream.Result{}, securechannel.ErrAuth
}

func TestAllRoutesAndUnusedAllowlistEntriesValidateBeforeEffects(t *testing.T) {
	good := Route{Kind: TCP, Address: localAddress(1)}
	var calls atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, ordered.ErrIO }
	inputs := func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		calls.Add(1)
		return securechannel.ClientConfig{}, syntra.ClientConfig{}, securechannel.ErrAuth
	}
	reject := func(cfg RouteConfig) {
		t.Helper()
		cfg.Dialer = dial
		if _, err := New(cfg, inputs); err == nil {
			t.Fatal("invalid policy accepted")
		}
		if calls.Load() != 0 {
			t.Fatal("effect before validation")
		}
	}
	reject(RouteConfig{})
	reject(RouteConfig{Routes: []Route{good}})
	reject(RouteConfig{Allowlist: []Endpoint{good.Endpoint()}})
	cfg := configFor(good)
	cfg.Allowlist[0].Address = localAddress(2)
	reject(cfg)
	for _, s := range []string{"127.0.0.1:0", "0.0.0.0:80", "[::]:80", "224.0.0.1:80", "[::ffff:0.0.0.0]:80", "[::ffff:224.0.0.1]:80", "[fe80::1%en0]:80"} {
		bad := Route{Kind: TCP, Address: netip.MustParseAddrPort(s)}
		reject(configFor(good, bad))
		cfg := configFor(good)
		cfg.Allowlist = append(cfg.Allowlist, bad.Endpoint())
		reject(cfg)
	}
	cfg = configFor(good)
	cfg.Routes = make([]Route, MaxRoutes+1)
	reject(cfg)
	cfg = configFor(good)
	cfg.Allowlist = make([]Endpoint, MaxRoutes+1)
	reject(cfg)
	cfg = configFor(good)
	cfg.Options.AttemptTimeout = -1
	reject(cfg)
	for _, r := range []Route{{Kind: TCP, Address: localAddress(1), URL: "ws://localhost/syntra/1.0/ws"}, {Kind: TCP, Address: localAddress(1), TLS: &rejectingTLS{}}, {Kind: WSS, Address: localAddress(1), URL: "wss://localhost/syntra/1.0/ws"}, {Kind: 99, Address: localAddress(1)}} {
		reject(configFor(r))
	}
	if _, err := New(configFor(good), neverInputs); err != nil {
		t.Fatal(err)
	}
}

func TestURLsAreStrictAndAllFormattingIsRedacted(t *testing.T) {
	provider := &rejectingTLS{}
	for _, raw := range []string{"https://localhost/syntra/1.0/ws", "ws://localhost/syntra/1.0/ws", "wss://localhost/wrong", "wss://user:secret@localhost/syntra/1.0/ws", "wss://@localhost/syntra/1.0/ws", "wss://localhost/syntra/1.0/ws?", "wss://localhost/syntra/1.0/ws#", "wss://localhost/else/../syntra/1.0/ws", "wss://localhost/%2e/syntra/1.0/ws", " wss://localhost/syntra/1.0/ws", "wss://localhost/syntra/1.0/ws\n", "wss://localhost\\syntra/1.0/ws", "wss://localhost/syntra/1.0/%77s", "wss://0.0.0.0/syntra/1.0/ws", "wss://localhost:0/syntra/1.0/ws", "wss://127.1/syntra/1.0/ws", "wss://[localhost]/syntra/1.0/ws", "wss://2001:db8::1:443/syntra/1.0/ws", "wss://" + strings.Repeat("a", 2048) + "/syntra/1.0/ws"} {
		r := Route{Kind: WSS, Address: localAddress(1), URL: raw, TLS: provider}
		if _, err := New(configFor(r), neverInputs); err == nil {
			t.Fatalf("accepted %q", raw)
		}
		valid := Route{Kind: WSS, Address: localAddress(1), URL: "wss://localhost/syntra/1.0/ws", TLS: provider}
		cfg := configFor(valid)
		cfg.Allowlist = append(cfg.Allowlist, r.Endpoint())
		if _, err := NewWithSetup(cfg, neverInputs); err == nil {
			t.Fatalf("accepted malformed unused allowlist URL %q", raw)
		}
		for _, v := range []any{r, r.Endpoint(), configFor(r)} {
			for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
				if s := fmt.Sprintf(verb, v); strings.Contains(s, "secret") {
					t.Fatalf("secret in %s", verb)
				}
			}
		}
	}
	for _, raw := range []string{"wss://localhost/syntra/1.0/ws", "wss://localhost:443/syntra/1.0/ws", "wss://[::1]:443/syntra/1.0/ws"} {
		if _, err := New(configFor(Route{Kind: WSS, Address: localAddress(1), URL: raw, TLS: provider}), neverInputs); err != nil {
			t.Fatalf("valid explicit URL: %v", err)
		}
	}
	if provider.calls.Load() != 0 {
		t.Fatal("provider called during construction")
	}
	for _, r := range []Route{{Kind: WS, Address: localAddress(1), URL: "ws://other.invalid/syntra/1.0/ws"}, {Kind: WS, Address: netip.MustParseAddrPort("192.0.2.1:80"), URL: "ws://localhost/syntra/1.0/ws"}} {
		if _, err := New(configFor(r), neverInputs); err == nil {
			t.Fatal("non-loopback plaintext WebSocket")
		}
	}
}

func TestCarrierAndProxyTargetIdentity(t *testing.T) {
	p, err := proxy.NewProxy(proxy.Config{Endpoint: localAddress(1080), Kind: proxy.Socks5})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	target, err := proxy.NewHostnameTarget("localhost", 443)
	if err != nil {
		t.Fatal(err)
	}
	r := Route{Kind: WSSProxy, Proxy: p, Target: target, URL: "wss://localhost/syntra/1.0/ws", TLS: &rejectingTLS{}}
	if _, err := New(configFor(r), neverInputs); err != nil {
		t.Fatal(err)
	}
	cfg := configFor(r)
	cfg.Allowlist[0].Proxy = localAddress(1081)
	if _, err := New(cfg, neverInputs); err == nil {
		t.Fatal("proxy hop not allowlisted")
	}
	other, _ := proxy.NewHostnameTarget("other.invalid", 443)
	cfg = configFor(r)
	cfg.Allowlist = append(cfg.Allowlist, Endpoint{Kind: WSSProxy, Proxy: p.Endpoint(), Target: other, URL: r.URL})
	if _, err := New(cfg, neverInputs); err == nil {
		t.Fatal("unused mismatched target accepted")
	}
	r.Target = other
	if _, err := New(configFor(r), neverInputs); err == nil {
		t.Fatal("tunnel target differs from authority")
	}
	tcpRoute := Route{Kind: TCP, Address: localAddress(1)}
	wsRoute := Route{Kind: WS, Address: localAddress(2), URL: "ws://localhost/syntra/1.0/ws"}
	if _, err := New(configFor(tcpRoute, wsRoute), neverInputs); err == nil {
		t.Fatal("homogeneous constructor accepted mixed carriers")
	}
	for _, carriers := range [][]securechannel.Carrier{nil, {securechannel.WS}, {securechannel.TCP, securechannel.TCP}, {99}, {securechannel.TCP, securechannel.WSS, securechannel.HTTP, securechannel.HTTPS, securechannel.WS}} {
		if _, err := NewCrossCarrier(configFor(tcpRoute), CrossCarrierPolicy{carriers}, neverInputs); err == nil {
			t.Fatal("invalid permissions")
		}
	}
	if _, err := NewCrossCarrier(configFor(wsRoute), CrossCarrierPolicy{[]securechannel.Carrier{securechannel.TCP, securechannel.WSS}}, neverInputs); err == nil {
		t.Fatal("loopback WS in cross-carrier routes")
	}
}

func TestRoundRobinSnapshotsAndTypedInputErrors(t *testing.T) {
	a := Route{Kind: TCP, Address: localAddress(1)}
	b := Route{Kind: TCP, Address: localAddress(2)}
	cfg := configFor(a, b)
	var got []Endpoint
	marker := syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "input denied")
	connector, err := New(cfg, func(ctx context.Context, e Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		got = append(got, e)
		return securechannel.ClientConfig{}, syntra.ClientConfig{}, marker
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Routes[0].Address = localAddress(9)
	cfg.Allowlist[1].Address = localAddress(10)
	for i := 0; i < 3; i++ {
		if _, err := connector(context.Background(), newBudget(t, time.Second)); err != marker {
			t.Fatalf("input error reclassified: %v", err)
		}
	}
	if len(got) != 3 || got[0] != a.Endpoint() || got[1] != b.Endpoint() || got[2] != a.Endpoint() {
		t.Fatalf("selection: %v", got)
	}
}

func TestInputsDoNotHoldSelectionMutex(t *testing.T) {
	entered := make(chan Endpoint, 2)
	release := make(chan struct{})
	defer close(release)
	connector, err := New(configFor(Route{Kind: TCP, Address: localAddress(1)}, Route{Kind: TCP, Address: localAddress(2)}), func(ctx context.Context, e Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		entered <- e
		select {
		case <-release:
		case <-ctx.Done():
		}
		return securechannel.ClientConfig{}, syntra.ClientConfig{}, securechannel.ErrAuth
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		b := newBudget(t, time.Second)
		go func() { defer wg.Done(); _, _ = connector(ctx, b) }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("callback held selection mutex")
		}
	}
	cancel()
	wg.Wait()
}

func TestExpiredAndCanceledCallsDoNotSelectOrConsumeInputs(t *testing.T) {
	var got []Endpoint
	connector, err := New(configFor(Route{Kind: TCP, Address: localAddress(1)}, Route{Kind: TCP, Address: localAddress(2)}), func(ctx context.Context, e Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		got = append(got, e)
		return securechannel.ClientConfig{}, syntra.ClientConfig{}, securechannel.ErrAuth
	})
	if err != nil {
		t.Fatal(err)
	}
	var age atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	b, err := ordered.NewEstablishmentBudget(clock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	age.Store(int64(time.Second))
	if _, err = connector(context.Background(), b); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = connector(ctx, newBudget(t, time.Second)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_, _ = connector(context.Background(), newBudget(t, time.Second))
	if len(got) != 1 || got[0].Address != localAddress(1) {
		t.Fatal("canceled call consumed selection")
	}
}

func TestCarrierMismatchAndExpiredInputsNeverDial(t *testing.T) {
	var calls atomic.Int32
	cfg := configFor(Route{Kind: TCP, Address: localAddress(1)})
	cfg.Dialer = func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, ordered.ErrIO }
	connector, err := New(cfg, func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		return securechannel.ClientConfig{Context: securechannel.Context{Carrier: securechannel.WSS}}, syntra.ClientConfig{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connector(context.Background(), newBudget(t, time.Second)); !errors.Is(err, securechannel.ErrConfig) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("mismatch dialed")
	}
	var age atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	b, _ := ordered.NewEstablishmentBudget(clock, time.Second)
	connector, err = New(cfg, func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		age.Store(int64(time.Second))
		return securechannel.ClientConfig{}, syntra.ClientConfig{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connector(context.Background(), b); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("expired callback dialed")
	}
}

func TestTCPRouteReachesProtectedReadinessAndPush(t *testing.T) {
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	host, err := syntra.OpenHost(syntra.HostConfig{ChannelPolicy: func(context.Context, syntra.ChannelIdentity, []byte) (string, error) { return "route-fixture", nil }, Authorize: syntra.AllowAllAuthorize})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err == nil {
			err = tcp.Accept(ctx, c, securechannel.ServerConfig{StaticKey: key, Scope: "route-fixture", Carrier: securechannel.TCP, AllowBootstrap: true}, host, ordered.Options{})
		}
		done <- err
	}()
	r := Route{Kind: TCP, Address: l.Addr().(*net.TCPAddr).AddrPort()}
	connector, err := New(configFor(r), func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		return securechannel.ClientConfig{Context: securechannel.Context{Carrier: securechannel.TCP, Mode: securechannel.Bootstrap, Scope: "route-fixture"}, ServerPublicKey: key.Public()}, syntra.ClientConfig{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := connector(ctx, newBudget(t, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err = host.NotifyAll([]byte("push")); err != nil {
		t.Fatal(err)
	}
	select {
	case n := <-client.Notifications():
		if string(n.GetPayload()) != "push" {
			t.Fatal("wrong push")
		}
	case <-ctx.Done():
		t.Fatal("no push")
	}
	_ = client.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("server not joined")
	}
}

func TestHTTPAuthorityAndHopAreIndependentAllowlistIdentity(t *testing.T) {
	a, err := syntrahttp.NewAuthority("origin.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	r := Route{Kind: HTTP, Address: localAddress(1), Authority: a}
	if _, err := New(configFor(r), neverInputs); err != nil {
		t.Fatal(err)
	}
	cfg := configFor(r)
	cfg.Allowlist[0].Authority, _ = syntrahttp.NewAuthority("other.invalid:80")
	if _, err := New(cfg, neverInputs); err == nil {
		t.Fatal("authority not allowlisted")
	}
	cfg = configFor(r)
	cfg.Allowlist = append(cfg.Allowlist, Endpoint{Kind: HTTPS, Address: localAddress(2), Authority: a})
	if _, err := New(cfg, neverInputs); err == nil {
		t.Fatal("mixed unused allowlist carrier")
	}
	p, err := proxy.NewProxy(proxy.Config{Endpoint: localAddress(1080), Kind: proxy.Socks5})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	target, _ := proxy.NewHostnameTarget("origin.invalid", 80)
	r = Route{Kind: HTTPForward, Proxy: p, Target: target, Authority: a}
	if _, err := New(configFor(r), neverInputs); err == nil {
		t.Fatal("SOCKS configuration on forward route")
	}
}

func TestCrossCarrierIsOneSelectionAndNeverUpgradesAfterRefusal(t *testing.T) {
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	provider := &rejectingTLS{}
	tcpRoute := Route{Kind: TCP, Address: localAddress(1)}
	wssRoute := Route{Kind: WSS, Address: localAddress(2), URL: "wss://localhost/syntra/1.0/ws", TLS: provider}
	cfg := configFor(tcpRoute, wssRoute)
	var dials []string
	var peers sync.WaitGroup
	cfg.Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Error("unexpected socket network")
		}
		dials = append(dials, address)
		left, right := net.Pipe()
		peers.Add(1)
		go func() { defer peers.Done(); defer right.Close(); _, _ = io.Copy(io.Discard, right) }()
		return left, nil
	}
	var endpoints []Endpoint
	connector, err := NewCrossCarrier(cfg, CrossCarrierPolicy{[]securechannel.Carrier{securechannel.TCP, securechannel.WSS}}, func(ctx context.Context, e Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		endpoints = append(endpoints, e)
		return securechannel.ClientConfig{Context: securechannel.Context{Carrier: e.Carrier(), Mode: securechannel.Bootstrap, Scope: "route-fixture"}, ServerPublicKey: key.Public()}, syntra.ClientConfig{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, err = connector(context.Background(), newBudget(t, 25*time.Millisecond))
		if i == 1 {
			if !errors.Is(err, securechannel.ErrAuth) {
				t.Fatalf("provider authentication rejection changed: %v", err)
			}
		} else if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if len(dials) != i+1 || len(endpoints) != i+1 {
			t.Fatal("internal fallback or duplicate inputs")
		}
	}
	peers.Wait()
	if dials[0] != tcpRoute.Address.String() || dials[1] != wssRoute.Address.String() || dials[2] != tcpRoute.Address.String() || provider.calls.Load() != 1 {
		t.Fatal("selection or provider invocation changed")
	}
}

func TestRouteCapCannotRenewSpentOwnerTime(t *testing.T) {
	var age atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	b, err := ordered.NewEstablishmentBudget(clock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	age.Store(int64(100 * time.Millisecond))
	cfg := configFor(Route{Kind: TCP, Address: localAddress(1)})
	cfg.Options.AttemptTimeout = 50 * time.Millisecond
	connector, err := New(cfg, neverInputs)
	if err != nil {
		t.Fatal(err)
	}
	_, err = connector(context.Background(), b)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cap renewed spent budget: %v", err)
	}
}

func TestHTTPCandidatePermissionMustPrecedeDial(t *testing.T) {
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := syntrahttp.NewAuthority("origin.invalid:80")
	cfg := configFor(Route{Kind: HTTP, Address: localAddress(1), Authority: a})
	var calls atomic.Int32
	cfg.Dialer = func(context.Context, string, string) (net.Conn, error) { calls.Add(1); return nil, ordered.ErrIO }
	connector, err := New(cfg, func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		return securechannel.ClientConfig{Context: securechannel.Context{Carrier: securechannel.HTTP, Mode: securechannel.Bootstrap, Scope: "candidate-fixture"}, ServerPublicKey: key.Public()}, syntra.ClientConfig{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connector(context.Background(), newBudget(t, time.Second)); !errors.Is(err, securechannel.ErrConfig) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("candidate without permission dialed")
	}
}

func TestTCPProxySeparatesHopAndProtectedHelloCredentials(t *testing.T) {
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	creds, err := proxy.NewCredentials([]byte("proxy-user"), []byte("proxy-password"))
	if err != nil {
		t.Fatal(err)
	}
	defer creds.Close()
	p, err := proxy.NewProxy(proxy.Config{Endpoint: l.Addr().(*net.TCPAddr).AddrPort(), Kind: proxy.HTTPConnect, Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	target, err := proxy.NewHostnameTarget("origin.invalid", 443)
	if err != nil {
		t.Fatal(err)
	}
	policySeen := make(chan string, 1)
	host, err := syntra.OpenHost(syntra.HostConfig{ChannelPolicy: func(_ context.Context, _ syntra.ChannelIdentity, credential []byte) (string, error) {
		policySeen <- string(credential)
		if string(credential) != "protected-hello" {
			return "", securechannel.ErrAuth
		}
		return "route-fixture", nil
	}, Authorize: syntra.AllowAllAuthorize})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		var header []byte
		var one [1]byte
		for len(header) < proxy.MaxConnectHeaderBytes && !strings.HasSuffix(string(header), "\r\n\r\n") {
			if _, err = io.ReadFull(c, one[:]); err != nil {
				done <- err
				return
			}
			header = append(header, one[0])
		}
		want := "CONNECT origin.invalid:443 HTTP/1.1\r\nHost: origin.invalid:443\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("proxy-user:proxy-password")) + "\r\n\r\n"
		if string(header) != want {
			done <- errors.New("hop credential or remote authority mismatch")
			return
		}
		clear(header)
		if _, err = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
			done <- err
			return
		}
		done <- tcp.Accept(ctx, c, securechannel.ServerConfig{StaticKey: key, Scope: "route-fixture", Carrier: securechannel.TCP, AllowBootstrap: true}, host, ordered.Options{})
	}()
	r := Route{Kind: TCPProxy, Proxy: p, Target: target}
	connector, err := New(configFor(r), func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		return securechannel.ClientConfig{Context: securechannel.Context{Carrier: securechannel.TCP, Mode: securechannel.Bootstrap, Scope: "route-fixture"}, ServerPublicKey: key.Public()}, syntra.ClientConfig{Credential: []byte("protected-hello")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := connector(ctx, newBudget(t, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case got := <-policySeen:
		if got != "protected-hello" {
			t.Fatal("proxy credentials reached application policy")
		}
	case <-ctx.Done():
		t.Fatal("protected policy not reached")
	}
	_ = client.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("proxy stream not joined")
	}
}
