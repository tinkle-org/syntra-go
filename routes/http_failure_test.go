package routes

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/proxy"
	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func TestForwardProtectedRejectionNeverSelectsLaterEndpoint(t *testing.T) {
	cc, sc := integrationSecurity(t, securechannel.Returning, securechannel.HTTP)
	var policies atomic.Int32
	host := integrationHost(&policies)
	host.ChannelPolicy = func(context.Context, syntra.ChannelIdentity, []byte) (string, error) {
		policies.Add(1)
		return "", syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "private-origin-diagnostic")
	}
	origin := integrationOrigin(t, sc, nil, host)
	a := integrationAuthority(t)
	hop := forwardProxy(t, origin.Addr().String(), a)
	p := proxyConfiguration(t, hop, proxy.HTTPConnect)
	target, err := proxy.NewHostnameTarget("localhost", 443)
	if err != nil {
		t.Fatal(err)
	}
	first := Route{Kind: HTTPForward, Proxy: p, Target: target, Authority: a}
	later := Route{Kind: HTTP, Address: localAddress(9), Authority: a}
	cfg := configFor(first, later)
	var dials, inputs atomic.Int32
	cfg.Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if address != hop.address().String() {
			t.Error("authentication failure dialed a later endpoint")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	connector, err := New(cfg, func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		inputs.Add(1)
		return cc, syntra.ClientConfig{Credential: []byte("protected-hello")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := connector(context.Background(), newBudget(t, 2*time.Second))
	var rpc *syntra.RpcError
	// The HTTP owner can retire a rejected initial frame as terminal framing.
	// Neither terminal representation permits routes to try another endpoint.
	auth := errors.Is(err, securechannel.ErrAuth) || errors.As(err, &rpc) && rpc.Code == syntra.ErrorCodeUnauthenticated
	if client != nil || !auth && !errors.Is(err, ordered.ErrProtocol) {
		t.Fatalf("protected rejection lost its terminal type: %v", err)
	}
	if strings.Contains(err.Error(), "private") || strings.Contains(err.Error(), "hop-") {
		t.Fatal("peer diagnostic or hop credential escaped")
	}
	if inputs.Load() != 1 || dials.Load() != 2 || policies.Load() != 1 {
		t.Fatalf("inputs=%d dials=%d policy=%d", inputs.Load(), dials.Load(), policies.Load())
	}
}

func TestProxyAuthenticationFailureNeverSelectsLaterEndpoint(t *testing.T) {
	for _, status := range []string{"403", "407"} {
		t.Run(status, func(t *testing.T) {
			peer := newLoopbackProxy(t, func(_ *loopbackProxy, c net.Conn) error {
				head, err := integrationReadHead(c)
				if err != nil {
					return err
				}
				defer clear(head)
				if !strings.HasPrefix(string(head), "CONNECT localhost:443 HTTP/1.1\r\n") || !strings.Contains(string(head), "Proxy-Authorization: Basic ") {
					return errors.New("proxy authentication request missing")
				}
				_, err = io.WriteString(c, "HTTP/1.1 "+status+" hop-password\r\nX-Reflect: hop-user\r\n\r\n")
				return err
			})
			p := proxyConfiguration(t, peer, proxy.HTTPConnect)
			target, err := proxy.NewHostnameTarget("localhost", 443)
			if err != nil {
				t.Fatal(err)
			}
			cc, _ := integrationSecurity(t, securechannel.Bootstrap, securechannel.HTTP)
			first := Route{Kind: HTTPProxy, Proxy: p, Target: target, Authority: integrationAuthority(t)}
			later := Route{Kind: TCP, Address: localAddress(9)}
			cfg := configFor(first, later)
			var dials, inputs atomic.Int32
			cfg.Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
				dials.Add(1)
				if address != peer.address().String() {
					t.Error("proxy refusal dialed a later endpoint")
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			connector, err := NewCrossCarrier(cfg, CrossCarrierPolicy{[]securechannel.Carrier{securechannel.HTTP, securechannel.TCP}}, func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
				inputs.Add(1)
				return cc, syntra.ClientConfig{}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			client, err := connector(context.Background(), newBudget(t, time.Second))
			if client != nil || !errors.Is(err, securechannel.ErrAuth) {
				t.Fatalf("proxy refusal changed: %v", err)
			}
			if strings.Contains(err.Error(), "hop-") || dials.Load() != 1 || inputs.Load() != 1 {
				t.Fatalf("proxy refusal leaked data or started another attempt: dials=%d inputs=%d", dials.Load(), inputs.Load())
			}
		})
	}
}

func TestHTTPProtocolFailureNeverSelectsLaterEndpoint(t *testing.T) {
	a := integrationAuthority(t)
	peer := newLoopbackProxy(t, func(_ *loopbackProxy, c net.Conn) error {
		head, err := integrationReadHead(c)
		if err != nil {
			return nil
		}
		parsed, err := syntrahttp.ParseRequest(head, a, syntrahttp.OriginPolicy{})
		if err != nil {
			return err
		}
		body := make([]byte, parsed.BodyLen)
		defer clear(body)
		if _, err = io.ReadFull(c, body); err != nil {
			return err
		}
		_, err = io.WriteString(c, "HTTP/1.1 201 private-peer-diagnostic\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n")
		return err
	})
	cc, _ := integrationSecurity(t, securechannel.Bootstrap, securechannel.HTTP)
	first := Route{Kind: HTTP, Address: peer.address(), Authority: a}
	later := first
	later.Address = localAddress(9)
	cfg := configFor(first, later)
	var dials, inputs atomic.Int32
	cfg.Dialer = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		if address != peer.address().String() {
			t.Error("protocol failure dialed a later endpoint")
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	connector, err := New(cfg, func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		inputs.Add(1)
		return cc, syntra.ClientConfig{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := connector(context.Background(), newBudget(t, 2*time.Second))
	if client != nil || !errors.Is(err, ordered.ErrProtocol) {
		t.Fatalf("malformed response was not terminal framing: %v", err)
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatal("peer diagnostic escaped")
	}
	if inputs.Load() != 1 || dials.Load() != 2 {
		t.Fatal("protocol failure started another route")
	}
}

type jumpReadConn struct {
	*bufferConn
	age   *atomic.Int64
	reads int
}

func (c *jumpReadConn) Read(p []byte) (int, error) {
	c.reads++
	if len(p) == 0 {
		return 0, nil
	}
	p[0] = 'H'
	c.age.Store(int64(time.Second))
	return 1, nil
}

func TestHTTPRawReadChecksOriginalBudgetBeforeAndAfterBytes(t *testing.T) {
	cc, _ := integrationSecurity(t, securechannel.Bootstrap, securechannel.HTTP)
	a := integrationAuthority(t)
	var age atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	b, err := ordered.NewEstablishmentBudget(clock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw := &jumpReadConn{bufferConn: &bufferConn{}, age: &age}
	download := &bufferConn{}
	cfg := configFor(Route{Kind: HTTP, Address: localAddress(1), Authority: a})
	cfg.Options.AttemptTimeout = time.Second
	var calls int
	cfg.Dialer = func(context.Context, string, string) (net.Conn, error) {
		calls++
		if calls == 1 {
			return raw, nil
		}
		return download, nil
	}
	connector, err := New(cfg, func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		return cc, syntra.ClientConfig{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := connector(context.Background(), b)
	if client != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("raw-read deadline changed: %v", err)
	}
	if calls != 2 || raw.reads != 1 || !raw.closed || !download.closed {
		t.Fatalf("calls=%d reads=%d uploadClosed=%t downloadClosed=%t", calls, raw.reads, raw.closed, download.closed)
	}
	if !errors.Is(b.Check(), context.DeadlineExceeded) {
		t.Fatal("raw reader did not retain original owner clock")
	}
}

func TestForwardRawReadUsesOriginalGateAndHonorsRelease(t *testing.T) {
	for _, release := range []bool{false, true} {
		var age atomic.Int64
		clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
		b, err := ordered.NewEstablishmentBudget(clock, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		if release {
			b.Release()
		}
		raw := &jumpReadConn{bufferConn: &bufferConn{}, age: &age}
		forward := forwardFixture(t, raw, false, b)
		defer forward.Close()
		var one [1]byte
		n, err := forward.Read(one[:])
		if release {
			if err != nil || n != 1 {
				t.Fatalf("released gate rejected active read: %v", err)
			}
		} else {
			if n != 0 || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expired raw bytes escaped: n=%d err=%v", n, err)
			}
			if _, err := forward.Read(one[:]); !errors.Is(err, context.DeadlineExceeded) || raw.reads != 1 {
				t.Fatal("expired stream repolled raw reader")
			}
		}
	}
}

func TestHTTPRoutesRejectUnprovisionedIPAuthorityBeforeInputs(t *testing.T) {
	for _, value := range []string{"0.0.0.0:443", "[::]:443", "224.0.0.1:443", "[::ffff:224.0.0.1]:443"} {
		a, err := syntrahttp.NewAuthority(value)
		if err != nil {
			t.Fatal(err)
		}
		r := Route{Kind: HTTP, Address: netip.MustParseAddrPort("127.0.0.1:1"), Authority: a}
		if _, err := NewWithSetup(configFor(r), neverInputs); !errors.Is(err, securechannel.ErrConfig) {
			t.Fatalf("accepted invalid authority %s", value)
		}
	}
}
