// Package routes composes explicitly provisioned connection paths. Each call
// selects one endpoint and obtains fresh application-owned security inputs.
package routes

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/proxy"
	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
	"github.com/tinkle-org/syntra-go/transport/websocket"
)

const MaxRoutes = 256

type Kind uint8

const (
	TCP Kind = iota + 1
	TCPProxy
	WS
	WSS
	WSSProxy
	HTTP
	HTTPS
	HTTPProxy
	HTTPSProxy
	HTTPForward
)

// Endpoint is a comparable, secret-free allowlist identity. A proxy identity
// includes the dialed socket and requested target. URL authority is independent
// of a provisioned direct address. Exact URL spelling participates in equality.
type Endpoint struct {
	Kind      Kind
	Address   netip.AddrPort
	Proxy     netip.AddrPort
	Target    proxy.Target
	URL       string
	Authority syntrahttp.Authority
}

func (e Endpoint) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[route endpoint]") }
func (e Endpoint) Carrier() securechannel.Carrier {
	switch e.Kind {
	case TCP, TCPProxy:
		return securechannel.TCP
	case WS:
		return securechannel.WS
	case WSS, WSSProxy:
		return securechannel.WSS
	case HTTP, HTTPProxy, HTTPForward:
		return securechannel.HTTP
	case HTTPS, HTTPSProxy:
		return securechannel.HTTPS
	}
	return 0
}

func validSocket(a netip.AddrPort) bool {
	return a.IsValid() && a.Port() != 0 && a.Addr().Zone() == "" && !a.Addr().Unmap().IsUnspecified() && !a.Addr().Unmap().IsMulticast()
}

func (e Endpoint) Validate() error {
	proxied := e.proxied()
	if proxied {
		if e.Address != (netip.AddrPort{}) || !validSocket(e.Proxy) || e.Target.Validate() != nil {
			return securechannel.ErrConfig
		}
	} else if !validSocket(e.Address) || e.Proxy != (netip.AddrPort{}) || e.Target != (proxy.Target{}) {
		return securechannel.ErrConfig
	}
	switch e.Kind {
	case TCP, TCPProxy:
		if e.URL != "" || e.Authority != (syntrahttp.Authority{}) {
			return securechannel.ErrConfig
		}
	case WS, WSS, WSSProxy:
		if e.Authority != (syntrahttp.Authority{}) {
			return securechannel.ErrConfig
		}
		a, err := urlAuthority(e.URL, e.Kind == WS)
		if err != nil {
			return err
		}
		if e.Kind == WS {
			ip, err := netip.ParseAddr(a.Host())
			if !e.Address.Addr().Unmap().IsLoopback() || a.Host() != "localhost" && (err != nil || !ip.Unmap().IsLoopback()) {
				return securechannel.ErrConfig
			}
		}
		if e.Kind == WSSProxy && e.Target.Authority() != a.String() {
			return securechannel.ErrConfig
		}
	case HTTP, HTTPS, HTTPProxy, HTTPSProxy, HTTPForward:
		if e.URL != "" {
			return securechannel.ErrConfig
		}
		a, err := syntrahttp.NewAuthority(e.Authority.String())
		if err != nil || a != e.Authority {
			return securechannel.ErrConfig
		}
		ta, err := a.TLSAuthority()
		if err != nil {
			return securechannel.ErrConfig
		}
		if ip, err := netip.ParseAddr(ta.Host()); err == nil {
			if !validSocket(netip.AddrPortFrom(ip, ta.Port())) {
				return securechannel.ErrConfig
			}
		} else if _, err := proxy.NewHostnameTarget(ta.Host(), ta.Port()); err != nil {
			return securechannel.ErrConfig
		}
		if proxied && e.Target.Authority() != a.String() {
			return securechannel.ErrConfig
		}
	default:
		return securechannel.ErrConfig
	}
	return nil
}
func (e Endpoint) proxied() bool {
	return e.Kind == TCPProxy || e.Kind == WSSProxy || e.Kind == HTTPProxy || e.Kind == HTTPSProxy || e.Kind == HTTPForward
}
func (e Endpoint) http() bool { return e.Kind >= HTTP && e.Kind <= HTTPForward }

// Route adds application-owned TLS policy and hop credentials to an endpoint.
// Proxy configurations and providers must remain valid throughout connector use.
type Route struct {
	Kind      Kind
	Address   netip.AddrPort
	Proxy     *proxy.ProxyConfig
	Target    proxy.Target
	URL       string
	TLS       tlsstream.Provider
	Authority syntrahttp.Authority
}

func (Route) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[route configuration]") }
func (r Route) Endpoint() Endpoint {
	e := Endpoint{Kind: r.Kind, Address: r.Address, Target: r.Target, URL: r.URL, Authority: r.Authority}
	if r.Proxy != nil {
		e.Proxy = r.Proxy.Endpoint()
	}
	return e
}
func (r Route) validate() error {
	if err := r.Endpoint().Validate(); err != nil {
		return err
	}
	proxied := r.Endpoint().proxied()
	if proxied {
		if r.Proxy.Validate() != nil {
			return securechannel.ErrConfig
		}
	} else if r.Proxy != nil {
		return securechannel.ErrConfig
	}
	if r.Kind == HTTPForward && r.Proxy.Kind() != proxy.HTTPConnect {
		return securechannel.ErrConfig
	}
	secure := r.Kind == WSS || r.Kind == WSSProxy || r.Kind == HTTPS || r.Kind == HTTPSProxy
	if secure && r.TLS == nil || !secure && r.TLS != nil {
		return securechannel.ErrConfig
	}
	return nil
}

// RouteConfig is snapshotted by construction. Dialer is optional; the default
// net.Dialer receives only prevalidated numeric addresses. Options.Budget must be
// empty: each invocation receives the supervising owner's original budget.
type RouteConfig struct {
	Routes    []Route
	Allowlist []Endpoint
	Options   ordered.Options
	Dialer    proxy.Dialer
}

func (RouteConfig) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[routes configuration]") }

type CrossCarrierPolicy struct{ PermittedCarriers []securechannel.Carrier }

// Connector is structurally convertible to an owning supervisor's connector.
// It owns one attempt, without retries, redirects, discovery, or replay.
type Connector func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error)

// ConnectorWithSetup installs per-attempt preparation before the client's Run.
// The supervisor supplies prepare, for example to attach a recovery session.
// It is composed after ClientConfig.Prepare, and each runs at most once.
type ConnectorWithSetup func(context.Context, *ordered.EstablishmentBudget, func(*syntra.Client) error) (*connection.Client, error)

// Inputs returns fresh per-endpoint encryption and protected hello settings.
// It executes outside the selection lock, must honor ctx, and must not learn
// trust or change authentication mode from untrusted endpoint responses.
type Inputs func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error)

// New requires one homogeneous carrier throughout routes and the full allowlist.
func New(cfg RouteConfig, inputs Inputs) (Connector, error) {
	connector, err := NewWithSetup(cfg, inputs)
	if err != nil {
		return nil, err
	}
	return withoutSetup(connector), nil
}

// NewWithSetup constructs a homogeneous connector with per-attempt preparation.
// It preserves and composes the Prepare function returned by Inputs.
func NewWithSetup(cfg RouteConfig, inputs Inputs) (ConnectorWithSetup, error) {
	return build(cfg, nil, inputs)
}

// NewCrossCarrier requires explicit nonempty, bounded, duplicate-free carrier
// permissions. Plain WebSocket is excluded, including loopback fixtures.
func NewCrossCarrier(cfg RouteConfig, policy CrossCarrierPolicy, inputs Inputs) (Connector, error) {
	connector, err := NewCrossCarrierWithSetup(cfg, policy, inputs)
	if err != nil {
		return nil, err
	}
	return withoutSetup(connector), nil
}

// NewCrossCarrierWithSetup combines explicit carrier permissions with preparation
// installed before Run. It uses the same one-endpoint selection policy as New.
func NewCrossCarrierWithSetup(cfg RouteConfig, policy CrossCarrierPolicy, inputs Inputs) (ConnectorWithSetup, error) {
	if len(policy.PermittedCarriers) == 0 || len(policy.PermittedCarriers) > 4 {
		return nil, securechannel.ErrConfig
	}
	seen := make(map[securechannel.Carrier]bool, len(policy.PermittedCarriers))
	for _, c := range policy.PermittedCarriers {
		if c != securechannel.TCP && c != securechannel.WSS && c != securechannel.HTTP && c != securechannel.HTTPS || seen[c] {
			return nil, securechannel.ErrConfig
		}
		seen[c] = true
	}
	return build(cfg, seen, inputs)
}

func withoutSetup(connector ConnectorWithSetup) Connector {
	return func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
		return connector(ctx, b, nil)
	}
}

func build(cfg RouteConfig, permitted map[securechannel.Carrier]bool, inputs Inputs) (ConnectorWithSetup, error) {
	if inputs == nil || len(cfg.Routes) == 0 || len(cfg.Routes) > MaxRoutes || len(cfg.Allowlist) == 0 || len(cfg.Allowlist) > MaxRoutes || cfg.Options.Budget != nil {
		return nil, securechannel.ErrConfig
	}
	o, err := cfg.Options.Normalize()
	if err != nil {
		return nil, err
	}
	first := cfg.Routes[0].Endpoint().Carrier()
	allowed := make(map[Endpoint]bool, len(cfg.Allowlist))
	for _, e := range cfg.Allowlist {
		if e.Validate() != nil || permitted == nil && e.Carrier() != first || permitted != nil && !permitted[e.Carrier()] {
			return nil, securechannel.ErrConfig
		}
		allowed[e] = true
	}
	for _, r := range cfg.Routes {
		e := r.Endpoint()
		if r.validate() != nil || !allowed[e] || permitted == nil && e.Carrier() != first || permitted != nil && !permitted[e.Carrier()] {
			return nil, securechannel.ErrConfig
		}
	}
	routes := append([]Route(nil), cfg.Routes...)
	dial := cfg.Dialer
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	var mu sync.Mutex
	cursor := 0
	return func(ctx context.Context, b *ordered.EstablishmentBudget, prepare func(*syntra.Client) error) (*connection.Client, error) {
		if ctx == nil || b == nil {
			return nil, securechannel.ErrConfig
		}
		if err := b.Check(); err != nil {
			return nil, err
		}
		if err := b.Cap(o.AttemptTimeout); err != nil {
			return nil, err
		}
		attempt, cancel := b.Context(ctx)
		defer cancel()
		if err := check(attempt, b); err != nil {
			return nil, err
		}
		mu.Lock()
		if err := check(attempt, b); err != nil {
			mu.Unlock()
			return nil, err
		}
		r := routes[cursor]
		cursor = (cursor + 1) % len(routes)
		mu.Unlock()
		if err := check(attempt, b); err != nil {
			return nil, err
		}
		security, core, err := inputs(attempt, r.Endpoint())
		if err != nil {
			return nil, err
		}
		if err := check(attempt, b); err != nil {
			return nil, err
		}
		if security.Context.Carrier != r.Endpoint().Carrier() || security.Context.ValidateWithHTTPCandidate(security.AllowHTTPCandidate) != nil || security.ServerPublicKey == ([32]byte{}) || security.Context.Mode == securechannel.Returning && security.AuthorizationKey == (securechannel.Key{}) {
			return nil, securechannel.ErrConfig
		}
		if r.Endpoint().http() && !security.AllowHTTPCandidate {
			return nil, securechannel.ErrConfig
		}
		core.Prepare = composePrepare(core.Prepare, prepare)
		opts := o
		opts.Budget = b
		return r.connect(attempt, security, core, opts, dial)
	}, nil
}

func composePrepare(base, prepare func(*syntra.Client) error) func(*syntra.Client) error {
	if base == nil {
		return prepare
	}
	if prepare == nil {
		return base
	}
	return func(client *syntra.Client) error {
		if err := base(client); err != nil {
			return err
		}
		return prepare(client)
	}
}
func check(ctx context.Context, b *ordered.EstablishmentBudget) error {
	if err := b.Check(); err != nil {
		return err
	}
	return stream.ContextError(ctx)
}

func (r Route) connect(ctx context.Context, security securechannel.ClientConfig, core syntra.ClientConfig, opts ordered.Options, dial proxy.Dialer) (*connection.Client, error) {
	if err := check(ctx, opts.Budget); err != nil {
		return nil, err
	}
	if r.Endpoint().http() {
		return r.connectHTTP(ctx, security, core, opts, dial)
	}
	raw, err := r.open(ctx, opts.Budget, dial)
	if err != nil {
		return nil, err
	}
	if err := check(ctx, opts.Budget); err != nil {
		_ = raw.Close()
		return nil, err
	}
	switch r.Kind {
	case TCP, TCPProxy:
		return tcp.Connect(ctx, raw, security, core, opts)
	case WS:
		return websocket.Connect(ctx, raw, r.URL, security, core, opts)
	case WSS, WSSProxy:
		a, err := urlAuthority(r.URL, false)
		if err != nil {
			_ = raw.Close()
			return nil, err
		}
		verified, err := tlsstream.Connect(ctx, raw, r.TLS, a, opts.Budget)
		if err != nil {
			return nil, err
		}
		return websocket.ConnectTLS(ctx, verified, r.URL, security, core, opts)
	default:
		_ = raw.Close()
		return nil, securechannel.ErrConfig
	}
}

func (r Route) open(ctx context.Context, b *ordered.EstablishmentBudget, dial proxy.Dialer) (net.Conn, error) {
	if err := check(ctx, b); err != nil {
		return nil, err
	}
	if r.Endpoint().proxied() && r.Kind != HTTPForward {
		return proxy.TunnelWithDialer(ctx, r.Proxy, r.Target, b, dial)
	}
	address := r.Address
	if r.Kind == HTTPForward {
		address = r.Proxy.Endpoint()
	}
	c, err := dial(ctx, "tcp", address.String())
	if cutoff := check(ctx, b); cutoff != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, cutoff
	}
	if err != nil {
		if c != nil {
			_ = c.Close()
		}
		return nil, stream.Error(err)
	}
	if c == nil {
		return nil, securechannel.ErrConfig
	}
	return c, nil
}

func (r Route) connectHTTP(ctx context.Context, security securechannel.ClientConfig, core syntra.ClientConfig, opts ordered.Options, dial proxy.Dialer) (*connection.Client, error) {
	u, err := r.open(ctx, opts.Budget, dial)
	if err != nil {
		return nil, err
	}
	d, err := r.open(ctx, opts.Budget, dial)
	if err != nil {
		_ = u.Close()
		return nil, err
	}
	if sameConnection(u, d) {
		_ = u.Close()
		return nil, securechannel.ErrConfig
	}
	switch r.Kind {
	case HTTPS, HTTPSProxy:
		return syntrahttp.ConnectTLSStreams(ctx, u, d, r.TLS, r.Authority, security, core, opts)
	case HTTPForward:
		u = newForwardConn(u, r.Proxy, r.Authority, true, opts.Budget)
		d = newForwardConn(d, r.Proxy, r.Authority, false, opts.Budget)
	}
	return syntrahttp.ConnectStreams(ctx, u, d, r.Authority, security, core, opts)
}

func sameConnection(a, b net.Conn) bool {
	// Conn implementations may have incomparable dynamic values. Reflection
	// permits an identity check without panicking on those implementations.
	x, y := reflect.ValueOf(a), reflect.ValueOf(b)
	return x.Type() == y.Type() && x.Comparable() && x.Equal(y)
}

func urlAuthority(raw string, plain bool) (tlsstream.Authority, error) {
	fail := func() (tlsstream.Authority, error) { return tlsstream.Authority{}, securechannel.ErrConfig }
	if len(raw) > 2048 {
		return fail()
	}
	for _, b := range []byte(raw) {
		if b <= 0x20 || b >= 0x7f {
			return fail()
		}
	}
	scheme, rest, ok := strings.Cut(raw, "://")
	expected, port := "wss", uint16(443)
	if plain {
		expected, port = "ws", 80
	}
	a, path, slash := strings.Cut(rest, "/")
	if !ok || !slash || scheme != expected || "/"+path != websocket.EndpointPath || a == "" || strings.ContainsAny(a, "@\\%?#") {
		return fail()
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return fail()
	}
	if strings.HasPrefix(u.Host, "[") {
		ip, err := netip.ParseAddr(u.Hostname())
		if err != nil || !ip.Is6() {
			return fail()
		}
	} else if strings.ContainsAny(u.Host, "[]") || strings.Contains(u.Hostname(), ":") {
		return fail()
	}
	if u.Port() != "" {
		n, err := strconv.ParseUint(u.Port(), 10, 16)
		if err != nil || n == 0 {
			return fail()
		}
		port = uint16(n)
	} else if strings.HasSuffix(a, ":") {
		return fail()
	}
	auth, err := tlsstream.NewAuthority(u.Hostname(), port)
	if err != nil {
		return fail()
	}
	if ip, err := netip.ParseAddr(auth.Host()); err == nil {
		if !validSocket(netip.AddrPortFrom(ip, port)) {
			return fail()
		}
	} else {
		if _, err := proxy.NewHostnameTarget(auth.Host(), port); err != nil {
			return fail()
		}
	}
	return auth, nil
}
