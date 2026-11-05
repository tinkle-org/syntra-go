package syntrahttp

import (
	"context"
	"net"
	"net/netip"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

func validClient(cfg securechannel.ClientConfig) bool {
	return cfg.AllowHTTPCandidate && cfg.Context.ValidateWithHTTPCandidate(cfg.AllowHTTPCandidate) == nil &&
		cfg.ServerPublicKey != ([32]byte{}) && (cfg.Context.Mode == securechannel.Returning) == (cfg.AuthorizationKey != (securechannel.Key{}))
}

// ConnectStreams takes ownership of a caller-provisioned HTTP stream pair and
// returns only after Noise and authenticated application Ready. Carrier 4 and
// the security configuration's explicit candidate opt-in are mandatory.
func ConnectStreams(ctx context.Context, upload, download net.Conn, authority Authority, security securechannel.ClientConfig, corecfg syntra.ClientConfig, opts ordered.Options) (*connection.Client, error) {
	if security.Context.Carrier != securechannel.HTTP || !validClient(security) {
		closeConns(upload, download)
		return nil, securechannel.ErrConfig
	}
	return connectPair(ctx, upload, download, authority, security, corecfg, opts)
}
func connectPair(ctx context.Context, u, d net.Conn, a Authority, security securechannel.ClientConfig, core syntra.ClientConfig, opts ordered.Options) (*connection.Client, error) {
	o, err := stream.Options(opts)
	if err != nil {
		closeConns(u, d)
		return nil, err
	}
	carrier, err := ClientPair(u, d, a, o)
	if err != nil {
		return nil, err
	}
	return connection.Connect(ctx, carrier, security, core, o)
}

// ConnectTLSPair consumes two genuine single-use proofs for the same authority,
// client role and original budget. Zero proofs, mismatches and reused proofs
// fail before HTTP bytes are emitted. Ownership transfers even on failure.
func ConnectTLSPair(ctx context.Context, upload, download *tlsstream.Verified, authority Authority, security securechannel.ClientConfig, corecfg syntra.ClientConfig, opts ordered.Options) (*connection.Client, error) {
	defer upload.Close()
	defer download.Close()
	if security.Context.Carrier != securechannel.HTTPS || !validClient(security) || upload == nil || download == nil {
		return nil, securechannel.ErrConfig
	}
	b := upload.Budget()
	if b == nil || b != download.Budget() || opts.Budget != nil && opts.Budget != b {
		return nil, securechannel.ErrConfig
	}
	a, err := authority.TLSAuthority()
	if err != nil {
		return nil, err
	}
	u, err := upload.Consume(a, tlsstream.Client, b)
	if err != nil {
		return nil, err
	}
	d, err := download.Consume(a, tlsstream.Client, b)
	if err != nil {
		_ = u.Close()
		return nil, err
	}
	opts.Budget = b
	return connectPair(ctx, u, d, authority, security, corecfg, opts)
}

// ConnectTLSStreams runs the trusted provider on both exclusively owned sockets
// under one attempt, then consumes both proofs. It never redials a socket.
func ConnectTLSStreams(ctx context.Context, u, d net.Conn, provider tlsstream.Provider, a Authority, security securechannel.ClientConfig, core syntra.ClientConfig, opts ordered.Options) (*connection.Client, error) {
	if u == nil || d == nil || sameConn(u, d) || security.Context.Carrier != securechannel.HTTPS || !validClient(security) {
		closeConns(u, d)
		return nil, securechannel.ErrConfig
	}
	o, err := stream.Options(opts)
	if err != nil {
		closeConns(u, d)
		return nil, err
	}
	ta, err := a.TLSAuthority()
	if err != nil {
		closeConns(u, d)
		return nil, err
	}
	up, err := tlsstream.Connect(ctx, u, provider, ta, o.Budget)
	if err != nil {
		_ = d.Close()
		return nil, err
	}
	defer up.Close()
	down, err := tlsstream.Connect(ctx, d, provider, ta, o.Budget)
	if err != nil {
		return nil, err
	}
	return ConnectTLSPair(ctx, up, down, a, security, core, o)
}

// Dial connects twice to an explicit IP socket address. The application must
// authorize that destination independently of authority and Noise scope/pin.
// A provider is required for HTTPS and forbidden for HTTP. No environment proxy,
// DNS discovery, redirect, fallback, automatic retry or operation replay occurs.
func Dial(ctx context.Context, destination netip.AddrPort, authority Authority, provider tlsstream.Provider, security securechannel.ClientConfig, corecfg syntra.ClientConfig, opts ordered.Options) (*connection.Client, error) {
	if !destination.IsValid() || destination.Port() == 0 || !authority.valid() || !validClient(security) || (security.Context.Carrier != securechannel.HTTP || provider != nil) && (security.Context.Carrier != securechannel.HTTPS || provider == nil) {
		return nil, securechannel.ErrConfig
	}
	o, err := stream.Options(opts)
	if err != nil {
		return nil, err
	}
	attempt, stop := o.Budget.Context(ctx)
	defer stop()
	dialer := net.Dialer{}
	u, err := dialer.DialContext(attempt, "tcp", destination.String())
	if err != nil {
		return nil, stream.Error(err)
	}
	d, err := dialer.DialContext(attempt, "tcp", destination.String())
	if err != nil {
		_ = u.Close()
		return nil, stream.Error(err)
	}
	if provider != nil {
		return ConnectTLSStreams(ctx, u, d, provider, authority, security, corecfg, o)
	}
	return ConnectStreams(ctx, u, d, authority, security, corecfg, o)
}
