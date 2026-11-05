package websocket

import (
	"context"
	"net"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

// NewClient upgrades an owned loopback WS connection. It checks both the URL
// host and the actual peer address. Pass budget unchanged to the ordered driver.
func NewClient(ctx context.Context, conn net.Conn, rawURL string, budget *ordered.EstablishmentBudget) (ordered.MessageIO, error) {
	a, err := endpoint(rawURL, false)
	if err != nil || !loopbackPeer(conn) {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, securechannel.ErrConfig
	}
	return upgrade(ctx, conn, a, true, budget)
}

// NewServer upgrades an owned loopback WS connection at the exact endpoint.
func NewServer(ctx context.Context, conn net.Conn, budget *ordered.EstablishmentBudget) (ordered.MessageIO, error) {
	if !loopbackPeer(conn) {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, securechannel.ErrConfig
	}
	return upgrade(ctx, conn, tlsstream.Authority{}, false, budget)
}

// NewClientTLS consumes the single-use proof before writing HTTP. The original
// TLS budget, authority, and client role must match exactly.
func NewClientTLS(ctx context.Context, verified *tlsstream.Verified, rawURL string, budget *ordered.EstablishmentBudget) (ordered.MessageIO, error) {
	a, err := endpoint(rawURL, true)
	if err != nil {
		_ = verified.Close()
		return nil, err
	}
	conn, err := verified.Consume(a, tlsstream.Client, budget)
	if err != nil {
		return nil, err
	}
	return upgrade(ctx, conn, a, true, budget)
}

// NewServerTLS checks a provisioned local authority, not a forwarded claim.
func NewServerTLS(ctx context.Context, verified *tlsstream.Verified, authority tlsstream.Authority, budget *ordered.EstablishmentBudget) (ordered.MessageIO, error) {
	conn, err := verified.Consume(authority, tlsstream.Server, budget)
	if err != nil {
		return nil, err
	}
	return upgrade(ctx, conn, authority, false, budget)
}

func Connect(ctx context.Context, conn net.Conn, rawURL string, security securechannel.ClientConfig, cfg syntra.ClientConfig, opts ordered.Options) (*connection.Client, error) {
	if security.Context.Carrier != securechannel.WS {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, securechannel.ErrConfig
	}
	o, err := stream.Options(opts)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	carrier, err := NewClient(ctx, conn, rawURL, o.Budget)
	if err != nil {
		return nil, err
	}
	return connection.Connect(ctx, carrier, security, cfg, o)
}

func Accept(ctx context.Context, conn net.Conn, security securechannel.ServerConfig, host *syntra.Host, opts ordered.Options) error {
	if security.Carrier != securechannel.WS {
		if conn != nil {
			_ = conn.Close()
		}
		return securechannel.ErrConfig
	}
	o, err := stream.Options(opts)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return err
	}
	carrier, err := NewServer(ctx, conn, o.Budget)
	if err != nil {
		return err
	}
	return connection.Accept(ctx, carrier, security, host, o)
}

// ConnectTLS continues the proof's original attempt through upgrade and Ready.
// An omitted Options.Budget selects the proof's budget, never a new origin.
func ConnectTLS(ctx context.Context, verified *tlsstream.Verified, rawURL string, security securechannel.ClientConfig, cfg syntra.ClientConfig, opts ordered.Options) (*connection.Client, error) {
	if security.Context.Carrier != securechannel.WSS {
		_ = verified.Close()
		return nil, securechannel.ErrConfig
	}
	if opts.Budget == nil {
		opts.Budget = verified.Budget()
	}
	o, err := opts.Normalize()
	if err != nil {
		_ = verified.Close()
		return nil, err
	}
	carrier, err := NewClientTLS(ctx, verified, rawURL, o.Budget)
	if err != nil {
		return nil, err
	}
	return connection.Connect(ctx, carrier, security, cfg, o)
}

func AcceptTLS(ctx context.Context, verified *tlsstream.Verified, authority tlsstream.Authority, security securechannel.ServerConfig, host *syntra.Host, opts ordered.Options) error {
	if security.Carrier != securechannel.WSS {
		_ = verified.Close()
		return securechannel.ErrConfig
	}
	if opts.Budget == nil {
		opts.Budget = verified.Budget()
	}
	o, err := opts.Normalize()
	if err != nil {
		_ = verified.Close()
		return err
	}
	carrier, err := NewServerTLS(ctx, verified, authority, o.Budget)
	if err != nil {
		return err
	}
	return connection.Accept(ctx, carrier, security, host, o)
}
