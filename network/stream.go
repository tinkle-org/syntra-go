package network

import (
	"context"
	"net"

	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

// StreamHost supplies owned connected sockets, including application-owned
// platform sockets. Open must honor ctx and never detach dial/cleanup work.
// A net.Conn alone makes no claim about TLS authentication.
type StreamHost interface {
	Open(ctx context.Context, address string) (net.Conn, error)
}
type StreamHostFunc func(context.Context, string) (net.Conn, error)

func (f StreamHostFunc) Open(ctx context.Context, address string) (net.Conn, error) {
	return f(ctx, address)
}

type TCPStreamHost struct{ Dialer net.Dialer }

func (h *TCPStreamHost) Open(ctx context.Context, address string) (net.Conn, error) {
	return h.Dialer.DialContext(ctx, "tcp", address)
}

type TLSProvider = tlsstream.Provider
type TLSAuthority = tlsstream.Authority

// Open bounds a configured stream host by the unchanged establishment budget.
// Ownership of any returned stream transfers even when Open reports an error.
// It is intended to run inside an owned Connector invocation.
func (n *Network) Open(ctx context.Context, address string, budget *ordered.EstablishmentBudget) (net.Conn, error) {
	if budget == nil {
		return nil, ErrConfig
	}
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return nil, ErrClosed
	}
	if !n.reserveCall() {
		n.mu.Unlock()
		return nil, ErrBusy
	}
	n.mu.Unlock()
	defer n.releaseCall()
	if ctx.Value(callbackOwnerKey{}) != n {
		if !n.reserveCallback() {
			return nil, ErrBusy
		}
		defer n.releaseCallback()
	}
	lifetime, stop := context.WithCancel(ctx)
	stopNetwork := context.AfterFunc(n.ctx, stop)
	defer stopNetwork()
	defer stop()
	if n.ctx.Err() != nil {
		stop()
	}
	host := n.cfg.StreamHost
	if host == nil {
		host = &TCPStreamHost{}
	}
	attempt, cancel := budget.Context(lifetime)
	defer cancel()
	conn, err := host.Open(attempt, address)
	if cutoff := stream.ContextError(attempt); cutoff != nil {
		err = cutoff
	}
	if cutoff := stream.Check(budget); cutoff != nil {
		err = cutoff
	}
	if conn == nil && err == nil {
		err = ErrConfig
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, Sanitize(err)
	}
	return conn, nil
}
