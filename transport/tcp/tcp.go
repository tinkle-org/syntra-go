// Package tcp carries encrypted Syntra records on an owned connected stream.
package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
)

const Binding = "syntra.1.0"

type records struct{ conn *stream.Conn }

// SupportsTerminalReceipt opts this ordered, cancellation-aware stream into the
// complete-frame barrier and exact-ciphertext terminal handoff contract.
func (r *records) SupportsTerminalReceipt() bool { return true }

// New takes ownership of conn. The same budget must be passed to the ordered
// driver; nil is useful only when establishment is managed externally.
func New(conn net.Conn, budget *ordered.EstablishmentBudget) ordered.MessageIO {
	return &records{conn: stream.New(conn, budget)}
}

func (r *records) Close() error { return stream.Error(r.conn.Close()) }
func (r *records) ReadMessage(ctx context.Context, dst []byte) (out []byte, err error) {
	err = stream.Do(ctx, r.conn, true, false, func() error {
		var prefix [2]byte
		if _, err := io.ReadFull(r.conn, prefix[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(prefix[:]))
		if n < 17 || n > min(cap(dst), securechannel.MaxCiphertext) {
			return ordered.ErrProtocol
		}
		out = dst[:n]
		_, err := io.ReadFull(r.conn, out)
		return err
	})
	if err != nil {
		_ = r.Close()
		return nil, err
	}
	return out, nil
}

func (r *records) WriteMessage(ctx context.Context, p []byte) error {
	if len(p) < 17 || len(p) > securechannel.MaxCiphertext {
		_ = r.Close()
		return ordered.ErrProtocol
	}
	err := stream.Do(ctx, r.conn, false, true, func() error {
		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(p)))
		if err := stream.WriteAll(r.conn, prefix[:]); err != nil {
			return err
		}
		return stream.WriteAll(r.conn, p)
	})
	if err != nil {
		_ = r.Close()
	}
	return err
}

// Connect owns a connected stream through authentication and core readiness.
func Connect(ctx context.Context, conn net.Conn, security securechannel.ClientConfig, cfg syntra.ClientConfig, opts ordered.Options) (*connection.Client, error) {
	if conn == nil {
		return nil, connection.ErrConfig
	}
	if security.Context.Carrier != securechannel.TCP {
		_ = conn.Close()
		return nil, securechannel.ErrConfig
	}
	o, err := stream.Options(opts)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return connection.Connect(ctx, New(conn, o.Budget), security, cfg, o)
}

// Accept serves an owned connected stream until cancellation or session close.
func Accept(ctx context.Context, conn net.Conn, security securechannel.ServerConfig, host *syntra.Host, opts ordered.Options) error {
	if conn == nil {
		return connection.ErrConfig
	}
	if security.Carrier != securechannel.TCP {
		_ = conn.Close()
		return securechannel.ErrConfig
	}
	o, err := stream.Options(opts)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return connection.Accept(ctx, New(conn, o.Budget), security, host, o)
}

// Dial includes address resolution and connection setup in the original budget.
func Dial(ctx context.Context, address string, security securechannel.ClientConfig, cfg syntra.ClientConfig, opts ordered.Options) (*connection.Client, error) {
	if security.Context.Carrier != securechannel.TCP {
		return nil, securechannel.ErrConfig
	}
	o, err := stream.Options(opts)
	if err != nil {
		return nil, err
	}
	attempt, cancel := o.Budget.Context(ctx)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(attempt, "tcp", address)
	if err != nil {
		if cutoff := stream.ContextError(attempt); cutoff != nil {
			return nil, cutoff
		}
		return nil, ordered.ErrIO
	}
	if err := stream.Check(o.Budget); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return Connect(ctx, conn, security, cfg, o)
}
