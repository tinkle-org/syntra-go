// Package tcp implements the SC1 draft-1 TCP carrier (u16 BE record length).
package tcp

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func Client(ctx context.Context, conn net.Conn, cfg securechannel.ClientConfig, opts ordered.Options) (*ordered.Transport, error) {
	if cfg.Context.Carrier != securechannel.TCP {
		conn.Close()
		return nil, securechannel.ErrConfig
	}
	o, err := opts.Normalize()
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ordered.Client(ctx, &messageIO{conn, o.RecordTimeout}, cfg, o)
}

func Server(ctx context.Context, conn net.Conn, cfg securechannel.ServerConfig, opts ordered.Options) (*ordered.Transport, error) {
	if cfg.Carrier != securechannel.TCP || cfg.Validate() != nil {
		conn.Close()
		return nil, securechannel.ErrConfig
	}
	o, err := opts.Normalize()
	if err != nil {
		conn.Close()
		return nil, err
	}
	return ordered.Server(ctx, &messageIO{conn, o.RecordTimeout}, cfg, o)
}

// Dial counts dialing and SC1 establishment against a single Lifetime budget
// from entry, with establishment also capped by HandshakeTimeout and ctx.
func Dial(ctx context.Context, address string, cfg securechannel.ClientConfig, opts ordered.Options) (*ordered.Transport, error) {
	return dial(ctx, address, cfg, opts, (&net.Dialer{}).DialContext)
}

func dial(ctx context.Context, address string, cfg securechannel.ClientConfig, opts ordered.Options, dialContext func(context.Context, string, string) (net.Conn, error)) (*ordered.Transport, error) {
	started := time.Now()
	o, err := opts.Normalize()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithDeadline(ctx, started.Add(min(o.HandshakeTimeout, o.Lifetime)))
	defer cancel()
	conn, err := dialContext(ctx, "tcp", address)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ordered.ErrIO
	}
	o.Lifetime -= time.Since(started)
	if o.Lifetime <= 0 {
		conn.Close()
		return nil, context.DeadlineExceeded
	}
	return Client(ctx, conn, cfg, o)
}

type messageIO struct {
	conn     net.Conn
	assembly time.Duration
}

func (m *messageIO) Close() error { return m.conn.Close() }

// deadline binds cancellation to socket I/O and joins the callback before
// clearing deadlines, so an old callback cannot poison the next operation.
func deadline(ctx context.Context, set func(time.Time) error) func() {
	d, _ := ctx.Deadline()
	_ = set(d)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = set(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
		_ = set(time.Time{})
	}
}

func (m *messageIO) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	finish := deadline(ctx, m.conn.SetReadDeadline)
	defer finish()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var prefix [2]byte
	// Idle is unlimited; as soon as the first length byte arrives, the whole
	// record (including the second length byte) has one absolute deadline.
	if _, err := io.ReadFull(m.conn, prefix[:1]); err != nil {
		return nil, err
	}
	d := time.Now().Add(m.assembly)
	if outer, ok := ctx.Deadline(); ok && outer.Before(d) {
		d = outer
	}
	_ = m.conn.SetReadDeadline(d)
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if _, err := io.ReadFull(m.conn, prefix[1:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(prefix[:]))
	if n == 0 || n > cap(dst) {
		return nil, ordered.ErrProtocol
	}
	dst = dst[:n]
	_, err := io.ReadFull(m.conn, dst)
	return dst, err
}

func (m *messageIO) WriteMessage(ctx context.Context, msg []byte) error {
	if len(msg) == 0 || len(msg) > securechannel.MaxCiphertext {
		return ordered.ErrProtocol
	}
	finish := deadline(ctx, m.conn.SetWriteDeadline)
	defer finish()
	if err := ctx.Err(); err != nil {
		return err
	}
	var prefix [2]byte
	binary.BigEndian.PutUint16(prefix[:], uint16(len(msg)))
	for _, p := range [][]byte{prefix[:], msg} {
		for len(p) != 0 {
			n, err := m.conn.Write(p)
			if err != nil {
				return err
			}
			if n <= 0 || n > len(p) {
				return io.ErrShortWrite
			}
			p = p[n:]
		}
	}
	return ctx.Err()
}
