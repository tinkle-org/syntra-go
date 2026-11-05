// Package stream gates connected application I/O during establishment.
package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

// Check samples the original budget synchronously. A released budget must return
// nil, allowing the ordered driver to own active-session deadlines.
func Check(b *ordered.EstablishmentBudget) error {
	if b == nil {
		return nil
	}
	return b.Check()
}

// ContextError preserves elapsed deadline causes without exposing diagnostics.
func ContextError(ctx context.Context) error {
	// A socket deadline may fire just before the context timer is scheduled.
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	if ctx.Err() == nil {
		return nil
	}
	if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ctx.Err()
}

// Conn owns exactly one connected stream. Each raw read/write is checked before
// and after I/O, including buffered plaintext returned by a TLS provider.
type Conn struct {
	inner  net.Conn
	budget *ordered.EstablishmentBudget
	once   sync.Once
	closed atomic.Bool
	err    error
}

func New(conn net.Conn, budget *ordered.EstablishmentBudget) *Conn {
	return &Conn{inner: conn, budget: budget}
}

func (c *Conn) Check() error {
	if c.inner == nil || c.closed.Load() {
		return ordered.ErrClosed
	}
	return Check(c.budget)
}

func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Check(); err != nil {
		return 0, err
	}
	n, err := c.inner.Read(p)
	if cutoff := Check(c.budget); cutoff != nil {
		return 0, cutoff
	}
	return n, err
}

func (c *Conn) Write(p []byte) (int, error) {
	if err := c.Check(); err != nil {
		return 0, err
	}
	n, err := c.inner.Write(p)
	if cutoff := Check(c.budget); cutoff != nil {
		return n, cutoff
	}
	return n, err
}

func (c *Conn) Close() error {
	c.once.Do(func() {
		c.closed.Store(true)
		if c.inner != nil {
			c.err = c.inner.Close()
		}
	})
	return c.err
}
func (c *Conn) LocalAddr() net.Addr                { return c.inner.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.inner.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// Do bounds one direction (or both for setup). Callers serialize each selected
// direction. Cancellation interrupts blocked I/O; the callback is joined before
// deadlines are cleared, so it cannot poison a subsequent operation.
func Do(ctx context.Context, conn net.Conn, read, write bool, fn func() error) error {
	if err := ContextError(ctx); err != nil {
		return err
	}
	if gate, ok := conn.(interface{ Check() error }); ok {
		if err := gate.Check(); err != nil {
			return err
		}
	}
	set := func(t time.Time) error {
		if read && write {
			return conn.SetDeadline(t)
		}
		if read {
			return conn.SetReadDeadline(t)
		}
		return conn.SetWriteDeadline(t)
	}
	deadline, _ := ctx.Deadline()
	if err := set(deadline); err != nil {
		return ordered.ErrIO
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = set(time.Now()); close(done) })
	err := fn()
	if !stop() {
		<-done
	}
	clearErr := set(time.Time{})
	if cutoff := ContextError(ctx); cutoff != nil {
		return cutoff
	}
	if gate, ok := conn.(interface{ Check() error }); ok {
		if cutoff := gate.Check(); cutoff != nil {
			return cutoff
		}
	}
	if err != nil {
		return Error(err)
	}
	if clearErr != nil {
		return ordered.ErrIO
	}
	return nil
}

// Error maps opaque stream errors to stable, diagnostic-free carrier errors.
func Error(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{context.Canceled, context.DeadlineExceeded, securechannel.ErrConfig, securechannel.ErrAuth, ordered.ErrProtocol, ordered.ErrOptions, ordered.ErrClosed, ordered.ErrIO} {
		if errors.Is(err, known) {
			return known
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) {
		return ordered.ErrClosed
	}
	return ordered.ErrIO
}

// Options normalizes limits and creates an origin only when none was supplied.
func Options(opts ordered.Options) (ordered.Options, error) {
	o, err := opts.Normalize()
	if err == nil && o.Budget == nil {
		o.Budget, err = ordered.NewEstablishmentBudget(nil, o.AttemptTimeout)
	}
	return o, err
}

// WriteAll detects broken stream implementations that make no progress.
func WriteAll(w io.Writer, p []byte) error {
	for len(p) != 0 {
		n, err := w.Write(p)
		if n < 0 || n > len(p) {
			return ordered.ErrIO
		}
		p = p[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}
