package websocket

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// messageBudget bounds every started wire frame, including control/reserved
// headers. A data message keeps its absolute budget across fragments and controls;
// completed idle controls release their own budget so idle reads stay unlimited.
type messageBudget struct {
	mu       sync.Mutex
	cancel   context.CancelFunc
	timer    *time.Timer
	fired    chan struct{}
	duration time.Duration
	message  bool
}

func (b *messageBudget) begin(cancel context.CancelFunc, duration time.Duration) {
	b.mu.Lock()
	b.cancel, b.duration = cancel, duration
	b.mu.Unlock()
}

func (b *messageBudget) start() {
	b.mu.Lock()
	b.message = true
	b.startLocked()
	b.mu.Unlock()
}

func (b *messageBudget) startFrame(control bool) {
	b.mu.Lock()
	if !control {
		b.message = true
	}
	b.startLocked()
	b.mu.Unlock()
}

func (b *messageBudget) startLocked() {
	if b.cancel != nil && b.timer == nil {
		cancel := b.cancel
		b.fired = make(chan struct{})
		fired := b.fired
		b.timer = time.AfterFunc(b.duration, func() { cancel(); close(fired) })
	}
}

func (b *messageBudget) stopLocked() {
	if b.timer != nil {
		if !b.timer.Stop() {
			<-b.fired
		}
		b.timer = nil
		b.fired = nil
	}
}

func (b *messageBudget) completeControl() {
	b.mu.Lock()
	if !b.message {
		b.stopLocked()
	}
	b.mu.Unlock()
}

func (b *messageBudget) end() {
	b.mu.Lock()
	b.stopLocked()
	b.cancel, b.message = nil, false
	b.mu.Unlock()
}

// observedIO inspects framing to maintain assembly clocks; coder/websocket remains
// responsible for all RFC validation, masking, control frames and reassembly.
// The first two header bytes are read individually; once the header length is
// known, its remainder can be read together. Reads never cross header/payload or
// frame boundaries, avoiding a timestamp queue and using 14 scratch bytes.
type observedIO struct {
	io.ReadWriteCloser
	reader     io.Reader
	budget     *messageBudget
	header     [14]byte
	have, need int
	payload    uint64
	control    bool
}

func (o *observedIO) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if o.payload > 0 {
		if uint64(len(p)) > o.payload {
			p = p[:int(o.payload)]
		}
		n, err := o.reader.Read(p)
		o.payload -= uint64(n)
		if o.payload == 0 && o.control {
			o.budget.completeControl()
		}
		return n, err
	}
	chunk := 1
	if o.have > 0 {
		chunk = min(len(p), o.need-o.have)
	}
	n, err := o.reader.Read(p[:chunk])
	if n == 0 {
		return n, err
	}
	if o.have == 0 {
		o.control = p[0]&8 != 0
		o.budget.startFrame(o.control)
		o.need = 2
	}
	copy(o.header[o.have:], p[:n])
	o.have += n
	if o.have == 2 {
		switch o.header[1] & 127 {
		case 126:
			o.need += 2
		case 127:
			o.need += 8
		}
		if o.header[1]&128 != 0 {
			o.need += 4
		}
	}
	if o.have == o.need {
		o.payload = uint64(o.header[1] & 127)
		switch o.payload {
		case 126:
			o.payload = uint64(binary.BigEndian.Uint16(o.header[2:4]))
		case 127:
			o.payload = binary.BigEndian.Uint64(o.header[2:10])
		}
		o.have = 0
		if o.payload == 0 && o.control {
			o.budget.completeControl()
		}
	}
	return n, err
}

type observedRoundTripper struct {
	base   http.RoundTripper
	budget *messageBudget
	abort  *upgradeAbort
}

func (o observedRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := o.base.RoundTrip(r)
	if err == nil && response.StatusCode == http.StatusSwitchingProtocols {
		// HTTP no longer owns cancellation after a 101 takeover. Arm before
		// coder/websocket validates it and potentially drains a silent body.
		o.abort.arm(response.Body)
		if body, ok := response.Body.(io.ReadWriteCloser); ok {
			response.Body = &observedIO{ReadWriteCloser: body, reader: body, budget: o.budget}
		}
	}
	return response, err
}

// upgradeAbort owns the temporary HTTP-takeover cancellation hook. Dial joins
// and disarms it before using a successful connection for the SC1 handshake.
type upgradeAbort struct {
	ctx  context.Context
	stop func() bool
	done chan struct{}
}

func (a *upgradeAbort) arm(body io.Closer) {
	a.done = make(chan struct{})
	done := a.done
	a.stop = context.AfterFunc(a.ctx, func() { _ = body.Close(); close(done) })
}

func (a *upgradeAbort) disarm() {
	if a.stop != nil {
		if !a.stop() {
			<-a.done
		}
		a.stop = nil
	}
}

type observedConn struct {
	net.Conn
	observed *observedIO
}

func (c *observedConn) Read(p []byte) (int, error) { return c.observed.Read(p) }

type observedWriter struct {
	http.ResponseWriter
	budget *messageBudget
	conn   net.Conn
}

func (w *observedWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *observedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	// HTTP may already have buffered the first WS bytes. Route those through
	// the same observer instead of letting the library bypass the clock.
	buffered, _ := brw.Reader.Peek(brw.Reader.Buffered())
	initial := bytes.Clone(buffered)
	observed := &observedIO{ReadWriteCloser: conn, reader: io.MultiReader(bytes.NewReader(initial), conn), budget: w.budget}
	wrapped := &observedConn{Conn: conn, observed: observed}
	w.conn = conn
	return wrapped, bufio.NewReadWriter(bufio.NewReader(wrapped), brw.Writer), nil
}
