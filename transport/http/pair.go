package syntrahttp

import (
	"context"
	"io"
	"math"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
)

const (
	exchangeTimeout = 5 * time.Second
	pollTimeout     = 30 * time.Second
	pollHold        = 25 * time.Second
	pollGap         = 5 * time.Second
)

// pairState is the single sticky retirement owner for both directions.
type pairState struct {
	mu        sync.Mutex
	u, d      net.Conn
	closed    bool
	ctx       context.Context
	cancel    context.CancelFunc
	budget    *ordered.EstablishmentBudget
	closeDone chan struct{}
}

func sameConn(a, b net.Conn) bool {
	if a == nil || b == nil {
		return false
	}
	x, y := reflect.ValueOf(a), reflect.ValueOf(b)
	return x.Type() == y.Type() && x.Comparable() && x.Equal(y)
}
func newState(u, d net.Conn, b *ordered.EstablishmentBudget) *pairState {
	ctx, cancel := context.WithCancel(context.Background())
	return &pairState{u: u, d: d, ctx: ctx, cancel: cancel, budget: b, closeDone: make(chan struct{})}
}
func closeConns(u, d net.Conn) {
	if u != nil && d != nil && !sameConn(u, d) {
		joined := make(chan struct{})
		go func() { _ = u.Close(); close(joined) }()
		_ = d.Close()
		<-joined
		return
	}
	if u != nil {
		_ = u.Close()
	}
	if d != nil && !sameConn(u, d) {
		_ = d.Close()
	}
}
func (p *pairState) Close() error {
	p.mu.Lock()
	if p.closed {
		done := p.closeDone
		p.mu.Unlock()
		<-done
		return nil
	}
	p.closed = true
	p.cancel()
	u, d := p.u, p.d
	p.mu.Unlock()
	closeConns(u, d)
	close(p.closeDone)
	return nil
}
func (p *pairState) check(ctx context.Context) error {
	if err := stream.ContextError(ctx); err != nil {
		return err
	}
	select {
	case <-p.ctx.Done():
		return ordered.ErrClosed
	default:
	}
	return stream.Check(p.budget)
}
func (p *pairState) context(parent context.Context, timeout time.Duration) (context.Context, func()) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	stop := context.AfterFunc(p.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}
func (p *pairState) do(ctx context.Context, conn net.Conn, timeout time.Duration, fn func(context.Context) error) error {
	op, cancel := p.context(ctx, timeout)
	defer cancel()
	err := p.check(op)
	if err == nil {
		err = stream.Do(op, conn, true, true, func() error { return fn(op) })
	}
	if err == nil {
		err = p.check(op)
	}
	if err != nil {
		_ = p.Close()
	}
	return err
}
func readBody(r io.Reader, dst []byte, n int) ([]byte, error) {
	if n < 0 || n > MaxRecord || n > cap(dst) {
		return nil, ordered.ErrProtocol
	}
	dst = dst[:n]
	_, err := io.ReadFull(r, dst)
	return dst, err
}
func writeUnit(w io.Writer, head, body []byte) error {
	if err := stream.WriteAll(w, head); err != nil {
		return err
	}
	return stream.WriteAll(w, body)
}

// Header assembly gets five seconds from the first byte, independently of an
// idle/long-poll wait. The existing operation deadline is never extended.
type headerReader struct {
	conn      net.Conn
	ctx       context.Context
	started   bool
	capWrites bool
}

func (r *headerReader) Read(b []byte) (int, error) {
	n, err := r.conn.Read(b)
	if n > 0 && !r.started {
		r.started = true
		at := time.Now().Add(exchangeTimeout)
		if deadline, ok := r.ctx.Deadline(); ok && deadline.Before(at) {
			at = deadline
		}
		if e := r.conn.SetReadDeadline(at); e != nil {
			return 0, e
		}
		if r.capWrites {
			if e := r.conn.SetWriteDeadline(at); e != nil {
				return 0, e
			}
		}
	}
	return n, err
}
func timedHeader(ctx context.Context, c net.Conn, capWrites bool) ([]byte, error) {
	return readHeader(&headerReader{conn: c, ctx: ctx, capWrites: capWrites})
}

// A response cannot carry bytes beyond its declared body. Probe without
// read-ahead; delayed surplus is fatal at the next header, never resynchronized.
func responseEnd(ctx context.Context, c net.Conn, persistent bool) error {
	probe, stop := context.WithTimeout(ctx, time.Millisecond)
	defer stop()
	var b [1]byte
	var n int
	err := stream.Do(probe, c, true, false, func() error { var e error; n, e = c.Read(b[:]); return e })
	if n != 0 {
		return ordered.ErrProtocol
	}
	if (err == ordered.ErrClosed || err == ordered.ErrIO) && !persistent {
		return nil
	}
	if err == context.DeadlineExceeded {
		return nil
	}
	if err != nil {
		return err
	}
	return ordered.ErrProtocol
}
func nextCounter(n uint64) (uint64, error) {
	if n == math.MaxUint64 {
		return 0, ordered.ErrProtocol
	}
	return n + 1, nil
}

type opened struct {
	route Route
	m2    [48]byte
}
type clientPair struct {
	*pairState
	authority             Authority
	opened                chan opened
	uRoute, dRoute        Route
	uCounter, dCounter    uint64
	firstWrite, firstRead bool
	uGate, dGate          chan struct{}
	due                   time.Time
}

var _ ordered.MessageIO = (*clientPair)(nil)

// ClientPair takes exclusive ownership of two distinct connected streams,
// including on failure. No bytes are emitted during construction. Raw streams
// make no HTTPS claim. The caller provisions identical authority, explicit route,
// owner and policy generation for both. ReadMessage must remain pending after M2
// so notifications and empty polls progress even without an application call.
func ClientPair(upload, download net.Conn, authority Authority, opts ordered.Options) (ordered.MessageIO, error) {
	if upload == nil || download == nil || sameConn(upload, download) || !authority.valid() {
		closeConns(upload, download)
		return nil, ordered.ErrOptions
	}
	o, err := stream.Options(opts)
	if err != nil {
		closeConns(upload, download)
		return nil, err
	}
	if err = stream.Check(o.Budget); err != nil {
		closeConns(upload, download)
		return nil, err
	}
	p := &clientPair{pairState: newState(stream.New(upload, o.Budget), stream.New(download, o.Budget), o.Budget), authority: authority, opened: make(chan opened, 1), firstWrite: true, firstRead: true, uGate: make(chan struct{}, 1), dGate: make(chan struct{}, 1)}
	return p, nil
}

func enter(gate chan struct{}) bool {
	select {
	case gate <- struct{}{}:
		return true
	default:
		return false
	}
}
func (p *clientPair) WriteMessage(ctx context.Context, body []byte) error {
	if !enter(p.uGate) {
		return ordered.ErrBusy
	}
	defer func() { <-p.uGate }()
	return p.do(ctx, p.u, exchangeTimeout, func(opctx context.Context) error {
		op := Send
		if p.firstWrite {
			op = Open
		}
		if op == Send {
			if _, err := nextCounter(p.uCounter); err != nil {
				return err
			}
		}
		h, err := requestHeader(op, p.authority, p.uRoute, p.uCounter, len(body))
		if err != nil {
			return err
		}
		if err = writeUnit(p.u, h, body); err != nil {
			return err
		}
		h, err = timedHeader(opctx, p.u, true)
		if err != nil {
			return err
		}
		head, err := ParseResponse(h, op)
		if err != nil {
			return err
		}
		if op == Open {
			var m2 [48]byte
			if _, err = io.ReadFull(p.u, m2[:]); err != nil {
				return err
			}
			if err = responseEnd(opctx, p.u, true); err != nil {
				return err
			}
			p.uRoute, p.firstWrite = head.Route, false
			p.opened <- opened{head.Route, m2}
		} else {
			if head.Counter != p.uCounter {
				return ordered.ErrProtocol
			}
			if err = responseEnd(opctx, p.u, true); err != nil {
				return err
			}
			p.uCounter, _ = nextCounter(p.uCounter)
		}
		return nil
	})
}
func (p *clientPair) ReadMessage(ctx context.Context, dst []byte) (out []byte, err error) {
	if !enter(p.dGate) {
		return nil, ordered.ErrBusy
	}
	defer func() { <-p.dGate }()
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	if err = p.check(ctx); err != nil {
		return nil, err
	}
	if p.firstRead {
		setup, stopBudget := p.budget.Context(ctx)
		defer stopBudget()
		setup, stopSetup := context.WithTimeout(setup, exchangeTimeout)
		defer stopSetup()
		var o opened
		select {
		case o = <-p.opened:
		case <-setup.Done():
			return nil, stream.ContextError(setup)
		case <-p.ctx.Done():
			return nil, ordered.ErrClosed
		}
		if cap(dst) < len(o.m2) {
			return nil, ordered.ErrProtocol
		}
		p.dRoute, p.firstRead, p.due = o.route, false, time.Now().Add(pollGap)
		return append(dst[:0], o.m2[:]...), p.check(setup)
	}
	// Empty poll responses do not renew the next-record deadline.
	record, stop := p.context(ctx, 60*time.Second)
	defer stop()
	for {
		if !time.Now().Before(p.due) {
			return nil, context.DeadlineExceeded
		}
		if _, err = nextCounter(p.dCounter); err != nil {
			return nil, err
		}
		err = p.do(record, p.d, pollTimeout, func(opctx context.Context) error {
			h, e := requestHeader(Poll, p.authority, p.dRoute, p.dCounter, 0)
			if e != nil {
				return e
			}
			if e = writeUnit(p.d, h, nil); e != nil {
				return e
			}
			h, e = timedHeader(opctx, p.d, true)
			if e != nil {
				return e
			}
			head, e := ParseResponse(h, Poll)
			if e != nil {
				return e
			}
			if head.Counter != p.dCounter {
				return ordered.ErrProtocol
			}
			out, e = readBody(p.d, dst, head.BodyLen)
			if e != nil {
				return e
			}
			return responseEnd(opctx, p.d, true)
		})
		if err != nil {
			return nil, err
		}
		p.dCounter, _ = nextCounter(p.dCounter)
		p.due = time.Now().Add(pollGap)
		if len(out) != 0 {
			return out, nil
		}
	}
}

// Shutdown attempts the terminal close exchange, then retires both streams.
// Close is the immediate interrupt required by ordered.MessageIO.
func (p *clientPair) Shutdown(ctx context.Context) error {
	if !enter(p.uGate) {
		_ = p.Close()
		return ordered.ErrBusy
	}
	defer func() { <-p.uGate; _ = p.Close() }()
	if p.firstWrite {
		return ordered.ErrClosed
	}
	complete := false
	err := p.do(ctx, p.u, 2*time.Second, func(opctx context.Context) error {
		h, e := requestHeader(Close, p.authority, p.uRoute, 0, 0)
		if e != nil {
			return e
		}
		if e = writeUnit(p.u, h, nil); e != nil {
			return e
		}
		h, e = readHeader(p.u)
		if e != nil {
			return e
		}
		_, e = ParseResponse(h, Close)
		if e != nil {
			return e
		}
		e = responseEnd(opctx, p.u, false)
		complete = e == nil
		return e
	})
	// Deadline clearing can fail after a valid terminal response and peer close.
	if complete && err == ordered.ErrIO {
		return nil
	}
	return err
}

type output struct {
	bytes  []byte
	result chan error
}
type serverPair struct {
	*pairState
	authority             Authority
	origins               OriginPolicy
	route                 Route
	first                 []byte
	firstRead, firstWrite bool
	uCounter              uint64
	output                chan output
	attached              chan struct{}
	done                  chan struct{}
	opened                bool // guarded by pairState.mu; only a completed M2 permits D attachment
	openDone              chan struct{}
	initialPoll           Head
	onRecord              func()
}

var _ ordered.MessageIO = (*serverPair)(nil)

func newServerPair(u net.Conn, first []byte, a Authority, origins OriginPolicy, route Route, budget *ordered.EstablishmentBudget) *serverPair {
	return &serverPair{pairState: newState(u, nil, budget), authority: a, origins: origins, route: route, first: first, firstRead: true, firstWrite: true, output: make(chan output), attached: make(chan struct{}), openDone: make(chan struct{}), done: make(chan struct{})}
}
func (p *serverPair) awaitOpen(ctx context.Context) error {
	select {
	case <-p.openDone:
		return p.check(ctx)
	case <-p.ctx.Done():
		return ordered.ErrClosed
	case <-ctx.Done():
		return stream.ContextError(ctx)
	}
}
func (p *serverPair) attachDownload(d net.Conn, head Head) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !p.opened || p.d != nil {
		return false
	}
	p.d = d
	p.initialPoll = head
	close(p.attached)
	return true
}
func (p *serverPair) ReadMessage(ctx context.Context, dst []byte) (out []byte, err error) {
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	if err = p.check(ctx); err != nil {
		return nil, err
	}
	if p.firstRead {
		p.firstRead = false
		if len(p.first) > cap(dst) {
			return nil, ordered.ErrProtocol
		}
		out = append(dst[:0], p.first...)
		clear(p.first)
		p.first = nil
		return out, nil
	}
	err = p.do(ctx, p.u, 60*time.Second, func(opctx context.Context) error {
		h, e := timedHeader(opctx, p.u, true)
		if e != nil {
			return e
		}
		head, e := ParseRequest(h, p.authority, p.origins)
		if e != nil {
			return ordered.ErrProtocol
		}
		if head.Route != p.route {
			return ordered.ErrProtocol
		}
		if head.Operation == Close {
			h, e = responseHeader(Close, Route{}, 0, 0)
			if e == nil {
				e = writeUnit(p.u, h, nil)
			}
			if e != nil {
				return e
			}
			return ordered.ErrClosed
		}
		if head.Operation != Send || head.Counter != p.uCounter {
			return ordered.ErrProtocol
		}
		if _, e = nextCounter(p.uCounter); e != nil {
			return e
		}
		out, e = readBody(p.u, dst, head.BodyLen)
		if e != nil {
			return e
		}
		if e = responseEnd(opctx, p.u, true); e != nil {
			return e
		}
		h, e = responseHeader(Send, Route{}, p.uCounter, 0)
		if e != nil {
			return e
		}
		if e = writeUnit(p.u, h, nil); e != nil {
			return e
		}
		p.uCounter, _ = nextCounter(p.uCounter)
		return nil
	})
	return out, err
}
func (p *serverPair) WriteMessage(ctx context.Context, body []byte) (err error) {
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()
	if err = p.check(ctx); err != nil {
		return err
	}
	if p.firstWrite {
		p.firstWrite = false
		err = p.do(ctx, p.u, exchangeTimeout, func(opctx context.Context) error {
			h, e := responseHeader(Open, p.route, 0, len(body))
			if e != nil {
				return e
			}
			if e = responseEnd(opctx, p.u, true); e != nil {
				return e
			}
			if e = writeUnit(p.u, h, body); e != nil {
				return e
			}
			if e = p.check(opctx); e != nil {
				return e
			}
			p.mu.Lock()
			p.opened = true
			close(p.openDone)
			p.mu.Unlock()
			return nil
		})
		return err
	}
	if len(body) < 17 || len(body) > MaxRecord {
		return ordered.ErrProtocol
	}
	op, stop := p.context(ctx, 10*time.Second)
	defer stop()
	work := output{bytes: body, result: make(chan error, 1)}
	select {
	case p.output <- work:
	case <-op.Done():
		return stream.ContextError(op)
	case <-p.ctx.Done():
		return ordered.ErrClosed
	}
	select {
	case err = <-work.result:
		if err == nil {
			err = p.check(ctx)
		}
		if err == nil && p.onRecord != nil {
			p.onRecord()
			p.onRecord = nil
		}
		return err
	case <-op.Done():
		_ = p.Close()
		// The driver must relinquish borrowed ciphertext before returning.
		<-work.result
		return stream.ContextError(op)
	case <-p.ctx.Done():
		<-work.result
		return ordered.ErrClosed
	}
}

// waitOutput rejects EOF or a pipelined request while a poll is held. A bounded
// read watcher is always joined before response emission or ownership release.
func (p *serverPair) waitOutput(ctx context.Context, d net.Conn) (output, bool, error) {
	type readResult struct {
		n   int
		err error
	}
	readDone := make(chan readResult, 1)
	watch, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	go func() {
		var one [1]byte
		var n int
		e := stream.Do(watch, d, true, false, func() error { var e error; n, e = d.Read(one[:]); return e })
		readDone <- readResult{n, e}
	}()
	timer := time.NewTimer(pollHold)
	defer timer.Stop()
	var work output
	var selected bool
	var err error
	select {
	case <-readDone:
		return output{}, false, ordered.ErrProtocol
	case work = <-p.output:
		selected = true
	case <-timer.C:
	case <-ctx.Done():
		err = stream.ContextError(ctx)
	case <-p.ctx.Done():
		err = ordered.ErrClosed
	}
	stopWatch()
	r := <-readDone
	if r.n != 0 || r.err != context.Canceled {
		err = ordered.ErrProtocol
	}
	if err != nil && selected {
		work.result <- err
		selected = false
	}
	return work, selected, err
}
func (p *serverPair) runDownload() {
	defer close(p.done)
	defer p.Close()
	select {
	case <-p.attached:
	case <-p.ctx.Done():
		return
	}
	p.mu.Lock()
	d, head := p.d, p.initialPoll
	p.mu.Unlock()
	var counter uint64
	for {
		var selectedOutput *output
		err := p.do(p.ctx, d, pollTimeout, func(ctx context.Context) error {
			if head.Operation != Poll || head.Route != p.route || head.Counter != counter {
				return ordered.ErrProtocol
			}
			if _, e := nextCounter(counter); e != nil {
				return e
			}
			work, selected, e := p.waitOutput(ctx, d)
			if e != nil {
				return e
			}
			var body []byte
			if selected {
				body = work.bytes
				selectedOutput = &work
			}
			h, e := responseHeader(Poll, Route{}, counter, len(body))
			if e == nil {
				e = writeUnit(d, h, body)
			}
			return e
		})
		// Complete the immutable borrowed output only after the same exchange's
		// final deadline/budget check and any failure-driven socket teardown.
		if selectedOutput != nil {
			selectedOutput.result <- err
		}
		if err != nil {
			return
		}
		counter, _ = nextCounter(counter)
		err = p.do(p.ctx, d, pollGap, func(opctx context.Context) error {
			h, e := timedHeader(opctx, d, false)
			if e != nil {
				return e
			}
			head, e = ParseRequest(h, p.authority, p.origins)
			return e
		})
		if err != nil {
			return
		}
	}
}
