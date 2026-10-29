// Package ordered binds SC1 records to an ordered, message-oriented carrier.
package ordered

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
)

const MaxFrame = 1 << 20

var (
	ErrClosed   = errors.New("ordered: closed")
	ErrProtocol = errors.New("ordered: invalid envelope")
	ErrIO       = errors.New("ordered: carrier failed")
	ErrBusy     = errors.New("ordered: admission limit reached")
	ErrOptions  = errors.New("ordered: invalid options")
)

// MessageIO must preserve messages and honor cancellation. ReadMessage appends
// to dst[:0], never allocating or reading a message larger than cap(dst).
// Close must immediately interrupt both directions. Each direction has at most
// one caller; Close may run concurrently. Errors must not contain secrets.
type MessageIO interface {
	ReadMessage(context.Context, []byte) ([]byte, error)
	WriteMessage(context.Context, []byte) error
	Close() error
}

// Options are per-connection limits. Zero selects the documented defaults;
// time limits may be shortened, but cannot exceed 5s (24h for Lifetime).
// MaxPending includes the active operation in each direction (default 32,
// maximum 1024). Admission beyond that limit fails immediately with ErrBusy.
type Options struct {
	HandshakeTimeout time.Duration
	WriteTimeout     time.Duration
	FrameTimeout     time.Duration
	RecordTimeout    time.Duration
	Lifetime         time.Duration
	MaxPending       int
}

func (o Options) Normalize() (Options, error) {
	for _, p := range []*time.Duration{&o.HandshakeTimeout, &o.WriteTimeout, &o.FrameTimeout, &o.RecordTimeout} {
		if *p == 0 {
			*p = 5 * time.Second
		}
		if *p < 0 || *p > 5*time.Second {
			return Options{}, ErrOptions
		}
	}
	if o.Lifetime == 0 {
		o.Lifetime = 24 * time.Hour
	}
	if o.Lifetime < 0 || o.Lifetime > 24*time.Hour {
		return Options{}, ErrOptions
	}
	if o.MaxPending == 0 {
		o.MaxPending = 32
	}
	if o.MaxPending < 1 || o.MaxPending > 1024 {
		return Options{}, ErrOptions
	}
	return o, nil
}

// Client performs M1/M2 and takes ownership of carrier, including on failure.
func Client(ctx context.Context, carrier MessageIO, cfg securechannel.ClientConfig, opts Options) (*Transport, error) {
	o, err := opts.Normalize()
	if err != nil {
		carrier.Close()
		return nil, err
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, min(o.HandshakeTimeout, o.Lifetime))
	defer cancel()
	i, first, err := securechannel.Begin(cfg)
	if err != nil {
		carrier.Close()
		return nil, err
	}
	defer i.Close()
	defer clear(first)
	if err = carrier.WriteMessage(ctx, first); err != nil {
		carrier.Close()
		return nil, publicError(ctx, err)
	}
	var reply [securechannel.HandshakeSize]byte
	m, err := carrier.ReadMessage(ctx, reply[:0])
	if err != nil {
		carrier.Close()
		return nil, publicError(ctx, err)
	}
	ch, err := i.Finish(m)
	clear(reply[:])
	if err != nil {
		carrier.Close()
		return nil, err
	}
	if ctx.Err() != nil {
		ch.Close()
		carrier.Close()
		return nil, ctx.Err()
	}
	o.Lifetime -= time.Since(started)
	if o.Lifetime <= 0 {
		ch.Close()
		carrier.Close()
		return nil, context.DeadlineExceeded
	}
	return newTransport(carrier, ch, nil, o), nil
}

// Server performs M1/M2. Identity remains unconfirmed until Decrypt succeeds.
func Server(ctx context.Context, carrier MessageIO, cfg securechannel.ServerConfig, opts Options) (*Transport, error) {
	o, err := opts.Normalize()
	if err != nil {
		carrier.Close()
		return nil, err
	}
	if cfg.Validate() != nil {
		carrier.Close()
		return nil, securechannel.ErrConfig
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, min(o.HandshakeTimeout, o.Lifetime))
	defer cancel()
	var first [securechannel.MaxContext + securechannel.HandshakeSize]byte
	m, err := carrier.ReadMessage(ctx, first[:0])
	if err != nil {
		carrier.Close()
		return nil, publicError(ctx, err)
	}
	ch, reply, err := securechannel.Respond(ctx, cfg, m)
	clear(first[:])
	if err != nil {
		carrier.Close()
		return nil, err
	}
	defer clear(reply)
	if err = carrier.WriteMessage(ctx, reply); err != nil {
		ch.Close()
		carrier.Close()
		return nil, publicError(ctx, err)
	}
	if ctx.Err() != nil {
		ch.Close()
		carrier.Close()
		return nil, ctx.Err()
	}
	o.Lifetime -= time.Since(started)
	if o.Lifetime <= 0 {
		ch.Close()
		carrier.Close()
		return nil, context.DeadlineExceeded
	}
	// Lifecycle rechecks need public routing and Lookup, not the static secret.
	cfg.StaticKey = securechannel.StaticKey{}
	return newTransport(carrier, ch, &cfg, o), nil
}

// Transport owns its cipher and bounded reusable record scratch. Returned
// frames are owned by the caller. Do not copy a Transport after construction.
type Transport struct {
	io      MessageIO
	channel *securechannel.Channel
	server  *securechannel.ServerConfig
	opts    Options

	mu        sync.Mutex // bounded admitted callers only; never held over I/O/waiting
	closed    bool
	ops       sync.WaitGroup
	once      sync.Once
	confirmed sync.Once
	confirm   chan struct{}

	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	socketStopped   chan struct{}
	stopped         chan struct{}
	lifetimeTimer   *time.Timer
	lifetimeStopped chan struct{}

	sendGate, recvGate           chan struct{}
	sendAdmission, recvAdmission chan struct{}
	sendPlain, sendCipher        []byte
	recvPlain, recvCipher        []byte
	remaining                    []byte
	receivedAt                   time.Time
}

var _ syntra.Transport = (*Transport)(nil)
var _ syntra.ChannelIdentityProvider = (*Transport)(nil)

func newTransport(carrier MessageIO, ch *securechannel.Channel, cfg *securechannel.ServerConfig, o Options) *Transport {
	ctx, cancel := context.WithCancel(context.Background())
	t := &Transport{io: carrier, channel: ch, server: cfg, opts: o, ctx: ctx, cancel: cancel,
		done: make(chan struct{}), socketStopped: make(chan struct{}), stopped: make(chan struct{}), lifetimeStopped: make(chan struct{}), confirm: make(chan struct{}),
		sendGate: make(chan struct{}, 1), recvGate: make(chan struct{}, 1),
		sendAdmission: make(chan struct{}, o.MaxPending), recvAdmission: make(chan struct{}, o.MaxPending),
		sendPlain: make([]byte, securechannel.MaxPlaintext), sendCipher: make([]byte, securechannel.MaxCiphertext),
		recvCipher: make([]byte, securechannel.MaxCiphertext), recvPlain: make([]byte, securechannel.MaxPlaintext)}
	// Independent of Lookup: even a bounded but slow lifecycle check must not
	// postpone the absolute channel lifetime or leave an idle socket open.
	t.lifetimeTimer = time.AfterFunc(o.Lifetime, func() { t.abort(); close(t.lifetimeStopped) })
	go t.supervise()
	return t
}

func (t *Transport) abort() {
	t.once.Do(func() {
		t.mu.Lock()
		t.closed = true
		close(t.done)
		t.cancel()
		t.mu.Unlock()
		_ = t.io.Close()
		close(t.socketStopped)
	})
}

// Close first shuts the socket, then joins operations and the lifecycle task
// before erasing scratch and releasing cipher states. Carriers and host Lookup
// implementations must honor their cancellation contract.
func (t *Transport) Close() error { t.abort(); <-t.stopped; return nil }

func (t *Transport) supervise() {
	defer close(t.stopped)
	defer func() {
		if !t.lifetimeTimer.Stop() {
			<-t.lifetimeStopped
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	confirm := t.confirm
	active := false
	for {
		select {
		case <-t.done:
			<-t.socketStopped
			t.ops.Wait()
			t.channel.Close()
			clear(t.sendPlain)
			clear(t.sendCipher)
			clear(t.recvPlain)
			clear(t.recvCipher)
			t.sendPlain, t.sendCipher, t.recvPlain, t.recvCipher = nil, nil, nil, nil
			t.remaining = nil
			t.server = nil
			return
		case <-confirm:
			confirm = nil
			active = t.server != nil
			if active {
				t.checkPeer()
			}
		case <-tick.C:
			if active {
				t.checkPeer()
			}
		}
	}
}

func (t *Transport) checkPeer() {
	p, ok := t.channel.Peer()
	if !ok || (!p.ExpiresAt.IsZero() && !time.Now().Before(p.ExpiresAt)) {
		t.abort()
		return
	}
	ctx, cancel := context.WithTimeout(t.ctx, time.Second)
	err := t.server.Check(ctx, p)
	cancel()
	if err != nil {
		t.abort()
	}
}

func (t *Transport) ChannelIdentity() (syntra.ChannelIdentity, bool) {
	p, ok := t.channel.Peer()
	if !ok {
		return syntra.ChannelIdentity{}, false
	}
	select {
	case <-t.done:
		return syntra.ChannelIdentity{}, false
	default:
	}
	c := p.Context
	return syntra.ChannelIdentity{Mode: c.Mode.String(), Carrier: c.Carrier.String(), Scope: c.Scope, Handle: c.Handle, Epoch: c.Epoch, Principal: p.Principal}, true
}

func (t *Transport) acquire(ctx context.Context, admission, gate chan struct{}) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-t.done:
		return nil, ErrClosed
	default:
	}
	// Reserve a bounded slot before the brief lifecycle mutex: even callers
	// racing admission cannot form an unbounded mutex wait queue.
	select {
	case admission <- struct{}{}:
	default:
		return nil, ErrBusy
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		<-admission
		return nil, ErrClosed
	}
	t.ops.Add(1)
	t.mu.Unlock()
	releaseAdmission := func() { <-admission; t.ops.Done() }
	select {
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-gate
			releaseAdmission()
			return nil, err
		}
		select {
		case <-t.done:
			<-gate
			releaseAdmission()
			return nil, ErrClosed
		default:
		}
		return func() { <-gate; releaseAdmission() }, nil
	case <-ctx.Done():
		releaseAdmission()
		return nil, ctx.Err()
	case <-t.done:
		releaseAdmission()
		return nil, ErrClosed
	}
}

func publicError(ctx context.Context, _ error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return ErrIO
}

// Send holds the writer for the entire envelope, including all its records.
// Any error after encryption is terminal: that nonce can never be reused.
func (t *Transport) Send(ctx context.Context, frame []byte) error {
	if len(frame) == 0 || len(frame) > MaxFrame {
		return ErrProtocol
	}
	ctx, cancel := context.WithTimeout(ctx, t.opts.WriteTimeout)
	defer cancel()
	release, err := t.acquire(ctx, t.sendAdmission, t.sendGate)
	if err != nil {
		return err
	}
	defer release()
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(frame)))
	for offset := 0; offset < 4+len(frame); {
		n := min(len(t.sendPlain), 4+len(frame)-offset)
		p := t.sendPlain[:n]
		copied := 0
		if offset < 4 {
			copied = copy(p, prefix[offset:])
		}
		copy(p[copied:], frame[max(0, offset-4):])
		record, encErr := t.channel.Encrypt(t.sendCipher[:0], p)
		clear(p)
		if encErr != nil {
			t.abort()
			return ErrProtocol
		}
		if err = t.io.WriteMessage(ctx, record); err != nil {
			t.abort()
			return publicError(ctx, err)
		}
		if ctx.Err() != nil {
			t.abort()
			return ctx.Err()
		}
		offset += n
	}
	return nil
}

// Ping invokes an optional carrier control ping. It shares bounded writer
// admission with Send, and requires a concurrent Recv to process pong replies.
func (t *Transport) Ping(ctx context.Context) error {
	p, ok := t.io.(interface{ Ping(context.Context) error })
	if !ok {
		return ErrOptions
	}
	ctx, cancel := context.WithTimeout(ctx, t.opts.WriteTimeout)
	defer cancel()
	release, err := t.acquire(ctx, t.sendAdmission, t.sendGate)
	if err != nil {
		return err
	}
	defer release()
	if err = p.Ping(ctx); err != nil {
		t.abort()
		return publicError(ctx, err)
	}
	return nil
}

// Recv reassembles the authenticated byte stream without parsing root Frames.
// The absolute frame clock begins with its first authenticated prefix byte,
// including when that byte was buffered alongside a preceding frame.
func (t *Transport) Recv(ctx context.Context) ([]byte, error) {
	release, err := t.acquire(ctx, t.recvAdmission, t.recvGate)
	if err != nil {
		return nil, err
	}
	defer release()
	var deadline time.Time
	var prefix [4]byte
	if err = t.readPlain(ctx, prefix[:], &deadline); err != nil {
		t.abort()
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n == 0 || n > MaxFrame {
		t.abort()
		return nil, ErrProtocol
	}
	frame := make([]byte, int(n)) // length has been checked before allocation
	if err = t.readPlain(ctx, frame, &deadline); err != nil {
		clear(frame)
		t.abort()
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		clear(frame)
		t.abort()
		return nil, err
	}
	if !time.Now().Before(deadline) {
		clear(frame)
		t.abort()
		return nil, context.DeadlineExceeded
	}
	return frame, nil
}

func (t *Transport) readPlain(ctx context.Context, dst []byte, deadline *time.Time) error {
	for len(dst) != 0 {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !deadline.IsZero() && !time.Now().Before(*deadline) {
			return context.DeadlineExceeded
		}
		if len(t.remaining) == 0 {
			readCtx := ctx
			cancel := func() {}
			if !deadline.IsZero() {
				readCtx, cancel = context.WithDeadline(ctx, *deadline)
			}
			ciphertext, err := t.io.ReadMessage(readCtx, t.recvCipher[:0])
			if err == nil {
				err = readCtx.Err()
			}
			if err != nil {
				out := publicError(readCtx, err)
				cancel()
				return out
			}
			cancel()
			if len(ciphertext) < 17 || len(ciphertext) > securechannel.MaxCiphertext {
				return ErrProtocol
			}
			plain, err := t.channel.Decrypt(t.recvPlain[:0], ciphertext)
			if err != nil {
				return ErrProtocol
			}
			t.receivedAt = time.Now()
			t.remaining = plain
			t.confirmed.Do(func() { close(t.confirm) })
		}
		if deadline.IsZero() {
			*deadline = t.receivedAt.Add(t.opts.FrameTimeout)
		}
		if !time.Now().Before(*deadline) {
			return context.DeadlineExceeded
		}
		n := copy(dst, t.remaining)
		clear(t.remaining[:n])
		t.remaining = t.remaining[n:]
		dst = dst[n:]
	}
	return nil
}
