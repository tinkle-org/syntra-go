// Package ordered binds Syntra records to an ordered, message-oriented carrier.
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

const MaxFrame = securechannel.MaxFrame

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
// time limits may be shortened from their defaults: attempt 15s, Noise and
// encrypted hello 5s shared, writes 10s, records/frames 30s, lifetime 24h.
// MaxPending includes the active operation in each direction (default 32,
// maximum 1024). Admission beyond that limit fails immediately with ErrBusy.
type Options struct {
	// EnableTerminalReceipts opts this driver into request-owned retirement.
	// The host must also configure method policies and the carrier must explicitly
	// support coordinated terminal I/O. Zero/default remains disabled.
	EnableTerminalReceipts bool
	AttemptTimeout         time.Duration
	HandshakeTimeout       time.Duration
	WriteTimeout           time.Duration
	FrameTimeout           time.Duration
	RecordTimeout          time.Duration
	Lifetime               time.Duration
	MaxPending             int
	Budget                 *EstablishmentBudget
}

func (o Options) Normalize() (Options, error) {
	for _, limit := range []struct {
		value   *time.Duration
		maximum time.Duration
	}{
		{&o.AttemptTimeout, 15 * time.Second}, {&o.HandshakeTimeout, 5 * time.Second},
		{&o.WriteTimeout, 10 * time.Second}, {&o.FrameTimeout, 30 * time.Second}, {&o.RecordTimeout, 30 * time.Second},
	} {
		if *limit.value == 0 {
			*limit.value = limit.maximum
		}
		if *limit.value < 0 || *limit.value > limit.maximum {
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

func setup(ctx context.Context, opts Options) (Options, *securechannel.Clock, time.Duration, time.Duration, error) {
	o, err := opts.Normalize()
	if err != nil {
		return Options{}, nil, 0, 0, err
	}
	b := o.Budget
	if b == nil {
		b, err = NewEstablishmentBudget(nil, o.AttemptTimeout)
	}
	if err != nil {
		return Options{}, nil, 0, 0, err
	}
	clock, attempt, phase, err := b.claim(o)
	if err == nil {
		err = elapsedError(ctx, clock, phase)
	}
	if err != nil {
		return Options{}, nil, 0, 0, err
	}
	o.Budget = b
	return o, clock, attempt, phase, nil
}

// Client performs M1/M2 and takes ownership of carrier, including on failure.
func Client(ctx context.Context, carrier MessageIO, cfg securechannel.ClientConfig, opts Options) (*Transport, error) {
	o, clock, attempt, phase, err := setup(ctx, opts)
	if err != nil {
		carrier.Close()
		return nil, err
	}
	ctx, cancel := elapsedContext(ctx, clock, phase)
	defer cancel()
	i, first, err := securechannel.BeginWithClock(cfg, clock)
	if err != nil {
		carrier.Close()
		return nil, err
	}
	defer i.Close()
	defer clear(first)
	if err = elapsedError(ctx, clock, phase); err == nil {
		err = carrier.WriteMessage(ctx, first)
	}
	if err == nil {
		err = elapsedError(ctx, clock, phase)
	}
	if err != nil {
		carrier.Close()
		return nil, publicError(ctx, err)
	}
	var reply [securechannel.HandshakeSize]byte
	m, err := carrier.ReadMessage(ctx, reply[:0])
	if err == nil {
		err = elapsedError(ctx, clock, phase)
	}
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
	if err = elapsedError(ctx, clock, phase); err != nil {
		ch.Close()
		carrier.Close()
		return nil, err
	}
	t := newTransport(carrier, ch, nil, o)
	t.establish(attempt, phase, false)
	if err := t.checkTime(); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

// Server performs M1/M2. Identity remains unconfirmed until Decrypt succeeds.
func Server(ctx context.Context, carrier MessageIO, cfg securechannel.ServerConfig, opts Options) (*Transport, error) {
	o, clock, attempt, phase, err := setup(ctx, opts)
	if err != nil {
		carrier.Close()
		return nil, err
	}
	if cfg.Validate() != nil {
		carrier.Close()
		return nil, securechannel.ErrConfig
	}
	ctx, cancel := elapsedContext(ctx, clock, phase)
	defer cancel()
	var first [securechannel.MaxContext + securechannel.HandshakeSize]byte
	m, err := carrier.ReadMessage(ctx, first[:0])
	if err == nil {
		err = elapsedError(ctx, clock, phase)
	}
	if err != nil {
		carrier.Close()
		return nil, publicError(ctx, err)
	}
	ch, reply, err := securechannel.RespondWithClock(ctx, cfg, m, clock)
	clear(first[:])
	if err != nil {
		carrier.Close()
		return nil, err
	}
	defer clear(reply)
	if err = elapsedError(ctx, clock, phase); err == nil {
		err = carrier.WriteMessage(ctx, reply)
	}
	if err == nil {
		err = elapsedError(ctx, clock, phase)
	}
	if err != nil {
		ch.Close()
		carrier.Close()
		return nil, publicError(ctx, err)
	}
	if err = elapsedError(ctx, clock, phase); err != nil {
		ch.Close()
		carrier.Close()
		return nil, err
	}
	// Lifecycle rechecks need public routing and Lookup, not the static secret.
	cfg.StaticKey = securechannel.StaticKey{}
	t := newTransport(carrier, ch, &cfg, o)
	t.establish(attempt, phase, true)
	if err := t.checkTime(); err != nil {
		t.Close()
		return nil, err
	}
	return t, nil
}

// Transport owns its cipher and bounded reusable record scratch. Returned
// frames are owned by the caller. Do not copy a Transport after construction.
type Transport struct {
	io      MessageIO
	channel *securechannel.Channel
	server  *securechannel.ServerConfig
	opts    Options

	mu                                                sync.Mutex // bounded admitted callers only; never held over I/O/waiting
	closed                                            bool
	localStop                                         bool
	suspended                                         bool
	terminal                                          error
	attemptDeadline, helloDeadline, readinessDeadline time.Duration
	establishing, helloPending, responder             bool
	readinessStarted                                  bool
	lastRecordAt                                      time.Duration
	ops                                               sync.WaitGroup
	confirmed                                         sync.Once
	confirm                                           chan struct{}
	peerGate                                          chan struct{}
	peerRequired, peerAuthorized                      bool
	identity                                          securechannel.VerifiedIdentity
	peer                                              securechannel.Peer
	identitySet                                       bool
	terminalPermit                                    *syntra.TerminalPermit
	terminalWake                                      chan struct{}

	ctx             context.Context
	cancel          context.CancelFunc
	done            chan struct{}
	carrierStopped  chan struct{}
	stopped         chan struct{}
	lifetimeTimer   *time.Timer
	lifetimeStopped chan struct{}
	clockStopped    chan struct{}

	sendGate, recvGate              chan struct{}
	sendAdmission, recvAdmission    chan struct{}
	sendPlain, sendCipher           []byte
	recvPlain, recvCipher           []byte
	decoder                         frameDecoder
	frames                          []receivedFrame
	frameDeadline, deliveryDeadline time.Duration
}

// receivedFrame keeps one owned envelope and its immutable assembly-batch origin.
type receivedFrame struct {
	raw     []byte
	receipt syntra.FrameReceipt
}

// frameDecoder permits per-owner assembly instrumentation without shared hooks.
type frameDecoder interface {
	// Push completes zero or more owned frames from authenticated plaintext.
	Push([]byte) ([][]byte, error)
	// IsPartial reports a retained incomplete envelope.
	IsPartial() bool
	// Close erases retained assembly state after receive owners join.
	Close()
}

var _ syntra.Transport = (*Transport)(nil)
var _ syntra.ChannelIdentityProvider = (*Transport)(nil)

// newTransport creates the sole record/nonce owner and starts bounded supervision.
func newTransport(carrier MessageIO, ch *securechannel.Channel, cfg *securechannel.ServerConfig, o Options) *Transport {
	ctx, cancel := context.WithCancel(context.Background())
	t := &Transport{io: carrier, channel: ch, server: cfg, opts: o, ctx: ctx, cancel: cancel,
		decoder:      &securechannel.FrameDecoder{},
		terminalWake: make(chan struct{}, 1),
		peerGate:     make(chan struct{}, 1), peerRequired: cfg != nil,
		done: make(chan struct{}), carrierStopped: make(chan struct{}), stopped: make(chan struct{}), lifetimeStopped: make(chan struct{}), clockStopped: make(chan struct{}), confirm: make(chan struct{}),
		sendGate: make(chan struct{}, 1), recvGate: make(chan struct{}, 1),
		sendAdmission: make(chan struct{}, o.MaxPending), recvAdmission: make(chan struct{}, o.MaxPending),
		sendPlain: make([]byte, securechannel.MaxPlaintext), sendCipher: make([]byte, securechannel.MaxCiphertext),
		recvCipher: make([]byte, securechannel.MaxCiphertext), recvPlain: make([]byte, securechannel.MaxPlaintext)}
	// Independent of Lookup: even a bounded but slow lifecycle check must not
	// postpone the absolute channel lifetime or leave an idle carrier open.
	t.lifetimeTimer = time.AfterFunc(max(0, o.Lifetime-ch.Age()), func() { t.abort(context.DeadlineExceeded); close(t.lifetimeStopped) })
	t.lastRecordAt = ch.Age()
	go t.monitorClock()
	go t.supervise()
	return t
}

func (t *Transport) monitorClock() {
	defer close(t.clockStopped)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-t.done:
			return
		case <-tick.C:
			if err := t.checkTime(); err != nil {
				t.abort(err)
				return
			}
		}
	}
}

func (t *Transport) abort(cause ...error) {
	var err error
	if len(cause) != 0 {
		err = cause[0]
	}
	t.retire(err, false)
}

// retire stops admission and carrier I/O, retiring terminal crypto before joining
// admitted operations; scratch remains owned until those operations exit.
func (t *Transport) retire(err error, local bool) {
	if err != nil {
		err = publicError(context.Background(), err)
	}
	t.mu.Lock()
	t.localStop = t.localStop || local
	// A source failure can finish after the local fence closes admission. Keep
	// it even then; only errors induced by interrupting I/O are clean shutdown.
	localError := !specificFailure(err) && (localStopError(err) || t.suspended && errors.Is(err, context.DeadlineExceeded))
	if err != nil && (t.terminal == nil || !specificFailure(t.terminal) && specificFailure(err)) && (!t.localStop || !localError) {
		t.terminal = err
	}
	if t.closed {
		t.mu.Unlock()
		return
	}
	t.closed = true
	permit := t.terminalPermit
	if permit != nil {
		permit.Fail(err)
	}
	close(t.done)
	t.cancel()
	t.mu.Unlock()
	// A terminal operation can outlive close. Retire cipher state now rather
	// than waiting for its authority callback; scratch remains owned until join.
	if permit != nil {
		t.channel.Close()
	}
	go func() {
		defer close(t.carrierStopped)
		_ = t.io.Close()
	}()
}

func localStopError(err error) bool {
	if specificFailure(err) {
		return false
	}
	var rpc *syntra.RpcError
	if errors.As(err, &rpc) {
		return rpc.Code == syntra.ErrorCodeCancelled || rpc.Code == syntra.ErrorCodeUnavailable
	}
	return errors.Is(err, context.Canceled) || errors.Is(err, ErrClosed) ||
		errors.Is(err, ErrIO) || errors.Is(err, securechannel.ErrClosed)
}

// Specific failures outrank generic loss, but never replace one another. Check
// security sentinels before cancellation: a joined error may carry both.
func specificFailure(err error) bool {
	if err == nil {
		return false
	}
	for _, known := range []error{securechannel.ErrAuth, securechannel.ErrRecord, securechannel.ErrLimit, securechannel.ErrConfig, ErrProtocol, ErrOptions} {
		if errors.Is(err, known) {
			return true
		}
	}
	var rpc *syntra.RpcError
	if errors.As(err, &rpc) {
		return rpc.Code != syntra.ErrorCodeCancelled && rpc.Code != syntra.ErrorCodeUnavailable && rpc.Code != syntra.ErrorCodeDeadlineExceeded
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) &&
		!errors.Is(err, ErrClosed) && !errors.Is(err, ErrIO) && !errors.Is(err, securechannel.ErrClosed)
}

// LocalStopError identifies interruption errors after this owner's stop fence.
func (t *Transport) LocalStopError(err error) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.localStop && !specificFailure(err) && (localStopError(err) || t.suspended && errors.Is(err, context.DeadlineExceeded))
}

// Stop installs the local admission fence and interrupts I/O without joining.
func (t *Transport) Stop() {
	t.retire(nil, true)
}

// TerminalError exposes the failure before carrier cleanup has joined. The first
// specific failure supersedes generic loss and stays sticky. Local closure is clean.
func (t *Transport) TerminalError() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.terminal
}

// Suspend fences I/O immediately when elapsed-clock continuity is lost.
func (t *Transport) Suspend() {
	t.mu.Lock()
	t.localStop, t.suspended = true, true
	t.mu.Unlock()
	t.channel.Clock().Invalidate()
	t.Stop()
}

// Close first shuts the carrier, then joins operations and the lifecycle task
// before erasing scratch and releasing cipher states. Carriers and host Lookup
// implementations must honor their cancellation contract.
func (t *Transport) Close() error { t.Stop(); <-t.stopped; return nil }

// Stopped closes after carrier cleanup, operations, and lifecycle tasks join.
func (t *Transport) Stopped() <-chan struct{} { return t.stopped }

// CloseContext stops admission and I/O, then waits within the caller's budget.
// A timeout retains the join owner; a later Close still waits for full cleanup.
func (t *Transport) CloseContext(ctx context.Context) error {
	t.Stop()
	select {
	case <-t.stopped:
		return nil
	default:
	}
	select {
	case <-t.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// supervise checks idle authority and joins all owners before clearing scratch.
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
			<-t.carrierStopped
			<-t.clockStopped
			t.ops.Wait()
			t.channel.Close()
			clear(t.sendPlain)
			clear(t.sendCipher)
			clear(t.recvPlain)
			clear(t.recvCipher)
			t.sendPlain, t.sendCipher, t.recvPlain, t.recvCipher = nil, nil, nil, nil
			t.decoder.Close()
			for _, frame := range t.frames {
				clear(frame.raw)
			}
			t.frames = nil
			t.server = nil
			t.mu.Lock()
			t.identity, t.peer, t.identitySet = securechannel.VerifiedIdentity{}, securechannel.Peer{}, false
			t.mu.Unlock()
			return
		case <-confirm:
			confirm = nil
			active = t.server != nil
		case <-t.terminalWake:
			tick.Reset(10 * time.Millisecond)
		case <-tick.C:
			if active {
				if err := t.checkPeer(t.ctx, t.operationDeadline(time.Second), false); err != nil {
					t.abort(err)
				}
			}
		}
	}
}

// VerifiedIdentity includes the authenticated handshake hash for application
// channel binding. Only the responder can issue it after client confirmation.
func (t *Transport) VerifiedIdentity() (securechannel.VerifiedIdentity, bool) {
	if !t.peerReady() {
		return securechannel.VerifiedIdentity{}, false
	}
	if err := t.checkTime(); err != nil {
		t.abort(err)
		return securechannel.VerifiedIdentity{}, false
	}
	select {
	case <-t.done:
		return securechannel.VerifiedIdentity{}, false
	default:
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !t.identitySet {
		return securechannel.VerifiedIdentity{}, false
	}
	return t.identity, true
}

func (t *Transport) rememberIdentity() {
	t.mu.Lock()
	set := t.identitySet
	t.mu.Unlock()
	if set {
		return
	}
	id, ok := t.channel.VerifiedIdentity()
	if !ok {
		return
	}
	peer, ok := t.channel.Peer()
	if !ok {
		return
	}
	t.mu.Lock()
	t.identity, t.peer, t.identitySet = id, peer, true
	t.mu.Unlock()
}

func (t *Transport) peerReady() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.peerRequired || t.peerAuthorized
}

// Serialize callbacks across delivery, writes and idle supervision. The first
// check belongs to Recv, before it exposes the complete initial frame.
func (t *Transport) checkPeer(parent context.Context, until time.Duration, initial bool) (err error) {
	return t.checkPeerMode(parent, until, initial, false, nil)
}

// checkPeerMode is the sole authority classifier for delivery, send and idle
// supervision. Once fenced there is NO ordinary traffic permission, including
// while Active. The explicit terminal observer covers the whole binding, avoiding
// a generic lookup racing an owned commit between two reads. Ordinary connections
// retain their unchanged fail-closed current-key lookup path.
func (t *Transport) checkPeerMode(parent context.Context, until time.Duration, initial, requireCommit bool, handoff func() error) (err error) {
	if !t.peerRequired {
		return nil
	}
	until = min(until, t.operationDeadline(time.Second))
	ctx, cancel := elapsedContext(parent, t.channel.Clock(), until)
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	defer cancel()
	select {
	case t.peerGate <- struct{}{}:
		defer func() {
			if err != nil {
				t.abort(err)
			}
			<-t.peerGate
		}()
	case <-ctx.Done():
		return publicError(ctx, ctx.Err())
	}
	if err := t.checkOperation(ctx, until); err != nil {
		return err
	}
	if !initial && !t.peerReady() {
		return securechannel.ErrAuth
	}
	t.mu.Lock()
	id, ok, permit := t.identity, t.identitySet, t.terminalPermit
	t.mu.Unlock()
	if !ok {
		return securechannel.ErrAuth
	}
	if permit != nil {
		_, err = permit.Observe(ctx, requireCommit)
		if err != nil {
			return securechannel.ErrAuth
		}
	}
	if permit == nil {
		err = t.server.CheckIdentity(ctx, id)
	}
	if timeErr := t.checkOperation(ctx, until); timeErr != nil {
		return timeErr
	}
	if err != nil {
		return securechannel.ErrAuth
	}
	t.mu.Lock()
	t.peerAuthorized = true
	t.mu.Unlock()
	// Consume while still holding the observation gate: no earlier observer can
	// be halfway through publishing a denial at this local linearization point.
	// The callback is prompt, local bookkeeping only; it never performs carrier I/O.
	if handoff != nil {
		return handoff()
	}
	return nil
}

func (t *Transport) ChannelIdentity() (syntra.ChannelIdentity, bool) {
	if !t.peerReady() {
		return syntra.ChannelIdentity{}, false
	}
	if err := t.checkTime(); err != nil {
		t.abort(err)
		return syntra.ChannelIdentity{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed || !t.identitySet {
		return syntra.ChannelIdentity{}, false
	}
	p := t.peer
	c := p.Context
	return syntra.ChannelIdentity{Mode: c.Mode.String(), Carrier: c.Carrier.String(), Scope: c.Scope, Handle: c.Handle, Epoch: c.Epoch, Principal: p.Principal}, true
}

func (t *Transport) acquire(ctx context.Context, admission, gate chan struct{}) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, publicError(ctx, err)
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
			return nil, publicError(ctx, err)
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
		return nil, publicError(ctx, ctx.Err())
	case <-t.done:
		releaseAdmission()
		return nil, ErrClosed
	}
}

func publicError(ctx context.Context, err error) error {
	for _, known := range []error{securechannel.ErrAuth, securechannel.ErrRecord, securechannel.ErrLimit, securechannel.ErrConfig, ErrProtocol, ErrOptions, ErrClosed} {
		if errors.Is(err, known) {
			return known
		}
	}
	var rpc *syntra.RpcError
	if errors.As(err, &rpc) {
		return syntra.NewRpcError(rpc.Code, "ordered: carrier failed")
	}
	if err := ctx.Err(); err != nil {
		if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			return context.DeadlineExceeded
		}
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return ErrIO
}

// Send holds the writer for the entire envelope, including all its records.
// Any error after encryption is terminal: that nonce can never be reused.
func (t *Transport) Send(ctx context.Context, frame []byte) error {
	if len(frame) == 0 || len(frame) > MaxFrame {
		t.abort(ErrProtocol)
		return ErrProtocol
	}
	until := t.operationDeadline(t.opts.WriteTimeout)
	ctx, cancel := elapsedContext(ctx, t.channel.Clock(), until)
	defer cancel()
	release, err := t.acquire(ctx, t.sendAdmission, t.sendGate)
	if err != nil {
		return err
	}
	defer release()
	t.mu.Lock()
	terminal := t.terminalPermit != nil
	t.mu.Unlock()
	if terminal {
		return ErrClosed
	}
	if err := t.checkOperation(ctx, until); err != nil {
		t.abort(err)
		return err
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(frame)))
	for offset := 0; offset < 4+len(frame); {
		if err := t.checkPeer(ctx, until, false); err != nil {
			t.abort(err)
			return err
		}
		if err := t.checkOperation(ctx, until); err != nil {
			t.abort(err)
			return err
		}
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
			return t.cipherFailure(encErr)
		}
		if err := t.checkOperation(ctx, until); err != nil {
			t.abort(err)
			return err
		}
		if err = t.io.WriteMessage(ctx, record); err != nil {
			out := publicError(ctx, err)
			t.abort(out)
			return out
		}
		if err = t.checkOperation(ctx, until); err != nil {
			t.abort(err)
			return err
		}
		offset += n
	}
	t.helloComplete(true)
	return nil
}

// Ping invokes an optional carrier control ping. It shares bounded writer
// admission with Send, and requires a concurrent Recv to process pong replies.
func (t *Transport) Ping(ctx context.Context) error {
	t.mu.Lock()
	terminal := t.terminalPermit != nil
	t.mu.Unlock()
	if terminal {
		return ErrClosed
	}
	p, ok := t.io.(interface{ Ping(context.Context) error })
	if !ok {
		return ErrOptions
	}
	until := t.operationDeadline(t.opts.WriteTimeout)
	ctx, cancel := elapsedContext(ctx, t.channel.Clock(), until)
	defer cancel()
	release, err := t.acquire(ctx, t.sendAdmission, t.sendGate)
	if err != nil {
		return err
	}
	defer release()
	t.mu.Lock()
	terminal = t.terminalPermit != nil
	t.mu.Unlock()
	if terminal {
		return ErrClosed
	}
	if err := t.checkOperation(ctx, until); err != nil {
		t.abort(err)
		return err
	}
	if err = p.Ping(ctx); err != nil {
		out := publicError(ctx, err)
		t.abort(out)
		return out
	}
	if err := t.checkOperation(ctx, until); err != nil {
		t.abort(err)
		return err
	}
	return nil
}

// Recv reassembles the authenticated byte stream without parsing root Frames.
// The absolute frame clock begins with its first authenticated prefix byte,
// including when that byte was buffered alongside a preceding frame.
func (t *Transport) Recv(ctx context.Context) ([]byte, error) {
	frame, _, err := t.RecvWithReceipt(ctx)
	return frame, err
}

// RecvWithReceipt atomically removes an owned frame and the timing captured
// BEFORE its completing decoder push, including time spent in peer authorization.
// Concurrent receivers share the same bounded admission and serialized queue.
// It also publishes that exact pair to the current SDK receive context.
func (t *Transport) RecvWithReceipt(ctx context.Context) ([]byte, syntra.FrameReceipt, error) {
	release, err := t.acquire(ctx, t.recvAdmission, t.recvGate)
	if err != nil {
		return nil, syntra.FrameReceipt{}, err
	}
	defer release()
	for {
		until := t.operationDeadline(t.opts.RecordTimeout)
		if t.frameDeadline != 0 {
			until = min(until, t.frameDeadline)
		}
		if len(t.frames) != 0 {
			until = min(until, t.deliveryDeadline)
		}
		if err := t.checkOperation(ctx, until); err != nil {
			t.abort(err)
			return nil, syntra.FrameReceipt{}, err
		}
		if len(t.frames) != 0 {
			if err := t.checkPeer(ctx, until, true); err != nil {
				t.abort(err)
				return nil, syntra.FrameReceipt{}, err
			}
			if err := t.checkOperation(ctx, until); err != nil {
				t.abort(err)
				return nil, syntra.FrameReceipt{}, err
			}
			frame := t.frames[0]
			t.frames[0] = receivedFrame{}
			t.frames = t.frames[1:]
			t.helloComplete(false)
			t.confirmed.Do(func() { close(t.confirm) })
			frame.receipt.Publish(ctx, frame.raw)
			return frame.raw, frame.receipt, nil
		}
		readCtx, cancel := elapsedContext(ctx, t.channel.Clock(), until)
		ciphertext, err := t.io.ReadMessage(readCtx, t.recvCipher[:0])
		if err == nil {
			err = t.checkOperation(readCtx, until)
		}
		if err != nil {
			out := publicError(readCtx, err)
			cancel()
			t.abort(out)
			return nil, syntra.FrameReceipt{}, out
		}
		cancel()
		plain, err := t.channel.Decrypt(t.recvPlain[:0], ciphertext)
		if err != nil {
			return nil, syntra.FrameReceipt{}, t.cipherFailure(err)
		}
		t.rememberIdentity()
		receipt := syntra.CaptureFrameReceipt(t.channel.Clock())
		frames, err := t.decoder.Push(plain)
		clear(plain)
		if err != nil {
			t.abort(ErrProtocol)
			return nil, syntra.FrameReceipt{}, ErrProtocol
		}
		for _, raw := range frames {
			t.frames = append(t.frames, receivedFrame{raw: raw, receipt: receipt})
		}
		// Synchronous assembly may exhaust the OLD record/frame/Hello/Ready
		// bound. Check it before updating activity or erasing partial state.
		if err := t.checkOperation(ctx, until); err != nil {
			t.abort(err)
			return nil, syntra.FrameReceipt{}, err
		}
		now := receipt.ElapsedAge()
		t.mu.Lock()
		t.lastRecordAt = now
		firstHello := t.responder && t.helloPending
		t.mu.Unlock()
		if firstHello && len(frames) != 0 && (len(frames) != 1 || t.decoder.IsPartial()) {
			t.abort(ErrProtocol)
			return nil, syntra.FrameReceipt{}, ErrProtocol
		}
		if !t.decoder.IsPartial() {
			t.frameDeadline = 0
		} else if t.frameDeadline == 0 || len(frames) != 0 {
			t.frameDeadline = now + t.opts.FrameTimeout
		}
		t.deliveryDeadline = now + t.opts.WriteTimeout
		if t.frameDeadline != 0 {
			until = min(until, t.frameDeadline)
		}
		until = min(until, t.deliveryDeadline)
		if err := t.checkOperation(ctx, until); err != nil {
			t.abort(err)
			return nil, syntra.FrameReceipt{}, err
		}
		if t.peerReady() {
			if err := t.checkPeer(ctx, until, false); err != nil {
				t.abort(err)
				return nil, syntra.FrameReceipt{}, err
			}
		}
	}
}

func (t *Transport) cipherFailure(err error) error {
	err = t.channelError(err)
	t.abort(err)
	if err == ErrClosed {
		return ErrClosed
	}
	return ErrProtocol
}

// Only a closed cipher caused by local teardown is an ordinary interruption.
// Classify the actual operation result, not current channel liveness: a genuine
// decrypt failure can be recorded after another direction has closed the owner.
func (t *Transport) channelError(err error) error {
	if err != securechannel.ErrClosed {
		return err
	}
	t.mu.Lock()
	local := t.localStop
	t.mu.Unlock()
	if local {
		return ErrClosed
	}
	return ErrProtocol
}
