// Session machines for Syntra v1 Go servers: transport-agnostic Client
// (initiator) and Host (responder) built on the validation and codec
// primitives in syntra.go.
//
// A Transport carries exactly one serialized Frame per Send/Recv call in
// each direction. The transport/tcp and transport/websocket packages provide
// bounded secure connectivity; connection orchestrates dialing and serving.
// Hosts may also supply transports that obey the same complete-frame contract.
// LoopbackPair provides an in-memory Transport for tests and embedding.
//
// Both Client and Host delegate state (handshake machine, correlation,
// timers) to the pure-Go core (native_purego.go) in default builds and to
// the production Rust core via the syntranative adapter (native.go) under
// -tags syntranative. NativeAvailable reports which core is linked (false
// in default builds, true with syntranative).
//
// Context deadlines and cancellation: every blocking call honors ctx.
// Call derives the wire timeout_ms budget as the minimum of the
// requested budget and the time remaining on ctx; ctx cancellation sends
// a best-effort cancel frame and reports CANCELLED (context.Canceled) or
// DEADLINE_EXCEEDED (context.DeadlineExceeded / budget expiry) without
// waiting for the late terminal result, which the pump still consumes to
// keep correlation exact.
package syntra

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	syntrav1 "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/encoding/protowire"
)

// Transport carries serialized Syntra Frames. Each Send transmits exactly
// one Frame toward the peer; each Recv returns exactly one inbound Frame.
// Implementations MUST preserve frame boundaries and MUST NOT batch
// multiple Frames into one Send payload. The session layer validates
// sizes and contents; transports MUST still bound allocation on receive.
type Transport interface {
	// Send transmits one serialized Frame. It MUST copy frame if it
	// retains it and return promptly when ctx ends.
	Send(ctx context.Context, frame []byte) error
	// Recv returns the next inbound serialized Frame. It returns an
	// error when the transport is closed and drained or ctx ends.
	Recv(ctx context.Context) ([]byte, error)
	// Close releases the transport and interrupts pending I/O. It is idempotent.
	Close() error
}

// ownedTransport gives each running session exactly one terminal close.
type ownedTransport struct {
	Transport
	once sync.Once
	err  error
}

func (t *ownedTransport) Close() error {
	t.once.Do(func() { t.err = t.Transport.Close() })
	return t.err
}

func (t *ownedTransport) ChannelIdentity() (ChannelIdentity, bool) {
	if provider, ok := t.Transport.(ChannelIdentityProvider); ok {
		return provider.ChannelIdentity()
	}
	return ChannelIdentity{}, false
}

// loopback is an in-memory Transport. Frames cross by value (Send copies)
// so callers can reuse buffers.
type loopback struct {
	mu     *sync.Mutex // shared by both endpoints, including Send and Close
	inbox  chan []byte
	closed bool
	peer   *loopback
}

const loopbackBuffer = 64

// LoopbackPair returns two connected in-memory Transports: frames sent
// on a arrive on b and vice versa. It is the standard harness for
// lifecycle tests and for embedding a session without a socket.
func LoopbackPair() (a, b Transport) {
	mu := &sync.Mutex{}
	x := &loopback{mu: mu, inbox: make(chan []byte, loopbackBuffer)}
	y := &loopback{mu: mu, inbox: make(chan []byte, loopbackBuffer)}
	x.peer = y
	y.peer = x
	return x, y
}

// Send transmits one frame toward the peer. A closed transport reports
// Unavailable; an oversize frame is rejected before allocation.
func (l *loopback) Send(ctx context.Context, frame []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateFrameSize(len(frame)); err != nil {
		return err
	}
	cp := make([]byte, len(frame))
	copy(cp, frame)
	l.mu.Lock()
	defer l.mu.Unlock()
	peer := l.peer
	if l.closed || peer.closed {
		return NewRpcError(ErrorCodeUnavailable, "syntra: loopback peer closed")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case peer.inbox <- cp:
		return nil
	default:
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: loopback peer inbox full")
	}
}

// Recv returns the next inbound frame, draining buffered frames after
// Close before reporting Unavailable.
func (l *loopback) Recv(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case f, ok := <-l.inbox:
		if !ok {
			return nil, NewRpcError(ErrorCodeUnavailable, "syntra: loopback closed")
		}
		if err := ValidateFrameSize(len(f)); err != nil {
			return nil, err
		}
		return f, nil
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case f, ok := <-l.inbox:
		if !ok {
			return nil, NewRpcError(ErrorCodeUnavailable, "syntra: loopback closed")
		}
		if err := ValidateFrameSize(len(f)); err != nil {
			return nil, err
		}
		return f, nil
	}
}

// Close drains and releases the transport. It is idempotent.
func (l *loopback) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.inbox)
	if l.peer != nil {
		if !l.peer.closed {
			l.peer.closed = true
			close(l.peer.inbox)
		}
	}
	return nil
}

// StaticPolicy returns a CredentialPolicy that accepts any credential and
// binds principal. It is intended for tests, examples, and
// anonymous-intent deployments; production hosts MUST verify credentials
// against their identity system. When allowEmpty is false, empty
// credentials are rejected as Unauthenticated.
func StaticPolicy(principal string, allowEmpty bool) CredentialPolicy {
	return func(ctx context.Context, credential []byte) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", NewRpcError(ErrorCodeUnavailable, "syntra: policy context ended")
		}
		if principal == "" {
			return "", NewRpcError(ErrorCodeInternal, "syntra: policy principal misconfigured")
		}
		if len(credential) == 0 && !allowEmpty {
			return "", NewRpcError(ErrorCodeUnauthenticated, "syntra: credential required")
		}
		return principal, nil
	}
}

// HandlerFunc implements one application method for a Host. It receives
// the validated RpcRequest with ctx bounded by the effective call budget
// (cancellation propagates client cancel frames and conn teardown). It
// returns either a valid *RpcResult or an error: a *RpcError becomes the
// wire error outcome; any other error becomes a generic INTERNAL outcome
// so handler internals never leak to the peer (SNTR-ERR-003). Returning
// (nil, nil) is a handler bug and is reported as INTERNAL.
type HandlerFunc func(ctx context.Context, req *RpcRequest) (*RpcResult, error)

// AuthorizeFunc is the host-owned per-method policy, evaluated
// for every RPC using the connection's bound principal, before handler
// effects. Implementations must be nonblocking and may re-check
// expiry/revocation here. A nil Authorize selects DenyAllAuthorize.
// Only generic Unauthenticated
// ("syntra: credential not accepted") and PermissionDenied
// ("syntra: access denied") codes/messages reach the wire, so policy
// internals never leak (SNTR-ERR-003). Returning Unauthenticated signals
// an expired/revoked binding: the per-RPC UNAUTHENTICATED error is sent,
// then Serve closes the connection by default (SNTR-AUTH-008/SNTR-ASEC-006);
// use PermissionDenied for per-method denials that keep the connection
// usable (SNTR-AUTH-009).
type AuthorizeFunc func(ctx context.Context, principal string, method string) error

// DenyAllAuthorize matches the Rust Handler::authorize fail-closed default:
// every RPC is denied with generic PermissionDenied. Wrap or replace with
// a principal-aware policy to allow selected methods.
func DenyAllAuthorize(ctx context.Context, principal string, method string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return NewRpcError(ErrorCodePermissionDenied, "syntra: access denied")
}

// AllowAllAuthorize documents an explicit opt-in to the permissive
// posture (every bound principal may invoke every method). It exists so
// call sites can state the allow-all choice instead of leaving
// HostConfig.Authorize nil by accident.
func AllowAllAuthorize(ctx context.Context, principal string, method string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

// clientCore owns initiator-side session state: handshake progress,
// correlation, timers, and notification queue. Implementations are the
// pure-Go core (native_purego.go, default builds) and the production
// native adapter (native.go, -tags syntranative). All methods except close are invalid
// after close reports, and report FailedPrecondition once closed.
type clientCore interface {
	// helloFrame returns the hello frame to transmit. It fails closed on
	// invalid config (empty version range, oversize credential). The session
	// calls it once and releases its Go credential references after emission.
	helloFrame() ([]byte, error)
	// activate validates the ServerReady frame, pins the negotiated
	// version, and moves the session to ACTIVE.
	activate(frame []byte) (*ServerReady, error)
	// version returns the negotiated version, or 0 before activate.
	version() uint32
	// onFrame validates one inbound frame and stores its terminal
	// effects. It returns the request IDs whose outcomes became terminal
	// (to deliver) and the number of queued notifications. A fatal
	// protocol violation is returned as *RpcError and the session MUST
	// be torn down by the caller.
	onFrame(frame []byte) (terminal []uint64, notifications int, fatal *RpcError)
	// beginCall validates and registers an outbound call and returns the
	// request frame to transmit.
	beginCall(requestID uint64, method string, payload []byte, timeoutMs uint32) (reqFrame []byte, err error)
	// cancelCall marks an outstanding call cancelled and returns the
	// cancel frame to transmit, or nil when the id is unknown (ignored
	// per SNTR-RPC-005, no error, no frame).
	cancelCall(requestID uint64) (cancelFrame []byte)
	// takeOutcome consumes the terminal outcome for id. ok is false when
	// the call is not terminal yet (or unknown).
	takeOutcome(requestID uint64) (result *RpcResult, ok bool)
	// pollNotification consumes one queued notification, or ok == false.
	pollNotification() (*Notification, bool)
	// lossTotals reports cumulative notification-loss totals for the core:
	// (dropped_count, dropped_bytes) for notifications discarded when the
	// bounded core queue was full. Bounds are unchanged; the queue stays
	// non-blocking and drops the newest notification. Counters advance
	// exactly once per drop (no double-counting), unifying the pure-Go
	// core, the native FFI core, and the async Rust notification_loss
	// signal.
	lossTotals() (dropped uint64, droppedBytes uint64)
	// reapExpired removes calls whose deadlines passed, stores a
	// DEADLINE_EXCEEDED outcome for each, and returns their ids for
	// delivery. Completion wins: ids with a stored outcome are skipped.
	reapExpired(now time.Time) (expired []uint64)
	// close deterministically releases the core. Second close reports
	// FailedPrecondition.
	close() error
}

// hostCore owns responder-side per-connection state: handshake progress,
// pending validated requests, outstanding call deadlines, cancellation
// marks, and the outbound queue. Handler dispatch itself lives in Go
// (Host.Serve); the core never interprets application payloads.
type hostCore interface {
	// acceptHello validates the ClientHello frame, negotiates the
	// highest overlap against the configured range, and returns the
	// selected version. State advances to NEGOTIATING.
	acceptHello(frame []byte) (version uint32, err error)
	// authComplete binds principal, advances to ACTIVE, and returns the
	// ServerReady frame to transmit.
	authComplete(principal string) (readyFrame []byte, err error)
	// onFrame validates one inbound frame. Immediate response frames
	// (ready is produced by authComplete; ACTIVE-phase validation
	// failures produce error results here) are returned for transmit.
	// Requests that pass validation are queued for takePending.
	// cancelIDs names outstanding calls the peer cancelled. A fatal
	// protocol violation (handshake-phase failure, empty body, version
	// mismatch) is returned and the caller MUST close the connection.
	onFrame(frame []byte) (responses [][]byte, cancelIDs []uint64, fatal *RpcError)
	// takePending dequeues one validated request for dispatch.
	takePending() (requestID uint64, req *RpcRequest, ok bool)
	// isCancelled reports whether id was cancelled by the peer.
	isCancelled(requestID uint64) bool
	// answer validates and enqueues the terminal result frame, returning
	// it for transmit. When the call expired first, expired is true (a
	// DEADLINE_EXCEEDED result was auto-enqueued instead) and resp is nil.
	answer(requestID uint64, result *RpcResult) (resp []byte, expired bool, err error)
	// notify validates and enqueues a broadcast notification.
	notify(payload []byte) error
	// nextOutbound dequeues one queued frame (results, auto-deadline
	// results, notifications), or ok == false when empty.
	nextOutbound() (frame []byte, ok bool)
	// reapExpired removes calls whose deadlines passed, auto-enqueues a
	// DEADLINE_EXCEEDED result for each, and returns their ids so the
	// caller can abandon the handlers.
	reapExpired(now time.Time) (expired []uint64)
	// close deterministically releases the core. Second close reports
	// FailedPrecondition.
	close() error
}

// activatedReady is the validated outcome of a client handshake.
type activatedReady struct {
	ready        *ServerReady
	frameVersion uint32
}

// activateFrame validates one inbound ServerReady frame against the
// proposed range and returns the selected version. Shared handshake
// acceptance for both cores (pure-Go default and syntranative native).
func activateFrame(frame []byte, minVersion, maxVersion uint32) (*activatedReady, error) {
	f, err := unmarshalSessionFrame(frame)
	if err != nil {
		return nil, err
	}
	if BodyKindOf(f) != BodyKindReady {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: handshake expects ready")
	}
	if f.GetRequestId() != 0 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: ready frame must carry request_id 0")
	}
	v := f.GetVersion()
	if v < minVersion || v > maxVersion {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: server selected version outside proposed range")
	}
	if err := ValidateReady(f.GetReady()); err != nil {
		return nil, err
	}
	return &activatedReady{ready: f.GetReady(), frameVersion: v}, nil
}

// unmarshalSessionFrame gives unsupported runtime envelope versions the
// connection-state error code. Stateless codec validation retains its own
// OUT_OF_RANGE contract.
func unmarshalSessionFrame(raw []byte) (*Frame, error) {
	f, err := UnmarshalFrame(raw)
	var rpcErr *RpcError
	if errors.As(err, &rpcErr) && rpcErr.Code == ErrorCodeOutOfRange {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: unsupported session version")
	}
	return f, err
}

func validateActiveSessionFrame(raw []byte, version uint32) error {
	if err := ValidateFrameSize(len(raw)); err != nil {
		return err
	}
	if err := scanFrameTags(raw); err != nil {
		return err
	}
	// Read only the phase header here. The core immediately performs full
	// decoding and semantic validation before admitting any effects. Avoid
	// constructing and copying a second Protobuf message in the session loop.
	var wireVersion uint64
	var body protowire.Number
	for len(raw) != 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		raw = raw[n:] // scanFrameTags has validated all tags and values.
		if num == 1 {
			v, n := protowire.ConsumeVarint(raw)
			wireVersion = v
			raw = raw[n:]
			continue
		}
		if num >= 10 && num <= 15 {
			body = num
		}
		var err error
		raw, err = skipUnknown(raw, num, typ, 1)
		if err != nil {
			return err
		}
	}
	if wireVersion == 0 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: version 0 is never negotiated")
	}
	if wireVersion != uint64(version) {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: frame version mismatch")
	}
	if body == 10 || body == 11 {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: re-handshake on the same connection is forbidden")
	}
	return nil
}

// resolvedClientConfig is a ClientConfig with defaults applied.
type resolvedClientConfig struct {
	minVersion   uint32
	maxVersion   uint32
	credential   []byte
	timeout      time.Duration
	maxPending   int
	notifyBuffer int
}

// ClientConfig configures a Client session.
type ClientConfig struct {
	// MinVersion/MaxVersion bound the proposed handshake range. Zero
	// selects the binding singleton (v1). Min must not exceed Max.
	MinVersion uint32
	// MaxVersion is the proposed maximum; the hello frame carries it.
	MaxVersion uint32
	// Credential is the opaque hello credential. Empty is an attempt
	// subject to host policy, not a parse error; oversize fails fast.
	// OpenClient copies it; callers retain ownership of their input buffer.
	// Go credential references are released after hello emission or Close.
	Credential []byte
	// DefaultTimeout applies when a call passes timeoutMs zero. Zero
	// selects DefaultRPCTimeout. Negative or above MaxRPCTimeoutMs fails fast.
	// The value is rounded up to whole milliseconds at resolution so the
	// pure-Go and native backends enforce the identical deadline.
	DefaultTimeout time.Duration
	// MaxConcurrent caps outstanding calls. Zero selects
	// MaxConcurrentRPCs; larger values are rejected. Excess calls fail fast
	// with ResourceExhausted.
	MaxConcurrent int
	// NotifyBuffer sizes the notification queue. Zero selects 16.
	// Overflow drops the newest notification and counts it (see
	// DroppedNotifications).
	NotifyBuffer int
}

func resolveClientConfig(cfg ClientConfig) (resolvedClientConfig, error) {
	out := resolvedClientConfig{
		minVersion:   cfg.MinVersion,
		maxVersion:   cfg.MaxVersion,
		timeout:      cfg.DefaultTimeout,
		maxPending:   cfg.MaxConcurrent,
		notifyBuffer: cfg.NotifyBuffer,
	}
	if out.minVersion == 0 {
		out.minVersion = MinSupportedVersion
	}
	if out.maxVersion == 0 {
		out.maxVersion = MaxSupportedVersion
	}
	if out.minVersion > out.maxVersion {
		return resolvedClientConfig{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: client min_version exceeds max_version")
	}
	if err := ValidateCredentialSize(cfg.Credential); err != nil {
		return resolvedClientConfig{}, err
	}
	if out.timeout == 0 {
		out.timeout = DefaultRPCTimeout
	}
	if out.timeout <= 0 {
		return resolvedClientConfig{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: client default timeout must be positive")
	}
	if out.timeout > time.Duration(MaxRPCTimeoutMs)*time.Millisecond {
		return resolvedClientConfig{}, NewRpcError(ErrorCodeOutOfRange, "syntra: client default timeout exceeds max")
	}
	// Normalize once so both backends share the identical deadline: whole
	// milliseconds, rounded up, never shorter than configured.
	out.timeout = time.Duration(roundUpToMs(out.timeout)) * time.Millisecond
	if out.maxPending == 0 {
		out.maxPending = MaxConcurrentRPCs
	}
	if out.maxPending < 1 {
		return resolvedClientConfig{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: client max concurrent must be positive")
	}
	if out.maxPending > MaxConcurrentRPCs {
		return resolvedClientConfig{}, NewRpcError(ErrorCodeOutOfRange, "syntra: client max concurrent exceeds max")
	}
	if out.notifyBuffer == 0 {
		out.notifyBuffer = 16
	}
	if out.notifyBuffer < 1 {
		return resolvedClientConfig{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: notify buffer must be positive")
	}
	out.credential = append([]byte(nil), cfg.Credential...)
	return out, nil
}

// Client is an initiator-side Syntra session. The zero value is invalid;
// construct with OpenClient. A Client is safe for concurrent Call and
// notification subscription; one Run pump owns the Transport.
type Client struct {
	core   clientCore
	cfg    resolvedClientConfig
	nextID atomic.Uint64

	mu           sync.Mutex
	activated    chan struct{} // closed after successful handshake
	closed       bool
	pumpStarted  bool // once true, Run alone closes notifyCh after the pump exits
	done         chan struct{}
	waiters      map[uint64]chan *RpcResult
	notifyCh     chan *Notification
	dropped      atomic.Uint64
	droppedBytes atomic.Uint64
	// lossCh is a broadcast channel: every drop closes the current channel
	// and replaces it, so ALL WaitLossChange waiters wake (a single-token
	// buffered channel would wake only one waiter). The counters are the
	// signal; the channel is only the wakeup. Guarded by lossMu.
	lossMu sync.Mutex
	lossCh chan struct{}
	// Core loss snapshots keep LossTotals monotonic across Close: the FFI
	// core reports (0,0) once its handle is destroyed, so Close caches the
	// last-known core totals and LossTotals returns the max of live and
	// cached. Pure-Go cores keep reporting after close; max() is a no-op
	// there.
	coreCachedDropped atomic.Uint64
	coreCachedBytes   atomic.Uint64
	transport         Transport
	transportOwner    *ownedTransport
	// Serializes frame ingestion (the only core loss producer) with the
	// final loss snapshot and destruction. Never held while waiting for Run
	// or while publishing notifications; Close may interrupt delivery.
	coreLifecycleMu sync.Mutex
}

// OpenClient creates an initiator session. It validates the config and
// opens the linked core (native or pure-Go) but performs no I/O; call
// Run to handshake and pump a Transport.
func OpenClient(cfg ClientConfig) (*Client, error) {
	rcfg, err := resolveClientConfig(cfg)
	if err != nil {
		return nil, err
	}
	core, err := newClientCore(rcfg)
	if err != nil {
		return nil, err
	}
	c := &Client{
		core:      core,
		cfg:       rcfg,
		activated: make(chan struct{}),
		done:      make(chan struct{}),
		waiters:   make(map[uint64]chan *RpcResult),
		notifyCh:  make(chan *Notification, rcfg.notifyBuffer),
		lossCh:    make(chan struct{}),
	}
	return c, nil
}

// Notifications returns the notification stream. The channel is closed
// when the session closes. Overflow drops the newest notification and
// counts it; see DroppedNotifications. Receive promptly or size
// NotifyBuffer for bursts.
func (c *Client) Notifications() <-chan *Notification {
	return c.notifyCh
}

// DroppedNotifications reports notifications discarded under overflow.
func (c *Client) DroppedNotifications() uint64 {
	if c == nil {
		return 0
	}
	return c.dropped.Load()
}

// DroppedBytes reports cumulative notification payload bytes discarded
// under overflow. It pairs with DroppedNotifications: both advance exactly
// once per drop (no double-counting).
func (c *Client) DroppedBytes() uint64 {
	if c == nil {
		return 0
	}
	return c.droppedBytes.Load()
}

// LossTotals reports cumulative notification-loss totals for the session:
// (dropped_count, dropped_bytes) summed over the public notifyCh queue and
// the linked core queue. Bounds are unchanged on both queues; both stay
// non-blocking and drop the newest notification. The two layers are
// disjoint (a notification dropped in the core never reaches the public
// queue), so the sum counts every drop exactly once. Totals are monotonic
// across Close: the last-known core totals are cached at Close and the max
// of live and cached is returned (the FFI core reports zero once its
// handle is destroyed).
func (c *Client) LossTotals() (dropped uint64, droppedBytes uint64) {
	if c == nil {
		return 0, 0
	}
	pubDropped := c.dropped.Load()
	pubBytes := c.droppedBytes.Load()
	var coreDropped, coreBytes uint64
	if c.core != nil {
		coreDropped, coreBytes = c.core.lossTotals()
	}
	if cached := c.coreCachedDropped.Load(); cached > coreDropped {
		coreDropped = cached
	}
	if cached := c.coreCachedBytes.Load(); cached > coreBytes {
		coreBytes = cached
	}
	return pubDropped + coreDropped, pubBytes + coreBytes
}

// snapshotCoreLoss caches the current core loss totals, keeping the max so
// LossTotals stays monotonic across Close. Caller holds coreLifecycleMu.
func (c *Client) snapshotCoreLoss() {
	if c == nil || c.core == nil {
		return
	}
	d, b := c.core.lossTotals()
	for {
		cur := c.coreCachedDropped.Load()
		if d <= cur || c.coreCachedDropped.CompareAndSwap(cur, d) {
			break
		}
	}
	for {
		cur := c.coreCachedBytes.Load()
		if b <= cur || c.coreCachedBytes.CompareAndSwap(cur, b) {
			break
		}
	}
}

// closeCore fences onFrame before taking the final snapshot. Waiting for
// Run itself here would deadlock its deferred cleanup; only the in-flight
// core operation must finish. Callers have already set closed under mu,
// and must release mu before acquiring coreLifecycleMu.
func (c *Client) closeCore() error {
	c.coreLifecycleMu.Lock()
	defer c.coreLifecycleMu.Unlock()
	c.snapshotCoreLoss()
	return c.core.close()
}

// broadcastLoss wakes ALL WaitLossChange waiters: the current channel is
// closed and replaced atomically under lossMu. Bursts cannot block the pump
// (close+replace never blocks) and waiters never double-count (counters
// are the signal, the channel only the wakeup).
func (c *Client) broadcastLoss() {
	if c == nil {
		return
	}
	c.lossMu.Lock()
	old := c.lossCh
	c.lossCh = make(chan struct{})
	c.lossMu.Unlock()
	if old != nil {
		close(old)
	}
}

// recordPublicLoss advances the public cumulative loss counters by one drop
// plus its payload bytes and wakes all loss waiters. It is the single
// place public drops are counted, so bursts cannot double-count.
func (c *Client) recordPublicLoss(payloadLen int) {
	c.dropped.Add(1)
	c.droppedBytes.Add(uint64(payloadLen))
	c.broadcastLoss()
}

// WaitLossChange blocks until the cumulative loss totals differ from
// lastDropped/lastBytes, the session closes, or ctx ends. It returns the
// current totals. Every waiter observes the same carried totals (broadcast
// wakeup: all concurrent waiters fire, not just one); a waiter subscribed
// after the drop reads them as current state instead of missing the signal.
// A closed session returns current totals with no error; ctx expiry returns
// ctx.Err.
func (c *Client) WaitLossChange(ctx context.Context, lastDropped, lastBytes uint64) (uint64, uint64, error) {
	if c == nil {
		return 0, 0, NewRpcError(ErrorCodeInternal, "syntra: nil client")
	}
	if d, b := c.LossTotals(); d != lastDropped || b != lastBytes {
		return d, b, nil
	}
	for {
		c.lossMu.Lock()
		ch := c.lossCh
		c.lossMu.Unlock()
		// Re-check after snapshotting the channel: a drop that landed
		// between the first check and the snapshot must not be missed.
		if d, b := c.LossTotals(); d != lastDropped || b != lastBytes {
			return d, b, nil
		}
		select {
		case <-ctx.Done():
			d, b := c.LossTotals()
			return d, b, ctx.Err()
		case <-c.done:
			d, b := c.LossTotals()
			return d, b, nil
		case <-ch:
			if d, b := c.LossTotals(); d != lastDropped || b != lastBytes {
				return d, b, nil
			}
		}
	}
}

// failWaiters completes outstanding calls with err. Callers MUST hold c.mu.
func (c *Client) failWaitersLocked(code ErrorCode, msg string) {
	res := NewWireErrorResult(code, msg)
	for id, w := range c.waiters {
		delete(c.waiters, id)
		select {
		case w <- res:
		default:
		}
	}
}

// handshake performs the hello/ready exchange on t.
func (c *Client) handshake(ctx context.Context, t Transport) (*ServerReady, error) {
	ctx, stop := context.WithTimeout(ctx, sessionHandshakeTimeout)
	defer stop()
	hello, err := c.core.helloFrame()
	c.mu.Lock()
	c.cfg.credential = nil
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if err := t.Send(ctx, hello); err != nil {
		return nil, err
	}
	hello = nil
	raw, err := t.Recv(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		return nil, NewRpcError(ErrorCodeUnavailable, fmt.Sprintf("syntra: handshake recv: %v", err))
	}
	ready, err := c.core.activate(raw)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	close(c.activated)
	return ready, nil
}

// Run handshakes on t, then pumps frames until ctx ends, the transport
// fails, a fatal protocol violation arrives, or Close is called. It
// returns nil only on a clean shutdown (Close or ctx end with no
// outstanding violation); transport and protocol failures are returned.
// Call Run once per Client in its own goroutine; concurrent Calls share
// the pump. Run owns t and closes it on every terminal path, including
// handshake failure. The handshake has a five-second deadline, shortened by ctx;
// that deadline does not limit the activated connection's lifetime.
func (c *Client) Run(ctx context.Context, t Transport) error {
	if c == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil client")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	if c.transport != nil {
		c.mu.Unlock()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: client already running")
	}
	if t == nil {
		c.mu.Unlock()
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil transport")
	}
	c.transport = t
	c.transportOwner = &ownedTransport{Transport: t}
	t = c.transportOwner
	c.mu.Unlock()

	// Close also interrupts a handshake blocked in transport I/O.
	runCtx, stop := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	defer func() { stop(); <-watchDone }()
	go func() {
		defer close(watchDone)
		select {
		case <-c.done:
			stop()
		case <-runCtx.Done():
		}
	}()
	defer func() {
		_ = t.Close()
		c.mu.Lock()
		c.cfg.credential = nil
		closeCore := !c.closed
		if closeCore {
			c.closed = true
			c.failWaitersLocked(ErrorCodeUnavailable, "syntra: client closed")
			close(c.done)
			if !c.pumpStarted {
				close(c.notifyCh)
			}
		}
		if c.pumpStarted {
			close(c.notifyCh)
		}
		c.mu.Unlock()
		if closeCore {
			_ = c.closeCore()
		}
	}()
	if _, err := c.handshake(runCtx, t); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		select {
		case <-c.done:
			return nil
		default:
			return err
		}
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.pumpStarted = true
	c.mu.Unlock()
	err := c.pump(runCtx, t)
	if err == nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}
	return err
}

// recvResult is one transport read: exactly one serialized frame or the
// terminal read error.
type recvResult struct {
	raw []byte
	err error
}

// pumpTick bounds deadline granularity for calls whose budget expires
// while no frames arrive. Reaping is idempotent and cheap on both cores.
const pumpTick = 10 * time.Millisecond

// The entire hello/policy/ready exchange shares one five-second budget
// (SNTR-HS-011), shortened by the caller's deadline or cancellation. It
// never becomes the lifetime context of an activated connection.
const sessionHandshakeTimeout = 5 * time.Second

// Go cannot forcibly interrupt host callbacks. Teardown signals all
// handlers and drains completions for this grace period before abandoning
// callbacks that ignore their contexts. No waiter goroutine is left behind.
const handlerShutdownGrace = time.Second

// pump routes inbound frames to call waiters and the notification
// stream, and reaps expired calls on a tick so budgets fire even when
// the peer goes silent.
func (c *Client) pump(ctx context.Context, t Transport) error {
	pumpCtx, pumpStop := context.WithCancel(ctx)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		select {
		case <-pumpCtx.Done():
		case <-c.done:
			pumpStop()
		}
	}()
	recvCh := make(chan recvResult, 1)
	recvDone := make(chan struct{})
	defer func() {
		pumpStop()
		_ = t.Close()
		<-recvDone
		<-watchDone
	}()
	go func() {
		defer close(recvDone)
		for {
			raw, err := t.Recv(pumpCtx)
			select {
			case recvCh <- recvResult{raw: raw, err: err}:
			case <-pumpCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(pumpTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-c.done:
			return nil
		case r := <-recvCh:
			if r.err != nil {
				if ctx.Err() != nil {
					return nil
				}
				select {
				case <-c.done:
					return nil
				default:
				}
				if errors.Is(r.err, context.Canceled) || errors.Is(r.err, context.DeadlineExceeded) {
					return nil
				}
				var rerr *RpcError
				if errors.As(r.err, &rerr) {
					c.failWaiters(rerr.Code, rerr.Message)
					return r.err
				}
				if errors.Is(r.err, io.EOF) {
					c.failWaiters(ErrorCodeUnavailable, "syntra: transport closed")
					return NewRpcError(ErrorCodeUnavailable, "syntra: transport closed")
				}
				c.failWaiters(ErrorCodeUnavailable, "syntra: transport recv failed")
				return NewRpcError(ErrorCodeUnavailable, fmt.Sprintf("syntra: transport recv: %v", r.err))
			}
			prevDropped, prevBytes := c.LossTotals()
			c.coreLifecycleMu.Lock()
			c.mu.Lock()
			closed := c.closed
			c.mu.Unlock()
			if closed {
				c.coreLifecycleMu.Unlock()
				return nil
			}
			if err := validateActiveSessionFrame(r.raw, c.core.version()); err != nil {
				c.coreLifecycleMu.Unlock()
				var rpcErr *RpcError
				if errors.As(err, &rpcErr) {
					c.failWaiters(rpcErr.Code, rpcErr.Message)
				}
				return err
			}
			terminal, n, fatal := c.core.onFrame(r.raw)
			c.coreLifecycleMu.Unlock()
			if fatal != nil {
				c.failWaiters(fatal.Code, fatal.Message)
				return fatal
			}
			for i := 0; i < n; i++ {
				if ntf, ok := c.core.pollNotification(); ok {
					select {
					case c.notifyCh <- ntf:
					default:
						c.recordPublicLoss(len(ntf.GetPayload()))
					}
				}
			}
			// Core-level drops (bounded core queue overflow) also wake
			// public loss waiters: the totals changed even though no new
			// notification arrived, so idle peers still observe the loss.
			// The counters are the signal; the broadcast wakes all waiters.
			if d, b := c.LossTotals(); d != prevDropped || b != prevBytes {
				c.broadcastLoss()
			}
			for _, id := range terminal {
				if res, ok := c.core.takeOutcome(id); ok {
					c.deliver(id, res)
				}
			}
			c.reap(time.Now())
		case <-ticker.C:
			c.reap(time.Now())
		}
	}
}

// reap expires overdue calls and delivers their DEADLINE_EXCEEDED
// outcomes to waiters (or discards them when the waiter already left;
// the core already consumed the outcome either way).
func (c *Client) reap(now time.Time) {
	for _, id := range c.core.reapExpired(now) {
		if res, ok := c.core.takeOutcome(id); ok {
			c.deliver(id, res)
		}
	}
}

// failWaiters completes outstanding calls with a synthesized error.
func (c *Client) failWaiters(code ErrorCode, msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failWaitersLocked(code, msg)
}

// deliver routes one terminal outcome to its waiter, discarding it when
// the waiter already left (cancelled or timed-out locally). The core
// already consumed the outcome, so correlation stays exact either way.
func (c *Client) deliver(id uint64, res *RpcResult) {
	c.mu.Lock()
	w, ok := c.waiters[id]
	if ok {
		delete(c.waiters, id)
	}
	c.mu.Unlock()
	if !ok {
		return
	}
	select {
	case w <- res:
	default:
	}
}

// Call invokes method with payload and waits for exactly one terminal
// result. timeoutMs zero selects the configured default; larger than
// MaxRPCTimeoutMs fails fast. The effective budget is the minimum of the
// requested budget and ctx's remaining time. On ctx end the binding sends
// a best-effort cancel and reports CANCELLED (ctx canceled) or
// DEADLINE_EXCEEDED (ctx deadline / budget expiry). A successful outcome
// returns the opaque payload bytes; an error outcome is returned as
// *RpcError (branch on Code, never on message text).
func (c *Client) Call(ctx context.Context, method string, payload []byte, timeoutMs uint32) ([]byte, error) {
	if c == nil {
		return nil, NewRpcError(ErrorCodeInternal, "syntra: nil client")
	}
	if err := ctx.Err(); err != nil {
		return nil, mapContextErr(err)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	c.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, mapContextErr(ctx.Err())
	case <-c.done:
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	case <-c.activated:
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	t := c.transport
	c.mu.Unlock()

	budget := c.cfg.timeout
	if timeoutMs > 0 {
		budget = time.Duration(timeoutMs) * time.Millisecond
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining <= 0 {
			return nil, NewRpcError(ErrorCodeDeadlineExceeded, "syntra: context deadline already exceeded")
		} else if remaining < budget {
			budget = remaining
		}
	}
	if err := ValidatePayloadSize(len(payload)); err != nil {
		return nil, err
	}
	id := c.nextID.Add(1)
	wireTimeout := uint32(budget / time.Millisecond)
	if wireTimeout == 0 {
		wireTimeout = 1
	}
	reqFrame, err := c.core.beginCall(id, method, payload, wireTimeout)
	if err != nil {
		return nil, err
	}
	w := make(chan *RpcResult, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	c.waiters[id] = w
	c.mu.Unlock()

	removeWaiter := func() {
		c.mu.Lock()
		if cur, ok := c.waiters[id]; ok && cur == w {
			delete(c.waiters, id)
		}
		c.mu.Unlock()
	}

	callStart := time.Now()
	sendCtx, sendStop := context.WithTimeout(ctx, budget)
	sendErr := t.Send(sendCtx, reqFrame)
	sendStop()
	if sendErr != nil {
		removeWaiter()
		if errors.Is(sendErr, context.Canceled) || errors.Is(sendErr, context.DeadlineExceeded) {
			c.cancelBestEffort(id)
			if ctx.Err() != nil {
				return nil, mapContextErr(ctx.Err())
			}
			return nil, NewRpcError(ErrorCodeDeadlineExceeded, "syntra: call budget exceeded during send")
		}
		return nil, NewRpcError(ErrorCodeUnavailable, fmt.Sprintf("syntra: send request: %v", sendErr))
	}
	remaining := budget - time.Since(callStart)
	if remaining <= 0 {
		select {
		case res := <-w:
			return finishCall(res)
		default:
		}
		removeWaiter()
		c.cancelBestEffort(id)
		return nil, NewRpcError(ErrorCodeDeadlineExceeded, "syntra: call budget exceeded")
	}
	budgetTimer := time.NewTimer(remaining)
	defer budgetTimer.Stop()
	select {
	case res := <-w:
		return finishCall(res)
	case <-ctx.Done():
		removeWaiter()
		c.cancelBestEffort(id)
		if ctx.Err() != nil {
			return nil, mapContextErr(ctx.Err())
		}
		return nil, NewRpcError(ErrorCodeCancelled, "syntra: call cancelled")
	case <-c.done:
		removeWaiter()
		return nil, NewRpcError(ErrorCodeUnavailable, "syntra: client closed")
	case <-budgetTimer.C:
		select {
		case res := <-w:
			return finishCall(res)
		default:
		}
		removeWaiter()
		c.cancelBestEffort(id)
		return nil, NewRpcError(ErrorCodeDeadlineExceeded, "syntra: call budget exceeded")
	}
}

// cancelBestEffort marks the call cancelled and transmits the cancel
// frame, ignoring transport errors: cancellation is advisory
// (SNTR-RPC-005) and the late terminal result still converges the
// correlation table via the pump.
func (c *Client) cancelBestEffort(id uint64) {
	frame := c.core.cancelCall(id)
	if len(frame) == 0 {
		return
	}
	c.mu.Lock()
	t := c.transport
	c.mu.Unlock()
	if t == nil {
		return
	}
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	_ = t.Send(ctx, frame)
}

// finishCall converts a terminal wire outcome to the Call contract.
func finishCall(res *RpcResult) ([]byte, error) {
	if res == nil {
		return nil, NewRpcError(ErrorCodeInternal, "syntra: nil terminal outcome")
	}
	switch outcome := res.GetOutcome().(type) {
	case *syntrav1.RpcResult_Payload:
		out := make([]byte, len(outcome.Payload))
		copy(out, outcome.Payload)
		return out, nil
	case *syntrav1.RpcResult_Error:
		if outcome.Error == nil {
			return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: result missing outcome")
		}
		return nil, RpcErrorFromWire(outcome.Error)
	default:
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: result missing outcome")
	}
}

// mapContextErr converts a context error to the Syntra code that owns the
// outcome: cancellation is CANCELLED, expiry is DEADLINE_EXCEEDED.
func mapContextErr(err error) *RpcError {
	if errors.Is(err, context.DeadlineExceeded) {
		return NewRpcError(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded")
	}
	return NewRpcError(ErrorCodeCancelled, "syntra: call cancelled")
}

// Close deterministically releases the session: in-flight calls complete
// with UNAVAILABLE, the notification stream closes, and the core is
// destroyed exactly once. A second Close reports FailedPrecondition so
// double-close bugs surface instead of passing. Close also closes the owned
// Transport, interrupting pending reads and writes.
func (c *Client) Close() error {
	if c == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil client")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: client already closed")
	}
	c.closed = true
	c.cfg.credential = nil
	t := c.transportOwner
	c.failWaitersLocked(ErrorCodeUnavailable, "syntra: client closed")
	close(c.done)
	if !c.pumpStarted {
		close(c.notifyCh)
	}
	c.mu.Unlock()
	if t != nil {
		_ = t.Close()
	}
	return c.closeCore()
}

// resolvedHostConfig is a HostConfig with defaults applied.
type resolvedHostConfig struct {
	minVersion    uint32
	maxVersion    uint32
	policy        CredentialPolicy
	channelPolicy ChannelPolicy
	handler       HandlerFunc
	authorize     AuthorizeFunc
	timeout       time.Duration
	maxPending    int
	writeTimeout  time.Duration
}

// HostConfig configures a Host session factory. Each Serve call opens one
// independent per-connection core from this config.
type HostConfig struct {
	// MinVersion/MaxVersion bound the accepted handshake range. Zero
	// selects the binding singleton (v1).
	MinVersion uint32
	// MaxVersion is the highest version the host emits.
	MaxVersion uint32
	// Policy verifies hello credentials and returns the principal to
	// bind when ChannelPolicy is unset. Nil denies these handshakes as
	// Unauthenticated.
	Policy CredentialPolicy
	// ChannelPolicy verifies a freshly confirmed transport channel identity and
	// hello credential. When set, it replaces Policy and requires a confirmed
	// ChannelIdentityProvider. It must return a nonempty principal.
	ChannelPolicy ChannelPolicy
	// Handler dispatches authorized, validated requests. Nil answers authorized
	// requests UNIMPLEMENTED (no method is known).
	Handler HandlerFunc
	// Authorize is the per-method policy evaluated with the bound principal
	// before handler effects. Nil selects DenyAllAuthorize.
	Authorize AuthorizeFunc
	// DefaultTimeout applies when a request passes timeoutMs zero. Zero
	// selects DefaultRPCTimeout. Negative or above MaxRPCTimeoutMs fails fast.
	// The value is rounded up to whole milliseconds at resolution so the
	// pure-Go and native backends enforce the identical deadline.
	DefaultTimeout time.Duration
	// MaxConcurrent caps outstanding calls per connection. Zero selects
	// MaxConcurrentRPCs. Values above MaxHostConcurrentRPCs fail fast as
	// OutOfRange. Excess calls fail with ResourceExhausted while
	// the connection stays usable.
	MaxConcurrent int
	// WriteTimeout bounds each post-handshake transport Send. Zero selects
	// five seconds. A failed or timed-out write terminates the connection.
	// One writer sends FIFO snapshots independently of the session loop.
	// Queued plus active writes are capped at 256 frames and 8 MiB per
	// connection; saturation terminates Serve with RESOURCE_EXHAUSTED.
	// Transports must honor their contexts and interrupt I/O on Close.
	WriteTimeout time.Duration
}

func resolveHostConfig(cfg HostConfig) (resolvedHostConfig, error) {
	out := resolvedHostConfig{
		minVersion:    cfg.MinVersion,
		maxVersion:    cfg.MaxVersion,
		policy:        cfg.Policy,
		channelPolicy: cfg.ChannelPolicy,
		handler:       cfg.Handler,
		authorize:     cfg.Authorize,
		timeout:       cfg.DefaultTimeout,
		maxPending:    cfg.MaxConcurrent,
		writeTimeout:  cfg.WriteTimeout,
	}
	if out.authorize == nil {
		out.authorize = DenyAllAuthorize
	}
	if out.writeTimeout == 0 {
		out.writeTimeout = 5 * time.Second
	}
	if out.writeTimeout < 0 {
		return resolvedHostConfig{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: host write timeout must be positive")
	}
	if out.minVersion == 0 {
		out.minVersion = MinSupportedVersion
	}
	if out.maxVersion == 0 {
		out.maxVersion = MaxSupportedVersion
	}
	if out.minVersion > out.maxVersion {
		return resolvedHostConfig{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: host min_version exceeds max_version")
	}
	if out.timeout == 0 {
		out.timeout = DefaultRPCTimeout
	}
	if out.timeout <= 0 {
		return resolvedHostConfig{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: host default timeout must be positive")
	}
	if out.timeout > time.Duration(MaxRPCTimeoutMs)*time.Millisecond {
		return resolvedHostConfig{}, NewRpcError(ErrorCodeOutOfRange, "syntra: host default timeout exceeds max")
	}
	// Normalize once so both backends share the identical deadline: whole
	// milliseconds, rounded up, never shorter than configured.
	out.timeout = time.Duration(roundUpToMs(out.timeout)) * time.Millisecond
	if out.maxPending == 0 {
		out.maxPending = MaxConcurrentRPCs
	}
	if out.maxPending < 1 {
		return resolvedHostConfig{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: host max concurrent must be positive")
	}
	if out.maxPending > MaxHostConcurrentRPCs {
		return resolvedHostConfig{}, NewRpcError(ErrorCodeOutOfRange, "syntra: host max concurrent exceeds max")
	}
	return out, nil
}

// Host is a responder-side Syntra session factory. The zero value is
// invalid; construct with OpenHost. A Host is safe for concurrent Serve
// calls (one per connection) and NotifyAll broadcasts.
type Host struct {
	cfg resolvedHostConfig

	mu     sync.Mutex
	conns  map[*hostConn]struct{}
	closed bool
}

// hostConn tracks one served connection for broadcast and teardown.
// wake signals the serve pump that queued outbound frames (expiry
// results, broadcasts) are ready even when no inbound frame arrived.
type hostConn struct {
	core      hostCore
	cancels   map[uint64]*callCancel
	wake      chan struct{}
	stop      context.CancelFunc // registered before Close can observe this connection
	completed chan *callCancel   // bounded by maxPending, including abandoned workers
	workers   int                // Serve-owned; released only when the callback actually returns
	principal string             // bound at handshake; used by Authorize before handler effects
	version   uint32             // negotiated once during handshake
	transport Transport          // owned by Serve; Close interrupts I/O
	writer    *hostWriter        // created after ready; only Serve admits frames
}

const (
	hostWriterMaxFrames = 256
	hostWriterMaxBytes  = 8 << 20
	hostWriterDrainTime = 200 * time.Millisecond
	hostWriterJoinTime  = time.Second
)

// hostWriter is the sole post-handshake sender. enqueue snapshots serialized
// bytes, so even a core returning borrowed storage cannot change a queued frame.
// Admission is nonblocking and FIFO. count/bytes include the active Send until
// it returns; a nil enqueue error means admission, never delivery to the peer.
type hostWriter struct {
	transport Transport
	timeout   time.Duration
	ctx       context.Context
	stop      context.CancelFunc
	frames    chan []byte
	fatal     chan error
	done      chan struct{}

	mu        sync.Mutex
	accepting bool
	count     int
	bytes     int
	failure   error
	idle      chan struct{} // closed only when every admitted Send has finished
}

func newHostWriter(t Transport, timeout time.Duration) *hostWriter {
	ctx, stop := context.WithCancel(context.Background())
	idle := make(chan struct{})
	close(idle)
	w := &hostWriter{
		transport: t, timeout: timeout, ctx: ctx, stop: stop,
		frames: make(chan []byte, hostWriterMaxFrames), fatal: make(chan error, 1),
		done: make(chan struct{}), accepting: true, idle: idle,
	}
	go w.run()
	return w
}

// failLocked publishes at most one fatal error; callers hold mu.
func (w *hostWriter) failLocked(err error) {
	if w.failure == nil {
		w.failure = err
		w.accepting = false
		w.fatal <- err
	}
}

func (w *hostWriter) enqueue(frame []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failure != nil {
		return w.failure
	}
	if !w.accepting {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host writer admission closed")
	}
	if w.count >= hostWriterMaxFrames || len(frame) > hostWriterMaxBytes-w.bytes {
		err := NewRpcError(ErrorCodeResourceExhausted, "syntra: host write backlog full")
		w.failLocked(err)
		return err
	}
	if w.count == 0 {
		w.idle = make(chan struct{})
	}
	owned := make([]byte, len(frame))
	copy(owned, frame)
	w.count++
	w.bytes += len(owned)
	w.frames <- owned // count includes the active write, so this cannot block
	return nil
}

func (w *hostWriter) err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failure
}

func (w *hostWriter) run() {
	defer close(w.done)
	defer func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		w.accepting = false
		for len(w.frames) > 0 {
			<-w.frames // release unsent snapshots on any terminal path
		}
		if w.count > 0 {
			w.count, w.bytes = 0, 0
			close(w.idle)
		}
	}()
	for {
		select {
		case <-w.ctx.Done():
			return
		case frame := <-w.frames:
			if w.ctx.Err() != nil || w.err() != nil {
				return
			}
			ctx, stop := context.WithTimeout(w.ctx, w.timeout)
			err := w.transport.Send(ctx, frame)
			stop()
			w.mu.Lock()
			if err != nil && w.ctx.Err() == nil {
				w.failLocked(NewRpcError(ErrorCodeUnavailable, fmt.Sprintf("syntra: send: %v", err)))
			}
			w.count--
			w.bytes -= len(frame)
			if w.count == 0 {
				close(w.idle)
			}
			w.mu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

// drain seals admission and waits for actual Send completions, including the
// active write. It is used only on terminal paths, after cancelling callbacks.
func (w *hostWriter) drain(ctx context.Context) error {
	w.mu.Lock()
	w.accepting = false
	idle := w.idle
	w.mu.Unlock()
	select {
	case <-idle:
		if err := w.err(); err != nil {
			return err
		}
		if w.ctx.Err() != nil {
			return NewRpcError(ErrorCodeUnavailable, "syntra: host writer stopped before drain")
		}
		return nil
	case <-w.fatal:
		return w.err()
	case <-ctx.Done():
		return NewRpcError(ErrorCodeUnavailable, "syntra: host write drain incomplete")
	}
}

// shutdown cancels Send, closes the owned transport, and joins the sole writer.
// The join has a hard bound for transports violating the cancellation/Close
// contract; conforming transports leave no writer goroutine behind.
func (w *hostWriter) shutdown() error {
	w.mu.Lock()
	w.accepting = false
	w.mu.Unlock()
	w.stop()
	_ = w.transport.Close()
	timer := time.NewTimer(hostWriterJoinTime)
	defer timer.Stop()
	select {
	case <-w.done:
		return nil
	case <-timer.C:
		return NewRpcError(ErrorCodeUnavailable, "syntra: host writer did not stop")
	}
}

// callCancel is the abandon handle for one in-flight handler. It is a
// pointer so dispatch completion can tell its own entry apart from a
// newer entry reusing the same request ID (functions are not comparable
// in Go; pointers are).
type callCancel struct {
	stop        context.CancelFunc
	id          uint64
	result      chan *RpcResult // one completion; publish before notifying Serve
	completedAt time.Time       // guarded by Host.mu; recorded at completion publication
	// authRevoked marks an Authorize Unauthenticated denial (expired/revoked
	// bound principal). Serve cancels other callbacks and attempts a bounded
	// drain of the per-RPC UNAUTHENTICATED error, then terminates per
	// SNTR-AUTH-008/SNTR-ASEC-006. PermissionDenied denials keep the
	// connection usable per SNTR-AUTH-009.
	authRevoked bool
}

// OpenHost creates a responder session factory. It validates the config
// and opens nothing per connection yet; each Serve call opens and closes
// exactly one core.
func OpenHost(cfg HostConfig) (*Host, error) {
	rcfg, err := resolveHostConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Host{cfg: rcfg, conns: make(map[*hostConn]struct{})}, nil
}

// Serve runs one connection on t: exactly one ClientHello first, exactly
// one terminal handshake outcome (ServerReady or handshake error +
// close), then validated dispatch until ctx ends, the transport fails, a
// fatal protocol violation arrives, or the Host closes. Unknown methods
// answer UNIMPLEMENTED; handler failures answer their mapped code; the
// connection stays usable. When HostConfig.Authorize is set it is checked
// with the bound principal before handler effects on every call; denials
// answer generic Unauthenticated/PermissionDenied. PermissionDenied keeps
// the connection usable; Unauthenticated (expired/revoked binding) cancels
// callbacks, attempts a bounded drain of the per-RPC error, then closes per
// SNTR-AUTH-008/SNTR-ASEC-006. A nil Authorize denies every method. ctx
// end cancels in-flight handlers and closes the connection. Serve returns
// nil on a clean handshake-completed close and the fatal error otherwise.
// The entire handshake, including Policy, has a five-second deadline
// shortened by ctx. Policy and Transport must honor their contexts.
// Serve owns t and closes it on every terminal path.
// Transport.Recv MUST return promptly when its context ends; teardown
// waits at most handlerShutdownGrace for a violating Recv before
// abandoning the pump (the leaked Recv goroutine exits when Recv finally
// returns). On teardown Serve cancels callbacks and drains completions
// for up to one second; callbacks that ignore cancellation cannot send a
// late result or access the closed connection core.
func (h *Host) Serve(ctx context.Context, t Transport) error {
	if h == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil host")
	}
	if t == nil {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil transport")
	}
	t = &ownedTransport{Transport: t}
	defer t.Close()
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	h.mu.Unlock()

	core, err := newHostCore(h.cfg)
	if err != nil {
		return err
	}
	serveCtx, stop := context.WithCancel(ctx)
	defer stop()
	hc := &hostConn{
		core: core, cancels: make(map[uint64]*callCancel), wake: make(chan struct{}, 1),
		stop: stop, completed: make(chan *callCancel, h.cfg.maxPending),
		transport: t,
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = core.close()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	h.conns[hc] = struct{}{}
	h.mu.Unlock()
	defer func() {
		stop()
		_ = t.Close()
		h.cancelHandlers(hc, nil, true)
		h.drainHandlers(hc)
		h.mu.Lock()
		delete(h.conns, hc)
		h.mu.Unlock()
		_ = core.close()
	}()

	if err := h.serveHandshake(serveCtx, t, hc); err != nil {
		return err
	}
	return h.serveLoop(serveCtx, t, hc)
}

// serveHandshake runs the hello/policy/ready exchange.
func (h *Host) serveHandshake(ctx context.Context, t Transport, hc *hostConn) error {
	ctx, stop := context.WithTimeout(ctx, sessionHandshakeTimeout)
	defer stop()
	raw, err := t.Recv(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return NewRpcError(ErrorCodeUnavailable, fmt.Sprintf("syntra: handshake recv: %v", err))
	}
	hello, uerr := unmarshalSessionFrame(raw)
	if uerr != nil {
		return uerr
	}
	if BodyKindOf(hello) != BodyKindHello {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: first frame must be hello")
	}
	if _, err := NegotiateVersionRanges(hello.GetHello().GetMinVersion(), hello.GetHello().GetMaxVersion(), h.cfg.minVersion, h.cfg.maxVersion); err != nil {
		return err
	}
	version, herr := hc.core.acceptHello(raw)
	if herr != nil {
		return herr
	}
	hc.version = version
	var principal string
	var perr error
	if h.cfg.channelPolicy != nil {
		provider, ok := t.(ChannelIdentityProvider)
		if !ok {
			return NewRpcError(ErrorCodeUnauthenticated, "syntra: confirmed channel required")
		}
		identity, confirmed := provider.ChannelIdentity()
		if !confirmed {
			return NewRpcError(ErrorCodeUnauthenticated, "syntra: confirmed channel required")
		}
		principal, perr = h.cfg.channelPolicy(ctx, identity, hello.GetHello().GetCredential())
	} else {
		if h.cfg.policy == nil {
			return NewRpcError(ErrorCodeUnauthenticated, "syntra: no credential policy configured")
		}
		principal, perr = h.cfg.policy(ctx, hello.GetHello().GetCredential())
	}
	hello = nil
	raw = nil
	if err := ctx.Err(); err != nil {
		return err
	}
	if perr != nil {
		var rerr *RpcError
		if errors.As(perr, &rerr) {
			return rerr
		}
		return NewRpcError(ErrorCodeInternal, "syntra: credential policy failed")
	}
	if principal == "" {
		return NewRpcError(ErrorCodeUnauthenticated, "syntra: credential not accepted")
	}
	readyFrame, aerr := hc.core.authComplete(principal)
	if aerr != nil {
		return aerr
	}
	h.mu.Lock()
	hc.principal = principal
	h.mu.Unlock()
	if serr := t.Send(ctx, readyFrame); serr != nil {
		if errors.Is(serr, context.Canceled) || errors.Is(serr, context.DeadlineExceeded) {
			return serr
		}
		return NewRpcError(ErrorCodeUnavailable, fmt.Sprintf("syntra: handshake send: %v", serr))
	}
	return nil
}

// serveLoop dispatches validated requests to the handler and streams
// terminal results and notifications until the connection ends. Queued
// outbound frames that arise without inbound traffic (expiry results,
// broadcasts) are flushed on the wake signal and on a reap tick, so a
// silent peer still observes budgets and broadcasts.
func (h *Host) serveLoop(ctx context.Context, t Transport, hc *hostConn) (serveErr error) {
	writer := newHostWriter(t, h.cfg.writeTimeout)
	hc.writer = writer
	pumpCtx, pumpStop := context.WithCancel(ctx)
	var recvDone chan struct{}
	defer func() {
		if ctx.Err() != nil && serveErr == nil {
			h.gracefulDrain(ctx, t, hc)
		}
		hc.stop()
		h.cancelHandlers(hc, nil, true)
		pumpStop()
		if err := writer.shutdown(); serveErr == nil && err != nil {
			serveErr = err
		}
		if recvDone != nil {
			// Close and cancellation release conforming readers immediately.
			// Bound the join for readers that violate their context contract.
			select {
			case <-recvDone:
			case <-time.After(handlerShutdownGrace):
			}
		}
	}()
	if err := h.flush(ctx, t, hc); err != nil {
		return err
	}
	recvCh := make(chan recvResult, 1)
	recvDone = make(chan struct{})
	go func() {
		defer close(recvDone)
		for {
			raw, err := t.Recv(pumpCtx)
			select {
			case recvCh <- recvResult{raw: raw, err: err}:
			case <-pumpCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	ticker := time.NewTicker(pumpTick)
	defer ticker.Stop()
	for {
		if ctx.Err() == nil {
			if err := writer.err(); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-writer.fatal:
			if ctx.Err() != nil {
				return nil
			}
			return err
		case cc := <-hc.completed:
			hc.workers--
			if err := h.finishReadyHandler(ctx, t, hc, cc); err != nil {
				return err
			}
		case <-hc.wake:
			if err := h.flush(ctx, t, hc); err != nil {
				h.cancelHandlers(hc, nil, true)
				return err
			}
		case <-ticker.C:
			h.reapHandlers(ctx, hc)
			if err := h.flush(ctx, t, hc); err != nil {
				h.cancelHandlers(hc, nil, true)
				return err
			}
		case r := <-recvCh:
			if r.err != nil {
				h.cancelHandlers(hc, nil, true)
				if ctx.Err() != nil || errors.Is(r.err, context.Canceled) || errors.Is(r.err, context.DeadlineExceeded) {
					return nil
				}
				var rerr *RpcError
				if errors.As(r.err, &rerr) {
					return r.err
				}
				if errors.Is(r.err, io.EOF) {
					return nil
				}
				return NewRpcError(ErrorCodeUnavailable, fmt.Sprintf("syntra: recv: %v", r.err))
			}
			if err := validateActiveSessionFrame(r.raw, hc.version); err != nil {
				return err
			}
			responses, cancelIDs, fatal := hc.core.onFrame(r.raw)
			if fatal != nil {
				h.cancelHandlers(hc, nil, true)
				return fatal
			}
			for _, id := range cancelIDs {
				if err := h.cancelHandler(ctx, t, hc, id); err != nil {
					return err
				}
			}
			for _, resp := range responses {
				if serr := writer.enqueue(resp); serr != nil {
					h.cancelHandlers(hc, nil, true)
					if ctx.Err() != nil {
						return nil
					}
					return serr
				}
			}
			for {
				id, req, ok := hc.core.takePending()
				if !ok {
					break
				}
				if err := h.dispatch(ctx, t, hc, id, req); err != nil {
					return err
				}
			}
			h.reapHandlers(ctx, hc)
			if err := h.flush(ctx, t, hc); err != nil {
				h.cancelHandlers(hc, nil, true)
				return err
			}
		}
	}
}

// validHandlerResult accepts either validated terminal outcome.
func validHandlerResult(res *RpcResult) bool {
	return res != nil && ValidateResult(res) == nil
}

// validSuccess reports whether res carries a validated success payload.
func validSuccess(res *RpcResult) bool {
	if !validHandlerResult(res) {
		return false
	}
	_, ok := res.GetOutcome().(*syntrav1.RpcResult_Payload)
	return ok
}

// dispatch runs at most maxPending callbacks per connection, including
// callbacks still running after a terminal cancel/deadline. Only Serve
// touches the core or admits result frames; workers publish one bounded completion.
func (h *Host) dispatch(ctx context.Context, t Transport, hc *hostConn, id uint64, req *RpcRequest) error {
	// Consume available completions before rejecting a new worker. A
	// cancelled, non-cooperative callback does NOT free a worker slot.
drain:
	for {
		select {
		case cc := <-hc.completed:
			hc.workers--
			if err := h.finishReadyHandler(ctx, t, hc, cc); err != nil {
				return err
			}
		default:
			break drain
		}
	}
	if hc.workers >= h.cfg.maxPending {
		return h.answer(ctx, t, hc, id, NewWireErrorResult(ErrorCodeResourceExhausted, "syntra: too many running handlers"))
	}
	budget := h.cfg.timeout
	if req.GetTimeoutMs() > 0 {
		budget = time.Duration(req.GetTimeoutMs()) * time.Millisecond
	}
	hctx, stop := context.WithTimeout(ctx, budget)
	cc := &callCancel{stop: stop, id: id, result: make(chan *RpcResult, 1)}
	h.mu.Lock()
	hc.cancels[id] = cc
	h.mu.Unlock()
	hc.workers++
	authorize := h.cfg.authorize
	principal := hc.principal
	method := req.GetMethod()
	go func() {
		handler := h.cfg.handler
		var out *RpcResult
		if authorize != nil {
			if aerr := authorize(hctx, principal, method); aerr != nil {
				if hctx.Err() != nil {
					out = NewWireErrorResult(mapContextErr(hctx.Err()).Code, "syntra: handler context ended")
				} else {
					var rerr *RpcError
					if errors.As(aerr, &rerr) && rerr.Code == ErrorCodeUnauthenticated {
						out = NewWireErrorResult(ErrorCodeUnauthenticated, "syntra: credential not accepted")
						// Expired/revoked bound principal: binding is
						// withdrawn. Send the per-RPC UNAUTHENTICATED
						// first; finishReadyHandler closes afterwards.
						cc.authRevoked = true
					} else {
						// Generic deny without oracle: policy internals
						// never reach the wire (SNTR-ERR-003), mirroring
						// the Rust Host sanitization.
						out = NewWireErrorResult(ErrorCodePermissionDenied, "syntra: access denied")
					}
				}
			}
		}
		// Authorizers may return nil after cancellation. Never start handler
		// effects on a context already cancelled by revocation or teardown.
		if out == nil && hctx.Err() != nil {
			out = NewWireErrorResult(mapContextErr(hctx.Err()).Code, "syntra: handler context ended")
		}
		if out == nil {
			if handler == nil {
				out = NewWireErrorResult(ErrorCodeUnimplemented, "syntra: unknown method")
			} else {
				res, herr := handler(hctx, req)
				switch {
				case hctx.Err() != nil && !validHandlerResult(res):
					out = NewWireErrorResult(mapContextErr(hctx.Err()).Code, "syntra: handler context ended")
				case herr != nil:
					var rerr *RpcError
					if errors.As(herr, &rerr) {
						out = NewWireErrorResult(rerr.Code, rerr.Message)
					} else {
						out = NewWireErrorResult(ErrorCodeInternal, "syntra: internal error")
					}
				case validHandlerResult(res):
					out = res
				default:
					out = NewWireErrorResult(ErrorCodeInternal, "syntra: internal error")
				}
			}
		}
		h.mu.Lock()
		cc.completedAt = time.Now()
		cc.result <- out
		h.mu.Unlock()
		stop()
		// Capacity covers ALL admitted callbacks, even if Serve has
		// finished its bounded shutdown drain. This never blocks a late
		// worker or lets it access a destroyed core or closed transport.
		hc.completed <- cc
	}()
	return nil
}

// finishReadyHandler commits a published completion only while this exact
// callback still owns its ID. Late callbacks cannot answer a reused ID.
// An Authorize Unauthenticated completion cancels other callbacks before a
// bounded drain of the queued denial. Successful drain returns Unauthenticated;
// incomplete/failed writes return their error. Serve closes either way.
func (h *Host) finishReadyHandler(ctx context.Context, t Transport, hc *hostConn, cc *callCancel) error {
	h.mu.Lock()
	current := hc.cancels[cc.id] == cc
	if current && !cc.completedAt.IsZero() {
		if timed, ok := hc.core.(completionRecorder); ok {
			timed.recordCompletion(cc.id, cc.completedAt)
		}
	}
	h.mu.Unlock()
	if !current {
		return nil
	}
	select {
	case out := <-cc.result:
		h.mu.Lock()
		delete(hc.cancels, cc.id)
		h.mu.Unlock()
		cc.stop()
		if cc.authRevoked {
			h.cancelHandlers(hc, nil, true)
		}
		if err := h.answer(ctx, t, hc, cc.id, out); err != nil {
			return err
		}
		if cc.authRevoked {
			drainCtx, stop := context.WithTimeout(ctx, hostWriterDrainTime)
			defer stop()
			if err := hc.writer.drain(drainCtx); err != nil {
				return err
			}
			return NewRpcError(ErrorCodeUnauthenticated, "syntra: credential revoked")
		}
		return nil
	default:
		return nil
	}
}

func (h *Host) answer(ctx context.Context, t Transport, hc *hostConn, id uint64, out *RpcResult) error {
	frame, expired, err := hc.core.answer(id, out)
	if err != nil {
		var rerr *RpcError
		if errors.As(err, &rerr) && rerr.Code == ErrorCodeResourceExhausted {
			bounded := NewWireErrorResult(ErrorCodeResourceExhausted, "syntra: result exceeds bound")
			frame2, expired2, err2 := hc.core.answer(id, bounded)
			if err2 != nil {
				return err2
			}
			if !expired2 && len(frame2) > 0 {
				if serr := hc.writer.enqueue(frame2); serr != nil {
					return serr
				}
			}
			return h.flush(ctx, t, hc)
		}
		return err
	}
	if !expired && len(frame) > 0 {
		if err := hc.writer.enqueue(frame); err != nil {
			return err
		}
	}
	return h.flush(ctx, t, hc)
}

// flush moves core frames into the bounded FIFO writer without waiting for I/O.
func (h *Host) flush(ctx context.Context, t Transport, hc *hostConn) error {
	for {
		frame, ok := hc.core.nextOutbound()
		if !ok {
			return nil
		}
		if len(frame) == 0 {
			continue
		}
		if err := hc.writer.enqueue(frame); err != nil {
			return err
		}
	}
}

// completionRecorder preserves callback completion time in cores that support
// it. The native v1 ABI has no timestamp input; it arbitrates at answer time.
type completionRecorder interface {
	recordCompletion(uint64, time.Time)
}

// reapHandlers abandons expired handlers after preserving published completions.
func (h *Host) reapHandlers(_ context.Context, hc *hostConn) {
	// Publication and reaping share a lock, so a completion published before
	// this expiry decision cannot be discarded by a randomly selected tick.
	h.mu.Lock()
	if timed, ok := hc.core.(completionRecorder); ok {
		for id, cc := range hc.cancels {
			if !cc.completedAt.IsZero() {
				timed.recordCompletion(id, cc.completedAt)
			}
		}
	}
	expired := hc.core.reapExpired(time.Now())
	h.mu.Unlock()
	h.cancelHandlers(hc, expired, false)
}

// cancelHandler commits CANCELLED without waiting for host code to
// cooperate. A completion already published at this decision wins.
func (h *Host) cancelHandler(ctx context.Context, t Transport, hc *hostConn, id uint64) error {
	h.mu.Lock()
	cc, ok := hc.cancels[id]
	h.mu.Unlock()
	if !ok {
		return nil
	}
	if err := h.finishReadyHandler(ctx, t, hc, cc); err != nil {
		return err
	}
	h.mu.Lock()
	current := hc.cancels[id] == cc
	delete(hc.cancels, id)
	h.mu.Unlock()
	if !current {
		return nil
	}
	cc.stop()
	return h.answer(ctx, t, hc, id, NewWireErrorResult(ErrorCodeCancelled, "syntra: cancelled"))
}

// drainHandlers joins cooperative callbacks without an unbounded wait on
// non-cooperative application code. Late completions fit in completed and
// cannot call into the core after Serve closes it.
func (h *Host) drainHandlers(hc *hostConn) {
	if hc.workers == 0 {
		return
	}
	timer := time.NewTimer(handlerShutdownGrace)
	defer timer.Stop()
	for hc.workers > 0 {
		select {
		case <-hc.completed:
			hc.workers--
		case <-timer.C:
			return
		}
	}
}

// cancelHandlers abandons handlers: exactly ids, or every in-flight
// handler when all is true. all exists because a nil ids slice is
// ambiguous (reapExpiry returns nil both when nothing expired and when
// the core is gone); callers MUST pass all=false for reap results.
func (h *Host) cancelHandlers(hc *hostConn, ids []uint64, all bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if all {
		for id, cc := range hc.cancels {
			cc.stop()
			delete(hc.cancels, id)
		}
		return
	}
	for _, id := range ids {
		if cc, ok := hc.cancels[id]; ok {
			cc.stop()
			delete(hc.cancels, id)
		}
	}
}

// NotifyDirected enqueues payload as a notification on exactly the served
// connections bound to principal. Connections bound to other principals
// never observe it (directed delivery isolation for recovery batches and
// per-stream signals). With no matching connections it is a documented
// no-op. Partial-delivery failures are combined and returned; RpcError
// values remain unwrappable via errors.As. Only connections with a
// successful enqueue are signaled. Recovery drivers MUST use this (or a
// subscription-handle-routed variant above it) instead of NotifyAll
// broadcast: broadcast leaks stream state across principals and breaks
// per-stream termination scope.
func (h *Host) NotifyDirected(principal string, payload []byte) error {
	if h == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil host")
	}
	if err := ValidatePayloadSize(len(payload)); err != nil {
		return err
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	var conns []*hostConn
	for hc := range h.conns {
		if hc.principal == principal {
			conns = append(conns, hc)
		}
	}
	h.mu.Unlock()
	var errs []error
	for _, hc := range conns {
		if err := hc.core.notify(payload); err != nil {
			errs = append(errs, err)
			continue
		}
		select {
		case hc.wake <- struct{}{}:
		default:
		}
	}
	return errors.Join(errs...)
}

// NotifyAll enqueues payload as a notification on every served
// connection. With no connections it is a documented no-op. Payloads
// MUST be opaque application bytes; empty is a valid empty event.
// Success acknowledges queue admission, not transport or peer delivery.
// Partial-delivery failures are combined and returned; RpcError values
// remain unwrappable via errors.As. Only connections with a successful
// enqueue are signaled.
func (h *Host) NotifyAll(payload []byte) error {
	if h == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil host")
	}
	if err := ValidatePayloadSize(len(payload)); err != nil {
		return err
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	conns := make([]*hostConn, 0, len(h.conns))
	for hc := range h.conns {
		conns = append(conns, hc)
	}
	h.mu.Unlock()
	var errs []error
	for _, hc := range conns {
		if err := hc.core.notify(payload); err != nil {
			errs = append(errs, err)
			continue
		}
		select {
		case hc.wake <- struct{}{}:
		default:
		}
	}
	return errors.Join(errs...)
}

// gracefulDrain cancels callbacks and makes a bounded best-effort attempt to
// send queued frames. A clean Serve shutdown does not acknowledge their delivery.
// Host.Close/DisconnectPrincipal may already have closed the transport.
func (h *Host) gracefulDrain(ctx context.Context, t Transport, hc *hostConn) {
	_ = ctx
	drainCtx, drainStop := context.WithTimeout(context.Background(), hostWriterDrainTime)
	defer drainStop()
	h.cancelHandlers(hc, nil, true)
	if h.flush(drainCtx, t, hc) == nil {
		_ = hc.writer.drain(drainCtx)
	}
}

// Close releases the factory: new Serve calls fail fast and served
// connections are closed and their handlers observe ctx cancellation. A second
// Close reports FailedPrecondition. Close signals shutdown without waiting;
// callers join their Serve calls to await the bounded callback drain.
func (h *Host) Close() error {
	if h == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil host")
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host already closed")
	}
	h.closed = true
	var transports []Transport
	for hc := range h.conns {
		hc.stop()
		transports = append(transports, hc.transport)
	}
	h.mu.Unlock()
	for _, t := range transports {
		_ = t.Close()
	}
	return nil
}

// DisconnectPrincipal cancels and closes every current connection bound to
// principal, including idle connections that only receive pushes. It does not
// prevent future authentication; the authentication policy must reject revoked
// identities. An empty principal matches no connection.
func (h *Host) DisconnectPrincipal(principal string) error {
	if h == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil host")
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	var transports []Transport
	if principal != "" {
		for hc := range h.conns {
			if hc.principal == principal {
				hc.stop()
				transports = append(transports, hc.transport)
			}
		}
	}
	h.mu.Unlock()
	for _, t := range transports {
		_ = t.Close()
	}
	return nil
}
