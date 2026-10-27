// Session machines for Syntra v1 Go servers: transport-agnostic Client
// (initiator) and Host (responder) built on the validation and codec
// primitives in syntra.go.
//
// A Transport carries exactly one serialized Frame per Send/Recv call in
// each direction. This binding does not dial TCP/TLS or WebSocket: the
// host application owns the socket and plugs it in here (length-prefix,
// binary-message, and close-code bindings per specifications/transports).
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
)

// Transport carries serialized Syntra Frames. Each Send transmits exactly
// one Frame toward the peer; each Recv returns exactly one inbound Frame.
// Implementations MUST preserve frame boundaries and MUST NOT batch
// multiple Frames into one Send payload. The session layer validates
// sizes and contents; transports MUST still bound allocation on receive.
type Transport interface {
	// Send transmits one serialized Frame. It MUST copy frame if it
	// retains it.
	Send(ctx context.Context, frame []byte) error
	// Recv returns the next inbound serialized Frame. It returns an
	// error when the transport is closed and drained or ctx ends.
	Recv(ctx context.Context) ([]byte, error)
	// Close releases the transport. It is idempotent.
	Close() error
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

// AuthorizeFunc is the optional host-owned per-method policy, evaluated
// for every RPC using the connection's bound principal, before handler
// effects. Implementations must be nonblocking and may re-check
// expiry/revocation here. A nil Authorize preserves the legacy
// allow-everything behavior for backward compatibility; set it explicitly
// for parity with the Rust Host, whose Handler::authorize default is
// fail-closed deny. Divergence tracking: nil (Go allow) vs default-deny
// (Rust) is intentional until callers opt into an explicit policy; pass
// DenyAllAuthorize to match the Rust default, or a principal-aware func
// to allow selected methods. Only generic Unauthenticated
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

// AllowAllAuthorize documents an explicit opt-in to the legacy permissive
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
	// invalid config (empty version range, oversize credential).
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
	f, err := UnmarshalFrame(frame)
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
		return nil, NewRpcError(ErrorCodeUnimplemented, "syntra: server selected version outside proposed range")
	}
	if err := ValidateReady(f.GetReady()); err != nil {
		return nil, err
	}
	return &activatedReady{ready: f.GetReady(), frameVersion: v}, nil
}

// decodeResultFrame validates owned result-frame bytes from a core into
// the terminal RpcResult. Unknown wire error codes normalize to UNKNOWN
// (SNTR-ERR-005); a missing outcome is INVALID_ARGUMENT, never success.
func decodeResultFrame(raw []byte) (*RpcResult, error) {
	f, err := UnmarshalFrame(raw)
	if err != nil {
		return nil, err
	}
	if BodyKindOf(f) != BodyKindResult {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: expected result frame")
	}
	res := f.GetResult()
	if err := ValidateResult(res); err != nil {
		return nil, err
	}
	return res, nil
}

// decodeNotificationFrame validates owned notification-frame bytes from
// a core into the event payload.
func decodeNotificationFrame(raw []byte) (*Notification, error) {
	f, err := UnmarshalFrame(raw)
	if err != nil {
		return nil, err
	}
	if BodyKindOf(f) != BodyKindNotification {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: expected notification frame")
	}
	if f.GetNotification() == nil {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: nil notification")
	}
	return f.GetNotification(), nil
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
		credential:   cfg.Credential,
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
	if err := ValidateCredentialSize(out.credential); err != nil {
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
	if err != nil {
		return nil, err
	}
	if err := t.Send(ctx, hello); err != nil {
		return nil, err
	}
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
// the pump. The handshake has a five-second deadline, shortened by ctx;
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
	c.transport = t
	c.mu.Unlock()

	// Close also interrupts a handshake blocked in transport I/O.
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		select {
		case <-c.done:
			stop()
		case <-runCtx.Done():
		}
	}()
	defer func() {
		c.mu.Lock()
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
		return err
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
	pumpCtx, pumpStop := context.WithCancel(context.Background())
	defer pumpStop()
	go func() {
		select {
		case <-ctx.Done():
			pumpStop()
		case <-c.done:
			pumpStop()
		}
	}()
	recvCh := make(chan recvResult, 1)
	go func() {
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
// double-close bugs surface instead of passing. Close does not close the
// Transport; its owner retains that.
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
	c.failWaitersLocked(ErrorCodeUnavailable, "syntra: client closed")
	close(c.done)
	if !c.pumpStarted {
		close(c.notifyCh)
	}
	c.mu.Unlock()
	return c.closeCore()
}

// resolvedHostConfig is a HostConfig with defaults applied.
type resolvedHostConfig struct {
	minVersion uint32
	maxVersion uint32
	policy     CredentialPolicy
	handler    HandlerFunc
	authorize  AuthorizeFunc
	timeout    time.Duration
	maxPending int
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
	// bind. Nil denies every handshake as Unauthenticated.
	Policy CredentialPolicy
	// Handler dispatches validated requests. Nil answers every request
	// UNIMPLEMENTED (no method is known).
	Handler HandlerFunc
	// Authorize is the optional per-method policy evaluated with the
	// bound principal before handler effects. Nil preserves the legacy
	// allow-everything behavior for backward compatibility and diverges
	// from the Rust Host fail-closed default; set DenyAllAuthorize to
	// match Rust, or a principal-aware func to allow selected methods.
	Authorize AuthorizeFunc
	// DefaultTimeout applies when a request passes timeoutMs zero. Zero
	// selects DefaultRPCTimeout. Negative or above MaxRPCTimeoutMs fails fast.
	// The value is rounded up to whole milliseconds at resolution so the
	// pure-Go and native backends enforce the identical deadline.
	DefaultTimeout time.Duration
	// MaxConcurrent caps outstanding calls per connection. Zero selects
	// MaxConcurrentRPCs. Excess calls fail with ResourceExhausted while
	// the connection stays usable.
	MaxConcurrent int
}

func resolveHostConfig(cfg HostConfig) (resolvedHostConfig, error) {
	out := resolvedHostConfig{
		minVersion: cfg.MinVersion,
		maxVersion: cfg.MaxVersion,
		policy:     cfg.Policy,
		handler:    cfg.Handler,
		authorize:  cfg.Authorize,
		timeout:    cfg.DefaultTimeout,
		maxPending: cfg.MaxConcurrent,
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
}

// callCancel is the abandon handle for one in-flight handler. It is a
// pointer so dispatch completion can tell its own entry apart from a
// newer entry reusing the same request ID (functions are not comparable
// in Go; pointers are).
type callCancel struct {
	stop   context.CancelFunc
	id     uint64
	result chan *RpcResult // one completion; publish before notifying Serve
	// authRevoked marks an Authorize Unauthenticated denial (expired/revoked
	// bound principal). The per-RPC UNAUTHENTICATED error is sent first,
	// then Serve terminates the connection per SNTR-AUTH-008/SNTR-ASEC-006
	// default-close. PermissionDenied denials never set this and keep the
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
// the connection usable; Unauthenticated (expired/revoked binding) sends
// the per-RPC error then closes the connection by default per
// SNTR-AUTH-008/SNTR-ASEC-006. A nil Authorize preserves the legacy allow-everything behavior
// (divergent from the Rust fail-closed default; see AuthorizeFunc). ctx
// end cancels in-flight handlers and closes the connection. Serve returns
// nil on a clean handshake-completed close and the fatal error otherwise.
// The entire handshake, including Policy, has a five-second deadline
// shortened by ctx. Policy and Transport must honor their contexts.
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
	version, herr := hc.core.acceptHello(raw)
	if herr != nil {
		return herr
	}
	_ = version
	hello, uerr := UnmarshalFrame(raw)
	if uerr != nil {
		return uerr
	}
	policy := h.cfg.policy
	if policy == nil {
		return NewRpcError(ErrorCodeUnauthenticated, "syntra: no credential policy configured")
	}
	principal, perr := policy(ctx, hello.GetHello().GetCredential())
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
	readyFrame, aerr := hc.core.authComplete(principal)
	if aerr != nil {
		return aerr
	}
	hc.principal = principal
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
func (h *Host) serveLoop(ctx context.Context, t Transport, hc *hostConn) error {
	if err := h.flush(ctx, t, hc); err != nil {
		return err
	}
	pumpCtx, pumpStop := context.WithCancel(ctx)
	recvCh := make(chan recvResult, 1)
	recvDone := make(chan struct{})
	defer func() {
		pumpStop()
		// Bound teardown: a conforming Transport.Recv returns promptly on
		// pumpCtx cancellation and this resolves immediately. A Recv that
		// violates its context contract must not hang Serve forever, so
		// wait at most the handler drain grace (1s, consistent with
		// handlerShutdownGrace) before abandoning the pump. The abandoned
		// Recv goroutine exits when Recv finally returns; it never touches
		// the closed core or caller transport afterwards.
		select {
		case <-recvDone:
		case <-time.After(handlerShutdownGrace):
		}
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
			h.gracefulDrain(ctx, t, hc)
			return nil
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
				if serr := t.Send(ctx, resp); serr != nil {
					h.cancelHandlers(hc, nil, true)
					if ctx.Err() != nil {
						return nil
					}
					return NewRpcError(ErrorCodeUnavailable, fmt.Sprintf("syntra: send: %v", serr))
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

// validSuccess reports whether res is a usable success outcome: valid
// and carrying a selected payload (empty counts; missing does not).
func validSuccess(res *RpcResult) bool {
	if res == nil || ValidateResult(res) != nil {
		return false
	}
	_, ok := res.GetOutcome().(*syntrav1.RpcResult_Payload)
	return ok
}

// dispatch runs at most maxPending callbacks per connection, including
// callbacks still running after a terminal cancel/deadline. Only Serve
// touches the core or sends results; workers publish one bounded completion.
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
		if out == nil {
			if handler == nil {
				out = NewWireErrorResult(ErrorCodeUnimplemented, "syntra: unknown method")
			} else {
				res, herr := handler(hctx, req)
				switch {
				case hctx.Err() != nil && !validSuccess(res):
					out = NewWireErrorResult(mapContextErr(hctx.Err()).Code, "syntra: handler context ended")
				case herr != nil:
					var rerr *RpcError
					if errors.As(herr, &rerr) {
						out = NewWireErrorResult(rerr.Code, rerr.Message)
					} else {
						out = NewWireErrorResult(ErrorCodeInternal, "syntra: internal error")
					}
				case validSuccess(res):
					out = res
				default:
					out = NewWireErrorResult(ErrorCodeInternal, "syntra: internal error")
				}
			}
		}
		cc.result <- out
		stop()
		// Capacity covers ALL admitted callbacks, even if Serve has
		// finished its bounded shutdown drain. This never blocks a late
		// worker or lets it access a destroyed core/caller-owned transport.
		hc.completed <- cc
	}()
	return nil
}

// finishReadyHandler commits a published completion only while this exact
// callback still owns its ID. Late callbacks cannot answer a reused ID.
// An Authorize Unauthenticated completion (expired/revoked binding) sends
// the per-RPC UNAUTHENTICATED error first, then returns a terminal
// Unauthenticated error so Serve closes the connection by default
// (SNTR-AUTH-008, SNTR-ASEC-006).
func (h *Host) finishReadyHandler(ctx context.Context, t Transport, hc *hostConn, cc *callCancel) error {
	h.mu.Lock()
	current := hc.cancels[cc.id] == cc
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
		if err := h.answer(ctx, t, hc, cc.id, out); err != nil {
			return err
		}
		if cc.authRevoked {
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
				if serr := t.Send(ctx, frame2); serr != nil {
					return hostSendError(ctx, serr)
				}
			}
			return h.flush(ctx, t, hc)
		}
		return err
	}
	if !expired && len(frame) > 0 {
		if err := t.Send(ctx, frame); err != nil {
			return hostSendError(ctx, err)
		}
	}
	return h.flush(ctx, t, hc)
}

// A transport-local cancellation/deadline is a failed write unless the
// connection's own context ended. Never swallow it and keep reading.
func hostSendError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return nil
	}
	return NewRpcError(ErrorCodeUnavailable, fmt.Sprintf("syntra: send: %v", err))
}

// flush drains queued outbound frames on the serve pump.
func (h *Host) flush(ctx context.Context, t Transport, hc *hostConn) error {
	for {
		frame, ok := hc.core.nextOutbound()
		if !ok {
			return nil
		}
		if len(frame) == 0 {
			continue
		}
		if err := t.Send(ctx, frame); err != nil {
			return hostSendError(ctx, err)
		}
	}
}

// reapHandlers abandons handlers whose budgets expired; the core already
// auto-enqueued their DEADLINE_EXCEEDED results.
func (h *Host) reapHandlers(_ context.Context, hc *hostConn) {
	expired := hc.core.reapExpired(time.Now())
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
// no-op. Recovery drivers MUST use this (or a subscription-handle-routed
// variant above it) instead of NotifyAll broadcast: broadcast leaks stream
// state across principals and breaks per-stream termination scope.
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
	for _, hc := range conns {
		_ = hc.core.notify(payload)
		select {
		case hc.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// NotifyAll enqueues payload as a notification on every served
// connection. With no connections it is a documented no-op. Payloads
// MUST be opaque application bytes; empty is a valid empty event.
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
	for _, hc := range conns {
		_ = hc.core.notify(payload)
		select {
		case hc.wake <- struct{}{}:
		default:
		}
	}
	return nil
}

// gracefulDrain implements SNTR-HS-006/013 draining for graceful close:
// flush already-queued outbound frames (terminal results, expiry results,
// broadcasts) before teardown, then abandon in-flight via cancelHandlers.
// Already-queued frames use a short bounded background context (the serve
// ctx is already done, so direct Send would fail instantly). Handler
// completion draining within the grace window stays in Serve's deferred
// drainHandlers (bounded by handlerShutdownGrace); this path must not add a
// second grace wait or Serve teardown would exceed its bound and existing
// close-interrupt tests would time out.
func (h *Host) gracefulDrain(ctx context.Context, t Transport, hc *hostConn) {
	_ = ctx
	drainCtx, drainStop := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer drainStop()
	_ = h.flush(drainCtx, t, hc)
	h.cancelHandlers(hc, nil, true)
	// One more best-effort flush for frames queued by reap during cancel.
	_ = h.flush(drainCtx, t, hc)
}

// Close releases the factory: new Serve calls fail fast and served
// connections are abandoned (their handlers observe ctx cancellation via
// the Serve ctx, and transports stay owned by their callers). A second
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
	for hc := range h.conns {
		hc.stop()
	}
	h.mu.Unlock()
	return nil
}
