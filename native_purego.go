//go:build !syntranative

package syntra

import (
	"errors"
	"sync"
	"time"
)

// Pure-Go core backend (default build).
//
// When the syntranative build tag is absent, sessions run on this
// in-process core built from the syntra.go primitives (Connection,
// Tracker, codec). This is the default Go session backend. NativeAvailable
// reports false in this configuration, and no CGO or native library is
// required to build, vet, or test the module. The syntranative adapter
// (native.go) provides the production Rust-backed alternative.

// NativeAvailable reports whether the process links the native
// libsyntra_ffi core. It is false in the default pure-Go build.
func NativeAvailable() bool { return false }

// CheckABI verifies the linked native core's C ABI version. With no
// native library linked there is nothing to check, so this returns nil.
func CheckABI() error { return nil }

// newClientCore opens a pure-Go initiator core.
func newClientCore(cfg resolvedClientConfig) (clientCore, error) {
	if cfg.minVersion == 0 || cfg.maxVersion == 0 || cfg.minVersion > cfg.maxVersion {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: client version range invalid")
	}
	return &goClientCore{
		cfg:      cfg,
		tracker:  NewTracker(),
		outcomes: make(map[uint64]*RpcResult),
		lossCh:   make(chan struct{}, 1),
	}, nil
}

// newHostCore opens a pure-Go responder core for one connection.
func newHostCore(cfg resolvedHostConfig) (hostCore, error) {
	if cfg.minVersion == 0 || cfg.maxVersion == 0 || cfg.minVersion > cfg.maxVersion {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: host version range invalid")
	}
	conn, err := NewConnection(HandshakeConfig{
		ServerMinVersion: cfg.minVersion,
		ServerMaxVersion: cfg.maxVersion,
	})
	if err != nil {
		return nil, err
	}
	return &goHostCore{
		cfg:         cfg,
		conn:        conn,
		outstanding: make(map[uint64]*hostCall),
	}, nil
}

// goClientCore is the pure-Go initiator core.
//
// Notification queue is bounded by cfg.notifyBuffer with cumulative loss
// accounting (unified with the async Rust and FFI cores): when full, the
// incoming (newest) notification drops and (dropped, droppedBytes) advance
// by exactly one drop plus its payload bytes. The queued prefix is
// preserved; there is no silent oldest-eviction. lossCh wakes loss
// waiters once per drop (non-blocking, no double-counting).
type goClientCore struct {
	mu            sync.Mutex
	cfg           resolvedClientConfig
	negotiated    uint32
	active        bool
	closed        bool
	tracker       *Tracker
	outcomes      map[uint64]*RpcResult
	notifications []*Notification
	dropped       uint64
	droppedBytes  uint64
	lossCh        chan struct{}
}

func (g *goClientCore) helloFrame() ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	hello := &ClientHello{
		MinVersion: g.cfg.minVersion,
		MaxVersion: g.cfg.maxVersion,
		Credential: g.cfg.credential,
	}
	if err := ValidateHello(hello); err != nil {
		return nil, err
	}
	if err := ValidateCredentialSize(hello.GetCredential()); err != nil {
		return nil, err
	}
	return MarshalFrame(NewHelloFrame(hello, g.cfg.maxVersion))
}

func (g *goClientCore) activate(frame []byte) (*ServerReady, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	if g.active {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client already active")
	}
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
	if v < g.cfg.minVersion || v > g.cfg.maxVersion {
		return nil, NewRpcError(ErrorCodeUnimplemented, "syntra: server selected version outside proposed range")
	}
	if err := ValidateReady(f.GetReady()); err != nil {
		return nil, err
	}
	g.negotiated = v
	g.active = true
	return f.GetReady(), nil
}

func (g *goClientCore) version() uint32 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.negotiated
}

func (g *goClientCore) onFrame(frame []byte) (terminal []uint64, notifications int, fatal *RpcError) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, 0, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	if !g.active {
		return nil, 0, NewRpcError(ErrorCodeFailedPrecondition, "syntra: frame before handshake completed")
	}
	f, err := UnmarshalFrame(frame)
	if err != nil {
		var rerr *RpcError
		if asErr(err, &rerr) {
			return nil, 0, rerr
		}
		return nil, 0, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed frame")
	}
	if f.GetVersion() != g.negotiated {
		return nil, 0, NewRpcError(ErrorCodeInvalidArgument, "syntra: frame version mismatch")
	}
	switch BodyKindOf(f) {
	case BodyKindResult:
		id := f.GetRequestId()
		if _, dup := g.outcomes[id]; dup {
			// Second terminal result for one id: keep the first and
			// ignore the storm (SNTR-RPC-901).
			return nil, 0, nil
		}
		if err := g.tracker.FinishResult(id, f.GetResult()); err != nil {
			// Unknown or expired id: locally ignore, no error storm
			// (SNTR-RPC section 4).
			return nil, 0, nil
		}
		g.outcomes[id] = f.GetResult()
		return []uint64{id}, 0, nil
	case BodyKindNotification:
		cap := g.cfg.notifyBuffer
		if cap <= 0 {
			cap = 16
		}
		if len(g.notifications) >= cap {
			payloadLen := len(f.GetNotification().GetPayload())
			g.dropped++
			g.droppedBytes += uint64(payloadLen)
			select {
			case g.lossCh <- struct{}{}:
			default:
			}
			return nil, 0, nil
		}
		g.notifications = append(g.notifications, f.GetNotification())
		return nil, 1, nil
	default:
		return nil, 0, NewRpcError(ErrorCodeInvalidArgument, "syntra: unexpected frame for client")
	}
}

func (g *goClientCore) beginCall(requestID uint64, method string, payload []byte, timeoutMs uint32) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	if !g.active {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: call before handshake completed")
	}
	if g.tracker.Pending() >= g.cfg.maxPending {
		return nil, NewRpcError(ErrorCodeResourceExhausted, "syntra: too many concurrent RPCs")
	}
	if err := ValidatePayloadSize(len(payload)); err != nil {
		return nil, err
	}
	req := &RpcRequest{Method: method, Payload: payload, TimeoutMs: timeoutMs}
	raw, err := MarshalFrame(NewRequestFrame(g.negotiated, requestID, req))
	if err != nil {
		return nil, err
	}
	// Encoding can fail even when the payload fits: envelope overhead also
	// counts toward MaxFrameBytes. Only track requests we can transmit.
	if err := g.tracker.StartWithBudget(time.Now(), requestID, method, timeoutMs); err != nil {
		return nil, err
	}
	return raw, nil
}

func (g *goClientCore) cancelCall(requestID uint64) []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || !g.active {
		return nil
	}
	if !g.tracker.Cancel(requestID) {
		return nil
	}
	raw, err := MarshalFrame(NewCancelFrame(g.negotiated, requestID))
	if err != nil {
		return nil
	}
	return raw
}

func (g *goClientCore) takeOutcome(requestID uint64) (*RpcResult, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	res, ok := g.outcomes[requestID]
	if ok {
		delete(g.outcomes, requestID)
	}
	return res, ok
}

func (g *goClientCore) pollNotification() (*Notification, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.notifications) == 0 {
		return nil, false
	}
	ntf := g.notifications[0]
	g.notifications = g.notifications[1:]
	return ntf, true
}

// lossTotals reports cumulative notification-loss totals for the pure-Go
// core: (dropped_count, dropped_bytes) for notifications discarded when the
// bounded queue was full. Bounds are unchanged; the queue stays
// non-blocking and drops the newest notification. Counters advance exactly
// once per drop (no double-counting), unifying with the async Rust
// notification_loss and the FFI client_notification_loss signals.
func (g *goClientCore) lossTotals() (uint64, uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.dropped, g.droppedBytes
}

func (g *goClientCore) reapExpired(now time.Time) []uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	expired := g.tracker.Expired(now)
	for _, id := range expired {
		g.outcomes[id] = NewWireErrorResult(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded")
	}
	return expired
}

func (g *goClientCore) close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: client already closed")
	}
	g.closed = true
	return nil
}

// hostCall is one outstanding responder-side call.
type hostCall struct {
	deadline  time.Time
	cancelled bool
}

type pendingReq struct {
	id  uint64
	req *RpcRequest
}

// hostNotificationBacklogLimit bounds notification admission against the
// shared outbound backlog. Terminal RPC results remain admissible at capacity.
// Each frame is also bounded by MaxFrameBytes.
const hostNotificationBacklogLimit = 256

// goHostCore is the pure-Go responder core for one connection.
type goHostCore struct {
	mu          sync.Mutex
	cfg         resolvedHostConfig
	conn        *Connection
	negotiated  uint32
	active      bool
	closed      bool
	pending     []pendingReq
	outstanding map[uint64]*hostCall
	outbound    [][]byte
}

func (g *goHostCore) acceptHello(frame []byte) (uint32, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return 0, NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	f, err := UnmarshalFrame(frame)
	if err != nil {
		return 0, err
	}
	if BodyKindOf(f) != BodyKindHello {
		return 0, NewRpcError(ErrorCodeFailedPrecondition, "syntra: first frame must be hello")
	}
	v, err := g.conn.OnHello(f.GetHello())
	if err != nil {
		return 0, err
	}
	g.negotiated = v
	return v, nil
}

func (g *goHostCore) authComplete(principal string) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	if err := g.conn.BeginAuth(); err != nil {
		return nil, err
	}
	if err := g.conn.AuthSuccess(principal); err != nil {
		_ = g.conn.AuthFailure()
		return nil, err
	}
	connID, err := NewConnectionID()
	if err != nil {
		return nil, err
	}
	ready := &ServerReady{ConnectionId: connID}
	raw, err := MarshalFrame(NewReadyFrame(g.negotiated, ready))
	if err != nil {
		return nil, err
	}
	g.active = true
	return raw, nil
}

func (g *goHostCore) onFrame(frame []byte) ([][]byte, []uint64, *RpcError) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	f, err := UnmarshalFrame(frame)
	if err != nil {
		// Undecodable bytes carry no routable request ID, so no
		// per-RPC error can be addressed; fail the connection closed
		// rather than dropping bytes silently or guessing a target.
		var rerr *RpcError
		if asErr(err, &rerr) {
			return nil, nil, rerr
		}
		return nil, nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed frame")
	}
	if !g.active {
		// Only hello is legal pre-ACTIVE and it is consumed by
		// acceptHello; anything else here is a state violation.
		return nil, nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: frame before handshake completed")
	}
	if f.GetVersion() != g.negotiated {
		return nil, nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: frame version mismatch")
	}
	switch BodyKindOf(f) {
	case BodyKindRequest:
		return nil, nil, g.onRequestLocked(f)
	case BodyKindCancel:
		id := f.GetRequestId()
		if call, ok := g.outstanding[id]; ok {
			call.cancelled = true
			return nil, []uint64{id}, nil
		}
		return nil, nil, nil
	case BodyKindResult, BodyKindNotification:
		// Clients never send these; tolerate without a storm.
		return nil, nil, nil
	default:
		// Re-handshake on an ACTIVE connection is forbidden.
		return nil, nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: re-handshake on the same connection is forbidden")
	}
}

// onRequestLocked validates one request and either queues it for
// dispatch or answers it immediately with a terminal error. Callers MUST
// hold g.mu.
func (g *goHostCore) onRequestLocked(f *Frame) *RpcError {
	id := f.GetRequestId()
	req := f.GetRequest()
	fail := func(code ErrorCode, msg string) *RpcError {
		g.outbound = append(g.outbound, mustMarshal(NewResultFrame(g.negotiated, id, NewWireErrorResult(code, msg))))
		return nil
	}
	if req == nil {
		return fail(ErrorCodeInvalidArgument, "syntra: nil request")
	}
	if err := ValidateMethod(req.GetMethod()); err != nil {
		return fail(ErrorCodeInvalidArgument, "syntra: malformed method")
	}
	if err := ValidatePayloadSize(len(req.GetPayload())); err != nil {
		return fail(ErrorCodeResourceExhausted, "syntra: payload exceeds bound")
	}
	if req.GetTimeoutMs() > MaxRPCTimeoutMs {
		return fail(ErrorCodeOutOfRange, "syntra: timeout_ms exceeds max")
	}
	if _, dup := g.outstanding[id]; dup {
		return fail(ErrorCodeFailedPrecondition, "syntra: duplicate request_id")
	}
	if len(g.outstanding) >= g.cfg.maxPending {
		return fail(ErrorCodeResourceExhausted, "syntra: too many concurrent RPCs")
	}
	budget := g.cfg.timeout
	if req.GetTimeoutMs() > 0 {
		budget = time.Duration(req.GetTimeoutMs()) * time.Millisecond
	}
	g.outstanding[id] = &hostCall{deadline: time.Now().Add(budget)}
	g.pending = append(g.pending, pendingReq{id: id, req: req})
	return nil
}

func (g *goHostCore) takePending() (uint64, *RpcRequest, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.pending) == 0 {
		return 0, nil, false
	}
	p := g.pending[0]
	g.pending = g.pending[1:]
	return p.id, p.req, true
}

func (g *goHostCore) isCancelled(requestID uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	call, ok := g.outstanding[requestID]
	return ok && call.cancelled
}

func (g *goHostCore) answer(requestID uint64, result *RpcResult) ([]byte, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, false, NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	call, ok := g.outstanding[requestID]
	if !ok {
		return nil, false, NewRpcError(ErrorCodeInternal, "syntra: answer for unknown call")
	}
	if err := ValidateResult(result); err != nil {
		return nil, false, err
	}
	now := time.Now()
	if !now.Before(call.deadline) {
		delete(g.outstanding, requestID)
		g.outbound = append(g.outbound, mustMarshal(NewResultFrame(g.negotiated, requestID, NewWireErrorResult(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded"))))
		return nil, true, nil
	}
	delete(g.outstanding, requestID)
	raw, err := MarshalFrame(NewResultFrame(g.negotiated, requestID, result))
	if err != nil {
		var rerr *RpcError
		if errors.As(err, &rerr) && rerr.Code == ErrorCodeResourceExhausted {
			bounded := NewWireErrorResult(ErrorCodeResourceExhausted, "syntra: result exceeds bound")
			raw2, err2 := MarshalFrame(NewResultFrame(g.negotiated, requestID, bounded))
			if err2 != nil {
				return nil, false, err2
			}
			return raw2, false, nil
		}
		return nil, false, err
	}
	return raw, false, nil
}

func (g *goHostCore) notify(payload []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	if !g.active {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: notify before handshake completed")
	}
	if err := ValidatePayloadSize(len(payload)); err != nil {
		return err
	}
	if len(g.outbound) >= hostNotificationBacklogLimit {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: outbound notification backlog full")
	}
	raw, err := MarshalFrame(NewNotificationFrame(g.negotiated, &Notification{Payload: payload}))
	if err != nil {
		return err
	}
	g.outbound = append(g.outbound, raw)
	return nil
}

func (g *goHostCore) nextOutbound() ([]byte, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.outbound) == 0 {
		return nil, false
	}
	raw := g.outbound[0]
	g.outbound[0] = nil // Do not retain a drained frame in the backing array.
	g.outbound = g.outbound[1:]
	if len(g.outbound) == 0 {
		g.outbound = nil
	}
	return raw, true
}

func (g *goHostCore) reapExpired(now time.Time) []uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	var expired []uint64
	for id, call := range g.outstanding {
		if !now.Before(call.deadline) {
			expired = append(expired, id)
		}
	}
	for _, id := range expired {
		delete(g.outstanding, id)
		g.outbound = append(g.outbound, mustMarshal(NewResultFrame(g.negotiated, id, NewWireErrorResult(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded"))))
	}
	return expired
}

func (g *goHostCore) close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host already closed")
	}
	g.closed = true
	return nil
}

// mustMarshal encodes f or panics. Callers pass frames built by the
// constructors above, which always validate; a failure here is a core
// bug, and panicking surfaces it instead of emitting a half frame.
func mustMarshal(f *Frame) []byte {
	raw, err := MarshalFrame(f)
	if err != nil {
		panic("syntra: core marshal failed: " + err.Error())
	}
	return raw
}

// asErr reports whether err is a *RpcError without importing errors
// into this core file; session.go uses errors.As directly.
func asErr(err error, target **RpcError) bool {
	if err == nil {
		return false
	}
	rerr, ok := err.(*RpcError)
	if !ok {
		return false
	}
	*target = rerr
	return true
}
