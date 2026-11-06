package syntra

import (
	"errors"
	"sync"
	"time"
)

// newClientCore opens a pure-Go initiator core.
func newClientCore(cfg resolvedClientConfig) (clientCore, error) {
	if cfg.minVersion == 0 || cfg.maxVersion == 0 || cfg.minVersion > cfg.maxVersion {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: client version range invalid")
	}
	tracker := NewTracker()
	tracker.limit = cfg.maxPending
	return &goClientCore{
		cfg:      cfg,
		tracker:  tracker,
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
// accounting: when full, the
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
	helloEmitted  bool
	highwater     uint64
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
	if g.helloEmitted {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: hello already emitted")
	}
	g.helloEmitted = true
	defer func() { g.cfg.credential = nil }()
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
	if !g.helloEmitted {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: ready before hello emission")
	}
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
	if v < g.cfg.minVersion || v > g.cfg.maxVersion {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: server selected version outside proposed range")
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
	f, err := unmarshalSessionFrame(frame)
	if err != nil {
		var rerr *RpcError
		if asErr(err, &rerr) {
			return nil, 0, rerr
		}
		return nil, 0, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed frame")
	}
	if f.GetVersion() != g.negotiated {
		return nil, 0, NewRpcError(ErrorCodeFailedPrecondition, "syntra: frame version mismatch")
	}
	switch BodyKindOf(f) {
	case BodyKindResult:
		id := f.GetRequestId()
		if _, dup := g.outcomes[id]; dup {
			// Second terminal result for one id: keep the first and
			// ignore the storm (SNTR-RPC-901).
			return nil, 0, nil
		}
		g.tracker.mu.Lock()
		call, ok := g.tracker.pending[id]
		if !ok {
			g.tracker.mu.Unlock()
			return nil, 0, nil
		}
		result := f.GetResult()
		if !time.Now().Before(call.deadline) {
			result = NewWireErrorResult(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded")
		}
		delete(g.tracker.pending, id)
		g.tracker.mu.Unlock()
		g.outcomes[id] = result
		if f.GetResult().GetError().GetCode() == ErrorCodeUnauthenticated {
			return []uint64{id}, 0, NewRpcError(ErrorCodeUnauthenticated, "syntra: credential not accepted")
		}
		return []uint64{id}, 0, nil
	case BodyKindNotification:
		cap := g.cfg.notifyBuffer
		if cap <= 0 {
			cap = DefaultQueueCapacity
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
	case BodyKindHello, BodyKindReady:
		return nil, 0, NewRpcError(ErrorCodeFailedPrecondition, "syntra: re-handshake on the same connection is forbidden")
	default:
		return nil, 0, nil
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
	if requestID == 0 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: request_id must be nonzero")
	}
	if requestID <= g.highwater {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: request_id was already retired")
	}
	g.highwater = requestID
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

// setCallDeadline pins the original caller deadline without restarting it at
// encoding or queue admission. The session holds its terminal gate.
func (g *goClientCore) setCallDeadline(id uint64, deadline time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tracker.mu.Lock()
	defer g.tracker.mu.Unlock()
	if call := g.tracker.pending[id]; call != nil {
		call.deadline = deadline
	}
}

// failCall selects one local candidate, preserving a previously selected
// outcome. Deadline expiry precedes every new candidate, including teardown.
func (g *goClientCore) failCall(id uint64, candidate *RpcResult) *RpcResult {
	g.mu.Lock()
	defer g.mu.Unlock()
	if result, ok := g.outcomes[id]; ok {
		delete(g.outcomes, id)
		return result
	}
	g.tracker.mu.Lock()
	defer g.tracker.mu.Unlock()
	if call := g.tracker.pending[id]; call != nil {
		if !time.Now().Before(call.deadline) {
			candidate = NewWireErrorResult(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded")
		}
		delete(g.tracker.pending, id)
	}
	return candidate
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
	g.notifications[0] = nil
	g.notifications = g.notifications[1:]
	return ntf, true
}

// lossTotals reports cumulative notification-loss totals for the pure-Go
// core: (dropped_count, dropped_bytes) for notifications discarded when the
// bounded queue was full. Bounds are unchanged; the queue stays
// non-blocking and drops the newest notification. Counters advance exactly
// once per drop (no double-counting).
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
	g.cfg.credential = nil
	g.notifications = nil
	g.outcomes = nil
	g.tracker = NewTracker()
	return nil
}

// hostCall is one outstanding responder-side call.
type hostCall struct {
	deadline  time.Time
	cancelled bool
	selected  *RpcResult
}

type pendingReq struct {
	id  uint64
	req *RpcRequest
}

const hostNotificationBacklogBytes = 8 * MaxFrameBytes

// goHostCore is the pure-Go responder core for one connection.
type goHostCore struct {
	mu             sync.Mutex
	cfg            resolvedHostConfig
	conn           *Connection
	negotiated     uint32
	active         bool
	closed         bool
	highwater      uint64
	pending        []pendingReq
	outstanding    map[uint64]*hostCall
	outbound       [][]byte
	terminalFenced bool // preserve validation/control, never admit new protected work
}

func (g *goHostCore) acceptHello(frame []byte) (uint32, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return 0, NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	f, err := unmarshalSessionFrame(frame)
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
	return g.onFrameAt(frame, time.Now())
}

func (g *goHostCore) onFrameAt(frame []byte, receivedAt time.Time) ([][]byte, []uint64, *RpcError) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	f, err := unmarshalSessionFrame(frame)
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
		return nil, nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: frame version mismatch")
	}
	switch BodyKindOf(f) {
	case BodyKindRequest:
		return nil, nil, g.onRequestLocked(f, receivedAt)
	case BodyKindCancel:
		id := f.GetRequestId()
		if call, ok := g.outstanding[id]; ok {
			call.cancelled = true
			g.selectResultLocked(call, NewWireErrorResult(ErrorCodeCancelled, "syntra: cancelled"))
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
func (g *goHostCore) onRequestLocked(f *Frame, receivedAt time.Time) *RpcError {
	id := f.GetRequestId()
	if id <= g.highwater {
		g.active = false
		_ = g.conn.Close()
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: non-increasing request_id")
	}
	g.highwater = id
	if g.terminalFenced {
		// Continue protocol validation without creating pending work, output or
		// correlation capacity. A fence must not hide fatal replay/framing errors.
		if req := f.GetRequest(); req == nil || ValidateMethod(req.GetMethod()) != nil || ValidatePayloadSize(len(req.GetPayload())) != nil {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: invalid request during retirement")
		}
		return nil
	}
	if len(g.outbound)+len(g.outstanding) >= g.cfg.writerCapacity+g.cfg.maxPending {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: terminal output capacity exhausted")
	}
	req := f.GetRequest()
	budget := g.cfg.timeout
	if req.GetTimeoutMs() > 0 {
		budget = time.Duration(req.GetTimeoutMs()) * time.Millisecond
	}
	if budget > g.cfg.maxTimeout {
		budget = g.cfg.maxTimeout
	}
	deadline := receivedAt.Add(budget)
	fail := func(code ErrorCode, msg string) *RpcError {
		if !time.Now().Before(deadline) {
			code, msg = ErrorCodeDeadlineExceeded, "syntra: deadline exceeded"
		}
		if len(g.outbound) >= g.cfg.writerCapacity+g.cfg.maxPending {
			return NewRpcError(ErrorCodeResourceExhausted, "syntra: terminal output capacity exhausted")
		}
		g.outbound = append(g.outbound, mustMarshal(NewResultFrame(g.negotiated, id, NewWireErrorResult(code, msg))))
		return nil
	}
	if req == nil {
		return fail(ErrorCodeInvalidArgument, "syntra: nil request")
	}
	if !time.Now().Before(deadline) {
		return fail(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded")
	}
	if err := ValidateMethod(req.GetMethod()); err != nil {
		return fail(ErrorCodeInvalidArgument, "syntra: malformed method")
	}
	if err := ValidatePayloadSize(len(req.GetPayload())); err != nil {
		return fail(ErrorCodeResourceExhausted, "syntra: payload exceeds bound")
	}
	if len(g.outstanding) >= g.cfg.maxPending {
		return fail(ErrorCodeResourceExhausted, "syntra: too many concurrent RPCs")
	}
	g.outstanding[id] = &hostCall{deadline: deadline}
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
	g.pending[0] = pendingReq{}
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
		return nil, false, nil
	}
	if call.selected == nil {
		if err := ValidateResult(result); err != nil {
			return nil, false, err
		}
	}
	g.selectResultLocked(call, result)
	result = call.selected
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
	if g.terminalFenced {
		return nil
	}
	if !g.active {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: notify before handshake completed")
	}
	if err := ValidatePayloadSize(len(payload)); err != nil {
		return err
	}
	if len(g.outbound) >= g.cfg.writerCapacity {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: outbound notification backlog full")
	}
	raw, err := MarshalFrame(NewNotificationFrame(g.negotiated, &Notification{Payload: payload}))
	if err != nil {
		return err
	}
	bytes := len(raw)
	for _, frame := range g.outbound {
		bytes += len(frame)
	}
	if bytes > hostNotificationBacklogBytes {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: outbound notification byte backlog full")
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
		if call.selected != nil {
			continue
		}
		if !now.Before(call.deadline) {
			expired = append(expired, id)
		}
	}
	for _, id := range expired {
		delete(g.outstanding, id)
		g.outbound = append(g.outbound, mustMarshal(NewResultFrame(g.negotiated, id, NewWireErrorResult(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded"))))
	}
	kept := g.pending[:0]
	for _, p := range g.pending {
		if _, ok := g.outstanding[p.id]; ok {
			kept = append(kept, p)
		}
	}
	clear(g.pending[len(kept):])
	g.pending = kept
	return expired
}

func (g *goHostCore) selectResult(id uint64, result *RpcResult) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if call := g.outstanding[id]; call != nil {
		g.selectResultLocked(call, result)
	}
}

func (g *goHostCore) selectResultLocked(call *hostCall, result *RpcResult) {
	if call.selected != nil {
		return
	}
	if !time.Now().Before(call.deadline) {
		result = NewWireErrorResult(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded")
	}
	call.selected = result
}

func (g *goHostCore) callDeadline(id uint64) (time.Time, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	call, ok := g.outstanding[id]
	if !ok {
		return time.Time{}, false
	}
	return call.deadline, true
}

// terminalPending excludes cancellation, expiry, and already-selected outcomes.
func (g *goHostCore) terminalPending(id uint64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	call := g.outstanding[id]
	return !g.closed && call != nil && call.selected == nil && !call.cancelled && time.Now().Before(call.deadline)
}

// fenceTerminal suppresses unstarted core output and request admission while
// retaining existing first-terminal state and fatal protocol validation.
func (g *goHostCore) fenceTerminal() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.terminalFenced = true
	g.pending = nil
	g.outbound = nil
}

func (g *goHostCore) close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host already closed")
	}
	g.closed = true
	g.pending = nil
	g.outbound = nil
	g.outstanding = nil
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

// asErr reports whether err is a *RpcError.
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
