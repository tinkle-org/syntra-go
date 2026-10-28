//go:build syntranative

package syntra

/*
#cgo LDFLAGS: -lsyntra_ffi
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Production native ABI: transport-agnostic initiator/responder cores.
//
// Build the Rust library with:
//   cargo build -p syntra-ffi --features production
// The authoritative header is crates/syntra-ffi/include/syntra_production.h.
// Default Rust builds export no C ABI; the test-fixture feature exports a
// separate syntra_* loopback ABI for native tests only.
// CI runs the default tags and this adapter (see repo-validation.yml).
//
// Buffer ownership:
//   - `const uint8_t*` inputs are BORROWED: the library copies what it
//     retains before returning. The caller keeps ownership and frees
//     with the usual Go/C rules (C.CBytes/C.CString results are freed
//     by the caller right after the call).
//   - `uint8_t**` outputs are OWNED: on success the library writes a
//     heap buffer the caller MUST release with syntra_ffi_free exactly
//     once. (NULL, 0) means "empty / absent" and needs no free.
//   - Output buffers are allocated by Rust and released only through
//     syntra_ffi_free with the returned length.
//   - Strings cross as explicit (ptr, len) pairs, never NUL-terminated.
//   - Handles (syntra_ffi_client_t / syntra_ffi_host_t) are owned: open
//     exactly once, close exactly once with the matching close call.
//     The Go wrapper guards with an atomic flag so double Close is
//     deterministic and never reaches a use-after-free. Rust contains
//     all panics at the FFI boundary and maps them to internal status.
//
// Status codes (int32_t return): 0 is SYNTRA_FFI_OK. Negative values are
// FFI-layer failures and map to Go control errors as documented on
// ffiStatus. Nonnegative values other than 0 are item counts where noted.
// Per-RPC failures NEVER surface as status codes: they travel inside the
// returned RpcResult frame, exactly as on the wire.
typedef struct syntra_ffi_client syntra_ffi_client_t;
typedef struct syntra_ffi_host syntra_ffi_host_t;

uint32_t syntra_ffi_abi_version(void);
void syntra_ffi_free(uint8_t *ptr, uintptr_t len);

// Client session: initiator-side state (handshake, correlation, timers,
// notification queue). The Go pump owns the transport; the core owns
// validation and bookkeeping.
int32_t syntra_ffi_client_open(uint32_t min_version, uint32_t max_version,
    const uint8_t *credential, uintptr_t credential_len,
    uint32_t default_timeout_ms, uint32_t max_concurrent,
    syntra_ffi_client_t **out);
int32_t syntra_ffi_client_hello_frame(syntra_ffi_client_t *c,
    uint8_t **out, uintptr_t *out_len);
int32_t syntra_ffi_client_activate(syntra_ffi_client_t *c,
    const uint8_t *ready_frame, uintptr_t len);
int32_t syntra_ffi_client_on_frame(syntra_ffi_client_t *c,
    const uint8_t *frame, uintptr_t len,
    uint64_t *terminal_ids, uintptr_t terminal_cap, uintptr_t *terminal_n,
    int32_t *notifications);
int32_t syntra_ffi_client_begin_call(syntra_ffi_client_t *c, uint64_t request_id,
    const uint8_t *method, uintptr_t method_len,
    const uint8_t *payload, uintptr_t payload_len, uint32_t timeout_ms,
    uint8_t **out_req_frame, uintptr_t *out_len);
int32_t syntra_ffi_client_cancel(syntra_ffi_client_t *c, uint64_t request_id,
    uint8_t **out_cancel_frame, uintptr_t *out_len);
int32_t syntra_ffi_client_take_outcome(syntra_ffi_client_t *c, uint64_t request_id,
    uint8_t **out, uintptr_t *out_len, int32_t *present);
int32_t syntra_ffi_client_poll_notification(syntra_ffi_client_t *c,
    uint8_t **out, uintptr_t *out_len, int32_t *present);
int32_t syntra_ffi_client_notification_loss(syntra_ffi_client_t *c,
    uint64_t *dropped_out, uint64_t *dropped_bytes_out);
int32_t syntra_ffi_client_reap_expired(syntra_ffi_client_t *c,
    uint64_t *ids, uintptr_t cap, uintptr_t *n);
int32_t syntra_ffi_client_close(syntra_ffi_client_t *c);

// Host session: responder-side per-connection state. Dispatch lives in Go
// (Host.Serve); the core validates, correlates, times out, and queues.
int32_t syntra_ffi_host_open(uint32_t min_version, uint32_t max_version,
    uint32_t max_concurrent, syntra_ffi_host_t **out);
int32_t syntra_ffi_host_accept_hello(syntra_ffi_host_t *h,
    const uint8_t *frame, uintptr_t len, uint32_t *version_out);
int32_t syntra_ffi_host_auth_complete(syntra_ffi_host_t *h,
    const char *principal, uintptr_t principal_len,
    uint8_t **out_ready_frame, uintptr_t *out_len);
int32_t syntra_ffi_host_on_frame(syntra_ffi_host_t *h,
    const uint8_t *frame, uintptr_t len,
    uint8_t **out_response, uintptr_t *out_len, int32_t *has_response,
    uint64_t *cancel_ids, uintptr_t cancel_cap, uintptr_t *cancel_n);
int32_t syntra_ffi_host_take_pending(syntra_ffi_host_t *h,
    uint64_t *request_id_out, uint8_t **out_req_frame, uintptr_t *out_len,
    int32_t *present);
int32_t syntra_ffi_host_is_cancelled(syntra_ffi_host_t *h, uint64_t request_id,
    int32_t *cancelled);
int32_t syntra_ffi_host_version(syntra_ffi_host_t *h, uint32_t *version_out);
int32_t syntra_ffi_host_answer(syntra_ffi_host_t *h,
    const uint8_t *result_frame, uintptr_t len, int32_t *expired);
int32_t syntra_ffi_host_notify(syntra_ffi_host_t *h,
    const uint8_t *payload, uintptr_t len);
int32_t syntra_ffi_host_next_outbound(syntra_ffi_host_t *h,
    uint8_t **out, uintptr_t *out_len, int32_t *present);
int32_t syntra_ffi_host_reap_expired(syntra_ffi_host_t *h,
    uint64_t *ids, uintptr_t cap, uintptr_t *n);
int32_t syntra_ffi_host_close(syntra_ffi_host_t *h);
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// NativeABIVersion is the production native ABI version. It matches
// SYNTRA_FFI_ABI_VERSION in crates/syntra-ffi/include/syntra_production.h.
const NativeABIVersion = 1

// Production native statuses, matching the Rust production ABI.
const (
	ffiOK       = 0
	ffiInvalid  = -1
	ffiClosed   = -2
	ffiABIMis   = -3
	ffiNoMem    = -4
	ffiExpired  = -5
	ffiInternal = -6
)

// ffiStatus converts an FFI-layer status to nil (ok) or a *RpcError. It
// MUST NOT be used for per-RPC failures, which arrive inside result
// frames. op names the operation for diagnostics.
func ffiStatus(st C.int32_t, op string) error {
	switch int(st) {
	case ffiOK:
		return nil
	case ffiInvalid:
		return NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: native %s rejected argument", op))
	case ffiClosed:
		return NewRpcError(ErrorCodeFailedPrecondition, fmt.Sprintf("syntra: native %s on closed handle", op))
	case ffiABIMis:
		return NewRpcError(ErrorCodeInternal, "syntra: native ABI mismatch")
	case ffiNoMem:
		return NewRpcError(ErrorCodeResourceExhausted, fmt.Sprintf("syntra: native %s out of memory", op))
	case ffiExpired:
		return NewRpcError(ErrorCodeDeadlineExceeded, "syntra: native deadline exceeded")
	default:
		return NewRpcError(ErrorCodeInternal, fmt.Sprintf("syntra: native %s failed (status %d)", op, int(st)))
	}
}

// NativeAvailable reports whether the process links the native
// production core built with `cargo build -p syntra-ffi --features production`.
func NativeAvailable() bool { return true }

// CheckABI queries syntra_ffi_abi_version and fails closed unless it
// equals NativeABIVersion. Call it after process start (or lazily on
// first Open) before trusting any other native call.
func CheckABI() error {
	v := uint32(C.syntra_ffi_abi_version())
	if v != NativeABIVersion {
		return NewRpcError(ErrorCodeInternal, fmt.Sprintf("syntra: native ABI version %d != binding %d", v, NativeABIVersion))
	}
	return nil
}

// takeOwned copies an owned (ptr, len) buffer into Go memory and frees
// the native side exactly once. (NULL, 0) yields nil without freeing.
func takeOwned(ptr *C.uint8_t, ln C.uintptr_t) []byte {
	if ptr == nil || ln == 0 {
		return nil
	}
	out := C.GoBytes(unsafe.Pointer(ptr), C.int(ln))
	C.syntra_ffi_free(ptr, ln)
	return out
}

// withBorrowed runs fn with the contents of b borrowed by C. The slice
// is kept alive for the duration of the call; empty input passes NULL
// (the C side treats (NULL, 0) as empty, which is valid for payloads and
// credentials but never for frames — callers validate first).
func withBorrowed(b []byte, fn func(ptr *C.uint8_t, ln C.uintptr_t)) {
	if len(b) == 0 {
		fn(nil, 0)
		return
	}
	fn((*C.uint8_t)(unsafe.Pointer(&b[0])), C.uintptr_t(len(b)))
}

// newClientCore opens a Rust-backed initiator core. Config defaults were
// applied by resolveClientConfig; values are re-validated Go-side first
// (defense in depth: the binding never trusts the caller or the peer).
func newClientCore(cfg resolvedClientConfig) (clientCore, error) {
	if cfg.minVersion == 0 || cfg.maxVersion == 0 || cfg.minVersion > cfg.maxVersion {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: client version range invalid")
	}
	if err := ValidateCredentialSize(cfg.credential); err != nil {
		return nil, err
	}
	if err := CheckABI(); err != nil {
		return nil, err
	}
	// cfg.timeout is already whole milliseconds (rounded up at config
	// resolution); the helper keeps the conversion exact and floors at 1.
	c := &ffiClientCore{
		minVersion: cfg.minVersion, maxVersion: cfg.maxVersion,
		timeoutMs: roundUpToMs(cfg.timeout), maxPending: uint32(cfg.maxPending),
	}
	var handle *C.syntra_ffi_client_t
	var st C.int32_t
	withBorrowed(cfg.credential, func(ptr *C.uint8_t, ln C.uintptr_t) {
		st = C.syntra_ffi_client_open(C.uint32_t(cfg.minVersion), C.uint32_t(cfg.maxVersion),
			ptr, ln, C.uint32_t(c.timeoutMs), C.uint32_t(c.maxPending), &handle)
	})
	if err := ffiStatus(st, "client_open"); err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, NewRpcError(ErrorCodeInternal, "syntra: native client_open returned nil handle")
	}
	c.handle = handle
	runtime.SetFinalizer(c, func(c *ffiClientCore) { c.destroy() })
	return c, nil
}

// ffiClientCore is the CGO initiator core. All handle uses go through
// locked, holding a read lock until unlockHandle after the full call;
// destroy runs exactly once via sync.Once (Close or GC finalizer).
type ffiClientCore struct {
	mu         sync.RWMutex
	handle     *C.syntra_ffi_client_t
	once       sync.Once
	closed     atomic.Bool
	timeoutMs  uint32
	maxPending uint32
	// Go-side mirrors for checks the binding enforces before crossing
	// FFI (identical to the pure-Go core's rules).
	minVersion uint32
	maxVersion uint32
	stateMu    sync.Mutex
	negotiated uint32
	active     atomic.Bool
	// Synthesized terminal outcomes for calls the native core reaped.
	// Rust drops expired correlation entries without an outcome frame;
	// the binding stashes DEADLINE_EXCEEDED here so reap() can deliver
	// them exactly like the pure-Go core does.
	expired map[uint64]*RpcResult
}

func (c *ffiClientCore) locked() (*C.syntra_ffi_client_t, error) {
	if c.closed.Load() {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	c.mu.RLock()
	if c.closed.Load() || c.handle == nil {
		c.mu.RUnlock()
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: client closed")
	}
	return c.handle, nil
}

func (c *ffiClientCore) unlockHandle() {
	c.mu.RUnlock()
	runtime.KeepAlive(c)
}

func (c *ffiClientCore) helloFrame() ([]byte, error) {
	h, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer c.unlockHandle()
	var out *C.uint8_t
	var ln C.uintptr_t
	if serr := ffiStatus(C.syntra_ffi_client_hello_frame(h, &out, &ln), "hello_frame"); serr != nil {
		return nil, serr
	}
	raw := takeOwned(out, ln)
	if len(raw) == 0 {
		return nil, NewRpcError(ErrorCodeInternal, "syntra: native hello_frame empty")
	}
	// Validate the frame Go-side before it reaches the transport.
	if _, verr := UnmarshalFrame(raw); verr != nil {
		return nil, verr
	}
	return raw, nil
}

func (c *ffiClientCore) activate(frame []byte) (*ServerReady, error) {
	h, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer c.unlockHandle()
	// Go-side shape check first so a malformed peer frame is rejected
	// with the binding's validators even if the native side is lenient.
	ready, verr := activateFrame(frame, c.minVersion, c.maxVersion)
	if verr != nil {
		return nil, verr
	}
	var st C.int32_t
	withBorrowed(frame, func(ptr *C.uint8_t, ln C.uintptr_t) {
		st = C.syntra_ffi_client_activate(h, ptr, ln)
	})
	if serr := ffiStatus(st, "activate"); serr != nil {
		return nil, serr
	}
	c.active.Store(true)
	c.stateMu.Lock()
	c.negotiated = ready.frameVersion
	c.stateMu.Unlock()
	return ready.ready, nil
}

func (c *ffiClientCore) version() uint32 {
	c.stateMu.Lock()
	defer c.stateMu.Unlock()
	return c.negotiated
}

func (c *ffiClientCore) onFrame(frame []byte) (terminal []uint64, notifications int, fatal *RpcError) {
	h, err := c.locked()
	if err != nil {
		return nil, 0, err.(*RpcError)
	}
	defer c.unlockHandle()
	const maxEvents = 128
	ids := make([]C.uint64_t, maxEvents)
	var n C.uintptr_t
	var notif C.int32_t
	var st C.int32_t
	withBorrowed(frame, func(ptr *C.uint8_t, ln C.uintptr_t) {
		st = C.syntra_ffi_client_on_frame(h, ptr, ln, &ids[0], C.uintptr_t(len(ids)), &n, &notif)
	})
	if serr := ffiStatus(st, "on_frame"); serr != nil {
		var rerr *RpcError
		if errors.As(serr, &rerr) {
			return nil, 0, rerr
		}
		return nil, 0, NewRpcError(ErrorCodeInternal, "syntra: native on_frame failed")
	}
	terminal = make([]uint64, 0, int(n))
	for i := 0; i < int(n); i++ {
		terminal = append(terminal, uint64(ids[i]))
	}
	return terminal, int(notif), nil
}

func (c *ffiClientCore) beginCall(requestID uint64, method string, payload []byte, timeoutMs uint32) ([]byte, error) {
	h, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer c.unlockHandle()
	// Go-side validation first: method shape, payload bound, timeout
	// ceiling — the binding never forwards a frame it would reject.
	if verr := ValidateMethod(method); verr != nil {
		return nil, verr
	}
	if verr := ValidatePayloadSize(len(payload)); verr != nil {
		return nil, verr
	}
	if timeoutMs > MaxRPCTimeoutMs {
		return nil, NewRpcError(ErrorCodeOutOfRange, "syntra: timeout_ms exceeds max")
	}
	if requestID == 0 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: request must carry nonzero request_id")
	}
	var out *C.uint8_t
	var ln C.uintptr_t
	var st C.int32_t
	mb := []byte(method)
	withBorrowed(mb, func(mptr *C.uint8_t, mln C.uintptr_t) {
		withBorrowed(payload, func(pptr *C.uint8_t, pln C.uintptr_t) {
			st = C.syntra_ffi_client_begin_call(h, C.uint64_t(requestID),
				mptr, mln, pptr, pln, C.uint32_t(timeoutMs), &out, &ln)
		})
	})
	if serr := ffiStatus(st, "begin_call"); serr != nil {
		return nil, serr
	}
	raw := takeOwned(out, ln)
	if verr := ValidateFrameSize(len(raw)); verr != nil {
		return nil, verr
	}
	return raw, nil
}

func (c *ffiClientCore) cancelCall(requestID uint64) []byte {
	h, err := c.locked()
	if err != nil {
		return nil
	}
	defer c.unlockHandle()
	var out *C.uint8_t
	var ln C.uintptr_t
	if serr := ffiStatus(C.syntra_ffi_client_cancel(h, C.uint64_t(requestID), &out, &ln), "cancel"); serr != nil {
		return nil
	}
	return takeOwned(out, ln)
}

func (c *ffiClientCore) takeOutcome(requestID uint64) (*RpcResult, bool) {
	c.stateMu.Lock()
	if res, ok := c.expired[requestID]; ok {
		delete(c.expired, requestID)
		c.stateMu.Unlock()
		return res, true
	}
	c.stateMu.Unlock()
	h, err := c.locked()
	if err != nil {
		return nil, false
	}
	defer c.unlockHandle()
	var out *C.uint8_t
	var ln C.uintptr_t
	var present C.int32_t
	if serr := ffiStatus(C.syntra_ffi_client_take_outcome(h, C.uint64_t(requestID), &out, &ln, &present), "take_outcome"); serr != nil {
		return nil, false
	}
	if present == 0 {
		return nil, false
	}
	raw := takeOwned(out, ln)
	res, verr := decodeResultFrame(raw)
	if verr != nil {
		return nil, false
	}
	return res, true
}

func (c *ffiClientCore) pollNotification() (*Notification, bool) {
	h, err := c.locked()
	if err != nil {
		return nil, false
	}
	defer c.unlockHandle()
	var out *C.uint8_t
	var ln C.uintptr_t
	var present C.int32_t
	if serr := ffiStatus(C.syntra_ffi_client_poll_notification(h, &out, &ln, &present), "poll_notification"); serr != nil {
		return nil, false
	}
	if present == 0 {
		return nil, false
	}
	raw := takeOwned(out, ln)
	ntf, verr := decodeNotificationFrame(raw)
	if verr != nil {
		return nil, false
	}
	return ntf, true
}

// lossTotals reports cumulative notification-loss totals from the native
// core via syntra_ffi_client_notification_loss. It unifies with the
// pure-Go core lossTotals and the async Rust notification_loss signal:
// (dropped_count, dropped_bytes), each advancing exactly once per drop.
func (c *ffiClientCore) lossTotals() (uint64, uint64) {
	h, err := c.locked()
	if err != nil {
		return 0, 0
	}
	defer c.unlockHandle()
	var dropped, droppedBytes C.uint64_t
	if serr := ffiStatus(C.syntra_ffi_client_notification_loss(h, &dropped, &droppedBytes), "notification_loss"); serr != nil {
		return 0, 0
	}
	return uint64(dropped), uint64(droppedBytes)
}

func (c *ffiClientCore) reapExpired(now time.Time) []uint64 {
	_ = now // expiry is enforced by the native timer wheel; reap only drains.
	h, err := c.locked()
	if err != nil {
		return nil
	}
	defer c.unlockHandle()
	const maxIDs = 256
	ids := make([]C.uint64_t, maxIDs)
	var n C.uintptr_t
	if serr := ffiStatus(C.syntra_ffi_client_reap_expired(h, &ids[0], C.uintptr_t(len(ids)), &n), "reap_expired"); serr != nil {
		return nil
	}
	out := make([]uint64, 0, int(n))
	for i := 0; i < int(n); i++ {
		out = append(out, uint64(ids[i]))
	}
	if len(out) > 0 {
		c.stateMu.Lock()
		if c.expired == nil {
			c.expired = make(map[uint64]*RpcResult, len(out))
		}
		for _, id := range out {
			c.expired[id] = NewWireErrorResult(ErrorCodeDeadlineExceeded, "syntra: deadline exceeded")
		}
		c.stateMu.Unlock()
	}
	return out
}

func (c *ffiClientCore) close() error {
	if c.closed.Swap(true) {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: client already closed")
	}
	c.destroy()
	return nil
}

// destroy closes the native handle exactly once (Close or finalizer).
func (c *ffiClientCore) destroy() {
	c.once.Do(func() {
		c.mu.Lock()
		h := c.handle
		c.handle = nil
		c.mu.Unlock()
		if h != nil {
			_ = C.syntra_ffi_client_close(h)
		}
	})
}

// newHostCore opens a Rust-backed responder core for one connection.
// host_open takes no default-timeout param in ABI v1, so the Go wrapper
// threads cfg.timeout at request time: onFrame rewrites a zero wire
// timeout_ms to the configured default before crossing FFI, matching the
// pure-Go core. An ABI change adding default_timeout_ms to host_open
// would require header + Rust + Go + smoke test updates and an ABI bump;
// request-time threading is the minimal compatible fix.
func newHostCore(cfg resolvedHostConfig) (hostCore, error) {
	if cfg.minVersion == 0 || cfg.maxVersion == 0 || cfg.minVersion > cfg.maxVersion {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: host version range invalid")
	}
	if err := CheckABI(); err != nil {
		return nil, err
	}
	// cfg.timeout is already whole milliseconds (rounded up at config
	// resolution); the helper keeps the conversion exact and floors at 1.
	timeoutMs := roundUpToMs(cfg.timeout)
	c := &ffiHostCore{timeoutMs: timeoutMs}
	var handle *C.syntra_ffi_host_t
	// host_open takes the version range and concurrency bound. Per-RPC
	// budgets travel with each request; a zero wire timeout is rewritten
	// to the configured default in onFrame before crossing FFI (host_open
	// has no timeout param in ABI v1).
	st := C.syntra_ffi_host_open(C.uint32_t(cfg.minVersion), C.uint32_t(cfg.maxVersion),
		C.uint32_t(cfg.maxPending), &handle)
	if err := ffiStatus(st, "host_open"); err != nil {
		return nil, err
	}
	if handle == nil {
		return nil, NewRpcError(ErrorCodeInternal, "syntra: native host_open returned nil handle")
	}
	c.handle = handle
	runtime.SetFinalizer(c, func(c *ffiHostCore) { c.destroy() })
	return c, nil
}

// ffiHostCore is the CGO responder core with the same exactly-once
// destruction discipline as the client core. timeoutMs is the resolved
// HostConfig.DefaultTimeout in milliseconds, threaded at request time
// because host_open takes no timeout param in ABI v1.
type ffiHostCore struct {
	mu        sync.RWMutex
	handle    *C.syntra_ffi_host_t
	once      sync.Once
	closed    atomic.Bool
	timeoutMs uint32
}

func (c *ffiHostCore) locked() (*C.syntra_ffi_host_t, error) {
	if c.closed.Load() {
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	c.mu.RLock()
	if c.closed.Load() || c.handle == nil {
		c.mu.RUnlock()
		return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	return c.handle, nil
}

func (c *ffiHostCore) unlockHandle() {
	c.mu.RUnlock()
	runtime.KeepAlive(c)
}

func (c *ffiHostCore) acceptHello(frame []byte) (uint32, error) {
	h, err := c.locked()
	if err != nil {
		return 0, err
	}
	defer c.unlockHandle()
	var version C.uint32_t
	var st C.int32_t
	withBorrowed(frame, func(ptr *C.uint8_t, ln C.uintptr_t) {
		st = C.syntra_ffi_host_accept_hello(h, ptr, ln, &version)
	})
	if serr := ffiStatus(st, "accept_hello"); serr != nil {
		return 0, serr
	}
	return uint32(version), nil
}

func (c *ffiHostCore) authComplete(principal string) ([]byte, error) {
	h, err := c.locked()
	if err != nil {
		return nil, err
	}
	defer c.unlockHandle()
	if principal == "" {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: principal must be non-empty at activation")
	}
	pb := []byte(principal)
	var out *C.uint8_t
	var ln C.uintptr_t
	var st C.int32_t
	withBorrowed(pb, func(ptr *C.uint8_t, pln C.uintptr_t) {
		// principal bytes are UTF-8 text; pass as (ptr, len).
		st = C.syntra_ffi_host_auth_complete(h, (*C.char)(unsafe.Pointer(ptr)), C.uintptr_t(pln), &out, &ln)
	})
	if serr := ffiStatus(st, "auth_complete"); serr != nil {
		return nil, serr
	}
	raw := takeOwned(out, ln)
	if _, verr := UnmarshalFrame(raw); verr != nil {
		return nil, verr
	}
	return raw, nil
}

func (c *ffiHostCore) onFrame(frame []byte) ([][]byte, []uint64, *RpcError) {
	h, err := c.locked()
	if err != nil {
		var rerr *RpcError
		if errors.As(err, &rerr) {
			return nil, nil, rerr
		}
		return nil, nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: host closed")
	}
	defer c.unlockHandle()
	// Thread the configured default: host_open has no timeout param, so a
	// zero wire timeout would otherwise fall back to the Rust hard-coded
	// 3s instead of cfg.timeout. Rewrite zero to the configured default
	// (validated <= MaxRPCTimeoutMs) to match the pure-Go core.
	wire := frame
	if f, uerr := UnmarshalFrame(frame); uerr == nil && BodyKindOf(f) == BodyKindRequest && f.GetRequest().GetTimeoutMs() == 0 {
		f.GetRequest().TimeoutMs = c.timeoutMs
		raw, merr := MarshalFrame(NewRequestFrame(f.GetVersion(), f.GetRequestId(), f.GetRequest()))
		if merr != nil {
			// Leave the original bytes for the native core: it reports
			// malformed requests as per-RPC errors, never fatal.
			wire = frame
		} else {
			wire = raw
		}
	}
	const maxCancels = 64
	cancels := make([]C.uint64_t, maxCancels)
	var out *C.uint8_t
	var ln C.uintptr_t
	var hasResp C.int32_t
	var nCancel C.uintptr_t
	var st C.int32_t
	withBorrowed(wire, func(ptr *C.uint8_t, fln C.uintptr_t) {
		st = C.syntra_ffi_host_on_frame(h, ptr, fln, &out, &ln, &hasResp,
			&cancels[0], C.uintptr_t(len(cancels)), &nCancel)
	})
	if serr := ffiStatus(st, "host_on_frame"); serr != nil {
		var rerr *RpcError
		if errors.As(serr, &rerr) {
			return nil, nil, rerr
		}
		return nil, nil, NewRpcError(ErrorCodeInternal, "syntra: native host_on_frame failed")
	}
	var responses [][]byte
	if hasResp != 0 {
		if raw := takeOwned(out, ln); len(raw) > 0 {
			responses = append(responses, raw)
		}
	}
	var cancelIDs []uint64
	for i := 0; i < int(nCancel); i++ {
		cancelIDs = append(cancelIDs, uint64(cancels[i]))
	}
	return responses, cancelIDs, nil
}

func (c *ffiHostCore) takePending() (uint64, *RpcRequest, bool) {
	h, err := c.locked()
	if err != nil {
		return 0, nil, false
	}
	defer c.unlockHandle()
	var id C.uint64_t
	var out *C.uint8_t
	var ln C.uintptr_t
	var present C.int32_t
	if serr := ffiStatus(C.syntra_ffi_host_take_pending(h, &id, &out, &ln, &present), "take_pending"); serr != nil {
		return 0, nil, false
	}
	if present == 0 {
		return 0, nil, false
	}
	raw := takeOwned(out, ln)
	f, verr := UnmarshalFrame(raw)
	if verr != nil || BodyKindOf(f) != BodyKindRequest {
		return 0, nil, false
	}
	return uint64(id), f.GetRequest(), true
}

func (c *ffiHostCore) isCancelled(requestID uint64) bool {
	h, err := c.locked()
	if err != nil {
		return false
	}
	defer c.unlockHandle()
	var cancelled C.int32_t
	if serr := ffiStatus(C.syntra_ffi_host_is_cancelled(h, C.uint64_t(requestID), &cancelled), "is_cancelled"); serr != nil {
		return false
	}
	return cancelled != 0
}

func (c *ffiHostCore) answer(requestID uint64, result *RpcResult) ([]byte, bool, error) {
	h, err := c.locked()
	if err != nil {
		return nil, false, err
	}
	defer c.unlockHandle()
	if verr := ValidateResult(result); verr != nil {
		return nil, false, verr
	}
	// The envelope version is pinned by the native session; query it so
	// the Go-built result frame carries the negotiated version.
	var version C.uint32_t
	if serr := ffiStatus(C.syntra_ffi_host_version(h, &version), "host_version"); serr != nil {
		return nil, false, serr
	}
	raw, merr := MarshalFrame(NewResultFrame(uint32(version), requestID, result))
	if merr != nil {
		return nil, false, merr
	}
	var expired C.int32_t
	var st C.int32_t
	withBorrowed(raw, func(ptr *C.uint8_t, ln C.uintptr_t) {
		st = C.syntra_ffi_host_answer(h, ptr, ln, &expired)
	})
	if serr := ffiStatus(st, "host_answer"); serr != nil {
		return nil, false, serr
	}
	if expired != 0 {
		return nil, true, nil
	}
	return raw, false, nil
}

func (c *ffiHostCore) notify(payload []byte) error {
	h, err := c.locked()
	if err != nil {
		return err
	}
	defer c.unlockHandle()
	if verr := ValidatePayloadSize(len(payload)); verr != nil {
		return verr
	}
	var st C.int32_t
	withBorrowed(payload, func(ptr *C.uint8_t, ln C.uintptr_t) {
		st = C.syntra_ffi_host_notify(h, ptr, ln)
	})
	return ffiStatus(st, "notify")
}

func (c *ffiHostCore) nextOutbound() ([]byte, bool) {
	h, err := c.locked()
	if err != nil {
		return nil, false
	}
	defer c.unlockHandle()
	var out *C.uint8_t
	var ln C.uintptr_t
	var present C.int32_t
	if serr := ffiStatus(C.syntra_ffi_host_next_outbound(h, &out, &ln, &present), "next_outbound"); serr != nil {
		return nil, false
	}
	if present == 0 {
		return nil, false
	}
	return takeOwned(out, ln), true
}

func (c *ffiHostCore) reapExpired(now time.Time) []uint64 {
	_ = now
	h, err := c.locked()
	if err != nil {
		return nil
	}
	defer c.unlockHandle()
	const maxIDs = 256
	ids := make([]C.uint64_t, maxIDs)
	var n C.uintptr_t
	if serr := ffiStatus(C.syntra_ffi_host_reap_expired(h, &ids[0], C.uintptr_t(len(ids)), &n), "reap_expired"); serr != nil {
		return nil
	}
	out := make([]uint64, 0, int(n))
	for i := 0; i < int(n); i++ {
		out = append(out, uint64(ids[i]))
	}
	return out
}

func (c *ffiHostCore) close() error {
	if c.closed.Swap(true) {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: host already closed")
	}
	c.destroy()
	return nil
}

// destroy closes the native handle exactly once (Close or finalizer).
func (c *ffiHostCore) destroy() {
	c.once.Do(func() {
		c.mu.Lock()
		h := c.handle
		c.handle = nil
		c.mu.Unlock()
		if h != nil {
			_ = C.syntra_ffi_host_close(h)
		}
	})
}
