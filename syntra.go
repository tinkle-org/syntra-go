// Package syntra is the Go binding for the Syntra v1 protocol.
//
// Distribution note: `go get github.com/tinkle-org/syntra-go`
// installs the Go sources in this module only (generated Protobuf types
// plus the pure-Go validation, codec, handshake, and session logic).
// Sessions use the supported pure-Go core by default; no native library
// is required and this module never downloads binaries. The syntranative
// adapter is supported via the production Rust core: build
// crates/syntra-ffi with --features production, link it with
// CGO_LDFLAGS="-L<dir> -lsyntra_ffi", and select the adapter with
// -tags syntranative (native.go matches
// crates/syntra-ffi/include/syntra_production.h). See README.md for the
// exact build, link, and test commands.
//
// The root package implements the transport-independent protocol core.
// securechannel and transport provide Noise and carrier bindings; connection
// orchestrates bounded establishment and serving. Identity policy, credential
// storage and application payload schemas belong to the host application.
// No messenger semantics (subscriptions, presence, JSON
// gateways, service registries) are defined here; neutral fixtures such as
// /example.Echo/Echo exist only in tests.
package syntra

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	syntrav1 "github.com/tinkle-org/syntra-go/gen/syntra/v1"
)

// Wire message aliases. The edge never defines its own Frame shape; field
// numbers, oneof cardinality, and reserved ranges come from the IDL, and
// binary encoding is owned by protoc-gen-go. Policy the generated code
// cannot express (size-before-alloc, version range, request_id polarity,
// exactly-one body, reserved rejection, ACTIVE gating) lives in the
// validators below.
type (
	// Frame is the versioned Syntra envelope (envelope.proto).
	Frame = syntrav1.Frame
	// ClientHello presents opaque credentials (handshake.proto).
	ClientHello = syntrav1.ClientHello
	// ServerReady confirms acceptance (handshake.proto).
	ServerReady = syntrav1.ServerReady
	// RpcRequest carries opaque application data (rpc.proto).
	RpcRequest = syntrav1.RpcRequest
	// RpcResult completes a call (rpc.proto).
	RpcResult = syntrav1.RpcResult
	// Cancel is an advisory cancellation target (rpc.proto).
	Cancel = syntrav1.Cancel
	// Notification carries uncorrelated opaque data (events.proto).
	Notification = syntrav1.Notification
	// WireRpcError is the failure payload inside RpcResult (errors.proto).
	WireRpcError = syntrav1.RpcError
	// ErrorCode is the error registry (errors.proto).
	ErrorCode = syntrav1.ErrorCode
)

// ErrorCode registry aliases. Values 0..16 match the IDL exactly.
const (
	// ErrorCodeUnspecified is not a valid failure outcome (SNTR-ERR-001).
	ErrorCodeUnspecified ErrorCode = syntrav1.ErrorCode_ERROR_CODE_UNSPECIFIED
	// ErrorCodeCancelled indicates cancellation.
	ErrorCodeCancelled ErrorCode = syntrav1.ErrorCode_ERROR_CODE_CANCELLED
	// ErrorCodeUnknown indicates an unclassified failure.
	ErrorCodeUnknown ErrorCode = syntrav1.ErrorCode_ERROR_CODE_UNKNOWN
	// ErrorCodeInvalidArgument indicates invalid arguments or envelope shape.
	ErrorCodeInvalidArgument ErrorCode = syntrav1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	// ErrorCodeDeadlineExceeded indicates budget expiry, not rollback.
	ErrorCodeDeadlineExceeded ErrorCode = syntrav1.ErrorCode_ERROR_CODE_DEADLINE_EXCEEDED
	// ErrorCodeNotFound indicates a missing target.
	ErrorCodeNotFound ErrorCode = syntrav1.ErrorCode_ERROR_CODE_NOT_FOUND
	// ErrorCodeAlreadyExists indicates a creation conflict.
	ErrorCodeAlreadyExists ErrorCode = syntrav1.ErrorCode_ERROR_CODE_ALREADY_EXISTS
	// ErrorCodePermissionDenied indicates insufficient access.
	ErrorCodePermissionDenied ErrorCode = syntrav1.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	// ErrorCodeResourceExhausted indicates an exhausted resource budget.
	ErrorCodeResourceExhausted ErrorCode = syntrav1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED
	// ErrorCodeFailedPrecondition indicates an operation cannot currently run.
	ErrorCodeFailedPrecondition ErrorCode = syntrav1.ErrorCode_ERROR_CODE_FAILED_PRECONDITION
	// ErrorCodeAborted indicates an aborted sequence.
	ErrorCodeAborted ErrorCode = syntrav1.ErrorCode_ERROR_CODE_ABORTED
	// ErrorCodeOutOfRange indicates a value outside the supported range.
	ErrorCodeOutOfRange ErrorCode = syntrav1.ErrorCode_ERROR_CODE_OUT_OF_RANGE
	// ErrorCodeUnimplemented indicates an unknown method or unsupported feature.
	ErrorCodeUnimplemented ErrorCode = syntrav1.ErrorCode_ERROR_CODE_UNIMPLEMENTED
	// ErrorCodeInternal indicates an internal failure.
	ErrorCodeInternal ErrorCode = syntrav1.ErrorCode_ERROR_CODE_INTERNAL
	// ErrorCodeUnavailable indicates unavailability; effects may be unknown.
	ErrorCodeUnavailable ErrorCode = syntrav1.ErrorCode_ERROR_CODE_UNAVAILABLE
	// ErrorCodeDataLoss indicates unrecoverable corruption or loss.
	ErrorCodeDataLoss ErrorCode = syntrav1.ErrorCode_ERROR_CODE_DATA_LOSS
	// ErrorCodeUnauthenticated indicates missing or unaccepted credentials.
	ErrorCodeUnauthenticated ErrorCode = syntrav1.ErrorCode_ERROR_CODE_UNAUTHENTICATED
)

const (
	// MaxFrameBytes is the default 1 MiB on-wire bound for one serialized
	// Frame (SNTR-WIRE-006). Validators enforce it before allocation.
	MaxFrameBytes = 1 << 20

	// MinSupportedVersion is the lowest Syntra version this binding speaks.
	MinSupportedVersion uint32 = 1
	// MaxSupportedVersion is the highest Syntra version this binding speaks.
	MaxSupportedVersion uint32 = 1

	// MaxMethodLength caps a canonical method string before allocation.
	MaxMethodLength = 512
	// MaxPayloadBytes caps a single opaque RPC or notification payload
	// before the caller retains it. The serialized-envelope bound stays
	// authoritative; this keeps one payload from consuming the frame budget.
	MaxPayloadBytes = 1 << 20
	// MaxCredentialBytes caps a ClientHello credential before verification.
	// Credentials are opaque; the bound prevents a peer from forcing a
	// large allocation in the verifier.
	MaxCredentialBytes = 8192
	// MaxConcurrentRPCs is the minimum concurrent-RPC budget every Syntra
	// host supports (SNTR-RPC-008). Hosts reject excess with
	// ResourceExhausted while the connection stays usable.
	MaxConcurrentRPCs = 16
	// MaxHostConcurrentRPCs caps per-connection handler concurrency on the
	// host side. Hosts fan out to many principals and may need headroom
	// above the client minimum; values above this fail fast as OutOfRange
	// so one connection cannot reserve an unbounded worker pool.
	MaxHostConcurrentRPCs = 256
	// ConnectionIDBytes is the 128-bit entropy bound into every
	// ServerReady.connection_id (SNTR-SESS-002). The ID is a diagnostic
	// handle, never an authenticator or resume token.
	ConnectionIDBytes = 16

	// ReservedFrameFieldNumber16 is the first reserved envelope number
	// (SNTR-SER-008, envelope.proto `reserved 16, 17`).
	ReservedFrameFieldNumber16 = 16
	// ReservedFrameFieldNumber17 is the second reserved envelope number.
	ReservedFrameFieldNumber17 = 17
)

// DefaultRPCTimeout is the bounded host default applied when
// RpcRequest.TimeoutMs is zero. Callers SHOULD document any deployment
// value that differs from this library default.
var DefaultRPCTimeout = 3 * time.Second

// MaxRPCTimeoutMs caps a caller-requested timeout budget. Larger values
// fail fast as OutOfRange so a peer cannot pin a session slot for minutes.
const MaxRPCTimeoutMs uint32 = 30_000

// roundUpToMs converts a validated positive timeout to whole milliseconds,
// rounding up. The native ABI expresses budgets as uint32 milliseconds, so
// config resolution normalizes once: both backends then enforce the
// identical effective deadline instead of the native side silently
// truncating sub-millisecond durations.
func roundUpToMs(d time.Duration) uint32 {
	ms := uint32((d + time.Millisecond - 1) / time.Millisecond)
	if ms == 0 {
		ms = 1
	}
	return ms
}

// ReservedFrameFieldNames are the reserved envelope oneof names
// (envelope.proto `reserved "event", "resume", "ack"`). Decoders that
// surface field names (JSON, debug strings) must reject these.
var ReservedFrameFieldNames = []string{"event", "resume", "ack"} //nolint:gochecknoglobals // allowlist is static.

// BodyKind identifies which Frame oneof alternative is set. It is the
// switch discriminant for request_id polarity and ACTIVE gating.
type BodyKind string

const (
	// BodyKindNone means no body pointer is set (invalid on the wire).
	BodyKindNone BodyKind = ""
	// BodyKindHello is the ClientHello alternative (field 10).
	BodyKindHello BodyKind = "hello"
	// BodyKindReady is the ServerReady alternative (field 11).
	BodyKindReady BodyKind = "ready"
	// BodyKindRequest is the RpcRequest alternative (field 12).
	BodyKindRequest BodyKind = "request"
	// BodyKindResult is the RpcResult alternative (field 13).
	BodyKindResult BodyKind = "result"
	// BodyKindCancel is the Cancel alternative (field 14).
	BodyKindCancel BodyKind = "cancel"
	// BodyKindNotification is the Notification alternative (field 15).
	BodyKindNotification BodyKind = "notification"
)

// BodyKindOf returns which oneof alternative is set on f. It returns
// BodyKindNone when f is nil, when no body is set, or when more than one
// body is set. The generated getters return non-nil for at most one
// alternative because proto.Unmarshal collapses duplicates into the last
// one; the strict duplicate rejection lives in the codec pre-scan before
// unmarshal.
func BodyKindOf(f *Frame) BodyKind {
	if f == nil {
		return BodyKindNone
	}
	count := 0
	var kind BodyKind
	if f.GetHello() != nil {
		count++
		kind = BodyKindHello
	}
	if f.GetReady() != nil {
		count++
		kind = BodyKindReady
	}
	if f.GetRequest() != nil {
		count++
		kind = BodyKindRequest
	}
	if f.GetResult() != nil {
		count++
		kind = BodyKindResult
	}
	if f.GetCancel() != nil {
		count++
		kind = BodyKindCancel
	}
	if f.GetNotification() != nil {
		count++
		kind = BodyKindNotification
	}
	if count != 1 {
		return BodyKindNone
	}
	return kind
}

// IsReservedFieldNumber reports whether a raw envelope field number is in
// the reserved set (16, 17). Reserved envelope numbers are rejected on
// both encoding and decoding (SNTR-SER-008).
func IsReservedFieldNumber(n int) bool {
	return n == ReservedFrameFieldNumber16 || n == ReservedFrameFieldNumber17
}

// IsReservedFieldName reports whether a decoded field name is in the
// reserved set ("event", "resume", "ack"). JSON/debug decoders call this
// when the wire format surfaces names instead of numbers.
func IsReservedFieldName(name string) bool {
	for _, r := range ReservedFrameFieldNames {
		if name == r {
			return true
		}
	}
	return false
}

// NewHelloFrame builds a hello Frame with the proposed maximum version.
func NewHelloFrame(hello *ClientHello, maxVersion uint32) *Frame {
	return &Frame{
		Version: maxVersion,
		Body:    &syntrav1.Frame_Hello{Hello: hello},
	}
}

// NewReadyFrame builds a ready Frame at the negotiated version.
func NewReadyFrame(version uint32, ready *ServerReady) *Frame {
	return &Frame{
		Version: version,
		Body:    &syntrav1.Frame_Ready{Ready: ready},
	}
}

// NewRequestFrame builds a request Frame with nonzero correlation.
func NewRequestFrame(version uint32, requestID uint64, req *RpcRequest) *Frame {
	return &Frame{
		Version:   version,
		RequestId: requestID,
		Body:      &syntrav1.Frame_Request{Request: req},
	}
}

// NewResultFrame builds a result Frame with nonzero correlation.
func NewResultFrame(version uint32, requestID uint64, res *RpcResult) *Frame {
	return &Frame{
		Version:   version,
		RequestId: requestID,
		Body:      &syntrav1.Frame_Result{Result: res},
	}
}

// NewCancelFrame builds a cancel Frame with nonzero correlation.
func NewCancelFrame(version uint32, requestID uint64) *Frame {
	return &Frame{
		Version:   version,
		RequestId: requestID,
		Body:      &syntrav1.Frame_Cancel{Cancel: &Cancel{}},
	}
}

// NewNotificationFrame builds a notification Frame (request_id zero).
func NewNotificationFrame(version uint32, n *Notification) *Frame {
	return &Frame{
		Version: version,
		Body:    &syntrav1.Frame_Notification{Notification: n},
	}
}

// NewSuccessResult builds a payload RpcResult. Empty payload with a
// selected outcome means success, even for zero-byte results
// (SNTR-WIRE-007). A nil outcome is never success.
func NewSuccessResult(payload []byte) *RpcResult {
	return &RpcResult{Outcome: &syntrav1.RpcResult_Payload{Payload: payload}}
}

// NewWireErrorResult builds an error RpcResult. An Unspecified code can
// never be emitted as a failure (SNTR-ERR-001), so it is mapped to
// Internal here rather than escaping as a success-shaped result.
func NewWireErrorResult(code ErrorCode, msg string) *RpcResult {
	if code == ErrorCodeUnspecified {
		code = ErrorCodeInternal
	}
	return &RpcResult{Outcome: &syntrav1.RpcResult_Error{Error: &syntrav1.RpcError{Code: code, Message: msg}}}
}

// RpcError is the binding control error. It is returned as a Go error
// from validators, session machines, and transport pumps so callers can
// fail fast. Wire failures inside RpcResult use the generated
// syntrav1.RpcError; convert at the codec boundary with ToWire /
// RpcErrorFromWire.
type RpcError struct {
	// Code is nonzero on emission; unknown received numbers map to
	// ErrorCodeUnknown per SNTR-ERR-005.
	Code ErrorCode
	// Message is public failure text safe to return to the peer. It MUST
	// NOT contain credentials, tokens, or private diagnostics
	// (SNTR-ERR-003). Callers branch on Code, never on Message.
	Message string
}

// ToWire converts a control error to its wire form.
func (e *RpcError) ToWire() *syntrav1.RpcError {
	if e == nil {
		return nil
	}
	return &syntrav1.RpcError{Code: e.Code, Message: e.Message}
}

// RpcErrorFromWire converts a wire failure to its control form,
// normalizing unknown codes to ErrorCodeUnknown.
func RpcErrorFromWire(w *syntrav1.RpcError) *RpcError {
	if w == nil {
		return nil
	}
	return &RpcError{Code: NormalizeErrorCode(int32(w.GetCode())), Message: w.GetMessage()}
}

// ErrorCodeName returns the canonical UPPER_SNAKE_CASE registry name for
// c. Unknown numbers report as ERROR_CODE_UNKNOWN so logs never print a
// bare integer for a failure code.
func ErrorCodeName(c ErrorCode) string {
	switch c {
	case ErrorCodeUnspecified:
		return "ERROR_CODE_UNSPECIFIED"
	case ErrorCodeCancelled:
		return "ERROR_CODE_CANCELLED"
	case ErrorCodeUnknown:
		return "ERROR_CODE_UNKNOWN"
	case ErrorCodeInvalidArgument:
		return "ERROR_CODE_INVALID_ARGUMENT"
	case ErrorCodeDeadlineExceeded:
		return "ERROR_CODE_DEADLINE_EXCEEDED"
	case ErrorCodeNotFound:
		return "ERROR_CODE_NOT_FOUND"
	case ErrorCodeAlreadyExists:
		return "ERROR_CODE_ALREADY_EXISTS"
	case ErrorCodePermissionDenied:
		return "ERROR_CODE_PERMISSION_DENIED"
	case ErrorCodeResourceExhausted:
		return "ERROR_CODE_RESOURCE_EXHAUSTED"
	case ErrorCodeFailedPrecondition:
		return "ERROR_CODE_FAILED_PRECONDITION"
	case ErrorCodeAborted:
		return "ERROR_CODE_ABORTED"
	case ErrorCodeOutOfRange:
		return "ERROR_CODE_OUT_OF_RANGE"
	case ErrorCodeUnimplemented:
		return "ERROR_CODE_UNIMPLEMENTED"
	case ErrorCodeInternal:
		return "ERROR_CODE_INTERNAL"
	case ErrorCodeUnavailable:
		return "ERROR_CODE_UNAVAILABLE"
	case ErrorCodeDataLoss:
		return "ERROR_CODE_DATA_LOSS"
	case ErrorCodeUnauthenticated:
		return "ERROR_CODE_UNAUTHENTICATED"
	default:
		return "ERROR_CODE_UNKNOWN"
	}
}

// NormalizeErrorCode maps any received int32 to the registry, returning
// ErrorCodeUnknown for numbers outside 0..16 (SNTR-ERR-005). Generated
// enum getters alone do not implement that policy, so every decode path
// must normalize before branching.
func NormalizeErrorCode(n int32) ErrorCode {
	if n < 0 || n > 16 {
		return ErrorCodeUnknown
	}
	return ErrorCode(n)
}

// IsValidFailure reports whether c is a legal failure outcome: any code
// except ErrorCodeUnspecified. Unspecified is representable on the wire
// but must never be emitted as an RpcError code (SNTR-ERR-001/005).
func IsValidFailure(c ErrorCode) bool {
	return c != ErrorCodeUnspecified && c >= ErrorCodeCancelled && c <= ErrorCodeUnauthenticated
}

// NewRpcError builds an *RpcError with code c and public message msg. It
// is fail-fast: an Unspecified code returns an Internal error carrying
// the caller message for triage, so an invalid emission can never escape
// as a success-shaped result.
func NewRpcError(c ErrorCode, msg string) *RpcError {
	if !IsValidFailure(c) {
		return &RpcError{Code: ErrorCodeInternal, Message: fmt.Sprintf("syntra: invalid error code %d for failure %q", int32(c), msg)}
	}
	return &RpcError{Code: c, Message: msg}
}

// Error implements the error interface for *RpcError. It prints the
// registry name plus the public message; the message is already public
// text, so this is safe to log.
func (e *RpcError) Error() string {
	if e == nil {
		return "syntra: nil RpcError"
	}
	return fmt.Sprintf("syntra: %s: %s", ErrorCodeName(e.Code), e.Message)
}

// Unwrap returns nil: RpcError is a leaf value, not a wrapper.
func (e *RpcError) Unwrap() error { return nil }

// Branch-on-code helpers. Each predicate takes the normalized code so
// callers can branch without string-matching on Message.

// IsCancelled reports whether c is Cancelled.
func IsCancelled(c ErrorCode) bool { return NormalizeErrorCode(int32(c)) == ErrorCodeCancelled }

// IsUnknown reports whether c is Unknown (including out-of-range numbers).
func IsUnknown(c ErrorCode) bool { return NormalizeErrorCode(int32(c)) == ErrorCodeUnknown }

// IsInvalidArgument reports whether c is InvalidArgument.
func IsInvalidArgument(c ErrorCode) bool {
	return NormalizeErrorCode(int32(c)) == ErrorCodeInvalidArgument
}

// IsDeadlineExceeded reports whether c is DeadlineExceeded.
func IsDeadlineExceeded(c ErrorCode) bool {
	return NormalizeErrorCode(int32(c)) == ErrorCodeDeadlineExceeded
}

// IsNotFound reports whether c is NotFound.
func IsNotFound(c ErrorCode) bool { return NormalizeErrorCode(int32(c)) == ErrorCodeNotFound }

// IsAlreadyExists reports whether c is AlreadyExists.
func IsAlreadyExists(c ErrorCode) bool {
	return NormalizeErrorCode(int32(c)) == ErrorCodeAlreadyExists
}

// IsPermissionDenied reports whether c is PermissionDenied.
func IsPermissionDenied(c ErrorCode) bool {
	return NormalizeErrorCode(int32(c)) == ErrorCodePermissionDenied
}

// IsResourceExhausted reports whether c is ResourceExhausted.
func IsResourceExhausted(c ErrorCode) bool {
	return NormalizeErrorCode(int32(c)) == ErrorCodeResourceExhausted
}

// IsFailedPrecondition reports whether c is FailedPrecondition.
func IsFailedPrecondition(c ErrorCode) bool {
	return NormalizeErrorCode(int32(c)) == ErrorCodeFailedPrecondition
}

// IsAborted reports whether c is Aborted.
func IsAborted(c ErrorCode) bool { return NormalizeErrorCode(int32(c)) == ErrorCodeAborted }

// IsOutOfRange reports whether c is OutOfRange.
func IsOutOfRange(c ErrorCode) bool { return NormalizeErrorCode(int32(c)) == ErrorCodeOutOfRange }

// IsUnimplemented reports whether c is Unimplemented.
func IsUnimplemented(c ErrorCode) bool {
	return NormalizeErrorCode(int32(c)) == ErrorCodeUnimplemented
}

// IsInternal reports whether c is Internal.
func IsInternal(c ErrorCode) bool { return NormalizeErrorCode(int32(c)) == ErrorCodeInternal }

// IsUnavailable reports whether c is Unavailable.
func IsUnavailable(c ErrorCode) bool { return NormalizeErrorCode(int32(c)) == ErrorCodeUnavailable }

// IsDataLoss reports whether c is DataLoss.
func IsDataLoss(c ErrorCode) bool { return NormalizeErrorCode(int32(c)) == ErrorCodeDataLoss }

// IsUnauthenticated reports whether c is Unauthenticated.
func IsUnauthenticated(c ErrorCode) bool {
	return NormalizeErrorCode(int32(c)) == ErrorCodeUnauthenticated
}

// Category helpers group codes the way retry and policy layers branch on
// them. Retriability here is non-binding; rpc.md section 1I governs.

// IsAuthFailure reports whether c denies the caller (Unauthenticated or
// PermissionDenied).
func IsAuthFailure(c ErrorCode) bool {
	switch NormalizeErrorCode(int32(c)) {
	case ErrorCodeUnauthenticated, ErrorCodePermissionDenied:
		return true
	default:
		return false
	}
}

// IsRetryable identifies codes for which an application may consider another
// attempt with backoff. It does not establish idempotency or authorize replay.
// Unavailable can leave effects unknown; Aborted requires a new application
// decision. The caller must establish its operation's retry and deduplication
// contract before issuing another request.
func IsRetryable(c ErrorCode) bool {
	switch NormalizeErrorCode(int32(c)) {
	case ErrorCodeUnavailable, ErrorCodeAborted, ErrorCodeResourceExhausted:
		return true
	default:
		return false
	}
}

// IsClientError reports whether c is the caller's fault. These never trip
// breakers or alerts.
func IsClientError(c ErrorCode) bool {
	switch NormalizeErrorCode(int32(c)) {
	case ErrorCodeInvalidArgument,
		ErrorCodeNotFound,
		ErrorCodeAlreadyExists,
		ErrorCodePermissionDenied,
		ErrorCodeFailedPrecondition,
		ErrorCodeAborted,
		ErrorCodeOutOfRange,
		ErrorCodeUnimplemented,
		ErrorCodeUnauthenticated,
		ErrorCodeCancelled:
		return true
	default:
		return false
	}
}

// IsServerError reports whether c is the host's fault. These feed breaker
// and alerting policy.
func IsServerError(c ErrorCode) bool {
	switch NormalizeErrorCode(int32(c)) {
	case ErrorCodeUnknown, ErrorCodeDeadlineExceeded, ErrorCodeInternal, ErrorCodeUnavailable, ErrorCodeDataLoss:
		return true
	default:
		return false
	}
}

// ValidateFrameSize rejects a wire length above the 1 MiB bound before
// the caller allocates a decode buffer. Negative lengths are caller bugs
// and are rejected as InvalidArgument rather than panicking.
func ValidateFrameSize(n int) error {
	if n < 0 {
		return NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: negative frame size %d", n))
	}
	if n > MaxFrameBytes {
		return NewRpcError(ErrorCodeResourceExhausted, fmt.Sprintf("syntra: frame size %d exceeds 1MiB bound %d", n, MaxFrameBytes))
	}
	return nil
}

// ValidateVersion checks that v is a legal Syntra version: nonzero and
// within the binding's supported range. Hello carries the proposed
// maximum and post-hello frames carry the negotiated version; both are
// checked with this function at their respective stages (negotiation
// overlap is decided by NegotiateVersion).
func ValidateVersion(v uint32) error {
	if v == 0 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: version 0 is never negotiated")
	}
	if v < MinSupportedVersion || v > MaxSupportedVersion {
		return NewRpcError(ErrorCodeOutOfRange, fmt.Sprintf("syntra: version %d outside supported range [%d,%d]", v, MinSupportedVersion, MaxSupportedVersion))
	}
	return nil
}

// ValidateBodyCardinality enforces exactly-one body set on f. An unset
// body is representable by the generated codec but is never valid on the
// wire (RFC 0001 B4).
func ValidateBodyCardinality(f *Frame) error {
	if f == nil {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil frame")
	}
	if BodyKindOf(f) == BodyKindNone {
		// Distinguish empty from multi-set for triage: the generated
		// getters collapse duplicates, so the codec pre-scan is the
		// authoritative duplicate detector; here an empty body is the
		// common case.
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: frame has no body set")
	}
	return nil
}

// ValidateRequestID enforces request_id polarity: zero only for hello,
// ready, and notification; nonzero for request, result, and cancel
// (SNTR-WIRE-003, SNTR-RPC-002/010). It requires exactly-one body first
// so the polarity rule has an unambiguous discriminant.
func ValidateRequestID(f *Frame) error {
	if f == nil {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil frame")
	}
	if err := ValidateBodyCardinality(f); err != nil {
		return err
	}
	kind := BodyKindOf(f)
	switch kind {
	case BodyKindHello, BodyKindReady, BodyKindNotification:
		if f.GetRequestId() != 0 {
			return NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: %s frame must carry request_id 0, got %d", string(kind), f.GetRequestId()))
		}
		return nil
	case BodyKindRequest, BodyKindResult, BodyKindCancel:
		if f.GetRequestId() == 0 {
			return NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: %s frame must carry nonzero request_id", string(kind)))
		}
		return nil
	default:
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: frame has no body set")
	}
}

// ValidateHello checks the nested ClientHello: nonzero versions with
// min <= max (SNTR-HS-020). Credential emptiness is host policy, not a
// parse error, so it is not checked here; the host's CredentialPolicy
// decides.
func ValidateHello(h *ClientHello) error {
	if h == nil {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil hello")
	}
	if h.GetMinVersion() == 0 || h.GetMaxVersion() == 0 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: hello versions must be nonzero")
	}
	if h.GetMinVersion() > h.GetMaxVersion() {
		return NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: hello min_version %d exceeds max_version %d", h.GetMinVersion(), h.GetMaxVersion()))
	}
	return nil
}

// ValidateReady checks the nested ServerReady. ConnectionId must be
// non-empty opaque text; it is never an authenticator (SNTR-SESS-002).
func ValidateReady(r *ServerReady) error {
	if r == nil {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil ready")
	}
	if r.GetConnectionId() == "" {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: ready connection_id must be non-empty")
	}
	return nil
}

// ValidateResult checks the nested RpcResult: exactly one outcome must be
// selected, even for a zero-byte success (SNTR-WIRE-007). The oneof
// carries presence, so a nil outcome is never success. An error outcome
// must carry a nonzero code; unknown nonzero codes are accepted here and
// mapped to ErrorCodeUnknown by the codec normalization (SNTR-ERR-005),
// so receipt never crashes or reports success for a future code.
// Emission strictness stays in the constructors (NewRpcError rejects
// Unspecified; MarshalFrame normalizes before encoding).
func ValidateResult(r *RpcResult) error {
	if r == nil {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil result")
	}
	switch outcome := r.GetOutcome().(type) {
	case *syntrav1.RpcResult_Payload:
		return nil
	case *syntrav1.RpcResult_Error:
		if outcome == nil || outcome.Error == nil {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: result must select exactly one outcome (payload or error)")
		}
		if outcome.Error.GetCode() == ErrorCodeUnspecified {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: result error code is not a valid failure")
		}
		return nil
	default:
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: result must select exactly one outcome (payload or error)")
	}
}

// ValidateFrame runs the full stateless Frame validation: version,
// exactly-one body, request_id polarity, and per-body nested rules.
// Reserved numbers/names are a codec pre-scan concern; by the time a
// Frame value exists the reserved alternatives cannot be represented, so
// there is nothing to re-check here beyond cardinality. ACTIVE gating is
// stateful and lives in ValidateFrameForState.
func ValidateFrame(f *Frame) error {
	return validateFrame(f, true)
}

// validateFrame defers request method validation only on decode, allowing
// the host to answer INVALID_ARGUMENT for a structurally routable request.
func validateFrame(f *Frame, validateRequestMethod bool) error {
	if f == nil {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil frame")
	}
	if err := ValidateBodyCardinality(f); err != nil {
		return err
	}
	if err := ValidateRequestID(f); err != nil {
		return err
	}
	if BodyKindOf(f) == BodyKindHello {
		if f.GetVersion() == 0 {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: hello version must be nonzero")
		}
		hello := f.GetHello()
		if err := ValidateHello(hello); err != nil {
			return err
		}
		if f.GetVersion() != hello.GetMaxVersion() {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: hello version must equal max_version")
		}
		return nil
	}
	if err := ValidateVersion(f.GetVersion()); err != nil {
		return err
	}
	switch BodyKindOf(f) {
	case BodyKindReady:
		return ValidateReady(f.GetReady())
	case BodyKindRequest:
		req := f.GetRequest()
		if req == nil {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil request")
		}
		if validateRequestMethod {
			return ValidateMethod(req.GetMethod())
		}
		return nil
	case BodyKindResult:
		return ValidateResult(f.GetResult())
	case BodyKindCancel:
		if f.GetCancel() == nil {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil cancel")
		}
		return nil
	case BodyKindNotification:
		if f.GetNotification() == nil {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil notification")
		}
		return nil
	default:
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: frame has no body set")
	}
}

// ConnectionState is the Syntra connection lifecycle state
// (SNTR-HS-001). Only six states exist; no shortcut such as CONNECTED to
// ACTIVE is permitted.
type ConnectionState int

const (
	// StateConnected means transport is up with no Syntra bytes exchanged.
	StateConnected ConnectionState = iota
	// StateNegotiating means hello was sent and version is under review.
	StateNegotiating ConnectionState = iota
	// StateAuthenticating means version overlap was found and credential policy runs.
	StateAuthenticating ConnectionState = iota
	// StateActive means handshake completed and RPCs plus notifications are legal.
	StateActive ConnectionState = iota
	// StateClosing means graceful close is in progress; no new RPCs are accepted.
	StateClosing ConnectionState = iota
	// StateClosed means transport is released and per-connection state is discarded.
	StateClosed ConnectionState = iota
)

// String returns the diagnostic name for s.
func (s ConnectionState) String() string {
	switch s {
	case StateConnected:
		return "CONNECTED"
	case StateNegotiating:
		return "NEGOTIATING"
	case StateAuthenticating:
		return "AUTHENTICATING"
	case StateActive:
		return "ACTIVE"
	case StateClosing:
		return "CLOSING"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// ValidateFrameForState enforces no app frames before ACTIVE: request,
// result, cancel, and notification are rejected in CONNECTED,
// NEGOTIATING, AUTHENTICATING, CLOSING, and CLOSED. Hello and ready are
// handshake frames and pass through to ValidateFrame; CLOSED rejects
// everything including handshake frames.
func ValidateFrameForState(f *Frame, st ConnectionState) error {
	if f == nil {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: nil frame")
	}
	if st == StateClosed {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: connection is closed")
	}
	if err := ValidateFrame(f); err != nil {
		return err
	}
	if st == StateActive {
		return nil
	}
	switch BodyKindOf(f) {
	case BodyKindRequest, BodyKindResult, BodyKindCancel, BodyKindNotification:
		return NewRpcError(ErrorCodeFailedPrecondition, fmt.Sprintf("syntra: %s frame not allowed before ACTIVE (state %s)", string(BodyKindOf(f)), st.String()))
	default:
		return nil
	}
}

// NegotiateVersion selects the highest version in the intersection of the
// initiator range and the binding range. It fails closed on empty ranges,
// inverted ranges, and disjoint ranges.
func NegotiateVersion(min, max uint32) (uint32, error) {
	if min == 0 || max == 0 {
		return 0, NewRpcError(ErrorCodeInvalidArgument, "syntra: hello versions must be nonzero")
	}
	if min > max {
		return 0, NewRpcError(ErrorCodeInvalidArgument, "syntra: hello min_version exceeds max_version")
	}
	lo := min
	if MinSupportedVersion > lo {
		lo = MinSupportedVersion
	}
	hi := max
	if MaxSupportedVersion < hi {
		hi = MaxSupportedVersion
	}
	if lo > hi {
		return 0, NewRpcError(ErrorCodeUnimplemented, "syntra: no shared version overlap")
	}
	return hi, nil
}

// NegotiateVersionRanges selects the highest version in the overlap of an
// explicit client range and an explicit server range. It is the testable
// core behind NegotiateVersion: callers that carry a configured server
// range use this instead of the binding singleton. All four bounds must
// be nonzero with min <= max per side; disjoint ranges fail as
// FailedPrecondition to distinguish an incompatible peer from malformed input.
func NegotiateVersionRanges(clientMin, clientMax, serverMin, serverMax uint32) (uint32, error) {
	if clientMin == 0 || clientMax == 0 {
		return 0, NewRpcError(ErrorCodeInvalidArgument, "syntra: hello versions must be nonzero")
	}
	if clientMin > clientMax {
		return 0, NewRpcError(ErrorCodeInvalidArgument, "syntra: hello min_version exceeds max_version")
	}
	if serverMin == 0 || serverMax == 0 {
		return 0, NewRpcError(ErrorCodeInternal, "syntra: server version range misconfigured")
	}
	if serverMin > serverMax {
		return 0, NewRpcError(ErrorCodeInternal, "syntra: server min_version exceeds max_version")
	}
	floor := clientMin
	if serverMin > floor {
		floor = serverMin
	}
	ceiling := clientMax
	if serverMax < ceiling {
		ceiling = serverMax
	}
	if ceiling < floor {
		return 0, NewRpcError(ErrorCodeFailedPrecondition, fmt.Sprintf("syntra: no version overlap (client [%d,%d], server [%d,%d])", clientMin, clientMax, serverMin, serverMax))
	}
	return ceiling, nil
}

// HandshakeConfig carries the local supported version range. The zero
// value selects the binding singleton (v1); construct via
// NewHandshakeConfig so the fail-fast range check cannot be skipped.
type HandshakeConfig struct {
	// ServerMinVersion is the lowest version the local side accepts.
	ServerMinVersion uint32
	// ServerMaxVersion is the highest version the local side emits.
	ServerMaxVersion uint32
}

// NewHandshakeConfig validates the version range up front, defaulting
// zero fields to the binding singleton.
func NewHandshakeConfig(cfg HandshakeConfig) (HandshakeConfig, error) {
	if cfg.ServerMinVersion == 0 {
		cfg.ServerMinVersion = MinSupportedVersion
	}
	if cfg.ServerMaxVersion == 0 {
		cfg.ServerMaxVersion = MaxSupportedVersion
	}
	if cfg.ServerMinVersion > cfg.ServerMaxVersion {
		return HandshakeConfig{}, fmt.Errorf("syntra: server min_version %d exceeds max_version %d", cfg.ServerMinVersion, cfg.ServerMaxVersion)
	}
	return cfg, nil
}

// Connection is the stateful handshake machine for one side of a
// transport. It wraps the pure NextState transition with a mutex so
// concurrent read and write loops cannot interleave hello and close.
// Callers that prefer explicit control flow can use NextState directly
// and skip Connection entirely; both enforce the same six-state set.
// The bound principal is an opaque host-defined string (never client
// bytes); identity verification lives in the host's CredentialPolicy.
type Connection struct {
	mu        sync.Mutex
	state     ConnectionState
	config    HandshakeConfig
	version   uint32
	principal string
}

// NewConnection returns a Connection in StateConnected. A misconfigured
// range fails fast here rather than at the first hello.
func NewConnection(cfg HandshakeConfig) (*Connection, error) {
	validated, err := NewHandshakeConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("syntra: invalid handshake config: %w", err)
	}
	return &Connection{state: StateConnected, config: validated}, nil
}

// State returns the current connection state.
func (c *Connection) State() ConnectionState {
	if c == nil {
		return StateClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

// Version returns the negotiated version, or 0 before negotiation.
func (c *Connection) Version() uint32 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// Principal returns the principal bound at activation, or "" before.
func (c *Connection) Principal() string {
	if c == nil {
		return ""
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.principal
}

// OnHello handles a ClientHello in StateConnected: it validates the
// hello, negotiates the highest overlap against the configured range,
// and advances to StateNegotiating. Any other state, a malformed hello,
// or a disjoint range leaves the state unchanged so the caller can
// divert to CLOSING.
func (c *Connection) OnHello(h *ClientHello) (uint32, error) {
	if c == nil {
		return 0, NewRpcError(ErrorCodeInternal, "syntra: nil connection")
	}
	if h == nil {
		return 0, NewRpcError(ErrorCodeInvalidArgument, "syntra: nil hello")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateConnected {
		return 0, NewRpcError(ErrorCodeFailedPrecondition, fmt.Sprintf("syntra: hello not allowed in state %s", c.state.String()))
	}
	if err := ValidateHello(h); err != nil {
		return 0, err
	}
	v, err := NegotiateVersionRanges(h.MinVersion, h.MaxVersion, c.config.ServerMinVersion, c.config.ServerMaxVersion)
	if err != nil {
		return 0, err
	}
	c.version = v
	c.state = StateNegotiating
	return v, nil
}

// BeginAuth advances StateNegotiating to StateAuthenticating when
// credential verification starts. It is separate from OnHello so the
// caller can rate-limit or async-dispatch verification without holding
// the handshake mutex across I/O.
func (c *Connection) BeginAuth() error {
	if c == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil connection")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateNegotiating {
		return NewRpcError(ErrorCodeFailedPrecondition, fmt.Sprintf("syntra: begin-auth not allowed in state %s", c.state.String()))
	}
	c.state = StateAuthenticating
	return nil
}

// AuthSuccess binds principal and advances StateAuthenticating to
// StateActive. An empty principal fails fast without mutating state: an
// anonymous activation would violate the ServerReady binding contract.
func (c *Connection) AuthSuccess(principal string) error {
	if c == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil connection")
	}
	if principal == "" {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: principal must be non-empty at activation")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateAuthenticating {
		return NewRpcError(ErrorCodeFailedPrecondition, fmt.Sprintf("syntra: auth-success not allowed in state %s", c.state.String()))
	}
	c.principal = principal
	c.state = StateActive
	return nil
}

// AuthFailure moves StateAuthenticating to StateClosing: the credential
// was presented but rejected, so no app frames were ever allowed.
func (c *Connection) AuthFailure() error {
	if c == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil connection")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateAuthenticating {
		return NewRpcError(ErrorCodeFailedPrecondition, fmt.Sprintf("syntra: auth-failure not allowed in state %s", c.state.String()))
	}
	c.state = StateClosing
	return nil
}

// Close initiates the drain from any non-terminal state into
// StateClosing. Closing from CLOSING is idempotent; closing from CLOSED
// is an error so double-close bugs surface instead of passing.
func (c *Connection) Close() error {
	if c == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil connection")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch c.state {
	case StateClosing:
		return nil
	case StateClosed:
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: connection already closed")
	default:
		c.state = StateClosing
		return nil
	}
}

// MarkClosed moves StateClosing to the terminal StateClosed once the
// drain completes. It is the only path into CLOSED; every other state
// must pass through Close first so in-flight RPCs are never dropped
// without a drain.
func (c *Connection) MarkClosed() error {
	if c == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil connection")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateClosing {
		return NewRpcError(ErrorCodeFailedPrecondition, fmt.Sprintf("syntra: mark-closed not allowed in state %s", c.state.String()))
	}
	c.state = StateClosed
	return nil
}

// NextState validates one handshake transition. It enforces the
// six-state machine: unexpected messages before ACTIVE fail with
// FailedPrecondition, a second hello fails, and re-handshake on the same
// connection is forbidden. The caller owns timer and transport-close
// behavior.
func NextState(current ConnectionState, kind BodyKind) (ConnectionState, error) {
	if current == StateClosed {
		return StateClosed, NewRpcError(ErrorCodeFailedPrecondition, "syntra: connection is closed")
	}
	switch current {
	case StateConnected:
		if kind != BodyKindHello {
			return StateClosing, NewRpcError(ErrorCodeFailedPrecondition, "syntra: first frame must be hello")
		}
		return StateNegotiating, nil
	case StateNegotiating:
		return StateClosing, NewRpcError(ErrorCodeFailedPrecondition, "syntra: unexpected frame during negotiation")
	case StateAuthenticating:
		return StateClosing, NewRpcError(ErrorCodeFailedPrecondition, "syntra: unexpected frame during authentication")
	case StateActive:
		if kind == BodyKindHello || kind == BodyKindReady {
			return StateClosing, NewRpcError(ErrorCodeFailedPrecondition, "syntra: re-handshake on the same connection is forbidden")
		}
		return StateActive, nil
	case StateClosing:
		return StateClosing, NewRpcError(ErrorCodeFailedPrecondition, "syntra: connection is closing")
	default:
		return StateClosing, NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: unknown connection state %d", int(current)))
	}
}

// ValidateCredentialSize rejects oversized credentials before any
// verifier runs. Empty credentials are an authentication attempt subject
// to host policy, not a parse error.
func ValidateCredentialSize(credential []byte) error {
	if len(credential) > MaxCredentialBytes {
		return NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: credential size %d exceeds bound %d", len(credential), MaxCredentialBytes))
	}
	return nil
}

// NewConnectionID generates a fresh 128-bit random identifier hex-encoded
// to 32 lowercase characters for ServerReady.connection_id. It fails
// closed on RNG failure so a predictable fallback ID can never be emitted.
func NewConnectionID() (string, error) {
	var buf [ConnectionIDBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", NewRpcError(ErrorCodeInternal, fmt.Sprintf("syntra: connection_id RNG failed: %v", err))
	}
	return hex.EncodeToString(buf[:]), nil
}

// CredentialPolicy authenticates an opaque credential and returns the
// principal string to bind at ServerReady. Implementations own identity:
// this binding never interprets credential bytes beyond the size bound.
// An empty credential is an attempt subject to host policy: policies may
// accept it for anonymous-intent deployments or reject it with
// Unauthenticated. The credential bytes and any derived token must never
// be logged. Implementations should accept ctx with a bounded budget and
// return Unauthenticated for rejections vs Internal for verifier outages
// so the handshake can distinguish policy denial from downstream failure.
type CredentialPolicy func(ctx context.Context, credential []byte) (principal string, err error)

// ValidateMethod checks that method is a canonical /package.Service/Method
// identifier (SNTR-RPC-001): leading slash, exactly two slashes,
// non-empty segments, printable ASCII excluding spaces and control
// characters, within MaxMethodLength. It rejects empty values, missing
// separators, and oversized inputs before any handler lookup runs.
// Deployments MAY narrow this further (e.g. per-segment character
// classes); they MUST NOT widen it.
func ValidateMethod(method string) error {
	if method == "" {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: method must be non-empty")
	}
	if len(method) > MaxMethodLength {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: method exceeds length bound")
	}
	if !strings.HasPrefix(method, "/") {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: method must start with /")
	}
	rest := strings.TrimPrefix(method, "/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: method must be /package.Service/Method")
	}
	for _, r := range method {
		if r <= 0x20 || r > 0x7e {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: method must be printable ASCII")
		}
	}
	return nil
}

// ValidatePayloadSize rejects an opaque payload above the per-RPC bound
// before the caller retains it.
func ValidatePayloadSize(n int) error {
	if n < 0 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: negative payload size")
	}
	if n > MaxPayloadBytes {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: payload exceeds bound")
	}
	return nil
}

// callEntry is one outstanding call: its canonical method, absolute
// deadline, and best-effort cancellation flag. Cancelled is set by
// Cancel; the worker observes it via IsCancelled and abandons work, but a
// late Result is still accepted because cancellation is advisory, never
// rollback (SNTR-RPC-005).
type callEntry struct {
	method    string
	deadline  time.Time
	cancelled bool
}

// Tracker correlates nonzero request IDs with exactly-one terminal
// results. It is safe for concurrent use by receive and timeout workers.
type Tracker struct {
	mu      sync.Mutex
	pending map[uint64]*callEntry
}

// NewTracker constructs an empty RPC correlation tracker.
func NewTracker() *Tracker {
	return &Tracker{pending: make(map[uint64]*callEntry)}
}

// Start registers requestID for method. It fails closed on zero IDs,
// duplicate IDs, uncanonical methods, and budget exhaustion. The call
// deadline is now plus DefaultRPCTimeout; use StartWithBudget for an
// explicit client budget.
func (t *Tracker) Start(requestID uint64, method string) error {
	return t.StartWithBudget(time.Now(), requestID, method, 0)
}

// StartWithBudget registers requestID for method with a timeout budget of
// timeoutMs (zero selects DefaultRPCTimeout). Budgets above
// MaxRPCTimeoutMs fail fast as OutOfRange. now anchors the deadline;
// callers pass time.Now in production and a fixed clock in tests.
func (t *Tracker) StartWithBudget(now time.Time, requestID uint64, method string, timeoutMs uint32) error {
	if t == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil tracker")
	}
	if requestID == 0 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: request must carry nonzero request_id")
	}
	if err := ValidateMethod(method); err != nil {
		return err
	}
	if timeoutMs > MaxRPCTimeoutMs {
		return NewRpcError(ErrorCodeOutOfRange, fmt.Sprintf("syntra: timeout_ms %d exceeds max %d", timeoutMs, MaxRPCTimeoutMs))
	}
	budget := DefaultRPCTimeout
	if timeoutMs > 0 {
		budget = time.Duration(timeoutMs) * time.Millisecond
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.pending[requestID]; exists {
		return NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: duplicate request_id %d", requestID))
	}
	if len(t.pending) >= MaxConcurrentRPCs {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: too many concurrent RPCs")
	}
	t.pending[requestID] = &callEntry{method: method, deadline: now.Add(budget)}
	return nil
}

// Finish releases requestID after its terminal result. It fails closed on
// unknown IDs so result storms cannot corrupt the table. A nil result is
// InvalidArgument; callers that decode a result should pass the decoded
// value through ValidateResult first so a both/neither outcome is
// rejected before the table is touched.
func (t *Tracker) Finish(requestID uint64) error {
	return t.FinishResult(requestID, NewSuccessResult(nil))
}

// FinishResult completes requestID with exactly one terminal result: a
// both/neither outcome or an error result with an Unspecified code is
// InvalidArgument and the id stays outstanding; an unknown id is
// InvalidArgument so duplicate finishes cannot corrupt the table.
func (t *Tracker) FinishResult(requestID uint64, result *RpcResult) error {
	if t == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil tracker")
	}
	if requestID == 0 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: result must carry nonzero request_id")
	}
	if err := ValidateResult(result); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, exists := t.pending[requestID]; !exists {
		return NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: unknown request_id %d", requestID))
	}
	delete(t.pending, requestID)
	return nil
}

// Cancel marks requestID as cancelled best-effort: it returns true when
// the id is outstanding (the worker should observe IsCancelled and
// abandon work), false when unknown (already finished, expired, or never
// started). Cancel never deletes the call and never returns an error; a
// late Result after Cancel is still accepted because cancellation is
// advisory, never rollback (SNTR-RPC-005).
func (t *Tracker) Cancel(requestID uint64) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.pending[requestID]
	if !ok {
		return false
	}
	e.cancelled = true
	return true
}

// IsCancelled reports whether requestID is outstanding and marked
// cancelled. It returns false for unknown ids so workers can poll
// without branching on existence first.
func (t *Tracker) IsCancelled(requestID uint64) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.pending[requestID]
	return ok && e.cancelled
}

// Expired returns the ids whose deadlines are at or before now and
// removes them from the outstanding set. The caller fails each with a
// DeadlineExceeded result; removal here guarantees exactly-one terminal
// semantics (a late Finish for an expired id reports unknown).
func (t *Tracker) Expired(now time.Time) []uint64 {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []uint64
	for id, e := range t.pending {
		if !now.Before(e.deadline) {
			out = append(out, id)
		}
	}
	for _, id := range out {
		delete(t.pending, id)
	}
	return out
}

// Pending returns the count of in-flight RPCs for backpressure triage.
func (t *Tracker) Pending() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.pending)
}

// MarshalFrame encodes f to protobuf binary wire bytes. It validates both
// the frame value and the emitted wire, including retained unknown fields.
func MarshalFrame(f *Frame) ([]byte, error) {
	if err := ValidateFrame(f); err != nil {
		return nil, err
	}
	if hello := f.GetHello(); hello != nil {
		if err := ValidateCredentialSize(hello.GetCredential()); err != nil {
			return nil, err
		}
	}
	// Normalize unknown wire codes on emission: an RpcError with an
	// out-of-range code never escapes; callers branch on code, never on
	// Message text (SNTR-ERR-003/005).
	if res := f.GetResult(); res != nil {
		if werr := res.GetError(); werr != nil {
			werr.Code = NormalizeErrorCode(int32(werr.GetCode()))
		}
	}
	if err := ValidateFrameSize(proto.Size(f)); err != nil {
		return nil, err
	}
	out, err := proto.Marshal(f)
	if err != nil {
		return nil, NewRpcError(ErrorCodeInternal, fmt.Sprintf("syntra: marshal frame: %v", err))
	}
	if err := ValidateFrameSize(len(out)); err != nil {
		return nil, err
	}
	if err := scanFrameTags(out); err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalFrame decodes exactly one Frame from data. It rejects empty
// inputs, trailing bytes, reserved top-level numbers 16/17, and duplicate
// bodies before running structural validation. Duplicate version/request_id
// occurrences are type-checked but follow protobuf merge semantics
// (last wins), matching the Rust core. Cancel inner bytes and nested
// unassigned numbers are tolerated as unknown fields per SNTR-SER-003.
// Request methods are validated by the host so malformed methods receive
// per-RPC errors. proto.Unmarshal owns decoding; the pre-scan owns protocol
// strictness the generated codec does not enforce (reserved 16/17 and
// duplicate body alternatives). Unknown fields alongside a known body remain
// forward-compatible metadata.
func UnmarshalFrame(data []byte) (*Frame, error) {
	if err := ValidateFrameSize(len(data)); err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: empty binary message")
	}
	if err := scanFrameTags(data); err != nil {
		return nil, err
	}
	var f Frame
	if err := (proto.UnmarshalOptions{RecursionLimit: 32}).Unmarshal(data, &f); err != nil {
		return nil, NewRpcError(ErrorCodeInvalidArgument, fmt.Sprintf("syntra: malformed frame: %v", err))
	}
	// Match the Rust core's unknown-only classification (SNTR-WIRE-004).
	// There is no allocated future-body tag range: with a known body,
	// unknown fields must remain tolerated (SNTR-SER-003). Distinguishing
	// mixed unknown bodies from metadata needs the discriminator in RFC B5.
	if BodyKindOf(&f) == BodyKindNone && len(f.ProtoReflect().GetUnknown()) > 0 {
		return nil, NewRpcError(ErrorCodeUnimplemented, "syntra: unknown frame variant")
	}
	// proto.Unmarshal consumed every tag the pre-scan walked, so a
	// successful unmarshal here consumed exactly one Frame.
	if err := validateFrame(&f, false); err != nil {
		return nil, err
	}
	// Normalize unknown wire codes on receipt per SNTR-ERR-005.
	if res := f.GetResult(); res != nil {
		if werr := res.GetError(); werr != nil {
			werr.Code = NormalizeErrorCode(int32(werr.GetCode()))
		}
	}
	return &f, nil
}

// scanFrameTags walks top-level tags to enforce strictness before
// proto.Unmarshal: reserved 16/17 rejected, duplicate bodies rejected,
// unknown fields skipped, version/request_id type-checked. Duplicate
// version/request_id occurrences follow protobuf merge semantics
// (last value wins in proto.Unmarshal); they are type-checked here but
// not rejected, matching the Rust core and SNTR-SER-002
// non-canonical tolerance. Duplicate bodies remain rejected per
// SNTR-WIRE-002 (see RFC 0001 B4).
func scanFrameTags(data []byte) error {
	bodySeen := false
	raw := data
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 || !num.IsValid() {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed frame tag")
		}
		raw = raw[n:]
		if num == ReservedFrameFieldNumber16 || num == ReservedFrameFieldNumber17 {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: reserved frame field number")
		}
		switch {
		case num == 1:
			if typ != protowire.VarintType {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed version")
			}
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed version")
			}
			if v > math.MaxUint32 {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed version")
			}
			raw = raw[m:]
		case num == 2:
			if typ != protowire.VarintType {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed request_id")
			}
			_, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed request_id")
			}
			raw = raw[m:]
		case num >= 10 && num <= 15:
			if typ != protowire.BytesType {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed body bytes")
			}
			v, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed body bytes")
			}
			raw = raw[m:]
			if bodySeen {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: frame has multiple bodies set")
			}
			bodySeen = true
			// The root Frame counts as depth 1, as in UnmarshalOptions.
			if err := scanNested(num, v, 2); err != nil {
				return err
			}
		default:
			// Unknown top-level fields are forward-compatible metadata:
			// skip per wire type (SNTR-SER-003). Reserved numbers never
			// reach here; they are rejected above.
			var err error
			raw, err = skipUnknown(raw, num, typ, 1)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// skipUnknown consumes one unknown field value per wire type so
// forward-compatible metadata is tolerated and skipped (SNTR-SER-003).
// Groups require matching end tags and share the 32-level message budget.
// Length-delimited unknown values are opaque, not nested messages.
func skipUnknown(raw []byte, num protowire.Number, typ protowire.Type, depth int) ([]byte, error) {
	switch typ {
	case protowire.VarintType:
		_, m := protowire.ConsumeVarint(raw)
		if m < 0 {
			return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed unknown varint field")
		}
		return raw[m:], nil
	case protowire.Fixed64Type:
		_, m := protowire.ConsumeFixed64(raw)
		if m < 0 {
			return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed unknown fixed64 field")
		}
		return raw[m:], nil
	case protowire.BytesType:
		_, m := protowire.ConsumeBytes(raw)
		if m < 0 {
			return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed unknown bytes field")
		}
		return raw[m:], nil
	case protowire.Fixed32Type:
		_, m := protowire.ConsumeFixed32(raw)
		if m < 0 {
			return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed unknown fixed32 field")
		}
		return raw[m:], nil
	case protowire.StartGroupType:
		if depth >= 32 {
			return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: exceeded max recursion depth")
		}
		for len(raw) > 0 {
			child, childType, n := protowire.ConsumeTag(raw)
			if n < 0 || !child.IsValid() {
				return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed unknown group tag")
			}
			raw = raw[n:]
			if childType == protowire.EndGroupType {
				if child != num {
					return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: mismatched unknown end group")
				}
				return raw, nil
			}
			var err error
			raw, err = skipUnknown(raw, child, childType, depth+1)
			if err != nil {
				return nil, err
			}
		}
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: unterminated unknown group")
	default:
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: unsupported wire type")
	}
}

// scanNested walks every message reachable from Frame: its six bodies and
// RpcResult.error (body 0). Only declared message fields recurse; strings,
// payloads, credentials, and length-delimited unknown values stay opaque.
func scanNested(body protowire.Number, data []byte, depth int) error {
	if depth > 32 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: exceeded max recursion depth")
	}
	switch body {
	case 10:
		return scanHello(data, depth)
	case 13:
		return scanResult(data, depth)
	default:
		for len(data) > 0 {
			num, typ, n := protowire.ConsumeTag(data)
			if n < 0 || !num.IsValid() {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed nested message tag")
			}
			var err error
			data, err = skipUnknown(data[n:], num, typ, depth)
			if err != nil {
				return err
			}
		}
		return nil
	}
}

// scanHello checks ClientHello fields 1, 2, 3 for shape and bounds every
// credential occurrence before protobuf can allocate it, including duplicates.
func scanHello(data []byte, depth int) error {
	raw := data
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 || !num.IsValid() {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed hello")
		}
		raw = raw[n:]
		switch {
		case num == 1 || num == 2:
			if typ != protowire.VarintType {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed hello version")
			}
			v, m := protowire.ConsumeVarint(raw)
			if m < 0 {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed hello version")
			}
			if v > math.MaxUint32 {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed hello version")
			}
			raw = raw[m:]
		case num == 3:
			if typ != protowire.BytesType {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed hello credential")
			}
			credential, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed hello credential")
			}
			if err := ValidateCredentialSize(credential); err != nil {
				return err
			}
			raw = raw[m:]
		default:
			// Unknown hello fields are forward-compatible metadata:
			// skip per wire type (SNTR-SER-003).
			var err error
			raw, err = skipUnknown(raw, num, typ, depth)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// scanResult checks RpcResult oneof fields 1 and 2 for cardinality: at
// most one outcome may appear on the wire. A second outcome alternative
// is a duplicate body and is rejected here because the generated decoder
// would silently collapse it into the last one.
func scanResult(data []byte, depth int) error {
	raw := data
	seen := 0
	for len(raw) > 0 {
		num, typ, n := protowire.ConsumeTag(raw)
		if n < 0 || !num.IsValid() {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed result")
		}
		raw = raw[n:]
		switch num {
		case 1, 2:
			if typ != protowire.BytesType {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed result outcome")
			}
			value, m := protowire.ConsumeBytes(raw)
			if m < 0 {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: malformed result outcome")
			}
			raw = raw[m:]
			seen++
			if seen > 1 {
				return NewRpcError(ErrorCodeInvalidArgument, "syntra: result has multiple outcomes")
			}
			if num == 2 {
				if err := scanNested(0, value, depth+1); err != nil {
					return err
				}
			}
		default:
			// Unknown result fields are forward-compatible metadata:
			// skip per wire type (SNTR-SER-003).
			var err error
			raw, err = skipUnknown(raw, num, typ, depth)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
