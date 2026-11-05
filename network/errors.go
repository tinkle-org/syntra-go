package network

import (
	"context"
	"errors"
	"io"
	"net"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

var (
	ErrConfig             = errors.New("network: invalid configuration")
	ErrClosed             = errors.New("network: stopped")
	ErrBusy               = errors.New("network: admission limit reached")
	ErrShutdownIncomplete = errors.New("network: shutdown incomplete; ownership retained")
)

// Failure contains categories and codes only, never arbitrary diagnostics.
type Failure uint8

const (
	FailureNone Failure = iota
	FailureConfiguration
	FailureAuthentication
	FailureProtocol
	FailureFraming
	FailureIO
	FailureTimeout
	FailureClosed
	FailureRuntime
	FailureRecovery
	FailureRecoveryUnavailable
	FailureElapsedContinuity
	FailureGenerationExhausted
	FailureRevisionExhausted
)

func (f Failure) Error() string {
	switch f {
	case FailureNone:
		return "network: no failure"
	case FailureConfiguration:
		return "network: configuration rejected"
	case FailureAuthentication:
		return "network: authentication rejected"
	case FailureProtocol:
		return "network: protocol rejected"
	case FailureFraming:
		return "network: framing rejected"
	case FailureIO:
		return "network: I/O failed"
	case FailureTimeout:
		return "network: timed out"
	case FailureClosed:
		return "network: connection closed"
	case FailureRecovery:
		return "network: recovery failed"
	case FailureRecoveryUnavailable:
		return "network: recovery unavailable"
	case FailureElapsedContinuity:
		return "network: elapsed continuity lost"
	case FailureGenerationExhausted:
		return "network: generation exhausted"
	case FailureRevisionExhausted:
		return "network: revision exhausted"
	default:
		return "network: runtime failed"
	}
}

func (f Failure) Retryable() bool { return f == FailureIO || f == FailureTimeout || f == FailureClosed }

// Classify preserves typed security failures before considering carrier failures.
// An unknown error fails closed. Nil is not a failed connection.
func Classify(err error) Failure {
	if err == nil {
		return FailureNone
	}
	var f Failure
	if errors.As(err, &f) {
		return f
	}
	if errors.Is(err, securechannel.ErrAuth) {
		return FailureAuthentication
	}
	for _, known := range []error{ErrConfig, connection.ErrConfig, securechannel.ErrConfig, ordered.ErrOptions} {
		if errors.Is(err, known) {
			return FailureConfiguration
		}
	}
	if errors.Is(err, securechannel.ErrRecord) || errors.Is(err, securechannel.ErrLimit) {
		return FailureFraming
	}
	if errors.Is(err, ordered.ErrProtocol) {
		return FailureProtocol
	}
	var rpc *syntra.RpcError
	if errors.As(err, &rpc) {
		if rpc == nil {
			return FailureRuntime
		}
		switch rpc.Code {
		case syntra.ErrorCodeUnauthenticated, syntra.ErrorCodePermissionDenied:
			return FailureAuthentication
		case syntra.ErrorCodeDeadlineExceeded:
			return FailureTimeout
		case syntra.ErrorCodeUnavailable:
			return FailureClosed
		case syntra.ErrorCodeInvalidArgument, syntra.ErrorCodeFailedPrecondition:
			return FailureProtocol
		default:
			return FailureRuntime
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, connection.ErrShutdownTimeout) || errors.Is(err, ErrShutdownIncomplete) {
		return FailureTimeout
	}
	for _, known := range []error{ErrClosed, connection.ErrClosed, ordered.ErrClosed, securechannel.ErrClosed, io.EOF, io.ErrUnexpectedEOF, net.ErrClosed, context.Canceled} {
		if errors.Is(err, known) {
			return FailureClosed
		}
	}
	if errors.Is(err, ordered.ErrIO) {
		return FailureIO
	}
	var ne net.Error
	if errors.As(err, &ne) && ne != nil {
		if ne.Timeout() {
			return FailureTimeout
		}
		return FailureIO
	}
	return FailureRuntime
}

type GenerationValue[T any] struct {
	Generation uint64
	Value      T
}

// CallError with a nonzero Generation means that generation may have observed
// the request. OutcomeUnknown is explicit; the supervisor never retries it.
// Generation zero means admission found no usable generation.
type CallError struct {
	Generation     uint64
	OutcomeUnknown bool
	Failure        Failure
	Code           syntra.ErrorCode
	cause          error
}

func (e *CallError) Error() string { return "network: call failed; no automatic replay" }
func (e *CallError) Unwrap() error {
	if e.cause != nil {
		return e.cause
	}
	return e.Failure
}

func callError(g uint64, err error, unknown bool) *CallError {
	e := &CallError{Generation: g, OutcomeUnknown: unknown, Failure: Classify(err), cause: Sanitize(err)}
	var rpc *syntra.RpcError
	if errors.As(err, &rpc) && rpc != nil {
		e.Code = syntra.NormalizeErrorCode(int32(rpc.Code))
	}
	return e
}

// TransportError preserves a stable sentinel or sanitized RPC code for
// errors.Is/errors.As, while dropping the original diagnostic and its object.
type TransportError struct {
	Failure Failure
	Code    syntra.ErrorCode
	cause   error
}

func (e *TransportError) Error() string { return e.Failure.Error() }
func (e *TransportError) Unwrap() error { return e.cause }

func Sanitize(err error) error {
	if err == nil {
		return nil
	}
	e := &TransportError{Failure: Classify(err)}
	var rpc *syntra.RpcError
	if errors.As(err, &rpc) && rpc != nil {
		e.Code = syntra.NormalizeErrorCode(int32(rpc.Code))
		e.cause = syntra.NewRpcError(e.Code, "network: session failed")
		return e
	}
	for _, known := range []error{ErrConfig, ErrClosed, ErrBusy, ErrShutdownIncomplete, connection.ErrConfig, connection.ErrClosed, connection.ErrShutdownTimeout, securechannel.ErrConfig, securechannel.ErrAuth, securechannel.ErrRecord, securechannel.ErrClosed, securechannel.ErrLimit, ordered.ErrOptions, ordered.ErrProtocol, ordered.ErrIO, ordered.ErrClosed, ordered.ErrBusy, context.Canceled, context.DeadlineExceeded, io.EOF, io.ErrUnexpectedEOF, net.ErrClosed} {
		if errors.Is(err, known) {
			e.cause = known
			return e
		}
	}
	e.cause = e.Failure
	return e
}
