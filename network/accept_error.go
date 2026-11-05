package network

import (
	"errors"
	"net"
)

// acceptError preserves the failure's stage independently of its I/O category.
// In particular, admission and listener-state failures must not retry merely
// because their underlying error implements net.Error.
type acceptError struct {
	cause     error
	retryable bool
}

// Preserve the source error's method set without making Temporary a retry
// decision. Only the explicit accept-stage classification permits retries.
type acceptNetworkError interface {
	error
	Timeout() bool
	Temporary() bool
}

func (e *acceptError) Error() string { return "network: accept failed" }
func (e *acceptError) Unwrap() error { return e.cause }
func (e *acceptError) Timeout() bool {
	var ne net.Error
	return errors.As(e.cause, &ne) && ne.Timeout()
}
func (e *acceptError) Temporary() bool {
	var ne acceptNetworkError
	return errors.As(e.cause, &ne) && ne.Temporary()
}

func socketAcceptError(err error) *acceptError {
	e := &acceptError{cause: err}
	// Temporary is deliberately not a retry policy: unknown errors fail closed.
	// Timeout is the portable net.Error contract; native pending-connection and
	// resource errors need explicit platform classification.
	if !errors.Is(err, net.ErrClosed) {
		e.retryable = e.Timeout() || retryableAcceptErrno(err)
	}
	return e
}
