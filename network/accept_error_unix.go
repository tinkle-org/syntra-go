//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package network

import (
	"errors"
	"syscall"

	"golang.org/x/sys/unix"
)

func retryableAcceptErrno(err error) bool {
	var code syscall.Errno
	if !errors.As(err, &code) {
		return false
	}
	switch code {
	case unix.ECONNABORTED, unix.ECONNRESET, unix.ECONNREFUSED,
		unix.EINTR, unix.EAGAIN, unix.ETIMEDOUT,
		unix.ENOMEM, unix.ENFILE, unix.EMFILE, unix.ENOBUFS,
		unix.ENETDOWN, unix.ENETUNREACH, unix.EHOSTUNREACH:
		return true
	}
	return retryableAcceptPlatformErrno(code)
}
