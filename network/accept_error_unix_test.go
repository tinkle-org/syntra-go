//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package network

import (
	"testing"

	"golang.org/x/sys/unix"
)

func acceptResourceTestError() error { return unix.EMFILE }

func TestAcceptErrorUnixErrnos(t *testing.T) {
	checkAcceptErrnos(t, []error{
		unix.ECONNABORTED, unix.ECONNRESET, unix.ECONNREFUSED, unix.EINTR,
		unix.EAGAIN, unix.EWOULDBLOCK, unix.ETIMEDOUT, unix.ENOMEM, unix.ENFILE,
		unix.EMFILE, unix.ENOBUFS, unix.ENETDOWN, unix.ENETUNREACH, unix.EHOSTUNREACH,
	}, []error{unix.EBADF, unix.EACCES, unix.EPERM, unix.EINVAL, unix.ENOTSOCK, unix.EPIPE})
}
