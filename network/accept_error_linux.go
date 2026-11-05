package network

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func retryableAcceptPlatformErrno(code syscall.Errno) bool {
	// Linux may return a pending connection's network error from accept itself.
	switch code {
	case unix.ENONET, unix.EPROTO, unix.ENOPROTOOPT, unix.EOPNOTSUPP, unix.EHOSTDOWN:
		return true
	}
	return false
}
