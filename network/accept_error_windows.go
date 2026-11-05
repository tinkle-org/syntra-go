package network

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

func retryableAcceptErrno(err error) bool {
	var code syscall.Errno
	if !errors.As(err, &code) {
		return false
	}
	switch code {
	case windows.WSAECONNABORTED, windows.WSAECONNRESET, windows.WSAECONNREFUSED,
		windows.WSAEINTR, windows.WSAEWOULDBLOCK, windows.WSAETIMEDOUT,
		windows.WSAEMFILE, windows.WSAENOBUFS, windows.ERROR_NOT_ENOUGH_MEMORY,
		windows.WSAENETDOWN, windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH:
		return true
	}
	return false
}
