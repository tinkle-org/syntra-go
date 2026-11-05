package network

import (
	"testing"

	"golang.org/x/sys/windows"
)

func acceptResourceTestError() error { return windows.WSAEMFILE }

func TestAcceptErrorWindowsErrnos(t *testing.T) {
	checkAcceptErrnos(t, []error{
		windows.WSAECONNABORTED, windows.WSAECONNRESET, windows.WSAECONNREFUSED,
		windows.WSAEINTR, windows.WSAEWOULDBLOCK, windows.WSAETIMEDOUT,
		windows.WSAEMFILE, windows.WSAENOBUFS, windows.ERROR_NOT_ENOUGH_MEMORY,
		windows.WSAENETDOWN, windows.WSAENETUNREACH, windows.WSAEHOSTUNREACH,
	}, []error{windows.WSAEBADF, windows.WSAEACCES, windows.WSAEINVAL, windows.WSAENOTSOCK})
}
