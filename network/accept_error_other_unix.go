//go:build aix || darwin || dragonfly || freebsd || netbsd || openbsd || solaris

package network

import "syscall"

func retryableAcceptPlatformErrno(syscall.Errno) bool { return false }
