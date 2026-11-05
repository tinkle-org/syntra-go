//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package network

func retryableAcceptErrno(error) bool { return false }
