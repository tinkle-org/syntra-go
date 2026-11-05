//go:build !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package network

import "context"

func acceptResourceTestError() error { return context.DeadlineExceeded }
