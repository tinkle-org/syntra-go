//go:build linux

package securechannel

import (
	"time"

	"golang.org/x/sys/unix"
)

func nativeElapsed() (time.Duration, bool) {
	var ts unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts) != nil {
		return 0, false
	}
	return checkedTimespec(int64(ts.Sec), int64(ts.Nsec))
}
