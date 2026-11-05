package securechannel

import (
	"time"

	"golang.org/x/sys/unix"
)

func nativeElapsed() (time.Duration, bool) {
	var ts unix.Timespec
	// CLOCK_MONOTONIC_RAW uses continuous time, including system suspension.
	if unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts) != nil {
		return 0, false
	}
	return checkedTimespec(ts.Sec, ts.Nsec)
}
