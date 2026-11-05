//go:build !linux && !darwin && !ios

package securechannel

import "time"

func nativeElapsed() (time.Duration, bool) { return 0, false }
