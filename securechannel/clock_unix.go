//go:build linux || darwin || ios

package securechannel

import (
	"math"
	"time"
)

func checkedTimespec(sec, nsec int64) (time.Duration, bool) {
	if sec < 0 || nsec < 0 || nsec >= 1e9 || sec > (math.MaxInt64-nsec)/1e9 {
		return 0, false
	}
	return time.Duration(sec*1e9 + nsec), true
}
