//go:build linux || darwin || ios

package securechannel

import "testing"

func TestNativeClockAvailable(t *testing.T) {
	first, ok := nativeElapsed()
	if !ok {
		t.Fatal("suspend-inclusive clock unavailable")
	}
	second, ok := nativeElapsed()
	if !ok || second < first || NewClock().Check() != nil {
		t.Fatal("native clock continuity")
	}
	if _, ok := checkedTimespec(-1, 0); ok {
		t.Fatal("negative timespec")
	}
	if _, ok := checkedTimespec(0, 1e9); ok {
		t.Fatal("unnormalized timespec")
	}
	if _, ok := checkedTimespec(1<<63-1, 0); ok {
		t.Fatal("timespec overflow")
	}
}
