package syntra

import (
	"testing"
)

// Bounded negative coverage for wire parsing. These run as normal unit
// tests in PR CI (seed corpus only); scheduled CI may extend them with
// short -fuzztime runs. No runtime behavior is changed here.
func TestFuzzSeedCorpus(t *testing.T) {
	seeds := [][]byte{
		nil,
		{},
		{0x08},
		{0x08, 0x01},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		make([]byte, 8*1024*1024+1),
	}
	for i, s := range seeds {
		f, err := UnmarshalFrame(s)
		if err != nil {
			continue
		}
		if err := ValidateFrame(f); err != nil {
			continue
		}
		_ = i
	}
}

func FuzzUnmarshalFrame(f *testing.F) {
	f.Add([]byte{0x08, 0x01})
	f.Add([]byte{})
	f.Add([]byte{0x08, 0x01, 0x10, 0x07})
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1024*1024 {
			t.Skip("oversize input capped at 1MiB for PR smoke")
		}
		frame, err := UnmarshalFrame(b)
		if err != nil {
			return
		}
		_ = ValidateFrame(frame)
	})
}

func FuzzDuplicateContent(f *testing.F) {
	f.Add("echo", []byte("req"), "echo", []byte("req"))
	f.Add("echo", []byte("req"), "other", []byte("req"))
	f.Fuzz(func(t *testing.T, methodA string, payloadA []byte, methodB string, payloadB []byte) {
		if len(methodA) > 256 || len(methodB) > 256 {
			t.Skip("method capped")
		}
		if len(payloadA) > 64*1024 || len(payloadB) > 64*1024 {
			t.Skip("payload capped")
		}
		same := methodA == methodB && string(payloadA) == string(payloadB)
		if err := CheckDuplicateContent(methodA, payloadA, methodB, payloadB); same && err != nil {
			t.Fatalf("identical content rejected: %v", err)
		} else if !same && err == nil {
			t.Fatalf("mismatched content accepted")
		}
		digestA := digestContent(methodA, payloadA)
		digestB := digestContent(methodB, payloadB)
		if err := checkDigest(digestA, methodB, payloadB); same && err != nil {
			t.Fatalf("checkDigest rejected identical inputs: %v", err)
		} else if !same && digestA != digestB && err == nil {
			t.Fatalf("checkDigest accepted mismatched digests")
		}
	})
}
