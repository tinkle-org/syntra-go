package securechannel

import (
	"bytes"
	"testing"
)

func FuzzParseContext(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("syntra.sc1.draft1"))
	for _, mode := range []Mode{Bootstrap, Returning} {
		fixture := newChannelFixture(f, mode)
		encoded := canonicalTestContext(fixture.client.Context)
		f.Add(encoded)
		f.Add(append(bytes.Clone(encoded), 0))
		fixture.client.Context.Scope = string([]byte{0xff})
		f.Add(canonicalTestContext(fixture.client.Context))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseContext(data)
		if err != nil {
			if err != ErrAuth || c != (Context{}) {
				t.Fatal("parse denial was not generic/zero")
			}
			return
		}
		if c.Validate() != nil {
			t.Fatal("parser accepted invalid context")
		}
		out, err := AppendContext(nil, c)
		if err != nil || !bytes.Equal(out, data) || !bytes.Equal(out, canonicalTestContext(c)) {
			t.Fatal("accepted noncanonical context")
		}
	})
}

func FuzzContextRoundTrip(f *testing.F) {
	f.Add(uint8(Bootstrap), uint8(TCP), uint32(0), uint64(0), []byte{}, "scope")
	f.Add(uint8(Returning), uint8(WSS), ^uint32(0), ^uint64(0), []byte{1, 2, 3}, "é")
	f.Add(uint8(255), uint8(255), uint32(1), uint64(0), []byte{}, string([]byte{0xff}))
	f.Fuzz(func(t *testing.T, mode, carrier uint8, keyID uint32, epoch uint64, handle []byte, scope string) {
		c := Context{Mode: Mode(mode), Carrier: Carrier(carrier), ServerKeyID: keyID, Epoch: epoch, Scope: scope}
		copy(c.Handle[:], handle)
		out, err := AppendContext(nil, c)
		if c.Validate() != nil {
			if err != ErrConfig || out != nil {
				t.Fatal("invalid context encoded")
			}
			return
		}
		if err != nil || len(out) > MaxContext || !bytes.Equal(out, canonicalTestContext(c)) {
			t.Fatal("invalid canonical encoding")
		}
		parsed, err := ParseContext(out)
		if err != nil || parsed != c {
			t.Fatal("valid context did not round trip exactly")
		}
	})
}
