package securechannel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func decodeHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestGoldenContexts(t *testing.T) {
	for _, f := range []struct {
		context Context
		hex     string
		size    int
	}{
		{Context{Mode: Bootstrap, Carrier: TCP, Scope: "a"}, "73796e7472612e312e3001010000000000000000000000000000000000000000000161", 83},
		{Context{Mode: Bootstrap, Carrier: WSS, ServerKeyID: 0x01020304, Scope: "example.service"}, "73796e7472612e312e3001030102030400000000000000000000000000000000000f6578616d706c652e73657276696365", 97},
		{Context{Mode: Returning, Carrier: WS, ServerKeyID: 0x01020304, Epoch: 1, Handle: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, Scope: "example.service"}, "73796e7472612e312e3002020102030400000000000000010102030405060708000f6578616d706c652e73657276696365", 97},
		{Context{Mode: Returning, Carrier: WSS, ServerKeyID: ^uint32(0), Epoch: ^uint64(0), Handle: [8]byte{8, 7, 6, 5, 4, 3, 2, 1}, Scope: "é"}, "73796e7472612e312e300203ffffffffffffffffffffffff08070605040302010002c3a9", 84},
	} {
		want := decodeHex(t, f.hex)
		got, err := AppendContext(nil, f.context)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("context %x: %v", got, err)
		}
		first := append(bytes.Clone(want), make([]byte, 48)...)
		parsed, msg, err := ParseFirst(first)
		if err != nil || parsed != f.context || len(first) != f.size || len(msg) != 48 {
			t.Fatalf("first flight: %v", err)
		}
		for n := 0; n < len(first); n++ {
			if _, _, err := ParseFirst(first[:n]); err != ErrAuth {
				t.Fatalf("truncation %d accepted", n)
			}
		}
		if _, _, err := ParseFirst(append(first, 0)); err != ErrAuth {
			t.Fatal("extra byte accepted")
		}
		static, _ := GenerateStaticKey()
		cfg := ClientConfig{Context: f.context, ServerPublicKey: static.Public()}
		if f.context.Mode == Returning {
			cfg.AuthorizationKey = Key{1}
		}
		i, actual, err := Begin(cfg)
		if err != nil {
			t.Fatal(err)
		}
		i.Close()
		if len(actual) != f.size || !bytes.Equal(actual[:len(want)], want) {
			t.Fatal("initiator first flight layout")
		}
	}
}

func TestResponderOutputRequiresConfirmation(t *testing.T) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		_, server := channelPair(t, newChannelFixture(t, mode))
		if out, err := server.Encrypt(nil, []byte("premature")); out != nil || err != ErrAuth {
			t.Fatalf("premature output: %v", err)
		}
		requireTerminal(t, server)
	}
}

func TestIdentityIsResponderOnlyAndBindsHandshake(t *testing.T) {
	f := newChannelFixture(t, Returning)
	client, server := channelPair(t, f)
	if _, ok := server.VerifiedIdentity(); ok {
		t.Fatal("unconfirmed identity")
	}
	wire, _ := client.Encrypt(nil, []byte("confirmed"))
	if _, err := server.Decrypt(nil, wire); err != nil {
		t.Fatal(err)
	}
	id, ok := server.VerifiedIdentity()
	if !ok || id.Context() != f.client.Context || id.HandshakeHash() == ([32]byte{}) || id.HandshakeHash() != client.peer.HandshakeHash {
		t.Fatal("invalid identity binding")
	}
	wire, _ = server.Encrypt(nil, []byte("reply"))
	if _, err := client.Decrypt(nil, wire); err != nil {
		t.Fatal(err)
	}
	if _, ok := client.VerifiedIdentity(); ok {
		t.Fatal("initiator issued identity")
	}
	server.clock.Invalidate()
	if _, ok := server.VerifiedIdentity(); ok {
		t.Fatal("retired identity")
	}
}

func TestKeyAdmissionAndPrincipalPolicyAreSeparate(t *testing.T) {
	f := newChannelFixture(t, Returning)
	var admission, policy int
	f.server.Lookup = nil
	f.server.LookupKey = func(context.Context, Context) (Key, error) { admission++; return f.client.AuthorizationKey, nil }
	f.server.Authorize = func(_ context.Context, id VerifiedIdentity) error {
		policy++
		if id.Context() != f.client.Context {
			t.Fatal("wrong context")
		}
		return nil
	}
	client, server := channelPair(t, f)
	if admission != 1 || policy != 0 {
		t.Fatal("principal policy ran during admission")
	}
	if err := f.server.CheckIdentity(context.Background(), VerifiedIdentity{}); err != ErrAuth || policy != 0 {
		t.Fatal("zero identity reached policy")
	}
	wire, _ := client.Encrypt(nil, []byte("hello"))
	if _, err := server.Decrypt(nil, wire); err != nil {
		t.Fatal(err)
	}
	id, ok := server.VerifiedIdentity()
	if !ok || id.peer.Principal != "" {
		t.Fatal("key lookup granted principal")
	}
	if err := f.server.CheckIdentity(context.Background(), id); err != nil || policy != 1 {
		t.Fatalf("policy: %v", err)
	}
	for _, lookup := range []KeyLookup{
		func(context.Context, Context) (Key, error) { return Key{}, nil },
		func(context.Context, Context) (Key, error) { return Key{1}, errors.New("private store failure") },
	} {
		f.server.LookupKey = lookup
		i, first, _ := Begin(f.client)
		s, second, err := Respond(context.Background(), f.server, first)
		i.Close()
		requireAuthDenied(t, s, second, err)
	}
}

func TestClockRetirementIsSticky(t *testing.T) {
	for _, failure := range []string{"missing", "negative", "regression", "expiry", "invalidate"} {
		t.Run(failure, func(t *testing.T) {
			var now atomic.Int64
			var missing atomic.Bool
			now.Store(int64(time.Hour))
			clock := NewClockWithSource(ElapsedFunc(func() (time.Duration, bool) { return time.Duration(now.Load()), !missing.Load() }))
			now.Add(int64(time.Second))
			if clock.Age() != time.Second {
				t.Fatal("wrong origin")
			}
			switch failure {
			case "missing":
				missing.Store(true)
			case "negative":
				now.Store(-1)
			case "regression":
				now.Add(-1)
			case "expiry":
				now.Store(int64(time.Hour + MaxAge))
			case "invalidate":
				clock.Invalidate()
			}
			if clock.Check() != ErrLimit {
				t.Fatal("discontinuity accepted")
			}
			missing.Store(false)
			now.Store(int64(time.Hour + 2*time.Second))
			if clock.Age() != MaxAge {
				t.Fatal("clock revived")
			}
		})
	}
	if NewClockWithSource(nil).Check() != ErrLimit {
		t.Fatal("nil source accepted")
	}
}

func TestHandshakeAndRecordsRetainEstablishmentOrigin(t *testing.T) {
	for _, stage := range []string{"begin", "lookup", "finish", "send", "receive"} {
		t.Run(stage, func(t *testing.T) {
			f := newChannelFixture(t, Returning)
			var now time.Duration
			clock := NewClockWithSource(ElapsedFunc(func() (time.Duration, bool) { return now, true }))
			if stage == "begin" {
				now = MaxAge
			}
			i, first, err := BeginWithClock(f.client, clock)
			if stage == "begin" {
				if err != ErrLimit || i != nil || first != nil {
					t.Fatal("expired begin")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if stage == "lookup" {
				lookup := f.server.Lookup
				f.server.Lookup = func(ctx context.Context, c Context) (Enrollment, error) { now = MaxAge; return lookup(ctx, c) }
			}
			s, second, err := RespondWithClock(context.Background(), f.server, first, clock)
			if stage == "lookup" {
				i.Close()
				if err != ErrLimit || s != nil || second != nil {
					t.Fatal("lookup renewed origin")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			if stage == "finish" {
				now = MaxAge
			}
			c, err := i.Finish(second)
			if stage == "finish" {
				if err != ErrLimit || c != nil {
					t.Fatal("finish renewed origin")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			now = MaxAge - time.Nanosecond
			wire, err := c.Encrypt(nil, []byte("last instant"))
			if err != nil {
				t.Fatal(err)
			}
			now = MaxAge
			if stage == "send" {
				_, err = c.Encrypt(nil, []byte("expired"))
			} else {
				_, err = s.Decrypt(nil, wire)
			}
			if err != ErrLimit {
				t.Fatalf("record after absolute lifetime: %v", err)
			}
		})
	}
}

func TestFrameDecoderBoundariesAndPoisoning(t *testing.T) {
	for _, size := range []int{1, MaxPlaintext, MaxFrame} {
		frame := bytes.Repeat([]byte{42}, size)
		stream, err := FramePlaintext(frame)
		if err != nil {
			t.Fatal(err)
		}
		for _, chunk := range []int{1, 3, MaxPlaintext} {
			var d FrameDecoder
			var frames [][]byte
			for offset := 0; offset < len(stream); {
				n := min(chunk, len(stream)-offset)
				got, err := d.Push(stream[offset : offset+n])
				if err != nil {
					t.Fatal(err)
				}
				frames = append(frames, got...)
				offset += n
			}
			if len(frames) != 1 || !bytes.Equal(frames[0], frame) || d.IsPartial() {
				t.Fatal("frame reassembly")
			}
		}
	}
	for _, size := range []uint32{0, MaxFrame + 1, ^uint32(0)} {
		var d FrameDecoder
		prefix := binary.BigEndian.AppendUint32(nil, size)
		for n := 0; n < 3; n++ {
			if _, err := d.Push(prefix[n : n+1]); err != nil || cap(d.body) != 0 {
				t.Fatal("premature allocation")
			}
		}
		if frames, err := d.Push(prefix[3:]); err != ErrLimit || frames != nil || cap(d.body) != 0 {
			t.Fatal("invalid length allocated")
		}
		if _, err := d.Push([]byte{1}); err != ErrClosed {
			t.Fatal("decoder revived")
		}
	}
	var d FrameDecoder
	first, _ := FramePlaintext([]byte("first"))
	bad := append(first, 0, 0, 0, 0)
	if frames, err := d.Push(bad); err != ErrLimit || frames != nil {
		t.Fatal("invalid batch delivered a prefix")
	}
	var huge FrameDecoder
	if _, err := huge.Push(make([]byte, MaxPlaintext+1)); err != ErrLimit {
		t.Fatal("oversized record accepted")
	}
	if _, err := FramePlaintext(nil); err != ErrLimit {
		t.Fatal("empty frame accepted")
	}
	if _, err := FramePlaintext(make([]byte, MaxFrame+1)); err != ErrLimit {
		t.Fatal("oversized frame accepted")
	}
}
