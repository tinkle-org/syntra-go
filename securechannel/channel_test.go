package securechannel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/flynn/noise"
)

type channelFixture struct {
	client ClientConfig
	server ServerConfig
	entry  Enrollment
}

func newChannelFixture(t testing.TB, mode Mode) channelFixture {
	t.Helper()
	// Fixed test-only static material; ephemeral keys still use crypto/rand.
	var private, authorization Key
	for n := range private {
		private[n], authorization[n] = byte(n+1), byte(n+65)
	}
	static, err := NewStaticKey(private)
	if err != nil {
		t.Fatal(err)
	}
	c := Context{Mode: mode, Carrier: WSS, ServerKeyID: 0x01020304, Scope: "test/securechannel/é"}
	e := Enrollment{Key: authorization, Principal: "test-principal", ExpiresAt: time.Now().Add(48 * time.Hour)}
	client := ClientConfig{Context: c, ServerPublicKey: static.Public()}
	if mode == Returning {
		client.Context.Epoch = 0x0102030405060708
		client.Context.Handle = [8]byte{8, 7, 6, 5, 4, 3, 2, 1}
		client.AuthorizationKey = authorization
	}
	server := ServerConfig{
		StaticKey: static, ServerKeyID: c.ServerKeyID, Scope: c.Scope, Carrier: c.Carrier,
		AllowBootstrap: true,
		Lookup:         func(context.Context, Context) (Enrollment, error) { return e, nil },
	}
	return channelFixture{client: client, server: server, entry: e}
}

func channelPair(t testing.TB, f channelFixture) (*Channel, *Channel) {
	t.Helper()
	i, m1, err := Begin(f.client)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	s, m2, err := Respond(context.Background(), f.server, m1)
	if err != nil {
		t.Fatal(err)
	}
	c, err := i.Finish(m2)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	t.Cleanup(s.Close)
	return c, s
}

// Construct the expected bytes without using AppendContext or package constants
// for the domain/field layout, so changing the encoder alone breaks the tests.
func canonicalTestContext(c Context) []byte {
	out := append([]byte("syntra.sc1.draft1"), byte(c.Mode), byte(c.Carrier))
	out = binary.BigEndian.AppendUint32(out, c.ServerKeyID)
	out = binary.BigEndian.AppendUint64(out, c.Epoch)
	out = append(out, c.Handle[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c.Scope)))
	return append(out, c.Scope...)
}

// This is a separate configuration of the SAME library, not an independent
// implementation or security audit. Do not call suite() here.
func directNoise(t testing.TB, f channelFixture, initiator bool, prologue []byte) *noise.HandshakeState {
	t.Helper()
	c := noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256),
		Pattern:     noise.HandshakeNK, Initiator: initiator, Prologue: prologue,
	}
	if string(c.CipherSuite.Name()) != "25519_ChaChaPoly_SHA256" || c.Pattern.Name != "NK" {
		t.Fatal("unexpected direct Noise suite")
	}
	if initiator {
		c.PeerStatic = f.client.ServerPublicKey[:]
	} else {
		c.StaticKeypair = noise.DHKey{Private: f.server.StaticKey.private[:], Public: f.server.StaticKey.public[:]}
	}
	if f.client.Context.Mode == Returning {
		c.PresharedKey = f.client.AuthorizationKey[:]
		c.PresharedKeyPlacement = 0
	}
	hs, err := noise.NewHandshakeState(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { disposeHandshake(hs) })
	return hs
}

func requireAuthDenied(t *testing.T, c *Channel, message []byte, err error) {
	t.Helper()
	if c != nil {
		c.Close()
	}
	if err != ErrAuth || c != nil || message != nil {
		t.Fatalf("denial: channel present=%t, message length=%d, error=%v; want only ErrAuth", c != nil, len(message), err)
	}
}

func requireTerminal(t *testing.T, c *Channel) {
	t.Helper()
	if _, ok := c.Peer(); ok {
		t.Fatal("closed channel reports a confirmed peer")
	}
	if out, err := c.Encrypt(nil, []byte("later")); err != ErrClosed || out != nil {
		t.Fatalf("Encrypt after failure = %v, want ErrClosed", err)
	}
	if out, err := c.Decrypt(nil, make([]byte, 17)); err != ErrClosed || out != nil {
		t.Fatalf("Decrypt after failure = %v, want ErrClosed", err)
	}
}

func TestNoiseSuiteInteroperability(t *testing.T) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newChannelFixture(t, mode)
			prologue := canonicalTestContext(f.client.Context)
			t.Run("package-initiator", func(t *testing.T) {
				i, m1, err := Begin(f.client)
				if err != nil {
					t.Fatal(err)
				}
				defer i.Close()
				if len(m1) != len(prologue)+48 || !bytes.Equal(m1[:len(prologue)], prologue) {
					t.Fatal("M1 must be the canonical context followed by exactly 48 Noise bytes")
				}
				r := directNoise(t, f, false, prologue)
				payload, a, b, err := r.ReadMessage(nil, m1[len(prologue):])
				if err != nil || len(payload) != 0 || a != nil || b != nil {
					t.Fatalf("direct ReadMessage(M1): payload=%d, error=%v", len(payload), err)
				}
				m2, c1, c2, err := r.WriteMessage(nil, nil)
				if err != nil || len(m2) != 48 || c1 == nil || c2 == nil || c1 == c2 {
					t.Fatalf("direct WriteMessage(M2): length=%d, error=%v", len(m2), err)
				}
				client, err := i.Finish(m2)
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				for n := 0; n < 3; n++ {
					want := []byte{byte(n), 42, 99}
					wire, err := client.Encrypt(nil, want)
					if err != nil {
						t.Fatal(err)
					}
					got, err := c1.Decrypt(nil, nil, wire) // split 1 is initiator -> responder
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("initiator -> direct responder: %v", err)
					}
					wire, err = c2.Encrypt(nil, nil, want) // split 2 is responder -> initiator
					if err != nil {
						t.Fatal(err)
					}
					got, err = client.Decrypt(nil, wire)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("direct responder -> initiator: %v", err)
					}
				}
			})
			t.Run("package-responder", func(t *testing.T) {
				i := directNoise(t, f, true, prologue)
				m1, _, _, err := i.WriteMessage(nil, nil)
				if err != nil || len(m1) != 48 {
					t.Fatalf("direct M1: length=%d, error=%v", len(m1), err)
				}
				server, m2, err := Respond(context.Background(), f.server, append(bytes.Clone(prologue), m1...))
				if err != nil || len(m2) != 48 {
					t.Fatalf("package M2: length=%d, error=%v", len(m2), err)
				}
				defer server.Close()
				payload, c1, c2, err := i.ReadMessage(nil, m2)
				if err != nil || len(payload) != 0 || c1 == nil || c2 == nil || c1 == c2 {
					t.Fatalf("direct ReadMessage(M2): %v", err)
				}
				for n := 0; n < 3; n++ {
					want := []byte{byte(n), 17, 23}
					wire, err := c1.Encrypt(nil, nil, want)
					if err != nil {
						t.Fatal(err)
					}
					got, err := server.Decrypt(nil, wire)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("direct initiator -> responder: %v", err)
					}
					wire, err = server.Encrypt(nil, want)
					if err != nil {
						t.Fatal(err)
					}
					got, err = c2.Decrypt(nil, nil, wire)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("responder -> direct initiator: %v", err)
					}
				}
			})
		})
	}
}

func TestContextCanonicalBounds(t *testing.T) {
	if HandshakeSize != 48 || MaxCiphertext != 65535 || MaxPlaintext != 65519 || MaxScopeBytes != 255 || MaxContext != len("syntra.sc1.draft1")+24+255 {
		t.Fatal("SC1 draft-1 wire bounds changed")
	}
	for _, mode := range []Mode{Bootstrap, Returning} {
		for _, carrier := range []Carrier{TCP, WS, WSS} {
			for _, scope := range []string{"x", "é", "e\u0301", "a/../b", strings.Repeat("é", 127) + "x"} {
				c := newChannelFixture(t, mode).client.Context
				c.Carrier, c.Scope = carrier, scope
				prefix := []byte{9, 8, 7}
				got, err := AppendContext(bytes.Clone(prefix), c)
				if err != nil || !bytes.Equal(got[:len(prefix)], prefix) || !bytes.Equal(got[len(prefix):], canonicalTestContext(c)) {
					t.Fatalf("canonical encoding: %v", err)
				}
				parsed, err := ParseContext(got[len(prefix):])
				if err != nil || parsed != c {
					t.Fatalf("context round trip: %v", err)
				}
			}
		}
	}
	base := newChannelFixture(t, Returning).client.Context
	invalid := map[string]func(*Context){
		"empty-scope":           func(c *Context) { c.Scope = "" },
		"oversize-scope":        func(c *Context) { c.Scope = strings.Repeat("x", 256) },
		"utf8-byte-bound":       func(c *Context) { c.Scope = strings.Repeat("é", 128) },
		"invalid-utf8":          func(c *Context) { c.Scope = string([]byte{0xff}) },
		"zero-mode":             func(c *Context) { c.Mode = 0 },
		"unknown-mode":          func(c *Context) { c.Mode = 255 },
		"zero-carrier":          func(c *Context) { c.Carrier = 0 },
		"unknown-carrier":       func(c *Context) { c.Carrier = 255 },
		"bootstrap-epoch":       func(c *Context) { c.Mode, c.Handle = Bootstrap, [8]byte{} },
		"bootstrap-handle":      func(c *Context) { c.Mode, c.Epoch = Bootstrap, 0 },
		"returning-zero-epoch":  func(c *Context) { c.Epoch = 0 },
		"returning-zero-handle": func(c *Context) { c.Handle = [8]byte{} },
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			c := base
			mutate(&c)
			if c.Validate() != ErrConfig {
				t.Fatal("invalid context accepted")
			}
			if out, err := AppendContext([]byte("prefix"), c); out != nil || err != ErrConfig {
				t.Fatalf("AppendContext invalid = %v", err)
			}
			if got, err := ParseContext(canonicalTestContext(c)); got != (Context{}) || err != ErrAuth {
				t.Fatalf("ParseContext invalid = %v", err)
			}
		})
	}
	encoded := canonicalTestContext(base)
	for n := 0; n < len(encoded); n++ {
		if _, err := ParseContext(encoded[:n]); err != ErrAuth {
			t.Fatalf("truncation at %d accepted", n)
		}
	}
	for _, bad := range [][]byte{
		append(bytes.Clone(encoded), 0),
		append([]byte("X"), encoded[1:]...),
		make([]byte, MaxContext+1),
	} {
		if _, err := ParseContext(bad); err != ErrAuth {
			t.Fatal("noncanonical context accepted")
		}
	}
	for _, n := range []uint16{0, 1, 255, 256, 65535} {
		bad := bytes.Clone(encoded)
		binary.BigEndian.PutUint16(bad[len(domain)+22:], n)
		if _, err := ParseContext(bad); err != ErrAuth {
			t.Fatalf("incorrect scope length %d accepted", n)
		}
	}
}

func TestHandshakeRejectsWrongKeysAndBoundContext(t *testing.T) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newChannelFixture(t, mode)
			for _, name := range []string{"server-key", "authorization-key"} {
				if mode == Bootstrap && name == "authorization-key" {
					continue
				}
				t.Run(name, func(t *testing.T) {
					bad := f.client
					if name == "server-key" {
						other, err := NewStaticKey(Key{123})
						if err != nil {
							t.Fatal(err)
						}
						bad.ServerPublicKey = other.Public()
					} else {
						bad.AuthorizationKey[0] ^= 1
					}
					i, m1, err := Begin(bad)
					if err != nil {
						t.Fatal(err)
					}
					defer i.Close()
					s, m2, err := Respond(context.Background(), f.server, m1)
					requireAuthDenied(t, s, m2, err)
				})
			}
			changes := map[string]func(*Context){
				"carrier": func(c *Context) { c.Carrier = TCP },
				"scope":   func(c *Context) { c.Scope += "/other" },
				"key-id":  func(c *Context) { c.ServerKeyID++ },
				"mode": func(c *Context) {
					if c.Mode == Bootstrap {
						c.Mode, c.Epoch, c.Handle = Returning, 1, [8]byte{1}
					} else {
						c.Mode, c.Epoch, c.Handle = Bootstrap, 0, [8]byte{}
					}
				},
			}
			if mode == Returning {
				changes["epoch"] = func(c *Context) { c.Epoch++ }
				changes["handle"] = func(c *Context) { c.Handle[0]++ }
			}
			for name, mutate := range changes {
				t.Run("prologue/"+name, func(t *testing.T) {
					i, m1, err := Begin(f.client)
					if err != nil {
						t.Fatal(err)
					}
					defer i.Close()
					changed := f.client.Context
					mutate(&changed)
					bad := append(canonicalTestContext(changed), m1[len(m1)-48:]...)
					// Match routing to the altered wire data: rejection must also bind
					// the prologue cryptographically, rather than only compare policy.
					server := f.server
					server.Scope, server.Carrier, server.ServerKeyID = changed.Scope, changed.Carrier, changed.ServerKeyID
					s, m2, err := Respond(context.Background(), server, bad)
					requireAuthDenied(t, s, m2, err)
				})
			}
			for _, field := range []string{"scope", "carrier", "key-id", "bootstrap-denied"} {
				if mode == Returning && field == "bootstrap-denied" {
					continue
				}
				t.Run("policy/"+field, func(t *testing.T) {
					server := f.server
					switch field {
					case "scope":
						server.Scope += "other"
					case "carrier":
						server.Carrier = WS
					case "key-id":
						server.ServerKeyID++
					case "bootstrap-denied":
						server.AllowBootstrap = false
					}
					i, m1, err := Begin(f.client)
					if err != nil {
						t.Fatal(err)
					}
					defer i.Close()
					s, m2, err := Respond(context.Background(), server, m1)
					requireAuthDenied(t, s, m2, err)
				})
			}
		})
	}
}

func TestHandshakeExactLengthAndNoPayload(t *testing.T) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newChannelFixture(t, mode)
			prologue := canonicalTestContext(f.client.Context)
			for _, payload := range [][]byte{nil, {1}, bytes.Repeat([]byte{7}, 64)} {
				i := directNoise(t, f, true, prologue)
				m1, _, _, err := i.WriteMessage(nil, payload)
				if err != nil || len(m1) != 48+len(payload) {
					t.Fatalf("direct M1: %v", err)
				}
				server, m2, err := Respond(context.Background(), f.server, append(bytes.Clone(prologue), m1...))
				if len(payload) != 0 {
					requireAuthDenied(t, server, m2, err)
				} else {
					if err != nil || len(m2) != 48 {
						t.Fatalf("valid empty-payload M1: %v", err)
					}
					server.Close()
				}
			}
			for _, payload := range [][]byte{{1}, bytes.Repeat([]byte{7}, 64)} {
				i, m1, err := Begin(f.client)
				if err != nil {
					t.Fatal(err)
				}
				r := directNoise(t, f, false, prologue)
				if _, _, _, err := r.ReadMessage(nil, m1[len(prologue):]); err != nil {
					t.Fatal(err)
				}
				m2, _, _, err := r.WriteMessage(nil, payload)
				if err != nil || len(m2) != 48+len(payload) {
					t.Fatalf("direct M2: %v", err)
				}
				c, err := i.Finish(m2)
				if c != nil || err != ErrAuth {
					t.Fatalf("authenticated M2 payload accepted: %v", err)
				}
				if _, err := i.Finish(m2); err != ErrClosed {
					t.Fatal("Finish failure was not terminal")
				}
			}
			i, m1, err := Begin(f.client)
			if err != nil {
				t.Fatal(err)
			}
			defer i.Close()
			for n := 0; n < len(m1); n++ {
				s, m2, err := Respond(context.Background(), f.server, m1[:n])
				requireAuthDenied(t, s, m2, err)
			}
			for _, bad := range [][]byte{append(bytes.Clone(m1), 0), make([]byte, MaxContext+49)} {
				s, m2, err := Respond(context.Background(), f.server, bad)
				requireAuthDenied(t, s, m2, err)
			}
			for _, n := range []int{0, 16, 32, 47, 48, 49, MaxCiphertext} {
				i, _, err := Begin(f.client)
				if err != nil {
					t.Fatal(err)
				}
				if c, err := i.Finish(make([]byte, n)); c != nil || err != ErrAuth {
					t.Fatalf("invalid M2 length %d: %v", n, err)
				}
				if _, err := i.Finish(nil); err != ErrClosed {
					t.Fatal("invalid M2 did not consume initiator")
				}
			}
		})
	}
}

func TestEnrollmentDenialsAreGeneric(t *testing.T) {
	f := newChannelFixture(t, Returning)
	storeFailure := errors.New("private-store-error/secret-diagnostic")
	cases := map[string]func(*Enrollment) error{
		"unknown":      func(e *Enrollment) error { *e = Enrollment{}; return nil },
		"expired":      func(e *Enrollment) error { e.ExpiresAt = time.Now().Add(-time.Minute); return nil },
		"revoked":      func(e *Enrollment) error { e.Revoked = true; return nil },
		"failure":      func(*Enrollment) error { return storeFailure },
		"no-validity":  func(e *Enrollment) error { e.ExpiresAt = time.Time{}; return nil },
		"no-principal": func(e *Enrollment) error { e.Principal = ""; return nil },
		"no-key":       func(e *Enrollment) error { e.Key = Key{}; return nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := f.entry
			lookupErr := mutate(&e)
			original := e
			calls := 0
			server := f.server
			server.Lookup = func(ctx context.Context, c Context) (Enrollment, error) {
				calls++
				if ctx == nil || c != f.client.Context {
					t.Error("lookup received wrong context")
				}
				return e, lookupErr
			}
			i, m1, err := Begin(f.client)
			if err != nil {
				t.Fatal(err)
			}
			defer i.Close()
			s, m2, err := Respond(context.Background(), server, m1)
			requireAuthDenied(t, s, m2, err)
			if errors.Is(err, storeFailure) || strings.Contains(err.Error(), "secret-diagnostic") {
				t.Fatal("store error leaked")
			}
			if calls != 1 || e != original {
				t.Fatal("lookup count or host-owned enrollment changed")
			}
			if err := server.Check(context.Background(), Peer{Context: f.client.Context, Principal: f.entry.Principal}); err != ErrAuth {
				t.Fatalf("Check denial: %v", err)
			}
			if calls != 2 || e != original {
				t.Fatal("Check mutated host-owned enrollment")
			}
		})
	}
	t.Run("missing-lookup", func(t *testing.T) {
		server := f.server
		server.Lookup = nil // still a valid bootstrap-only server configuration
		i, m1, err := Begin(f.client)
		if err != nil {
			t.Fatal(err)
		}
		defer i.Close()
		s, m2, err := Respond(context.Background(), server, m1)
		requireAuthDenied(t, s, m2, err)
	})
	t.Run("cancellation", func(t *testing.T) {
		type contextKey struct{}
		ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "sentinel"))
		defer cancel()
		server := f.server
		server.Lookup = func(got context.Context, _ Context) (Enrollment, error) {
			if got != ctx || got.Value(contextKey{}) != "sentinel" {
				t.Error("caller context not forwarded")
			}
			cancel()
			return f.entry, nil
		}
		i, m1, err := Begin(f.client)
		if err != nil {
			t.Fatal(err)
		}
		defer i.Close()
		s, m2, err := Respond(ctx, server, m1)
		requireAuthDenied(t, s, m2, err)
		if server.Check(ctx, Peer{Context: f.client.Context, Principal: f.entry.Principal}) != ErrAuth {
			t.Fatal("cancelled Check accepted")
		}
	})
}

func TestReplayM1RequiresFreshRecordConfirmation(t *testing.T) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newChannelFixture(t, mode)
			original := f.entry
			calls := 0
			f.server.Lookup = func(context.Context, Context) (Enrollment, error) { calls++; return f.entry, nil }
			i, m1, err := Begin(f.client)
			if err != nil {
				t.Fatal(err)
			}
			defer i.Close()
			s1, m2, err := Respond(context.Background(), f.server, m1)
			if err != nil {
				t.Fatal(err)
			}
			defer s1.Close()
			s2, replayM2, err := Respond(context.Background(), f.server, bytes.Clone(m1))
			if err != nil {
				t.Fatal(err)
			}
			defer s2.Close()
			if bytes.Equal(m2, replayM2) || s1.send.cipher == s2.send.cipher || s1.recv.cipher == s2.recv.cipher {
				t.Fatal("replayed M1 reused responder ephemeral/state")
			}
			for _, s := range []*Channel{s1, s2} {
				peer, confirmed := s.Peer()
				if confirmed || peer.Context != f.client.Context {
					t.Fatal("M1 fresh-confirmed client or lost context")
				}
				if mode == Returning && (peer.Principal != original.Principal || peer.ExpiresAt != original.ExpiresAt) {
					t.Fatal("peer evidence mismatch")
				}
				if _, err := s.Encrypt(nil, []byte("server sending is not client confirmation")); err != nil {
					t.Fatal(err)
				}
				if _, confirmed := s.Peer(); confirmed {
					t.Fatal("sending confirmed a client")
				}
			}
			wantCalls := 0
			if mode == Returning {
				wantCalls = 2
			}
			if calls != wantCalls || f.entry != original {
				t.Fatal("store rechecked or mutated before confirmation")
			}
			client, err := i.Finish(m2)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := i.Finish(m2); err != ErrClosed {
				t.Fatal("initiator reused")
			}
			wire, err := client.Encrypt(nil, []byte("fresh record"))
			if err != nil {
				t.Fatal(err)
			}
			if got, err := s1.Decrypt(nil, wire); err != nil || string(got) != "fresh record" {
				t.Fatalf("first record: %v", err)
			}
			peer, confirmed := s1.Peer()
			if !confirmed {
				t.Fatal("authenticated record did not confirm peer")
			}
			if calls != wantCalls || f.entry != original {
				t.Fatal("confirmation mutated or rechecked store")
			}
			if err := f.server.Check(context.Background(), peer); err != nil {
				t.Fatalf("valid peer Check: %v", err)
			}
			if got, err := s2.Decrypt(nil, wire); got != nil || err != ErrRecord {
				t.Fatalf("replayed M1 accepted original channel's record: %v", err)
			}
			requireTerminal(t, s2)
		})
	}
}

func TestRecordRoundTripAndBuffers(t *testing.T) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		t.Run(mode.String(), func(t *testing.T) {
			client, server := channelPair(t, newChannelFixture(t, mode))
			for _, pair := range [][2]*Channel{{client, server}, {server, client}} {
				for _, size := range []int{1, 64, 1024, MaxPlaintext} {
					want := bytes.Repeat([]byte{byte(size)}, size)
					before := bytes.Clone(want)
					prefix := []byte("prefix")
					wire, err := pair[0].Encrypt(append(make([]byte, 0, size+16+len(prefix)), prefix...), want)
					if err != nil || len(wire) != len(prefix)+size+16 || !bytes.Equal(wire[:len(prefix)], prefix) || !bytes.Equal(want, before) {
						t.Fatalf("Encrypt size %d: %v", size, err)
					}
					ciphertext := bytes.Clone(wire[len(prefix):])
					got, err := pair[1].Decrypt(append(make([]byte, 0, size+len(prefix)), prefix...), ciphertext)
					if err != nil || !bytes.Equal(got[:len(prefix)], prefix) || !bytes.Equal(got[len(prefix):], want) || !bytes.Equal(ciphertext, wire[len(prefix):]) {
						t.Fatalf("Decrypt size %d: %v", size, err)
					}
				}
			}
			if client.send.cipher == client.recv.cipher || server.send.cipher == server.recv.cipher || client.send.cipher == server.recv.cipher {
				t.Fatal("cipher state objects alias")
			}
			if client.send.cipher.Nonce() != 4 || client.recv.cipher.Nonce() != 4 || server.send.cipher.Nonce() != 4 || server.recv.cipher.Nonce() != 4 {
				t.Fatal("nonces did not advance independently")
			}
		})
	}
}

func TestInvalidRecordsAreTerminal(t *testing.T) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		for _, kind := range []string{"empty", "tag-only", "oversize", "bad-tag", "bad-body", "replay", "out-of-order", "reflection", "other-channel"} {
			t.Run(mode.String()+"/"+kind, func(t *testing.T) {
				f := newChannelFixture(t, mode)
				client, server := channelPair(t, f)
				wire, err := client.Encrypt(nil, []byte("authenticated record"))
				if err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "empty":
					wire = nil
				case "tag-only":
					wire = make([]byte, 16)
				case "oversize":
					wire = make([]byte, MaxCiphertext+1)
				case "bad-tag":
					wire[len(wire)-1] ^= 1
				case "bad-body":
					wire[0] ^= 1
				case "replay":
					if _, err := server.Decrypt(nil, wire); err != nil {
						t.Fatal(err)
					}
				case "out-of-order":
					wire, err = client.Encrypt(nil, []byte("nonce one before nonce zero"))
					if err != nil {
						t.Fatal(err)
					}
				case "reflection":
					server = client
				case "other-channel":
					_, server = channelPair(t, f)
				}
				if got, err := server.Decrypt([]byte("prefix"), wire); err != ErrRecord || got != nil {
					t.Fatalf("invalid record accepted: %v", err)
				}
				requireTerminal(t, server)
			})
		}
	}
}

func TestInvalidPlaintextDoesNotConsumeNonce(t *testing.T) {
	client, server := channelPair(t, newChannelFixture(t, Returning))
	for _, bad := range [][]byte{nil, {}, make([]byte, MaxPlaintext+1)} {
		if out, err := client.Encrypt(nil, bad); out != nil || err != ErrRecord {
			t.Fatalf("invalid plaintext: %v", err)
		}
	}
	if client.send.cipher.Nonce() != 0 {
		t.Fatal("invalid local plaintext consumed a nonce")
	}
	wire, err := client.Encrypt(nil, []byte("still nonce zero"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Decrypt(nil, wire); err != nil {
		t.Fatal(err)
	}
}

func TestChannelLimits(t *testing.T) {
	for _, direction := range []string{"send", "receive"} {
		for _, limit := range []string{"age", "expiry", "records"} {
			t.Run(direction+"/"+limit, func(t *testing.T) {
				client, server := channelPair(t, newChannelFixture(t, Returning))
				if client.maxAge != 24*time.Hour || server.maxAge != 24*time.Hour || client.maxRecords != 1<<32 || server.maxRecords != 1<<32 {
					t.Fatal("default channel limits changed")
				}
				target := client
				if direction == "receive" {
					target = server
				}
				var wire []byte
				switch limit {
				case "age":
					target.created = time.Now().Add(-24 * time.Hour)
				case "expiry":
					target.peer.ExpiresAt = time.Now().Add(-time.Minute)
				case "records":
					// Boundary-only forward jump, before any transport encryption.
					// Benchmarks never set or roll back a nonce.
					client.send.cipher.SetNonce((1 << 32) - 1)
					server.recv.cipher.SetNonce((1 << 32) - 1)
					var err error
					wire, err = client.Encrypt(nil, []byte("last permitted nonce"))
					if err != nil {
						t.Fatal(err)
					}
					if _, err := server.Decrypt(nil, wire); err != nil {
						t.Fatalf("last permitted record: %v", err)
					}
				}
				var out []byte
				var err error
				if direction == "send" {
					out, err = target.Encrypt(nil, []byte("over limit"))
				} else {
					out, err = target.Decrypt(nil, wire)
				}
				if out != nil || err != ErrLimit {
					t.Fatalf("boundary = %v, want ErrLimit", err)
				}
				requireTerminal(t, target)
			})
		}
	}
}

func TestServerCheckRevalidatesEnrollment(t *testing.T) {
	f := newChannelFixture(t, Returning)
	_, server := channelPair(t, f)
	peer, _ := server.Peer()
	for _, mutate := range []func(*Peer){
		func(p *Peer) { p.Principal += "other" },
		func(p *Peer) { p.Context.Scope += "other" },
		func(p *Peer) { p.Context.Carrier = TCP },
		func(p *Peer) { p.Context.ServerKeyID++ },
	} {
		bad := peer
		mutate(&bad)
		if f.server.Check(context.Background(), bad) != ErrAuth {
			t.Fatal("changed peer policy accepted")
		}
	}
	entry := f.entry
	f.server.Lookup = func(context.Context, Context) (Enrollment, error) { return entry, nil }
	if err := f.server.Check(context.Background(), peer); err != nil {
		t.Fatal(err)
	}
	entry.Revoked = true
	if f.server.Check(context.Background(), peer) != ErrAuth {
		t.Fatal("revocation was not rechecked")
	}
}

func TestConfigurationAndKeyDiagnostics(t *testing.T) {
	f := newChannelFixture(t, Returning)
	for _, change := range []func(*ClientConfig){
		func(c *ClientConfig) { c.ServerPublicKey = [32]byte{} },
		func(c *ClientConfig) { c.AuthorizationKey = Key{} },
		func(c *ClientConfig) { c.Context.Scope = "" },
		func(c *ClientConfig) { c.Context.Mode, c.Context.Epoch, c.Context.Handle = Bootstrap, 0, [8]byte{} },
	} {
		c := f.client
		change(&c)
		if i, m1, err := Begin(c); i != nil || m1 != nil || err != ErrConfig {
			t.Fatalf("invalid client configuration: %v", err)
		}
	}
	for _, change := range []func(*ServerConfig){
		func(c *ServerConfig) { c.StaticKey = StaticKey{} },
		func(c *ServerConfig) { c.Scope = "" },
		func(c *ServerConfig) { c.Scope = string([]byte{0xff}) },
		func(c *ServerConfig) { c.Scope = strings.Repeat("x", 256) },
		func(c *ServerConfig) { c.Carrier = 0 },
		func(c *ServerConfig) { c.Carrier = 255 },
		func(c *ServerConfig) { c.Lookup, c.AllowBootstrap = nil, false },
	} {
		c := f.server
		change(&c)
		if c.Validate() != ErrConfig {
			t.Fatal("invalid server configuration accepted")
		}
		if s, m2, err := Respond(context.Background(), c, nil); s != nil || m2 != nil || err != ErrConfig {
			t.Fatalf("invalid server configuration: %v", err)
		}
	}
	if _, err := NewStaticKey(Key{}); err != ErrConfig {
		t.Fatal("zero static key accepted")
	}
	public := f.server.StaticKey.Public()
	public[0] ^= 1
	if public == f.server.StaticKey.Public() {
		t.Fatal("Public did not return a copy")
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%032x"} {
		if got := fmt.Sprintf(verb, f.client.AuthorizationKey); got != "[redacted key]" {
			t.Errorf("Key formatting with %s was not redacted", verb)
		}
		if got := fmt.Sprintf(verb, &f.client.AuthorizationKey); got != "[redacted key]" {
			t.Errorf("*Key formatting with %s was not redacted", verb)
		}
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%032x"} {
		if got := fmt.Sprintf(verb, f.server.StaticKey); got != "[server static key]" {
			t.Errorf("StaticKey formatting with %s was not redacted", verb)
		}
		if got := fmt.Sprintf(verb, &f.server.StaticKey); got != "[server static key]" {
			t.Errorf("*StaticKey formatting with %s was not redacted", verb)
		}
	}
	if Bootstrap.String() != "bootstrap" || Returning.String() != "returning" || Mode(255).String() != "invalid" || TCP.String() != "tcp" || WS.String() != "ws" || WSS.String() != "wss" || Carrier(255).String() != "invalid" {
		t.Fatal("enum diagnostics changed")
	}
	var i *Initiator
	i.Close()
	if _, err := i.Finish(nil); err != ErrClosed {
		t.Fatal("nil initiator accepted")
	}
}

func TestGenerateKeys(t *testing.T) {
	a, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if a == (Key{}) || b == (Key{}) || a == b {
		t.Fatal("generated authorization keys empty or repeated")
	}
	s, err := GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	if s.Public() == ([32]byte{}) {
		t.Fatal("generated static public key empty")
	}
}

type entropyFailingReader struct {
	err       error
	calls     int
	requested int
}

func (r *entropyFailingReader) Read(p []byte) (int, error) {
	r.calls++
	r.requested += len(p)
	return 0, r.err
}

func TestEntropyFailureFailsClosed(t *testing.T) {
	entropyErr := errors.New("private entropy source failure")
	checkRead := func(t *testing.T, r *entropyFailingReader) {
		t.Helper()
		if r.calls != 1 || r.requested != 32 {
			t.Fatalf("entropy reads = %d calls requesting %d bytes, want one 32-byte read", r.calls, r.requested)
		}
	}
	t.Run("key-generation", func(t *testing.T) {
		r := &entropyFailingReader{err: entropyErr}
		key, err := generateKey(r)
		if err != entropyErr || key != (Key{}) {
			t.Fatal("zero-byte entropy failure did not return a zero key and the reader error")
		}
		checkRead(t, r)
	})
	for _, mode := range []Mode{Bootstrap, Returning} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newChannelFixture(t, mode)
			t.Run("initiator-write", func(t *testing.T) {
				r := &entropyFailingReader{err: entropyErr}
				i, m1, err := begin(f.client, r)
				if i != nil {
					i.Close()
				}
				if err != ErrAuth || i != nil || m1 != nil {
					t.Fatalf("initiator entropy failure: initiator present=%t, M1 length=%d, error=%v; want only ErrAuth", i != nil, len(m1), err)
				}
				checkRead(t, r)
			})
			t.Run("responder-write", func(t *testing.T) {
				i, m1, err := Begin(f.client)
				if err != nil {
					t.Fatal(err)
				}
				defer i.Close()
				// A valid M1 and enrollment reach responder WriteMessage; only
				// its ephemeral generation needs entropy on this path.
				r := &entropyFailingReader{err: entropyErr}
				s, m2, err := respond(context.Background(), f.server, m1, r)
				requireAuthDenied(t, s, m2, err)
				checkRead(t, r)
			})
		})
	}
	t.Run("unknown-lookup-dummy-key", func(t *testing.T) {
		f := newChannelFixture(t, Returning)
		calls := 0
		f.server.Lookup = func(_ context.Context, c Context) (Enrollment, error) {
			calls++
			if c != f.client.Context {
				t.Error("lookup received wrong context")
			}
			return Enrollment{}, nil
		}
		i, m1, err := Begin(f.client)
		if err != nil {
			t.Fatal(err)
		}
		defer i.Close()
		r := &entropyFailingReader{err: entropyErr}
		s, m2, err := respond(context.Background(), f.server, m1, r)
		requireAuthDenied(t, s, m2, err)
		checkRead(t, r)
		if calls != 1 {
			t.Fatalf("lookup calls = %d, want 1", calls)
		}
	})
}

func TestWarmPreallocatedAllocations(t *testing.T) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		t.Run(mode.String(), func(t *testing.T) {
			f := newChannelFixture(t, mode)
			f.client.Context.Scope = strings.Repeat("x", MaxScopeBytes)
			dst := make([]byte, 0, MaxContext+3)
			allocs := testing.AllocsPerRun(1000, func() {
				out, err := AppendContext(dst[:3], f.client.Context)
				if err != nil || len(out) != MaxContext+3 {
					t.Fatal("AppendContext failed")
				}
			})
			if allocs != 0 {
				t.Fatalf("preallocated AppendContext: %g allocs/run", allocs)
			}
			for _, size := range []int{64, 1024, MaxPlaintext} {
				client, server := channelPair(t, newChannelFixture(t, mode))
				plaintext := bytes.Repeat([]byte{0x5a}, size)
				wire := make([]byte, 0, size+16)
				out := make([]byte, 0, size)
				// AllocsPerRun warms once, then advances both independent states
				// sequentially. No nonce reset or ciphertext replay is involved.
				allocs := testing.AllocsPerRun(1000, func() {
					var err error
					wire, err = client.Encrypt(wire[:0], plaintext)
					if err != nil {
						t.Fatal(err)
					}
					out, err = server.Decrypt(out[:0], wire)
					if err != nil || !bytes.Equal(out, plaintext) {
						t.Fatalf("warm record: %v", err)
					}
				})
				// Unlike AppendContext, the Channel API does not promise zero
				// allocations. Keep the dependency's nonce-slice allocations visible
				// without turning today's measurement into a required minimum.
				t.Logf("warm preallocated %d-byte Encrypt/Decrypt: %g allocs/run", size, allocs)
				if client.send.cipher.Nonce() != 1001 || server.recv.cipher.Nonce() != 1001 {
					t.Fatal("allocation loop did not advance both nonces")
				}
			}
		})
	}
}

func TestConcurrentFullDuplexAndClose(t *testing.T) {
	client, server := channelPair(t, newChannelFixture(t, Returning))
	var wg sync.WaitGroup
	for _, pair := range [][2]*Channel{{client, server}, {server, client}} {
		wg.Add(1)
		go func(sender, receiver *Channel) {
			defer wg.Done()
			for n := 0; n < 100; n++ {
				want := []byte{byte(n), 1}
				wire, err := sender.Encrypt(nil, want)
				if err != nil {
					t.Error(err)
					return
				}
				got, err := receiver.Decrypt(nil, wire)
				if err != nil || !bytes.Equal(got, want) {
					t.Errorf("full duplex: %v", err)
					return
				}
				receiver.Peer()
			}
		}(pair[0], pair[1])
	}
	wg.Wait()
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() { defer wg.Done(); client.Close(); server.Close() }()
	}
	wg.Wait()
	requireTerminal(t, client)
	requireTerminal(t, server)
}
