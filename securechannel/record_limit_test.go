package securechannel

import (
	"bytes"
	"context"
	"testing"
	"time"
)

// These fixtures exist only in the augmented test package. They let the
// external ordered-driver tests accelerate exhaustion without a production knob.
func SetIdentityRecordLimitForTesting(t testing.TB, id VerifiedIdentity, limit uint64) {
	t.Helper()
	if !id.valid || id.channel == nil || limit == 0 || limit > MaxRecords {
		t.Fatal("invalid record-limit fixture")
	}
	c := id.channel
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit > c.maxRecords {
		t.Fatal("fixture must not increase the record limit")
	}
	c.maxRecords = limit
}

func IdentityCiphersRetainedForTesting(id VerifiedIdentity) bool {
	if id.channel == nil {
		return false
	}
	c := id.channel
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && c.send.cipher != nil && c.recv.cipher != nil
}

func TestFirstAndFinalRecordConfirmsIdentity(t *testing.T) {
	f := newChannelFixture(t, Returning)
	client, server := channelPair(t, f)
	server.maxRecords = 1
	if _, ok := server.VerifiedIdentity(); ok {
		t.Fatal("unconfirmed identity exposed")
	}
	wire, err := client.Encrypt(nil, []byte("only permitted record"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Decrypt(nil, wire); err != nil {
		t.Fatal(err)
	}
	id, ok := server.VerifiedIdentity()
	if !ok || f.server.CheckIdentity(context.Background(), id) != nil {
		t.Fatal("first and final record did not confirm an authorizable identity")
	}
	if !IdentityCiphersRetainedForTesting(id) {
		t.Fatal("first identity acquisition retired cipher states")
	}
	if _, err := server.Decrypt(nil, wire); err != ErrLimit {
		t.Fatalf("next record: %v", err)
	}
	requireTerminal(t, server)
}

func TestFinalRecordIdentityChecksRetainCiphers(t *testing.T) {
	for _, direction := range []string{"encrypt", "decrypt"} {
		for _, next := range []string{"encrypt", "decrypt"} {
			t.Run(direction+"/next-"+next, func(t *testing.T) {
				f := newChannelFixture(t, Returning)
				client, server := channelPair(t, f)
				server.maxRecords = 2
				if _, ok := server.VerifiedIdentity(); ok {
					t.Fatal("unconfirmed identity exposed")
				}
				wire, err := client.Encrypt(nil, []byte("hello"))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := server.Decrypt(nil, wire); err != nil {
					t.Fatal(err)
				}
				id, ok := server.VerifiedIdentity()
				if !ok {
					t.Fatal("missing confirmed identity")
				}
				want := []byte("final permitted record")
				if direction == "encrypt" {
					first, firstErr := server.Encrypt(nil, []byte("first reply"))
					if firstErr != nil {
						t.Fatal(firstErr)
					}
					if _, err := client.Decrypt(nil, first); err != nil {
						t.Fatal(err)
					}
					wire, err = server.Encrypt(nil, want)
				} else {
					wire, err = client.Encrypt(nil, want)
					if err == nil {
						var got []byte
						got, err = server.Decrypt(nil, wire)
						if !bytes.Equal(got, want) {
							t.Fatal("final plaintext lost")
						}
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				for i := 0; i < 3; i++ {
					if _, ok := server.Peer(); !ok {
						t.Fatal("final record retired peer")
					}
					if _, ok := server.VerifiedIdentity(); !ok {
						t.Fatal("final record retired identity")
					}
					if err := server.CheckLive(); err != nil {
						t.Fatalf("post-record liveness: %v", err)
					}
					if err := f.server.CheckIdentity(context.Background(), id); err != nil {
						t.Fatalf("cached identity recheck: %v", err)
					}
					if !IdentityCiphersRetainedForTesting(id) {
						t.Fatal("identity check released cipher states")
					}
				}
				if direction == "encrypt" {
					got, err := client.Decrypt(nil, wire)
					if err != nil || !bytes.Equal(got, want) {
						t.Fatalf("final ciphertext corrupted by identity checks: %v", err)
					}
				}
				var out []byte
				if next == "encrypt" {
					out, err = server.Encrypt(nil, []byte("over budget"))
				} else {
					out, err = server.Decrypt(nil, wire)
				}
				if err != ErrLimit || out != nil {
					t.Fatalf("next record = %x, %v; want ErrLimit", out, err)
				}
				if IdentityCiphersRetainedForTesting(id) {
					t.Fatal("next operation did not retire cipher states")
				}
				if err := f.server.CheckIdentity(context.Background(), id); err != ErrAuth {
					t.Fatalf("closed cached identity accepted: %v", err)
				}
				requireTerminal(t, server)
			})
		}
	}
}

func TestCachedIdentityRejectsClosureAndExpiry(t *testing.T) {
	for _, cause := range []string{"close", "clock", "enrollment"} {
		t.Run(cause, func(t *testing.T) {
			f := newChannelFixture(t, Returning)
			client, server := channelPair(t, f)
			wire, err := client.Encrypt(nil, []byte("hello"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := server.Decrypt(nil, wire); err != nil {
				t.Fatal(err)
			}
			id, ok := server.VerifiedIdentity()
			if !ok {
				t.Fatal("missing identity")
			}
			switch cause {
			case "close":
				server.Close()
			case "clock":
				server.Clock().Invalidate()
			case "enrollment":
				server.peer.ExpiresAt = time.Now().Add(-time.Second)
			}
			if _, ok := server.VerifiedIdentity(); ok {
				t.Fatal("retired identity exposed")
			}
			if err := f.server.CheckIdentity(context.Background(), id); err != ErrAuth {
				t.Fatalf("retired cached identity accepted: %v", err)
			}
			requireTerminal(t, server)
		})
	}
}
