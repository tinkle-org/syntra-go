package securechannel

import (
	"bytes"
	"context"
	"fmt"
	"testing"
)

func BenchmarkAppendContext(b *testing.B) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		b.Run(mode.String(), func(b *testing.B) {
			f := newChannelFixture(b, mode)
			dst := make([]byte, 0, MaxContext)
			encoded, err := AppendContext(dst, f.client.Context)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(encoded)))
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				encoded, err = AppendContext(dst[:0], f.client.Context)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			if !bytes.Equal(encoded, canonicalTestContext(f.client.Context)) {
				b.Fatal("noncanonical context")
			}
		})
	}
}

// Measures both roles, real ephemeral crypto/rand generation, and one verified
// transport record per direction. Static fixture setup is outside the timer.
// Only public pattern/suite names are logged, never configs or key material.
func BenchmarkHandshakeAndConfirm(b *testing.B) {
	for _, pattern := range []struct {
		name string
		mode Mode
	}{{"NK", Bootstrap}, {"NKpsk0", Returning}} {
		b.Run(pattern.name, func(b *testing.B) {
			f := newChannelFixture(b, pattern.mode)
			ctx := context.Background()
			prologue := canonicalTestContext(f.client.Context)
			request, response := bytes.Repeat([]byte{1}, 64), bytes.Repeat([]byte{2}, 64)
			wire := make([]byte, 0, 80)
			plaintext := make([]byte, 0, 64)
			b.Logf("Noise_%s_25519_ChaChaPoly_SHA256; crypto/rand ephemerals; both roles + duplex confirmation", pattern.name)
			b.ReportAllocs()
			b.SetBytes(int64(len(prologue) + 2*48 + 2*80))
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				i, m1, err := Begin(f.client)
				if err != nil {
					b.Fatal(err)
				}
				server, m2, err := Respond(ctx, f.server, m1)
				if err != nil {
					i.Close()
					b.Fatal(err)
				}
				client, err := i.Finish(m2)
				if err != nil {
					server.Close()
					b.Fatal(err)
				}
				if len(m1) != len(prologue)+48 || len(m2) != 48 || client.send.cipher == server.recv.cipher || client.send.cipher == client.recv.cipher {
					b.Fatal("invalid handshake/state ownership")
				}
				if _, ok := server.Peer(); ok {
					b.Fatal("M1 prematurely confirmed peer")
				}
				wire, err = client.Encrypt(wire[:0], request)
				if err != nil {
					b.Fatal(err)
				}
				plaintext, err = server.Decrypt(plaintext[:0], wire)
				if err != nil || !bytes.Equal(plaintext, request) {
					b.Fatalf("client -> server: %v", err)
				}
				wire, err = server.Encrypt(wire[:0], response)
				if err != nil {
					b.Fatal(err)
				}
				plaintext, err = client.Decrypt(plaintext[:0], wire)
				if err != nil || !bytes.Equal(plaintext, response) {
					b.Fatalf("server -> client: %v", err)
				}
				if _, ok := server.Peer(); !ok {
					b.Fatal("server not confirmed")
				}
				if _, ok := client.Peer(); !ok {
					b.Fatal("client not confirmed")
				}
				client.Close()
				server.Close()
			}
		})
	}
}

// One encrypt+decrypt per iteration on warmed, separately owned cipher states.
// Buffer lengths are reset; cipher nonces are NEVER reset. SetBytes reports
// plaintext bytes processed by a complete encrypt/decrypt pair.
func BenchmarkRecordWarm(b *testing.B) {
	for _, mode := range []Mode{Bootstrap, Returning} {
		for _, size := range []int{64, 1024, MaxPlaintext} {
			for _, direction := range []string{"client-to-server", "server-to-client"} {
				b.Run(fmt.Sprintf("%s/%d/%s", mode, size, direction), func(b *testing.B) {
					client, server := channelPair(b, newChannelFixture(b, mode))
					sender, receiver := client, server
					if direction == "server-to-client" {
						sender, receiver = server, client
					}
					plaintext := bytes.Repeat([]byte{0x5a}, size)
					wire := make([]byte, 0, size+16)
					out := make([]byte, 0, size)
					var err error
					wire, err = sender.Encrypt(wire, plaintext)
					if err != nil {
						b.Fatal(err)
					}
					out, err = receiver.Decrypt(out, wire)
					if err != nil || !bytes.Equal(out, plaintext) {
						b.Fatalf("warmup: %v", err)
					}
					if uint64(b.N)+1 > sender.maxRecords {
						b.Fatal("benchmark exceeds per-channel record limit")
					}
					b.ReportAllocs()
					b.SetBytes(int64(size))
					b.ResetTimer()
					for n := 0; n < b.N; n++ {
						wire, err = sender.Encrypt(wire[:0], plaintext)
						if err != nil {
							b.Fatal(err)
						}
						out, err = receiver.Decrypt(out[:0], wire)
						if err != nil {
							b.Fatal(err)
						}
					}
					b.StopTimer()
					if !bytes.Equal(out, plaintext) || sender.send.cipher.Nonce() != uint64(b.N)+1 || receiver.recv.cipher.Nonce() != uint64(b.N)+1 {
						b.Fatal("record mismatch or nonce progression failure")
					}
				})
			}
		}
	}
}
