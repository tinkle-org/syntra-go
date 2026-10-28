package ordered

import (
	"bytes"
	"context"
	"testing"
)

func TestConsumedPlaintextScratchIsCleared(t *testing.T) {
	tr, client, m := receiver(t, Options{})
	secret := []byte("opaque handshake credential")
	putRecord(t, m, client, envelope(secret))
	got, err := tr.Recv(context.Background())
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("receive failed: %v", err)
	}
	if !bytes.Equal(tr.recvPlain, make([]byte, len(tr.recvPlain))) {
		t.Fatal("consumed plaintext remains in receive scratch")
	}
	m.out = make(chan []byte, 1)
	if err := tr.Send(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tr.sendPlain, make([]byte, len(tr.sendPlain))) {
		t.Fatal("encrypted plaintext remains in send scratch")
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("scratch cleanup modified the caller's owned frame")
	}
}
