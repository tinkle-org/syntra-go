package securechannel_test

import (
	"bytes"
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

type limitCarrier struct {
	in, out chan []byte
	done    chan struct{}
	once    *sync.Once
}

func (m *limitCarrier) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	select {
	case p := <-m.in:
		if len(p) > cap(dst) {
			return nil, ordered.ErrProtocol
		}
		return append(dst[:0], p...), nil
	case <-m.done:
		return nil, ordered.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (m *limitCarrier) WriteMessage(ctx context.Context, p []byte) error {
	select {
	case m.out <- bytes.Clone(p):
		return nil
	case <-m.done:
		return ordered.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *limitCarrier) Close() error { m.once.Do(func() { close(m.done) }); return nil }

func limitedOrderedPair(t *testing.T, limit uint64) (*securechannel.Channel, *ordered.Transport, *limitCarrier, *atomic.Int32) {
	t.Helper()
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	a, b := make(chan []byte, 8), make(chan []byte, 8)
	done, once := make(chan struct{}), new(sync.Once)
	clientIO := &limitCarrier{in: a, out: b, done: done, once: once}
	serverIO := &limitCarrier{in: b, out: a, done: done, once: once}
	t.Cleanup(func() { _ = clientIO.Close() })
	calls := new(atomic.Int32)
	cfg := securechannel.ServerConfig{StaticKey: key, Scope: "final-record", Carrier: securechannel.TCP, AllowBootstrap: true,
		Authorize: func(context.Context, securechannel.VerifiedIdentity) error { calls.Add(1); return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type result struct {
		transport *ordered.Transport
		err       error
	}
	server := make(chan result, 1)
	go func() {
		tr, err := ordered.Server(ctx, serverIO, cfg, ordered.Options{})
		server <- result{tr, err}
	}()
	i, first, err := securechannel.Begin(securechannel.ClientConfig{
		Context: securechannel.Context{Mode: securechannel.Bootstrap, Scope: cfg.Scope, Carrier: cfg.Carrier}, ServerPublicKey: key.Public(),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	if err := clientIO.WriteMessage(ctx, first); err != nil {
		t.Fatal(err)
	}
	reply, err := clientIO.ReadMessage(ctx, make([]byte, 0, securechannel.HandshakeSize))
	if err != nil {
		t.Fatal(err)
	}
	client, err := i.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	got := <-server
	if got.err != nil {
		t.Fatal(got.err)
	}
	tr := got.transport
	t.Cleanup(func() { _ = tr.Close() })
	if _, ok := tr.VerifiedIdentity(); ok {
		t.Fatal("unconfirmed transport identity")
	}
	if _, ok := tr.ChannelIdentity(); ok {
		t.Fatal("unconfirmed channel identity")
	}
	writeLimitedRecord(t, client, clientIO, limitFrame(t, "hello"))
	if frame, err := tr.Recv(ctx); err != nil || string(frame) != "hello" {
		t.Fatalf("hello: %q %v", frame, err)
	}
	id, ok := tr.VerifiedIdentity()
	if !ok {
		t.Fatal("missing confirmed transport identity")
	}
	securechannel.SetIdentityRecordLimitForTesting(t, id, limit)
	return client, tr, clientIO, calls
}

func limitFrame(t *testing.T, body string) []byte {
	t.Helper()
	p, err := securechannel.FramePlaintext([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func writeLimitedRecord(t *testing.T, client *securechannel.Channel, carrier *limitCarrier, plaintext []byte) {
	t.Helper()
	wire, err := client.Encrypt(nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if err := carrier.WriteMessage(context.Background(), wire); err != nil {
		t.Fatal(err)
	}
}

func TestOrderedFinalRecordDeliversAllBufferedFrames(t *testing.T) {
	for _, split := range []int{0, 2} {
		t.Run(map[int]string{0: "coalesced", 2: "split-prefix"}[split], func(t *testing.T) {
			testOrderedFinalRecordFrames(t, split)
		})
	}
}

func testOrderedFinalRecordFrames(t *testing.T, split int) {
	t.Helper()
	limit := uint64(2)
	if split != 0 {
		limit++
	}
	client, tr, carrier, calls := limitedOrderedPair(t, limit)
	id, _ := tr.VerifiedIdentity()
	stream := append(limitFrame(t, "first"), limitFrame(t, "second")...)
	if split != 0 {
		writeLimitedRecord(t, client, carrier, stream[:split])
		stream = stream[split:]
	}
	writeLimitedRecord(t, client, carrier, stream)
	first, err := tr.Recv(context.Background())
	if err != nil || string(first) != "first" {
		t.Fatalf("final record first frame: %q %v", first, err)
	}
	if _, ok := tr.VerifiedIdentity(); !ok {
		t.Fatal("final record lost cached identity")
	}
	if _, ok := tr.ChannelIdentity(); !ok {
		t.Fatal("final record lost channel identity")
	}
	// Idle authorization must also preserve the remaining buffered frame.
	before := calls.Load()
	deadline := time.After(2 * time.Second)
	for calls.Load() == before {
		select {
		case <-deadline:
			t.Fatal("idle authorization stopped after final record")
		case <-time.After(time.Millisecond):
		}
	}
	second, err := tr.Recv(context.Background())
	if err != nil || string(second) != "second" {
		t.Fatalf("final record buffered frame: %q %v", second, err)
	}
	if !securechannel.IdentityCiphersRetainedForTesting(id) {
		t.Fatal("authorization rechecks retired final-record cipher states")
	}
	writeLimitedRecord(t, client, carrier, limitFrame(t, "over budget"))
	if frame, err := tr.Recv(context.Background()); err != ordered.ErrProtocol || frame != nil {
		t.Fatalf("next record: %q %v", frame, err)
	}
	if _, ok := tr.VerifiedIdentity(); ok {
		t.Fatal("failed next operation retained exposed identity")
	}
	if _, ok := tr.ChannelIdentity(); ok {
		t.Fatal("failed next operation retained exposed channel identity")
	}
	if securechannel.IdentityCiphersRetainedForTesting(id) {
		t.Fatal("next operation did not poison cipher states")
	}
}

func TestOrderedFinalEncryptIdentityChecksRetainCiphers(t *testing.T) {
	client, tr, carrier, _ := limitedOrderedPair(t, 2)
	id, _ := tr.VerifiedIdentity()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, body := range []string{"ready", "final output"} {
		if err := tr.Send(ctx, []byte(body)); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if _, ok := tr.VerifiedIdentity(); !ok {
				t.Fatal("post-encrypt identity check retired channel")
			}
			if _, ok := tr.ChannelIdentity(); !ok {
				t.Fatal("post-encrypt channel identity check retired channel")
			}
		}
		if !securechannel.IdentityCiphersRetainedForTesting(id) {
			t.Fatal("post-encrypt checks released cipher states")
		}
		wire, err := carrier.ReadMessage(ctx, make([]byte, 0, securechannel.MaxCiphertext))
		if err != nil {
			t.Fatal(err)
		}
		plain, err := client.Decrypt(nil, wire)
		if err != nil || !bytes.Equal(plain, limitFrame(t, body)) {
			t.Fatalf("output damaged by post-encrypt checks: %v", err)
		}
	}
	if err := tr.Send(ctx, []byte("over budget")); err != ordered.ErrProtocol {
		t.Fatalf("next encryption: %v", err)
	}
	if securechannel.IdentityCiphersRetainedForTesting(id) {
		t.Fatal("next encryption did not poison cipher states")
	}
}
