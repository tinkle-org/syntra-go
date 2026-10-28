package ordered

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
)

type memoryIO struct {
	in   chan []byte
	out  chan []byte
	done chan struct{}
	once sync.Once
}

func (m *memoryIO) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	select {
	case p := <-m.in:
		if len(p) > cap(dst) {
			return nil, ErrProtocol
		}
		return append(dst[:0], p...), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-m.done:
		return nil, ErrClosed
	}
}
func (m *memoryIO) WriteMessage(ctx context.Context, p []byte) error {
	select {
	case m.out <- append([]byte(nil), p...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-m.done:
		return ErrClosed
	}
}
func (m *memoryIO) Close() error { m.once.Do(func() { close(m.done) }); return nil }

func channels(t testing.TB) (*securechannel.Channel, *securechannel.Channel) {
	t.Helper()
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	i, first, err := securechannel.Begin(securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Bootstrap, Carrier: securechannel.TCP, Scope: "test"}, ServerPublicKey: key.Public()})
	if err != nil {
		t.Fatal(err)
	}
	server, reply, err := securechannel.Respond(context.Background(), securechannel.ServerConfig{StaticKey: key, Scope: "test", Carrier: securechannel.TCP, AllowBootstrap: true}, first)
	if err != nil {
		t.Fatal(err)
	}
	client, err := i.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func envelope(frame []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(frame))), frame...)
}

func receiver(t testing.TB, opts Options) (*Transport, *securechannel.Channel, *memoryIO) {
	t.Helper()
	client, server := channels(t)
	m := &memoryIO{in: make(chan []byte, 128), out: make(chan []byte), done: make(chan struct{})}
	o, err := opts.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	tr := newTransport(m, server, nil, o)
	t.Cleanup(func() { tr.Close(); client.Close() })
	return tr, client, m
}

func putRecord(t testing.TB, m *memoryIO, client *securechannel.Channel, p []byte) {
	t.Helper()
	c, err := client.Encrypt(nil, p)
	if err != nil {
		t.Fatal(err)
	}
	m.in <- c
}

func TestSplitPrefixesAndCoalescedFrames(t *testing.T) {
	for _, split := range []int{1, 2, 3, 4, 7, 19} {
		t.Run(string(rune('a'+split)), func(t *testing.T) {
			tr, client, m := receiver(t, Options{})
			if _, ok := tr.ChannelIdentity(); ok {
				t.Fatal("identity before confirmation")
			}
			frames := [][]byte{[]byte("first"), []byte("second frame"), []byte("last")}
			var stream []byte
			for _, f := range frames {
				stream = append(stream, envelope(f)...)
			}
			for len(stream) > 0 {
				n := min(split, len(stream))
				putRecord(t, m, client, stream[:n])
				stream = stream[n:]
			}
			for _, want := range frames {
				got, err := tr.Recv(context.Background())
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("Recv = %q, %v", got, err)
				}
			}
			identity, ok := tr.ChannelIdentity()
			if !ok || identity.Scope != "test" || identity.Carrier != "tcp" {
				t.Fatalf("identity: %+v %v", identity, ok)
			}
		})
	}
}

func TestInvalidEnvelopeAndTagAreTerminal(t *testing.T) {
	for _, size := range []uint32{0, MaxFrame + 1, ^uint32(0)} {
		t.Run(time.Duration(size).String(), func(t *testing.T) {
			tr, client, m := receiver(t, Options{})
			putRecord(t, m, client, binary.BigEndian.AppendUint32(nil, size))
			if _, err := tr.Recv(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatalf("Recv = %v", err)
			}
			if err := tr.Send(context.Background(), []byte("later")); !errors.Is(err, ErrClosed) {
				t.Fatalf("reuse = %v", err)
			}
		})
	}
	t.Run("tag", func(t *testing.T) {
		tr, client, m := receiver(t, Options{})
		c, err := client.Encrypt(nil, envelope([]byte("bad")))
		if err != nil {
			t.Fatal(err)
		}
		c[len(c)-1] ^= 1
		m.in <- c
		if _, err := tr.Recv(context.Background()); !errors.Is(err, ErrProtocol) {
			t.Fatal(err)
		}
		if _, ok := tr.ChannelIdentity(); ok {
			t.Fatal("forged record confirmed identity")
		}
	})
	for _, n := range []int{0, 1, 16} {
		t.Run("record-"+time.Duration(n).String(), func(t *testing.T) {
			tr, _, m := receiver(t, Options{})
			m.in <- make([]byte, n)
			if _, err := tr.Recv(context.Background()); !errors.Is(err, ErrProtocol) {
				t.Fatal(err)
			}
		})
	}
}

func TestFrameDeadlineIsAbsolute(t *testing.T) {
	tr, client, m := receiver(t, Options{FrameTimeout: 60 * time.Millisecond})
	putRecord(t, m, client, []byte{0})
	done := make(chan error, 1)
	go func() { _, err := tr.Recv(context.Background()); done <- err }()
	for j := 0; j < 2; j++ {
		time.Sleep(20 * time.Millisecond)
		putRecord(t, m, client, []byte{0})
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("tiny records renewed frame deadline")
	}
}

func TestBufferedPrefixKeepsOriginalDeadline(t *testing.T) {
	tr, client, m := receiver(t, Options{FrameTimeout: 20 * time.Millisecond})
	putRecord(t, m, client, append(envelope([]byte("first")), 0))
	if _, err := tr.Recv(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if _, err := tr.Recv(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
}

func TestAdmissionAndCloseJoin(t *testing.T) {
	tr, _, _ := receiver(t, Options{MaxPending: 1})
	done := make(chan error, 1)
	go func() { done <- tr.Send(context.Background(), make([]byte, MaxFrame)) }()
	deadline := time.After(time.Second)
	for len(tr.sendAdmission) != 1 {
		select {
		case <-deadline:
			t.Fatal("writer did not enter")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if err := tr.Send(context.Background(), []byte("second")); !errors.Is(err, ErrBusy) {
		t.Fatalf("admission = %v", err)
	}
	scratch := [][]byte{tr.sendPlain, tr.sendCipher, tr.recvPlain, tr.recvCipher}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not join")
	}
	for _, p := range scratch {
		if !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatal("scratch retained data")
		}
	}
}

func TestCanceledQueuedWriterDoesNotConsumeNonce(t *testing.T) {
	tr, client, m := receiver(t, Options{})
	firstDone := make(chan error, 1)
	go func() { firstDone <- tr.Send(context.Background(), []byte("first")) }()
	limit := time.After(time.Second)
	for len(tr.sendAdmission) != 1 {
		select {
		case <-limit:
			t.Fatal("first writer stalled")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	queuedDone := make(chan error, 1)
	go func() { queuedDone <- tr.Send(ctx, []byte("canceled")) }()
	for len(tr.sendAdmission) != 2 {
		select {
		case <-limit:
			t.Fatal("queued writer stalled")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()
	if err := <-queuedDone; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	first := <-m.out
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	plain, err := client.Decrypt(nil, first)
	if err != nil || !bytes.Equal(plain, envelope([]byte("first"))) {
		t.Fatalf("first: %v", err)
	}
	nextDone := make(chan error, 1)
	go func() { nextDone <- tr.Send(context.Background(), []byte("next")) }()
	next := <-m.out
	if err := <-nextDone; err != nil {
		t.Fatal(err)
	}
	plain, err = client.Decrypt(nil, next)
	if err != nil || !bytes.Equal(plain, envelope([]byte("next"))) {
		t.Fatalf("nonce lost to queued cancellation: %v", err)
	}
}

func TestTruncatedAuthenticatedEnvelopeAndIdleCancel(t *testing.T) {
	for _, partial := range [][]byte{nil, {0}, {0, 0, 0, 4, 1}} {
		t.Run(time.Duration(len(partial)).String(), func(t *testing.T) {
			tr, client, m := receiver(t, Options{})
			if len(partial) > 0 {
				putRecord(t, m, client, partial)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			if frame, err := tr.Recv(ctx); frame != nil || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("truncated %v %v", frame, err)
			}
			if err := tr.Send(context.Background(), []byte("reuse")); !errors.Is(err, ErrClosed) {
				t.Fatal(err)
			}
		})
	}
}

func TestLifetimeClosesIdleInitiator(t *testing.T) {
	client, server := channels(t)
	defer server.Close()
	m := &memoryIO{in: make(chan []byte), out: make(chan []byte), done: make(chan struct{})}
	o, _ := (Options{Lifetime: 20 * time.Millisecond}).Normalize()
	tr := newTransport(m, client, nil, o)
	defer tr.Close()
	select {
	case <-tr.stopped:
	case <-time.After(time.Second):
		t.Fatal("idle lifetime not enforced")
	}
}

func TestWatchdogRevokesIdleConfirmedPeer(t *testing.T) {
	key, _ := securechannel.GenerateStaticKey()
	psk, _ := securechannel.GenerateKey()
	var revoked atomic.Bool
	var lookups atomic.Int32
	firstCheck := make(chan struct{}, 1)
	cfg := securechannel.ServerConfig{StaticKey: key, Scope: "test", Carrier: securechannel.TCP,
		Lookup: func(ctx context.Context, _ securechannel.Context) (securechannel.Enrollment, error) {
			if d, ok := ctx.Deadline(); !ok || time.Until(d) > time.Second+time.Millisecond {
				t.Error("lookup not bounded")
			}
			isRevoked := revoked.Load()
			if lookups.Add(1) > 1 {
				select {
				case firstCheck <- struct{}{}:
				default:
				}
			}
			return securechannel.Enrollment{Key: psk, Principal: "principal", ExpiresAt: time.Now().Add(time.Hour), Revoked: isRevoked}, nil
		}}
	i, first, err := securechannel.Begin(securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Returning, Carrier: securechannel.TCP, Scope: "test", Epoch: 1, Handle: [8]byte{1}}, ServerPublicKey: key.Public(), AuthorizationKey: psk})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	server, reply, err := securechannel.Respond(ctx, cfg, first)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	client, err := i.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	m := &memoryIO{in: make(chan []byte, 1), out: make(chan []byte), done: make(chan struct{})}
	o, _ := (Options{}).Normalize()
	tr := newTransport(m, server, &cfg, o)
	defer tr.Close()
	putRecord(t, m, client, envelope([]byte("confirm")))
	if _, err := tr.Recv(context.Background()); err != nil {
		t.Fatal(err)
	}
	id, ok := tr.ChannelIdentity()
	if !ok || id.Principal != "principal" {
		t.Fatalf("identity %+v %v", id, ok)
	}
	select {
	case <-firstCheck:
	case <-time.After(time.Second):
		t.Fatal("first lifecycle check missed")
	}
	revoked.Store(true)
	select {
	case <-tr.stopped:
	case <-time.After(2300 * time.Millisecond):
		t.Fatal("idle revocation missed")
	}
}

var prefixSink [4]byte

func BenchmarkPrefixPreallocated(b *testing.B) {
	lengths := [...]uint32{1, 64, 1024, MaxFrame}
	b.ReportAllocs()
	b.SetBytes(4)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint32(prefixSink[:], lengths[i&3])
	}
	b.StopTimer()
	if got := binary.BigEndian.Uint32(prefixSink[:]); got != lengths[(b.N-1)&3] {
		b.Fatalf("frame prefix = %d", got)
	}
}
