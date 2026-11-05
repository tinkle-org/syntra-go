package ordered

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
)

func policyReceiver(t *testing.T, authorize func(context.Context, securechannel.VerifiedIdentity) error) (*Transport, *securechannel.Channel, *memoryIO) {
	t.Helper()
	c, s := channels(t)
	m := &memoryIO{in: make(chan []byte, 8), out: make(chan []byte, 8), done: make(chan struct{})}
	o, _ := (Options{}).Normalize()
	cfg := &securechannel.ServerConfig{Scope: "test", Carrier: securechannel.TCP, AllowBootstrap: true, Authorize: authorize}
	tr := newTransport(m, s, cfg, o)
	t.Cleanup(func() { tr.Close(); c.Close() })
	return tr, c, m
}

func TestInitialAuthorizationBlocksHelloAndConcurrentReady(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	var calls atomic.Int32
	tr, c, m := policyReceiver(t, func(context.Context, securechannel.VerifiedIdentity) error {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		return securechannel.ErrAuth
	})
	defer unblock.Do(func() { close(release) })
	putRecord(t, m, c, envelope([]byte("hello")))
	received, sent := make(chan error, 1), make(chan error, 1)
	go func() {
		frame, err := tr.Recv(context.Background())
		if frame != nil {
			t.Error("unauthorized hello delivered")
		}
		received <- err
	}()
	<-entered
	go func() { sent <- tr.Send(context.Background(), []byte("ready")) }()
	select {
	case <-received:
		t.Fatal("Recv returned before authorization")
	case <-time.After(30 * time.Millisecond):
	}
	if _, ok := tr.ChannelIdentity(); ok {
		t.Fatal("identity exposed before authorization")
	}
	if _, ok := tr.VerifiedIdentity(); ok {
		t.Fatal("verified identity exposed before authorization")
	}
	if calls.Load() != 1 || len(m.out) != 0 {
		t.Fatal("concurrent authorization or Ready escaped barrier")
	}
	unblock.Do(func() { close(release) })
	if err := <-received; err != securechannel.ErrAuth {
		t.Fatalf("rejected hello: %v", err)
	}
	if err := <-sent; err == nil || len(m.out) != 0 || calls.Load() != 1 {
		t.Fatalf("rejected Ready: %v, callbacks %d", err, calls.Load())
	}
}

func TestAuthorizationRecheckedAtRecordBoundaries(t *testing.T) {
	for _, boundary := range []string{"ready", "record", "buffered"} {
		t.Run(boundary, func(t *testing.T) {
			var revoked atomic.Bool
			var calls atomic.Int32
			tr, c, m := policyReceiver(t, func(context.Context, securechannel.VerifiedIdentity) error {
				calls.Add(1)
				if revoked.Load() {
					return securechannel.ErrAuth
				}
				return nil
			})
			putRecord(t, m, c, envelope([]byte("hello")))
			if _, err := tr.Recv(context.Background()); err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 1 {
				t.Fatal("initial authorization did not have one owner")
			}
			if boundary == "buffered" {
				putRecord(t, m, c, append(envelope([]byte("first")), envelope([]byte("queued"))...))
				if _, err := tr.Recv(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			revoked.Store(true)
			if boundary == "ready" {
				if err := tr.Send(context.Background(), []byte("ready")); err != securechannel.ErrAuth || len(m.out) != 0 {
					t.Fatalf("revoked Ready reached carrier: %v", err)
				}
			} else {
				if boundary == "record" {
					putRecord(t, m, c, envelope([]byte("rpc")))
				}
				if frame, err := tr.Recv(context.Background()); frame != nil || err != securechannel.ErrAuth {
					t.Fatalf("revoked frame delivered: %q %v", frame, err)
				}
			}
		})
	}
}

func TestCachedIdentityDoesNotOutliveChannel(t *testing.T) {
	for _, cause := range []string{"close", "expiry"} {
		t.Run(cause, func(t *testing.T) {
			tr, c, m := policyReceiver(t, nil)
			putRecord(t, m, c, append(envelope([]byte("hello")), envelope([]byte("buffered"))...))
			if _, err := tr.Recv(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, ok := tr.VerifiedIdentity(); !ok {
				t.Fatal("missing established identity")
			}
			if cause == "close" {
				tr.channel.Close()
			} else {
				tr.channel.Clock().Invalidate()
			}
			if _, ok := tr.VerifiedIdentity(); ok {
				t.Fatal("retired cached identity exposed")
			}
			if _, ok := tr.ChannelIdentity(); ok {
				t.Fatal("retired cached channel identity exposed")
			}
			if frame, err := tr.Recv(context.Background()); frame != nil || err == nil {
				t.Fatalf("retired channel delivered buffered frame: %q %v", frame, err)
			}
		})
	}
}

type cleanupBlockingIO struct {
	*memoryIO
	release chan struct{}
	calls   atomic.Int32
}

func (m *cleanupBlockingIO) Close() error {
	m.calls.Add(1)
	_ = m.memoryIO.Close()
	<-m.release
	return nil
}

func TestCloseContextBoundsBlockedCarrierCleanup(t *testing.T) {
	c, s := channels(t)
	defer s.Close()
	m := &cleanupBlockingIO{memoryIO: &memoryIO{in: make(chan []byte), out: make(chan []byte), done: make(chan struct{})}, release: make(chan struct{})}
	o, _ := (Options{}).Normalize()
	tr := newTransport(m, c, nil, o)
	defer tr.Close()
	var release sync.Once
	defer release.Do(func() { close(m.release) })
	recvDone := make(chan error, 1)
	go func() { _, err := tr.Recv(context.Background()); recvDone <- err }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := tr.CloseContext(ctx); err != context.DeadlineExceeded {
		t.Fatalf("CloseContext = %v", err)
	}
	if time.Since(start) > 150*time.Millisecond {
		t.Fatal("CloseContext waited for carrier cleanup")
	}
	select {
	case <-recvDone:
	case <-time.After(time.Second):
		t.Fatal("carrier close did not interrupt I/O")
	}
	// Repeated close attempts must retain the same single cleanup owner.
	for i := 0; i < 8; i++ {
		if err := tr.CloseContext(ctx); err != context.DeadlineExceeded {
			t.Fatal(err)
		}
	}
	select {
	case <-tr.Stopped():
		t.Fatal("Stopped completed before carrier cleanup")
	case <-time.After(200 * time.Millisecond):
	}
	if m.calls.Load() != 1 {
		t.Fatalf("carrier close owners: %d", m.calls.Load())
	}
	release.Do(func() { close(m.release) })
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-tr.Stopped():
	default:
		t.Fatal("Close did not join retained owner")
	}
}

func TestReadinessPhaseRetainsTrustedDeadline(t *testing.T) {
	var now atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(now.Load()), true }))
	b, err := NewEstablishmentBudget(clock, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c, s := driverPair(t, securechannel.Bootstrap, Options{}, Options{Budget: b})
	now.Store(int64(2 * time.Second))
	phase, cancel := s.EstablishmentContextWithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := phase.Err(); err != nil {
		t.Fatalf("phase did not start after Noise: %v", err)
	}
	if err := c.Send(context.Background(), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recv(context.Background()); err != nil {
		t.Fatal(err)
	}
	now.Store(int64(3 * time.Second))
	resampled, stop := s.EstablishmentContext(context.Background())
	defer stop()
	if resampled.Err() == nil {
		t.Fatal("post-policy check renewed or discarded phase deadline")
	}
	if err := s.Send(context.Background(), []byte("ready")); err != context.DeadlineExceeded && err != ErrClosed {
		t.Fatalf("late Ready accepted: %v", err)
	}
}

func TestReadinessPhaseChecksSynchronousReadyCompletion(t *testing.T) {
	var now atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(now.Load()), true }))
	c, s := channelsWithClock(t, clock)
	wire, err := c.Encrypt(nil, envelope([]byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Decrypt(nil, wire); err != nil {
		t.Fatal(err)
	}
	m := &functionalIO{write: func(context.Context, []byte) error {
		now.Store(int64(time.Second))
		return nil
	}}
	o, _ := (Options{}).Normalize()
	tr := newTransport(m, s, nil, o)
	defer tr.Close()
	tr.establish(15*time.Second, 5*time.Second, true)
	tr.helloComplete(false)
	_, cancel := tr.EstablishmentContextWithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := tr.Send(context.Background(), []byte("ready")); err != context.DeadlineExceeded {
		t.Fatalf("late synchronous Ready completion accepted: %v", err)
	}
	tr.mu.Lock()
	establishing := tr.establishing
	tr.mu.Unlock()
	if !establishing {
		t.Fatal("late Ready retired establishment budget")
	}
}
