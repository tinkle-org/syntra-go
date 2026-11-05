package ordered

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
)

type functionalIO struct {
	read   func(context.Context, []byte) ([]byte, error)
	write  func(context.Context, []byte) error
	closed atomic.Int32
}

func (f *functionalIO) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	return f.read(ctx, dst)
}
func (f *functionalIO) WriteMessage(ctx context.Context, p []byte) error { return f.write(ctx, p) }
func (f *functionalIO) Close() error                                     { f.closed.Add(1); return nil }

func driverPair(t *testing.T, mode securechannel.Mode, co, so Options) (*Transport, *Transport) {
	t.Helper()
	static, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	key := securechannel.Key{9}
	cc := securechannel.ClientConfig{Context: securechannel.Context{Mode: mode, Carrier: securechannel.TCP, Scope: "driver"}, ServerPublicKey: static.Public()}
	if mode == securechannel.Returning {
		cc.Context.Handle = [8]byte{1}
		cc.Context.Epoch = 1
		cc.AuthorizationKey = key
	}
	sc := securechannel.ServerConfig{StaticKey: static, Scope: "driver", Carrier: securechannel.TCP, AllowBootstrap: mode == securechannel.Bootstrap, LookupKey: func(context.Context, securechannel.Context) (securechannel.Key, error) { return key, nil }}
	a, b := make(chan []byte, 128), make(chan []byte, 128)
	ci := &memoryIO{in: a, out: b, done: make(chan struct{})}
	si := &memoryIO{in: b, out: a, done: make(chan struct{})}
	type result struct {
		tr  *Transport
		err error
	}
	server := make(chan result, 1)
	go func() { tr, err := Server(context.Background(), si, sc, so); server <- result{tr, err} }()
	c, err := Client(context.Background(), ci, cc, co)
	s := <-server
	if err != nil || s.err != nil {
		if c != nil {
			c.Close()
		}
		if s.tr != nil {
			s.tr.Close()
		}
		t.Fatalf("setup: %v %v", err, s.err)
	}
	t.Cleanup(func() { c.Close(); s.tr.Close() })
	return c, s.tr
}

func TestPublicDriverBothModesAndMaximumFrame(t *testing.T) {
	for _, mode := range []securechannel.Mode{securechannel.Bootstrap, securechannel.Returning} {
		t.Run(mode.String(), func(t *testing.T) {
			c, s := driverPair(t, mode, Options{}, Options{})
			if _, ok := s.ChannelIdentity(); ok {
				t.Fatal("identity before record")
			}
			if err := c.Send(context.Background(), []byte("hello")); err != nil {
				t.Fatal(err)
			}
			if got, err := s.Recv(context.Background()); err != nil || string(got) != "hello" {
				t.Fatalf("hello: %v", err)
			}
			id, ok := s.VerifiedIdentity()
			if !ok || id.Context().Mode != mode || id.HandshakeHash() == ([32]byte{}) {
				t.Fatal("missing verified binding")
			}
			if err := s.Send(context.Background(), []byte("ready")); err != nil {
				t.Fatal(err)
			}
			if got, err := c.Recv(context.Background()); err != nil || string(got) != "ready" {
				t.Fatalf("ready: %v", err)
			}
			if _, ok := c.ChannelIdentity(); ok {
				t.Fatal("initiator identity")
			}
			frame := bytes.Repeat([]byte{0xa5}, MaxFrame)
			for _, p := range [][2]*Transport{{c, s}, {s, c}} {
				if err := p[0].Send(context.Background(), frame); err != nil {
					t.Fatal(err)
				}
				if got, err := p[1].Recv(context.Background()); err != nil || !bytes.Equal(got, frame) {
					t.Fatalf("maximum frame: %v", err)
				}
			}
		})
	}
}

func TestMalformedTrailingFrameRejectsEntireRecord(t *testing.T) {
	tr, c, m := receiver(t, Options{})
	putRecord(t, m, c, append(envelope([]byte("valid prefix")), 0, 0, 0, 0))
	if frame, err := tr.Recv(context.Background()); frame != nil || err != ErrProtocol {
		t.Fatalf("partially delivered invalid batch: %q %v", frame, err)
	}
	if _, ok := tr.ChannelIdentity(); ok {
		t.Fatal("failed batch retained identity")
	}
}

func TestFirstHelloCannotPipelineFrames(t *testing.T) {
	c, s := driverPair(t, securechannel.Bootstrap, Options{}, Options{})
	stream := append(envelope([]byte("hello")), 0)
	wire, err := c.channel.Encrypt(nil, stream)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.io.WriteMessage(context.Background(), wire); err != nil {
		t.Fatal(err)
	}
	if frame, err := s.Recv(context.Background()); err != ErrProtocol || frame != nil {
		t.Fatalf("pipelined hello: %v", err)
	}
}

func TestRecordTimeoutIncludesIdle(t *testing.T) {
	tr, _, _ := receiver(t, Options{RecordTimeout: 20 * time.Millisecond})
	select {
	case <-tr.stopped:
	case <-time.After(time.Second):
		t.Fatal("idle record timeout not enforced")
	}
}

func TestOptionsBudgets(t *testing.T) {
	o, err := (Options{}).Normalize()
	if err != nil || o.AttemptTimeout != 15*time.Second || o.HandshakeTimeout != 5*time.Second || o.WriteTimeout != 10*time.Second || o.RecordTimeout != 30*time.Second || o.FrameTimeout != 30*time.Second || o.Lifetime != 24*time.Hour {
		t.Fatalf("defaults: %+v %v", o, err)
	}
	for _, bad := range []Options{{AttemptTimeout: 15*time.Second + 1}, {HandshakeTimeout: 5*time.Second + 1}, {WriteTimeout: 10*time.Second + 1}, {RecordTimeout: 30*time.Second + 1}, {FrameTimeout: 30*time.Second + 1}, {Lifetime: 24*time.Hour + 1}, {MaxPending: 1025}, {MaxPending: -1}, {WriteTimeout: -1}} {
		if _, err := bad.Normalize(); err != ErrOptions {
			t.Fatal("invalid budget accepted")
		}
	}
}

func TestProvidedAttemptAndHelloDoNotRenew(t *testing.T) {
	for _, stage := range []string{"carrier", "noise", "hello", "ready", "lifetime"} {
		t.Run(stage, func(t *testing.T) {
			var elapsed atomic.Int64
			clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(elapsed.Load()), true }))
			budget, err := NewEstablishmentBudget(clock, 15*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			static, _ := securechannel.GenerateStaticKey()
			cfg := securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Bootstrap, Carrier: securechannel.TCP, Scope: "budget"}, ServerPublicKey: static.Public()}
			var server *securechannel.Channel
			var reply []byte
			var writes int
			io := &functionalIO{}
			io.write = func(_ context.Context, p []byte) error {
				writes++
				if writes == 1 {
					var e error
					server, reply, e = securechannel.Respond(context.Background(), securechannel.ServerConfig{StaticKey: static, Scope: "budget", Carrier: securechannel.TCP, AllowBootstrap: true}, p)
					return e
				}
				_, e := server.Decrypt(nil, p)
				return e
			}
			io.read = func(_ context.Context, dst []byte) ([]byte, error) {
				if stage == "carrier" {
					elapsed.Store(int64(15 * time.Second))
				} else if stage == "noise" {
					elapsed.Store(int64(5 * time.Second))
				} else {
					elapsed.Store(int64(3 * time.Second))
				}
				return append(dst[:0], reply...), nil
			}
			if stage == "carrier" {
				elapsed.Store(int64(12 * time.Second))
			}
			o := Options{Budget: budget}
			if stage == "lifetime" {
				o.Lifetime = 4 * time.Second
			}
			tr, err := Client(context.Background(), io, cfg, o)
			if server != nil {
				defer server.Close()
			}
			if stage == "carrier" || stage == "noise" {
				if err != context.DeadlineExceeded || tr != nil || io.closed.Load() != 1 {
					t.Fatalf("carrier reset attempt: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Close()
			switch stage {
			case "hello":
				elapsed.Store(int64(5 * time.Second))
			case "lifetime":
				elapsed.Store(int64(4 * time.Second))
			case "ready":
				if err := tr.Send(context.Background(), []byte("hello")); err != nil {
					t.Fatal(err)
				}
				elapsed.Store(int64(15 * time.Second))
				if frame, err := tr.Recv(context.Background()); frame != nil || (err != context.DeadlineExceeded && err != ErrClosed) {
					t.Fatalf("ready reset attempt: %v", err)
				}
				return
			}
			if err := tr.Send(context.Background(), []byte("late hello")); err != context.DeadlineExceeded && err != ErrClosed {
				t.Fatalf("renewed budget: %v", err)
			}
			if writes != 1 {
				t.Fatal("expired hello reached carrier")
			}
		})
	}
}

func TestWriteFailureIsTerminalAndSanitized(t *testing.T) {
	client, server := channels(t)
	defer server.Close()
	var writes int
	io := &functionalIO{write: func(context.Context, []byte) error { writes++; return errors.New("private carrier error") }}
	o, _ := (Options{}).Normalize()
	tr := newTransport(io, client, nil, o)
	defer tr.Close()
	if err := tr.Send(context.Background(), bytes.Repeat([]byte{1}, MaxFrame)); err != ErrIO {
		t.Fatalf("failure: %v", err)
	}
	if err := tr.Send(context.Background(), []byte("retry")); err != ErrClosed {
		t.Fatalf("retry: %v", err)
	}
	if writes != 1 {
		t.Fatal("consumed nonce retried")
	}
}

func TestBudgetContinuityCancelsBlockedCarrier(t *testing.T) {
	var now atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(now.Load()), true }))
	b, err := NewEstablishmentBudget(clock, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := b.Context(context.Background())
	defer cancel()
	clock.Invalidate()
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			t.Fatal("wrong cancellation")
		}
	case <-time.After(time.Second):
		t.Fatal("clock retirement did not interrupt carrier")
	}
	if _, _, _, err := b.claim(Options{Lifetime: securechannel.MaxAge, HandshakeTimeout: 5 * time.Second}); err != context.DeadlineExceeded {
		t.Fatal("invalid budget revived")
	}
}

func channelsWithClock(t *testing.T, clock *securechannel.Clock) (*securechannel.Channel, *securechannel.Channel) {
	t.Helper()
	static, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	i, first, err := securechannel.BeginWithClock(securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Bootstrap, Carrier: securechannel.TCP, Scope: "test"}, ServerPublicKey: static.Public()}, clock)
	if err != nil {
		t.Fatal(err)
	}
	s, second, err := securechannel.RespondWithClock(context.Background(), securechannel.ServerConfig{StaticKey: static, Scope: "test", Carrier: securechannel.TCP, AllowBootstrap: true}, first, clock)
	if err != nil {
		i.Close()
		t.Fatal(err)
	}
	c, err := i.Finish(second)
	if err != nil {
		s.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return c, s
}

func TestOneWriteBudgetCoversAllRecordsAndChecksSynchronousCompletion(t *testing.T) {
	var now atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(now.Load()), true }))
	c, _ := channelsWithClock(t, clock)
	writes := 0
	io := &functionalIO{write: func(context.Context, []byte) error { writes++; now.Store(int64(10 * time.Second)); return nil }}
	o, _ := (Options{}).Normalize()
	tr := newTransport(io, c, nil, o)
	defer tr.Close()
	if err := tr.Send(context.Background(), make([]byte, MaxFrame)); err != context.DeadlineExceeded {
		t.Fatalf("late success accepted: %v", err)
	}
	if writes != 1 {
		t.Fatal("later record renewed frame write budget")
	}
}

func TestReadChecksElapsedAfterSynchronousCompletion(t *testing.T) {
	var now atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(now.Load()), true }))
	c, s := channelsWithClock(t, clock)
	wire, err := c.Encrypt(nil, envelope([]byte("late")))
	if err != nil {
		t.Fatal(err)
	}
	io := &functionalIO{read: func(_ context.Context, dst []byte) ([]byte, error) {
		now.Store(int64(30 * time.Second))
		return append(dst[:0], wire...), nil
	}}
	o, _ := (Options{}).Normalize()
	tr := newTransport(io, s, nil, o)
	defer tr.Close()
	if frame, err := tr.Recv(context.Background()); err != context.DeadlineExceeded || frame != nil {
		t.Fatalf("late frame returned: %v", err)
	}
	if _, ok := tr.ChannelIdentity(); ok {
		t.Fatal("late record authenticated")
	}
}

func TestCloseContextRetainsJoinOwner(t *testing.T) {
	c, s := channels(t)
	defer c.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	cfg := securechannel.ServerConfig{Scope: "test", Carrier: securechannel.TCP, AllowBootstrap: true, Authorize: func(context.Context, securechannel.VerifiedIdentity) error { close(entered); <-release; return nil }}
	m := &memoryIO{in: make(chan []byte, 1), out: make(chan []byte), done: make(chan struct{})}
	o, _ := (Options{}).Normalize()
	tr := newTransport(m, s, &cfg, o)
	defer tr.Close()
	defer close(release)
	putRecord(t, m, c, envelope([]byte("hello")))
	recvDone := make(chan error, 1)
	go func() { _, err := tr.Recv(context.Background()); recvDone <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("policy did not enter")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := tr.CloseContext(ctx); err != context.DeadlineExceeded {
		t.Fatalf("unfinished join reported success: %v", err)
	}
	select {
	case <-m.done:
	default:
		t.Fatal("carrier not stopped before join")
	}
	select {
	case <-tr.stopped:
		t.Fatal("unfinished policy owner lost")
	default:
	}
	// Recv remains owned until the synchronous callback returns.
	select {
	case <-recvDone:
		t.Fatal("initial frame escaped the policy barrier")
	default:
	}
}

func TestServerHelloAndOriginShareBudget(t *testing.T) {
	var now atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(now.Load()), true }))
	b, err := NewEstablishmentBudget(clock, 15*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c, s := driverPair(t, securechannel.Bootstrap, Options{}, Options{Budget: b})
	now.Store(int64(5 * time.Second))
	if err := c.Send(context.Background(), []byte("late hello")); err != nil {
		t.Fatal(err)
	}
	if frame, err := s.Recv(context.Background()); frame != nil || (err != context.DeadlineExceeded && err != ErrClosed) {
		t.Fatalf("server hello renewed phase: %v", err)
	}
	if _, ok := s.VerifiedIdentity(); ok {
		t.Fatal("expired responder identity")
	}
}
