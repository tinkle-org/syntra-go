// File declared_deadline_test.go exercises fresh driver timing after source-only suspension.
package ordered

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
)

// TestDeclaredDriverDeadlineSamplesSchedulerBeforeElapsed prevents the scheduler
// projection from renewing time between its elapsed sample and scheduler sample.
// The real clock's source marks the first Age call without production clock hooks.
func TestDeclaredDriverDeadlineSamplesSchedulerBeforeElapsed(t *testing.T) {
	const until, age = time.Second, 20 * time.Millisecond
	var calls atomic.Int32
	sampled := make(chan time.Time, 1)
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) {
		switch calls.Add(1) {
		case 1:
			return 0, true // Clock constructor's origin, before elapsedContext.
		case 2:
			at := time.Now()
			// Cross a real scheduler-clock tick so a later timer sample must
			// exceed the marker; no sleep duration or scheduling race is assumed.
			for !time.Now().After(at) {
			}
			sampled <- at
		}
		return age, true
	}))
	ctx, cancel := elapsedContext(context.Background(), clock, until)
	defer cancel()
	at := <-sampled
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(at.Add(until-age)) {
		t.Fatalf("scheduler projection renewed after elapsed sample: deadline=%v latest=%v", deadline, at.Add(until-age))
	}
}

// declaredReceiptIO explicitly opts the in-memory encrypted carrier into terminal I/O.
type declaredReceiptIO struct{ *memoryIO }

// SupportsTerminalReceipt declares the test carrier's coordinated ownership.
func (*declaredReceiptIO) SupportsTerminalReceipt() bool { return true }

// declaredSendDriver injects suspension immediately before the real ordered send.
type declaredSendDriver struct {
	*Transport
	beforeSend  func()
	plainParent bool
}

// TerminalReceiptDriver retains the wrapper so its send barrier is exercised.
func (d *declaredSendDriver) TerminalReceiptDriver() syntra.TerminalReceiptDriver { return d }

// SendTerminal delegates the entire write, including validation and handoff, to stock code.
func (d *declaredSendDriver) SendTerminal(ctx context.Context, p *syntra.TerminalPermit) error {
	if d.plainParent {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
	}
	if d.beforeSend != nil {
		d.beforeSend()
	}
	return d.Transport.SendTerminal(ctx, p)
}

// declaredAuthority keeps exact owned evidence for the real terminal coordinator.
type declaredAuthority struct {
	owned  atomic.Bool
	reads  atomic.Int32
	commit func(context.Context) error
}

// Commit optionally exercises a periodic-style refresh before recording ownership.
func (a *declaredAuthority) Commit(ctx context.Context, _ syntra.TerminalTransition) error {
	if a.commit != nil {
		if err := a.commit(ctx); err != nil {
			return err
		}
	}
	a.owned.Store(true)
	return nil
}

// Observe returns exact active or owned evidence without renewing callback timing.
func (a *declaredAuthority) Observe(ctx context.Context, tr syntra.TerminalTransition) (syntra.TerminalObservation, error) {
	a.reads.Add(1)
	if b, ok := syntra.RequestBudgetFromContext(ctx); !ok || b.Remaining() == 0 {
		return syntra.TerminalObservation{}, context.DeadlineExceeded
	}
	state, revision := syntra.TerminalActive, uint64(1)
	if a.owned.Load() {
		state, revision = syntra.TerminalOwnedCommitted, 2
	}
	return syntra.TerminalObservation{State: state, Transition: tr, Revision: revision}, nil
}

// TestDeclaredDriverDeadlineAfterSourceOnlySuspend requires one real encrypted
// terminal frame after a source-only jump, both at SendTerminal and fresh refresh.
// An actually earlier plain parent must still forbid any proof or ciphertext.
func TestDeclaredDriverDeadlineAfterSourceOnlySuspend(t *testing.T) {
	for _, test := range []struct {
		stage string
		plain bool
	}{
		{stage: "send"}, {stage: "refresh"},
		{stage: "send", plain: true}, {stage: "refresh", plain: true},
	} {
		name := test.stage
		if test.plain {
			name += "/plain-parent"
		}
		t.Run(name, func(t *testing.T) {
			var age atomic.Int64
			clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) {
				return time.Duration(age.Load()), true
			}))
			static, err := securechannel.GenerateStaticKey()
			if err != nil {
				t.Fatal(err)
			}
			key := securechannel.Key{9}
			cc := securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Returning, Carrier: securechannel.TCP, Scope: "declared", ServerKeyID: 1, Handle: [8]byte{1}, Epoch: 1}, ServerPublicKey: static.Public(), AuthorizationKey: key}
			sc := securechannel.ServerConfig{StaticKey: static, ServerKeyID: 1, Scope: "declared", Carrier: securechannel.TCP,
				LookupKey: func(context.Context, securechannel.Context) (securechannel.Key, error) { return key, nil }}
			i, first, err := securechannel.Begin(cc)
			if err != nil {
				t.Fatal(err)
			}
			defer i.Close()
			server, second, err := securechannel.RespondWithClock(context.Background(), sc, first, clock)
			if err != nil {
				t.Fatal(err)
			}
			client, err := i.Finish(second)
			if err != nil {
				server.Close()
				t.Fatal(err)
			}
			defer client.Close()
			m := &memoryIO{in: make(chan []byte, 8), out: make(chan []byte, 8), done: make(chan struct{})}
			opts, err := (Options{EnableTerminalReceipts: true, WriteTimeout: 200 * time.Millisecond}).Normalize()
			if err != nil {
				t.Fatal(err)
			}
			tr := newTransport(&declaredReceiptIO{m}, server, &sc, opts)
			tr.establish(15*time.Second, 5*time.Second, true)
			defer tr.Close()
			driver := &declaredSendDriver{Transport: tr, plainParent: test.plain}
			authority := &declaredAuthority{}
			var readsBeforeJump int32
			jump := func() {
				readsBeforeJump = authority.reads.Load()
				age.Store(int64(500 * time.Millisecond))
			}
			if test.stage == "send" {
				driver.beforeSend = jump
			} else {
				authority.commit = func(context.Context) error {
					parent := context.Background()
					if test.plain {
						var cancel context.CancelFunc
						parent, cancel = context.WithTimeout(parent, 100*time.Millisecond)
						defer cancel()
					}
					jump()
					// Same fresh driver context/classifier as idle supervision,
					// without waiting for a ticker or the request's proof path.
					return tr.checkPeerMode(parent, tr.operationDeadline(opts.WriteTimeout), false, false, nil)
				}
			}
			result := make(chan error, 1)
			const method = "/example.Authority/Retire"
			host, err := syntra.OpenHost(syntra.HostConfig{
				ChannelPolicy:   func(context.Context, syntra.ChannelIdentity, []byte) (string, error) { return "principal", nil },
				Authorize:       syntra.AllowAllAuthorize,
				TerminalMethods: map[string]syntra.TerminalMethodPolicy{method: {SuccessPayload: []byte("retired"), Authority: authority, ObservationTimeout: 100 * time.Millisecond}},
				Handler: func(ctx context.Context, _ *syntra.RpcRequest) (*syntra.RpcResult, error) {
					err := syntra.CompleteTerminalReceipt(ctx, "operation", 1)
					result <- err
					return nil, err
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- host.Serve(ctx, driver) }()
			defer func() { cancel(); tr.Stop(); terminalRaceWait(t, done) }()
			hello, _ := syntra.MarshalFrame(syntra.NewHelloFrame(&syntra.ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
			putRecord(t, m, client, envelope(hello))
			if _, err := client.Decrypt(nil, terminalRaceWait(t, m.out)); err != nil {
				t.Fatal(err)
			}
			request, _ := syntra.MarshalFrame(syntra.NewRequestFrame(1, 1, &syntra.RpcRequest{Method: method, TimeoutMs: 3000}))
			putRecord(t, m, client, envelope(request))
			err = terminalRaceWait(t, result)
			if test.plain {
				if err == nil || len(m.out) != 0 || authority.reads.Load() != readsBeforeJump {
					t.Fatalf("expired plain parent admitted proof/ciphertext: err=%v frames=%d reads=%d before=%d", err, len(m.out), authority.reads.Load(), readsBeforeJump)
				}
				return
			}
			if err != nil {
				t.Fatalf("fresh %s context reprojected through old receipt: %v age=%v reads=%d owned=%v transport=%v", test.stage, err, time.Duration(age.Load()), authority.reads.Load(), authority.owned.Load(), tr.TerminalError())
			}
			plain, err := client.Decrypt(nil, terminalRaceWait(t, m.out))
			if err != nil {
				t.Fatal(err)
			}
			var decoder securechannel.FrameDecoder
			frames, err := decoder.Push(plain)
			if err != nil || len(frames) != 1 {
				t.Fatalf("terminal frame count=%d err=%v", len(frames), err)
			}
			frame, err := syntra.UnmarshalFrame(frames[0])
			if err != nil || frame.GetRequestId() != 1 || string(frame.GetResult().GetPayload()) != "retired" {
				t.Fatalf("terminal result=%v err=%v", frame, err)
			}
			if len(m.out) != 0 {
				t.Fatal("more than one terminal frame emitted")
			}
		})
	}
}
