// File receipt_timing_test.go checks assembly and pre-delivery timing ownership.
package ordered

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
)

// timingDecoder advances only this receiver's clock around real synchronous assembly.
type timingDecoder struct {
	securechannel.FrameDecoder
	before, after func()
}

// Push exercises the actual decoder between independently injected suspensions.
func (d *timingDecoder) Push(plain []byte) ([][]byte, error) {
	if d.before != nil {
		d.before()
	}
	frames, err := d.FrameDecoder.Push(plain)
	if d.after != nil {
		d.after()
	}
	return frames, err
}

// timingReceiver builds a stock record owner on an independently advanced clock.
func timingReceiver(t *testing.T, age *atomic.Int64, opts Options) (*Transport, *securechannel.Channel, *memoryIO) {
	t.Helper()
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	client, server := channelsWithClock(t, clock)
	m := &memoryIO{in: make(chan []byte, 8), out: make(chan []byte, 8), done: make(chan struct{})}
	o, err := opts.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	tr := newTransport(m, server, nil, o)
	t.Cleanup(func() { _ = tr.Close() })
	return tr, client, m
}

// TestReceiptBatchBeforeAssemblyAndDelivery preserves one completing-batch
// origin across coalescing, fragmentation, assembly work and delayed queue pops.
func TestReceiptBatchBeforeAssemblyAndDelivery(t *testing.T) {
	for _, fragmented := range []bool{false, true} {
		t.Run(fmt.Sprint(fragmented), func(t *testing.T) {
			var age atomic.Int64
			tr, client, m := timingReceiver(t, &age, Options{})
			timed, ok := any(tr).(syntra.FrameReceiptTransport)
			if !ok {
				t.Fatal("stock driver lacks atomic frame receipt capability")
			}
			first := envelope([]byte("first"))
			if fragmented {
				putRecord(t, m, client, first[:4])
				// The first fragment is not the request origin.
				d := &timingDecoder{after: func() { age.Store(int64(10 * time.Millisecond)) }}
				tr.decoder = d
				first = first[4:]
			} else {
				age.Store(int64(10 * time.Millisecond))
			}
			d := tr.decoder
			// Replace the instrumentation after the partial push, retaining its state.
			tr.decoder = &completionTimingDecoder{frameDecoder: d, age: &age}
			putRecord(t, m, client, append(first, envelope([]byte("second"))...))
			_, r1, err := timed.RecvWithReceipt(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			age.Store(int64(90 * time.Millisecond))
			_, r2, err := timed.RecvWithReceipt(context.Background())
			if err != nil || r1 != r2 || r1.ElapsedAge() != 10*time.Millisecond {
				t.Fatalf("batch origin renewed: first=%v second=%v err=%v", r1.ElapsedAge(), r2.ElapsedAge(), err)
			}
		})
	}
}

// completionTimingDecoder suspends only after a batch completes at least one frame.
type completionTimingDecoder struct {
	frameDecoder
	age *atomic.Int64
}

// Push retains fragmented state while advancing trusted time after completion.
func (d *completionTimingDecoder) Push(p []byte) ([][]byte, error) {
	frames, err := d.frameDecoder.Push(p)
	if len(frames) != 0 {
		d.age.Store(int64(80 * time.Millisecond))
	}
	return frames, err
}

// TestReceiptAssemblyRechecksOldBounds covers record/partial/Hello/Ready bounds
// at exact expiry before a completed batch clears or replaces assembly state.
func TestReceiptAssemblyRechecksOldBounds(t *testing.T) {
	for _, bound := range []string{"record", "partial", "hello", "ready", "new-partial"} {
		for _, point := range []string{"before", "after"} {
			t.Run(bound+"/"+point, func(t *testing.T) {
				var age atomic.Int64
				opts := Options{RecordTimeout: time.Second, FrameTimeout: 50 * time.Millisecond}
				if bound == "record" {
					opts.RecordTimeout = 50 * time.Millisecond
				}
				tr, client, m := timingReceiver(t, &age, opts)
				d := &timingDecoder{}
				plain := envelope([]byte("complete"))
				if bound == "partial" {
					if _, err := d.Push(plain[:4]); err != nil {
						t.Fatal(err)
					}
					tr.frameDeadline = 50 * time.Millisecond
					plain = plain[4:]
				}
				if bound == "hello" || bound == "ready" {
					tr.establish(time.Second, 50*time.Millisecond, bound == "hello")
				}
				if bound == "new-partial" {
					plain = append(plain, 0)
				}
				advance := func() { age.Store(int64(50 * time.Millisecond)) }
				if point == "before" {
					d.before = advance
				} else {
					d.after = advance
				}
				tr.decoder = d
				putRecord(t, m, client, plain)
				if frame, err := tr.Recv(context.Background()); frame != nil || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("expired assembly delivered frame: frame=%q err=%v", frame, err)
				}
			})
		}
	}
}

// TestReceiptBufferedBeforeHostLoopChargesPreauthorization proves that stock
// assembly metadata survives the root handshake, owned wrapper and receive pump.
func TestReceiptBufferedBeforeHostLoopChargesPreauthorization(t *testing.T) {
	for _, stage := range []string{"assembly", "channel-authorization", "host-policy"} {
		t.Run(stage, func(t *testing.T) {
			var age atomic.Int64
			tr, client, m := timingReceiver(t, &age, Options{})
			if stage == "assembly" {
				tr.decoder = &timingDecoder{after: func() { age.Store(int64(80 * time.Millisecond)) }}
			}
			if stage == "channel-authorization" {
				tr.peerRequired = true
				tr.server = &securechannel.ServerConfig{Scope: "test", Carrier: securechannel.TCP, AllowBootstrap: true,
					Authorize: func(context.Context, securechannel.VerifiedIdentity) error {
						age.Store(int64(80 * time.Millisecond))
						return nil
					}}
			}
			var authorizations atomic.Int32
			host, err := syntra.OpenHost(syntra.HostConfig{
				Policy: func(context.Context, []byte) (string, error) {
					if stage == "host-policy" {
						age.Store(int64(80 * time.Millisecond))
					}
					return "principal", nil
				},
				RequestBudget: func(string, string, []byte) (time.Duration, bool) { return 40 * time.Millisecond, true },
				Authorize:     func(context.Context, string, string) error { authorizations.Add(1); return nil },
				Handler: func(context.Context, *syntra.RpcRequest) (*syntra.RpcResult, error) {
					return syntra.NewSuccessResult(nil), nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			hello, _ := syntra.MarshalFrame(syntra.NewHelloFrame(&syntra.ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
			request, _ := syntra.MarshalFrame(syntra.NewRequestFrame(1, 1, &syntra.RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 1000}))
			putRecord(t, m, client, append(envelope(hello), envelope(request)...))
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- host.Serve(ctx, tr) }()
			defer func() { cancel(); _ = tr.Close(); <-done }()
			var decoder securechannel.FrameDecoder
			for results := 0; results < 2; {
				select {
				case wire := <-m.out:
					plain, err := client.Decrypt(nil, wire)
					if err != nil {
						t.Fatal(err)
					}
					frames, err := decoder.Push(plain)
					if err != nil {
						t.Fatal(err)
					}
					for _, raw := range frames {
						frame, err := syntra.UnmarshalFrame(raw)
						if err != nil {
							t.Fatal(err)
						}
						results++
						if frame.GetResult() != nil && frame.GetResult().GetError().GetCode() != syntra.ErrorCodeDeadlineExceeded {
							t.Errorf("preauthorization delay forgiven: result=%v", frame.GetResult())
						}
					}
				case <-ctx.Done():
					t.Fatal("missing Ready or request result")
				}
			}
			if authorizations.Load() != 0 {
				t.Fatal("buffered expired request reached authorization")
			}
		})
	}
}

// TestReceiptReadyHandoffRetainsPartialDeadline keeps a trailing partial's
// pre-assembly cutoff after Ready ends establishment and the caller starts Recv.
func TestReceiptReadyHandoffRetainsPartialDeadline(t *testing.T) {
	var age atomic.Int64
	tr, client, m := timingReceiver(t, &age, Options{FrameTimeout: 50 * time.Millisecond})
	tr.establish(time.Second, time.Second, false)
	tr.decoder = &timingDecoder{after: func() { age.Store(int64(40 * time.Millisecond)) }}
	next := envelope([]byte("after-ready"))
	putRecord(t, m, client, append(envelope([]byte("ready")), next[:4]...))
	putRecord(t, m, client, next[4:])
	if raw, err := tr.Recv(context.Background()); err != nil || string(raw) != "ready" {
		t.Fatalf("healthy Ready handoff: raw=%q err=%v", raw, err)
	}
	age.Store(int64(50 * time.Millisecond))
	if raw, err := tr.Recv(context.Background()); raw != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Ready renewed trailing assembly deadline: raw=%q err=%v", raw, err)
	}
}

// TestReceiptConcurrentReceiversKeepFrameMetadata exercises competing receive
// callers across multiple completion batches without a last-received side channel.
func TestReceiptConcurrentReceiversKeepFrameMetadata(t *testing.T) {
	var age atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	client, server := channelsWithClock(t, clock)
	const batches = 8
	wires := make([][]byte, batches)
	for i := range wires {
		plain := append(envelope([]byte{byte(i), 0}), envelope([]byte{byte(i), 1})...)
		var err error
		wires[i], err = client.Encrypt(nil, plain)
		if err != nil {
			t.Fatal(err)
		}
	}
	index := 0 // accessed only under the stock receiver gate
	io := &functionalIO{read: func(_ context.Context, dst []byte) ([]byte, error) {
		if index == len(wires) {
			return nil, ErrIO
		}
		wire := wires[index]
		index++
		age.Store(int64(time.Duration(index) * 10 * time.Millisecond))
		return append(dst[:0], wire...), nil
	}}
	opts, err := (Options{}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	tr := newTransport(io, server, nil, opts)
	defer tr.Close()
	var callers sync.WaitGroup
	for range 2 * batches {
		callers.Add(1)
		go func() {
			defer callers.Done()
			raw, receipt, err := tr.RecvWithReceipt(context.Background())
			if err != nil || len(raw) != 2 {
				t.Errorf("concurrent receive: raw=%v err=%v", raw, err)
				return
			}
			want := time.Duration(raw[0]+1) * 10 * time.Millisecond
			if receipt.ElapsedAge() != want {
				t.Errorf("frame/receipt mismatch: raw=%v age=%v want=%v", raw, receipt.ElapsedAge(), want)
			}
		}()
	}
	callers.Wait()
}

// TestReceiptAssemblyDiscontinuityFailsClosed invalidates the original clock
// during assembly and rejects every completed frame before identity/readiness.
func TestReceiptAssemblyDiscontinuityFailsClosed(t *testing.T) {
	var age atomic.Int64
	tr, client, m := timingReceiver(t, &age, Options{})
	tr.decoder = &timingDecoder{after: tr.channel.Clock().Invalidate}
	putRecord(t, m, client, envelope([]byte("never-delivered")))
	if raw, receipt, err := tr.RecvWithReceipt(context.Background()); err == nil || raw != nil || receipt != (syntra.FrameReceipt{}) {
		t.Fatalf("discontinuous assembly escaped: raw=%q receipt=%v err=%v", raw, receipt, err)
	}
}

// TestReceiptExpiredNewPartialSkipsPeerRead prevents synchronous assembly from
// starting another authority read after its newly created partial budget expires.
func TestReceiptExpiredNewPartialSkipsPeerRead(t *testing.T) {
	var age atomic.Int64
	tr, client, m := timingReceiver(t, &age, Options{FrameTimeout: 50 * time.Millisecond})
	var reads atomic.Int32
	tr.peerRequired, tr.peerAuthorized = true, true
	tr.server = &securechannel.ServerConfig{Scope: "test", Carrier: securechannel.TCP, AllowBootstrap: true,
		Authorize: func(context.Context, securechannel.VerifiedIdentity) error { reads.Add(1); return nil }}
	tr.decoder = &timingDecoder{after: func() { age.Store(int64(50 * time.Millisecond)) }}
	putRecord(t, m, client, append(envelope([]byte("complete")), 0))
	if raw, err := tr.Recv(context.Background()); raw != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired partial delivered: raw=%q err=%v", raw, err)
	}
	if reads.Load() != 0 {
		t.Fatal("expired new partial started an unnecessary authority read")
	}
}
