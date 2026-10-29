package syntra

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"
)

const benchmarkSessionWait = 5 * time.Second

type benchmarkSessionPair struct {
	client *Client
	host   *Host
	a, b   Transport
	cancel context.CancelFunc
	run    chan error
	serve  chan error
	once   sync.Once
}

func benchmarkSessionConfigs() (ClientConfig, HostConfig) {
	return ClientConfig{
			MinVersion: 1, MaxVersion: 1, Credential: []byte("benchmark-credential"),
			DefaultTimeout: benchmarkSessionWait,
		}, HostConfig{
			MinVersion: 1, MaxVersion: 1,
			Policy: StaticPolicy("benchmark-principal", true), Authorize: AllowAllAuthorize,
			Handler: func(ctx context.Context, req *RpcRequest) (*RpcResult, error) {
				if req.GetMethod() != benchmarkEchoMethod {
					return nil, NewRpcError(ErrorCodeUnimplemented, "unknown method")
				}
				return NewSuccessResult(bytes.Clone(req.GetPayload())), nil
			},
		}
}

// The caller owns cleanup. Register it once per throughput run, rather than
// retaining one testing cleanup closure for every handshake iteration.
func newBenchmarkSessionPair(tb testing.TB, ccfg ClientConfig, hcfg HostConfig) *benchmarkSessionPair {
	tb.Helper()
	host, err := OpenHost(hcfg)
	if err != nil {
		tb.Fatal(err)
	}
	client, err := OpenClient(ccfg)
	if err != nil {
		_ = host.Close()
		tb.Fatal(err)
	}
	a, z := LoopbackPair()
	ctx, cancel := context.WithCancel(context.Background())
	p := &benchmarkSessionPair{
		client: client, host: host, a: a, b: z, cancel: cancel,
		run: make(chan error, 1), serve: make(chan error, 1),
	}
	go func() { p.serve <- host.Serve(ctx, a) }()
	go func() { p.run <- client.Run(ctx, z) }()
	timer := time.NewTimer(benchmarkSessionWait)
	defer timer.Stop()
	select {
	case <-client.activated:
		return p
	case err := <-p.run:
		// Put the outcome back so cleanup can join both session goroutines.
		p.run <- err
		p.close(tb)
		tb.Fatalf("client exited before activation: %v", err)
	case err := <-p.serve:
		p.serve <- err
		p.close(tb)
		tb.Fatalf("host exited before activation: %v", err)
	case <-timer.C:
		p.close(tb)
		tb.Fatal("session activation timed out")
	}
	return nil
}

func (p *benchmarkSessionPair) close(tb testing.TB) {
	tb.Helper()
	p.once.Do(func() {
		for _, done := range []chan error{p.run, p.serve} {
			select {
			case err := <-done:
				done <- err
				tb.Errorf("session pump terminated before local shutdown: %v", err)
			default:
			}
		}
		p.cancel()
		// Both peers own their transport. During joint cancellation one peer can
		// close it before the other observes cancellation. No calls remain live.
		timer := time.NewTimer(benchmarkSessionWait)
		defer timer.Stop()
		for _, done := range []<-chan error{p.run, p.serve} {
			select {
			case err := <-done:
				var rpc *RpcError
				peerClosed := errors.As(err, &rpc) && rpc.Code == ErrorCodeUnavailable
				if err != nil && !errors.Is(err, context.Canceled) && !peerClosed {
					tb.Errorf("session pump: %v", err)
				}
			case <-timer.C:
				_ = p.client.Close()
				_ = p.host.Close()
				_ = p.a.Close()
				_ = p.b.Close()
				tb.Fatal("session teardown timed out")
			}
		}
		// Run owns client-core shutdown; Host.Close releases its factory.
		if err := p.host.Close(); err != nil {
			tb.Error(err)
		}
		if err := p.a.Close(); err != nil {
			tb.Error(err)
		}
		if err := p.b.Close(); err != nil {
			tb.Error(err)
		}
	})
}

func TestBenchmarkSessionReadinessAndEcho(t *testing.T) {
	ccfg, hcfg := benchmarkSessionConfigs()
	p := newBenchmarkSessionPair(t, ccfg, hcfg)
	t.Cleanup(func() { p.close(t) })
	want := []byte("first call after activation")
	got, err := p.client.Call(context.Background(), benchmarkEchoMethod, want, 5000)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("first echo differs")
	}
}

func BenchmarkSessionHeaderValidation(b *testing.B) {
	frame, err := MarshalFrame(NewRequestFrame(1, 1, &RpcRequest{Method: benchmarkEchoMethod, Payload: make([]byte, 1024)}))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := validateActiveSessionFrame(frame, 1); err != nil {
			b.Fatal(err)
		}
	}
}

func TestSessionHeaderValidationDoesNotAllocate(t *testing.T) {
	frame, err := MarshalFrame(NewRequestFrame(1, 1, &RpcRequest{Method: benchmarkEchoMethod, Payload: make([]byte, 1024)}))
	if err != nil {
		t.Fatal(err)
	}
	if got := testing.AllocsPerRun(100, func() {
		if err := validateActiveSessionFrame(frame, 1); err != nil {
			t.Fatal(err)
		}
	}); got != 0 {
		t.Fatalf("header validation allocated %g times", got)
	}
}

func BenchmarkSessionLoopback(b *testing.B) {
	for _, size := range benchmarkPayloadSizes {
		payload := bytes.Repeat([]byte{0x61}, size.size)
		b.Run(size.name, func(b *testing.B) {
			b.Run("Serial", func(b *testing.B) {
				ccfg, hcfg := benchmarkSessionConfigs()
				p := newBenchmarkSessionPair(b, ccfg, hcfg)
				b.Cleanup(func() { p.close(b) })
				b.ReportAllocs()
				b.SetBytes(int64(2 * len(payload)))
				var out []byte
				var err error
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					out, err = p.client.Call(context.Background(), benchmarkEchoMethod, payload, 5000)
					if err != nil {
						b.Fatal(err)
					}
					if !bytes.Equal(out, payload) {
						b.Fatal("echo differs")
					}
				}
				b.StopTimer()
				runtime.KeepAlive(out)
				b.ReportMetric(float64(b.N), "calls")
				b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "rpc/s")
			})
			for _, workers := range []int{1, 4, 16} {
				b.Run(fmt.Sprintf("Workers%d", workers), func(b *testing.B) {
					benchmarkSessionWorkers(b, payload, workers)
				})
			}
		})
	}
}

func benchmarkSessionWorkers(b *testing.B, payload []byte, workers int) {
	ccfg, hcfg := benchmarkSessionConfigs()
	p := newBenchmarkSessionPair(b, ccfg, hcfg)
	b.Cleanup(func() { p.close(b) })
	type result struct {
		completed int
		err       error
	}
	start := make(chan struct{})
	done := make(chan result, workers)
	for worker := 0; worker < workers; worker++ {
		go func(worker int) {
			<-start
			r := result{}
			for i := worker; i < b.N; i += workers {
				out, err := p.client.Call(context.Background(), benchmarkEchoMethod, payload, 5000)
				if err != nil {
					r.err = err
					break
				}
				if !bytes.Equal(out, payload) {
					r.err = errors.New("echo differs")
					break
				}
				r.completed++
			}
			done <- r
		}(worker)
	}
	b.ReportAllocs()
	b.SetBytes(int64(2 * len(payload)))
	completed := 0
	var firstErr error
	b.ResetTimer()
	close(start)
	for worker := 0; worker < workers; worker++ {
		r := <-done
		completed += r.completed
		if firstErr == nil {
			firstErr = r.err
		}
	}
	b.StopTimer()
	if firstErr != nil {
		b.Fatal(firstErr)
	}
	if completed != b.N {
		b.Fatalf("completed %d calls, want %d", completed, b.N)
	}
	b.ReportMetric(float64(completed), "calls")
	b.ReportMetric(float64(completed)/b.Elapsed().Seconds(), "rpc/s")
}

// Core creation, hello/ready encoding and validation, authentication completion,
// activation and both core closes are timed. Config resolution is excluded.
func BenchmarkSessionCoreHandshake(b *testing.B) {
	ccfg, hcfg := benchmarkSessionConfigs()
	clientCfg, err := resolveClientConfig(ccfg)
	if err != nil {
		b.Fatal(err)
	}
	hostCfg, err := resolveHostConfig(hcfg)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client, err := newClientCore(clientCfg)
		if err != nil {
			b.Fatal(err)
		}
		host, err := newHostCore(hostCfg)
		if err != nil {
			_ = client.close()
			b.Fatal(err)
		}
		hello, err := client.helloFrame()
		if err == nil {
			_, err = host.acceptHello(hello)
		}
		var ready []byte
		if err == nil {
			ready, err = host.authComplete("benchmark-principal")
		}
		if err == nil {
			var activated *ServerReady
			activated, err = client.activate(ready)
			if err == nil && (activated == nil || activated.GetConnectionId() == "" || client.version() != 1) {
				err = errors.New("invalid core activation")
			}
		}
		clientErr := client.close()
		hostErr := host.close()
		if err != nil || clientErr != nil || hostErr != nil {
			b.Fatalf("handshake: %v; client close: %v; host close: %v", err, clientErr, hostErr)
		}
	}
}

// The complete loopback lifecycle is timed, including setup, activation and
// cancellation/join/close. No application RPC is issued.
func BenchmarkSessionHandshake(b *testing.B) {
	ccfg, hcfg := benchmarkSessionConfigs()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p := newBenchmarkSessionPair(b, ccfg, hcfg)
		p.close(b)
	}
}
