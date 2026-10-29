package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

type shortConn struct {
	net.Conn
	chunk int
}

func (c shortConn) Read(p []byte) (int, error)  { return c.Conn.Read(p[:min(len(p), c.chunk)]) }
func (c shortConn) Write(p []byte) (int, error) { return c.Conn.Write(p[:min(len(p), c.chunk)]) }

func configs(t testing.TB) (securechannel.ClientConfig, securechannel.ServerConfig) {
	t.Helper()
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := securechannel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cc := securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Returning, Carrier: securechannel.TCP, Scope: "test", Epoch: 9, Handle: [8]byte{1}}, ServerPublicKey: key.Public(), AuthorizationKey: psk}
	sc := securechannel.ServerConfig{StaticKey: key, Scope: "test", Carrier: securechannel.TCP, Lookup: func(context.Context, securechannel.Context) (securechannel.Enrollment, error) {
		return securechannel.Enrollment{Key: psk, Principal: "device", ExpiresAt: time.Now().Add(time.Hour)}, nil
	}}
	return cc, sc
}

func pair(t testing.TB, chunk int) (*ordered.Transport, *ordered.Transport) {
	t.Helper()
	cc, sc := configs(t)
	return pairWithConfigs(t, chunk, cc, sc)
}

func pairWithConfigs(t testing.TB, chunk int, cc securechannel.ClientConfig, sc securechannel.ServerConfig) (*ordered.Transport, *ordered.Transport) {
	t.Helper()
	a, b := net.Pipe()
	if chunk > 0 {
		a, b = shortConn{a, chunk}, shortConn{b, chunk}
	}
	type result struct {
		tr  *ordered.Transport
		err error
	}
	done := make(chan result, 1)
	go func() { tr, err := Server(context.Background(), b, sc, ordered.Options{}); done <- result{tr, err} }()
	client, err := Client(context.Background(), a, cc, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := <-done
	if s.err != nil {
		client.Close()
		t.Fatal(s.err)
	}
	t.Cleanup(func() { client.Close(); s.tr.Close() })
	return client, s.tr
}

func TestShortWritesAndOwnedLargeFrames(t *testing.T) {
	for _, chunk := range []int{1, 97, 0} {
		t.Run(time.Duration(chunk).String(), func(t *testing.T) {
			client, server := pair(t, chunk)
			sizes := []int{1, 65515, 65516, ordered.MaxFrame}
			if chunk == 1 {
				sizes = []int{1, 257}
			}
			var previous []byte
			for _, size := range sizes {
				want := bytes.Repeat([]byte{byte(size)}, size)
				done := make(chan error, 1)
				go func() { done <- client.Send(context.Background(), want) }()
				got, err := server.Recv(context.Background())
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("size %d: %v", size, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if previous != nil && previous[0] != 42 {
					t.Fatal("returned frame aliases scratch")
				}
				got[0] = 42
				previous = got
			}
		})
	}
}

func TestConcurrentSendsSerializeWholeEnvelope(t *testing.T) {
	client, server := pair(t, 0)
	const count = 12
	errs := make(chan error, count)
	for j := 0; j < count; j++ {
		go func(j int) { errs <- client.Send(context.Background(), bytes.Repeat([]byte{byte(j)}, 150000)) }(j)
	}
	seen := make(map[byte]bool)
	for j := 0; j < count; j++ {
		frame, err := server.Recv(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(frame) != 150000 || !bytes.Equal(frame, bytes.Repeat(frame[:1], len(frame))) || seen[frame[0]] {
			t.Fatal("interleaved envelope")
		}
		seen[frame[0]] = true
	}
	for j := 0; j < count; j++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestCancelMidRecordClosesBothDirections(t *testing.T) {
	cc, sc := configs(t)
	a, b := net.Pipe()
	serverDone := make(chan *ordered.Transport, 1)
	go func() {
		tr, err := Server(context.Background(), b, sc, ordered.Options{})
		if err != nil {
			serverDone <- nil
			return
		}
		serverDone <- tr
	}()
	client, err := Client(context.Background(), a, cc, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	server := <-serverDone
	if server == nil {
		t.Fatal("server handshake")
	}
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Send(ctx, make([]byte, ordered.MaxFrame)) }()
	// Read only the first record's length: encryption has consumed a nonce,
	// but no ciphertext can be accepted by this intentionally stalled peer.
	var prefix [2]byte
	if _, err := io.ReadFull(b, prefix[:]); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel blocked")
	}
	if err := client.Send(context.Background(), []byte("reuse")); !errors.Is(err, ordered.ErrClosed) {
		t.Fatal(err)
	}
}

func TestWireLengthBoundTruncationAndRecordDeadline(t *testing.T) {
	for _, wire := range [][]byte{{0, 0}, {0, 49}, {0, 2, 1}} {
		t.Run(string(wire), func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			go func() { defer b.Close(); b.Write(wire) }()
			m := messageIO{a, 50 * time.Millisecond}
			var dst [48]byte
			if _, err := m.ReadMessage(context.Background(), dst[:0]); err == nil {
				t.Fatal("invalid/truncated message accepted")
			}
		})
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	m := messageIO{a, 30 * time.Millisecond}
	done := make(chan error, 1)
	go func() { var dst [100]byte; _, err := m.ReadMessage(context.Background(), dst[:0]); done <- err }()
	// Idle longer than the record budget must remain allowed.
	select {
	case err := <-done:
		t.Fatalf("idle timed out: %v", err)
	case <-time.After(45 * time.Millisecond):
	}
	if _, err := b.Write([]byte{0}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("partial prefix accepted")
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("prefix assembly not bounded")
	}
}

func TestTCPPacketsCoalesceAndPrefixPreallocated(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() { b.Write([]byte{0, 1, 7, 0, 2, 8, 9}) }()
	m := messageIO{a, time.Second}
	var scratch [8]byte
	for _, want := range [][]byte{{7}, {8, 9}} {
		got, err := m.ReadMessage(context.Background(), scratch[:0])
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%v %v", got, err)
		}
	}
}

func TestDialRealSocketAndCanceledHandshake(t *testing.T) {
	cc, sc := configs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan *ordered.Transport, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- nil
			return
		}
		server, err := Server(context.Background(), conn, sc, ordered.Options{})
		if err != nil {
			serverDone <- nil
			return
		}
		serverDone <- server
	}()
	client, err := Dial(context.Background(), listener.Addr().String(), cc, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-serverDone
	if server == nil {
		t.Fatal("server failed")
	}
	defer server.Close()
	done := make(chan error, 1)
	go func() { done <- client.Send(context.Background(), []byte("socket")) }()
	frame, err := server.Recv(context.Background())
	if err != nil || string(frame) != "socket" {
		t.Fatalf("%q %v", frame, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	a, b := net.Pipe()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Client(ctx, a, cc, ordered.Options{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	var scratch [1]byte
	if _, err := b.Read(scratch[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("failed handshake kept socket alive: %v", err)
	}
}

func TestSilentDialIsBoundedByEstablishmentLifetime(t *testing.T) {
	cc, _ := configs(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := dial(ctx, "unused", cc, ordered.Options{Lifetime: 30 * time.Millisecond}, func(ctx context.Context, network, address string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("silent TCP dial ignored Lifetime")
	}
}

func TestDialSubtractsElapsedBeforeSC1Handshake(t *testing.T) {
	cc, _ := configs(t)
	var dialingDeadline time.Time
	var handshakeDeadline time.Time
	conn, peer := net.Pipe()
	defer peer.Close()
	// The injected dial waits until its entry budget expires, then deliberately
	// returns a socket anyway. The adapter must reject it without writing M1.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tr, err := dial(ctx, "unused", cc, ordered.Options{Lifetime: 30 * time.Millisecond}, func(ctx context.Context, _, _ string) (net.Conn, error) {
		dialingDeadline, _ = ctx.Deadline()
		<-ctx.Done()
		return conn, nil
	})
	if tr != nil {
		tr.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired establishment entered SC1: %v", err)
	}
	handshakeDeadline, _ = ctx.Deadline()
	if !dialingDeadline.Before(handshakeDeadline) {
		t.Fatal("dial did not receive shorter Lifetime budget")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var first [1]byte
	if _, err := peer.Read(first[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("expired socket was not closed before M1: %v", err)
	}
}

func TestRootRPCChannelPolicyAndFreshReconnect(t *testing.T) {
	cc, sc := configs(t)
	var policyCalls int
	var mu sync.Mutex
	host, err := syntra.OpenHost(syntra.HostConfig{
		ChannelPolicy: func(_ context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			if id.Mode != "returning" || id.Carrier != "tcp" || id.Scope != "test" || id.Epoch != 9 || id.Handle != ([8]byte{1}) || id.Principal != "device" || string(credential) != "explicit" {
				return "", errors.New("invalid binding")
			}
			mu.Lock()
			policyCalls++
			mu.Unlock()
			return "verified", nil
		},
		Authorize: func(_ context.Context, principal, method string) error {
			if principal != "verified" {
				return errors.New("wrong principal")
			}
			return nil
		},
		Handler: func(_ context.Context, req *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return syntra.NewSuccessResult(req.GetPayload()), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	for reconnect := 0; reconnect < 2; reconnect++ {
		clientTR, serverTR := pairWithConfigs(t, 0, cc, sc)
		if _, ok := serverTR.ChannelIdentity(); ok {
			t.Fatal("reconnect inherited confirmation")
		}
		client, err := syntra.OpenClient(syntra.ClientConfig{Credential: []byte("explicit")})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		serveDone, runDone := make(chan error, 1), make(chan error, 1)
		go func() { serveDone <- host.Serve(ctx, serverTR) }()
		go func() { runDone <- client.Run(ctx, clientTR) }()
		for {
			out, callErr := client.Call(ctx, "/example.Echo/Echo", []byte("root-rpc"), 1000)
			if callErr == nil {
				if string(out) != "root-rpc" {
					t.Fatal("wrong result")
				}
				break
			}
			if ctx.Err() != nil {
				t.Fatalf("RPC failed: %v", callErr)
			}
			time.Sleep(time.Millisecond)
		}
		if _, ok := serverTR.ChannelIdentity(); !ok {
			t.Fatal("RPC did not confirm channel")
		}
		cancel()
		client.Close()
		clientTR.Close()
		serverTR.Close()
		for _, done := range []chan error{serveDone, runDone} {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("session did not stop")
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if policyCalls != 2 {
		t.Fatalf("policy calls = %d", policyCalls)
	}
}

func BenchmarkNetPipeReassembly(b *testing.B) {
	client, server := pair(b, 0)
	frame := make([]byte, 128*1024)
	done := make(chan error, 1)
	b.ReportAllocs()
	b.SetBytes(int64(len(frame)))
	b.ResetTimer()
	go func() {
		for i := 0; i < b.N; i++ {
			if err := client.Send(context.Background(), frame); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < b.N; i++ {
		if _, err := server.Recv(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		b.Fatal(err)
	}
}

var prefixSink [2]byte

func BenchmarkTCPPrefixPreallocated(b *testing.B) {
	lengths := [...]uint16{17, 48, 1024, 65535}
	b.ReportAllocs()
	b.SetBytes(2)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.BigEndian.PutUint16(prefixSink[:], lengths[i&3])
	}
	b.StopTimer()
	if got := binary.BigEndian.Uint16(prefixSink[:]); got != lengths[(b.N-1)&3] {
		b.Fatalf("record prefix = %d", got)
	}
}
