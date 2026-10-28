package websocket

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	ws "github.com/coder/websocket"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

// This listener serves exactly one net.Pipe connection, without OS sockets.
// Subsequent Accept calls wait for Close, so http.Server.Serve stays joinable.
type benchmarkPipeListener struct {
	conn chan net.Conn
	done chan struct{}
	once sync.Once
}

func (l *benchmarkPipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conn:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *benchmarkPipeListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *benchmarkPipeListener) Addr() net.Addr { return benchmarkPipeAddr{} }

type benchmarkPipeAddr struct{}

func (benchmarkPipeAddr) Network() string { return "pipe" }
func (benchmarkPipeAddr) String() string  { return "benchmark.pipe" }

type benchmarkHTTPPipe struct {
	client                 *http.Client
	clientConn, serverConn net.Conn
}

func benchmarkJoin(b *testing.B, done <-chan error) {
	b.Helper()
	select {
	case err := <-done:
		if err != nil {
			b.Error(err)
		}
	case <-time.After(2 * time.Second):
		b.Error("benchmark worker did not stop")
	}
}

// Setup and cleanup run with timing stopped. Both pipe ends, the HTTP accept
// loop, and the one handler are closed/joined, including benchmark failure paths.
func benchmarkHTTPOverPipe(b *testing.B, handler http.HandlerFunc) *benchmarkHTTPPipe {
	b.Helper()
	b.StopTimer()
	clientConn, serverConn := net.Pipe()
	listener := &benchmarkPipeListener{conn: make(chan net.Conn, 1), done: make(chan struct{})}
	listener.conn <- serverConn
	handlerEntered, handlerDone := make(chan struct{}), make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(handlerEntered)
		defer close(handlerDone)
		handler(w, r)
	})}
	serveDone := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveDone <- err
	}()
	available := make(chan net.Conn, 1)
	available <- clientConn
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case conn := <-available:
			return conn, nil
		default:
			return nil, errors.New("benchmark pipe already dialed")
		}
	}}
	b.Cleanup(func() {
		b.StopTimer()
		_ = clientConn.Close()
		_ = serverConn.Close()
		_ = server.Close()
		_ = listener.Close()
		transport.CloseIdleConnections()
		benchmarkJoin(b, serveDone)
		select {
		case <-handlerEntered:
			select {
			case <-handlerDone:
			case <-time.After(2 * time.Second):
				b.Error("benchmark handler did not stop")
			}
		default:
		}
	})
	return &benchmarkHTTPPipe{client: &http.Client{Transport: transport}, clientConn: clientConn, serverConn: serverConn}
}

func benchmarkOrderedWSPair(b *testing.B) (*ordered.Transport, *ordered.Transport) {
	b.Helper()
	b.StopTimer()
	// Key provisioning and both SC1 handshakes are excluded from throughput.
	clientConfig, serverConfig := configs(b, securechannel.WS)
	type accepted struct {
		transport *ordered.Transport
		err       error
	}
	ready := make(chan accepted, 1)
	pipe := benchmarkHTTPOverPipe(b, func(w http.ResponseWriter, r *http.Request) {
		tr, err := Accept(context.Background(), w, r, serverConfig, Options{})
		ready <- accepted{tr, err}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := Dial(ctx, "ws://benchmark.pipe/sc1", clientConfig, Options{HTTPClient: pipe.client})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { b.StopTimer(); client.Close() })
	var server *ordered.Transport
	select {
	case result := <-ready:
		if result.err != nil {
			b.Fatal(result.err)
		}
		server = result.transport
	case <-ctx.Done():
		b.Fatal(ctx.Err())
	}
	b.Cleanup(func() { b.StopTimer(); server.Close() })
	return client, server
}

// One operation is a serial Send/Recv echo, carrying two complete owned frames.
// MB/s and frames/s count both directions; ns/op measures one round trip.
func BenchmarkWebSocketAdapterPipeEcho(b *testing.B) {
	for _, test := range []struct {
		name string
		size int
	}{{"64B", 64}, {"1KiB", 1024}, {"64KiB", 64 * 1024}} {
		b.Run(test.name, func(b *testing.B) {
			client, server := benchmarkOrderedWSPair(b)
			frame := bytes.Repeat([]byte{0x5a}, test.size)
			done := make(chan error, 1)
			start := make(chan struct{})
			go func() {
				<-start
				for i := 0; i < b.N; i++ {
					got, err := server.Recv(context.Background())
					if err != nil {
						done <- err
						return
					}
					if !bytes.Equal(got, frame) {
						done <- errors.New("benchmark server frame mismatch")
						return
					}
					if err := server.Send(context.Background(), got); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			b.Cleanup(func() { b.StopTimer(); client.Close(); server.Close(); benchmarkJoin(b, done) })
			b.ReportAllocs()
			b.SetBytes(int64(2 * test.size))
			b.ResetTimer()
			b.StartTimer()
			close(start)
			for i := 0; i < b.N; i++ {
				if err := client.Send(context.Background(), frame); err != nil {
					b.Fatal(err)
				}
				got, err := client.Recv(context.Background())
				if err != nil {
					b.Fatal(err)
				}
				if !bytes.Equal(got, frame) {
					b.Fatal("benchmark client frame mismatch")
				}
			}
			b.StopTimer()
			b.ReportMetric(2*float64(b.N)/b.Elapsed().Seconds(), "frames/s")
		})
	}
}

// The raw pair exposes the same in-memory HTTP upgrade, but leaves SC1 out so
// the library's actual frame/header encoder can be benchmarked independently.
func benchmarkRawWSPair(b *testing.B) (*ws.Conn, *ws.Conn, *benchmarkHTTPPipe) {
	b.Helper()
	ready := make(chan *ws.Conn, 1)
	errs := make(chan error, 1)
	pipe := benchmarkHTTPOverPipe(b, func(w http.ResponseWriter, r *http.Request) {
		conn, err := ws.Accept(w, r, &ws.AcceptOptions{Subprotocols: []string{Subprotocol}, CompressionMode: ws.CompressionDisabled})
		if err != nil {
			errs <- err
			return
		}
		ready <- conn
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, _, err := ws.Dial(ctx, "ws://benchmark.pipe/headers", &ws.DialOptions{HTTPClient: pipe.client, Subprotocols: []string{Subprotocol}, CompressionMode: ws.CompressionDisabled})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { b.StopTimer(); client.CloseNow() })
	var server *ws.Conn
	select {
	case server = <-ready:
	case err := <-errs:
		b.Fatal(err)
	case <-ctx.Done():
		b.Fatal(ctx.Err())
	}
	b.Cleanup(func() { b.StopTimer(); server.CloseNow() })
	return client, server, pipe
}

// Empty binary messages exercise the dependency's real encoder with no payload:
// six wire bytes for masked client headers and two for unmasked server headers.
func BenchmarkWebSocketHeaderEncode(b *testing.B) {
	for _, masked := range []bool{false, true} {
		name := "ServerUnmasked"
		if masked {
			name = "ClientMasked"
		}
		b.Run(name, func(b *testing.B) {
			client, server, pipe := benchmarkRawWSPair(b)
			writer, reader, headerBytes := server, pipe.clientConn, 2
			if masked {
				writer, reader, headerBytes = client, pipe.serverConn, 6
			}
			done := make(chan error, 1)
			start := make(chan struct{})
			go func() { <-start; _, err := io.CopyN(io.Discard, reader, int64(headerBytes)*int64(b.N)); done <- err }()
			b.Cleanup(func() { b.StopTimer(); client.CloseNow(); server.CloseNow(); benchmarkJoin(b, done) })
			b.ReportAllocs()
			b.SetBytes(int64(headerBytes))
			b.ResetTimer()
			b.StartTimer()
			close(start)
			for i := 0; i < b.N; i++ {
				if err := writer.Write(context.Background(), ws.MessageBinary, nil); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "frames/s")
		})
	}
}

type benchmarkCountingReader struct {
	reader bytes.Reader
	reads  int64
}

func (r *benchmarkCountingReader) Read(p []byte) (int, error) { r.reads++; return r.reader.Read(p) }

// Capture one actual library-encoded frame outside timing. The observer
// benchmark below replays these bytes instead of duplicating a header encoder.
func benchmarkEncodedFrame(b *testing.B, masked bool, size int) []byte {
	b.Helper()
	client, server, pipe := benchmarkRawWSPair(b)
	writer, reader, headerBytes := server, pipe.clientConn, 2
	if masked {
		writer, reader, headerBytes = client, pipe.serverConn, 6
	}
	if size >= 126 {
		headerBytes += 2
	}
	if size >= 65536 {
		headerBytes += 6
	}
	wire := make([]byte, size+headerBytes)
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(reader, wire); done <- err }()
	if err := writer.Write(context.Background(), ws.MessageBinary, make([]byte, size)); err != nil {
		client.CloseNow()
		server.CloseNow()
		benchmarkJoin(b, done)
		b.Fatal(err)
	}
	benchmarkJoin(b, done)
	client.CloseNow()
	server.CloseNow()
	return wire
}

// An unarmed budget isolates observer/header parsing and underlying Read count.
// The adapter echo benchmark above includes active timers, encryption and I/O.
func BenchmarkWebSocketObserver(b *testing.B) {
	for _, test := range []struct {
		name   string
		masked bool
		size   int
	}{
		{"Header2", false, 64}, {"Header6", true, 64}, {"Header8", true, 1024}, {"Header14", true, 65536},
	} {
		b.Run(test.name, func(b *testing.B) {
			wire := benchmarkEncodedFrame(b, test.masked, test.size)
			reader := &benchmarkCountingReader{}
			observer := observedIO{reader: reader, budget: &messageBudget{}}
			scratch := make([]byte, len(wire))
			b.ReportAllocs()
			b.SetBytes(int64(len(wire)))
			b.ResetTimer()
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				reader.reader.Reset(wire)
				total := 0
				for {
					n, err := observer.Read(scratch)
					total += n
					if err == io.EOF {
						break
					}
					if err != nil {
						b.Fatal(err)
					}
				}
				if total != len(wire) || observer.have != 0 || observer.payload != 0 {
					b.Fatal("observer lost frame boundary")
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(reader.reads)/float64(b.N), "reads/frame")
			b.ReportMetric(float64(b.N)/b.Elapsed().Seconds(), "frames/s")
		})
	}
}
