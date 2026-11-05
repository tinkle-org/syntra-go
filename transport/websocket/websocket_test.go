package websocket

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

func testBudget(t *testing.T) *ordered.EstablishmentBudget {
	t.Helper()
	b, err := ordered.NewEstablishmentBudget(nil, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func frame(op byte, fin, masked bool, payload []byte) []byte {
	head := []byte{op, byte(len(payload))}
	if fin {
		head[0] |= 0x80
	}
	if len(payload) >= 126 {
		head[1] = 126
		head = binary.BigEndian.AppendUint16(head, uint16(len(payload)))
	}
	if masked {
		head[1] |= 0x80
		mask := [4]byte{1, 2, 3, 4}
		head = append(head, mask[:]...)
		for i, b := range payload {
			head = append(head, b^mask[i%4])
		}
		return head
	}
	return append(head, payload...)
}

func rawRecords(conn net.Conn, client bool) *records {
	owned := stream.New(conn, nil)
	return &records{conn: owned, reader: bufio.NewReader(owned), client: client, writer: make(chan struct{}, 1)}
}

func TestFrameRejectionsAreTerminal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		bytes []byte
		cap   int
	}{
		{"unmasked-client", frame(2, true, false, make([]byte, 17)), 32},
		{"text", frame(1, true, true, make([]byte, 17)), 32},
		{"reserved-bit", []byte{0xc2, 0x80}, 32},
		{"reserved-opcode", frame(3, true, true, nil), 32},
		{"continuation", frame(0, true, true, make([]byte, 17)), 32},
		{"interleaved-data", append(frame(2, false, true, []byte{1}), frame(2, true, true, make([]byte, 17))...), 32},
		{"short-record", frame(2, true, true, make([]byte, 16)), 32},
		{"over-capacity", []byte{0x82, 0xfe, 0x01, 0x00}, 32},
		{"huge-length", []byte{0x82, 0xff}, 32},
		{"nonminimal-length", []byte{0x82, 0xfe, 0, 17}, 32},
		{"fragmented-control", frame(9, false, true, nil), 32},
		{"large-control", frame(9, true, true, make([]byte, 126)), 32},
		{"reserved-control", frame(11, true, true, nil), 32},
		{"short-close", frame(8, true, true, []byte{1}), 32},
		{"reserved-close", frame(8, true, true, []byte{3, 237}), 32},
		{"invalid-close-text", frame(8, true, true, []byte{3, 232, 0xff}), 32},
		{"control-flood", bytes.Repeat(frame(10, true, true, nil), maxFrames), 32},
		{"fragment-flood", append(frame(2, false, true, nil), bytes.Repeat(frame(0, false, true, nil), maxFrames-1)...), 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			r := rawRecords(a, false)
			done := make(chan struct{})
			go func() { defer close(done); _, _ = b.Write(tc.bytes) }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := r.ReadMessage(ctx, make([]byte, 0, tc.cap)); !errors.Is(err, ordered.ErrProtocol) {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("writer not interrupted")
			}
		})
	}
	a, b := net.Pipe()
	defer b.Close()
	r := rawRecords(a, true)
	go func() { _, _ = b.Write(frame(2, true, true, make([]byte, 17))) }()
	if _, err := r.ReadMessage(context.Background(), make([]byte, 0, 17)); err != ordered.ErrProtocol {
		t.Fatal("masked server accepted", err)
	}
}

func TestFragmentsPingPongAndCallerStorage(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	r := rawRecords(a, false)
	defer r.Close()
	want := bytes.Repeat([]byte{7}, 200)
	input := append(frame(2, false, true, want[:100]), frame(9, true, true, []byte("ping"))...)
	input = append(input, frame(0, true, true, want[100:])...)
	done := make(chan error, 1)
	go func() {
		if _, err := b.Write(input); err != nil {
			done <- err
			return
		}
		var pong [6]byte
		_, err := io.ReadFull(b, pong[:])
		if err == nil && !bytes.Equal(pong[:], []byte{0x8a, 4, 'p', 'i', 'n', 'g'}) {
			err = errors.New("incorrect pong")
		}
		done <- err
	}()
	storage := make([]byte, 0, 200)
	got, err := r.ReadMessage(context.Background(), storage)
	if err != nil || !bytes.Equal(got, want) || &got[0] != &storage[:200][0] {
		t.Fatalf("fragmented read: %d, %v", len(got), err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRecordSizesAndMasking(t *testing.T) {
	for _, client := range []bool{false, true} {
		for _, size := range []int{17, 125, 126, 4097, 65535} {
			a, b := net.Pipe()
			writer, reader := rawRecords(a, client), rawRecords(b, !client)
			want := bytes.Repeat([]byte{0xa5}, size)
			done := make(chan error, 1)
			go func() { done <- writer.WriteMessage(context.Background(), want) }()
			got, err := reader.ReadMessage(context.Background(), make([]byte, 0, size))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("size %d client %t: %v", size, client, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			writer.Close()
			reader.Close()
		}
	}
}

func TestUpgradeValidation(t *testing.T) {
	base := "GET " + EndpointPath + " HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\nSec-WebSocket-Protocol: " + Subprotocol + "\r\n"
	if _, _, err := readHeaders(bufio.NewReader(strings.NewReader(base + "\r\n"))); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"Cookie: \r\n", "Authorization: secret\r\n", "Origin: null\r\n", "Sec-WebSocket-Extensions: \r\n", "Content-Length: 0\r\n", "Transfer-Encoding: chunked\r\n", "Upgrade: websocket\r\n", " folded: value\r\n", "Bad : value\r\n", "X: a\x00b\r\n", "X: value\n", "X: value\rX: value\r\n", "X: " + strings.Repeat("a", maxHeaders) + "\r\n"} {
		if _, _, err := readHeaders(bufio.NewReader(strings.NewReader(base + extra + "\r\n"))); err == nil {
			t.Fatalf("accepted header %q", extra[:min(len(extra), 40)])
		}
	}
	var fields strings.Builder
	fields.WriteString(base)
	for i := 0; i < maxFields; i++ {
		fields.WriteString("X-" + strconv.Itoa(i) + ": a\r\n")
	}
	fields.WriteString("\r\n")
	if _, _, err := readHeaders(bufio.NewReader(strings.NewReader(fields.String()))); err == nil {
		t.Fatal("too many fields accepted")
	}
}

func TestEndpointValidation(t *testing.T) {
	for _, raw := range []string{"ws://127.0.0.1" + EndpointPath, "ws://localhost:80" + EndpointPath, "ws://[::1]" + EndpointPath} {
		if _, err := endpoint(raw, false); err != nil {
			t.Fatal(raw, err)
		}
	}
	for _, raw := range []string{"ws://remote.invalid" + EndpointPath, "wss://localhost" + EndpointPath, "ws://user:password@localhost" + EndpointPath, "ws://localhost/", "ws://localhost" + EndpointPath + "?", "ws://localhost" + EndpointPath + "#", "ws://localhost" + EndpointPath + "?x", "ws://localhost/syntra/1.0/%77s", "ws://localhost:0" + EndpointPath, "ws://localhost:" + EndpointPath} {
		if _, err := endpoint(raw, false); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}

func TestUpgradeResponseAndCoalescedFrame(t *testing.T) {
	for _, variant := range []string{"valid", "status", "accept", "protocol", "extension", "cookie", "duplicate", "bare-lf", "status-control"} {
		t.Run(variant, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			auth, _ := tlsstream.NewAuthority("localhost", 443)
			done := make(chan struct{})
			go func() {
				defer close(done)
				_, h, err := readHeaders(bufio.NewReader(b))
				if err != nil {
					return
				}
				response := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + acceptKey(h["sec-websocket-key"]) + "\r\nSec-WebSocket-Protocol: " + Subprotocol + "\r\n"
				switch variant {
				case "status-control":
					response = strings.Replace(response, "Switching Protocols", "Switching\x00Protocols", 1)
				case "status":
					response = strings.Replace(response, "101", "302", 1)
				case "accept":
					response = strings.Replace(response, acceptKey(h["sec-websocket-key"]), "wrong", 1)
				case "protocol":
					response = strings.Replace(response, Subprotocol, "wrong", 1)
				case "extension":
					response += "Sec-WebSocket-Extensions: \r\n"
				case "cookie":
					response += "Set-Cookie: private\r\n"
				case "duplicate":
					response += "Sec-WebSocket-Protocol: " + Subprotocol + "\r\n"
				}
				response += "\r\n"
				if variant == "bare-lf" {
					response = strings.ReplaceAll(response, "\r\n", "\n")
				}
				_, _ = b.Write(append([]byte(response), frame(2, true, false, bytes.Repeat([]byte{9}, 17))...))
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			r, err := upgrade(ctx, a, auth, true, testBudget(t))
			if variant == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				defer r.Close()
				got, err := r.ReadMessage(ctx, make([]byte, 0, 17))
				if err != nil || len(got) != 17 || got[0] != 9 {
					t.Fatal("lost coalesced frame", err)
				}
			} else if !errors.Is(err, securechannel.ErrConfig) {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("upgrade writer not joined")
			}
		})
	}
}

func TestCancellationStopsUpgradeAndFraming(t *testing.T) {
	for _, operation := range []string{"upgrade", "read", "write"} {
		t.Run(operation, func(t *testing.T) {
			a, b := net.Pipe()
			defer b.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()
			var err error
			switch operation {
			case "upgrade":
				auth, _ := tlsstream.NewAuthority("localhost", 443)
				_, err = upgrade(ctx, a, auth, true, testBudget(t))
			case "read":
				_, err = rawRecords(a, false).ReadMessage(ctx, make([]byte, 0, 17))
			case "write":
				err = rawRecords(a, true).WriteMessage(ctx, make([]byte, 17))
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal(err)
			}
			if _, err := b.Read(make([]byte, 1)); err == nil {
				t.Fatal("failed stream not closed")
			}
		})
	}
}

func testTLS(t *testing.T) *tlsstream.StandardProvider {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	p, err := tlsstream.NewStandardProvider(&tls.Config{RootCAs: roots}, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type applicationProvider struct {
	inner tlsstream.Provider
	calls atomic.Int32
}

func (p *applicationProvider) Connect(ctx context.Context, c net.Conn, a tlsstream.Authority) (tlsstream.Result, error) {
	p.calls.Add(1)
	return p.inner.Connect(ctx, c, a)
}
func (p *applicationProvider) Accept(ctx context.Context, c net.Conn, a tlsstream.Authority) (tlsstream.Result, error) {
	p.calls.Add(1)
	return p.inner.Accept(ctx, c, a)
}

func TestLoopbackSessionsAndTLSProvidersPushWithoutCall(t *testing.T) {
	for _, carrier := range []string{"ws", "standard-tls", "application-tls"} {
		for _, mode := range []securechannel.Mode{securechannel.Bootstrap, securechannel.Returning} {
			t.Run(carrier+"/"+mode.String(), func(t *testing.T) {
				binding := securechannel.WS
				if carrier != "ws" {
					binding = securechannel.WSS
				}
				key, err := securechannel.GenerateStaticKey()
				if err != nil {
					t.Fatal(err)
				}
				cc := securechannel.ClientConfig{Context: securechannel.Context{Mode: mode, Carrier: binding, Scope: "native"}, ServerPublicKey: key.Public()}
				sc := securechannel.ServerConfig{StaticKey: key, Carrier: binding, Scope: "native", AllowBootstrap: mode == securechannel.Bootstrap}
				if mode == securechannel.Returning {
					cc.AuthorizationKey, err = securechannel.GenerateKey()
					if err != nil {
						t.Fatal(err)
					}
					cc.Context.Epoch, cc.Context.Handle = 1, [8]byte{1}
					sc.Lookup = func(context.Context, securechannel.Context) (securechannel.Enrollment, error) {
						return securechannel.Enrollment{Key: cc.AuthorizationKey, Principal: "device", ExpiresAt: time.Now().Add(time.Hour)}, nil
					}
				}
				host, err := syntra.OpenHost(syntra.HostConfig{
					ChannelPolicy: func(context.Context, syntra.ChannelIdentity, []byte) (string, error) { return "native", nil },
					Authorize:     syntra.AllowAllAuthorize,
					Handler: func(_ context.Context, request *syntra.RpcRequest) (*syntra.RpcResult, error) {
						return syntra.NewSuccessResult(request.GetPayload()), nil
					},
				})
				if err != nil {
					t.Fatal(err)
				}
				defer host.Close()
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				port := listener.Addr().(*net.TCPAddr).Port
				auth, _ := tlsstream.NewAuthority("localhost", uint16(port))
				var p tlsstream.Provider
				var application *applicationProvider
				if carrier != "ws" {
					p = testTLS(t)
				}
				if carrier == "application-tls" {
					application = &applicationProvider{inner: p}
					p = application
				}
				ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
				defer cancel()
				var age atomic.Int64
				clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
				clientBudget, err := ordered.NewEstablishmentBudget(clock, 80*time.Millisecond)
				if err != nil {
					t.Fatal(err)
				}
				serverBudget, err := ordered.NewEstablishmentBudget(clock, 80*time.Millisecond)
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					conn, err := listener.Accept()
					if err == nil {
						if p == nil {
							err = Accept(ctx, conn, sc, host, ordered.Options{Budget: serverBudget})
						} else {
							var proof *tlsstream.Verified
							proof, err = tlsstream.Accept(ctx, conn, p, auth, serverBudget)
							if err == nil {
								err = AcceptTLS(ctx, proof, auth, sc, host, ordered.Options{})
							}
						}
					}
					done <- err
				}()
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				var c *connection.Client
				if p == nil {
					c, err = Connect(ctx, conn, "ws://"+auth.String()+EndpointPath, cc, syntra.ClientConfig{}, ordered.Options{Budget: clientBudget})
				} else {
					var proof *tlsstream.Verified
					proof, err = tlsstream.Connect(ctx, conn, p, auth, clientBudget)
					if err != nil {
						t.Fatal(err)
					}
					c, err = ConnectTLS(ctx, proof, "wss://"+auth.String()+EndpointPath, cc, syntra.ClientConfig{}, ordered.Options{})
				}
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				if err := host.NotifyAll([]byte("push")); err != nil {
					t.Fatal(err)
				}
				select {
				case n := <-c.Notifications():
					if string(n.GetPayload()) != "push" {
						t.Fatal("wrong push")
					}
				case <-ctx.Done():
					t.Fatal("missing push")
				}
				// Keep the original clock and budgets across TLS, upgrade, Ready,
				// and active I/O. The first push confirms server Ready committed.
				age.Store(int64(100 * time.Millisecond))
				if err := clientBudget.Check(); err != nil {
					t.Fatalf("client setup cutoff not released: %v", err)
				}
				if err := serverBudget.Check(); err != nil {
					t.Fatalf("server setup cutoff not released: %v", err)
				}
				time.Sleep(100 * time.Millisecond)
				if err := host.NotifyAll([]byte("after cutoff")); err != nil {
					t.Fatal(err)
				}
				select {
				case n := <-c.Notifications():
					if string(n.GetPayload()) != "after cutoff" {
						t.Fatal("wrong post-cutoff push")
					}
				case <-ctx.Done():
					t.Fatal("missing post-cutoff push")
				}
				got, err := c.Call(ctx, "/example.Echo/Echo", []byte("after cutoff"), 0)
				if err != nil || string(got) != "after cutoff" {
					t.Fatalf("post-cutoff call = %q, %v", got, err)
				}
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
				if application != nil && application.calls.Load() != 2 {
					t.Fatal("provider role not called")
				}
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("accept cleanup not joined")
				}
			})
		}
	}
}
