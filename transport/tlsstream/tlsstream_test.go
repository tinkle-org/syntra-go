package tlsstream

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func budget(t *testing.T) *ordered.EstablishmentBudget {
	t.Helper()
	b, err := ordered.NewEstablishmentBudget(nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func authority(t *testing.T) Authority {
	t.Helper()
	a, err := NewAuthority("localhost", 443)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

type providerFunc func(context.Context, net.Conn, Authority) (Result, error)

func (f providerFunc) Connect(ctx context.Context, c net.Conn, a Authority) (Result, error) {
	return f(ctx, c, a)
}
func (f providerFunc) Accept(ctx context.Context, c net.Conn, a Authority) (Result, error) {
	return f(ctx, c, a)
}
func observed(role Role) providerFunc {
	return func(_ context.Context, c net.Conn, a Authority) (Result, error) {
		return Result{Conn: c, Metadata: Metadata{Authority: a, Role: role, Version: tls.VersionTLS13, ALPN: "http/1.1"}}, nil
	}
}

func TestAuthorityValidation(t *testing.T) {
	for _, value := range []struct{ host, want string }{{"LOCALHOST", "localhost:443"}, {"127.0.0.1", "127.0.0.1:443"}, {"[::1]", "[::1]:443"}, {"::1", "[::1]:443"}} {
		a, err := NewAuthority(value.host, 443)
		if err != nil || a.String() != value.want {
			t.Fatalf("%q: %v %v", value.host, a, err)
		}
	}
	for _, host := range []string{"", "user@localhost", "host/path", "host:443", "a..b", "-name", "a_", "host\r\nHeader", "[localhost]", "[::1%zone]"} {
		if _, err := NewAuthority(host, 443); err == nil {
			t.Fatalf("accepted %q", host)
		}
	}
	if _, err := NewAuthority("localhost", 0); err == nil {
		t.Fatal("zero port accepted")
	}
}

func TestProofConsumptionSharedAcrossCopies(t *testing.T) {
	a, peer := net.Pipe()
	defer peer.Close()
	b, auth := budget(t), authority(t)
	v, err := Connect(context.Background(), a, observed(Client), auth, b)
	if err != nil {
		t.Fatal(err)
	}
	copyOfProof := *v
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			proof := v
			if i%2 == 0 {
				proof = &copyOfProof
			}
			c, err := proof.Consume(auth, Client, b)
			if err == nil {
				won.Add(1)
				_ = c.Close()
			} else if !errors.Is(err, securechannel.ErrConfig) {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatalf("consumed %d times", won.Load())
	}
}

func TestProofMismatchRetiresAndCloses(t *testing.T) {
	for _, mismatch := range []string{"authority", "role", "budget", "nil-budget"} {
		t.Run(mismatch, func(t *testing.T) {
			a, peer := net.Pipe()
			defer peer.Close()
			b, auth := budget(t), authority(t)
			v, err := Connect(context.Background(), a, observed(Client), auth, b)
			if err != nil {
				t.Fatal(err)
			}
			expected, role, attempt := auth, Client, b
			switch mismatch {
			case "authority":
				expected, _ = NewAuthority("other.invalid", 443)
			case "role":
				role = Server
			case "budget":
				attempt = budget(t)
			case "nil-budget":
				attempt = nil
			}
			if _, err := v.Consume(expected, role, attempt); !errors.Is(err, securechannel.ErrConfig) {
				t.Fatal(err)
			}
			if _, err := v.Consume(auth, Client, b); err == nil {
				t.Fatal("mismatch did not retire proof")
			}
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := peer.Read(make([]byte, 1)); err == nil {
				t.Fatal("raw stream not closed")
			}
		})
	}
}

func TestMetadataRejectedBeforeProof(t *testing.T) {
	for _, field := range []string{"authority", "role", "version", "alpn", "early", "nil"} {
		t.Run(field, func(t *testing.T) {
			a, peer := net.Pipe()
			defer peer.Close()
			p := providerFunc(func(ctx context.Context, c net.Conn, auth Authority) (Result, error) {
				r, _ := observed(Client)(ctx, c, auth)
				switch field {
				case "authority":
					r.Metadata.Authority = Authority{}
				case "role":
					r.Metadata.Role = Server
				case "version":
					r.Metadata.Version = tls.VersionTLS12
				case "alpn":
					r.Metadata.ALPN = ""
				case "early":
					r.Metadata.EarlyData = true
				case "nil":
					r.Conn = nil
				}
				return r, nil
			})
			v, err := Connect(context.Background(), a, p, authority(t), budget(t))
			if v != nil || !errors.Is(err, securechannel.ErrConfig) {
				t.Fatalf("%v, %v", v, err)
			}
			_ = peer.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := peer.Read(make([]byte, 1)); err == nil {
				t.Fatal("not closed")
			}
		})
	}
}

func TestProviderCancellationAndSanitizedErrors(t *testing.T) {
	a, peer := net.Pipe()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	p := providerFunc(func(_ context.Context, c net.Conn, _ Authority) (Result, error) {
		close(started)
		_, err := c.Read(make([]byte, 1))
		return Result{}, err
	})
	done := make(chan error, 1)
	auth, b := authority(t), budget(t)
	go func() { _, err := Connect(ctx, a, p, auth, b); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("provider not joined")
	}
	a, peer2 := net.Pipe()
	defer peer2.Close()
	_, err := Connect(context.Background(), a, providerFunc(func(context.Context, net.Conn, Authority) (Result, error) {
		return Result{}, errors.New("private diagnostic")
	}), auth, budget(t))
	if err != ordered.ErrIO {
		t.Fatalf("unsanitized error: %v", err)
	}
}

func certificate(t *testing.T, name string, expired bool) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if expired {
		template.NotBefore, template.NotAfter = now.Add(-2*time.Hour), now.Add(-time.Hour)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func TestStandardProviderPolicyRejection(t *testing.T) {
	cert, _ := certificate(t, "localhost", false)
	for _, cfg := range []*tls.Config{
		{InsecureSkipVerify: true}, {MinVersion: tls.VersionTLS12}, {MaxVersion: tls.VersionTLS12}, {NextProtos: []string{"unexpected"}},
		{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return &tls.Config{}, nil }},
	} {
		if _, err := NewStandardProvider(cfg, nil); !errors.Is(err, securechannel.ErrConfig) {
			t.Fatal(err)
		}
	}
	if _, err := NewStandardProvider(nil, &tls.Config{}); err == nil {
		t.Fatal("missing credentials accepted")
	}
	other, _ := certificate(t, "localhost", false)
	cert.PrivateKey = other.PrivateKey
	if _, err := NewStandardProvider(nil, &tls.Config{Certificates: []tls.Certificate{cert}}); err == nil {
		t.Fatal("mismatched key accepted")
	}
}

func TestStandardTLSAuthenticationFailuresAreTerminal(t *testing.T) {
	for _, failure := range []string{"name", "expired", "roots", "alpn", "version", "policy"} {
		t.Run(failure, func(t *testing.T) {
			name := "localhost"
			if failure == "name" {
				name = "other.invalid"
			}
			cert, roots := certificate(t, name, failure == "expired")
			if failure == "roots" {
				roots = x509.NewCertPool()
			}
			cfg := &tls.Config{RootCAs: roots}
			if failure == "policy" {
				cfg.VerifyConnection = func(tls.ConnectionState) error { return errors.New("private policy") }
			}
			p, err := NewStandardProvider(cfg, nil)
			if err != nil {
				t.Fatal(err)
			}
			sc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
			if failure == "alpn" {
				sc.NextProtos = nil
			}
			if failure == "version" {
				sc.MinVersion, sc.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				peer, err := listener.Accept()
				if err != nil {
					return
				}
				defer peer.Close()
				conn := tls.Server(peer, sc)
				_ = conn.Handshake()
				var b [1]byte
				_, _ = conn.Read(b[:])
			}()
			a, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			v, err := Connect(context.Background(), a, p, authority(t), budget(t))
			if v != nil || !errors.Is(err, securechannel.ErrConfig) {
				t.Fatalf("result=%v err=%v", v, err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("TLS peer not joined")
			}
		})
	}
}

type temporaryWireError struct{ timeout, temporary bool }

func (temporaryWireError) Error() string     { return "private socket diagnostic" }
func (e temporaryWireError) Timeout() bool   { return e.timeout }
func (e temporaryWireError) Temporary() bool { return e.temporary }

type permanentWireError struct{ error }

func (e permanentWireError) Unwrap() error { return e.error }
func (permanentWireError) Timeout() bool   { return true }
func (permanentWireError) Temporary() bool { return false }

func TestWireErrorsPreserveNetworkSemanticsWithoutDiagnostics(t *testing.T) {
	for _, flags := range []temporaryWireError{{true, true}, {true, false}, {false, true}, {false, false}} {
		raw := fmt.Errorf("private wrapper: %w", flags)
		wire := wireIOError(raw)
		external := tlsError(wire)
		for _, err := range []error{wire, external} {
			network, ok := err.(tlsNetworkError)
			if !ok || network.Timeout() != flags.timeout || network.Temporary() != flags.temporary {
				t.Fatalf("network semantics lost: %v", err)
			}
			if !errors.Is(err, ordered.ErrIO) {
				t.Fatalf("sanitized code lost: %v", err)
			}
			if strings.Contains(fmt.Sprintf("%v %#v %v", err, err, errors.Unwrap(err)), "private") {
				t.Fatal("raw diagnostic escaped")
			}
			var retained temporaryWireError
			if errors.As(err, &retained) {
				t.Fatal("raw error retained")
			}
		}
	}
	err := wireIOError(&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded})
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("deadline sentinel lost")
	}
	terminal := tlsError(permanentWireError{err})
	if network, ok := terminal.(tlsNetworkError); !ok || !network.Timeout() || network.Temporary() {
		t.Fatal("TLS terminal network semantics lost")
	}
	if wireIOError(io.EOF) != io.EOF || wireIOError(io.ErrUnexpectedEOF) != io.ErrUnexpectedEOF {
		t.Fatal("TLS EOF sentinel identity lost")
	}
}

func TestIdleTLSDeadlineProbeLeavesNextReadUsable(t *testing.T) {
	cert, roots := certificate(t, "localhost", false)
	provider, err := NewStandardProvider(&tls.Config{RootCAs: roots}, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	clientBudget, serverBudget, auth := budget(t), budget(t), authority(t)
	type accepted struct {
		proof *Verified
		err   error
	}
	done := make(chan accepted, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- accepted{err: err}
			return
		}
		proof, err := Accept(ctx, raw, provider, auth, serverBudget)
		done <- accepted{proof: proof, err: err}
	}()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientProof, err := Connect(ctx, raw, provider, auth, clientBudget)
	if err != nil {
		t.Fatal(err)
	}
	defer clientProof.Close()
	var serverProof *Verified
	select {
	case result := <-done:
		if result.err != nil {
			t.Fatal(result.err)
		}
		serverProof = result.proof
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer serverProof.Close()
	client, err := clientProof.Consume(auth, Client, clientBudget)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := serverProof.Consume(auth, Server, serverBudget)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, direction := range []struct {
		name        string
		read, write net.Conn
	}{{"client", client, server}, {"server", server, client}} {
		t.Run(direction.name, func(t *testing.T) {
			for i := 0; i < 3; i++ {
				if err := direction.read.SetReadDeadline(time.Now().Add(2 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				var one [1]byte
				n, err := direction.read.Read(one[:])
				network, ok := err.(tlsNetworkError)
				if n != 0 || !ok || !network.Timeout() || !network.Temporary() || !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("idle probe: n=%d err=%v", n, err)
				}
				if err := direction.read.SetReadDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				deadline := time.Now().Add(time.Second)
				if err := direction.write.SetWriteDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				if err := direction.read.SetReadDeadline(deadline); err != nil {
					t.Fatal(err)
				}
				want := []byte("read after idle probe")
				if n, err := direction.write.Write(want); err != nil || n != len(want) {
					t.Fatalf("write after probe: n=%d err=%v", n, err)
				}
				got := make([]byte, len(want))
				if _, err := io.ReadFull(direction.read, got); err != nil || string(got) != string(want) {
					t.Fatalf("read after probe: %q, %v", got, err)
				}
				if err := direction.write.SetWriteDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
				if err := direction.read.SetReadDeadline(time.Time{}); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
