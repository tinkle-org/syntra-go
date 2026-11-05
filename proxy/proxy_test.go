package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func budget(t *testing.T, timeout time.Duration) *ordered.EstablishmentBudget {
	t.Helper()
	b, err := ordered.NewEstablishmentBudget(nil, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func target(t *testing.T) Target {
	t.Helper()
	v, err := NewHostnameTarget("origin.invalid", 443)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func config(t *testing.T, kind Kind, address netip.AddrPort, creds *Credentials) *ProxyConfig {
	t.Helper()
	p, err := NewProxy(Config{Endpoint: address, Kind: kind, Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}
func credentials(t *testing.T, u, p []byte) *Credentials {
	t.Helper()
	c, err := NewCredentials(u, p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}
func local(t *testing.T) (net.Listener, netip.AddrPort) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, l.Addr().(*net.TCPAddr).AddrPort()
}
func head(r io.Reader) ([]byte, error) {
	p := make([]byte, 0, MaxConnectHeaderBytes)
	var one [1]byte
	for len(p) < MaxConnectHeaderBytes {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return p, err
		}
		p = append(p, one[0])
		if bytes.HasSuffix(p, []byte("\r\n\r\n")) {
			return p, nil
		}
	}
	return p, ErrFraming
}

func TestConfigurationPrecedesEffectsAndRedactsAllFormats(t *testing.T) {
	var calls atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("unreachable")
	}
	for _, address := range []string{"127.0.0.1:0", "0.0.0.0:80", "[::]:80", "224.0.0.1:80", "[::ffff:224.0.0.1]:80", "[fe80::1%en0]:80"} {
		_, err := NewProxy(Config{Endpoint: netip.MustParseAddrPort(address), Kind: Socks5, Dialer: dial})
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("accepted %s", address)
		}
	}
	for _, host := range []string{"", "a..b", "-a", "a-", "a/b", "a:b", "a@b", "a?b", "a#b", "a\r\nb", "a_b", "é.test", ".", "127.0.0.1", "127.1", "123", "::1", "[::1]", strings.Repeat("a", 64)} {
		if _, err := NewHostnameTarget(host, 80); err == nil {
			t.Fatalf("accepted hostname %q", host)
		}
	}
	for _, u := range [][]byte{[]byte("a:b"), []byte("a\rb"), []byte("a\nb"), {0xff}} {
		c := credentials(t, u, []byte("password-secret"))
		if _, err := NewProxy(Config{Endpoint: netip.MustParseAddrPort("127.0.0.1:80"), Kind: HTTPConnect, Credentials: c, Dialer: dial}); err == nil {
			t.Fatal("accepted HTTP credential")
		}
		if _, err := NewProxy(Config{Endpoint: netip.MustParseAddrPort("127.0.0.1:80"), Kind: Socks5, Credentials: c}); err != nil {
			t.Fatal(err)
		}
	}
	c := credentials(t, []byte("username-secret"), []byte("password-secret"))
	p := config(t, HTTPConnect, netip.MustParseAddrPort("127.0.0.1:80"), c)
	for _, v := range []any{c, *c, p, *p, Config{Credentials: c}} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			s := fmt.Sprintf(verb, v)
			if strings.Contains(s, "username-secret") || strings.Contains(s, "password-secret") {
				t.Fatalf("secret in format %s", verb)
			}
		}
	}
	if _, err := Tunnel(context.Background(), p, Target{}, budget(t, time.Second)); !errors.Is(err, ErrConfig) {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("effect during invalid configuration")
	}
	_ = c.Close()
	if p.Validate() != nil {
		t.Fatal("configuration did not own credential copy")
	}
	_ = p.Close()
	if p.Validate() == nil {
		t.Fatal("closed configuration accepted")
	}
}

func TestHTTPResponseGrammarAndBounds(t *testing.T) {
	for code := 200; code < 300; code++ {
		if err := parseResponse([]byte(fmt.Sprintf("HTTP/1.1 %d OK\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\n", code))); err != nil {
			t.Fatalf("%d: %v", code, err)
		}
	}
	for _, code := range []int{401, 403, 407} {
		if err := parseResponse([]byte(fmt.Sprintf("HTTP/1.1 %d Denied\r\n\r\n", code))); !errors.Is(err, ErrAuthentication) {
			t.Fatal(err)
		}
	}
	for _, code := range []int{100, 101, 199, 300, 301, 307, 400, 500, 503} {
		if err := parseResponse([]byte(fmt.Sprintf("HTTP/1.1 %d No\r\n\r\n", code))); !errors.Is(err, ErrRefused) {
			t.Fatalf("%d: %v", code, err)
		}
	}
	for _, s := range []string{"HTTP/2.0 200 OK\r\n\r\n", "HTTP/1.1 200\r\n\r\n", "HTTP/1.1  200 OK\r\n\r\n", "HTTP/1.1 020 OK\r\n\r\n", "HTTP/1.1 600 OK\r\n\r\n", "HTTP/1.1 200 O\x00K\r\n\r\n", "HTTP/1.1 200 OK\n\r\n", "HTTP/1.1 200 OK\r\nStatus: 500\r\n\r\n", "HTTP/1.1 200 OK\r\n folded\r\n\r\n", "HTTP/1.1 200 OK\r\nX : val\r\n\r\n", "HTTP/1.1 200 OK\r\nX: va\rlue\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 500 NO\r\n\r\n", "HTTP/1.1 200 OK\r\n" + strings.Repeat("X: y\r\n", 65) + "\r\n", "HTTP/1.1 200 OK\r\nX: " + strings.Repeat("x", MaxHTTPLineBytes) + "\r\n\r\n"} {
		if err := parseResponse([]byte(s)); !errors.Is(err, ErrFraming) {
			t.Fatalf("accepted malformed response: %v", err)
		}
	}
}

func TestHTTPConnectRemoteNameAndNoOverread(t *testing.T) {
	l, address := local(t)
	creds := credentials(t, []byte("u"), []byte("a"))
	cfg := config(t, HTTPConnect, address, creds)
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		request, err := head(c)
		if err != nil {
			done <- err
			return
		}
		expected := "CONNECT origin.invalid:443 HTTP/1.1\r\nHost: origin.invalid:443\r\nProxy-Authorization: Basic dTph\r\n\r\n"
		if string(request) != expected {
			done <- errors.New("unexpected CONNECT bytes")
			return
		}
		_, err = c.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 999\r\nTransfer-Encoding: chunked\r\n\r\ntunnel"))
		done <- err
	}()
	c, err := Tunnel(context.Background(), cfg, target(t), budget(t, time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var got [6]byte
	if _, err = io.ReadFull(c, got[:]); err != nil || string(got[:]) != "tunnel" {
		t.Fatalf("overread: %q %v", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPAuthFailuresHaveNoRetryOrCredentialDiagnostic(t *testing.T) {
	for _, code := range []int{403, 407} {
		t.Run(strconvInt(code), func(t *testing.T) {
			l, address := local(t)
			cfg := config(t, HTTPConnect, address, credentials(t, []byte("user-secret"), []byte("password-secret")))
			done := make(chan error, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					done <- err
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err = head(c); err != nil {
					done <- err
					return
				}
				if _, err = fmt.Fprintf(c, "HTTP/1.1 %d password-secret\r\nX-Reflect: user-secret\r\n\r\n", code); err != nil {
					done <- err
					return
				}
				var extra [1]byte
				_, err = c.Read(extra[:])
				if err != io.EOF {
					done <- errors.New("partial proxy stream not retired")
					return
				}
				done <- nil
			}()
			c, err := Tunnel(context.Background(), cfg, target(t), budget(t, time.Second))
			if c != nil || !errors.Is(err, securechannel.ErrAuth) {
				t.Fatalf("%v %v", c, err)
			}
			if strings.Contains(fmt.Sprint(err), "secret") {
				t.Fatal("credential diagnostic")
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
func strconvInt(i int) string { return fmt.Sprint(i) }

func TestSOCKSRawCredentialsRemoteDNSAndRules(t *testing.T) {
	for _, rep := range []byte{0, 2, 7, 8, 3, 9} {
		t.Run(fmt.Sprint(rep), func(t *testing.T) {
			l, address := local(t)
			cfg := config(t, Socks5, address, credentials(t, []byte{0, 255}, []byte{255, 0}))
			done := make(chan error, 1)
			go func() {
				c, err := l.Accept()
				if err != nil {
					done <- err
					return
				}
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(3 * time.Second))
				var greeting [3]byte
				if err = readFull(c, greeting[:]); err != nil {
					done <- err
					return
				}
				if greeting != ([3]byte{5, 1, 2}) {
					done <- errors.New("auth downgrade")
					return
				}
				_, _ = c.Write([]byte{5, 2})
				var auth [7]byte
				if err = readFull(c, auth[:]); err != nil {
					done <- err
					return
				}
				if auth != ([7]byte{1, 2, 0, 255, 2, 255, 0}) {
					done <- errors.New("raw credential mismatch")
					return
				}
				_, _ = c.Write([]byte{1, 0})
				want := append([]byte{5, 1, 0, 3, 14}, []byte("origin.invalid")...)
				want = append(want, 1, 187)
				got := make([]byte, len(want))
				if err = readFull(c, got); err != nil {
					done <- err
					return
				}
				if !bytes.Equal(got, want) {
					done <- errors.New("remote DNS request mismatch")
					return
				}
				_, err = c.Write([]byte{5, rep, 0, 1, 127, 0, 0, 1, 0, 1})
				done <- err
			}()
			c, err := Tunnel(context.Background(), cfg, target(t), budget(t, time.Second))
			switch rep {
			case 0:
				if err != nil {
					t.Fatal(err)
				}
				_ = c.Close()
			case 2:
				if !errors.Is(err, ErrAuthentication) {
					t.Fatal(err)
				}
			case 7, 8:
				if !errors.Is(err, ErrConfig) {
					t.Fatal(err)
				}
			case 3:
				if !errors.Is(err, ordered.ErrIO) {
					t.Fatal(err)
				}
			default:
				if !errors.Is(err, ErrFraming) {
					t.Fatal(err)
				}
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSOCKSMethodCannotDowngradeAndAuthCannotContinue(t *testing.T) {
	for _, method := range []byte{0, 2, 255} {
		l, address := local(t)
		cfg := config(t, Socks5, address, credentials(t, []byte("u"), []byte("p")))
		done := make(chan error, 1)
		go func() {
			c, err := l.Accept()
			if err != nil {
				done <- err
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			var greeting [3]byte
			if err = readFull(c, greeting[:]); err != nil {
				done <- err
				return
			}
			_, _ = c.Write([]byte{5, method})
			if method == 2 {
				var auth [5]byte
				if err = readFull(c, auth[:]); err != nil {
					done <- err
					return
				}
				_, _ = c.Write([]byte{1, 1})
			}
			var extra [1]byte
			_, err = c.Read(extra[:])
			if err != io.EOF {
				done <- errors.New("request followed authentication rejection")
				return
			}
			done <- nil
		}()
		c, err := Tunnel(context.Background(), cfg, target(t), budget(t, time.Second))
		if c != nil || !errors.Is(err, ErrAuthentication) {
			t.Fatalf("%v", err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}

func TestTruncationIsFramingAndStallUsesAbsoluteBudget(t *testing.T) {
	for _, response := range [][]byte{nil, []byte("HTTP/1.1 200 OK\r\nX: unfinished"), bytes.Repeat([]byte{'a'}, MaxConnectHeaderBytes)} {
		left, right := net.Pipe()
		cfg := config(t, HTTPConnect, netip.MustParseAddrPort("127.0.0.1:1"), nil)
		done := make(chan struct{})
		go func() { defer close(done); defer right.Close(); _, _ = head(right); _, _ = right.Write(response) }()
		c, err := TunnelStream(context.Background(), left, cfg, target(t), budget(t, time.Second))
		if c != nil || !errors.Is(err, ErrFraming) {
			t.Fatalf("truncation: %v", err)
		}
		<-done
	}
	left, right := net.Pipe()
	defer right.Close()
	cfg := config(t, Socks5, netip.MustParseAddrPort("127.0.0.1:1"), nil)
	start := time.Now()
	c, err := TunnelStream(context.Background(), left, cfg, target(t), budget(t, 30*time.Millisecond))
	if c != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("stall escaped deadline")
	}
}
