package syntrahttp

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func testAuthority(t *testing.T) Authority {
	t.Helper()
	a, e := NewAuthority("localhost:443")
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func testRoute(t *testing.T) Route {
	t.Helper()
	r, e := ParseRoute(strings.Repeat("a", 64))
	if e != nil {
		t.Fatal(e)
	}
	return r
}

func TestCanonicalAuthorityOriginAndRoute(t *testing.T) {
	for _, value := range []string{"localhost:443", "127.0.0.1:80", "[::1]:443", "a-b.service:1234"} {
		if _, e := NewAuthority(value); e != nil {
			t.Fatalf("%s: %v", value, e)
		}
	}
	for _, value := range []string{"LOCALHOST:443", "localhost.:443", "localhost:0443", "host:0", "host:65536", "host:443/path", "user@host:443", "[0:0::1]:443", "[::1%lo0]:443", "host:443\r\nInjected: x", "-host:443"} {
		if _, e := NewAuthority(value); e == nil {
			t.Fatalf("accepted authority %q", value)
		}
	}
	for _, value := range []string{"https://localhost", "https://localhost:8443", "http://[::1]"} {
		if _, e := AllowExactOrigins(value); e != nil {
			t.Fatalf("%s: %v", value, e)
		}
	}
	for _, value := range []string{"null", "https://LOCALHOST", "https://localhost/", "https://localhost:443", "https://u@localhost", "https://localhost?", "https://localhost#x", "https://localhost https://other"} {
		if _, e := AllowExactOrigins(value); e == nil {
			t.Fatalf("accepted origin %q", value)
		}
	}
	r := testRoute(t)
	if strings.Contains(fmt.Sprintf("%v %#v %s %q", r, r, r, r), r.value) {
		t.Fatal("route exposed by formatting")
	}
	for _, value := range []string{"", strings.Repeat("a", 63), strings.Repeat("A", 64), strings.Repeat("g", 64)} {
		if _, e := ParseRoute(value); e == nil {
			t.Fatal("invalid route accepted")
		}
	}
}

func TestStrictRequestCodec(t *testing.T) {
	a, r := testAuthority(t), testRoute(t)
	valid, e := requestHeader(Send, a, r, 0, 17)
	if e != nil {
		t.Fatal(e)
	}
	for name, mutate := range map[string]func(string) string{
		"bare-lf": func(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") },
		"duplicate-host": func(s string) string {
			return strings.Replace(s, "Host: localhost:443", "Host: localhost:443\r\nhOsT: localhost:443", 1)
		},
		"fold": func(s string) string {
			return strings.Replace(s, "Host: localhost:443", "Host: localhost:443\r\n folded", 1)
		},
		"transfer": func(s string) string {
			return strings.Replace(s, "\r\n\r\n", "\r\nTransfer-Encoding: chunked\r\n\r\n", 1)
		},
		"cookie": func(s string) string { return strings.Replace(s, "\r\n\r\n", "\r\nCookie: private\r\n\r\n", 1) },
		"auth":   func(s string) string { return strings.Replace(s, "\r\n\r\n", "\r\nAuthorization: private\r\n\r\n", 1) },
		"origin": func(s string) string {
			return strings.Replace(s, "\r\n\r\n", "\r\nOrigin: https://localhost\r\n\r\n", 1)
		},
		"foreign-authority": func(s string) string { return strings.Replace(s, "localhost:443", "foreign:443", 1) },
		"decimal":           func(s string) string { return strings.Replace(s, "Content-Length: 17", "Content-Length: 017", 1) },
		"overflow-length": func(s string) string {
			return strings.Replace(s, "Content-Length: 17", "Content-Length: 18446744073709551616", 1)
		},
		"too-large":    func(s string) string { return strings.Replace(s, "Content-Length: 17", "Content-Length: 65536", 1) },
		"poll-counter": func(s string) string { return strings.Replace(s, "Syntra-Upload:", "Syntra-Poll:", 1) },
		"counter-overflow": func(s string) string {
			return strings.Replace(s, "Syntra-Upload: 0", "Syntra-Upload: 18446744073709551616", 1)
		},
		"query":             func(s string) string { return strings.Replace(s, "/send ", "/send?x=1 ", 1) },
		"absolute":          func(s string) string { return strings.Replace(s, "POST /", "POST https://localhost:443/", 1) },
		"new-syntra-header": func(s string) string { return strings.Replace(s, "\r\n\r\n", "\r\nSyntra-Other: ignored\r\n\r\n", 1) },
		"content-type": func(s string) string {
			return strings.Replace(s, "application/octet-stream\r\nSyntra-Route", "application/octet-stream; charset=utf8\r\nSyntra-Route", 1)
		},
		"connection-nomination": func(s string) string {
			return strings.Replace(s, "\r\n\r\n", "\r\nConnection: content-length\r\n\r\n", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := ParseRequest([]byte(mutate(string(valid))), a, OriginPolicy{}); e == nil {
				t.Fatal("accepted malformed request")
			}
		})
	}
	p, e := AllowExactOrigins("https://localhost")
	if e != nil {
		t.Fatal(e)
	}
	origin := strings.Replace(string(valid), "\r\n\r\n", "\r\nOrigin: https://localhost\r\n\r\n", 1)
	if _, e := ParseRequest([]byte(origin), a, p); e != nil {
		t.Fatal(e)
	}
	if _, e := ParseRequest([]byte(strings.Replace(origin, "Origin: https://localhost", "Origin: https://localhost\r\nOrigin: https://localhost", 1)), a, p); e == nil {
		t.Fatal("duplicate origin accepted")
	}
	for _, op := range []Operation{Open, Send, Poll, Close} {
		n := 0
		route := r
		if op == Open {
			n = 83
			route = Route{}
		}
		if op == Send {
			n = MaxRecord
		}
		h, e := requestHeader(op, a, route, 0, n)
		if e != nil {
			t.Fatal(e)
		}
		got, e := ParseRequest(h, a, OriginPolicy{})
		if e != nil || got.Operation != op || got.BodyLen != n {
			t.Fatalf("roundtrip: %+v %v", got, e)
		}
	}
}

func TestStrictResponsesAndBounds(t *testing.T) {
	r := testRoute(t)
	for _, tc := range []struct {
		op Operation
		n  int
	}{{Open, 48}, {Send, 0}, {Poll, 0}, {Poll, 17}, {Poll, MaxRecord}, {Close, 0}} {
		route := Route{}
		if tc.op == Open {
			route = r
		}
		h, e := responseHeader(tc.op, route, 1, tc.n)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = ParseResponse(h, tc.op); e != nil {
			t.Fatal(e)
		}
	}
	for _, s := range []string{
		"HTTP/1.1 302 Found\r\nCache-Control: no-store\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\nContent-Length: 0\r\nSyntra-Upload: 0\r\n\r\n",
		"HTTP/1.1 204 No Content\r\nCache-Control: no-store\r\nSyntra-Upload: 0\r\nSet-Cookie: private\r\n\r\n",
	} {
		if _, e := ParseResponse([]byte(s), Send); e == nil {
			t.Fatal("invalid response accepted")
		}
	}
	for _, raw := range [][]byte{bytes.Repeat([]byte{'a'}, MaxHeaders+1), []byte("POST / HTTP/1.1\nx: y\n\n"), []byte("POST / HTTP/1.1\rX")} {
		if _, e := readHeader(bytes.NewReader(raw)); e == nil {
			t.Fatal("unbounded/malformed header accepted")
		}
	}
	if _, e := nextCounter(math.MaxUint64); !errors.Is(e, ordered.ErrProtocol) {
		t.Fatal("counter wrapped")
	}
	for _, code := range []int{400, 403, 404, 405, 410, 413, 429, 431, 503, 505} {
		b := rejectionBytes(code)
		if len(b) > 92 || !bytes.HasSuffix(b, []byte("Content-Length: 0\r\n\r\n")) {
			t.Fatal("unsafe rejection")
		}
	}
}
