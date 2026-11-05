package syntrahttp

import (
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

// Codec limits apply before allocation, including on incomplete headers.
const (
	MaxHeaders   = 16384
	MaxFields    = 64
	MaxStartLine = 2048
	MaxFieldLine = 4096
	MaxRecord    = 65535
)

// Authority requires an already canonical DNS A-label or IP and explicit port.
// It is routing configuration, not evidence of endpoint authentication.
type Authority struct{ value string }

// NewAuthority accepts canonical ASCII host:port syntax without normalization.
func NewAuthority(value string) (Authority, error) {
	if len(value) > 320 {
		return Authority{}, securechannel.ErrConfig
	}
	host, port, err := net.SplitHostPort(value)
	n, e := decimal(port)
	if err != nil || e != nil || n == 0 || n > 65535 {
		return Authority{}, securechannel.ErrConfig
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" || ip.String() != host {
			return Authority{}, securechannel.ErrConfig
		}
	} else {
		if len(host) == 0 || len(host) > 253 {
			return Authority{}, securechannel.ErrConfig
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Authority{}, securechannel.ErrConfig
			}
			for _, b := range []byte(label) {
				if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
					return Authority{}, securechannel.ErrConfig
				}
			}
		}
	}
	if net.JoinHostPort(host, port) != value {
		return Authority{}, securechannel.ErrConfig
	}
	return Authority{value}, nil
}
func (a Authority) String() string { return a.value }
func (a Authority) valid() bool    { b, err := NewAuthority(a.value); return err == nil && a == b }

// TLSAuthority returns the same provisioned host and effective port for TLS.
func (a Authority) TLSAuthority() (tlsstream.Authority, error) {
	if !a.valid() {
		return tlsstream.Authority{}, securechannel.ErrConfig
	}
	h, p, _ := net.SplitHostPort(a.value)
	n, _ := strconv.ParseUint(p, 10, 16)
	return tlsstream.NewAuthority(h, uint16(n))
}

// Route is an opaque transient selector. Formatting never renders its bytes.
type Route struct{ value string }

// ParseRoute validates exactly 64 lower-case hexadecimal selector characters.
func ParseRoute(value string) (Route, error) {
	if len(value) != 64 {
		return Route{}, ordered.ErrProtocol
	}
	for _, b := range []byte(value) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return Route{}, ordered.ErrProtocol
		}
	}
	return Route{value}, nil
}

// WireValue explicitly exposes routing bytes for the HTTP envelope only.
func (r Route) WireValue() string        { return r.value }
func (Route) String() string             { return "[route]" }
func (Route) GoString() string           { return "[route]" }
func (Route) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[route]") }
func routeFromRandom(b [32]byte) Route   { return Route{hex.EncodeToString(b[:])} }

// OriginPolicy's zero value accepts only absent Origin. The allowlist is copied.
type OriginPolicy struct{ allowed []string }

// AllowExactOrigins copies up to 64 canonical serialized HTTP(S) origins. Paths,
// credentials, null, origin lists and explicitly spelled default ports fail.
func AllowExactOrigins(origins ...string) (OriginPolicy, error) {
	if len(origins) > 64 {
		return OriginPolicy{}, securechannel.ErrConfig
	}
	for _, s := range origins {
		u, err := url.Parse(s)
		if err != nil || len(s) > 2048 || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Path != "" || u.RawPath != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return OriginPolicy{}, securechannel.ErrConfig
		}
		port := u.Port()
		if port == "" {
			if u.Scheme == "http" {
				port = "80"
			} else {
				port = "443"
			}
		} else if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			return OriginPolicy{}, securechannel.ErrConfig
		}
		a, err := NewAuthority(net.JoinHostPort(u.Hostname(), port))
		if err != nil {
			return OriginPolicy{}, securechannel.ErrConfig
		}
		h := a.value
		if u.Port() == "" {
			h = strings.TrimSuffix(h, ":"+port)
		}
		if s != u.Scheme+"://"+h {
			return OriginPolicy{}, securechannel.ErrConfig
		}
	}
	return OriginPolicy{append([]string(nil), origins...)}, nil
}
func (p OriginPolicy) accepts(s string) bool {
	for _, a := range p.allowed {
		if a == s {
			return true
		}
	}
	return false
}

// Operation selects exactly one supported HTTP POST path.
type Operation uint8

const (
	Open Operation = iota + 1
	Send
	Poll
	Close
)

// Path is the exact origin-form target, without query or fragment syntax.
func (op Operation) Path() string {
	switch op {
	case Open:
		return "/syntra/1.0/http/open"
	case Send:
		return "/syntra/1.0/http/send"
	case Poll:
		return "/syntra/1.0/http/poll"
	case Close:
		return "/syntra/1.0/http/close"
	}
	return ""
}

// Head is validated routing/framing metadata. It establishes no identity.
type Head struct {
	Operation Operation
	Status    int
	BodyLen   int
	Route     Route
	Counter   uint64
}

// rejection contains no peer-controlled text.
type rejection int

func (rejection) Error() string { return "syntrahttp: request rejected" }
func reject(code int) error     { return rejection(code) }
func rejectionBytes(code int) []byte {
	phrase := map[int]string{400: "Bad Request", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 410: "Gone", 413: "Content Too Large", 429: "Too Many Requests", 431: "Request Header Fields Too Large", 503: "Service Unavailable", 505: "HTTP Version Not Supported"}[code]
	if phrase == "" {
		code, phrase = 400, "Bad Request"
	}
	extra := ""
	if code == 405 {
		extra = "Allow: POST\r\n"
	}
	return []byte(fmt.Sprintf("HTTP/1.1 %d %s\r\n%sCache-Control: no-store\r\nContent-Length: 0\r\n\r\n", code, phrase, extra))
}

func decimal(s string) (uint64, error) {
	if s == "" || len(s) > 1 && s[0] == '0' {
		return 0, ordered.ErrProtocol
	}
	for _, b := range []byte(s) {
		if b < '0' || b > '9' {
			return 0, ordered.ErrProtocol
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, ordered.ErrProtocol
	}
	return n, nil
}
func token(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}
func fields(raw []byte) (string, map[string]string, error) {
	if len(raw) > MaxHeaders {
		return "", nil, reject(431)
	}
	s := string(raw)
	if !strings.HasSuffix(s, "\r\n\r\n") {
		return "", nil, reject(400)
	}
	lines := strings.Split(s[:len(s)-4], "\r\n")
	if len(lines[0])+2 > MaxStartLine || len(lines)-1 > MaxFields {
		return "", nil, reject(431)
	}
	for _, b := range []byte(lines[0]) {
		if b < 32 || b > 126 {
			return "", nil, reject(400)
		}
	}
	h := make(map[string]string, len(lines)-1)
	for _, line := range lines[1:] {
		if len(line)+2 > MaxFieldLine {
			return "", nil, reject(431)
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || name == "" {
			return "", nil, reject(400)
		}
		for _, b := range []byte(name) {
			if !token(b) {
				return "", nil, reject(400)
			}
		}
		for _, b := range []byte(value) {
			if b != '\t' && (b < 32 || b > 126) {
				return "", nil, reject(400)
			}
		}
		name = strings.ToLower(name)
		if _, ok := h[name]; ok {
			if name == "origin" {
				return "", nil, reject(403)
			}
			return "", nil, reject(400)
		}
		value = strings.Trim(value, " \t")
		switch name {
		case "transfer-encoding", "content-encoding", "trailer", "expect", "upgrade", "te", "authorization", "proxy-authorization", "cookie", "set-cookie":
			return "", nil, reject(400)
		}
		if strings.HasPrefix(name, "syntra-") && name != "syntra-route" && name != "syntra-upload" && name != "syntra-poll" {
			return "", nil, reject(400)
		}
		if name == "connection" {
			for _, v := range strings.Split(value, ",") {
				if !strings.EqualFold(strings.Trim(v, " \t"), "keep-alive") {
					return "", nil, reject(400)
				}
			}
		}
		h[name] = value
	}
	return lines[0], h, nil
}
func length(h map[string]string, status int) (int, error) {
	s, present := h["content-length"]
	var n uint64
	if status == 204 {
		if present {
			return 0, reject(400)
		}
	} else {
		var err error
		n, err = decimal(s)
		if !present || err != nil {
			return 0, reject(400)
		}
	}
	if n > MaxRecord {
		return 0, reject(413)
	}
	v, exists := h["content-type"]
	if n > 0 && v != "application/octet-stream" || n == 0 && exists {
		return 0, reject(400)
	}
	return int(n), nil
}
func association(h map[string]string, route, upload, poll bool) (Route, uint64, error) {
	_, r := h["syntra-route"]
	_, u := h["syntra-upload"]
	_, p := h["syntra-poll"]
	if r != route || u != upload || p != poll {
		return Route{}, 0, reject(400)
	}
	var out Route
	var counter uint64
	var err error
	if r {
		out, err = ParseRoute(h["syntra-route"])
		if err != nil {
			return out, 0, reject(400)
		}
	}
	if u {
		counter, err = decimal(h["syntra-upload"])
	} else if p {
		counter, err = decimal(h["syntra-poll"])
	}
	if err != nil {
		return Route{}, 0, reject(400)
	}
	return out, counter, nil
}

// ParseRequest validates all routing and framing metadata before body allocation
// or association lookup. It accepts exactly one complete header block.
func ParseRequest(raw []byte, authority Authority, origins OriginPolicy) (Head, error) {
	start, h, err := fields(raw)
	if err != nil {
		return Head{}, err
	}
	w := strings.Split(start, " ")
	if len(w) != 3 || w[0] == "" || len(w[2]) != 8 || !strings.HasPrefix(w[2], "HTTP/") || w[2][5] < '0' || w[2][5] > '9' || w[2][6] != '.' || w[2][7] < '0' || w[2][7] > '9' {
		return Head{}, reject(400)
	}
	for _, b := range []byte(w[0]) {
		if !token(b) {
			return Head{}, reject(400)
		}
	}
	if w[2] != "HTTP/1.1" {
		return Head{}, reject(505)
	}
	if w[0] != "POST" {
		return Head{}, reject(405)
	}
	var op Operation
	for _, candidate := range []Operation{Open, Send, Poll, Close} {
		if w[1] == candidate.Path() {
			op = candidate
		}
	}
	if op == 0 {
		return Head{}, reject(404)
	}
	if _, exists := h["host"]; !exists {
		return Head{}, reject(400)
	}
	if !authority.valid() || h["host"] != authority.value {
		return Head{}, reject(404)
	}
	if o, exists := h["origin"]; exists && !origins.accepts(o) {
		return Head{}, reject(403)
	}
	if h["accept"] != "application/octet-stream" || h["cache-control"] != "no-store" {
		return Head{}, reject(400)
	}
	declared, e := decimal(h["content-length"])
	if e != nil {
		value := h["content-length"]
		canonical := len(value) > 0 && value[0] != '0'
		for _, b := range []byte(value) {
			canonical = canonical && b >= '0' && b <= '9'
		}
		if canonical {
			return Head{}, reject(413)
		}
		return Head{}, reject(400)
	}
	maximum := uint64(MaxRecord)
	if op == Open {
		maximum = uint64(securechannel.MaxContext + securechannel.HandshakeSize)
	} else if op == Poll || op == Close {
		maximum = 0
	}
	if declared > maximum {
		return Head{}, reject(413)
	}
	n, err := length(h, 0)
	if err != nil {
		return Head{}, err
	}
	if op == Open && n < 83 || op == Send && n < 17 {
		return Head{}, reject(400)
	}
	r, c, err := association(h, op != Open, op == Send, op == Poll)
	return Head{Operation: op, BodyLen: n, Route: r, Counter: c}, err
}

// ParseResponse accepts only the exact success class for the selected operation.
// Redirects, challenges, informational and native error responses are terminal.
func ParseResponse(raw []byte, op Operation) (Head, error) {
	start, h, err := fields(raw)
	if err != nil {
		return Head{}, ordered.ErrProtocol
	}
	w := strings.SplitN(start, " ", 3)
	if len(w) != 3 || w[0] != "HTTP/1.1" || len(w[1]) != 3 || h["cache-control"] != "no-store" {
		return Head{}, ordered.ErrProtocol
	}
	num, err := decimal(w[1])
	if err != nil {
		return Head{}, ordered.ErrProtocol
	}
	n, err := length(h, int(num))
	if err != nil {
		return Head{}, ordered.ErrProtocol
	}
	valid := op == Open && num == 201 && n == 48 || (op == Send || op == Close) && num == 204 || op == Poll && (num == 204 || num == 200 && n >= 17)
	if !valid {
		return Head{}, ordered.ErrProtocol
	}
	r, c, err := association(h, op == Open, op == Send, op == Poll)
	if err != nil {
		return Head{}, ordered.ErrProtocol
	}
	return Head{Operation: op, Status: int(num), BodyLen: n, Route: r, Counter: c}, nil
}

func requestHeader(op Operation, a Authority, r Route, counter uint64, n int) ([]byte, error) {
	s := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nCache-Control: no-store\r\nAccept: application/octet-stream\r\nContent-Length: %d\r\n", op.Path(), a.value, n)
	if n > 0 {
		s += "Content-Type: application/octet-stream\r\n"
	}
	if op != Open {
		s += "Syntra-Route: " + r.value + "\r\n"
	}
	if op == Send {
		s += fmt.Sprintf("Syntra-Upload: %d\r\n", counter)
	}
	if op == Poll {
		s += fmt.Sprintf("Syntra-Poll: %d\r\n", counter)
	}
	b := []byte(s + "\r\n")
	_, err := ParseRequest(b, a, OriginPolicy{})
	if err != nil {
		return nil, ordered.ErrProtocol
	}
	return b, nil
}
func responseHeader(op Operation, r Route, counter uint64, n int) ([]byte, error) {
	status := "204 No Content"
	if op == Open {
		status = "201 Created"
	} else if op == Poll && n != 0 {
		status = "200 OK"
	}
	s := "HTTP/1.1 " + status + "\r\nCache-Control: no-store\r\n"
	if !strings.HasPrefix(status, "204") {
		s += fmt.Sprintf("Content-Length: %d\r\n", n)
	}
	if n > 0 {
		s += "Content-Type: application/octet-stream\r\n"
	}
	if op == Open {
		s += "Syntra-Route: " + r.value + "\r\n"
	}
	if op == Send {
		s += fmt.Sprintf("Syntra-Upload: %d\r\n", counter)
	}
	if op == Poll {
		s += fmt.Sprintf("Syntra-Poll: %d\r\n", counter)
	}
	b := []byte(s + "\r\n")
	head, err := ParseResponse(b, op)
	if err != nil || head.BodyLen != n {
		return nil, ordered.ErrProtocol
	}
	return b, nil
}

// readHeader reads no body or following message. All storage and line counts
// are bounded even when a peer never terminates its header block.
func readHeader(r io.Reader) ([]byte, error) {
	b := make([]byte, 0, MaxHeaders)
	line, count := 0, 0
	for len(b) < MaxHeaders {
		var one [1]byte
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return nil, err
		}
		b = append(b, one[0])
		n := len(b)
		limit := MaxFieldLine
		if line == 0 {
			limit = MaxStartLine
		}
		if n-line > limit {
			return nil, reject(431)
		}
		if one[0] == '\n' {
			if n < 2 || b[n-2] != '\r' {
				return nil, reject(400)
			}
			if n-line == 2 {
				return b, nil
			}
			if line != 0 {
				count++
				if count > MaxFields {
					return nil, reject(431)
				}
			}
			line = n
		} else if n > 1 && b[n-2] == '\r' {
			return nil, reject(400)
		}
	}
	return nil, reject(431)
}
