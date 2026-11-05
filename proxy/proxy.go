// Package proxy negotiates explicit, bounded proxy tunnels on owned streams.
// Destinations are sent to the proxy without local name resolution. Credentials
// belong only to the proxy hop. There is no discovery, retry, or direct fallback.
package proxy

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
)

const (
	MaxConnectHeaderBytes = 16 * 1024
	MaxConnectHeaders     = 64
	MaxHTTPLineBytes      = 4096
)

var (
	ErrConfig         = securechannel.ErrConfig
	ErrAuthentication = securechannel.ErrAuth
	ErrFraming        = ordered.ErrProtocol
	ErrRefused        = fmt.Errorf("%w: proxy tunnel refused", ordered.ErrIO)
)

type Kind uint8

const (
	Socks5 Kind = iota + 1
	HTTPConnect
)

// Dialer receives an explicit numeric socket address and must honor ctx.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Target distinguishes an IP destination from a remotely resolved DNS name.
// The zero value is invalid. Target is comparable and contains no credentials.
type Target struct {
	host string
	ip   netip.Addr
	port uint16
}

func NewIPTarget(ip netip.Addr, port uint16) (Target, error) {
	if !validSocket(netip.AddrPortFrom(ip, port)) {
		return Target{}, ErrConfig
	}
	return Target{ip: ip, port: port}, nil
}

func NewHostnameTarget(host string, port uint16) (Target, error) {
	if port == 0 || len(host) == 0 || len(host) > 253 {
		return Target{}, ErrConfig
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return Target{}, ErrConfig
	}
	numeric := true
	for _, c := range []byte(host) {
		if !(c >= '0' && c <= '9' || c == '.') {
			numeric = false
		}
	}
	if numeric {
		return Target{}, ErrConfig
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Target{}, ErrConfig
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return Target{}, ErrConfig
			}
		}
	}
	return Target{host: host, port: port}, nil
}

func (t Target) Validate() error {
	var v Target
	var err error
	if t.ip.IsValid() {
		v, err = NewIPTarget(t.ip, t.port)
	} else {
		v, err = NewHostnameTarget(t.host, t.port)
	}
	if err != nil || v != t {
		return ErrConfig
	}
	return nil
}
func (t Target) Host() string {
	if t.ip.IsValid() {
		return t.ip.String()
	}
	return t.host
}
func (t Target) Port() uint16      { return t.port }
func (t Target) Authority() string { return net.JoinHostPort(t.Host(), strconv.Itoa(int(t.port))) }

// Credentials owns copies of raw octets. Close erases these copies. Formatting
// is redacted for every verb; caller buffers and socket buffers remain external.
type Credentials struct{ *credentialState }
type credentialState struct {
	mu                 sync.RWMutex
	username, password []byte
	closed             bool
}

func NewCredentials(username, password []byte) (*Credentials, error) {
	if len(username) < 1 || len(username) > 255 || len(password) < 1 || len(password) > 255 {
		return nil, ErrConfig
	}
	return &Credentials{&credentialState{username: append([]byte(nil), username...), password: append([]byte(nil), password...)}}, nil
}
func (Credentials) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted proxy credentials]")
}
func (c *Credentials) Close() error {
	if c != nil && c.credentialState != nil {
		c.mu.Lock()
		defer c.mu.Unlock()
		clear(c.username)
		clear(c.password)
		c.closed = true
	}
	return nil
}

type Config struct {
	Endpoint    netip.AddrPort
	Kind        Kind
	Credentials *Credentials
	Dialer      Dialer
}

func (Config) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[proxy configuration]") }

// ProxyConfig is an immutable validated configuration. Close clears its owned
// credential copy after all uses have completed. Do not copy this value.
type ProxyConfig struct {
	endpoint    netip.AddrPort
	kind        Kind
	credentials *Credentials
	dialer      Dialer
}

func (ProxyConfig) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[redacted proxy configuration]")
}
func NewProxy(cfg Config) (*ProxyConfig, error) {
	if !validSocket(cfg.Endpoint) || cfg.Kind != Socks5 && cfg.Kind != HTTPConnect {
		return nil, ErrConfig
	}
	p := &ProxyConfig{endpoint: cfg.Endpoint, kind: cfg.Kind, dialer: cfg.Dialer}
	if cfg.Credentials != nil {
		c := cfg.Credentials
		if c.credentialState == nil {
			return nil, ErrConfig
		}
		c.mu.RLock()
		defer c.mu.RUnlock()
		if c.closed {
			return nil, ErrConfig
		}
		if cfg.Kind == HTTPConnect && !validHTTP(c.username, c.password) {
			return nil, ErrConfig
		}
		var err error
		p.credentials, err = NewCredentials(c.username, c.password)
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}
func (p *ProxyConfig) Endpoint() netip.AddrPort {
	if p == nil {
		return netip.AddrPort{}
	}
	return p.endpoint
}
func (p *ProxyConfig) Kind() Kind {
	if p == nil {
		return 0
	}
	return p.kind
}
func (p *ProxyConfig) Close() error {
	if p == nil {
		return nil
	}
	return p.credentials.Close()
}
func (p *ProxyConfig) Validate() error {
	if p == nil || !validSocket(p.endpoint) || p.kind != Socks5 && p.kind != HTTPConnect {
		return ErrConfig
	}
	if c := p.credentials; c != nil {
		if c.credentialState == nil {
			return ErrConfig
		}
		c.mu.RLock()
		defer c.mu.RUnlock()
		if c.closed {
			return ErrConfig
		}
	}
	return nil
}
func validSocket(a netip.AddrPort) bool {
	return a.IsValid() && a.Port() != 0 && a.Addr().Zone() == "" && !a.Addr().Unmap().IsUnspecified() && !a.Addr().Unmap().IsMulticast()
}
func validHTTP(u, p []byte) bool {
	for _, c := range u {
		if c == ':' {
			return false
		}
	}
	for _, b := range [][]byte{u, p} {
		for _, c := range b {
			if c < 0x20 || c > 0x7e {
				return false
			}
		}
	}
	return true
}

// Tunnel dials exactly one configured proxy and returns its negotiated stream.
// The caller continues establishment with the same budget pointer.
func Tunnel(ctx context.Context, cfg *ProxyConfig, target Target, budget *ordered.EstablishmentBudget) (net.Conn, error) {
	return TunnelWithDialer(ctx, cfg, target, budget, nil)
}

// TunnelWithDialer overrides only the socket opener, retaining all negotiation.
func TunnelWithDialer(ctx context.Context, cfg *ProxyConfig, target Target, budget *ordered.EstablishmentBudget, dial Dialer) (net.Conn, error) {
	if ctx == nil || cfg.Validate() != nil || target.Validate() != nil || budget == nil {
		return nil, ErrConfig
	}
	if err := budget.Check(); err != nil {
		return nil, err
	}
	attempt, cancel := budget.Context(ctx)
	defer cancel()
	if err := stream.ContextError(attempt); err != nil {
		return nil, err
	}
	if dial == nil {
		dial = cfg.dialer
	}
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	c, err := dial(attempt, "tcp", cfg.endpoint.String())
	if err != nil {
		if c != nil {
			_ = c.Close()
		}
		if cutoff := stream.ContextError(attempt); cutoff != nil {
			return nil, cutoff
		}
		return nil, stream.Error(err)
	}
	if c == nil {
		return nil, ErrConfig
	}
	return TunnelStream(attempt, c, cfg, target, budget)
}

// TunnelStream takes ownership, including on malformed input or cancellation.
func TunnelStream(ctx context.Context, raw net.Conn, cfg *ProxyConfig, target Target, budget *ordered.EstablishmentBudget) (net.Conn, error) {
	if raw == nil {
		return nil, ErrConfig
	}
	ok := false
	defer func() {
		if !ok {
			_ = raw.Close()
		}
	}()
	if ctx == nil || cfg.Validate() != nil || target.Validate() != nil || budget == nil {
		return nil, ErrConfig
	}
	attempt, cancel := budget.Context(ctx)
	defer cancel()
	c := stream.New(raw, budget)
	err := stream.Do(attempt, c, true, true, func() error {
		if cfg.kind == Socks5 {
			return socks(c, cfg, target)
		}
		return connectHTTP(c, cfg, target)
	})
	if err != nil {
		return nil, err
	}
	ok = true
	return raw, nil
}

func readFull(r io.Reader, p []byte) error {
	_, err := io.ReadFull(r, p)
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return ErrFraming
	}
	return err
}

func socks(c net.Conn, cfg *ProxyConfig, target Target) error {
	method := byte(0)
	if cfg.credentials != nil {
		method = 2
	}
	if err := stream.WriteAll(c, []byte{5, 1, method}); err != nil {
		return err
	}
	var reply [4]byte
	if err := readFull(c, reply[:2]); err != nil {
		return err
	}
	if reply[0] != 5 {
		return ErrFraming
	}
	if reply[1] != method {
		return ErrAuthentication
	}
	if creds := cfg.credentials; creds != nil {
		auth, err := func() ([]byte, error) {
			creds.mu.RLock()
			defer creds.mu.RUnlock()
			if creds.closed {
				return nil, ErrConfig
			}
			p := make([]byte, 0, 3+len(creds.username)+len(creds.password))
			p = append(p, 1, byte(len(creds.username)))
			p = append(p, creds.username...)
			p = append(p, byte(len(creds.password)))
			return append(p, creds.password...), nil
		}()
		if err != nil {
			return err
		}
		err = stream.WriteAll(c, auth)
		clear(auth)
		if err != nil {
			return err
		}
		if err := readFull(c, reply[:2]); err != nil {
			return err
		}
		if reply[0] != 1 {
			return ErrFraming
		}
		if reply[1] != 0 {
			return ErrAuthentication
		}
	}
	request := make([]byte, 0, 262)
	request = append(request, 5, 1, 0)
	if target.ip.Is4() {
		a := target.ip.As4()
		request = append(request, 1)
		request = append(request, a[:]...)
	} else if target.ip.IsValid() {
		a := target.ip.As16()
		request = append(request, 4)
		request = append(request, a[:]...)
	} else {
		request = append(request, 3, byte(len(target.host)))
		request = append(request, target.host...)
	}
	request = binary.BigEndian.AppendUint16(request, target.port)
	if err := stream.WriteAll(c, request); err != nil {
		return err
	}
	if err := readFull(c, reply[:]); err != nil {
		return err
	}
	if reply[0] != 5 || reply[2] != 0 {
		return ErrFraming
	}
	switch reply[1] {
	case 0:
	case 2:
		return ErrAuthentication
	case 7, 8:
		return ErrConfig
	case 1, 3, 4, 5, 6:
		return ErrRefused
	default:
		return ErrFraming
	}
	n := 0
	switch reply[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		if err := readFull(c, reply[:1]); err != nil {
			return err
		}
		n = int(reply[0])
		if n == 0 {
			return ErrFraming
		}
	default:
		return ErrFraming
	}
	var bound [257]byte
	return readFull(c, bound[:n+2])
}

// AppendForwardAuthorization appends hop authentication only for an explicitly
// selected HTTP forward stream. dst must reserve MaxConnectHeaderBytes capacity;
// the caller must clear the returned bytes after writing and never send them on
// a tunnel or origin connection.
func (p *ProxyConfig) AppendForwardAuthorization(dst []byte) ([]byte, error) {
	if p.Validate() != nil || p.kind != HTTPConnect || cap(dst) < MaxConnectHeaderBytes {
		return dst, ErrConfig
	}
	c := p.credentials
	if c == nil {
		return dst, nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return dst, ErrConfig
	}
	plain := make([]byte, 0, len(c.username)+1+len(c.password))
	plain = append(plain, c.username...)
	plain = append(plain, ':')
	plain = append(plain, c.password...)
	defer clear(plain)
	n := base64.StdEncoding.EncodedLen(len(plain))
	const prefix = "Proxy-Authorization: Basic "
	if len(dst)+len(prefix)+n+2 > MaxConnectHeaderBytes {
		return dst, ErrFraming
	}
	dst = append(dst, prefix...)
	start := len(dst)
	dst = dst[:start+n]
	base64.StdEncoding.Encode(dst[start:], plain)
	return append(dst, '\r', '\n'), nil
}

func connectHTTP(c net.Conn, cfg *ProxyConfig, target Target) error {
	request := make([]byte, 0, MaxConnectHeaderBytes)
	defer func() { clear(request[:cap(request)]) }()
	a := target.Authority()
	request = append(request, "CONNECT "...)
	request = append(request, a...)
	request = append(request, " HTTP/1.1\r\nHost: "...)
	request = append(request, a...)
	request = append(request, '\r', '\n')
	var err error
	request, err = cfg.AppendForwardAuthorization(request)
	if err != nil {
		return err
	}
	request = append(request, '\r', '\n')
	if err = stream.WriteAll(c, request); err != nil {
		return err
	}
	head := make([]byte, 0, MaxConnectHeaderBytes)
	defer func() { clear(head[:cap(head)]) }()
	var one [1]byte
	lineStart, lines := 0, 0
	for len(head) < MaxConnectHeaderBytes {
		if err := readFull(c, one[:]); err != nil {
			return err
		}
		head = append(head, one[0])
		n := len(head)
		if n-lineStart > MaxHTTPLineBytes+2 {
			return ErrFraming
		}
		if one[0] == '\n' {
			if n < 2 || head[n-2] != '\r' {
				return ErrFraming
			}
			lines++
			if lines > MaxConnectHeaders+2 {
				return ErrFraming
			}
			lineStart = n
		} else if n > 1 && head[n-2] == '\r' {
			return ErrFraming
		}
		if n >= 4 && string(head[n-4:]) == "\r\n\r\n" {
			return parseResponse(head)
		}
	}
	return ErrFraming
}

func valueByte(b byte) bool { return b == '\t' || b >= 0x20 && b != 0x7f }
func tokenByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(b))
}
func parseResponse(head []byte) error {
	if len(head) > MaxConnectHeaderBytes {
		return ErrFraming
	}
	// Work on byte slices so reflected credentials never enter immutable strings.
	lines := splitLines(head)
	if len(lines) < 2 || len(lines)-2 > MaxConnectHeaders {
		return ErrFraming
	}
	s := lines[0]
	if len(s) < 13 || len(s) > MaxHTTPLineBytes || string(s[:9]) != "HTTP/1.1 " && string(s[:9]) != "HTTP/1.0 " || s[12] != ' ' {
		return ErrFraming
	}
	code := 0
	for _, b := range s[9:12] {
		if b < '0' || b > '9' {
			return ErrFraming
		}
		code = code*10 + int(b-'0')
	}
	for _, b := range s[13:] {
		if !valueByte(b) {
			return ErrFraming
		}
	}
	for _, line := range lines[1 : len(lines)-1] {
		if len(line) == 0 || len(line) > MaxHTTPLineBytes {
			return ErrFraming
		}
		colon := -1
		for i, b := range line {
			if b == ':' {
				colon = i
				break
			}
			if !tokenByte(b) {
				return ErrFraming
			}
		}
		if colon <= 0 || equalASCII(line[:colon], "status") {
			return ErrFraming
		}
		for _, b := range line[colon+1:] {
			if !valueByte(b) {
				return ErrFraming
			}
		}
	}
	if len(lines[len(lines)-1]) != 0 {
		return ErrFraming
	}
	switch {
	case code >= 200 && code <= 299:
		return nil
	case code == 401 || code == 403 || code == 407:
		return ErrAuthentication
	case code >= 100 && code <= 599:
		return ErrRefused
	default:
		return ErrFraming
	}
}
func splitLines(p []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i := 0; i < len(p); i++ {
		if p[i] == '\n' {
			if i == 0 || p[i-1] != '\r' {
				return nil
			}
			lines = append(lines, p[start:i-1])
			if len(lines) > MaxConnectHeaders+2 {
				return nil
			}
			start = i + 1
		} else if p[i] == '\r' && (i+1 == len(p) || p[i+1] != '\n') {
			return nil
		}
	}
	if start != len(p) {
		return nil
	}
	return lines
}
func equalASCII(p []byte, s string) bool {
	if len(p) != len(s) {
		return false
	}
	for i, b := range p {
		if b >= 'A' && b <= 'Z' {
			b += 'a' - 'A'
		}
		if b != s[i] {
			return false
		}
	}
	return true
}
