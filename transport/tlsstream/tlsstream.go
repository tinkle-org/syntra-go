// Package tlsstream owns authenticated TLS on application-provided connections.
package tlsstream

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
)

// Authority is a canonical DNS name or IP and nonzero effective port.
// DNS input must be ASCII; international names must already use ASCII labels.
type Authority struct {
	host string
	port uint16
}

func NewAuthority(host string, port uint16) (Authority, error) {
	if port == 0 || host == "" {
		return Authority{}, securechannel.ErrConfig
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
		if ip := net.ParseIP(host); ip == nil || !strings.Contains(host, ":") {
			return Authority{}, securechannel.ErrConfig
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return Authority{ip.String(), port}, nil
	}
	host = strings.ToLower(host)
	if len(host) > 253 {
		return Authority{}, securechannel.ErrConfig
	}
	name := strings.TrimSuffix(host, ".")
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return Authority{}, securechannel.ErrConfig
		}
		for _, c := range []byte(label) {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return Authority{}, securechannel.ErrConfig
			}
		}
	}
	return Authority{host, port}, nil
}
func (a Authority) Host() string   { return a.host }
func (a Authority) Port() uint16   { return a.port }
func (a Authority) String() string { return net.JoinHostPort(a.host, strconv.Itoa(int(a.port))) }
func (a Authority) valid() bool {
	canonical, err := NewAuthority(a.host, a.port)
	return err == nil && canonical == a
}

type Role uint8

const (
	Client Role = iota + 1
	Server
)

type Metadata struct {
	Authority Authority
	Role      Role
	Version   uint16
	ALPN      string
	EarlyData bool
}
type Result struct {
	Conn     net.Conn
	Metadata Metadata
}

// Provider is trusted application code. It must complete authenticated TLS 1.3
// on the supplied stream, negotiate http/1.1, disable early data, honor ctx, and
// retain that stream's ownership and I/O gates. It must never redial or detach
// I/O. Connect validates the chain, hostname, time and current application trust
// policy; Accept uses current credentials for the provisioned local authority.
// Metadata is an observation of that session. Caller honesty remains necessary:
// this boundary cannot prove that an arbitrary provider actually performed TLS.
// Trust, credential and protocol rejection must return securechannel.ErrConfig
// or ErrAuth. Other errors are treated as sanitized carrier I/O failures.
type Provider interface {
	Connect(context.Context, net.Conn, Authority) (Result, error)
	Accept(context.Context, net.Conn, Authority) (Result, error)
}

// Verified is a single-use authority/role/attempt proof. Copies share private
// consumption state. It deliberately does not implement net.Conn.
type Verified struct{ state *proof }
type proof struct {
	mu       sync.Mutex
	conn     net.Conn
	metadata Metadata
	budget   *ordered.EstablishmentBudget
}

func (v *Verified) Metadata() Metadata {
	if v == nil || v.state == nil {
		return Metadata{}
	}
	return v.state.metadata
}

// Budget returns the original attempt for composition, without renewing it.
func (v *Verified) Budget() *ordered.EstablishmentBudget {
	if v == nil || v.state == nil {
		return nil
	}
	return v.state.budget
}

// Consume transfers the connection exactly once. A mismatch retires the proof
// and closes its stream; no HTTP bytes may be sent before this check.
func (v *Verified) Consume(a Authority, role Role, b *ordered.EstablishmentBudget) (net.Conn, error) {
	if v == nil || v.state == nil {
		return nil, securechannel.ErrConfig
	}
	s := v.state
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn == nil {
		return nil, securechannel.ErrConfig
	}
	if b == nil || b != s.budget || !valid(s.metadata, a, role) {
		_ = conn.Close()
		return nil, securechannel.ErrConfig
	}
	if err := stream.Check(b); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// Close releases an unconsumed proof. Once consumed, the recipient owns close.
func (v *Verified) Close() error {
	if v == nil || v.state == nil {
		return nil
	}
	s := v.state
	s.mu.Lock()
	c := s.conn
	s.conn = nil
	s.mu.Unlock()
	if c != nil {
		return stream.Error(c.Close())
	}
	return nil
}

func valid(m Metadata, a Authority, r Role) bool {
	return a.valid() && m.Authority == a && m.Role == r && (r == Client || r == Server) && m.Version == tls.VersionTLS13 && m.ALPN == "http/1.1" && !m.EarlyData
}
func Connect(ctx context.Context, raw net.Conn, p Provider, a Authority, b *ordered.EstablishmentBudget) (*Verified, error) {
	return establish(ctx, raw, p, a, Client, b)
}
func Accept(ctx context.Context, raw net.Conn, p Provider, a Authority, b *ordered.EstablishmentBudget) (*Verified, error) {
	return establish(ctx, raw, p, a, Server, b)
}

func establish(ctx context.Context, raw net.Conn, p Provider, a Authority, role Role, b *ordered.EstablishmentBudget) (*Verified, error) {
	if raw == nil {
		return nil, securechannel.ErrConfig
	}
	owned := stream.New(raw, b)
	if p == nil || b == nil || !a.valid() {
		_ = owned.Close()
		return nil, securechannel.ErrConfig
	}
	attempt, cancel := b.Context(ctx)
	defer cancel()
	var result Result
	err := stream.Do(attempt, owned, true, true, func() error {
		if err := stream.Check(b); err != nil {
			return err
		}
		var err error
		if role == Client {
			result, err = p.Connect(attempt, owned, a)
		} else {
			result, err = p.Accept(attempt, owned, a)
		}
		if err != nil {
			return err
		}
		if result.Conn == nil || !valid(result.Metadata, a, role) {
			return securechannel.ErrConfig
		}
		return stream.Check(b)
	})
	if err != nil {
		_ = owned.Close()
		if result.Conn != nil {
			_ = result.Conn.Close()
		}
		return nil, err
	}
	conn := &ownedResult{Conn: result.Conn, raw: owned}
	return &Verified{state: &proof{conn: stream.New(conn, b), metadata: result.Metadata, budget: b}}, nil
}

type ownedResult struct {
	net.Conn
	raw  *stream.Conn
	once sync.Once
	err  error
}

func (c *ownedResult) Close() error {
	c.once.Do(func() {
		// Close raw first: TLS shutdown must never wait on an unresponsive peer.
		c.err = c.raw.Close()
		_ = c.Conn.Close()
	})
	return c.err
}
