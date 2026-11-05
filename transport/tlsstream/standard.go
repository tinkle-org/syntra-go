package tlsstream

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
)

// StandardProvider uses crypto/tls with fresh certificate verification on every
// connection. Configs are cloned; application callbacks and keys must be safe for
// concurrent use and must honor the handshake context. VerifyConnection may add
// current application policy after standard verification, including revocation.
// No session cache or tickets are used. Stream TLS sends no early data.
type StandardProvider struct{ client, server *tls.Config }

// NewStandardProvider accepts either or both role configurations. Version and
// ALPN may be omitted or explicitly match TLS 1.3 and http/1.1. Dynamic configs,
// verification bypasses, key logging and custom resumption hooks are rejected.
func NewStandardProvider(client, server *tls.Config) (*StandardProvider, error) {
	if client == nil && server == nil {
		return nil, securechannel.ErrConfig
	}
	p := &StandardProvider{}
	var err error
	if client != nil {
		p.client, err = standardConfig(client)
		if err != nil {
			return nil, err
		}
	}
	if server != nil {
		p.server, err = standardConfig(server)
		if err != nil || len(p.server.Certificates) == 0 || p.server.GetCertificate != nil {
			return nil, securechannel.ErrConfig
		}
		for _, cert := range p.server.Certificates {
			if len(cert.Certificate) == 0 {
				return nil, securechannel.ErrConfig
			}
			leaf, e := x509.ParseCertificate(cert.Certificate[0])
			signer, ok := cert.PrivateKey.(crypto.Signer)
			if e != nil || !ok {
				return nil, securechannel.ErrConfig
			}
			pub, e := x509.MarshalPKIXPublicKey(signer.Public())
			if e != nil || !bytes.Equal(pub, leaf.RawSubjectPublicKeyInfo) {
				return nil, securechannel.ErrConfig
			}
		}
	}
	return p, nil
}

func standardConfig(in *tls.Config) (*tls.Config, error) {
	if in.InsecureSkipVerify || in.GetConfigForClient != nil || in.KeyLogWriter != nil || in.WrapSession != nil || in.UnwrapSession != nil ||
		(in.MinVersion != 0 && in.MinVersion != tls.VersionTLS13) || (in.MaxVersion != 0 && in.MaxVersion != tls.VersionTLS13) ||
		(len(in.NextProtos) != 0 && (len(in.NextProtos) != 1 || in.NextProtos[0] != "http/1.1")) {
		return nil, securechannel.ErrConfig
	}
	c := in.Clone()
	c.MinVersion, c.MaxVersion = tls.VersionTLS13, tls.VersionTLS13
	c.NextProtos = []string{"http/1.1"}
	c.ClientSessionCache = nil
	c.SessionTicketsDisabled = true
	if in.RootCAs != nil {
		c.RootCAs = in.RootCAs.Clone()
	}
	if in.ClientCAs != nil {
		c.ClientCAs = in.ClientCAs.Clone()
	}
	c.Certificates = append([]tls.Certificate(nil), in.Certificates...)
	for i := range c.Certificates {
		cert := &c.Certificates[i]
		cert.Certificate = make([][]byte, len(in.Certificates[i].Certificate))
		for j, der := range in.Certificates[i].Certificate {
			cert.Certificate[j] = bytes.Clone(der)
		}
		cert.Leaf = nil
	}
	return c, nil
}

func (p *StandardProvider) Connect(ctx context.Context, raw net.Conn, a Authority) (Result, error) {
	if p == nil || p.client == nil || !a.valid() {
		return Result{}, securechannel.ErrConfig
	}
	cfg := p.client.Clone()
	if cfg.ServerName != "" && cfg.ServerName != a.Host() {
		return Result{}, securechannel.ErrConfig
	}
	cfg.ServerName = a.Host()
	return standardHandshake(ctx, tls.Client(&standardWire{Conn: raw}, cfg), a, Client)
}
func (p *StandardProvider) Accept(ctx context.Context, raw net.Conn, a Authority) (Result, error) {
	if p == nil || p.server == nil || !a.valid() {
		return Result{}, securechannel.ErrConfig
	}
	cfg := p.server.Clone()
	now := time.Now()
	if cfg.Time != nil {
		now = cfg.Time()
	}
	// The provisioned authority must be covered by the credentials in use.
	for _, cert := range cfg.Certificates {
		leaf, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil || leaf.VerifyHostname(a.Host()) != nil || now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return Result{}, securechannel.ErrConfig
		}
	}
	return standardHandshake(ctx, tls.Server(&standardWire{Conn: raw}, cfg), a, Server)
}
func standardHandshake(ctx context.Context, conn *tls.Conn, a Authority, role Role) (Result, error) {
	if err := conn.HandshakeContext(ctx); err != nil {
		if cutoff := stream.ContextError(ctx); cutoff != nil {
			return Result{}, cutoff
		}
		return Result{}, tlsError(err)
	}
	s := conn.ConnectionState()
	m := Metadata{Authority: a, Role: role, Version: s.Version, ALPN: s.NegotiatedProtocol}
	if !s.HandshakeComplete || !valid(m, a, role) {
		return Result{}, securechannel.ErrConfig
	}
	return Result{Conn: &standardConn{Conn: conn}, Metadata: m}, nil
}

// Preserve the distinction between typed TLS rejection and ordinary stream loss
// after establishment, when the encrypted record parser is still active.
func tlsError(err error) error {
	if err == nil {
		return nil
	}
	var wire *wireError
	if errors.As(err, &wire) {
		// TLS may make an outbound failure permanent. Preserve its outer
		// network semantics as well as the original sanitized I/O code.
		return wireIOError(err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return stream.Error(err)
	}
	var network *net.OpError
	if errors.As(err, &network) && network.Op != "remote error" {
		return ordered.ErrIO
	}
	return securechannel.ErrConfig
}

type standardConn struct{ *tls.Conn }

func (c *standardConn) Read(p []byte) (int, error) { n, err := c.Conn.Read(p); return n, tlsError(err) }
func (c *standardConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	return n, tlsError(err)
}

// Keep only a sanitized code and network-error flags. crypto/tls needs Temporary
// to leave its reader usable after an idle deadline, and callers need Timeout to
// recognize that probe. Retaining the raw error would expose peer diagnostics.
type wireError struct {
	error
	timeout, temporary, deadline bool
}

// tlsNetworkError preserves the retry classification required by crypto/tls's
// record reader. It is an internal compatibility contract, not a retry policy.
type tlsNetworkError interface {
	error
	Timeout() bool
	Temporary() bool
}

func (e *wireError) Timeout() bool        { return e.timeout }
func (e *wireError) Temporary() bool      { return e.temporary }
func (e *wireError) Unwrap() error        { return e.error }
func (e *wireError) Is(target error) bool { return e.deadline && target == os.ErrDeadlineExceeded }

func wireIOError(err error) error {
	if err == nil {
		return nil
	}
	// TLS distinguishes EOF at a record boundary from truncated records by
	// sentinel identity; these errors carry no connection-specific diagnostics.
	if errors.Is(err, io.EOF) {
		return io.EOF
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return io.ErrUnexpectedEOF
	}
	e := &wireError{error: stream.Error(err), deadline: errors.Is(err, os.ErrDeadlineExceeded)}
	var network tlsNetworkError
	if errors.As(err, &network) {
		e.timeout, e.temporary = network.Timeout(), network.Temporary()
	}
	return e
}

type standardWire struct{ net.Conn }

func (c *standardWire) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	return n, wireIOError(err)
}
func (c *standardWire) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	return n, wireIOError(err)
}
