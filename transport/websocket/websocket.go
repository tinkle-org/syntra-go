// Package websocket implements SC1 draft-1 over binary WS/WSS messages.
package websocket

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	ws "github.com/coder/websocket"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

// Subprotocol identifies this implementation's SC1 draft, not an upstream
// assigned protocol identifier.
const Subprotocol = "syntra.sc1.draft1"

type Options struct {
	Limits         ordered.Options
	HTTPClient     *http.Client
	OriginPatterns []string
}

// Dial accepts only explicit ws:// or wss:// URLs. Redirects are refused.
// Inspectable HTTP transports are cloned, require certificate verification,
// and use TLS >= 1.3; custom TLS dial hooks are unsupported and custom
// RoundTrippers own their TLS security policy.
// Establishment and the eventual connection share one Lifetime budget measured
// from entry; HandshakeTimeout and HTTPClient.Timeout also bound establishment.
func Dial(ctx context.Context, address string, cfg securechannel.ClientConfig, opts Options) (*ordered.Transport, error) {
	started := time.Now()
	u, err := url.Parse(address)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" || (u.Scheme != "ws" && u.Scheme != "wss") {
		return nil, securechannel.ErrConfig
	}
	carrier := securechannel.WS
	if u.Scheme == "wss" {
		carrier = securechannel.WSS
	}
	if cfg.Context.Carrier != carrier {
		return nil, securechannel.ErrConfig
	}
	o, err := opts.Limits.Normalize()
	if err != nil {
		return nil, err
	}
	client, err := secureHTTPClient(opts.HTTPClient)
	if err != nil {
		return nil, err
	}
	budget := &messageBudget{}
	bound := min(o.HandshakeTimeout, o.Lifetime)
	if client.Timeout > 0 {
		bound = min(bound, client.Timeout)
	}
	// Use the adapter's context for this timeout instead of letting the library
	// create/cancel a private context while returning a successful connection.
	client.Timeout = 0
	ctx, cancel := context.WithDeadline(ctx, started.Add(bound))
	defer cancel()
	abort := &upgradeAbort{ctx: ctx}
	client.Transport = observedRoundTripper{base: client.Transport, budget: budget, abort: abort}
	c, _, err := ws.Dial(ctx, address, &ws.DialOptions{HTTPClient: client, Subprotocols: []string{Subprotocol}, CompressionMode: ws.CompressionDisabled})
	abort.disarm()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ordered.ErrIO
	}
	if c.Subprotocol() != Subprotocol {
		c.CloseNow()
		return nil, ordered.ErrProtocol
	}
	c.SetReadLimit(securechannel.MaxCiphertext)
	o.Lifetime -= time.Since(started)
	if o.Lifetime <= 0 {
		c.CloseNow()
		return nil, context.DeadlineExceeded
	}
	return ordered.Client(ctx, &messageIO{conn: c, assembly: o.RecordTimeout, budget: budget}, cfg, o)
}

func secureHTTPClient(original *http.Client) (*http.Client, error) {
	var client http.Client
	if original != nil {
		client = *original
	}
	rt := client.Transport
	if rt == nil {
		rt = http.DefaultTransport
	}
	if standard, ok := rt.(*http.Transport); ok {
		if standard.DialTLSContext != nil || standard.DialTLS != nil {
			return nil, securechannel.ErrConfig
		}
		tr := standard.Clone()
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{}
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		if tr.TLSClientConfig.InsecureSkipVerify {
			return nil, securechannel.ErrConfig
		}
		if tr.TLSClientConfig.MinVersion < tls.VersionTLS13 {
			tr.TLSClientConfig.MinVersion = tls.VersionTLS13
		}
		if tr.TLSClientConfig.MaxVersion != 0 && tr.TLSClientConfig.MaxVersion < tls.VersionTLS13 {
			return nil, securechannel.ErrConfig
		}
		client.Transport = tr
	} else {
		client.Transport = rt
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &client, nil
}

// Accept checks SC1 carrier and subprotocol before upgrading. r.TLS is the
// authoritative WS/WSS binding and WSS requires TLS >= 1.3. TLS termination
// requires an explicitly secure deployment rather than trusting forwarded headers.
// Establishment counts against Lifetime from entry, and is also bounded by
// HandshakeTimeout and ctx. Successful transports retain only the remaining life.
func Accept(ctx context.Context, w http.ResponseWriter, r *http.Request, cfg securechannel.ServerConfig, opts Options) (*ordered.Transport, error) {
	started := time.Now()
	carrier := securechannel.WS
	if r.TLS != nil {
		if r.TLS.Version < tls.VersionTLS13 {
			http.Error(w, "TLS 1.3 required", http.StatusBadRequest)
			return nil, securechannel.ErrConfig
		}
		carrier = securechannel.WSS
	}
	o, err := opts.Limits.Normalize()
	if err != nil {
		http.Error(w, "invalid configuration", http.StatusInternalServerError)
		return nil, err
	}
	if cfg.Carrier != carrier || cfg.Validate() != nil {
		http.Error(w, "invalid configuration", http.StatusBadRequest)
		return nil, securechannel.ErrConfig
	}
	found := false
	for _, header := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, token := range strings.Split(header, ",") {
			if strings.TrimSpace(token) == Subprotocol {
				found = true
			}
		}
	}
	if !found {
		http.Error(w, "SC1 subprotocol required", http.StatusBadRequest)
		return nil, ordered.ErrProtocol
	}
	// coder/websocket matches subprotocols case-insensitively. Only offer its
	// selector the exact token already verified above, including when a peer
	// sent differently-cased alternatives before that token.
	request := new(http.Request)
	*request = *r
	request.Header = r.Header.Clone()
	request.Header.Set("Sec-WebSocket-Protocol", Subprotocol)
	ctx, cancel := context.WithDeadline(ctx, started.Add(min(o.HandshakeTimeout, o.Lifetime)))
	defer cancel()
	if ctx.Err() != nil {
		http.Error(w, "handshake expired", http.StatusRequestTimeout)
		return nil, ctx.Err()
	}
	budget := &messageBudget{}
	writer := &observedWriter{ResponseWriter: w, budget: budget}
	d, _ := ctx.Deadline()
	_ = http.NewResponseController(w).SetWriteDeadline(d)
	interrupted := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = http.NewResponseController(w).SetWriteDeadline(time.Now()); close(interrupted) })
	defer func() {
		if !stop() {
			<-interrupted
		}
		if writer.conn != nil {
			_ = writer.conn.SetDeadline(time.Time{})
		} else {
			_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		}
	}()
	c, err := ws.Accept(writer, request, &ws.AcceptOptions{Subprotocols: []string{Subprotocol}, OriginPatterns: opts.OriginPatterns, CompressionMode: ws.CompressionDisabled})
	if err != nil {
		return nil, ordered.ErrIO
	}
	if c.Subprotocol() != Subprotocol {
		c.CloseNow()
		return nil, ordered.ErrProtocol
	}
	c.SetReadLimit(securechannel.MaxCiphertext)
	o.Lifetime -= time.Since(started)
	if o.Lifetime <= 0 {
		c.CloseNow()
		return nil, context.DeadlineExceeded
	}
	return ordered.Server(ctx, &messageIO{conn: c, assembly: o.RecordTimeout, budget: budget}, cfg, o)
}

type messageIO struct {
	conn     *ws.Conn
	assembly time.Duration
	budget   *messageBudget
}

func (m *messageIO) Close() error { _ = m.conn.CloseNow(); return nil }

func (m *messageIO) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	m.budget.begin(cancel, m.assembly)
	defer m.budget.end()
	typ, reader, err := m.conn.Reader(ctx)
	if err != nil {
		return nil, ordered.ErrIO
	}
	if typ != ws.MessageBinary {
		return nil, ordered.ErrProtocol
	}
	// The wire observer has already started the absolute clock, including
	// partial headers. This also covers custom RoundTrippers with read-ahead.
	m.budget.start()
	dst = dst[:cap(dst)]
	n, err := io.ReadFull(reader, dst)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return dst[:n], nil
	}
	if err != nil {
		return nil, ordered.ErrIO
	}
	var extra [1]byte
	n, err = io.ReadFull(reader, extra[:])
	if n != 0 || err != io.EOF {
		return nil, ordered.ErrProtocol
	}
	return dst, nil
}

func (m *messageIO) WriteMessage(ctx context.Context, msg []byte) error {
	if err := m.conn.Write(ctx, ws.MessageBinary, msg); err != nil {
		return ordered.ErrIO
	}
	return nil
}

// Ping uses WebSocket control frames, never SC1 application data. A concurrent
// Recv must be active so the library can process the matching pong.
func (m *messageIO) Ping(ctx context.Context) error {
	if err := m.conn.Ping(ctx); err != nil {
		return ordered.ErrIO
	}
	return nil
}
