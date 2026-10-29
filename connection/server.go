package connection

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	ws "github.com/tinkle-org/syntra-go/transport/websocket"
)

// ServerOptions controls shared admission and shutdown, plus adapter limits.
// A Server's channel carrier is fixed at construction; use separate Servers
// for TCP, WS, and WSS. Zero selects the documented defaults.
type ServerOptions struct {
	MaxConnections  int           // default 128, maximum 4096; includes handshakes
	MaxHandshakes   int           // default 16, maximum 256; includes core hello/policy
	ShutdownTimeout time.Duration // default 5s, may be shortened, maximum 5s
	TCP             ordered.Options
	WebSocket       ws.Options // includes OriginPatterns for the HTTP upgrade
}

// Server owns the Host, listeners passed to ServeTCP, and admitted connections,
// including raw sockets in SC1 handshakes. It is safe for concurrent use.
// Construct with NewServer; do not copy it or replace Host. Host is exposed for
// NotifyAll/DisconnectPrincipal; shut down through Server.Close to also release
// listeners and pre-handshake sockets. Host callbacks must honor their contexts.
type Server struct {
	Host          *syntra.Host
	channel       securechannel.ServerConfig
	opts          ServerOptions
	ctx           context.Context
	cancel        context.CancelFunc
	once          sync.Once
	mu            sync.Mutex
	closed        bool
	handshakes    int
	conns         map[*serverConn]struct{}
	listeners     map[net.Listener]struct{}
	drained       chan struct{}
	drainedClosed bool
	done          chan struct{}
	err           error
}

type serverConn struct {
	s           *Server
	raw         net.Conn // registered before SC1, including immediately on WS hijack
	transport   syntra.Transport
	handshaking bool
}

// NewServer validates configuration and builds the owned Host. ChannelPolicy is
// required: channel authentication never implicitly enables anonymous RPCs.
// Channel enrollment lookup and lifecycle rechecks use channelcfg unchanged.
// The server lives until Close or a ServeTCP context ends. For WebSocket-only
// servers the caller must explicitly Close it.
func NewServer(hostcfg syntra.HostConfig, channelcfg securechannel.ServerConfig, opts ServerOptions) (*Server, error) {
	if hostcfg.ChannelPolicy == nil || channelcfg.Validate() != nil {
		return nil, ErrConfig
	}
	if opts.MaxConnections == 0 {
		opts.MaxConnections = 128
	}
	if opts.MaxHandshakes == 0 {
		opts.MaxHandshakes = 16
	}
	if opts.ShutdownTimeout == 0 {
		opts.ShutdownTimeout = ShutdownTimeout
	}
	if opts.MaxConnections < 1 || opts.MaxConnections > 4096 || opts.MaxHandshakes < 1 || opts.MaxHandshakes > 256 || opts.ShutdownTimeout < 0 || opts.ShutdownTimeout > ShutdownTimeout {
		return nil, ErrConfig
	}
	var err error
	if channelcfg.Carrier == securechannel.TCP {
		opts.TCP, err = opts.TCP.Normalize()
	} else {
		opts.WebSocket.Limits, err = opts.WebSocket.Limits.Normalize()
		opts.WebSocket.OriginPatterns = append([]string(nil), opts.WebSocket.OriginPatterns...)
	}
	if err != nil {
		return nil, err
	}
	host, err := syntra.OpenHost(hostcfg)
	if err != nil {
		return nil, publicError(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{Host: host, channel: channelcfg, opts: opts, ctx: ctx, cancel: cancel,
		conns: make(map[*serverConn]struct{}), listeners: make(map[net.Listener]struct{}),
		drained: make(chan struct{}), done: make(chan struct{})}, nil
}

// ServeTCP takes ownership of listener. Admission is checked before starting a
// connection goroutine; excess sockets are immediately closed. Canceling ctx,
// Close, or a listener error stops this server and joins its connections within
// the configured shutdown budget. A custom listener may supply any net.Conn;
// its I/O and Close must obey the net package's cancellation/deadline contract.
func (s *Server) ServeTCP(ctx context.Context, listener net.Listener) (err error) {
	if listener == nil {
		return ErrConfig
	}
	if s.channel.Carrier != securechannel.TCP {
		_ = listener.Close()
		return ErrConfig
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		_ = listener.Close()
		return ErrClosed
	}
	if _, exists := s.listeners[listener]; exists {
		s.mu.Unlock()
		return ErrConfig
	}
	s.listeners[listener] = struct{}{}
	s.mu.Unlock()
	stop := context.AfterFunc(ctx, s.initiateClose)
	defer stop()
	defer func() {
		_ = listener.Close()
		// Signal completion before joining, so shutdown never waits on itself.
		s.mu.Lock()
		delete(s.listeners, listener)
		s.checkDrainedLocked()
		s.mu.Unlock()
		if closeErr := s.Close(); closeErr != nil && (err == nil || err == context.Canceled) {
			err = closeErr
		}
	}()
	if ctx.Err() != nil {
		s.initiateClose()
		return ctx.Err()
	}
	backoff := 5 * time.Millisecond
	const maxBackoff = time.Second
	for {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if s.ctx.Err() != nil {
				return nil
			}
			if errors.Is(acceptErr, net.ErrClosed) {
				return nil
			}
			if !isTemporaryAcceptError(acceptErr) {
				return ordered.ErrIO
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-s.ctx.Done():
				return nil
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = 5 * time.Millisecond
		entry := s.admit(raw)
		if entry == nil {
			_ = raw.Close()
			continue
		}
		go func() {
			defer entry.release()
			t, handshakeErr := tcp.Server(s.ctx, raw, s.channel, s.opts.TCP)
			if handshakeErr == nil {
				entry.serve(t)
			}
		}()
	}
}

// isTemporaryAcceptError reports whether an Accept error is transient and
// worth retrying with backoff. It recognizes timeouts and temporary network
// errors as well as transient syscall resource conditions.
func isTemporaryAcceptError(err error) bool {
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() || ne.Temporary() {
			return true
		}
	}
	if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.ENOMEM) ||
		errors.Is(err, syscall.EAGAIN) {
		return true
	}
	return false
}

// WebSocketHandler returns a WS/WSS handler with shared connection/handshake
// admission and the configured OriginPatterns. After upgrade the server's
// lifecycle, NOT r.Context(), owns Host.Serve. The handler remains until that
// connection is joined. The caller owns http.Server: configure ReadHeaderTimeout,
// MaxHeaderBytes and TLS there, and call Server.Close as well as HTTP shutdown
// (net/http does not shut down hijacked WebSockets).
func (s *Server) WebSocketHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.channel.Carrier != securechannel.WS && s.channel.Carrier != securechannel.WSS {
			http.Error(w, "invalid carrier", http.StatusBadRequest)
			return
		}
		entry := s.admit(nil)
		if entry == nil {
			http.Error(w, "connection admission unavailable", http.StatusServiceUnavailable)
			return
		}
		defer entry.release()
		t, err := ws.Accept(s.ctx, &trackingWriter{ResponseWriter: w, entry: entry}, r, s.channel, s.opts.WebSocket)
		if err == nil {
			entry.serve(t)
		}
	})
}

func (s *Server) admit(raw net.Conn) *serverConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(s.conns) >= s.opts.MaxConnections || s.handshakes >= s.opts.MaxHandshakes {
		return nil
	}
	e := &serverConn{s: s, raw: raw, handshaking: true}
	s.conns[e] = struct{}{}
	s.handshakes++
	return e
}

func (e *serverConn) finishHandshake() {
	e.s.mu.Lock()
	if e.handshaking {
		e.handshaking = false
		e.s.handshakes--
	}
	e.s.mu.Unlock()
}

func (e *serverConn) serve(t syntra.Transport) {
	e.s.mu.Lock()
	closed := e.s.closed
	if !closed {
		e.transport = t
	}
	e.s.mu.Unlock()
	if closed {
		_ = t.Close()
		return
	}
	_ = e.s.Host.Serve(e.s.ctx, &readyTransport{Transport: t, ready: e.finishHandshake})
}

func (e *serverConn) release() {
	e.s.mu.Lock()
	raw, transport := e.raw, e.transport
	e.s.mu.Unlock()
	if raw != nil {
		_ = raw.Close()
	}
	if transport != nil {
		_ = transport.Close()
	}
	e.s.mu.Lock()
	if e.handshaking {
		e.s.handshakes--
	}
	delete(e.s.conns, e)
	e.s.checkDrainedLocked()
	e.s.mu.Unlock()
}

// The Host's first successful Send is ServerReady. Keep handshake admission
// through policy and the ready write, without changing core session internals.
type readyTransport struct {
	syntra.Transport
	ready func()
	once  sync.Once
}

func (t *readyTransport) Send(ctx context.Context, frame []byte) error {
	err := t.Transport.Send(ctx, frame)
	if err == nil {
		t.once.Do(t.ready)
	}
	return err
}

func (t *readyTransport) ChannelIdentity() (syntra.ChannelIdentity, bool) {
	if p, ok := t.Transport.(syntra.ChannelIdentityProvider); ok {
		return p.ChannelIdentity()
	}
	return syntra.ChannelIdentity{}, false
}

type trackingWriter struct {
	http.ResponseWriter
	entry *serverConn
}

func (w *trackingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	w.entry.s.mu.Lock()
	closed := w.entry.s.closed
	if !closed {
		w.entry.raw = conn
	}
	w.entry.s.mu.Unlock()
	if closed {
		_ = conn.Close()
		return nil, nil, net.ErrClosed
	}
	return conn, rw, nil
}

func (s *Server) checkDrainedLocked() {
	if s.closed && !s.drainedClosed && len(s.conns) == 0 && len(s.listeners) == 0 {
		s.drainedClosed = true
		close(s.drained)
	}
}

func (s *Server) initiateClose() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		// Snapshot resources under the lock; no socket or adapter I/O under it.
		var closers []func()
		for listener := range s.listeners {
			closers = append(closers, func() { _ = listener.Close() })
		}
		for e := range s.conns {
			raw, transport := e.raw, e.transport
			closers = append(closers, func() {
				if raw != nil {
					_ = raw.Close()
				}
				if transport != nil {
					_ = transport.Close()
				}
			})
		}
		closers = append(closers, func() { _ = s.Host.Close() })
		s.checkDrainedLocked()
		s.mu.Unlock()
		go s.shutdown(closers)
	})
}

func (s *Server) shutdown(closers []func()) {
	defer close(s.done)
	timer := time.NewTimer(s.opts.ShutdownTimeout)
	defer timer.Stop()
	finished := make(chan struct{}, len(closers))
	// Fan out within the admitted bound: one slow callback/adapter cannot
	// postpone closing any other socket. No unbounded WaitGroup waiter.
	for _, closeResource := range closers {
		go func() { closeResource(); finished <- struct{}{} }()
	}
	drained := s.drained
	for pending := len(closers); pending > 0 || drained != nil; {
		select {
		case <-finished:
			pending--
		case <-drained:
			drained = nil
		case <-timer.C:
			s.mu.Lock()
			s.err = ErrShutdownTimeout
			s.mu.Unlock()
			return
		}
	}
}

// Close synchronously stops admission, cancels the lifecycle, closes listeners,
// raw sockets and active adapters, wakes Host.Serve, and joins within the budget.
// It is idempotent. Callbacks and external net.Conns must honor cancellation;
// ErrShutdownTimeout reports an incomplete join. Done closes on either outcome.
func (s *Server) Close() error {
	s.initiateClose()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Done closes when the bounded shutdown has completed, including on timeout.
func (s *Server) Done() <-chan struct{} { return s.done }
