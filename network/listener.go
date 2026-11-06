// File listener.go owns managed stream listeners, admission and session teardown.
package network

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
	"github.com/tinkle-org/syntra-go/transport/websocket"
)

// ListenerConfig owns the bound listener, fresh per-connection hosts, and all
// setup/callback work. A supplied Listener transfers ownership on success only.
// Admission optionally adds a bound shared with listeners on other Networks.
// The Network-wide admission bound always applies as well.
type ListenerConfig struct {
	Address        string
	Listener       net.Listener
	MaxConnections int
	Admission      *Admission
	Security       securechannel.ServerConfig
	Host           syntra.HostConfig
	Options        ordered.Options
	TLS            TLSProvider
	Authority      TLSAuthority
}
type TCPServerConfig = ListenerConfig
type WebSocketServerConfig = ListenerConfig

type ListenerStatus struct {
	Paused           bool
	NetworkAvailable bool
	Stopping         bool
	Stopped          bool
	WaitingAdmission int
	Admitted         int
	Callbacks        int
	Completed        uint64
	Rejected         uint64
	LastFailure      Failure
}

// Listener's address and snapshots are immutable values. Notification methods
// are fenced by listener controls and never enqueue into a future connection.
type Listener struct {
	network                       *Network
	cfg                           ListenerConfig
	kind                          securechannel.Carrier
	socket                        net.Listener
	address                       net.Addr
	mu                            sync.Mutex
	paused, online, stopped       bool
	networkPaused, networkOffline bool
	epoch                         context.Context
	cancelEpoch                   context.CancelFunc
	ctx                           context.Context
	cancel                        context.CancelFunc
	wake                          chan struct{}
	done                          chan struct{}
	status                        ListenerStatus
	sessions                      map[*serverSession]struct{}
	workers                       sync.WaitGroup
	local                         chan struct{}
}

func (n *Network) ListenTCP(cfg ListenerConfig) (*Listener, error) {
	return n.listen(cfg, securechannel.TCP)
}
func (n *Network) ListenWS(cfg ListenerConfig) (*Listener, error) {
	return n.listen(cfg, securechannel.WS)
}
func (n *Network) ListenWSS(cfg ListenerConfig) (*Listener, error) {
	return n.listen(cfg, securechannel.WSS)
}

func (n *Network) listen(cfg ListenerConfig, kind securechannel.Carrier) (*Listener, error) {
	if cfg.MaxConnections < 1 || cfg.MaxConnections > 4096 || cfg.Options.Budget != nil || cfg.Security.Carrier != kind || cfg.Security.Validate() != nil || cfg.Host.ChannelPolicy == nil {
		return nil, ErrConfig
	}
	if kind == securechannel.WSS {
		if cfg.TLS == nil || cfg.Authority.Host() == "" || cfg.Authority.Port() == 0 {
			return nil, ErrConfig
		}
	} else if cfg.TLS != nil {
		return nil, ErrConfig
	}
	opts, err := cfg.Options.Normalize()
	if err != nil {
		return nil, Sanitize(err)
	}
	cfg.Options = opts
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		return nil, ErrClosed
	}
	if !n.reserveCall() {
		n.mu.Unlock()
		return nil, ErrBusy
	}
	n.mu.Unlock()
	socket := cfg.Listener
	if socket == nil {
		bind, stop := context.WithTimeout(n.ctx, opts.AttemptTimeout)
		socket, err = (&net.ListenConfig{}).Listen(bind, "tcp", cfg.Address)
		stop()
		if err != nil {
			n.releaseCall()
			return nil, Sanitize(err)
		}
	}
	if kind == securechannel.WS && !loopbackAddress(socket.Addr()) {
		if cfg.Listener == nil {
			_ = socket.Close()
		}
		n.releaseCall()
		return nil, ErrConfig
	}
	ctx, cancel := context.WithCancel(context.Background())
	epoch, ce := context.WithCancel(ctx)
	l := &Listener{network: n, cfg: cfg, kind: kind, socket: socket, address: socket.Addr(), online: true,
		ctx: ctx, cancel: cancel, epoch: epoch, cancelEpoch: ce, wake: make(chan struct{}, 1), done: make(chan struct{}), sessions: make(map[*serverSession]struct{}), local: make(chan struct{}, cfg.MaxConnections)}
	// Validate runtime settings before listener ownership escapes.
	validation := l.hostConfig(nil)
	host, e := syntra.OpenHost(validation)
	if e != nil {
		cancel()
		if cfg.Listener == nil {
			_ = socket.Close()
		}
		n.releaseCall()
		return nil, Sanitize(e)
	}
	_ = host.Close()
	_ = host.Wait(context.Background())
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.stopped {
		cancel()
		if cfg.Listener == nil {
			_ = socket.Close()
		}
		n.releaseCall()
		return nil, ErrClosed
	}
	l.networkPaused = n.paused
	l.networkOffline = !n.online
	n.listeners[l] = struct{}{}
	n.eventLocked(Event{Kind: ListenerStarted, Address: l.LocalAddr().String()})
	n.changedLocked()
	go l.run()
	go func() { <-l.Done(); n.signal() }()
	return l, nil
}
func loopbackAddress(addr net.Addr) bool {
	if addr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(addr.String())
	return err == nil && net.ParseIP(host).IsLoopback()
}
func (l *Listener) LocalAddr() net.Addr   { return l.address }
func (l *Listener) Done() <-chan struct{} { return l.done }
func (l *Listener) Snapshot() ListenerStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.status
	s.Paused = l.paused || l.networkPaused
	s.NetworkAvailable = l.online && !l.networkOffline
	s.Stopping = l.stopped
	return s
}
func (l *Listener) control(update func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		return
	}
	update()
	l.cancelEpoch()
	for s := range l.sessions {
		s.clock.Invalidate()
	}
	l.epoch, l.cancelEpoch = context.WithCancel(l.ctx)
	if l.stopped {
		l.cancel()
	}
	select {
	case l.wake <- struct{}{}:
	default:
	}
}
func (l *Listener) Pause()                          { l.control(func() { l.paused = true }) }
func (l *Listener) Resume()                         { l.control(func() { l.paused = false }) }
func (l *Listener) NetworkAvailable(available bool) { l.control(func() { l.online = available }) }
func (l *Listener) PlatformWake()                   { l.control(func() {}) }
func (l *Listener) Stop()                           { l.control(func() { l.stopped = true }) }
func (l *Listener) applyNetwork(paused, online, stopped bool) {
	l.control(func() { l.networkPaused = paused; l.networkOffline = !online; l.stopped = stopped })
}
func (l *Listener) CloseContext(ctx context.Context) error {
	l.Stop()
	timer := time.NewTimer(l.network.cfg.CloseTimeout)
	defer timer.Stop()
	select {
	case <-l.done:
		return nil
	default:
	}
	select {
	case <-l.done:
		return nil
	case <-ctx.Done():
		return ErrShutdownIncomplete
	case <-timer.C:
		return ErrShutdownIncomplete
	}
}
func (l *Listener) Close() error                   { return l.CloseContext(context.Background()) }
func (l *Listener) NotifyAll(payload []byte) error { return l.notify("", payload) }
func (l *Listener) NotifyDirected(principal string, payload []byte) error {
	return l.notify(principal, payload)
}
func (l *Listener) notify(principal string, payload []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped || l.paused || l.networkPaused || !l.online || l.networkOffline {
		return ErrClosed
	}
	var errs []error
	for s := range l.sessions {
		if s.host == nil || s.principal == "" || s.ctx.Err() != nil {
			continue
		}
		if principal != "" && principal != s.principal {
			continue
		}
		// Each host belongs to one session. Directed delivery only finds its
		// connection after authentication has activated the core and bound the
		// principal, even if the policy callback has only just returned.
		if err := s.host.NotifyDirected(s.principal, payload); err != nil {
			errs = append(errs, Sanitize(err))
		}
	}
	return errors.Join(errs...)
}

// run owns socket acceptance and FIFO admission through each session's joined
// teardown, publishing waiters only after their shared admission position exists.
func (l *Listener) run() {
	failed := false
	closed := make(chan struct{})
	stopClose := context.AfterFunc(l.ctx, func() { _ = l.socket.Close(); close(closed) })
	defer func() {
		l.Stop()
		if stopClose() {
			_ = l.socket.Close()
		} else {
			<-closed
		}
		l.workers.Wait()
		if failed {
			l.network.recordFailure()
		}
		l.mu.Lock()
		l.status.Stopped = true
		close(l.done)
		l.mu.Unlock()
	}()
	var retryNotBefore time.Time
	for {
		l.mu.Lock()
		epoch := l.epoch
		stopped := l.stopped
		allowed := !l.paused && !l.networkPaused && l.online && !l.networkOffline
		l.mu.Unlock()
		if stopped {
			return
		}
		if !allowed {
			select {
			case <-l.wake:
			case <-l.ctx.Done():
			}
			continue
		}
		if delay := time.Until(retryNotBefore); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-l.wake:
			case <-l.ctx.Done():
			}
			timer.Stop()
			// Controls can interrupt this wait, but never renew or erase its cutoff.
			continue
		}
		select {
		case l.local <- struct{}{}:
		case <-epoch.Done():
			continue
		}
		if epoch.Err() != nil {
			<-l.local
			continue
		}
		conn, acceptErr := l.acceptSocket()
		if acceptErr != nil {
			<-l.local
			if l.ctx.Err() != nil {
				return
			}
			l.mu.Lock()
			l.status.LastFailure = Classify(acceptErr)
			l.mu.Unlock()
			if acceptErr.retryable {
				retryNotBefore = time.Now().Add(100 * time.Millisecond)
				continue
			}
			failed = true
			return
		}
		if conn == nil {
			<-l.local
			continue
		}
		if epoch.Err() != nil {
			_ = conn.Close()
			<-l.local
			continue
		}
		clock := securechannel.NewClock()
		budget, err := ordered.NewEstablishmentBudget(clock, l.cfg.Options.AttemptTimeout)
		if err != nil {
			_ = conn.Close()
			<-l.local
			l.mu.Lock()
			l.status.LastFailure = Classify(err)
			l.mu.Unlock()
			failed = true
			return
		}
		attempt, cancel := budget.Context(epoch)
		waiting := false
		release, err := l.network.admission.acquireTracked(attempt, func() {
			l.mu.Lock()
			l.status.WaitingAdmission++
			waiting = true
			l.mu.Unlock()
		})
		var releaseExtra func()
		if err == nil && l.cfg.Admission != nil && l.cfg.Admission != l.network.admission {
			releaseExtra, err = l.cfg.Admission.acquire(attempt)
		}
		l.mu.Lock()
		if waiting {
			l.status.WaitingAdmission--
		}
		l.mu.Unlock()
		if err != nil || attempt.Err() != nil {
			terminal := err != nil && attempt.Err() == nil && epoch.Err() == nil
			if release != nil {
				release()
			}
			if releaseExtra != nil {
				releaseExtra()
			}
			cancel()
			_ = conn.Close()
			<-l.local
			if terminal && l.ctx.Err() == nil {
				l.mu.Lock()
				l.status.LastFailure = Classify(err)
				l.mu.Unlock()
				failed = true
				return
			}
			continue
		}
		// The establishment context bounds setup only; the epoch owns live use.
		sctx, scancel := context.WithCancel(epoch)
		s := &serverSession{listener: l, ctx: sctx, cancel: scancel, raw: conn, clock: clock, changed: make(chan struct{})}
		l.mu.Lock()
		if epoch.Err() != nil || l.stopped {
			l.mu.Unlock()
			scancel()
			cancel()
			release()
			if releaseExtra != nil {
				releaseExtra()
			}
			_ = conn.Close()
			<-l.local
			continue
		}
		l.sessions[s] = struct{}{}
		l.status.Admitted++
		l.mu.Unlock()
		l.network.event(Event{Kind: ConnectionAdmitted, Address: l.LocalAddr().String()})
		l.workers.Add(1)
		go func() {
			defer l.workers.Done()
			defer func() {
				release()
				if releaseExtra != nil {
					releaseExtra()
				}
				<-l.local
			}()
			defer func() {
				if recover() != nil {
					l.network.failed.Add(1)
					l.rejected(FailureRuntime)
				}
				cancel()
				l.mu.Lock()
				delete(l.sessions, s)
				l.status.Admitted--
				l.status.Completed++
				l.mu.Unlock()
				l.network.event(Event{Kind: ConnectionCompleted, Address: l.LocalAddr().String()})
			}()
			s.serve(attempt, budget)
		}()
	}
}

// acceptSocket owns any returned socket, including on a failed raw accept or
// accepted-socket setup. The caller releases local admission before retrying.
func (l *Listener) acceptSocket() (net.Conn, *acceptError) {
	conn, err := l.socket.Accept()
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, socketAcceptError(err)
	}
	if conn == nil {
		return nil, &acceptError{cause: ErrConfig}
	}
	if l.kind == securechannel.WS {
		if !loopbackAddress(l.socket.Addr()) {
			_ = conn.Close()
			return nil, &acceptError{cause: ErrConfig}
		}
		if !loopbackAddress(conn.RemoteAddr()) {
			_ = conn.Close()
			l.rejected(ErrConfig)
			return nil, nil
		}
	}
	if socket, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		if err := socket.SetNoDelay(true); err != nil {
			_ = conn.Close()
			return nil, &acceptError{cause: err, retryable: true}
		}
	}
	return conn, nil
}

type serverSession struct {
	listener  *Listener
	ctx       context.Context
	cancel    context.CancelFunc
	raw       net.Conn
	clock     *securechannel.Clock
	host      *syntra.Host // guarded by Listener.mu
	principal string       // guarded by Listener.mu; empty until policy acceptance
	mu        sync.Mutex
	callbacks int
	closed    bool
	changed   chan struct{}
}

func (s *serverSession) begin(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ctx.Err() != nil || s.ctx.Err() != nil {
		return false
	}
	n := s.listener.network
	if !n.reserveCallback() {
		return false
	}
	s.callbacks++
	s.listener.mu.Lock()
	s.listener.status.Callbacks++
	s.listener.mu.Unlock()
	return true
}
func (s *serverSession) end() {
	s.mu.Lock()
	s.callbacks--
	close(s.changed)
	s.changed = make(chan struct{})
	s.mu.Unlock()
	s.listener.mu.Lock()
	s.listener.status.Callbacks--
	s.listener.mu.Unlock()
	s.listener.network.releaseCallback()
}
func callbackRejected() error {
	return syntra.NewRpcError(syntra.ErrorCodeResourceExhausted, "network: callback unavailable")
}
func (l *Listener) hostConfig(s *serverSession) syntra.HostConfig {
	cfg := l.cfg.Host
	cfg.ExecutionBudget = l.network.executions
	if s == nil {
		return cfg
	}
	policy := cfg.ChannelPolicy
	cfg.ChannelPolicy = func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
		if !s.begin(ctx) {
			return "", callbackRejected()
		}
		defer s.end()
		principal, err := policy(context.WithValue(ctx, callbackOwnerKey{}, l.network), id, credential)
		if err == nil && principal != "" && ctx.Err() == nil {
			l.mu.Lock()
			if s.ctx.Err() == nil {
				s.principal = principal
			}
			l.mu.Unlock()
		}
		return principal, err
	}
	if authorize := cfg.Authorize; authorize != nil {
		cfg.Authorize = func(ctx context.Context, principal, method string) error {
			if !s.begin(ctx) {
				return callbackRejected()
			}
			defer s.end()
			return authorize(context.WithValue(ctx, callbackOwnerKey{}, l.network), principal, method)
		}
	}
	if handler := cfg.Handler; handler != nil {
		cfg.Handler = func(ctx context.Context, request *syntra.RpcRequest) (*syntra.RpcResult, error) {
			if !s.begin(ctx) {
				return nil, callbackRejected()
			}
			defer s.end()
			return handler(context.WithValue(ctx, callbackOwnerKey{}, l.network), request)
		}
	}
	return cfg
}
func (s *serverSession) serve(attempt context.Context, budget *ordered.EstablishmentBudget) {
	l := s.listener
	closed := make(chan struct{})
	stopClose := context.AfterFunc(s.ctx, func() { _ = s.raw.Close(); close(closed) })
	defer func() {
		s.cancel()
		if stopClose() {
			_ = s.raw.Close()
		} else {
			<-closed
		}
		s.mu.Lock()
		s.closed = true
		for s.callbacks != 0 {
			ch := s.changed
			s.mu.Unlock()
			<-ch
			s.mu.Lock()
		}
		s.mu.Unlock()
		l.mu.Lock()
		host := s.host
		s.host = nil
		l.mu.Unlock()
		if host != nil {
			_ = host.Close()
			_ = host.Wait(context.Background())
		}
	}()
	host, err := syntra.OpenHost(l.hostConfig(s))
	if err != nil {
		l.rejected(err)
		return
	}
	l.mu.Lock()
	s.host = host
	l.mu.Unlock()
	opts := l.cfg.Options
	opts.Budget = budget
	security := l.cfg.Security
	if lookup := security.Lookup; lookup != nil {
		security.Lookup = func(ctx context.Context, peer securechannel.Context) (securechannel.Enrollment, error) {
			if !s.begin(ctx) {
				return securechannel.Enrollment{}, securechannel.ErrAuth
			}
			defer s.end()
			return lookup(context.WithValue(ctx, callbackOwnerKey{}, l.network), peer)
		}
	}
	if lookup := security.LookupKey; lookup != nil {
		security.LookupKey = func(ctx context.Context, peer securechannel.Context) (securechannel.Key, error) {
			if !s.begin(ctx) {
				return securechannel.Key{}, securechannel.ErrAuth
			}
			defer s.end()
			return lookup(context.WithValue(ctx, callbackOwnerKey{}, l.network), peer)
		}
	}
	if authorize := security.Authorize; authorize != nil {
		security.Authorize = func(ctx context.Context, id securechannel.VerifiedIdentity) error {
			if !s.begin(ctx) {
				return securechannel.ErrAuth
			}
			defer s.end()
			return authorize(context.WithValue(ctx, callbackOwnerKey{}, l.network), id)
		}
	}
	switch l.kind {
	case securechannel.TCP:
		err = tcp.Accept(s.ctx, s.raw, security, host, opts)
	case securechannel.WS:
		err = websocket.Accept(s.ctx, s.raw, security, host, opts)
	case securechannel.WSS:
		var verified *tlsstream.Verified
		verified, err = tlsstream.Accept(attempt, s.raw, sessionTLSProvider{s}, l.cfg.Authority, budget)
		if err == nil {
			err = websocket.AcceptTLS(s.ctx, verified, l.cfg.Authority, security, host, opts)
		}
	}
	if err != nil && s.ctx.Err() == nil {
		l.rejected(err)
	}
}

type sessionTLSProvider struct{ s *serverSession }

func (p sessionTLSProvider) Connect(context.Context, net.Conn, TLSAuthority) (tlsstream.Result, error) {
	return tlsstream.Result{}, ErrConfig
}
func (p sessionTLSProvider) Accept(ctx context.Context, raw net.Conn, authority TLSAuthority) (tlsstream.Result, error) {
	if !p.s.begin(ctx) {
		return tlsstream.Result{}, callbackRejected()
	}
	defer p.s.end()
	return p.s.listener.cfg.TLS.Accept(context.WithValue(ctx, callbackOwnerKey{}, p.s.listener.network), raw, authority)
}
func (l *Listener) rejected(err error) {
	l.mu.Lock()
	l.status.Rejected++
	l.status.LastFailure = Classify(err)
	l.mu.Unlock()
}
