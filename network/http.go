package network

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

type HTTPServerConfig = syntrahttp.ServerConfig

type HTTPListenerStatus struct {
	Revision         uint64
	Paused           bool
	NetworkAvailable bool
	Stopping         bool
	Stopped          bool
	Callbacks        int
	WaitingAdmission int
	Admitted         int
	LastFailure      Failure
	Server           syntrahttp.ServerStatus
}

// HTTPListener retains the complete association server and every owned callback
// through actual completion, including after a bounded shutdown wait returns.
type HTTPListener struct {
	network                       *Network
	server                        *syntrahttp.Server
	mu                            sync.Mutex
	paused, online, stopped       bool
	networkPaused, networkOffline bool
	revision                      uint64
	status                        HTTPListenerStatus
	ctx                           context.Context
	cancel                        context.CancelFunc
	epoch                         context.Context
	cancelEpoch                   context.CancelFunc
	wake                          chan struct{}
	done                          chan struct{}
	callbacks                     sync.WaitGroup
	hosts                         map[*syntra.Host]struct{}
}

func (n *Network) ListenHTTP(cfg syntrahttp.ServerConfig) (*HTTPListener, error) {
	return n.listenHTTP(cfg, securechannel.HTTP)
}
func (n *Network) ListenHTTPS(cfg syntrahttp.ServerConfig) (*HTTPListener, error) {
	return n.listenHTTP(cfg, securechannel.HTTPS)
}

func (n *Network) listenHTTP(cfg syntrahttp.ServerConfig, carrier securechannel.Carrier) (*HTTPListener, error) {
	if cfg.Security.Carrier != carrier || !cfg.Security.AllowHTTPCandidate || carrier == securechannel.HTTP && cfg.TLS != nil || carrier == securechannel.HTTPS && cfg.TLS == nil || cfg.Host.ChannelPolicy == nil {
		return nil, ErrConfig
	}
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
	ctx, cancel := context.WithCancel(context.Background())
	l := &HTTPListener{network: n, online: true, ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), done: make(chan struct{}), hosts: make(map[*syntra.Host]struct{})}
	l.epoch, l.cancelEpoch = context.WithCancel(ctx)
	// Native bounds cover both streams and pre-association TLS/header workers.
	if cfg.Limits.Associations == 0 || cfg.Limits.Associations > n.cfg.MaxConnections {
		cfg.Limits.Associations = n.cfg.MaxConnections
	}
	if cfg.Limits.Handshakes == 0 || cfg.Limits.Handshakes > cfg.Limits.Associations {
		cfg.Limits.Handshakes = min(32, cfg.Limits.Associations)
	}
	if cfg.Limits.UnboundStreams == 0 {
		cfg.Limits.UnboundStreams = min(32, 2*n.cfg.MaxConnections)
	}
	if cfg.Limits.Sockets == 0 {
		cfg.Limits.Sockets = min(4096, 2*cfg.Limits.Associations+cfg.Limits.UnboundStreams)
	}
	cfg.Host = l.hostConfig(cfg.Host)
	cfg.Security = l.securityConfig(cfg.Security)
	if cfg.TLS != nil {
		cfg.TLS = httpTLSProvider{listener: l, provider: cfg.TLS}
	}
	admit := cfg.AdmitAssociation
	cfg.AdmitAssociation = func(ctx context.Context, budget *ordered.EstablishmentBudget) (func(), error) {
		l.mu.Lock()
		epoch := l.epoch
		l.mu.Unlock()
		attempt, cancel := budget.Context(ctx)
		stop := context.AfterFunc(epoch, cancel)
		defer stop()
		defer cancel()
		if epoch.Err() != nil {
			cancel()
		}
		release, err := l.admit(attempt, budget)
		if err != nil || admit == nil {
			return release, err
		}
		external, err := l.applicationAdmit(attempt, budget, admit)
		if err == nil && external == nil {
			err = ErrConfig
		}
		if err == nil {
			err = budget.Check()
		}
		if err == nil {
			err = attempt.Err()
		}
		var once sync.Once
		return func() {
			once.Do(func() {
				defer release()
				if external != nil {
					l.applicationRelease(external)
				}
			})
		}, err
	}
	server, err := syntrahttp.Bind(cfg)
	if err != nil {
		cancel()
		n.releaseCall()
		return nil, Sanitize(err)
	}
	l.server = server
	// No accepts can race initial parent registration or its pause/offline fence.
	server.Pause()
	n.mu.Lock()
	if n.stopped {
		n.mu.Unlock()
		cancel()
		_ = server.Close()
		_ = server.Wait(context.Background())
		n.releaseCall()
		return nil, ErrClosed
	}
	l.networkPaused = n.paused
	l.networkOffline = !n.online
	n.httpListeners[l] = struct{}{}
	n.eventLocked(Event{Kind: ListenerStarted, Address: l.LocalAddr().String()})
	n.changedLocked()
	n.mu.Unlock()
	go l.run()
	go func() { <-l.Done(); n.signal() }()
	return l, nil
}

func (l *HTTPListener) LocalAddr() net.Addr   { return l.server.Addr() }
func (l *HTTPListener) Done() <-chan struct{} { return l.done }
func (l *HTTPListener) Snapshot() HTTPListenerStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.status
	s.Revision = l.revision
	s.Paused = l.paused || l.networkPaused
	s.NetworkAvailable = l.online && !l.networkOffline
	s.Stopping = l.stopped
	s.Server = l.server.Status()
	return s
}
func (l *HTTPListener) control(update func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.stopped {
		return
	}
	update()
	l.cancelEpoch()
	l.epoch, l.cancelEpoch = context.WithCancel(l.ctx)
	l.revision++
	if l.stopped {
		l.cancel()
	}
	select {
	case l.wake <- struct{}{}:
	default:
	}
	l.network.signal()
}
func (l *HTTPListener) Pause()                          { l.control(func() { l.paused = true }) }
func (l *HTTPListener) Resume()                         { l.control(func() { l.paused = false }) }
func (l *HTTPListener) NetworkAvailable(available bool) { l.control(func() { l.online = available }) }
func (l *HTTPListener) PlatformWake()                   { l.control(func() {}) }
func (l *HTTPListener) Stop()                           { l.control(func() { l.stopped = true }) }
func (l *HTTPListener) applyNetwork(paused, online, stopped bool) {
	l.control(func() { l.networkPaused = paused; l.networkOffline = !online; l.stopped = stopped })
}
func (l *HTTPListener) CloseContext(ctx context.Context) error {
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
func (l *HTTPListener) Close() error                   { return l.CloseContext(context.Background()) }
func (l *HTTPListener) NotifyAll(payload []byte) error { return l.notify("", payload) }
func (l *HTTPListener) NotifyDirected(principal string, payload []byte) error {
	return l.notify(principal, payload)
}
func (l *HTTPListener) notify(principal string, payload []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.allowedLocked() {
		return ErrClosed
	}
	var errs []error
	for _, host := range l.server.Hosts() {
		var err error
		if principal == "" {
			err = host.NotifyAll(payload)
		} else {
			err = host.NotifyDirected(principal, payload)
		}
		if err != nil {
			errs = append(errs, Sanitize(err))
		}
	}
	return errors.Join(errs...)
}
func (l *HTTPListener) allowedLocked() bool {
	return !l.stopped && !l.paused && !l.networkPaused && l.online && !l.networkOffline
}

func (l *HTTPListener) admit(ctx context.Context, budget *ordered.EstablishmentBudget) (func(), error) {
	l.mu.Lock()
	if !l.allowedLocked() {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	revision, epoch := l.revision, l.epoch
	l.status.WaitingAdmission++
	l.mu.Unlock()
	l.network.signal()
	attempt, cancel := budget.Context(ctx)
	stop := context.AfterFunc(epoch, cancel)
	if epoch.Err() != nil {
		cancel()
	}
	release, err := l.network.admission.acquire(attempt)
	if err == nil {
		err = budget.Check()
	}
	stop()
	cancel()
	l.mu.Lock()
	l.status.WaitingAdmission--
	if err == nil && (l.revision != revision || !l.allowedLocked()) {
		err = ErrClosed
	}
	if err != nil {
		l.mu.Unlock()
		if release != nil {
			release()
		}
		l.network.signal()
		return nil, err
	}
	l.status.Admitted++
	l.mu.Unlock()
	l.network.event(Event{Kind: ConnectionAdmitted, Address: l.LocalAddr().String()})
	l.network.signal()
	var once sync.Once
	return func() {
		once.Do(func() {
			release()
			l.mu.Lock()
			l.status.Admitted--
			l.mu.Unlock()
			l.network.event(Event{Kind: ConnectionCompleted, Address: l.LocalAddr().String()})
			l.network.signal()
		})
	}, nil
}

func (l *HTTPListener) run() {
	result := make(chan error, 1)
	go func() { result <- l.server.Run(l.ctx) }()
	defer func() {
		l.Stop()
		_ = l.server.Close()
		_ = l.server.Wait(context.Background())
		l.callbacks.Wait()
		l.mu.Lock()
		hosts := make([]*syntra.Host, 0, len(l.hosts))
		for host := range l.hosts {
			hosts = append(hosts, host)
		}
		l.mu.Unlock()
		for _, host := range hosts {
			_ = host.Close()
			_ = host.Wait(context.Background())
		}
		l.mu.Lock()
		l.status.Stopped = true
		close(l.done)
		l.mu.Unlock()
	}()
	var applied uint64
	initial := true
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		l.mu.Lock()
		revision, allowed, stopped := l.revision, l.allowedLocked(), l.stopped
		l.mu.Unlock()
		if stopped {
			<-result
			return
		}
		if initial || revision != applied {
			// Every lifecycle revision retires both old streams before resuming.
			if !initial {
				l.server.Pause()
			}
			if allowed {
				l.server.Resume()
			} else if initial {
				l.server.Pause()
			}
			initial = false
			applied = revision
			l.network.signal()
		}
		select {
		case err := <-result:
			if err != nil {
				l.mu.Lock()
				l.status.LastFailure = Classify(err)
				l.mu.Unlock()
				l.network.failed.Add(1)
			}
			return
		case <-l.wake:
		case <-l.ctx.Done():
		case <-tick.C:
			l.observeHosts()
		}
	}
}

func (l *HTTPListener) observeHosts() {
	hosts := l.server.Hosts()
	l.mu.Lock()
	defer l.mu.Unlock()
	for host := range l.hosts {
		select {
		case <-host.Done():
			delete(l.hosts, host)
		default:
		}
	}
	for _, host := range hosts {
		l.hosts[host] = struct{}{}
	}
}

func (l *HTTPListener) begin(ctx context.Context) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ctx.Err() != nil || !l.allowedLocked() || !l.network.reserveCallback() {
		return false
	}
	l.callbacks.Add(1)
	l.status.Callbacks++
	return true
}
func (l *HTTPListener) end() {
	l.mu.Lock()
	l.status.Callbacks--
	l.mu.Unlock()
	l.network.releaseCallback()
	l.callbacks.Done()
}

func (l *HTTPListener) applicationAdmit(ctx context.Context, budget *ordered.EstablishmentBudget, admit func(context.Context, *ordered.EstablishmentBudget) (func(), error)) (release func(), err error) {
	if !l.begin(ctx) {
		return nil, ErrBusy
	}
	defer l.end()
	defer func() {
		if recover() != nil {
			err = FailureRuntime
		}
	}()
	return admit(context.WithValue(ctx, callbackOwnerKey{}, l.network), budget)
}

func (l *HTTPListener) applicationRelease(release func()) {
	// The native association's bounded worker owns this wait and cannot finish
	// until release returns. Cleanup is mandatory even after stop/cancellation;
	// unlike ordinary admission, a full callback quota must not discard it.
	for {
		l.mu.Lock()
		if l.network.reserveCallback() {
			l.callbacks.Add(1)
			l.status.Callbacks++
			l.mu.Unlock()
			break
		}
		l.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	defer l.end()
	defer func() {
		if recover() != nil {
			l.network.failed.Add(1)
		}
	}()
	release()
}
func (l *HTTPListener) hostConfig(cfg syntra.HostConfig) syntra.HostConfig {
	cfg.ExecutionBudget = l.network.executions
	policy := cfg.ChannelPolicy
	cfg.ChannelPolicy = func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
		if !l.begin(ctx) {
			return "", callbackRejected()
		}
		defer l.end()
		return policy(context.WithValue(ctx, callbackOwnerKey{}, l.network), id, credential)
	}
	{
		authorize := cfg.Authorize
		if authorize == nil {
			authorize = syntra.DenyAllAuthorize
		}
		cfg.Authorize = func(ctx context.Context, principal, method string) error {
			if !l.begin(ctx) {
				return callbackRejected()
			}
			defer l.end()
			// Recovery source work can outlive Serve. Capture its owning Host
			// synchronously before authorizing any RPC which can start that work.
			l.observeHosts()
			return authorize(context.WithValue(ctx, callbackOwnerKey{}, l.network), principal, method)
		}
	}
	if handler := cfg.Handler; handler != nil {
		cfg.Handler = func(ctx context.Context, request *syntra.RpcRequest) (*syntra.RpcResult, error) {
			if !l.begin(ctx) {
				return nil, callbackRejected()
			}
			defer l.end()
			return handler(context.WithValue(ctx, callbackOwnerKey{}, l.network), request)
		}
	}
	return cfg
}
func (l *HTTPListener) securityConfig(cfg securechannel.ServerConfig) securechannel.ServerConfig {
	if lookup := cfg.Lookup; lookup != nil {
		cfg.Lookup = func(ctx context.Context, peer securechannel.Context) (securechannel.Enrollment, error) {
			if !l.begin(ctx) {
				return securechannel.Enrollment{}, securechannel.ErrAuth
			}
			defer l.end()
			return lookup(context.WithValue(ctx, callbackOwnerKey{}, l.network), peer)
		}
	}
	if lookup := cfg.LookupKey; lookup != nil {
		cfg.LookupKey = func(ctx context.Context, peer securechannel.Context) (securechannel.Key, error) {
			if !l.begin(ctx) {
				return securechannel.Key{}, securechannel.ErrAuth
			}
			defer l.end()
			return lookup(context.WithValue(ctx, callbackOwnerKey{}, l.network), peer)
		}
	}
	if authorize := cfg.Authorize; authorize != nil {
		cfg.Authorize = func(ctx context.Context, id securechannel.VerifiedIdentity) error {
			if !l.begin(ctx) {
				return securechannel.ErrAuth
			}
			defer l.end()
			return authorize(context.WithValue(ctx, callbackOwnerKey{}, l.network), id)
		}
	}
	return cfg
}

type httpTLSProvider struct {
	listener *HTTPListener
	provider tlsstream.Provider
}

func (p httpTLSProvider) Connect(context.Context, net.Conn, tlsstream.Authority) (tlsstream.Result, error) {
	return tlsstream.Result{}, ErrConfig
}
func (p httpTLSProvider) Accept(ctx context.Context, raw net.Conn, authority tlsstream.Authority) (tlsstream.Result, error) {
	if !p.listener.begin(ctx) {
		return tlsstream.Result{}, callbackRejected()
	}
	defer p.listener.end()
	return p.provider.Accept(context.WithValue(ctx, callbackOwnerKey{}, p.listener.network), raw, authority)
}
