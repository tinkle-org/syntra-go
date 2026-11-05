package syntrahttp

import (
	"context"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

// MaxHostBufferBytes caps conservative carrier/runtime reservations across all
// servers in this process. TLS and application-private storage are additional.
const MaxHostBufferBytes int64 = 256 << 20

// Account for the raw header, parser string/slices/maps, a bounded M1 and
// admission metadata, rather than charging only the wire bytes in Go's heap.
const unboundBytes int64 = int64(4*MaxHeaders + 512*MaxFields + securechannel.MaxContext + securechannel.HandshakeSize)

// ServerLimits are finite admission limits, checked before large allocation or
// credential lookup. Zero fields select bounded defaults. Reserved bytes include
// selected and active records and conservative maximum-sized runtime frames.
// The aggregate byte limit can admit fewer associations than the item limit.
type ServerLimits struct {
	Associations          int
	Handshakes            int // pending Noise/Ready associations; TLS permits two socket handshakes per association, at most 32 process-wide
	UnboundStreams        int
	Sockets               int // admitted leases; the accept loop holds at most one additional socket before admission
	AggregateBytes        int64
	PrincipalAssociations int
	SourceEntries         int
	OpensPerSecond        int
	OpenBurst             int
	SourceOpensPerSecond  int
	SourceOpenBurst       int
}

func (l ServerLimits) normalize() (ServerLimits, error) {
	defaultHandshakes := l.Handshakes == 0
	for _, v := range []struct {
		p   *int
		def int
	}{{&l.Associations, 128}, {&l.Handshakes, 32}, {&l.UnboundStreams, 32}, {&l.Sockets, 288}, {&l.PrincipalAssociations, 16}, {&l.SourceEntries, 256}, {&l.OpensPerSecond, 64}, {&l.OpenBurst, 64}, {&l.SourceOpensPerSecond, 8}, {&l.SourceOpenBurst, 16}} {
		if *v.p == 0 {
			*v.p = v.def
		}
		if *v.p < 1 || *v.p > 65536 {
			return l, ordered.ErrOptions
		}
	}
	if defaultHandshakes {
		l.Handshakes = min(l.Handshakes, l.Associations)
	}
	if l.AggregateBytes == 0 {
		l.AggregateBytes = MaxHostBufferBytes
	}
	if l.AggregateBytes < 1 || l.AggregateBytes > MaxHostBufferBytes || l.Sockets < 2 || l.Handshakes > l.Associations {
		return l, ordered.ErrOptions
	}
	return l, nil
}

// ServerConfig provisions one explicit authority, listener and policy generation.
// Address must be a numeric IP:port (port zero is allowed for binding). Host must
// have an explicit ChannelPolicy. Its Authorize policy retains deny-all defaults.
// Security must explicitly opt in to HTTP/HTTPS. HTTPS requires TLS; HTTP forbids
// it. Options.Budget must be nil: each accepted attempt gets its own origin.
// Zero Host.MaxConcurrent and Host.WriterCapacity each select 16 for this carrier.
type ServerConfig struct {
	Address   string
	Authority Authority
	Security  securechannel.ServerConfig
	Host      syntra.HostConfig
	Origins   OriginPolicy
	TLS       tlsstream.Provider
	Options   ordered.Options
	Limits    ServerLimits
	// AdmitAssociation optionally acquires an embedding/shared admission lease.
	// It runs once for a validated open header, before M1 allocation, body reads
	// or credential lookup, outside server locks. ctx and Budget retain the
	// original accepted-stream attempt and cancellation. Honor ctx; do not rebase
	// or release Budget. A successful call must return a nonnil release function.
	// Any returned release function, including with an error, is called exactly
	// once after carrier cleanup, Host.Close/Wait and native reservation teardown.
	// Idle sockets and download attachment never invoke this hook.
	AdmitAssociation func(context.Context, *ordered.EstablishmentBudget) (func(), error)
}

// ServerStatus counts retained admission leases, rather than estimating RSS.
// Closed streams remain counted until their dispatch/association owner joins.
// ReservedBytes excludes application-owned recovery/TLS/provider allocations.
type ServerStatus struct {
	Associations   int
	Handshakes     int
	TLSHandshakes  int
	UnboundStreams int
	Sockets        int
	ReservedBytes  int64
	Completed      uint64
	Rejected       uint64
	Paused         bool
	Stopped        bool
}

type bucket struct {
	tokens float64
	at     time.Time
}

func (b bucket) full(now time.Time, rate, burst int) bool {
	return !now.Before(b.at) && b.tokens+now.Sub(b.at).Seconds()*float64(rate) >= float64(burst)
}
func (b *bucket) take(now time.Time, rate, burst int) bool {
	if now.Before(b.at) {
		return false
	}
	b.tokens = min(float64(burst), b.tokens+now.Sub(b.at).Seconds()*float64(rate))
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Process-wide reservations cannot be bypassed by binding additional listeners.
var hostAdmission = struct {
	sync.Mutex
	bytes                                  int64
	sockets, associations, handshakes, tls int
	principals                             map[string]int
}{principals: make(map[string]int)}

type associationOwner struct {
	pair       *serverPair
	host       *syntra.Host
	generation uint64
	principal  string
	handshake  bool
	callbacks  callbackGate
	download   *admittedConn
}

// A core timeout may abandon a non-cooperative callback. Its actual invocation
// retains this association's reservation until return. Sealing also fences a
// callback goroutine that was scheduled but has not entered application code.
type callbackGate struct {
	mu     sync.Mutex
	sealed bool
	wg     sync.WaitGroup
}

func (g *callbackGate) enter() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed {
		return false
	}
	g.wg.Add(1)
	return true
}
func (g *callbackGate) join() { g.mu.Lock(); g.sealed = true; g.mu.Unlock(); g.wg.Wait() }

// Server owns its listener, sockets, registry, hosts and cleanup workers. Bind
// constructs it; Run blocks in the caller, while Serve starts an owned Run.
// Pause retires current associations; Resume admits fresh connections only.
// Close is bounded, and Done/Wait retain the actual join after a timeout.
type Server struct {
	mu              sync.Mutex
	cfg             ServerConfig
	listener        net.Listener
	ctx             context.Context
	cancel          context.CancelFunc
	status          ServerStatus
	closed, running bool
	generation      uint64
	registry        map[Route]*associationOwner
	sockets         map[*admittedConn]struct{}
	sources         map[netip.Addr]bucket
	global          bucket
	reservation     int64
	wg              sync.WaitGroup
	stopOnce        sync.Once
	runDoneOnce     sync.Once
	runDone         chan struct{}
	done            chan struct{}
}

// Bind validates all configuration before binding a listener. No worker starts
// until Run or Serve; Close also works before Run.
func Bind(cfg ServerConfig) (*Server, error) {
	address, err := netip.ParseAddrPort(cfg.Address)
	if err != nil || !address.IsValid() || !cfg.Authority.valid() || cfg.Host.ChannelPolicy == nil || cfg.Options.Budget != nil || cfg.Security.Validate() != nil {
		return nil, securechannel.ErrConfig
	}
	if (cfg.Security.Carrier != securechannel.HTTP || cfg.TLS != nil) && (cfg.Security.Carrier != securechannel.HTTPS || cfg.TLS == nil) {
		return nil, securechannel.ErrConfig
	}
	cfg.Limits, err = cfg.Limits.normalize()
	if err != nil {
		return nil, err
	}
	cfg.Options, err = cfg.Options.Normalize()
	if err != nil {
		return nil, err
	}
	if cfg.Host.MaxConcurrent == 0 {
		cfg.Host.MaxConcurrent = 16
	}
	if cfg.Host.WriterCapacity == 0 {
		cfg.Host.WriterCapacity = 16
	}
	// Validate the runtime without retaining an extra live host.
	h, err := syntra.OpenHost(cfg.Host)
	if err != nil {
		return nil, securechannel.ErrConfig
	}
	_ = h.Close()
	_ = h.Wait(context.Background())
	frames := int64(3*cfg.Host.MaxConcurrent + 3*cfg.Host.WriterCapacity + 8)
	reservation := frames*ordered.MaxFrame + 8*MaxRecord + 2*MaxHeaders
	if reservation+int64(cfg.Limits.UnboundStreams)*unboundBytes > cfg.Limits.AggregateBytes {
		return nil, ordered.ErrOptions
	}
	l, err := net.Listen("tcp", address.String())
	if err != nil {
		return nil, stream.Error(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{cfg: cfg, listener: l, ctx: ctx, cancel: cancel, registry: make(map[Route]*associationOwner), sockets: make(map[*admittedConn]struct{}), sources: make(map[netip.Addr]bucket), global: bucket{float64(cfg.Limits.OpenBurst), time.Now()}, reservation: reservation, runDone: make(chan struct{}), done: make(chan struct{})}, nil
}

// Addr returns the actual bound socket address, including a selected port.
func (s *Server) Addr() net.Addr { return s.listener.Addr() }

// Status snapshots retained resources and current admission controls.
func (s *Server) Status() ServerStatus { s.mu.Lock(); defer s.mu.Unlock(); return s.status }

// Done closes after the accept loop, association workers and cleanup join.
func (s *Server) Done() <-chan struct{} { return s.done }

// Wait joins shutdown; canceling ctx stops only this waiter, retaining ownership.
func (s *Server) Wait(ctx context.Context) error {
	select {
	case <-s.done:
		return nil
	default:
	}
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *Server) start(parent context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.closed {
		return false
	}
	// Derive operation lifetimes directly from the run context, so cancellation
	// gates raw I/O even before the listener-close callback gets scheduled.
	s.cancel()
	s.ctx, s.cancel = context.WithCancel(parent)
	s.running = true
	return true
}

// Run owns one accept loop in the caller and returns after complete cleanup.
// Canceling ctx stops admission and all associations. Slow callbacks retain Run
// and their reservations; Close or Wait can independently bound a caller's wait.
func (s *Server) Run(ctx context.Context) error {
	if !s.start(ctx) {
		return ordered.ErrClosed
	}
	err := s.run(ctx)
	<-s.done
	return err
}

// Serve begins exactly one owned accept loop. Wait joins it and all its children.
func (s *Server) Serve(ctx context.Context) error {
	if !s.start(ctx) {
		return ordered.ErrClosed
	}
	go func() { _ = s.run(ctx) }()
	return nil
}
func (s *Server) run(ctx context.Context) error {
	stop := context.AfterFunc(ctx, s.initiateClose)
	defer stop()
	defer s.runDoneOnce.Do(func() { close(s.runDone) })
	defer s.initiateClose()
	for {
		c, err := s.listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return stream.Error(err)
		}
		owned := s.admitSocket(c)
		if owned == nil {
			_ = c.Close()
			continue
		}
		go func() { defer s.wg.Done(); s.dispatch(owned) }()
	}
}
func (s *Server) initiateClose() {
	s.stopOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		if !s.running {
			s.runDoneOnce.Do(func() { close(s.runDone) })
		}
		pairs, sockets := s.snapshotLocked()
		s.mu.Unlock()
		_ = s.listener.Close()
		go func() {
			// Interrupt every raw socket before joining provider-level Close.
			// This cleanup owner survives a bounded Close/Wait timeout.
			for _, c := range sockets {
				_ = c.Close()
			}
			for _, p := range pairs {
				_ = p.Close()
			}
			<-s.runDone
			s.wg.Wait()
			s.mu.Lock()
			s.status.Stopped = true
			s.mu.Unlock()
			close(s.done)
		}()
	})
}

// Close initiates terminal shutdown and joins for connection.ShutdownTimeout.
// A timeout retains the cleanup owner; Done/Wait observe its eventual completion.
func (s *Server) Close() error {
	s.initiateClose()
	ctx, stop := context.WithTimeout(context.Background(), connection.ShutdownTimeout)
	defer stop()
	if s.Wait(ctx) != nil {
		return connection.ErrShutdownTimeout
	}
	return nil
}
func (s *Server) snapshotLocked() ([]*serverPair, []*admittedConn) {
	var pairs []*serverPair
	var sockets []*admittedConn
	for _, a := range s.registry {
		pairs = append(pairs, a.pair)
	}
	for c := range s.sockets {
		sockets = append(sockets, c)
	}
	return pairs, sockets
}

// Pause fences admission and retires every current socket and association.
// It preserves the listener and its address. Resume cannot revive old streams.
func (s *Server) Pause() {
	s.mu.Lock()
	s.status.Paused = true
	s.generation++
	pairs, sockets := s.snapshotLocked()
	s.mu.Unlock()
	for _, c := range sockets {
		_ = c.Close()
	}
	for _, p := range pairs {
		_ = p.Close()
	}
}

// Resume permits fresh associations unless terminal shutdown has begun.
func (s *Server) Resume() {
	s.mu.Lock()
	if !s.closed {
		s.status.Paused = false
	}
	s.mu.Unlock()
}

// Hosts is a bounded snapshot for notifications. The server retains ownership.
func (s *Server) Hosts() []*syntra.Host {
	s.mu.Lock()
	defer s.mu.Unlock()
	var hosts []*syntra.Host
	for _, a := range s.registry {
		if a.host != nil && a.principal != "" {
			hosts = append(hosts, a.host)
		}
	}
	return hosts
}

// NotifyAll admits a notification to each authenticated host's bounded queue.
// Success means admission only; it does not attest to peer receipt.
func (s *Server) NotifyAll(payload []byte) error {
	var result error
	for _, h := range s.Hosts() {
		if err := h.NotifyAll(payload); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

type admittedConn struct {
	net.Conn
	server     *Server
	ctx        context.Context
	cancel     context.CancelFunc
	once       sync.Once
	released   sync.Once
	unbound    bool // server.mu
	generation uint64
}

func (c *admittedConn) Close() error {
	c.once.Do(func() {
		c.cancel()
		_ = c.Conn.Close()
	})
	return nil
}

// The socket lease outlives raw Close while a TLS result or carrier worker
// still owns resources. Only its joined dispatch/association releases it.
func (c *admittedConn) release() {
	c.released.Do(func() {
		s := c.server
		s.mu.Lock()
		defer s.mu.Unlock()
		hostAdmission.Lock()
		defer hostAdmission.Unlock()
		delete(s.sockets, c)
		s.status.Sockets--
		hostAdmission.sockets--
		if c.unbound {
			c.unbound = false
			s.status.UnboundStreams--
			s.status.ReservedBytes -= unboundBytes
			hostAdmission.bytes -= unboundBytes
		}
	})
}
func (s *Server) releaseUnbound(c *admittedConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hostAdmission.Lock()
	defer hostAdmission.Unlock()
	if c.unbound {
		c.unbound = false
		s.status.UnboundStreams--
		s.status.ReservedBytes -= unboundBytes
		hostAdmission.bytes -= unboundBytes
	}
}
func (s *Server) rateLocked(source netip.Addr) error {
	return s.rateLockedAt(source, time.Now())
}

func (s *Server) rateLockedAt(source netip.Addr, now time.Time) error {
	l := s.cfg.Limits
	for key, b := range s.sources {
		if b.full(now, l.SourceOpensPerSecond, l.SourceOpenBurst) {
			delete(s.sources, key)
		}
	}
	b, exists := s.sources[source]
	if !exists {
		if len(s.sources) >= l.SourceEntries {
			return reject(503)
		}
		b = bucket{float64(l.SourceOpenBurst), now}
	}
	ok := b.take(now, l.SourceOpensPerSecond, l.SourceOpenBurst)
	s.sources[source] = b
	if !ok {
		return reject(429)
	}
	// A source rejected by its own quota or the registry must not spend another
	// source's global capacity. A source admitted here remains charged even when
	// the shared bucket rejects this attempt.
	if !s.global.take(now, l.OpensPerSecond, l.OpenBurst) {
		return reject(429)
	}
	return nil
}
func (s *Server) admitSocket(c net.Conn) *admittedConn {
	if _, err := netip.ParseAddrPort(c.RemoteAddr().String()); err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hostAdmission.Lock()
	defer hostAdmission.Unlock()
	l := s.cfg.Limits
	if s.closed || s.status.Paused || s.status.Sockets >= l.Sockets || s.status.UnboundStreams >= l.UnboundStreams || s.status.ReservedBytes+unboundBytes > l.AggregateBytes || hostAdmission.sockets >= 4096 || hostAdmission.bytes+unboundBytes > MaxHostBufferBytes {
		s.status.Rejected++
		return nil
	}
	ctx, cancel := context.WithCancel(s.ctx)
	owned := &admittedConn{Conn: c, server: s, ctx: ctx, cancel: cancel, unbound: true, generation: s.generation}
	s.sockets[owned] = struct{}{}
	s.status.Sockets++
	s.status.UnboundStreams++
	s.status.ReservedBytes += unboundBytes
	hostAdmission.sockets++
	hostAdmission.bytes += unboundBytes
	s.wg.Add(1)
	return owned
}

func (s *Server) reject(ctx context.Context, c net.Conn, err error) {
	code := 400
	var r rejection
	if errors.As(err, &r) {
		code = int(r)
	}
	_ = stream.Do(ctx, c, false, true, func() error { return stream.WriteAll(c, rejectionBytes(code)) })
	s.mu.Lock()
	s.status.Rejected++
	s.mu.Unlock()
}
func (s *Server) dispatch(raw *admittedConn) {
	transferred := false
	var releaseAssociation func()
	defer func() {
		if !transferred {
			_ = raw.Close()
			raw.release()
		}
		if releaseAssociation != nil {
			releaseAssociation()
		}
	}()
	opts, err := stream.Options(s.cfg.Options)
	if err != nil {
		return
	}
	attempt, stop := opts.Budget.Context(raw.ctx)
	defer stop()
	first, stopFirst := context.WithTimeout(attempt, exchangeTimeout)
	defer stopFirst()
	var c net.Conn = stream.New(raw, opts.Budget)
	if s.cfg.TLS != nil {
		s.mu.Lock()
		hostAdmission.Lock()
		// Handshakes bounds logical associations; each HTTPS association owns
		// two socket-level TLS handshakes, which can overlap at acceptance.
		allowed := !s.closed && !s.status.Paused && s.status.TLSHandshakes < 2*s.cfg.Limits.Handshakes && hostAdmission.tls < 32
		if allowed {
			s.status.TLSHandshakes++
			hostAdmission.tls++
		}
		hostAdmission.Unlock()
		s.mu.Unlock()
		if !allowed {
			return
		}
		a, _ := s.cfg.Authority.TLSAuthority()
		proof, e := tlsstream.Accept(first, c, s.cfg.TLS, a, opts.Budget)
		s.mu.Lock()
		hostAdmission.Lock()
		s.status.TLSHandshakes--
		hostAdmission.tls--
		hostAdmission.Unlock()
		s.mu.Unlock()
		if e != nil {
			return
		}
		defer proof.Close()
		c, e = proof.Consume(a, tlsstream.Server, opts.Budget)
		if e != nil {
			return
		}
	}
	// The TLS result and the raw socket are both retained through actual cleanup.
	defer func() {
		if !transferred {
			_ = c.Close()
		}
	}()
	var head Head
	var parseErr error
	err = stream.Do(first, c, true, false, func() error {
		h, e := readHeader(c)
		if e != nil {
			var r rejection
			if errors.As(e, &r) {
				parseErr = e
				return nil
			}
			return e
		}
		head, parseErr = ParseRequest(h, s.cfg.Authority, s.cfg.Origins)
		return nil
	})
	if err == nil {
		err = parseErr
	}
	if err != nil {
		if first.Err() == nil {
			s.reject(first, c, err)
		}
		return
	}
	if head.Operation == Poll {
		s.mu.Lock()
		a := s.registry[head.Route]
		if s.closed || s.status.Paused || raw.generation != s.generation || a == nil || a.generation != s.generation {
			s.mu.Unlock()
			s.reject(first, c, reject(410))
			return
		}
		if head.Counter != 0 || stream.Check(a.pair.budget) != nil {
			s.mu.Unlock()
			_ = a.pair.Close()
			s.reject(first, c, reject(400))
			return
		}
		s.mu.Unlock()
		// A lawful client can observe the last response byte just before the
		// upload writer returns. Wait for that same write to complete, without
		// attaching D early or holding the registry lock across the wait.
		if err = a.pair.awaitOpen(first); err != nil {
			return
		}
		s.mu.Lock()
		if s.closed || s.status.Paused || s.registry[head.Route] != a || raw.generation != s.generation {
			s.mu.Unlock()
			return
		}
		// D's pre-association TLS/header budget ends only after a synchronous
		// check, then every raw access is gated by U's earlier original budget.
		if err = stream.Check(opts.Budget); err != nil {
			s.mu.Unlock()
			return
		}
		d := stream.New(c, a.pair.budget)
		if !a.pair.attachDownload(d, head) {
			s.mu.Unlock()
			_ = a.pair.Close()
			s.reject(first, c, reject(410))
			return
		}
		opts.Budget.Release()
		a.download = raw
		s.mu.Unlock()
		s.releaseUnbound(raw)
		transferred = true
		return
	}
	if head.Operation != Open {
		s.mu.Lock()
		a := s.registry[head.Route]
		s.mu.Unlock()
		if a != nil {
			_ = a.pair.Close()
		}
		s.reject(first, c, reject(400))
		return
	}
	source, _ := netip.ParseAddrPort(raw.RemoteAddr().String())
	s.mu.Lock()
	rateErr := s.rateLocked(source.Addr().Unmap())
	s.mu.Unlock()
	if rateErr != nil {
		s.reject(first, c, rateErr)
		return
	}
	owner, err := s.reserve(raw.generation)
	if err != nil {
		s.reject(first, c, err)
		return
	}
	defer s.release(owner)
	defer owner.callbacks.join()
	if admit := s.cfg.AdmitAssociation; admit != nil {
		// The bounded native owner stays on this stack even if a hook ignores
		// cancellation. No mutex or unbounded detached callback is involved.
		releaseAssociation, err = admit(first, opts.Budget)
		if err == nil && releaseAssociation == nil {
			err = ordered.ErrOptions
		}
		if err == nil {
			err = stream.ContextError(first)
		}
		if err == nil {
			err = opts.Budget.Check()
		}
		s.mu.Lock()
		current := !s.closed && !s.status.Paused && raw.generation == s.generation
		s.mu.Unlock()
		if err != nil || !current {
			if stream.ContextError(first) == nil && current {
				s.reject(first, c, reject(503))
			}
			return
		}
	}
	// The association, handshake and worst-case runtime bytes were reserved
	// before reading M1 or invoking any cryptographic/credential lookup.
	body := make([]byte, head.BodyLen)
	err = stream.Do(first, c, true, false, func() error { _, e := readBody(c, body[:0], head.BodyLen); return e })
	if err != nil {
		return
	}
	var entropy [32]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return
	}
	route := routeFromRandom(entropy)
	p := newServerPair(c, body, s.cfg.Authority, s.cfg.Origins, route, opts.Budget)
	p.onRecord = func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		hostAdmission.Lock()
		defer hostAdmission.Unlock()
		if owner.handshake && owner.principal != "" {
			owner.handshake = false
			s.status.Handshakes--
			hostAdmission.handshakes--
		}
	}
	owner.pair = p
	s.mu.Lock()
	if s.closed || s.status.Paused || raw.generation != s.generation || s.registry[route] != nil {
		s.mu.Unlock()
		_ = p.Close()
		return
	}
	s.registry[route] = owner
	s.mu.Unlock()
	s.releaseUnbound(raw)
	go p.runDownload()
	defer func() {
		_ = p.Close()
		<-p.done
		<-p.closeDone
		// Serve has a bounded drain; recovery source work may still be alive.
		// Retain native bytes/permits and the embedding lease until it exits.
		if host := owner.host; host != nil {
			_ = host.Close()
			_ = host.Wait(context.Background())
		}
	}()
	hostcfg := s.cfg.Host
	base := hostcfg.ChannelPolicy
	hostcfg.ChannelPolicy = func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
		if !owner.callbacks.enter() {
			return "", securechannel.ErrAuth
		}
		defer owner.callbacks.wg.Done()
		principal, e := base(ctx, id, credential)
		if e != nil || ctx.Err() != nil || principal == "" || len(principal) > 1024 {
			return "", securechannel.ErrAuth
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		hostAdmission.Lock()
		defer hostAdmission.Unlock()
		if s.closed || s.status.Paused || owner.generation != s.generation || owner.principal != "" || hostAdmission.principals[principal] >= s.cfg.Limits.PrincipalAssociations {
			return "", securechannel.ErrAuth
		}
		hostAdmission.principals[principal]++
		owner.principal = principal
		return principal, nil
	}
	if handler := hostcfg.Handler; handler != nil {
		hostcfg.Handler = func(ctx context.Context, req *syntra.RpcRequest) (*syntra.RpcResult, error) {
			if !owner.callbacks.enter() {
				return nil, ordered.ErrClosed
			}
			defer owner.callbacks.wg.Done()
			return handler(ctx, req)
		}
	}
	if authorize := hostcfg.Authorize; authorize != nil {
		hostcfg.Authorize = func(ctx context.Context, principal, method string) error {
			if !owner.callbacks.enter() {
				return ordered.ErrClosed
			}
			defer owner.callbacks.wg.Done()
			return authorize(ctx, principal, method)
		}
	}
	host, err := syntra.OpenHost(hostcfg)
	if err != nil {
		return
	}
	s.mu.Lock()
	owner.host = host
	s.mu.Unlock()
	lifetime, cancel := context.WithCancel(s.ctx)
	watched := make(chan struct{})
	stopWatch := context.AfterFunc(p.ctx, func() { cancel(); close(watched) })
	defer func() {
		if !stopWatch() {
			<-watched
		}
		cancel()
	}()
	_ = connection.Accept(lifetime, p, s.cfg.Security, host, opts)
}
func (s *Server) reserve(generation uint64) (*associationOwner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	hostAdmission.Lock()
	defer hostAdmission.Unlock()
	l := s.cfg.Limits
	if s.closed || s.status.Paused || s.generation != generation || s.status.Associations >= l.Associations || s.status.Handshakes >= l.Handshakes || hostAdmission.associations >= 1024 || hostAdmission.handshakes >= 128 || s.status.ReservedBytes+s.reservation > l.AggregateBytes || hostAdmission.bytes+s.reservation > MaxHostBufferBytes {
		return nil, reject(503)
	}
	s.status.Associations++
	s.status.Handshakes++
	s.status.ReservedBytes += s.reservation
	hostAdmission.associations++
	hostAdmission.handshakes++
	hostAdmission.bytes += s.reservation
	return &associationOwner{generation: generation, handshake: true}, nil
}
func (s *Server) release(a *associationOwner) {
	s.mu.Lock()
	download := a.download
	s.mu.Unlock()
	if download != nil {
		download.release()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	hostAdmission.Lock()
	defer hostAdmission.Unlock()
	if a.pair != nil {
		delete(s.registry, a.pair.route)
	}
	if a.principal != "" {
		hostAdmission.principals[a.principal]--
		if hostAdmission.principals[a.principal] == 0 {
			delete(hostAdmission.principals, a.principal)
		}
	}
	s.status.Associations--
	s.status.Completed++
	s.status.ReservedBytes -= s.reservation
	hostAdmission.associations--
	hostAdmission.bytes -= s.reservation
	if a.handshake {
		s.status.Handshakes--
		hostAdmission.handshakes--
	}
}
