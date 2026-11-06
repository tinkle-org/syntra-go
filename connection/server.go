// File server.go owns encrypted responder sessions and their bounded lifecycle.
package connection

import (
	"context"
	"sync"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

// Accept takes ownership of carrier, including on failure, establishes an
// encrypted channel, and serves it on host until ctx ends or the session stops.
// It blocks for the connection lifetime and joins carrier cleanup before return.
// The caller owns host and may use it concurrently for other connections.
// Configure host with an explicit ChannelPolicy and per-method Authorize policy.
//
// opts.Budget may include earlier carrier setup, as described by Connect. That
// same deadline bounds host policy and the Ready write, then is retired without
// limiting the activated session. Canceling ctx still stops the active session.
func Accept(ctx context.Context, carrier ordered.MessageIO, channelcfg securechannel.ServerConfig, host *syntra.Host, opts ordered.Options) error {
	if carrier == nil {
		return ErrConfig
	}
	if host == nil {
		_ = carrier.Close()
		return ErrConfig
	}
	opts, err := establishmentOptions(opts)
	if err != nil {
		_ = carrier.Close()
		return publicError(err)
	}
	t, err := ordered.Server(ctx, carrier, channelcfg, opts)
	if err != nil {
		return publicError(err)
	}
	defer t.Close()
	establish, stopEstablish := t.EstablishmentContext(ctx)
	lifetime, stopLifetime := context.WithCancel(ctx)
	ready := &readyTransport{Transport: t, budget: opts.Budget, establish: establish, done: make(chan struct{}), phase: make(chan context.Context, 1)}
	defer func() {
		if ready.stopPhase != nil {
			ready.stopPhase()
		}
	}()
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		defer stopEstablish()
		for {
			select {
			case phase := <-ready.phase:
				establish = phase
			case <-ready.done:
				return
			case <-establish.Done():
				ready.mu.Lock()
				if !ready.ready {
					stopLifetime()
				}
				ready.mu.Unlock()
				return
			}
		}
	}()
	err = host.Serve(lifetime, ready)
	ready.mu.Lock()
	if !ready.ready {
		if ctxErr := establishmentError(ctx, t); ctxErr != nil {
			err = ctxErr
		}
	}
	ready.mu.Unlock()
	stopLifetime()
	stopEstablish()
	<-watchDone
	return publicError(err)
}

// Host's first successful Send is Ready. Serialize readiness with the deadline
// watcher so an expired attempt cannot activate, or cancel an active lifetime.
type readyTransport struct {
	*ordered.Transport
	budget    *ordered.EstablishmentBudget
	establish context.Context
	mu        sync.Mutex
	ready     bool
	done      chan struct{}
	phaseOnce sync.Once
	phase     chan context.Context
	stopPhase context.CancelFunc
}

// TerminalReceiptDriver forwards to the same ordered owner, never a new permit.
func (t *readyTransport) TerminalReceiptDriver() syntra.TerminalReceiptDriver {
	return t.Transport.TerminalReceiptDriver()
}

func (t *readyTransport) Recv(ctx context.Context) ([]byte, error) {
	t.phaseOnce.Do(func() {
		// Host's runtime handshake context carries its configured timeout.
		// Capture its remaining budget in the channel's trusted clock domain.
		timeout := 5 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			timeout = max(time.Nanosecond, time.Until(deadline))
		}
		phase, cancel := t.Transport.EstablishmentContextWithTimeout(t.establish, timeout)
		t.stopPhase = cancel
		t.phase <- phase
	})
	return t.Transport.Recv(ctx)
}

func (t *readyTransport) Send(ctx context.Context, frame []byte) error {
	t.mu.Lock()
	if !t.ready {
		if err := establishmentError(ctx, t.Transport); err != nil {
			t.mu.Unlock()
			return err
		}
	}
	t.mu.Unlock()
	err := t.Transport.Send(ctx, frame)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ready {
		if err := establishmentError(t.establish, t.Transport); err != nil {
			return err
		}
		t.budget.Release()
		if err := t.budget.Check(); err != nil {
			return err
		}
		t.ready = true
		close(t.done)
	}
	return nil
}

// ServerOptions bounds admitted carriers, including pending handshakes.
type ServerOptions struct {
	MaxConnections  int           // zero selects 128; maximum 4096
	ShutdownTimeout time.Duration // zero selects 5s; maximum 5s
}

// Server owns its Host and carriers passed to Accept. It is safe concurrently;
// construct with NewServer and do not copy it or replace Host. Use Host for
// broadcasts and principal disconnection, and Server.Close for owned shutdown.
type Server struct {
	Host    *syntra.Host
	channel securechannel.ServerConfig
	opts    ServerOptions
	ctx     context.Context
	cancel  context.CancelFunc
	once    sync.Once
	mu      sync.Mutex
	closed  bool
	conns   map[*ownedCarrier]struct{}
	drained chan struct{}
	done    chan struct{}
}

// NewServer builds an owned Host with an explicit ChannelPolicy. Nil Authorize
// retains the core's deny-all default. Carrier setup remains the embedder's job.
func NewServer(hostcfg syntra.HostConfig, channelcfg securechannel.ServerConfig, opts ServerOptions) (*Server, error) {
	if hostcfg.ChannelPolicy == nil || channelcfg.Validate() != nil {
		return nil, ErrConfig
	}
	if opts.MaxConnections == 0 {
		opts.MaxConnections = 128
	}
	if opts.ShutdownTimeout == 0 {
		opts.ShutdownTimeout = ShutdownTimeout
	}
	if opts.MaxConnections < 1 || opts.MaxConnections > 4096 || opts.ShutdownTimeout < 0 || opts.ShutdownTimeout > ShutdownTimeout {
		return nil, ErrConfig
	}
	host, err := syntra.OpenHost(hostcfg)
	if err != nil {
		return nil, publicError(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Server{Host: host, channel: channelcfg, opts: opts, ctx: ctx, cancel: cancel,
		conns: make(map[*ownedCarrier]struct{}), drained: make(chan struct{}), done: make(chan struct{})}, nil
}

// Accept admits and serves one caller-supplied carrier, blocking until it stops.
// Ownership transfers even on rejection. Cancellation ends this connection;
// Close stops all admitted connections. Options and Budget are per connection.
func (s *Server) Accept(ctx context.Context, carrier ordered.MessageIO, opts ordered.Options) error {
	if carrier == nil {
		return ErrConfig
	}
	owned := &ownedCarrier{MessageIO: carrier}
	s.mu.Lock()
	var err error
	if s.closed {
		err = ErrClosed
	} else if len(s.conns) >= s.opts.MaxConnections {
		err = ordered.ErrBusy
	} else {
		s.conns[owned] = struct{}{}
	}
	s.mu.Unlock()
	if err != nil {
		_ = owned.Close()
		return err
	}
	defer func() {
		_ = owned.Close()
		s.mu.Lock()
		delete(s.conns, owned)
		if s.closed && len(s.conns) == 0 {
			close(s.drained)
		}
		s.mu.Unlock()
	}()
	lifetime, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer stop()
	defer cancel()
	return Accept(lifetime, owned, s.channel, s.Host, opts)
}

type ownedCarrier struct {
	ordered.MessageIO
	once sync.Once
	err  error
}

func (c *ownedCarrier) Close() error {
	c.once.Do(func() { c.err = c.MessageIO.Close() })
	return c.err
}

// SupportsTerminalReceipt preserves only the underlying carrier's explicit opt-in.
func (c *ownedCarrier) SupportsTerminalReceipt() bool {
	if provider, ok := c.MessageIO.(interface{ SupportsTerminalReceipt() bool }); ok {
		return provider.SupportsTerminalReceipt()
	}
	return false
}

func (s *Server) initiateClose() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.cancel()
		carriers := make([]*ownedCarrier, 0, len(s.conns))
		for c := range s.conns {
			carriers = append(carriers, c)
		}
		if len(s.conns) == 0 {
			close(s.drained)
		}
		s.mu.Unlock()
		go func() {
			var joins sync.WaitGroup
			for _, c := range carriers {
				joins.Add(1)
				go func() { defer joins.Done(); _ = c.Close() }()
			}
			_ = s.Host.Close()
			joins.Wait()
			<-s.drained
			_ = s.Host.Wait(context.Background())
			close(s.done)
		}()
	})
}

// Close stops admission, cancels connections, closes carriers and Host, then
// joins within the configured timeout. It is concurrent and idempotent. On
// timeout the join owner remains active; Done signals eventual completion.
func (s *Server) Close() error {
	s.initiateClose()
	ctx, cancel := context.WithTimeout(context.Background(), s.opts.ShutdownTimeout)
	defer cancel()
	if s.Wait(ctx) != nil {
		return ErrShutdownTimeout
	}
	return nil
}

// Done closes once owned connections and shutdown cleanup have actually joined.
func (s *Server) Done() <-chan struct{} { return s.done }

// Wait observes shutdown completion. Canceling ctx only stops this wait.
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
