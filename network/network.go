package network

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
)

// Config bounds goroutine-owned services, calls, accepted connections and
// application callbacks. Counts remain charged through actual cleanup.
type Config struct {
	MaxOperations           int
	MaxConnections          int
	MaxCallbacks            int
	CloseTimeout            time.Duration
	StartPaused             bool
	InitialNetworkAvailable bool
	StreamHost              StreamHost
	EventCapacity           int
}

func DefaultConfig() Config {
	return Config{MaxOperations: 256, MaxConnections: 128, MaxCallbacks: 128, CloseTimeout: time.Second, InitialNetworkAvailable: true}
}

type Report struct {
	Complete          bool
	PendingOperations int
	LiveConnections   int
	LiveCallbacks     int
	// LiveExecutions includes retained root recovery/source and egress workers.
	// Ordinary managed host callbacks also appear in LiveCallbacks.
	LiveExecutions    int
	FailedSupervisors uint64
}

// SupervisorFailed precedes the stopped event for a joined failed owner.
const SupervisorFailed EventKind = ConnectionCompleted + 1

type NetworkStatus struct {
	Revision         uint64
	Paused           bool
	NetworkAvailable bool
	Stopping         bool
	Shutdown         Report
}

// Network owns services on ordinary goroutines; it never changes process
// scheduling or creates an independent runtime. Do not copy it.
type Network struct {
	cfg                     Config
	mu                      sync.Mutex
	paused, online, stopped bool
	revision                uint64
	clients                 map[*Client]struct{}
	listeners               map[*Listener]struct{}
	httpListeners           map[*HTTPListener]struct{}
	changed                 chan struct{}
	wake                    chan struct{}
	done                    chan struct{}
	ctx                     context.Context
	cancel                  context.CancelFunc
	operations              atomic.Int64
	callbacks               atomic.Int64
	failed                  atomic.Uint64
	admission               *Admission
	executions              *syntra.ExecutionBudget
	events                  []Event
	eventSequence           uint64
}

type callbackOwnerKey struct{}

func New(cfg Config) (*Network, error) {
	if cfg.MaxOperations < 1 || cfg.MaxOperations > 1_000_000 || cfg.MaxConnections < 1 || cfg.MaxConnections > 4096 || cfg.MaxCallbacks < 1 || cfg.MaxCallbacks > 1024 || cfg.CloseTimeout <= 0 || cfg.CloseTimeout > 5*time.Second || cfg.EventCapacity < 0 || cfg.EventCapacity > 65536 {
		return nil, ErrConfig
	}
	if cfg.EventCapacity == 0 {
		cfg.EventCapacity = 128
	}
	admission, _ := NewAdmission(cfg.MaxConnections)
	executions, _ := syntra.NewExecutionBudget(cfg.MaxCallbacks)
	ctx, cancel := context.WithCancel(context.Background())
	n := &Network{cfg: cfg, paused: cfg.StartPaused, online: cfg.InitialNetworkAvailable, clients: make(map[*Client]struct{}), listeners: make(map[*Listener]struct{}), httpListeners: make(map[*HTTPListener]struct{}), changed: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{}), admission: admission, executions: executions, ctx: ctx, cancel: cancel}
	go n.run()
	return n, nil
}
func (n *Network) signal() {
	select {
	case n.wake <- struct{}{}:
	default:
	}
}
func (n *Network) changedLocked() {
	n.revision++
	close(n.changed)
	n.changed = make(chan struct{})
	n.signal()
}
func (n *Network) reserveCall() bool {
	for {
		count := n.operations.Load()
		if count >= int64(n.cfg.MaxOperations) {
			return false
		}
		if n.operations.CompareAndSwap(count, count+1) {
			return true
		}
	}
}
func (n *Network) releaseCall() { n.operations.Add(-1); n.signal() }
func (n *Network) reserveCallback() bool {
	for {
		count := n.callbacks.Load()
		if count >= int64(n.cfg.MaxCallbacks) {
			return false
		}
		if n.callbacks.CompareAndSwap(count, count+1) {
			n.signal()
			return true
		}
	}
}
func (n *Network) releaseCallback() { n.callbacks.Add(-1); n.signal() }

// recordFailure records one settled failure, never a caller's pending wait.
// Callers are responsible for accounting for each owned failure only once.
func (n *Network) recordFailure() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.recordFailureLocked()
}

func (n *Network) recordFailureLocked() {
	for {
		count := n.failed.Load()
		if n.failed.CompareAndSwap(count, saturate(count, 1)) {
			break
		}
	}
	n.eventLocked(Event{Kind: SupervisorFailed})
}

func (n *Network) report() Report {
	return Report{PendingOperations: int(n.operations.Load()), LiveConnections: n.admission.InUse(), LiveCallbacks: int(n.callbacks.Load()), LiveExecutions: n.executions.Live(), FailedSupervisors: n.failed.Load()}
}
func (n *Network) Snapshot() NetworkStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	r := n.report()
	select {
	case <-n.done:
		r.Complete = true
	default:
	}
	return NetworkStatus{Revision: n.revision, Paused: n.paused, NetworkAvailable: n.online, Stopping: n.stopped, Shutdown: r}
}
func (n *Network) WaitChange(ctx context.Context, revision uint64) (NetworkStatus, error) {
	for {
		n.mu.Lock()
		rev, ch := n.revision, n.changed
		n.mu.Unlock()
		if rev != revision {
			return n.Snapshot(), nil
		}
		select {
		case <-ch:
		case <-n.done:
			return n.Snapshot(), ErrClosed
		case <-ctx.Done():
			return n.Snapshot(), ctx.Err()
		}
	}
}
func (n *Network) Done() <-chan struct{} { return n.done }
func (n *Network) control(update func()) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.stopped {
		return
	}
	update()
	if n.stopped {
		n.cancel()
	}
	for c := range n.clients {
		c.applyNetwork(n.paused, n.online, n.stopped)
	}
	for l := range n.listeners {
		l.applyNetwork(n.paused, n.online, n.stopped)
	}
	for l := range n.httpListeners {
		l.applyNetwork(n.paused, n.online, n.stopped)
	}
	n.eventLocked(Event{Kind: ControlsChanged})
	n.changedLocked()
}
func (n *Network) Pause()                          { n.control(func() { n.paused = true }) }
func (n *Network) Resume()                         { n.control(func() { n.paused = false }) }
func (n *Network) NetworkAvailable(available bool) { n.control(func() { n.online = available }) }
func (n *Network) PlatformWake()                   { n.control(func() {}) }
func (n *Network) Stop()                           { n.control(func() { n.stopped = true }) }
func (n *Network) Shutdown(ctx context.Context) Report {
	n.Stop()
	timer := time.NewTimer(n.cfg.CloseTimeout)
	defer timer.Stop()
	select {
	case <-n.done:
		return n.Snapshot().Shutdown
	default:
	}
	select {
	case <-n.done:
	case <-ctx.Done():
	case <-timer.C:
	}
	return n.Snapshot().Shutdown
}
func (n *Network) run() {
	var previous Report
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		n.mu.Lock()
		for c := range n.clients {
			select {
			case <-c.Done():
				delete(n.clients, c)
				if outcome := c.completionOutcome(); outcome.complete && outcome.err != nil {
					n.recordFailureLocked()
				}
				n.eventLocked(Event{Kind: ClientStopped})
				n.releaseCall()
				n.changedLocked()
			default:
			}
		}
		for l := range n.listeners {
			select {
			case <-l.Done():
				delete(n.listeners, l)
				n.eventLocked(Event{Kind: ListenerStopped, Address: l.LocalAddr().String()})
				n.releaseCall()
				n.changedLocked()
			default:
			}
		}
		for l := range n.httpListeners {
			select {
			case <-l.Done():
				delete(n.httpListeners, l)
				n.eventLocked(Event{Kind: ListenerStopped, Address: l.LocalAddr().String()})
				n.releaseCall()
				n.changedLocked()
			default:
			}
		}
		if report := n.report(); report != previous {
			previous = report
			n.changedLocked()
		}
		if n.stopped && len(n.clients) == 0 && len(n.listeners) == 0 && len(n.httpListeners) == 0 && n.operations.Load() == 0 && n.callbacks.Load() == 0 && n.executions.Live() == 0 {
			close(n.done)
			n.changedLocked()
			n.mu.Unlock()
			return
		}
		n.mu.Unlock()
		// Child completion has one watcher each, owned by this registry.
		select {
		case <-n.wake:
		case <-tick.C:
		}
	}
}
func (n *Network) Client(cfg ReconnectConfig, connector Connector) (*Client, error) {
	return n.client(cfg, connector, nil)
}
func (n *Network) ClientWithSetup(cfg ReconnectConfig, connector ConnectorWithSetup) (*Client, error) {
	return n.client(cfg, nil, connector)
}
func (n *Network) client(cfg ReconnectConfig, connector Connector, setup ConnectorWithSetup) (*Client, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.stopped {
		return nil, ErrClosed
	}
	if !n.reserveCall() {
		return nil, ErrBusy
	}
	paused := cfg.StartPaused
	cfg.StartPaused = true
	var c *Client
	var err error
	if setup == nil {
		c, err = NewClient(cfg, connector)
	} else {
		c, err = NewClientWithSetup(cfg, setup)
	}
	if err != nil {
		n.releaseCall()
		return nil, err
	}
	c.mu.Lock()
	c.owner = n
	c.paused = paused
	c.networkPaused = n.paused
	c.networkOffline = !n.online
	c.mu.Unlock()
	n.clients[c] = struct{}{}
	n.eventLocked(Event{Kind: ClientStarted})
	n.changedLocked()
	go func() { <-c.Done(); n.signal() }()
	select {
	case c.wake <- struct{}{}:
	default:
	}
	return c, nil
}
