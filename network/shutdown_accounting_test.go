package network

import (
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
)

// Interrupt I/O promptly, but retain the carrier cleanup owner until released.
type retirementGate struct {
	ordered.MessageIO
	entered, release chan struct{}
	once             sync.Once
}

func (g *retirementGate) Close() error {
	err := g.MessageIO.Close()
	g.once.Do(func() { close(g.entered) })
	<-g.release
	return err
}

func shutdownFixture(t *testing.T, cfg ReconnectConfig, gate bool) (*Network, *Client, *connection.Client, *atomic.Int32, func()) {
	t.Helper()
	server := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	l, err := server.ListenTCP(listenerConfig(sc))
	if err != nil {
		t.Fatal(err)
	}
	n := testNetwork(t, DefaultConfig())
	var dials atomic.Int32
	connected := make(chan *connection.Client, 1)
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	connect := func(ctx context.Context, b *ordered.EstablishmentBudget, prepare func(*syntra.Client) error) (*connection.Client, error) {
		dials.Add(1)
		raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", l.LocalAddr().String())
		if err != nil {
			return nil, err
		}
		var records ordered.MessageIO = tcp.New(raw, b)
		if gate {
			records = &retirementGate{MessageIO: records, entered: make(chan struct{}), release: release}
		}
		conn, err := connection.Connect(ctx, records, cc, syntra.ClientConfig{Prepare: prepare}, ordered.Options{Budget: b})
		if err == nil {
			connected <- conn
		}
		return conn, err
	}
	var c *Client
	if cfg.RecoveryFactory == nil {
		c, err = n.Client(cfg, func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
			return connect(ctx, b, nil)
		})
	} else {
		c, err = n.ClientWithSetup(cfg, connect)
	}
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RecoveryFactory == nil {
		phase(t, c, CoreReady)
	} else {
		phase(t, c, RecoveryNegotiated)
	}
	return n, c, <-connected, &dials, unblock
}

func assertShutdownAccounting(t *testing.T, n *Network, c *Client, events *Events, failures uint64, want Phase) {
	t.Helper()
	select {
	case <-c.Done():
	case <-testContext(t).Done():
		t.Fatal("client owner did not join")
	}
	if got := c.Snapshot(); got.Phase != want || got.Generation != 0 {
		t.Errorf("joined client status = %+v, want phase %d", got, want)
	}
	var observed uint64
	for {
		event, err := events.Next(testContext(t))
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind == SupervisorFailed {
			observed++
		}
		if event.Kind == ClientStopped {
			break
		}
	}
	if observed != failures {
		t.Errorf("failure events before ClientStopped = %d, want %d", observed, failures)
	}
	report := n.Shutdown(testContext(t))
	if !report.Complete || report.PendingOperations != 0 || report.LiveCallbacks != 0 || report.LiveConnections != 0 || report.LiveExecutions != 0 || report.FailedSupervisors != failures {
		t.Fatalf("joined report = %+v, want %d failures and no retained work", report, failures)
	}
	for i := 0; i < 3; i++ {
		if got := n.Shutdown(testContext(t)); got != report {
			t.Fatalf("repeated shutdown changed report: %+v -> %+v", report, got)
		}
		if got := n.Snapshot().Shutdown; got != report {
			t.Fatalf("snapshot changed report: %+v -> %+v", report, got)
		}
		closeErr := c.CloseContext(testContext(t))
		if failures == 0 && closeErr != nil || failures != 0 && !errors.Is(closeErr, ErrShutdownIncomplete) {
			t.Fatalf("repeated close lost joined outcome: %v", closeErr)
		}
	}
	for {
		event, err := events.Next(testContext(t))
		if errors.Is(err, ErrClosed) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if event.Kind == SupervisorFailed || event.Kind == ClientStopped {
			t.Fatalf("duplicate completion event: %+v", event)
		}
	}
}

func TestManagedHealthyCloseAccounting(t *testing.T) {
	n, c, conn, dials, _ := shutdownFixture(t, reconnectConfig(), false)
	events := n.Events()
	if err := c.CloseContext(testContext(t)); err != nil {
		t.Fatal(err)
	}
	assertShutdownAccounting(t, n, c, events, 0, Stopped)
	if err := conn.Wait(testContext(t)); err != nil || dials.Load() != 1 {
		t.Fatalf("healthy connection: error=%v dials=%d", err, dials.Load())
	}
}

func TestManagedPendingCloseCountsOnlyJoinedOverdueRetirement(t *testing.T) {
	cfg := reconnectConfig()
	cfg.CloseTimeout = 40 * time.Millisecond
	n, c, conn, dials, release := shutdownFixture(t, cfg, true)
	events := n.Events()
	// Retirement must fence replacement on its own, without relying on Stop.
	c.PlatformWake()
	until(t, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.completionErr != nil
	})
	for i := 0; i < 2; i++ {
		if err := c.CloseContext(testContext(t)); !errors.Is(err, ErrShutdownIncomplete) {
			t.Fatalf("pending CloseContext = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		report := n.Shutdown(ctx)
		if report.Complete || report.PendingOperations != 1 || report.FailedSupervisors != 0 || report.LiveCallbacks != 0 {
			t.Fatalf("pending owner counted or released: %+v", report)
		}
		select {
		case <-c.Done():
			t.Fatal("lost client owner before carrier cleanup joined")
		case <-conn.Done():
			t.Fatal("lost connection owner before carrier cleanup joined")
		default:
		}
	}
	phase(t, c, ShutdownIncomplete)
	if report := n.Snapshot().Shutdown; report.FailedSupervisors != 0 || report.PendingOperations != 1 {
		t.Fatalf("overdue but unjoined retirement counted early: %+v", report)
	}
	n.mu.Lock()
	for _, event := range n.events {
		if event.Kind == SupervisorFailed || event.Kind == ClientStopped {
			t.Errorf("completion event while pending: %+v", event)
		}
	}
	n.mu.Unlock()
	c.Retry()
	c.Resume()
	release()
	assertShutdownAccounting(t, n, c, events, 1, ShutdownIncomplete)
	if err := conn.Wait(testContext(t)); err != nil || dials.Load() != 1 {
		t.Fatalf("retired connection: error=%v dials=%d", err, dials.Load())
	}
}

func TestManagedRejectedAttemptIsNotSupervisorFailure(t *testing.T) {
	for _, failure := range []error{securechannel.ErrAuth, securechannel.ErrRecord, ordered.ErrProtocol} {
		t.Run(failure.Error(), func(t *testing.T) {
			n := testNetwork(t, DefaultConfig())
			events := n.Events()
			c, err := n.Client(reconnectConfig(), func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error) {
				return nil, failure
			})
			if err != nil {
				t.Fatal(err)
			}
			phase(t, c, Blocked)
			c.Stop()
			assertShutdownAccounting(t, n, c, events, 0, Stopped)
		})
	}
}

func TestManagedCallerTimeoutDoesNotFailCleanCompletion(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	events := n.Events()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	t.Cleanup(unblock)
	cfg := reconnectConfig()
	cfg.CloseTimeout = time.Second
	c, err := n.Client(cfg, func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error) {
		close(entered)
		<-release
		return nil, context.Canceled
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-testContext(t).Done():
		t.Fatal("connector did not enter")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 3; i++ {
		if outcome := c.closeOutcome(ctx); outcome.complete || !errors.Is(outcome.err, ErrShutdownIncomplete) {
			t.Fatalf("pending close outcome = %+v", outcome)
		}
		if report := n.Shutdown(ctx); report.Complete || report.FailedSupervisors != 0 || report.PendingOperations != 1 || report.LiveCallbacks != 1 {
			t.Fatalf("caller wait changed owner accounting: %+v", report)
		}
	}
	unblock()
	assertShutdownAccounting(t, n, c, events, 0, Stopped)
}

type failedRetirementProfile struct{ closes atomic.Int32 }

func (*failedRetirementProfile) Negotiate(context.Context) error { return nil }
func (p *failedRetirementProfile) Close() {
	p.closes.Add(1)
	panic("private cleanup diagnostic")
}

func TestManagedJoinedCleanupFailureReportedOnceWithoutReplacement(t *testing.T) {
	profile := &failedRetirementProfile{}
	cfg := reconnectConfig()
	cfg.RecoveryFactory = func(*syntra.Client) (RecoverySession, error) { return profile, nil }
	n, c, conn, dials, _ := shutdownFixture(t, cfg, false)
	events := n.Events()
	// A failed retirement triggered by wake must stop, not dial a replacement.
	c.PlatformWake()
	assertShutdownAccounting(t, n, c, events, 1, ShutdownIncomplete)
	c.Retry()
	c.Resume()
	if profile.closes.Load() != 1 || dials.Load() != 1 {
		t.Fatalf("cleanup repeated or replacement dialed: closes=%d dials=%d", profile.closes.Load(), dials.Load())
	}
	if err := conn.Wait(testContext(t)); err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorFailureCounterSaturates(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	events := n.Events()
	n.failed.Store(math.MaxUint64 - 1)
	n.recordFailure()
	n.recordFailure()
	if got := n.Snapshot().Shutdown.FailedSupervisors; got != math.MaxUint64 {
		t.Fatalf("failure counter wrapped: %d", got)
	}
	for i := 0; i < 2; i++ {
		if event, err := events.Next(testContext(t)); err != nil || event.Kind != SupervisorFailed {
			t.Fatalf("missing failure event: %+v %v", event, err)
		}
	}
}

type retirementSourceFailure struct {
	ordered.MessageIO
	reads   atomic.Int32
	trigger <-chan struct{}
	err     error
}

func (r *retirementSourceFailure) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	if r.reads.Add(1) < 3 {
		return r.MessageIO.ReadMessage(ctx, dst)
	}
	select {
	case <-r.trigger:
		return nil, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestManagedRemoteTerminalIsNotSupervisorFailure(t *testing.T) {
	for _, failure := range []error{securechannel.ErrAuth, securechannel.ErrRecord, ordered.ErrProtocol} {
		t.Run(failure.Error(), func(t *testing.T) {
			server := testNetwork(t, DefaultConfig())
			cc, sc := trust(t, securechannel.TCP)
			l, err := server.ListenTCP(listenerConfig(sc))
			if err != nil {
				t.Fatal(err)
			}
			n := testNetwork(t, DefaultConfig())
			events := n.Events()
			trigger := make(chan struct{})
			var dials atomic.Int32
			c, err := n.Client(reconnectConfig(), func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
				dials.Add(1)
				raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", l.LocalAddr().String())
				if err != nil {
					return nil, err
				}
				records := &retirementSourceFailure{MessageIO: tcp.New(raw, b), trigger: trigger, err: failure}
				return connection.Connect(ctx, records, cc, syntra.ClientConfig{}, ordered.Options{Budget: b})
			})
			if err != nil {
				t.Fatal(err)
			}
			phase(t, c, CoreReady)
			close(trigger)
			if got := phase(t, c, Blocked); got.Failure != Classify(failure) {
				t.Fatalf("terminal reason lost: %+v", got)
			}
			c.Stop()
			assertShutdownAccounting(t, n, c, events, 0, Stopped)
			if dials.Load() != 1 {
				t.Fatalf("terminal failure reconnected: %d", dials.Load())
			}
		})
	}
}
