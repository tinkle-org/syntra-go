package network

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

type acceptOutcome struct {
	conn net.Conn
	err  error
}

type faultListener struct {
	outcomes chan acceptOutcome
	calls    chan time.Time
	closed   chan struct{}
	once     sync.Once
}

func newFaultListener() *faultListener {
	return &faultListener{outcomes: make(chan acceptOutcome, 16), calls: make(chan time.Time, 16), closed: make(chan struct{})}
}
func (f *faultListener) Accept() (net.Conn, error) {
	f.calls <- time.Now()
	select {
	case next := <-f.outcomes:
		return next.conn, next.err
	case <-f.closed:
		return nil, net.ErrClosed
	}
}
func (f *faultListener) Close() error { f.once.Do(func() { close(f.closed) }); return nil }
func (f *faultListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}

func faultManagedListener(t *testing.T, n *Network, kind securechannel.Carrier, f net.Listener) *Listener {
	t.Helper()
	_, sc := trust(t, kind)
	cfg := listenerConfig(sc)
	cfg.Listener = f
	l, err := n.listen(cfg, kind)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestAcceptErrorRetriesTimeout(t *testing.T) {
	for _, kind := range []securechannel.Carrier{securechannel.TCP, securechannel.WS} {
		t.Run(kind.String(), func(t *testing.T) {
			n := testNetwork(t, DefaultConfig())
			f := newFaultListener()
			f.outcomes <- acceptOutcome{err: &net.OpError{Op: "accept", Net: "tcp", Err: context.DeadlineExceeded}}
			l := faultManagedListener(t, n, kind, f)
			<-f.calls
			select {
			case <-f.calls:
			case <-l.Done():
				t.Fatal("retryable accept error stopped listener")
			case <-time.After(time.Second):
				t.Fatal("accept did not retry")
			}
			if n.Snapshot().Shutdown.FailedSupervisors != 0 {
				t.Fatal("retry counted as supervisor failure")
			}
		})
	}
}

func TestAcceptErrorTerminalCountedOnce(t *testing.T) {
	for _, kind := range []securechannel.Carrier{securechannel.TCP, securechannel.WS} {
		for _, cause := range []error{errors.New("unknown accept failure"), os.ErrPermission, os.ErrInvalid, net.ErrClosed} {
			t.Run(kind.String()+"/"+cause.Error(), func(t *testing.T) {
				n := testNetwork(t, DefaultConfig())
				events := n.Events()
				f := newFaultListener()
				f.outcomes <- acceptOutcome{err: &net.OpError{Op: "accept", Net: "tcp", Err: cause}}
				l := faultManagedListener(t, n, kind, f)
				select {
				case <-l.Done():
				case <-time.After(time.Second):
					t.Fatal("terminal accept did not stop")
				}
				if got := n.Snapshot().Shutdown.FailedSupervisors; got != 1 {
					t.Fatalf("terminal failures = %d, want 1", got)
				}
				select {
				case <-f.closed:
				default:
					t.Fatal("Done preceded socket cleanup")
				}
				var failed, stopped int
				for stopped == 0 {
					event, err := events.Next(testContext(t))
					if err != nil {
						t.Fatal(err)
					}
					switch event.Kind {
					case SupervisorFailed:
						failed++
					case ListenerStopped:
						stopped++
					}
				}
				if failed != 1 || len(f.calls) != 1 || len(l.local) != 0 {
					t.Fatalf("failed events=%d accepts=%d local permits=%d", failed, len(f.calls), len(l.local))
				}
			})
		}
	}
}

func checkAcceptErrnos(t *testing.T, retryable, terminal []error) {
	t.Helper()
	for _, group := range []struct {
		codes []error
		retry bool
	}{{retryable, true}, {terminal, false}} {
		for _, cause := range group.codes {
			wrapped := &net.OpError{Op: "accept", Net: "tcp", Err: &os.SyscallError{Syscall: "accept", Err: cause}}
			err := socketAcceptError(wrapped)
			if err.retryable != group.retry || !errors.Is(err, cause) {
				t.Errorf("errno %v: retry=%v, want %v", cause, err.retryable, group.retry)
			}
			var original *net.OpError
			if !errors.As(err, &original) || original != wrapped {
				t.Fatal("lost original net.OpError")
			}
			var ne acceptNetworkError = err
			if ne.Timeout() != wrapped.Timeout() || ne.Temporary() != wrapped.Temporary() {
				t.Fatal("changed net.Error semantics")
			}
			// An identical I/O error outside raw accept is terminal by default.
			if (&acceptError{cause: wrapped}).retryable {
				t.Fatal("non-accept I/O failure retried")
			}
		}
	}
}

type acceptFixtureConn struct {
	net.Conn
	setupError error
}

func (c *acceptFixtureConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *acceptFixtureConn) RemoteAddr() net.Addr  { return c.LocalAddr() }
func (c *acceptFixtureConn) SetNoDelay(bool) error { return c.setupError }

type missingAddressListener struct{ *faultListener }

func (missingAddressListener) Addr() net.Addr { return nil }

func TestAcceptListenerAddressFailureIsTerminalBeforeSetup(t *testing.T) {
	f := newFaultListener()
	defer f.Close()
	raw, peer := net.Pipe()
	defer peer.Close()
	// The same timeout would be retryable at raw accept or socket setup, but
	// invalid listener state is terminal and must precede socket configuration.
	f.outcomes <- acceptOutcome{conn: &acceptFixtureConn{Conn: raw, setupError: context.DeadlineExceeded}}
	l := &Listener{socket: missingAddressListener{f}, kind: securechannel.WS}
	conn, err := l.acceptSocket()
	if conn != nil || err == nil || err.retryable || !errors.Is(err, ErrConfig) {
		t.Fatalf("listener address failure: conn=%v error=%v", conn, err)
	}
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("listener address failure did not close accepted socket")
	}
}

func TestAcceptRejectsCallerBudgetWithoutTakingListener(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	_, sc := trust(t, securechannel.TCP)
	cfg := listenerConfig(sc)
	f := newFaultListener()
	defer f.Close()
	cfg.Listener = f
	budget, err := ordered.NewEstablishmentBudget(nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Options.Budget = budget
	if _, err := n.ListenTCP(cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("listener replaced caller budget: %v", err)
	}
	select {
	case <-f.closed:
		t.Fatal("failed construction took caller listener")
	default:
	}
	if len(f.calls) != 0 || budget.Check() != nil {
		t.Fatal("failed construction used listener or expired caller budget")
	}
}

func TestAcceptAdmissionClosureWakesQueuedOwners(t *testing.T) {
	a, err := NewAdmission(1)
	if err != nil {
		t.Fatal(err)
	}
	held, err := a.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() {
			release, err := a.acquire(ctx)
			if release != nil {
				release()
			}
			results <- err
		}()
	}
	until(t, func() bool { a.mu.Lock(); defer a.mu.Unlock(); return len(a.waiters) == 2 })
	a.close()
	a.close()
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrClosed) {
				t.Fatalf("closed admission granted queued owner: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("closed admission did not join waiter")
		}
	}
	if a.InUse() != 1 || a.Available() != 0 {
		t.Fatal("admission closure released another owner's permit")
	}
	held()
	if a.InUse() != 0 || a.Available() != 1 {
		t.Fatal("existing owner could not release closed admission")
	}
	if release, err := a.acquire(ctx); release != nil || !errors.Is(err, ErrClosed) {
		t.Fatalf("closed admission reopened: release=%v error=%v", release != nil, err)
	}
}
