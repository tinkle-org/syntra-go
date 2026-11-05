//go:build go1.25

package network

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"testing/synctest"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	"github.com/tinkle-org/syntra-go/transport/websocket"
)

func acceptAssertCalls(t *testing.T, f *faultListener, want int) {
	t.Helper()
	synctest.Wait()
	if got := len(f.calls); got != want {
		t.Fatalf("accept calls=%d, want %d", got, want)
	}
}

func acceptAssertStopped(t *testing.T, l *Listener, failures uint64) {
	t.Helper()
	synctest.Wait()
	select {
	case <-l.Done():
	default:
		t.Fatal("listener did not join cleanup")
	}
	if got := l.network.Snapshot().Shutdown.FailedSupervisors; got != failures {
		t.Fatalf("failures=%d, want %d", got, failures)
	}
	if l.Snapshot().Admitted != 0 || l.Snapshot().WaitingAdmission != 0 || len(l.local) != 0 {
		t.Fatalf("listener retained owners: %+v local=%d", l.Snapshot(), len(l.local))
	}
}

func TestAcceptRetryBoundaryAndControls(t *testing.T) {
	for _, kind := range []securechannel.Carrier{securechannel.TCP, securechannel.WS} {
		t.Run(kind.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := testNetwork(t, DefaultConfig())
				f := newFaultListener()
				f.outcomes <- acceptOutcome{err: acceptResourceTestError()}
				f.outcomes <- acceptOutcome{err: context.DeadlineExceeded}
				l := faultManagedListener(t, n, kind, f)
				acceptAssertCalls(t, f, 1)
				if len(l.local) != 0 || n.admission.InUse() != 0 {
					t.Fatal("retry delay retained admission")
				}
				start := time.Now()
				time.Sleep(99 * time.Millisecond)
				acceptAssertCalls(t, f, 1)
				for _, control := range []func(){l.Pause, l.Resume,
					func() { l.NetworkAvailable(false) }, func() { l.NetworkAvailable(true) },
					l.PlatformWake, n.Pause, n.Resume,
					func() { n.NetworkAvailable(false) }, func() { n.NetworkAvailable(true) }, n.PlatformWake} {
					control()
					acceptAssertCalls(t, f, 1)
				}
				time.Sleep(time.Millisecond)
				acceptAssertCalls(t, f, 2)
				if time.Since(start) != 100*time.Millisecond {
					t.Fatal("controls renewed the retry cutoff")
				}
				l.Pause()
				time.Sleep(100 * time.Millisecond)
				acceptAssertCalls(t, f, 2)
				l.NetworkAvailable(false)
				l.Resume()
				acceptAssertCalls(t, f, 2)
				l.NetworkAvailable(true)
				acceptAssertCalls(t, f, 3)
				l.Stop() // Close unblocks a pending raw accept without counting failure.
				acceptAssertStopped(t, l, 0)
			})
		})
	}
}

func TestAcceptStopInterruptsRetryDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := testNetwork(t, DefaultConfig())
		f := newFaultListener()
		f.outcomes <- acceptOutcome{err: acceptResourceTestError()}
		l := faultManagedListener(t, n, securechannel.TCP, f)
		acceptAssertCalls(t, f, 1)
		start := time.Now()
		l.Stop()
		acceptAssertStopped(t, l, 0)
		if time.Now() != start {
			t.Fatal("Stop waited for the retry cutoff")
		}
	})
}

func TestAcceptSocketSetupRetriesBeforeAuthentication(t *testing.T) {
	for _, kind := range []securechannel.Carrier{securechannel.TCP, securechannel.WS} {
		t.Run(kind.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := testNetwork(t, DefaultConfig())
				_, sc := trust(t, kind)
				cfg := listenerConfig(sc)
				cfg.Host.ChannelPolicy = func(context.Context, syntra.ChannelIdentity, []byte) (string, error) {
					t.Error("setup failure reached authentication")
					return "", errors.New("unexpected policy call")
				}
				f := newFaultListener()
				raw, peer := net.Pipe()
				defer peer.Close()
				f.outcomes <- acceptOutcome{conn: &acceptFixtureConn{Conn: raw, setupError: errors.New("setup failure")}}
				cfg.Listener = f
				l, err := n.listen(cfg, kind)
				if err != nil {
					t.Fatal(err)
				}
				acceptAssertCalls(t, f, 1)
				if len(l.local) != 0 || n.admission.InUse() != 0 || l.Snapshot().Admitted != 0 {
					t.Fatal("setup failure retained admission")
				}
				if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("failed socket not closed: %v", err)
				}
				time.Sleep(99 * time.Millisecond)
				acceptAssertCalls(t, f, 1)
				time.Sleep(time.Millisecond)
				acceptAssertCalls(t, f, 2)
				l.Stop()
				acceptAssertStopped(t, l, 0)
			})
		})
	}
}

func TestAcceptLiveRPCProgressesDuringRetry(t *testing.T) {
	for _, kind := range []securechannel.Carrier{securechannel.TCP, securechannel.WS} {
		t.Run(kind.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				n := testNetwork(t, DefaultConfig())
				cc, sc := trust(t, kind)
				f := newFaultListener()
				raw, peer := net.Pipe()
				defer peer.Close()
				f.outcomes <- acceptOutcome{conn: &acceptFixtureConn{Conn: raw}}
				f.outcomes <- acceptOutcome{err: acceptResourceTestError()}
				cfg := listenerConfig(sc)
				cfg.Listener = f
				l, err := n.listen(cfg, kind)
				if err != nil {
					t.Fatal(err)
				}
				acceptAssertCalls(t, f, 2)
				start := time.Now()
				clientConn := &acceptFixtureConn{Conn: peer}
				var client *connection.Client
				if kind == securechannel.TCP {
					client, err = tcp.Connect(context.Background(), clientConn, cc, syntra.ClientConfig{}, ordered.Options{})
				} else {
					client, err = websocket.Connect(context.Background(), clientConn, "ws://127.0.0.1/syntra/1.0/ws", cc, syntra.ClientConfig{}, ordered.Options{})
				}
				if err != nil {
					t.Fatal(err)
				}
				defer client.Close()
				response, err := client.Call(context.Background(), "/test.Service/Echo", []byte("echo"), 1000)
				if err != nil || string(response) != "echo" {
					t.Fatalf("response=%q error=%v", response, err)
				}
				if time.Now() != start {
					t.Fatal("RPC waited for accept backoff")
				}
				acceptAssertCalls(t, f, 2)
				l.Stop()
				acceptAssertStopped(t, l, 0)
			})
		})
	}
}

func TestAcceptAdmissionCancellationFIFOAndClosure(t *testing.T) {
	for _, kind := range []securechannel.Carrier{securechannel.TCP, securechannel.WS} {
		t.Run(kind.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				cfg := DefaultConfig()
				cfg.MaxConnections = 1
				n := testNetwork(t, cfg)
				held, err := n.admission.acquire(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				defer held()
				f := newFaultListener()
				raw, peer := net.Pipe()
				defer peer.Close()
				f.outcomes <- acceptOutcome{conn: &acceptFixtureConn{Conn: raw}}
				l := faultManagedListener(t, n, kind, f)
				synctest.Wait()
				if l.Snapshot().WaitingAdmission != 1 || n.admission.InUse() != 1 {
					t.Fatal("accepted socket did not retain queue position")
				}
				// A subsequent owner must not bypass the pending accepted socket.
				later, cancelLater := context.WithCancel(context.Background())
				defer cancelLater()
				gotLater := make(chan func(), 1)
				go func() { release, _ := n.admission.acquire(later); gotLater <- release }()
				synctest.Wait()
				if len(n.admission.waiters) != 2 {
					t.Fatal("missing FIFO waiters")
				}
				// Unrelated completed work and wakeups of the registry cannot cancel it.
				n.signal()
				synctest.Wait()
				if len(n.admission.waiters) != 2 || len(f.calls) != 1 {
					t.Fatal("pending accept lost its queue position")
				}
				l.PlatformWake()
				synctest.Wait()
				if l.Snapshot().WaitingAdmission != 0 || len(n.admission.waiters) != 1 || n.admission.InUse() != 1 {
					t.Fatal("canceling accept leaked or released another owner's permit")
				}
				if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("canceled socket not closed: %v", err)
				}
				held()
				releaseLater := <-gotLater
				if releaseLater == nil {
					t.Fatal("next FIFO owner did not acquire")
				}
				releaseLater()
				l.Stop()
				acceptAssertStopped(t, l, 0)

				// Closed shared admission is a terminal stage, not a retryable close.
				n.admission.close()
				f = newFaultListener()
				raw, peer2 := net.Pipe()
				defer peer2.Close()
				f.outcomes <- acceptOutcome{conn: &acceptFixtureConn{Conn: raw}}
				l = faultManagedListener(t, n, kind, f)
				acceptAssertStopped(t, l, 1)
				if len(f.calls) != 1 || n.admission.InUse() != 0 {
					t.Fatal("closed admission retried or leaked")
				}
				if _, err := peer2.Read(make([]byte, 1)); err != io.EOF {
					t.Fatalf("closed admission retained socket: %v", err)
				}
			})
		})
	}
}

func TestAcceptTerminalFailureWaitsForOwnedCallbacks(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := testNetwork(t, DefaultConfig())
		cc, sc := trust(t, securechannel.TCP)
		f := newFaultListener()
		raw, peer := net.Pipe()
		defer peer.Close()
		f.outcomes <- acceptOutcome{conn: &acceptFixtureConn{Conn: raw}}
		entered, release := make(chan struct{}), make(chan struct{})
		cfg := listenerConfig(sc)
		cfg.Listener = f
		cfg.Host.ChannelPolicy = func(context.Context, syntra.ChannelIdentity, []byte) (string, error) {
			close(entered)
			<-release
			return "device", nil
		}
		l, err := n.ListenTCP(cfg)
		if err != nil {
			t.Fatal(err)
		}
		connected := make(chan error, 1)
		go func() {
			c, err := tcp.Connect(context.Background(), peer, cc, syntra.ClientConfig{}, ordered.Options{})
			if c != nil {
				_ = c.Close()
			}
			connected <- err
		}()
		<-entered
		f.outcomes <- acceptOutcome{err: errors.New("terminal accept failure")}
		synctest.Wait()
		select {
		case <-l.Done():
			t.Fatal("Done released a live callback")
		default:
		}
		if n.Snapshot().Shutdown.FailedSupervisors != 0 || n.admission.InUse() != 1 {
			t.Fatal("failure counted before owned cleanup completed")
		}
		close(release)
		acceptAssertStopped(t, l, 1)
		if n.admission.InUse() != 0 || n.callbacks.Load() != 0 {
			t.Fatal("terminal accept retained callback or admission")
		}
		if err := <-connected; err == nil {
			t.Fatal("canceled establishment succeeded")
		}
	})
}

func TestAcceptClosedExtraAdmissionReleasesNetworkPermit(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		n := testNetwork(t, DefaultConfig())
		_, sc := trust(t, securechannel.TCP)
		f := newFaultListener()
		raw, peer := net.Pipe()
		defer peer.Close()
		f.outcomes <- acceptOutcome{conn: &acceptFixtureConn{Conn: raw}}
		cfg := listenerConfig(sc)
		cfg.Listener = f
		cfg.Admission, _ = NewAdmission(1)
		cfg.Admission.close()
		l, err := n.ListenTCP(cfg)
		if err != nil {
			t.Fatal(err)
		}
		acceptAssertStopped(t, l, 1)
		if n.admission.InUse() != 0 || cfg.Admission.InUse() != 0 {
			t.Fatal("closed extra admission retained network permit")
		}
	})
}
