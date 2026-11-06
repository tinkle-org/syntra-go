// File terminal_review_regression_test.go checks independent observation cutoff
// and reentrant host control without releasing the active observer first.
package tcp_test

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
)

// TestTerminalReviewTCPStalledPostHandoffObserverRetiresSocket enforces observer
// cutoff without releasing its execution charge or falsely reporting joined cleanup.
func TestTerminalReviewTCPStalledPostHandoffObserverRetiresSocket(t *testing.T) {
	writeEntered, observerEntered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	f := terminalTCP(t, terminalTCPOptions{
		wrap: func(conn net.Conn) net.Conn {
			return &terminalFaultConn{Conn: conn, entered: writeEntered, closed: make(chan struct{})}
		},
		observe: func(o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
			select {
			case <-writeEntered:
				once.Do(func() { close(observerEntered) })
				<-release
			default:
			}
			return o, nil
		},
	})
	defer close(release)
	c := f.connect(t)
	done := make(chan error, 1)
	go func() { _, err := c.Call(f.ctx, retireMethod, nil, 3000); done <- err }()
	select {
	case <-observerEntered:
	case <-time.After(time.Second):
		t.Fatal("post-handoff observer not entered")
	}
	select {
	case <-c.Done():
	case <-time.After(200 * time.Millisecond):
		t.Fatal("read timeout did not retire socket while observer remained blocked")
	}
	if f.budget.Live() == 0 {
		t.Fatal("stalled observer lost its actual execution charge")
	}
	if err := f.host.Close(); err != nil {
		t.Fatal(err)
	}
	joinCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := f.host.Wait(joinCtx); err == nil {
		t.Fatal("host reported joined closure while authority callback was still blocked")
	}
	if err := <-done; err == nil {
		t.Fatal("stalled observation became success")
	}
}

// TestTerminalReviewTCPObserverCanStopHostWithoutSelfJoin verifies reentrant host
// close/disconnect returns while the observer itself remains at a barrier.
func TestTerminalReviewTCPObserverCanStopHostWithoutSelfJoin(t *testing.T) {
	for _, control := range []string{"disconnect", "close"} {
		t.Run(control, func(t *testing.T) {
			var host atomic.Pointer[syntra.Host]
			var once atomic.Bool
			returned, release := make(chan error, 1), make(chan struct{})
			f := terminalTCP(t, terminalTCPOptions{observe: func(o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
				if o.State == syntra.TerminalOwnedCommitted && once.CompareAndSwap(false, true) {
					called := make(chan error, 1)
					// The observer cannot complete until its host control returns.
					// release is a test-only escape for the red self-join case.
					go func() {
						if control == "close" {
							called <- host.Load().Close()
						} else {
							called <- host.Load().DisconnectPrincipal("fixture")
						}
					}()
					select {
					case err := <-called:
						returned <- err
					case <-release:
					}
					o.State = syntra.TerminalDenied
				}
				return o, nil
			}})
			defer close(release)
			host.Store(f.host)
			c := f.connect(t)
			done := make(chan error, 1)
			go func() { _, err := c.Call(f.ctx, retireMethod, nil, 3000); done <- err }()
			select {
			case err := <-returned:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(200 * time.Millisecond):
				t.Fatal("host control joined its own active authority observer")
			}
			if err := <-done; err == nil {
				t.Fatal("host withdrawal became success")
			}
		})
	}
}
