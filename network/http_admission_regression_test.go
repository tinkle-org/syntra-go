// File http_admission_regression_test.go checks that reported HTTP admission
// waiting has already joined the shared FIFO, even if budget sampling is delayed.
package network

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

// TestHTTPWaitingAdmissionAlreadyQueued blocks budget sampling at the exact
// scheduling gap between the old WaitingAdmission publication and acquire.
// A later listener must not overtake a supposedly queued HTTP association.
func TestHTTPWaitingAdmissionAlreadyQueued(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConnections = 1
	n := testNetwork(t, cfg)
	l, _ := managedHTTP(t, n, false, nil)
	until(t, func() bool { return !l.Snapshot().Server.Paused })
	release, err := n.admission.acquire(testContext(t))
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	entered, resume := make(chan struct{}), make(chan struct{})
	var armed atomic.Bool
	var once sync.Once
	defer once.Do(func() { close(resume) })
	origin := time.Now()
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) {
		if armed.CompareAndSwap(true, false) {
			close(entered)
			<-resume
		}
		return time.Since(origin), true
	}))
	budget, err := ordered.NewEstablishmentBudget(clock, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	armed.Store(true)
	go func() {
		finish, err := l.admit(ctx, budget)
		if finish != nil {
			finish()
		}
		done <- err
	}()
	// Always release the clock and join admission, including on the red path.
	defer func() {
		once.Do(func() { close(resume) })
		release()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("admission did not reach budget barrier")
	}
	n.admission.mu.Lock()
	queued := len(n.admission.waiters)
	n.admission.mu.Unlock()
	if waiting := l.Snapshot().WaitingAdmission; waiting != 0 || queued != 0 {
		t.Fatalf("HTTP reports waiting before joining FIFO: waiting=%d queued=%d; a later TCP waiter can overtake", waiting, queued)
	}
	once.Do(func() { close(resume) })
	until(t, func() bool { return l.Snapshot().WaitingAdmission == 1 })
	n.admission.mu.Lock()
	queued = len(n.admission.waiters)
	n.admission.mu.Unlock()
	if queued != 1 {
		t.Fatal("published waiter has no FIFO position")
	}
}
