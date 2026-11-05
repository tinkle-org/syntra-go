package stream

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

type jumpConn struct {
	net.Conn
	age   *atomic.Int64
	calls int
}

func (c *jumpConn) Write(p []byte) (int, error) {
	c.calls++
	c.age.Store(int64(time.Second))
	return len(p), nil
}
func (c *jumpConn) Read(p []byte) (int, error) {
	c.calls++
	c.age.Store(int64(time.Second))
	p[0] = 1
	return 1, nil
}

func TestGateChecksSynchronousCompletion(t *testing.T) {
	for _, read := range []bool{false, true} {
		var age atomic.Int64
		clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
		b, err := ordered.NewEstablishmentBudget(clock, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		raw := &jumpConn{age: &age}
		c := New(raw, b)
		var n int
		if read {
			n, err = c.Read(make([]byte, 1))
		} else {
			n, err = c.Write([]byte{1})
		}
		if !errors.Is(err, context.DeadlineExceeded) || read && n != 0 {
			t.Fatalf("completion: n=%d err=%v", n, err)
		}
		_, err = c.Write([]byte{1})
		if !errors.Is(err, context.DeadlineExceeded) || raw.calls != 1 {
			t.Fatalf("gate allowed more I/O: %d, %v", raw.calls, err)
		}
	}
}

func TestCancellationWatcherJoinsBeforeDeadlineReset(t *testing.T) {
	a, peer := net.Pipe()
	defer a.Close()
	defer peer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Do(ctx, a, true, false, func() error { close(started); _, err := a.Read(make([]byte, 1)); return err })
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("read not interrupted")
	}
	go func() { _, _ = peer.Write([]byte{7}) }()
	ctx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	var value [1]byte
	if err := Do(ctx, a, true, false, func() error { _, err := a.Read(value[:]); return err }); err != nil || value[0] != 7 {
		t.Fatalf("stale cancellation: %v", err)
	}
}
