package syntra

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Model the native counter lifetime: onFrame can record loss until it
// returns, and destroying the core makes those totals inaccessible.
type teardownLossCore struct {
	clientCore
	entered, release, destroyed chan struct{}
	once                        sync.Once
	dropped                     atomic.Uint64
	closed                      atomic.Bool
}

func (c *teardownLossCore) onFrame([]byte) ([]uint64, int, *RpcError) {
	close(c.entered)
	<-c.release
	c.dropped.Add(1)
	return nil, 0, nil
}

func (c *teardownLossCore) lossTotals() (uint64, uint64) {
	if c.closed.Load() {
		return 0, 0
	}
	d := c.dropped.Load()
	return d, d * 9
}

func (c *teardownLossCore) close() error {
	c.once.Do(func() { c.closed.Store(true); close(c.destroyed) })
	return c.clientCore.close()
}

func TestClientCloseSnapshotsAfterInFlightFrame(t *testing.T) {
	c, err := OpenClient(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	core := &teardownLossCore{clientCore: c.core, entered: make(chan struct{}), release: make(chan struct{}), destroyed: make(chan struct{})}
	c.core = core
	var release sync.Once
	unblock := func() { release.Do(func() { close(core.release) }) }
	defer unblock()
	a, b := LoopbackPair()
	defer a.Close()
	h, err := OpenHost(testHostConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	runDone, serveDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(runDone); _ = c.Run(ctx, a) }()
	go func() { defer close(serveDone); _ = h.Serve(ctx, b) }()
	t.Cleanup(func() {
		unblock()
		cancel()
		_ = a.Close()
		awaitSignal(t, runDone, "client cleanup")
		awaitSignal(t, serveDone, "host cleanup")
	})
	awaitSignal(t, c.activated, "client activation")
	if err := h.NotifyAll([]byte("loss-frame")); err != nil {
		t.Fatal(err)
	}
	awaitSignal(t, core.entered, "in-flight frame")
	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	awaitSignal(t, c.done, "close admission fence")
	select {
	case <-core.destroyed:
		t.Error("Close destroyed core before in-flight onFrame stopped recording loss")
	case <-time.After(50 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close deadlocked with Run teardown")
	}
	awaitSignal(t, runDone, "Run teardown")
	if d, b := c.LossTotals(); d != 1 || b != 9 {
		t.Fatalf("final loss totals = (%d,%d), want (1,9)", d, b)
	}
	cancel()
	awaitSignal(t, serveDone, "host teardown")
}
