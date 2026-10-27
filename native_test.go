//go:build syntranative

// Production native adapter tests: require the production Rust library
// (cargo build -p syntra-ffi --features production) linked with
// -tags syntranative. Skipped by default (no -tags); CI runs this suite
// in the go-tests native step (see repo-validation.yml).
package syntra

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestNativeClientConfiguredVersionRange(t *testing.T) {
	cfg, err := resolveClientConfig(ClientConfig{MinVersion: 1, MaxVersion: 3})
	if err != nil {
		t.Fatal(err)
	}
	core, err := newClientCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	c := core.(*ffiClientCore)
	if c.minVersion != cfg.minVersion || c.maxVersion != cfg.maxVersion {
		t.Fatalf("native range = [%d,%d], want [%d,%d]", c.minVersion, c.maxVersion, cfg.minVersion, cfg.maxVersion)
	}
	ready, err := MarshalFrame(NewReadyFrame(1, &ServerReady{ConnectionId: "test-connection"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.activate(ready); err != nil {
		t.Fatalf("configured version rejected: %v", err)
	}
	if c.version() != 1 {
		t.Fatalf("negotiated version = %d", c.version())
	}
}

func TestNativeCloseWaitsForHandleUsers(t *testing.T) {
	ccfg, err := resolveClientConfig(testClientConfig())
	if err != nil {
		t.Fatal(err)
	}
	hcfg, err := resolveHostConfig(testHostConfig())
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClientCore(ccfg)
	if err != nil {
		t.Fatal(err)
	}
	host, err := newHostCore(hcfg)
	if err != nil {
		_ = client.close()
		t.Fatal(err)
	}
	c, h := client.(*ffiClientCore), host.(*ffiHostCore)
	for _, tc := range []struct {
		name    string
		lock    func() error
		unlock  func()
		closed  func() bool
		present func() bool
		close   func() error
	}{
		{"client", func() error { _, err := c.locked(); return err }, c.unlockHandle, c.closed.Load, func() bool { return c.handle != nil }, c.close},
		{"host", func() error { _, err := h.locked(); return err }, h.unlockHandle, h.closed.Load, func() bool { return h.handle != nil }, h.close},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer tc.close()
			if err := tc.lock(); err != nil {
				t.Fatal(err)
			}
			var unlock sync.Once
			defer unlock.Do(tc.unlock)
			done := make(chan error, 1)
			go func() { done <- tc.close() }()
			deadline := time.Now().Add(time.Second)
			for !tc.closed() {
				if time.Now().After(deadline) {
					t.Fatal("Close did not start")
				}
				runtime.Gosched()
			}
			select {
			case <-done:
				t.Fatal("Close returned with a handle user still in flight")
			default:
			}
			if !tc.present() {
				t.Fatal("Close detached a handle still in use")
			}
			unlock.Do(tc.unlock)
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("Close did not finish after releasing handle")
			}
			if err := tc.lock(); err == nil {
				tc.unlock()
				t.Fatal("closed handle acquired")
			}
		})
	}
}

func TestNativeCallsRaceClose(t *testing.T) {
	for iteration := 0; iteration < 10; iteration++ {
		ccfg, err := resolveClientConfig(testClientConfig())
		if err != nil {
			t.Fatal(err)
		}
		hcfg, err := resolveHostConfig(testHostConfig())
		if err != nil {
			t.Fatal(err)
		}
		c, err := newClientCore(ccfg)
		if err != nil {
			t.Fatal(err)
		}
		h, err := newHostCore(hcfg)
		if err != nil {
			_ = c.close()
			t.Fatal(err)
		}
		hello, err := c.helloFrame()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.acceptHello(hello); err != nil {
			t.Fatal(err)
		}
		ready, err := h.authComplete("test-principal")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.activate(ready); err != nil {
			t.Fatal(err)
		}
		request, err := c.beginCall(1, "/example.Echo/Echo", nil, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, fatal := h.onFrame(request); fatal != nil {
			t.Fatal(fatal)
		}
		result, err := MarshalFrame(NewResultFrame(1, 1, NewSuccessResult(nil)))
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for worker := 0; worker < 4; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				for j := 0; j < 20; j++ {
					_, _ = c.helloFrame()
					_, _ = c.activate(ready)
					_ = c.version()
					_, _ = c.beginCall(uint64(j+2), "/example.Echo/Echo", nil, 1000)
					_, _, _ = c.onFrame(result)
					_ = c.cancelCall(1)
					_, _ = c.takeOutcome(1)
					_, _ = c.pollNotification()
					_ = c.reapExpired(time.Now())
					_, _ = h.acceptHello(hello)
					_, _ = h.authComplete("test-principal")
					_, _, _ = h.onFrame(request)
					_, _, _ = h.takePending()
					_ = h.isCancelled(1)
					_, _, _ = h.answer(1, NewSuccessResult(nil))
					_ = h.notify(nil)
					_, _ = h.nextOutbound()
					_ = h.reapExpired(time.Now())
				}
			}()
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_ = c.close()
			_ = h.close()
		}()
		close(start)
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		awaitSignal(t, done, "native calls racing Close")
	}
}
