package syntra

import (
	"context"
	"testing"
	"time"
)

// TestMemoryStoreAtomicFailure covers persistence failure: a failing write
// records nothing and the last persisted position is retained for retry.
func TestMemoryStoreAtomicFailure(t *testing.T) {
	s := NewMemoryStore()
	pos := CommittedPosition{Stream: "s", Generation: 7, Committed: []byte("c-43")}
	if err := s.StoreAtomic(pos, []byte("fx-1")); err != nil {
		t.Fatal(err)
	}
	s.FailNext = true
	bad := CommittedPosition{Stream: "s", Generation: 7, Committed: []byte("c-44")}
	if err := s.StoreAtomic(bad, []byte("fx-2")); err == nil {
		t.Fatal("failing write must error")
	}
	got := s.Load("s")
	if got == nil || string(got.Committed) != "c-43" {
		t.Fatalf("last persisted must be retained, got %v", got)
	}
	if err := s.StoreAtomic(bad, []byte("fx-2")); err != nil {
		t.Fatal(err)
	}
	if got := s.Load("s"); string(got.Committed) != "c-44" {
		t.Fatalf("retry must advance, got %v", got)
	}
}

// TestMemoryStoreDeepCopy covers aliasing: StoreAtomic and Load deep-copy
// committed bytes so caller mutation can never alias durable state.
func TestMemoryStoreDeepCopy(t *testing.T) {
	s := NewMemoryStore()
	committed := []byte("c-100")
	if err := s.StoreAtomic(CommittedPosition{Stream: "s", Generation: 1, Committed: committed}, []byte("fx")); err != nil {
		t.Fatal(err)
	}
	committed[0] = 'X'
	if got := s.Load("s"); string(got.Committed) == "X-100" {
		t.Fatal("StoreAtomic aliased caller committed bytes")
	}
	got := s.Load("s")
	got.Committed[0] = 'Z'
	if got2 := s.Load("s"); got2.Committed[0] == 'Z' {
		t.Fatal("Load returned aliased store bytes")
	}
}

// TestNoteObservedDeepCopy covers aliasing: NoteObserved deep-copies Base
// and Result so caller mutation cannot affect reconciler state.
func TestNoteObservedDeepCopy(t *testing.T) {
	rec := NewCheckpointReconciler(ReconcilerConfig{TickInterval: 0, MaxStreamsPerTick: 8})
	base := []byte("base-1")
	result := []byte("res-1")
	rec.NoteObserved(Checkpoint{Stream: "s", Generation: 1, Base: base, Result: result})
	base[0] = 'X'
	result[0] = 'X'
	found := rec.Tick(time.Now(), func(stream string) ([]byte, uint64, bool) {
		return []byte("res-1"), 1, true
	})
	if len(found) != 0 {
		t.Fatalf("mutated caller bytes must not affect observed state, got %v", found)
	}
}

func TestReconcilerTickDoesNotCopyOwnedCursors(t *testing.T) {
	allocations := func(cursor []byte) float64 {
		rec := NewCheckpointReconciler(ReconcilerConfig{MaxStreamsPerTick: 1})
		rec.NoteObserved(Checkpoint{Stream: "s", Generation: 1, Base: cursor, Result: cursor})
		return testing.AllocsPerRun(20, func() {
			if gaps := rec.Tick(time.Now(), func(string) ([]byte, uint64, bool) {
				return cursor, 1, true
			}); len(gaps) != 0 {
				t.Fatalf("converged checkpoint reported gaps: %v", gaps)
			}
		})
	}
	empty, large := allocations(nil), allocations(make([]byte, 64*1024))
	if large > empty {
		t.Fatalf("Tick copied owned cursor buffers: empty=%.0f allocations, large=%.0f", empty, large)
	}
}

func TestReconcilerTickSnapshotSurvivesReplacement(t *testing.T) {
	rec := NewCheckpointReconciler(ReconcilerConfig{MaxStreamsPerTick: 1})
	rec.NoteObserved(Checkpoint{Stream: "s", Generation: 1, Result: []byte("res-1")})
	if gaps := rec.Tick(time.Now(), func(stream string) ([]byte, uint64, bool) {
		rec.Forget(stream)
		rec.NoteObserved(Checkpoint{Stream: stream, Generation: 2, Result: []byte("res-2")})
		return []byte("res-1"), 1, true
	}); len(gaps) != 0 {
		t.Fatalf("replacement mutated in-progress snapshot: %v", gaps)
	}
	if gaps := rec.Tick(time.Now(), func(string) ([]byte, uint64, bool) {
		return []byte("res-2"), 2, true
	}); len(gaps) != 0 {
		t.Fatalf("replacement not visible on next tick: %v", gaps)
	}
}

// TestDuplicateCacheBounded covers bounded duplicate suppression: hits avoid
// re-apply, overflow evicts oldest first.
func TestDuplicateCacheBounded(t *testing.T) {
	c := NewDuplicateCache(2)
	c.Insert([]byte("a"))
	c.Insert([]byte("b"))
	if !c.Contains([]byte("a")) {
		t.Fatal("expected hit")
	}
	c.Insert([]byte("c"))
	if c.Contains([]byte("a")) {
		t.Fatal("oldest must be evicted first")
	}
	if !c.Contains([]byte("b")) || !c.Contains([]byte("c")) {
		t.Fatal("recent entries must be retained")
	}
	if c.Len() != 2 {
		t.Fatalf("len = %d, want 2", c.Len())
	}
}

// TestStagedSnapshotFailure covers snapshot failure: incomplete install
// fails without advancing, boundary mismatch fails.
func TestStagedSnapshotFailure(t *testing.T) {
	s, err := NewStagedSnapshot([]byte("h1"), []byte("b-100"), 2, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.StagePage(0, []byte("half"), []byte("b-100")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Install(); err == nil {
		t.Fatal("incomplete install must fail")
	}
	if err := s.StagePage(1, []byte("x"), []byte("other")); err == nil {
		t.Fatal("boundary mismatch must fail")
	}
	if err := s.StagePage(1, []byte("rest"), []byte("b-100")); err != nil {
		t.Fatal(err)
	}
	out, err := s.Install()
	if err != nil || string(out) != "halfrest" {
		t.Fatalf("install = %q, %v", out, err)
	}
}

// TestDirectedDeliveryIsolation covers targeted delivery: a batch routed to
// one principal is never visible to another (no NotifyAll broadcast).
func TestDirectedDeliveryIsolation(t *testing.T) {
	pA := newPair(t, testClientConfig(), testHostConfig())
	defer pA.Cleanup()
	pB := newPair(t, testClientConfig(), testHostConfig())
	defer pB.Cleanup()

	// Directed send at a non-member principal is a no-op for both pairs.
	if err := pA.host.NotifyDirected("no-such-principal", []byte("x")); err != nil {
		t.Fatal(err)
	}
	select {
	case ntf := <-pA.client.Notifications():
		t.Fatalf("isolation violated: untargeted notification arrived: %q", ntf.GetPayload())
	case <-time.After(150 * time.Millisecond):
	}
	select {
	case ntf := <-pB.client.Notifications():
		t.Fatalf("isolation violated on peer: %q", ntf.GetPayload())
	case <-time.After(150 * time.Millisecond):
	}

	// Broadcast still works as the non-recovery path; drivers must not use
	// it for recovery batches.
	if err := pA.host.NotifyAll([]byte("broadcast-ok")); err != nil {
		t.Fatal(err)
	}
	select {
	case ntf := <-pA.client.Notifications():
		if string(ntf.GetPayload()) != "broadcast-ok" {
			t.Fatalf("broadcast = %q", ntf.GetPayload())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("broadcast never arrived")
	}
}

// TestDirectedDeliveryTargeted covers positive targeted delivery: with two
// connections bound to distinct principals on one Host, NotifyDirected to
// one existing principal arrives exactly on that principal's client while
// the other client's stream stays silent.
func TestDirectedDeliveryTargeted(t *testing.T) {
	// Principal is derived from the hello credential so two clients on one
	// Host bind distinct principals.
	policy := func(ctx context.Context, credential []byte) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", NewRpcError(ErrorCodeUnavailable, "syntra: policy context ended")
		}
		return "principal-" + string(credential), nil
	}
	mkHost := func() *Host {
		t.Helper()
		h, err := OpenHost(HostConfig{
			MinVersion: 1, MaxVersion: 1, Policy: policy, Handler: echoHandler,
		})
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	mkClient := func(cred string) (*Client, context.CancelFunc, chan error, Transport, Transport) {
		t.Helper()
		ccfg := testClientConfig()
		ccfg.Credential = []byte(cred)
		c, err := OpenClient(ccfg)
		if err != nil {
			t.Fatal(err)
		}
		return c, nil, nil, nil, nil
	}
	_ = mkClient
	host := mkHost()
	defer host.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	openConn := func(cred string) (*Client, Transport, Transport, chan error) {
		t.Helper()
		ccfg := testClientConfig()
		ccfg.Credential = []byte(cred)
		c, err := OpenClient(ccfg)
		if err != nil {
			t.Fatal(err)
		}
		a, b := LoopbackPair()
		runErr := make(chan error, 1)
		serveErr := make(chan error, 1)
		go func() { serveErr <- host.Serve(ctx, a) }()
		go func() { runErr <- c.Run(ctx, b) }()
		t.Cleanup(func() {
			cancel()
			_ = c.Close()
			_ = a.Close()
			_ = b.Close()
			select {
			case <-runErr:
			case <-time.After(3 * time.Second):
			}
			select {
			case <-serveErr:
			case <-time.After(3 * time.Second):
			}
		})
		warm, wstop := context.WithTimeout(ctx, 3*time.Second)
		defer wstop()
		for {
			out, err := c.Call(warm, "/example.Echo/Echo", []byte("warmup"), 1000)
			if err == nil && string(out) == "warmup" {
				break
			}
			if warm.Err() != nil {
				t.Fatalf("handshake never completed for %q: %v", cred, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		return c, a, b, runErr
	}

	alice, _, _, _ := openConn("alice")
	bob, _, _, _ := openConn("bob")

	// Drain any handshake-time notifications (there are none, but guard the
	// targeted assertion against leftovers).
	drain := func(c *Client) {
		for {
			select {
			case <-c.Notifications():
			default:
				return
			}
		}
	}
	drain(alice)
	drain(bob)

	if err := host.NotifyDirected("principal-alice", []byte("for-alice")); err != nil {
		t.Fatal(err)
	}
	select {
	case ntf := <-alice.Notifications():
		if string(ntf.GetPayload()) != "for-alice" {
			t.Fatalf("targeted = %q, want for-alice", ntf.GetPayload())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("targeted notification never arrived on alice")
	}
	select {
	case ntf := <-bob.Notifications():
		t.Fatalf("isolation violated: bob received %q", ntf.GetPayload())
	case <-time.After(200 * time.Millisecond):
	}
}

// TestCheckpointReconciliationIdlePeers covers bounded checkpoint
// reconciliation: a missing final update is discovered without requiring
// another update, while idle peers stay quiet once converged. Tick is
// independently scheduled (interval-gated) and bounded per tick. Both the
// result bytes and the continuity generation are compared: a generation
// bump with identical bytes still reports.
func TestCheckpointReconciliationIdlePeers(t *testing.T) {
	rec := NewCheckpointReconciler(ReconcilerConfig{TickInterval: 0, MaxStreamsPerTick: 8})
	rec.NoteObserved(Checkpoint{Stream: "s", Generation: 7, Base: []byte("c-40"), Result: []byte("c-43")})
	committed := map[string]CommittedPosition{"s": {Stream: "s", Generation: 7, Committed: []byte("c-40")}}
	lookup := func(stream string) ([]byte, uint64, bool) {
		pos, ok := committed[stream]
		if !ok {
			return nil, 0, false
		}
		return pos.Committed, pos.Generation, true
	}
	found := rec.Tick(time.Now(), lookup)
	if len(found) != 1 || found[0] != "s" {
		t.Fatalf("reconciliation must discover missing final update, got %v", found)
	}
	committed["s"] = CommittedPosition{Stream: "s", Generation: 7, Committed: []byte("c-43")}
	if found := rec.Tick(time.Now(), lookup); len(found) != 0 {
		t.Fatalf("converged streams must stay quiet, got %v", found)
	}
	// Same bytes but a generation bump still needs recovery: the continuity
	// epoch moved even though the cursor compares equal.
	rec.NoteObserved(Checkpoint{Stream: "s", Generation: 8, Base: []byte("c-43"), Result: []byte("c-43")})
	if found := rec.Tick(time.Now(), lookup); len(found) != 1 {
		t.Fatalf("generation mismatch must report, got %v", found)
	}
	committed["s"] = CommittedPosition{Stream: "s", Generation: 8, Committed: []byte("c-43")}
	if found := rec.Tick(time.Now(), lookup); len(found) != 0 {
		t.Fatalf("generation-converged streams must stay quiet, got %v", found)
	}
}

// TestReconcilerTickIgnoresCallbackReentrancy covers the no-deadlock
// contract: the committed callback may call back into NoteObserved/Forget
// (Tick holds no lock across the callback).
func TestReconcilerTickIgnoresCallbackReentrancy(t *testing.T) {
	rec := NewCheckpointReconciler(ReconcilerConfig{TickInterval: 0, MaxStreamsPerTick: 8})
	rec.NoteObserved(Checkpoint{Stream: "s", Generation: 1, Result: []byte("r-new")})
	done := make(chan []string, 1)
	go func() {
		got := rec.Tick(time.Now(), func(stream string) ([]byte, uint64, bool) {
			// Re-entrant reconciler use from inside the callback must not
			// deadlock.
			rec.NoteObserved(Checkpoint{Stream: "s", Generation: 1, Result: []byte("r-new")})
			rec.Forget("other")
			return []byte("r-old"), 1, true
		})
		done <- got
	}()
	select {
	case got := <-done:
		if len(got) != 1 || got[0] != "s" {
			t.Fatalf("re-entrant tick = %v, want [s]", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Tick deadlocked across callback")
	}
}

// TestReconcilerBoundedTick covers the per-tick bound and schedule gate.
func TestReconcilerBoundedTick(t *testing.T) {
	rec := NewCheckpointReconciler(ReconcilerConfig{TickInterval: time.Hour, MaxStreamsPerTick: 1})
	rec.NoteObserved(Checkpoint{Stream: "a", Generation: 1, Result: []byte("r1")})
	rec.NoteObserved(Checkpoint{Stream: "b", Generation: 1, Result: []byte("r2")})
	lookup := func(stream string) ([]byte, uint64, bool) { return []byte("old"), 1, true }
	if got := rec.Tick(time.Now(), lookup); len(got) != 1 {
		t.Fatalf("tick must be bounded to 1, got %v", got)
	}
	if got := rec.Tick(time.Now(), lookup); len(got) != 0 {
		t.Fatalf("schedule gate must suppress close ticks, got %v", got)
	}
}

// TestLossTotalsCumulativeNoDoubleCount covers unified loss semantics on the
// public queue: cumulative counts/bytes advance exactly once per drop and
// loss-change wakeups observe the same totals without double-counting.
func TestLossTotalsCumulativeNoDoubleCount(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	d0, b0 := p.client.LossTotals()
	for i := 0; i < 64; i++ {
		_ = p.host.NotifyAll([]byte("x"))
	}
	// A terminal RPC result follows the previously queued notifications on
	// this connection. Wait for it before sampling totals so the pump cannot
	// still be recording the tail of the burst during the idle assertion.
	barrier, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if _, err := p.client.Call(barrier, "/example.Echo/Echo", nil, 1000); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if d, _ := p.client.LossTotals(); d != d0 {
			break
		}
		if time.Now().After(deadline) {
			d, b := p.client.LossTotals()
			t.Fatalf("loss totals never advanced (d0=%d b0=%d totals=(%d,%d))", d0, b0, d, b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	d1, b1 := p.client.LossTotals()
	if d1 <= d0 {
		t.Fatalf("dropped did not advance: %d -> %d", d0, d1)
	}
	if b1 <= b0 {
		t.Fatalf("dropped bytes did not advance: %d -> %d", b0, b1)
	}
	if got := p.client.DroppedNotifications(); got != d1-pureGoCoreDropped(p.client) {
		t.Fatalf("public drops inconsistent: public=%d totals=(%d,%d)", got, d1, b1)
	}
	// Late subscriber with stale totals returns immediately with current
	// totals and no error (no double-counting, no missed signal).
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	d2, b2, err := p.client.WaitLossChange(ctx, d0, b0)
	if err != nil {
		t.Fatalf("WaitLossChange with stale totals = %d,%d,%v", d2, b2, err)
	}
	if d2 != d1 || b2 != b1 {
		t.Fatalf("WaitLossChange = (%d,%d), want current totals (%d,%d)", d2, b2, d1, b1)
	}
	// A waiter already at current totals blocks: with no further loss it
	// ends via ctx expiry (wakeups fire on change, not spuriously).
	short, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, _, err := p.client.WaitLossChange(short, d1, b1); err == nil {
		t.Fatal("WaitLossChange at current totals must block until change or ctx end")
	}
}

// pureGoCoreDropped returns core-layer drops for the consistency check
// above (zero under the native adapter when the FFI core holds them).
func pureGoCoreDropped(c *Client) uint64 {
	if c == nil || c.core == nil {
		return 0
	}
	d, _ := c.core.lossTotals()
	return d
}

// TestWaitLossChangeBroadcastsToAllWaiters covers the broadcast contract: a
// single drop wakes every concurrent WaitLossChange waiter, not just one
// token consumer.
func TestWaitLossChangeBroadcastsToAllWaiters(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	defer p.Cleanup()
	d0, b0 := p.client.LossTotals()
	const waiters = 4
	type result struct {
		d, b uint64
		err  error
	}
	results := make(chan result, waiters)
	for i := 0; i < waiters; i++ {
		go func() {
			ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			d, b, err := p.client.WaitLossChange(ctx, d0, b0)
			results <- result{d: d, b: b, err: err}
		}()
	}
	// Let all waiters subscribe, then force one drop burst.
	time.Sleep(100 * time.Millisecond)
	for i := 0; i < 64; i++ {
		_ = p.host.NotifyAll([]byte("broadcast-wakeup"))
	}
	for i := 0; i < waiters; i++ {
		select {
		case r := <-results:
			if r.err != nil {
				t.Fatalf("waiter %d: %v", i, r.err)
			}
			if r.d == d0 && r.b == b0 {
				t.Fatalf("waiter %d woke without totals advancing", i)
			}
		case <-time.After(4 * time.Second):
			t.Fatalf("waiter %d never woke (single-token channel would strand it)", i)
		}
	}
}

// TestLossTotalsMonotonicAfterClose covers Close caching: totals sampled
// before Close must not regress after Close even though the underlying core
// (FFI) reports zero once its handle is destroyed.
func TestLossTotalsMonotonicAfterClose(t *testing.T) {
	p := newPair(t, testClientConfig(), testHostConfig())
	for i := 0; i < 64; i++ {
		_ = p.host.NotifyAll([]byte("x"))
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if d, _ := p.client.LossTotals(); d > 0 {
			break
		}
		if time.Now().After(deadline) {
			d, b := p.client.LossTotals()
			t.Fatalf("loss totals never advanced: (%d,%d)", d, b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	beforeD, beforeB := p.client.LossTotals()
	// Run's deferred close path and explicit Close both snapshot; call the
	// public Close and assert monotonicity rather than a drop to zero.
	p.cancel()
	_ = p.client.Close()
	afterD, afterB := p.client.LossTotals()
	if afterD < beforeD || afterB < beforeB {
		t.Fatalf("LossTotals regressed across Close: (%d,%d) -> (%d,%d)", beforeD, beforeB, afterD, afterB)
	}
}
