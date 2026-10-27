package syntra

import (
	"fmt"
	"testing"
	"time"
)

func testReliableManager(t *testing.T) *ReliableManager {
	t.Helper()
	m, err := NewReliableManager(DefaultControlBounds())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestReliableSessionIdentityDistinct(t *testing.T) {
	if _, err := ValidateSessionID(make([]byte, 15)); err == nil {
		t.Fatal("short session id accepted")
	}
	if _, err := ValidateSessionID(make([]byte, 16)); err == nil {
		t.Fatal("zero session id accepted")
	}
	ok := make([]byte, 16)
	for i := range ok {
		ok[i] = byte(i + 1)
	}
	if _, err := ValidateSessionID(ok); err != nil {
		t.Fatalf("valid session id rejected: %v", err)
	}
}

func TestReliableEpochFencing(t *testing.T) {
	if err := ValidateEpoch(0); err == nil {
		t.Fatal("zero epoch accepted")
	}
	if err := CheckEpochAdvance(3, 3); err == nil {
		t.Fatal("stale epoch accepted")
	}
	if _, err := NextEpoch(^uint64(0)); err == nil {
		t.Fatal("epoch wrap accepted")
	}
}

func TestReliableLeaseNegotiation(t *testing.T) {
	got, err := NegotiateLease(LeaseProposal{})
	if err != nil {
		t.Fatal(err)
	}
	if got.KeepaliveIntervalMs >= got.IdleTimeoutMs {
		t.Fatal("keepalive not below idle")
	}
	if _, err := NegotiateLease(LeaseProposal{IdleTimeoutMs: 1, KeepaliveIntervalMs: 1000}); err == nil {
		t.Fatal("under-minimum idle accepted")
	}
}

func TestReliableAttachFencesOld(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, epoch, cred, _ := mustCreate(t, m, now)
	if epoch != 1 {
		t.Fatalf("epoch = %d, want 1", epoch)
	}
	if _, _, _, _, err := m.Attach(now, sid, nil, "conn-1", "svc-a", 1, LeaseProposal{}); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	epoch2, _, fenced, fresh, err := m.Attach(now, sid, cred, "conn-2", "svc-a", 1, LeaseProposal{})
	if err != nil {
		t.Fatalf("resume: %v", err)
	}
	if epoch2 != 2 || fenced != "conn-1" {
		t.Fatalf("epoch2=%d fenced=%q", epoch2, fenced)
	}
	if len(fresh) == 0 {
		t.Fatal("resume did not rotate credential")
	}
	if _, _, _, _, err := m.Attach(now, sid, cred, "conn-3", "svc-a", 1, LeaseProposal{}); err == nil {
		t.Fatal("rotated handle replay accepted")
	}
	epoch3, _, fenced3, fresh3, err := m.Attach(now, sid, fresh, "conn-3", "svc-a", 1, LeaseProposal{})
	if err != nil {
		t.Fatalf("second resume with rotated credential: %v", err)
	}
	if epoch3 != 3 || fenced3 != "conn-2" {
		t.Fatalf("epoch3=%d fenced=%q, want 3/conn-2", epoch3, fenced3)
	}
	if len(fresh3) == 0 || string(fresh3) == string(fresh) {
		t.Fatal("second resume did not rotate credential")
	}
}

func mustCreate(t *testing.T, m *ReliableManager, now time.Time) (SessionID, uint64, []byte, ConfirmedLease) {
	t.Helper()
	sid, epoch, cred, lease, err := m.CreateSession(now, "svc-a", 1, LeaseProposal{})
	if err != nil {
		t.Fatal(err)
	}
	return sid, epoch, cred, lease
}

func TestReliableReconciliation(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, _, _, _ := mustCreate(t, m, now)
	if _, _, _, _, err := m.Attach(now, sid, nil, "conn-1", "svc-a", 1, LeaseProposal{}); err != nil {
		t.Fatal(err)
	}
	var did DeliveryID
	for i := range did {
		did[i] = 7
	}
	if out, _, err := m.Reconcile(now, sid, did); err != nil || out != ReconcileUnknown {
		t.Fatalf("out=%v err=%v", out, err)
	}
	okOutcome := StoredOutcome{Payload: []byte("hello")}
	if _, err := m.RecordResult(now, sid, 1, did, "/example.Echo/Echo", []byte("hello"), okOutcome); err != nil {
		t.Fatal(err)
	}
	if out, stored, err := m.Reconcile(now, sid, did); err != nil || out != ReconcileRetained || stored == nil {
		t.Fatalf("out=%v err=%v", out, err)
	}
	if _, err := m.RecordResult(now, sid, 1, did, "/example.Echo/Echo", []byte("different"), okOutcome); err == nil {
		t.Fatal("mismatched content accepted")
	}
}

func TestReliableSignalsMapToExistingCodes(t *testing.T) {
	if SignalCode(SignalOverloaded) != ErrorCodeResourceExhausted {
		t.Fatal("overloaded must map to RESOURCE_EXHAUSTED")
	}
	if SignalCode(SignalFenced) != ErrorCodeFailedPrecondition {
		t.Fatal("fenced must map to FAILED_PRECONDITION")
	}
	if _, err := ParseSessionSignal("nope"); err == nil {
		t.Fatal("unknown signal accepted")
	}
}

func TestReliableZeroDeliveryIDRejected(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, _, _, _ := mustCreate(t, m, now)
	var zero DeliveryID
	if _, err := m.RecordResult(now, sid, 1, zero, "/example.Echo/Echo", []byte("x"), StoredOutcome{Payload: []byte("x")}); err == nil {
		t.Fatal("zero delivery id accepted by RecordResult")
	}
	if _, _, err := m.Reconcile(now, sid, zero); err == nil {
		t.Fatal("zero delivery id accepted by Reconcile")
	}
	if err := m.RecordTombstone(now, sid, zero, ErrorCodeDeadlineExceeded); err == nil {
		t.Fatal("zero delivery id accepted by RecordTombstone")
	}
	if _, _, err := m.TombstoneOf(now, sid, zero); err == nil {
		t.Fatal("zero delivery id accepted by TombstoneOf")
	}
	if _, err := m.Forget(sid, zero); err == nil {
		t.Fatal("zero delivery id accepted by Forget")
	}
}

func TestReliableIdleTimeoutDetaches(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, _, _, _ := mustCreate(t, m, now)
	lease, err := NegotiateLease(LeaseProposal{IdleTimeoutMs: 2000, KeepaliveIntervalMs: 1000})
	if err != nil {
		t.Fatal(err)
	}
	_ = lease
	if _, _, _, _, err := m.Attach(now, sid, nil, "conn-1", "svc-a", 1, LeaseProposal{IdleTimeoutMs: 2000, KeepaliveIntervalMs: 1000}); err != nil {
		t.Fatal(err)
	}
	if idle, err := m.CheckIdle(now, sid); err != nil || idle {
		t.Fatalf("fresh session must not be idle: idle=%v err=%v", idle, err)
	}
	later := now.Add(2100 * time.Millisecond)
	if idle, err := m.CheckIdle(later, sid); err != nil || !idle {
		t.Fatalf("stale session must be idle: idle=%v err=%v", idle, err)
	}
	swept, err := m.SweepIdle(later)
	if err != nil {
		t.Fatalf("SweepIdle: %v", err)
	}
	if len(swept) != 1 || swept[0] != sid {
		t.Fatalf("SweepIdle = %v, want [%v]", swept, sid)
	}
	signals := m.DrainSignals(16)
	found := false
	for _, s := range signals {
		if s.ID == sid && s.Signal == SignalIdleTimeout {
			found = true
		}
	}
	if !found {
		t.Fatalf("IdleTimeout signal missing: %v", signals)
	}
	// Reap path also enforces idle: re-attach, go stale, reap, expect detach.
	if _, _, _, _, err := m.Attach(later, sid, nil, "conn-2", "svc-a", 1, LeaseProposal{IdleTimeoutMs: 2000, KeepaliveIntervalMs: 1000}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := m.ReapExpired(later.Add(2100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	stillIdle, err := m.CheckIdle(later.Add(2100*time.Millisecond), sid)
	if err != nil {
		t.Fatal(err)
	}
	if stillIdle {
		t.Fatal("reap must have detached the idle active")
	}
}

func TestReliableFencedSignalFullQueue(t *testing.T) {
	bounds := DefaultControlBounds()
	bounds.MaxControlQueue = 1
	bounds.MaxControlBytes = 64
	m, err := NewReliableManager(bounds)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sid, _, cred, _ := mustCreate(t, m, now)
	if _, _, _, _, err := m.Attach(now, sid, nil, "conn-1", "svc-a", 1, LeaseProposal{}); err != nil {
		t.Fatal(err)
	}
	// Fill the control queue so the Fenced signal has nowhere to go.
	if err := m.Signal(sid, SignalOverloaded); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := m.Attach(now, sid, cred, "conn-2", "svc-a", 1, LeaseProposal{}); err == nil {
		t.Fatal("attach with full control queue must propagate ResourceExhausted, not swallow Fenced")
	} else if rerr, ok := err.(*RpcError); !ok || rerr.Code != ErrorCodeResourceExhausted {
		t.Fatalf("attach full-queue = %v, want RESOURCE_EXHAUSTED", err)
	}
}

func TestReliableDrainForShutdownReportsDropped(t *testing.T) {
	bounds := DefaultControlBounds()
	bounds.MaxControlQueue = 1
	bounds.MaxControlBytes = 64
	m, err := NewReliableManager(bounds)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sid, _, _, _ := mustCreate(t, m, now)
	if _, _, _, _, err := m.Attach(now, sid, nil, "conn-1", "svc-a", 1, LeaseProposal{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Signal(sid, SignalOverloaded); err != nil {
		t.Fatal(err)
	}
	ids, signals, dropped, derr := m.DrainForShutdown()
	if derr == nil {
		t.Fatal("DrainForShutdown with full queue must report the dropped GoingAway signal")
	}
	if len(ids) != 1 {
		t.Fatalf("drained ids = %v", ids)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	_ = signals
}

func TestReliableExpiredRetainedReinsert(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, _, _, _ := mustCreate(t, m, now)
	var did DeliveryID
	for i := range did {
		did[i] = 9
	}
	if _, err := m.RecordResult(now, sid, 1, did, "/example.Echo/Echo", []byte("one"), StoredOutcome{Payload: []byte("one")}); err != nil {
		t.Fatal(err)
	}
	later := now.Add(DefaultControlBounds().ResultRetention + time.Second)
	// Expired entry must not behave as a duplicate: the new insert with
	// different content succeeds and becomes Retained.
	if _, err := m.RecordResult(later, sid, 1, did, "/example.Echo/Echo", []byte("two"), StoredOutcome{Payload: []byte("two")}); err != nil {
		t.Fatalf("expired retained must allow reinsert, got %v", err)
	}
	out, stored, err := m.Reconcile(later, sid, did)
	if err != nil || out != ReconcileRetained || stored == nil || string(stored.Payload) != "two" {
		t.Fatalf("reinsert = %v %v %v", out, stored, err)
	}
}

func TestReliableOutcomeDeepCopy(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, _, _, _ := mustCreate(t, m, now)
	var did DeliveryID
	for i := range did {
		did[i] = 11
	}
	payload := []byte("mutable")
	outcome := StoredOutcome{Payload: payload}
	if _, err := m.RecordResult(now, sid, 1, did, "/example.Echo/Echo", []byte("m"), outcome); err != nil {
		t.Fatal(err)
	}
	payload[0] = 'X'
	outcome.Payload[0] = 'X'
	_, stored, err := m.Reconcile(now, sid, did)
	if err != nil || stored == nil {
		t.Fatal(err)
	}
	if string(stored.Payload) == "Xutable" {
		t.Fatal("RecordResult aliased caller payload")
	}
	stored.Payload[0] = 'Z'
	_, stored2, err := m.Reconcile(now, sid, did)
	if err != nil || stored2 == nil {
		t.Fatal(err)
	}
	if stored2.Payload[0] == 'Z' {
		t.Fatal("Reconcile returned aliased retained bytes")
	}
	// Err pointer aliasing: mutating the caller's RpcError must not affect
	// retained state, and vice versa.
	var did2 DeliveryID
	for i := range did2 {
		did2[i] = 12
	}
	rerr := NewRpcError(ErrorCodeNotFound, "orig")
	if _, err := m.RecordResult(now, sid, 1, did2, "/example.Echo/Echo", []byte("m"), StoredOutcome{Err: rerr}); err != nil {
		t.Fatal(err)
	}
	rerr.Message = "mutated"
	_, stored3, err := m.Reconcile(now, sid, did2)
	if err != nil || stored3 == nil || stored3.Err == nil {
		t.Fatal(err)
	}
	if stored3.Err.Message == "mutated" {
		t.Fatal("RecordResult aliased caller RpcError")
	}
	stored3.Err.Code = ErrorCodeInternal
	stored3.Err.Message = "returned mutation"
	_, stored4, err := m.Reconcile(now, sid, did2)
	if err != nil || stored4 == nil || stored4.Err == nil || stored4.Err.Code != ErrorCodeNotFound || stored4.Err.Message != "orig" {
		t.Fatalf("Reconcile aliased retained RpcError: stored=%v err=%v", stored4, err)
	}
}

func requireReliableCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	if rpc, ok := err.(*RpcError); !ok || rpc.Code != code {
		t.Fatalf("error = %v, want %v", err, code)
	}
}

func attachForReview(t *testing.T, m *ReliableManager, now time.Time) (SessionID, uint64, []byte) {
	t.Helper()
	sid, _, cred, _ := mustCreate(t, m, now)
	epoch, _, _, _, err := m.Attach(now, sid, nil, "conn-1", "svc-a", 1, LeaseProposal{})
	if err != nil {
		t.Fatal(err)
	}
	return sid, epoch, cred
}

func TestReliableReviewPendingContentAndLifetime(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, epoch, _ := attachForReview(t, m, now)
	did := DeliveryID{1}
	payload := []byte("request")
	if err := m.NoteDispatch(now, sid, epoch, did, "echo", payload); err != nil {
		t.Fatal(err)
	}
	payload[0] = 'X'
	if err := m.NoteDispatch(now, sid, epoch, did, "echo", []byte("request")); err != nil {
		t.Fatalf("identical duplicate rejected (or payload aliased): %v", err)
	}
	for _, change := range []struct{ method, payload string }{{"other", "request"}, {"echo", "changed"}} {
		t.Run(change.method+change.payload, func(t *testing.T) {
			requireReliableCode(t, m.NoteDispatch(now, sid, epoch, did, change.method, []byte(change.payload)), ErrorCodeFailedPrecondition)
			_, err := m.RecordResult(now, sid, 1, did, change.method, []byte(change.payload), StoredOutcome{})
			requireReliableCode(t, err, ErrorCodeFailedPrecondition)
		})
	}
	if _, err := m.Forget(sid, did); err == nil {
		t.Error("Forget erased live pending work")
	}
	later := now.Add(3 * m.bounds.ResultRetention)
	if _, _, _, err := m.ReapExpired(later); err != nil {
		t.Fatal(err)
	}
	if got, _, err := m.Reconcile(later, sid, did); err != nil || got != ReconcilePending {
		t.Fatalf("live dispatch expired: got=%v err=%v", got, err)
	}
	if _, err := m.RecordResult(later, sid, 1, did, "echo", []byte("request"), StoredOutcome{Payload: []byte("done")}); err != nil {
		t.Fatal(err)
	}
	if got, _, err := m.Reconcile(later, sid, did); err != nil || got != ReconcileRetained {
		t.Fatalf("terminal transition: got=%v err=%v", got, err)
	}
}

func TestReliableReviewDispatchFenceAndActivity(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, epoch, cred := attachForReview(t, m, now)
	newEpoch, _, _, _, err := m.Attach(now, sid, cred, "conn-2", "svc-a", 1, LeaseProposal{})
	if err != nil {
		t.Fatal(err)
	}
	did := DeliveryID{1}
	requireReliableCode(t, m.NoteDispatch(now, sid, 0, did, "echo", nil), ErrorCodeInvalidArgument)
	requireReliableCode(t, m.NoteDispatch(now, sid, epoch, did, "echo", nil), ErrorCodeFailedPrecondition)
	if err := m.NoteDispatch(now.Add(20*time.Second), sid, newEpoch, did, "echo", nil); err != nil {
		t.Fatal(err)
	}
	if idle, err := m.CheckIdle(now.Add(31*time.Second), sid); err != nil || idle {
		t.Errorf("accepted dispatch did not refresh activity: idle=%v err=%v", idle, err)
	}
	m.Detach(sid, "conn-2")
	requireReliableCode(t, m.NoteDispatch(now, sid, newEpoch, did, "echo", nil), ErrorCodeFailedPrecondition)
}

func TestReliableReviewDispatchActivity(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, epoch, _ := attachForReview(t, m, now)
	if err := m.NoteDispatch(now.Add(20*time.Second), sid, epoch, DeliveryID{1}, "echo", nil); err != nil {
		t.Fatal(err)
	}
	if idle, err := m.CheckIdle(now.Add(31*time.Second), sid); err != nil || idle {
		t.Fatalf("dispatch did not refresh activity: idle=%v err=%v", idle, err)
	}
}

func TestReliableReviewStaleDispatchEpoch(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, epoch, cred := attachForReview(t, m, now)
	if _, _, _, _, err := m.Attach(now, sid, cred, "conn-2", "svc-a", 1, LeaseProposal{}); err != nil {
		t.Fatal(err)
	}
	requireReliableCode(t, m.NoteDispatch(now, sid, epoch, DeliveryID{1}, "echo", nil), ErrorCodeFailedPrecondition)
}

func TestReliableReviewPendingSurvivesRetention(t *testing.T) {
	for _, reap := range []bool{false, true} {
		t.Run(fmt.Sprint(reap), func(t *testing.T) {
			m := testReliableManager(t)
			now := time.Now()
			sid, epoch, _ := attachForReview(t, m, now)
			did := DeliveryID{1}
			if err := m.NoteDispatch(now, sid, epoch, did, "echo", nil); err != nil {
				t.Fatal(err)
			}
			if _, err := m.RecordResult(now, sid, 1, did, "other", nil, StoredOutcome{}); err == nil {
				t.Error("terminal result accepted mismatched pending content")
			}
			later := now.Add(3 * m.bounds.ResultRetention)
			if reap {
				if _, _, _, err := m.ReapExpired(later); err != nil {
					t.Fatal(err)
				}
			}
			if got, _, err := m.Reconcile(later, sid, did); err != nil || got != ReconcilePending {
				t.Fatalf("live pending work expired: got=%v err=%v", got, err)
			}
		})
	}
}

func TestReliableReviewPendingBudgets(t *testing.T) {
	for _, kind := range []string{"bytes", "count"} {
		t.Run(kind, func(t *testing.T) {
			bounds := DefaultControlBounds()
			bounds.MaxRetainedBytes = 8
			if kind == "count" {
				bounds.MaxRetainedResults = 1
			}
			m, err := NewReliableManager(bounds)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			sid, epoch, _ := attachForReview(t, m, now)
			did := DeliveryID{1}
			if err := m.NoteDispatch(now, sid, epoch, did, "echo", []byte("data")); err != nil {
				t.Fatal(err)
			}
			requireReliableCode(t, m.NoteDispatch(now, sid, epoch, DeliveryID{2}, "x", nil), ErrorCodeResourceExhausted)
			_, err = m.RecordResult(now, sid, 1, DeliveryID{2}, "x", nil, StoredOutcome{})
			requireReliableCode(t, err, ErrorCodeResourceExhausted)
			// Converting a pending entry reuses its metadata reservation.
			if _, err := m.RecordResult(now, sid, 1, did, "echo", []byte("data"), StoredOutcome{}); err != nil {
				t.Fatalf("pending-to-retained double charged: %v", err)
			}
			requireReliableCode(t, m.NoteDispatch(now, sid, epoch, DeliveryID{2}, "x", nil), ErrorCodeResourceExhausted)
			if _, err := m.Forget(sid, did); err != nil {
				t.Fatal(err)
			}
			if err := m.NoteDispatch(now, sid, epoch, DeliveryID{2}, "x", nil); err != nil {
				t.Fatalf("forget did not release budget: %v", err)
			}
		})
	}
}

func TestReliableReviewFailedResultPreservesTombstone(t *testing.T) {
	for _, kind := range []string{"bytes", "count"} {
		t.Run(kind, func(t *testing.T) {
			bounds := DefaultControlBounds()
			bounds.MaxRetainedBytes = 4
			bounds.MaxRetainedResults = 1
			m, err := NewReliableManager(bounds)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			sid, _, _, _ := mustCreate(t, m, now)
			did := DeliveryID{1}
			if err := m.RecordTombstone(now, sid, did, ErrorCodeCancelled); err != nil {
				t.Fatal(err)
			}
			method := "12345"
			if kind == "count" {
				method = "x"
				if _, err := m.RecordResult(now, sid, 1, DeliveryID{2}, "x", nil, StoredOutcome{}); err != nil {
					t.Fatal(err)
				}
			}
			_, err = m.RecordResult(now, sid, 1, did, method, nil, StoredOutcome{})
			requireReliableCode(t, err, ErrorCodeResourceExhausted)
			if code, ok, err := m.TombstoneOf(now, sid, did); err != nil || !ok || code != ErrorCodeCancelled {
				t.Fatalf("failed admission erased terminal tombstone: code=%v ok=%v err=%v", code, ok, err)
			}
		})
	}
}

func TestReliableReviewFailedResumeIsRetryable(t *testing.T) {
	for _, kind := range []string{"count", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			bounds := DefaultControlBounds()
			if kind == "count" {
				bounds.MaxControlQueue = 1
			} else {
				bounds.MaxControlBytes = 32
			}
			m, err := NewReliableManager(bounds)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			sid, epoch, cred := attachForReview(t, m, now)
			if err := m.Signal(sid, SignalOverloaded); err != nil {
				t.Fatal(err)
			}
			_, _, _, _, err = m.Attach(now, sid, cred, "conn-2", "svc-a", 1, LeaseProposal{})
			requireReliableCode(t, err, ErrorCodeResourceExhausted)
			m.DrainSignals(1)
			next, _, fenced, fresh, err := m.Attach(now, sid, cred, "conn-2", "svc-a", 1, LeaseProposal{})
			if err != nil || next != epoch+1 || fenced != "conn-1" || len(fresh) == 0 {
				t.Fatalf("failed resume consumed credentials or attachment: next=%d fenced=%q err=%v", next, fenced, err)
			}
		})
	}
}

func TestReliableReviewReapReportsQueueError(t *testing.T) {
	bounds := DefaultControlBounds()
	bounds.MaxControlQueue = 1
	bounds.ResultRetention = time.Second
	bounds.TombstoneRetention = time.Second
	m, err := NewReliableManager(bounds)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sid, epoch, _ := attachForReview(t, m, now)
	if _, err := m.RecordResult(now, sid, 1, DeliveryID{1}, "echo", nil, StoredOutcome{}); err != nil {
		t.Fatal(err)
	}
	if err := m.NoteDispatch(now, sid, epoch, DeliveryID{2}, "echo", nil); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordTombstone(now, sid, DeliveryID{3}, ErrorCodeCancelled); err != nil {
		t.Fatal(err)
	}
	if err := m.Signal(sid, SignalOverloaded); err != nil {
		t.Fatal(err)
	}
	later := now.Add(31 * time.Second)
	outcomes, tombstones, resumes, err := m.ReapExpired(later)
	requireReliableCode(t, err, ErrorCodeResourceExhausted)
	if outcomes != 1 || tombstones != 1 || resumes != 0 {
		t.Fatalf("reap counts = %d/%d/%d, want 1/1/0", outcomes, tombstones, resumes)
	}
	if got, _, err := m.Reconcile(later, sid, DeliveryID{2}); err != nil || got != ReconcilePending {
		t.Fatalf("reap erased live pending work: got=%v err=%v", got, err)
	}
	if idle, err := m.CheckIdle(later, sid); err != nil || idle {
		t.Fatalf("reap did not detach idle attachment: idle=%v err=%v", idle, err)
	}
}

func TestReliablePendingTerminalAdmissionAndRelease(t *testing.T) {
	for _, terminal := range []string{"result", "tombstone"} {
		t.Run(terminal, func(t *testing.T) {
			bounds := DefaultControlBounds()
			bounds.MaxRetainedResults = 1
			bounds.MaxRetainedBytes = 8
			bounds.MaxTombstones = 1
			m, err := NewReliableManager(bounds)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			sid, epoch, _ := attachForReview(t, m, now)
			did := DeliveryID{1}
			if err := m.NoteDispatch(now, sid, epoch, did, "echo", []byte("data")); err != nil {
				t.Fatal(err)
			}
			if terminal == "result" {
				_, err = m.RecordResult(now, sid, 1, did, "echo", []byte("data"), StoredOutcome{Payload: []byte("x")})
				requireReliableCode(t, err, ErrorCodeResourceExhausted)
			} else {
				if err := m.RecordTombstone(now.Add(-2*bounds.TombstoneRetention), sid, DeliveryID{9}, ErrorCodeCancelled); err != nil {
					t.Fatal(err)
				}
				requireReliableCode(t, m.RecordTombstone(now, sid, did, ErrorCodeCancelled), ErrorCodeResourceExhausted)
			}
			if got, _, err := m.Reconcile(now, sid, did); err != nil || got != ReconcilePending {
				t.Fatalf("failed terminal admission erased pending: got=%v err=%v", got, err)
			}
			requireReliableCode(t, m.NoteDispatch(now, sid, epoch, DeliveryID{2}, "x", nil), ErrorCodeResourceExhausted)
			if terminal == "result" {
				if _, err := m.RecordResult(now, sid, 1, did, "echo", []byte("data"), StoredOutcome{}); err != nil {
					t.Fatal(err)
				}
				if _, err := m.Forget(sid, did); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, _, _, err := m.ReapExpired(now); err != nil {
					t.Fatal(err)
				}
				if err := m.RecordTombstone(now, sid, did, ErrorCodeCancelled); err != nil {
					t.Fatal(err)
				}
				if got, stored, err := m.Reconcile(now, sid, did); err != nil || got != ReconcileRetained || stored == nil || stored.Err == nil || stored.Err.Code != ErrorCodeCancelled {
					t.Fatalf("pending-to-tombstone: got=%v stored=%v err=%v", got, stored, err)
				}
			}
			if err := m.NoteDispatch(now, sid, epoch, DeliveryID{2}, "echo", []byte("data")); err != nil {
				t.Fatalf("terminal transition leaked pending reservation: %v", err)
			}
		})
	}
}

func TestReliableDispatchRejectsWithoutActivity(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, epoch, _ := attachForReview(t, m, now)
	did := DeliveryID{1}
	if err := m.NoteDispatch(now, sid, epoch, did, "echo", nil); err != nil {
		t.Fatal(err)
	}
	requireReliableCode(t, m.NoteDispatch(now.Add(20*time.Second), sid, epoch, did, "changed", nil), ErrorCodeFailedPrecondition)
	if idle, err := m.CheckIdle(now.Add(31*time.Second), sid); err != nil || !idle {
		t.Fatalf("rejected duplicate refreshed activity: idle=%v err=%v", idle, err)
	}
	requireReliableCode(t, m.NoteDispatch(now.Add(31*time.Second), sid, epoch, did, "echo", nil), ErrorCodeFailedPrecondition)
	requireReliableCode(t, m.NoteDispatch(now, sid, epoch, DeliveryID{}, "echo", nil), ErrorCodeInvalidArgument)
	requireReliableCode(t, m.NoteDispatch(now, sid, epoch, DeliveryID{2}, "echo", make([]byte, MaxFrameBytes+1)), ErrorCodeResourceExhausted)
	if _, _, _, err := m.DrainForShutdown(); err != nil {
		t.Fatal(err)
	}
	requireReliableCode(t, m.NoteDispatch(now, sid, epoch, did, "echo", nil), ErrorCodeUnavailable)
	// Shutdown stops admission but still permits already-dispatched completion.
	if _, err := m.RecordResult(now, sid, 1, did, "echo", nil, StoredOutcome{}); err != nil {
		t.Fatal(err)
	}
}

func TestReliableReviewShutdownDroppedCount(t *testing.T) {
	bounds := DefaultControlBounds()
	bounds.MaxControlQueue = 1
	m, err := NewReliableManager(bounds)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for i := 0; i < 3; i++ {
		attachForReview(t, m, now)
	}
	ids, signals, dropped, err := m.DrainForShutdown()
	requireReliableCode(t, err, ErrorCodeResourceExhausted)
	if len(ids) != 3 || len(signals) != 1 || dropped != 2 {
		t.Fatalf("drain counts: ids=%d signals=%d dropped=%d", len(ids), len(signals), dropped)
	}
	ids, signals, dropped, err = m.DrainForShutdown()
	if err != nil || len(ids) != 0 || len(signals) != 0 || dropped != 0 {
		t.Fatalf("repeat drain: ids=%d signals=%d dropped=%d err=%v", len(ids), len(signals), dropped, err)
	}
}

func TestReliableInsertClearsForgotten(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, _, _, _ := mustCreate(t, m, now)
	var did DeliveryID
	for i := range did {
		did[i] = 13
	}
	if _, err := m.RecordResult(now, sid, 1, did, "/example.Echo/Echo", []byte("x"), StoredOutcome{Payload: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Forget(sid, did); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := m.Reconcile(now, sid, did); out != ReconcileForgotten {
		t.Fatalf("after forget = %v, want forgotten", out)
	}
	if _, err := m.RecordResult(now, sid, 1, did, "/example.Echo/Echo", []byte("x"), StoredOutcome{Payload: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if out, _, _ := m.Reconcile(now, sid, did); out != ReconcileRetained {
		t.Fatalf("reinsert after forget = %v, want retained", out)
	}
}

func TestReliableExpiredTombstoneBecomesForgotten(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, _, _, _ := mustCreate(t, m, now)
	var did DeliveryID
	for i := range did {
		did[i] = 14
	}
	if err := m.RecordTombstone(now, sid, did, ErrorCodeDeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	later := now.Add(DefaultControlBounds().TombstoneRetention + time.Second)
	out, _, err := m.Reconcile(later, sid, did)
	if err != nil || out != ReconcileForgotten {
		t.Fatalf("expired tombstone reconcile = %v %v, want forgotten", out, err)
	}
	if out2, _, _ := m.Reconcile(later, sid, did); out2 != ReconcileForgotten {
		t.Fatalf("second reconcile = %v, want forgotten", out2)
	}
}

func TestReliableTombstoneFirstWriteWins(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, _, _, _ := mustCreate(t, m, now)
	var did DeliveryID
	for i := range did {
		did[i] = 15
	}
	if err := m.RecordTombstone(now, sid, did, ErrorCodeDeadlineExceeded); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordTombstone(now, sid, did, ErrorCodeDeadlineExceeded); err != nil {
		t.Fatalf("same-code tombstone must be idempotent: %v", err)
	}
	if err := m.RecordTombstone(now, sid, did, ErrorCodeCancelled); err == nil {
		t.Fatal("code-mismatched tombstone must be rejected without overwriting")
	}
	code, ok, err := m.TombstoneOf(now, sid, did)
	if err != nil || !ok || code != ErrorCodeDeadlineExceeded {
		t.Fatalf("tombstone overwritten: code=%v ok=%v err=%v", code, ok, err)
	}
}

func seedReliableDispatchMarker(t *testing.T, m *ReliableManager, now time.Time, sid SessionID, epoch uint64, did DeliveryID, kind string) {
	t.Helper()
	switch kind {
	case "result":
		if _, err := m.RecordResult(now, sid, epoch, did, "old", []byte("x"), StoredOutcome{Payload: []byte("done")}); err != nil {
			t.Fatal(err)
		}
	case "tombstone":
		// Seed via dispatch so the tombstone retains the request digest for
		// live duplicate-content validation ("old"/"x").
		if err := m.NoteDispatch(now, sid, epoch, did, "old", []byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := m.RecordTombstone(now, sid, did, ErrorCodeCancelled); err != nil {
			t.Fatal(err)
		}
	case "forgotten":
		if _, err := m.RecordResult(now.Add(-2*m.bounds.ResultRetention), sid, epoch, did, "old", []byte("x"), StoredOutcome{Payload: []byte("done")}); err != nil {
			t.Fatal(err)
		}
		if got, _, err := m.Reconcile(now, sid, did); err != nil || got != ReconcileForgotten {
			t.Fatalf("seed forgotten: got=%v err=%v", got, err)
		}
	default:
		t.Fatalf("unknown marker kind %q", kind)
	}
}

func TestReliableDispatchExpiredMarkersBecomePending(t *testing.T) {
	for _, kind := range []string{"result", "tombstone", "forgotten"} {
		t.Run(kind, func(t *testing.T) {
			bounds := DefaultControlBounds()
			bounds.ResultRetention = 10 * time.Millisecond
			bounds.TombstoneRetention = bounds.ResultRetention
			bounds.MaxRetainedResults = 1
			bounds.MaxRetainedBytes = 8
			m, err := NewReliableManager(bounds)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1000, 0)
			sid, epoch, _ := attachForReview(t, m, now)
			did := DeliveryID{1}
			seedReliableDispatchMarker(t, m, now, sid, epoch, did, kind)
			later := now.Add(bounds.ResultRetention + time.Nanosecond)
			payload := []byte("12345")
			// The changed content is a new decision after terminal retention.
			// A stale result must release its entire slot/byte reservation.
			if err := m.NoteDispatch(later, sid, epoch, did, "new", payload); err != nil {
				t.Fatalf("replace expired %s: %v", kind, err)
			}
			st := m.sessions[sid]
			pending, ok := st.pending[did]
			if !ok || pending.method != "new" || string(pending.payload) != "12345" || st.pendingBytes != 8 || st.outcomeBytes != 0 {
				t.Fatalf("expired %s lacks owned reservation: pending=%+v present=%v pendingBytes=%d outcomeBytes=%d", kind, pending, ok, st.pendingBytes, st.outcomeBytes)
			}
			if len(st.outcomes) != 0 || len(st.tombstones) != 0 || len(st.forgotten) != 0 {
				t.Fatalf("stale %s marker survived replacement", kind)
			}
			payload[0] = 'X'
			if err := m.NoteDispatch(later, sid, epoch, did, "new", []byte("12345")); err != nil {
				t.Fatalf("replacement aliased caller payload: %v", err)
			}
			requireReliableCode(t, m.NoteDispatch(later, sid, epoch, did, "new", payload), ErrorCodeFailedPrecondition)
			if got, _, err := m.Reconcile(later, sid, did); err != nil || got != ReconcilePending {
				t.Fatalf("expired %s did not become Pending: got=%v err=%v", kind, got, err)
			}
			if idle, err := m.CheckIdle(later, sid); err != nil || idle {
				t.Fatalf("attachment must still be active: idle=%v err=%v", idle, err)
			}
		})
	}
}

func TestReliableDispatchFailedReplacementPreservesMarkers(t *testing.T) {
	for _, kind := range []string{"result", "tombstone", "forgotten"} {
		for _, budget := range []string{"bytes", "count"} {
			if kind == "result" && budget == "count" {
				// Replacing an existing result reuses its count reservation.
				continue
			}
			t.Run(kind+"/"+budget, func(t *testing.T) {
				bounds := DefaultControlBounds()
				bounds.ResultRetention = 10 * time.Millisecond
				bounds.TombstoneRetention = bounds.ResultRetention
				bounds.MaxRetainedResults = 1
				bounds.MaxRetainedBytes = 8
				m, err := NewReliableManager(bounds)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Unix(1000, 0)
				sid, epoch, _ := attachForReview(t, m, now)
				did := DeliveryID{1}
				seedReliableDispatchMarker(t, m, now, sid, epoch, did, kind)
				if budget == "count" {
					if err := m.NoteDispatch(now, sid, epoch, DeliveryID{2}, "x", nil); err != nil {
						t.Fatal(err)
					}
				}
				st := m.sessions[sid]
				oldResult, hadResult := st.outcomes[did]
				oldTombstone, hadTombstone := st.tombstones[did]
				oldForgotten, hadForgotten := st.forgotten[did]
				oldBytes, oldPendingBytes, oldPendingCount := st.outcomeBytes, st.pendingBytes, len(st.pending)
				oldActivity := st.lastActivity
				payload := []byte("123456") // 3+6 exceeds the eight-byte cap.
				if budget == "count" {
					payload = nil
				}
				later := now.Add(bounds.ResultRetention + time.Nanosecond)
				requireReliableCode(t, m.NoteDispatch(later, sid, epoch, did, "new", payload), ErrorCodeResourceExhausted)
				result, hasResult := st.outcomes[did]
				tombstone, hasTombstone := st.tombstones[did]
				forgotten, hasForgotten := st.forgotten[did]
				if hasResult != hadResult || hasTombstone != hadTombstone || hasForgotten != hadForgotten ||
					result.method != oldResult.method || string(result.payload) != string(oldResult.payload) ||
					string(result.outcome.Payload) != string(oldResult.outcome.Payload) || result.retainedAt != oldResult.retainedAt ||
					tombstone != oldTombstone || forgotten != oldForgotten || st.outcomeBytes != oldBytes ||
					st.pendingBytes != oldPendingBytes || len(st.pending) != oldPendingCount || st.lastActivity != oldActivity {
					t.Fatalf("failed %s admission mutated %s state", budget, kind)
				}
				if _, admitted := st.pending[did]; admitted {
					t.Fatal("failed replacement inserted Pending")
				}
			})
		}
	}
}

func TestReliableDispatchLiveMarkersStillSuppress(t *testing.T) {
	for _, kind := range []string{"result", "tombstone", "forgotten"} {
		t.Run(kind, func(t *testing.T) {
			bounds := DefaultControlBounds()
			bounds.ResultRetention = 10 * time.Millisecond
			bounds.TombstoneRetention = bounds.ResultRetention
			m, err := NewReliableManager(bounds)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Unix(1000, 0)
			sid, epoch, _ := attachForReview(t, m, now)
			did := DeliveryID{1}
			seedReliableDispatchMarker(t, m, now, sid, epoch, did, kind)
			// The exact retention boundary is still live in both languages.
			atBoundary := now.Add(bounds.ResultRetention)
			if err := m.NoteDispatch(atBoundary, sid, epoch, did, "old", []byte("x")); err != nil {
				t.Fatal(err)
			}
			if _, admitted := m.sessions[sid].pending[did]; admitted || m.sessions[sid].pendingBytes != 0 {
				t.Fatalf("live %s marker admitted pending work", kind)
			}
			// Live markers must still enforce duplicate-content: same DID
			// different content is rejected, identical stays idempotent.
			requireReliableCode(t, m.NoteDispatch(atBoundary, sid, epoch, did, "new", nil), ErrorCodeFailedPrecondition)
			requireReliableCode(t, m.NoteDispatch(atBoundary, sid, epoch, did, "old", []byte("y")), ErrorCodeFailedPrecondition)
			want := ReconcileRetained
			if kind == "forgotten" {
				want = ReconcileForgotten
			}
			if got, _, err := m.Reconcile(atBoundary, sid, did); err != nil || got != want {
				t.Fatalf("live marker changed: got=%v want=%v err=%v", got, want, err)
			}
		})
	}
}

func TestReliableRedRecordResultEpochFencing(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, epoch1, cred := attachForReview(t, m, now)
	// Advance to epoch 2 via resume so stale (1), zero (0) and future (3) are distinct.
	epoch2, _, _, _, err := m.Attach(now, sid, cred, "conn-2", "svc-a", 1, LeaseProposal{})
	if err != nil {
		t.Fatal(err)
	}
	if epoch2 != epoch1+1 {
		t.Fatalf("epoch2=%d want %d", epoch2, epoch1+1)
	}
	did := DeliveryID{9}
	oldActivity := m.sessions[sid].lastActivity
	oldOutcomes := len(m.sessions[sid].outcomes)
	for _, bad := range []uint64{0, epoch1, epoch2 + 1} {
		_, err := m.RecordResult(now, sid, bad, did, "echo", []byte("p"), StoredOutcome{Payload: []byte("done")})
		requireReliableCode(t, err, ErrorCodeFailedPrecondition)
		if got, _, _ := m.Reconcile(now, sid, did); got != ReconcileUnknown {
			t.Fatalf("stale/zero/future epoch %d mutated state: reconcile=%v", bad, got)
		}
		st := m.sessions[sid]
		if len(st.outcomes) != oldOutcomes || len(st.pending) != 0 {
			t.Fatalf("epoch %d mutated pending/outcomes", bad)
		}
		if !st.lastActivity.Equal(oldActivity) {
			t.Fatalf("epoch %d refreshed activity: got %v want %v", bad, st.lastActivity, oldActivity)
		}
	}
	// Current epoch must succeed.
	if _, err := m.RecordResult(now, sid, epoch2, did, "echo", []byte("p"), StoredOutcome{Payload: []byte("done")}); err != nil {
		t.Fatalf("current epoch rejected: %v", err)
	}
	if got, _, _ := m.Reconcile(now, sid, did); got != ReconcileRetained {
		t.Fatalf("current epoch did not retain: got=%v", got)
	}
}

func TestReliableRedRecordResultRefreshesActivity(t *testing.T) {
	m := testReliableManager(t)
	now := time.Unix(2000, 0)
	sid, epoch, _ := attachForReview(t, m, now)
	didNew := DeliveryID{21}
	// New insert must refresh activity.
	t1 := now.Add(1500 * time.Millisecond)
	if _, err := m.RecordResult(t1, sid, epoch, didNew, "echo", nil, StoredOutcome{Payload: []byte("ok")}); err != nil {
		t.Fatal(err)
	}
	if got := m.sessions[sid].lastActivity; !got.Equal(t1) {
		t.Fatalf("new insert did not refresh activity: got %v want %v", got, t1)
	}
	// Idempotent live duplicate must also refresh.
	t2 := t1.Add(100 * time.Millisecond)
	if _, err := m.RecordResult(t2, sid, epoch, didNew, "echo", nil, StoredOutcome{Payload: []byte("ok")}); err != nil {
		t.Fatal(err)
	}
	if got := m.sessions[sid].lastActivity; !got.Equal(t2) {
		t.Fatalf("idempotent duplicate did not refresh activity: got %v want %v", got, t2)
	}
	// Expired-marker replacement must refresh.
	didExp := DeliveryID{22}
	if _, err := m.RecordResult(now, sid, epoch, didExp, "echo", []byte("a"), StoredOutcome{Payload: []byte("a")}); err != nil {
		t.Fatal(err)
	}
	// Failed admission (mismatch on live didNew) must NOT refresh. Check
	// before advancing to expiry so didNew is still live.
	beforeFail := m.sessions[sid].lastActivity
	_, err := m.RecordResult(t2.Add(100*time.Millisecond), sid, epoch, didNew, "echo", []byte("different"), StoredOutcome{})
	requireReliableCode(t, err, ErrorCodeFailedPrecondition)
	if got := m.sessions[sid].lastActivity; !got.Equal(beforeFail) {
		t.Fatalf("mismatched result refreshed activity: got %v want %v", got, beforeFail)
	}
	later := now.Add(DefaultControlBounds().ResultRetention + time.Second)
	t3 := later
	if _, err := m.RecordResult(t3, sid, epoch, didExp, "echo", []byte("b"), StoredOutcome{Payload: []byte("b")}); err != nil {
		t.Fatalf("expired replacement rejected: %v", err)
	}
	if got := m.sessions[sid].lastActivity; !got.Equal(t3) {
		t.Fatalf("expired replacement did not refresh activity: got %v want %v", got, t3)
	}
}

func TestReliableRedTerminalMarkerContentValidation(t *testing.T) {
	for _, kind := range []string{"tombstone", "forgotten"} {
		t.Run(kind, func(t *testing.T) {
			m := testReliableManager(t)
			now := time.Now()
			sid, epoch, _ := attachForReview(t, m, now)
			did := DeliveryID{31}
			// Seed live marker with known content "echo"/"req".
			if err := m.NoteDispatch(now, sid, epoch, did, "echo", []byte("req")); err != nil {
				t.Fatal(err)
			}
			if kind == "tombstone" {
				if err := m.RecordTombstone(now, sid, did, ErrorCodeCancelled); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err := m.RecordResult(now, sid, epoch, did, "echo", []byte("req"), StoredOutcome{Payload: []byte("done")}); err != nil {
					t.Fatal(err)
				}
				if _, err := m.Forget(sid, did); err != nil {
					t.Fatal(err)
				}
				if got, _, _ := m.Reconcile(now, sid, did); got != ReconcileForgotten {
					t.Fatalf("seed forgotten: got=%v want forgotten", got)
				}
			}
			oldActivity := m.sessions[sid].lastActivity
			// Identical resend must be idempotent success.
			if err := m.NoteDispatch(now, sid, epoch, did, "echo", []byte("req")); err != nil {
				t.Fatalf("identical %s resend rejected: %v", kind, err)
			}
			// Mismatched resend must be rejected without mutation or activity refresh.
			midActivity := m.sessions[sid].lastActivity
			requireReliableCode(t, m.NoteDispatch(now, sid, epoch, did, "echo", []byte("different")), ErrorCodeFailedPrecondition)
			requireReliableCode(t, m.NoteDispatch(now, sid, epoch, did, "other", []byte("req")), ErrorCodeFailedPrecondition)
			st := m.sessions[sid]
			if _, admitted := st.pending[did]; admitted {
				t.Fatalf("mismatched %s resend admitted pending", kind)
			}
			if !st.lastActivity.Equal(midActivity) {
				t.Fatalf("mismatched %s resend refreshed activity: got %v want %v", kind, st.lastActivity, midActivity)
			}
			_ = oldActivity
		})
	}
}

func TestReliableRedTombstoneOverLiveOutcomeRejected(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, epoch, _ := attachForReview(t, m, now)
	did := DeliveryID{41}
	if _, err := m.RecordResult(now, sid, epoch, did, "echo", []byte("req"), StoredOutcome{Payload: []byte("done")}); err != nil {
		t.Fatal(err)
	}
	requireReliableCode(t, m.RecordTombstone(now, sid, did, ErrorCodeCancelled), ErrorCodeFailedPrecondition)
	if got, stored, _ := m.Reconcile(now, sid, did); got != ReconcileRetained || stored == nil || string(stored.Payload) != "done" {
		t.Fatalf("tombstone over live outcome mutated retained result: got=%v stored=%v", got, stored)
	}
	// Expired retained handling: after retention, tombstone must succeed as new terminal.
	later := now.Add(DefaultControlBounds().ResultRetention + time.Second)
	if err := m.RecordTombstone(later, sid, did, ErrorCodeCancelled); err != nil {
		t.Fatalf("tombstone over expired outcome rejected: %v", err)
	}
	if code, ok, err := m.TombstoneOf(later, sid, did); err != nil || !ok || code != ErrorCodeCancelled {
		t.Fatalf("expired-outcome tombstone missing: code=%v ok=%v err=%v", code, ok, err)
	}
}
