package syntra

import (
	"testing"
	"time"
)

// Fresh reattachment without a resume credential must advance the fencing
// epoch after the first attachment, while the initial attach after
// CreateSession stays at epoch 1 for compatibility.
func TestReliableFreshReattachAdvancesEpoch(t *testing.T) {
	m := testReliableManager(t)
	now := time.Now()
	sid, epoch, _, _ := mustCreate(t, m, now)
	if epoch != 1 {
		t.Fatalf("create epoch = %d, want 1", epoch)
	}
	first, _, _, _, err := m.Attach(now, sid, nil, "conn-1", "svc-a", 1, LeaseProposal{})
	if err != nil {
		t.Fatal(err)
	}
	if first != 1 {
		t.Fatalf("first attach epoch = %d, want 1", first)
	}
	m.Detach(sid, "conn-1")
	second, _, _, _, err := m.Attach(now.Add(time.Second), sid, nil, "conn-2", "svc-a", 1, LeaseProposal{})
	if err != nil {
		t.Fatal(err)
	}
	if second != 2 {
		t.Fatalf("second fresh attach epoch = %d, want 2", second)
	}
	did := DeliveryID{7}
	if err := m.NoteDispatch(now, sid, first, did, "echo", nil); err == nil {
		t.Fatal("stale epoch dispatch accepted after fresh reattach")
	}
	if err := m.NoteDispatch(now, sid, second, did, "echo", nil); err != nil {
		t.Fatalf("current epoch dispatch rejected: %v", err)
	}
}

// Forget must use the caller's clock, not the system clock, so markers
// created with a simulated clock expire on that same clock.
func TestReliableForgetUsesCallerClock(t *testing.T) {
	m := testReliableManager(t)
	base := time.Unix(1_700_000_000, 0).UTC()
	sid, _, _, _ := mustCreate(t, m, base)
	did := DeliveryID{9}
	if _, err := m.RecordResult(base, sid, 1, did, "echo", []byte("req"), StoredOutcome{Payload: []byte("done")}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Forget(base, sid, did); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := m.Reconcile(base, sid, did); got != ReconcileForgotten {
		t.Fatalf("after forget = %v, want forgotten", got)
	}
	later := base.Add(2 * m.bounds.ResultRetention)
	if got, _, _ := m.Reconcile(later, sid, did); got != ReconcileUnknown {
		t.Fatalf("expired forgotten = %v, want unknown", got)
	}
}
