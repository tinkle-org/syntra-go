// File terminal_receipt_test.go tests retirement fencing and sticky evidence.
package syntra

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// terminalTestClock keeps elapsed time fixed for evidence-only tests.
type terminalTestClock struct{}

// Age returns the fixture's fixed origin.
func (terminalTestClock) Age() time.Duration { return 0 }

// Check keeps the evidence fixture's clock valid.
func (terminalTestClock) Check() error { return nil }

// terminalTestAuthority returns controlled evidence and counts mutation attempts.
type terminalTestAuthority struct {
	observation TerminalObservation
	err         error
	commits     atomic.Int32
}

// Commit records a mutation attempt without claiming durable state.
func (a *terminalTestAuthority) Commit(context.Context, TerminalTransition) error {
	a.commits.Add(1)
	return nil
}

// Observe returns the exact injected state or authority error.
func (a *terminalTestAuthority) Observe(context.Context, TerminalTransition) (TerminalObservation, error) {
	return a.observation, a.err
}

// TestTerminalEvidenceIsStickyAndExact rejects mismatched evidence and prevents
// a later valid read from resurrecting an already failed reservation.
func TestTerminalEvidenceIsStickyAndExact(t *testing.T) {
	for _, fault := range []string{"unknown", "denied", "error", "reservation", "operation", "principal", "scope", "epoch", "method", "revision", "server-key", "handshake", "active-after-commit"} {
		t.Run(fault, func(t *testing.T) {
			transition := TerminalTransition{ReservationID: [32]byte{1}, Principal: "p", Operation: "operation", Method: "/example.Authority/Retire", ExpectedRevision: 3, Channel: ChannelIdentity{Scope: "s", Epoch: 1}}
			a := &terminalTestAuthority{observation: TerminalObservation{State: TerminalOwnedCommitted, Transition: transition, Revision: 4}}
			p := &TerminalPermit{valid: true, clock: terminalTestClock{}, until: time.Second, wallUntil: time.Now().Add(time.Second), transition: transition, policy: TerminalMethodPolicy{Authority: a, ObservationTimeout: time.Second}}
			if fault == "active-after-commit" {
				if _, err := p.Observe(context.Background(), true); err != nil {
					t.Fatal(err)
				}
			}
			switch fault {
			case "unknown":
				a.observation.State = TerminalUnknown
			case "denied":
				a.observation.State = TerminalDenied
			case "error":
				a.err = errors.New("store unavailable")
			case "reservation":
				a.observation.Transition.ReservationID[0]++
			case "operation":
				a.observation.Transition.Operation = "other"
			case "principal":
				a.observation.Transition.Principal = "other"
			case "scope":
				a.observation.Transition.Channel.Scope = "other"
			case "epoch":
				a.observation.Transition.Channel.Epoch++
			case "method":
				a.observation.Transition.Method = "/example.Authority/Other"
			case "revision":
				a.observation.Revision = 3
			case "server-key":
				a.observation.Transition.ServerKeyID++
			case "handshake":
				a.observation.Transition.HandshakeHash[0]++
			case "active-after-commit":
				a.observation.State = TerminalActive
				a.observation.Revision = 3
			}
			if _, err := p.Observe(context.Background(), false); err == nil {
				t.Fatal("invalid evidence allowed")
			}
			a.err = nil
			a.observation = TerminalObservation{State: TerminalOwnedCommitted, Transition: transition, Revision: 4}
			if _, err := p.Observe(context.Background(), true); err == nil {
				t.Fatal("late success resurrected failed reservation")
			}
		})
	}
}

// TestTerminalQuiesceSuppressesQueuedNotActive retains the active full frame
// while discarding queued ordinary output and rejecting later output silently.
func TestTerminalQuiesceSuppressesQueuedNotActive(t *testing.T) {
	probe := newWriterProbe()
	w := newHostWriter(probe, time.Second)
	defer w.shutdown()
	if err := w.enqueue([]byte("active")); err != nil {
		t.Fatal(err)
	}
	hostWriterSignal(t, probe.entered, "active frame")
	if err := w.enqueue([]byte("queued")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- w.quiesce(context.Background()) }()
	awaitHostWriterState(t, w, func(count, _ int, accepting bool) bool { return count == 1 && !accepting })
	select {
	case <-done:
		t.Fatal("barrier passed partial active frame")
	default:
	}
	close(probe.release)
	if err := runtimeAwait(t, done); err != nil {
		t.Fatal(err)
	}
	if err := w.enqueue([]byte("late")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-probe.sent:
		if string(got) != "active" {
			t.Fatal(string(got))
		}
	default:
		t.Fatal("active frame was dropped")
	}
	select {
	case got := <-probe.sent:
		t.Fatalf("queued output leaked: %q", got)
	default:
	}
}

// TestTerminalContextCannotBeManufactured rejects unowned contexts and zero permits.
func TestTerminalContextCannotBeManufactured(t *testing.T) {
	if err := CompleteTerminalReceipt(context.Background(), "operation", 1); err == nil {
		t.Fatal("unowned context reserved")
	}
	var zero TerminalPermit
	if zero.CheckTime() == nil || zero.Handoff() == nil {
		t.Fatal("zero permit grants access")
	}
}

// TestTerminalUnsupportedFrameTransportRejectsBeforeCommit refuses raw frame
// transports before the application authority can mutate.
func TestTerminalUnsupportedFrameTransportRejectsBeforeCommit(t *testing.T) {
	authority := &terminalTestAuthority{}
	cfg := testHostConfig()
	cfg.TerminalMethods = map[string]TerminalMethodPolicy{"/example.Authority/Retire": {SuccessPayload: []byte("retired"), Authority: authority, ObservationTimeout: time.Millisecond}}
	cfg.Handler = func(ctx context.Context, _ *RpcRequest) (*RpcResult, error) {
		return nil, CompleteTerminalReceipt(ctx, "operation", 1)
	}
	p := newRawSessionPeer(t, cfg, nil)
	p.request(t, 1, "/example.Authority/Retire")
	if result := p.recv(t).GetResult(); result.GetError() == nil {
		t.Fatal("raw frame transport granted receipt")
	}
	if authority.commits.Load() != 0 {
		t.Fatal("unsupported frame transport started mutation")
	}
}
