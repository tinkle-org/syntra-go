package network

import (
	"errors"
	"testing"
)

func TestBoundedManagedEventsExposeLossAndFinalStop(t *testing.T) {
	cfg := DefaultConfig()
	cfg.EventCapacity = 1
	n := testNetwork(t, cfg)
	events := n.Events()
	n.Pause()
	n.Resume()
	_, err := events.Next(testContext(t))
	var loss *EventLossError
	if !errors.As(err, &loss) || loss.Dropped != 1 {
		t.Fatalf("missing bounded-log loss: %v", err)
	}
	event, err := events.Next(testContext(t))
	if err != nil || event.Kind != ControlsChanged || event.Sequence != 2 {
		t.Fatalf("event=%+v err=%v", event, err)
	}
	if report := n.Shutdown(testContext(t)); !report.Complete {
		t.Fatalf("shutdown=%+v", report)
	}
	event, err = events.Next(testContext(t))
	if err != nil || event.Kind != ControlsChanged || event.Sequence != 3 {
		t.Fatalf("final event=%+v err=%v", event, err)
	}
	if _, err := events.Next(testContext(t)); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
