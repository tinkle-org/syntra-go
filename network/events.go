package network

import (
	"context"
	"math"
	"sync"
)

type EventKind uint8

const (
	ClientStarted EventKind = iota + 1
	ClientStopped
	ListenerStarted
	ListenerStopped
	ControlsChanged
	ConnectionAdmitted
	ConnectionCompleted
)

type Event struct {
	Sequence uint64
	Kind     EventKind
	Address  string
}
type EventLossError struct{ Dropped uint64 }

func (e *EventLossError) Error() string { return "network: event receiver fell behind" }

// Events is an independent cursor over a bounded event log. Snapshots remain
// authoritative for current state; slow receivers get explicit local loss.
type Events struct {
	network  *Network
	mu       sync.Mutex
	sequence uint64
}

func (n *Network) Events() *Events {
	n.mu.Lock()
	defer n.mu.Unlock()
	return &Events{network: n, sequence: n.eventSequence}
}
func (n *Network) eventLocked(event Event) {
	if n.eventSequence == math.MaxUint64 {
		return
	}
	n.eventSequence++
	event.Sequence = n.eventSequence
	if len(n.events) == n.cfg.EventCapacity {
		copy(n.events, n.events[1:])
		n.events[len(n.events)-1] = event
	} else {
		n.events = append(n.events, event)
	}
	n.changedLocked()
}
func (n *Network) event(event Event) { n.mu.Lock(); defer n.mu.Unlock(); n.eventLocked(event) }
func (e *Events) Next(ctx context.Context) (Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	n := e.network
	for {
		n.mu.Lock()
		if len(n.events) > 0 {
			oldest := n.events[0].Sequence
			if e.sequence < oldest-1 {
				loss := oldest - 1 - e.sequence
				e.sequence = oldest - 1
				n.mu.Unlock()
				return Event{}, &EventLossError{Dropped: loss}
			}
			if e.sequence < n.eventSequence {
				event := n.events[e.sequence+1-oldest]
				e.sequence = event.Sequence
				n.mu.Unlock()
				return event, nil
			}
		}
		changed := n.changed
		n.mu.Unlock()
		select {
		case <-changed:
		case <-n.Done():
			n.mu.Lock()
			unseen := n.eventSequence > e.sequence
			n.mu.Unlock()
			if !unseen {
				return Event{}, ErrClosed
			}
		case <-ctx.Done():
			return Event{}, ctx.Err()
		}
	}
}
