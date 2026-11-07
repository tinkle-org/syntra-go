// File terminal_callback_budget_test.go checks authority budgets on actual
// ordered/TCP periodic observations while the initiating Commit is still active.
package tcp_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
)

// TestTerminalTCPPeriodicObserversHaveDerivedBudget requires two real periodic
// driver reads before Commit returns; request-path proof cannot satisfy the gate.
func TestTerminalTCPPeriodicObserversHaveDerivedBudget(t *testing.T) {
	var reads atomic.Int32
	periodic := make(chan struct{})
	f := terminalTCP(t, terminalTCPOptions{
		observationTimeout: 100 * time.Millisecond,
		commit: func(ctx context.Context) {
			b, ok := syntra.RequestBudgetFromContext(ctx)
			d, hasDeadline := ctx.Deadline()
			before := time.Until(d)
			if !ok || !hasDeadline || !b.Deadline().Equal(d) || b.Remaining() > before {
				t.Error("TCP Commit lacks operation-cutoff SDK budget")
			}
			select {
			case <-periodic:
			case <-ctx.Done():
				t.Error("periodic driver reads did not run while Commit was active")
			}
		},
		observeContext: func(ctx context.Context, o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
			b, ok := syntra.RequestBudgetFromContext(ctx)
			d, hasDeadline := ctx.Deadline()
			before := time.Until(d)
			if !ok || !hasDeadline || !b.Deadline().Equal(d) || b.Remaining() <= 0 || b.Remaining() > before || before > 100*time.Millisecond {
				t.Error("periodic/proof observer lacks exact read/permit SDK budget")
			}
			if reads.Add(1) == 2 {
				close(periodic)
			}
			return o, nil
		},
	})
	c := f.connect(t)
	got, err := c.Call(f.ctx, retireMethod, nil, 3000)
	if err != nil || string(got) != "retired" || reads.Load() < 2 {
		t.Fatalf("periodic budget receipt=%q err=%v reads=%d", got, err, reads.Load())
	}
}
