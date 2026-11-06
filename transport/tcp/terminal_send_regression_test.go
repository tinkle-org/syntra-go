// File terminal_send_regression_test.go isolates ordered terminal send gates
// from idle supervisor observations and the host's longer receipt deadline.
package tcp_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

// terminalSendKey labels only SendTerminal's authority reads, never idle polls.
type terminalSendKey struct{}

// terminalMarkedTransport preserves the real ordered driver and tags only its
// terminal send context; it neither supplies observations nor consumes permits.
type terminalMarkedTransport struct {
	*ordered.Transport
	result chan<- error
}

// TerminalReceiptDriver returns the same marked driver for this test connection.
func (t *terminalMarkedTransport) TerminalReceiptDriver() syntra.TerminalReceiptDriver { return t }

// SendTerminal distinguishes its two fresh reads from all other driver reads.
func (t *terminalMarkedTransport) SendTerminal(ctx context.Context, p *syntra.TerminalPermit) error {
	err := t.Transport.SendTerminal(context.WithValue(ctx, terminalSendKey{}, true), p)
	t.result <- err
	return err
}

// terminalCountConn counts actual carrier writes, including record prefixes.
type terminalCountConn struct {
	net.Conn
	writes atomic.Int32
}

// Write counts handoffs without altering the supplied stream or its bytes.
func (c *terminalCountConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

// TestTerminalTCPFinalObservationDenialWins stops precisely at the second
// SendTerminal read: after encryption, before handoff. Supervisor polls cannot
// satisfy this barrier. Removing the final gate must fail, not merely shift the
// denial to another observer.
func TestTerminalTCPFinalObservationDenialWins(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var reads atomic.Int32
	var carrier *terminalCountConn
	writeResult := make(chan error, 1)
	f := terminalTCP(t, terminalTCPOptions{
		wrap: func(conn net.Conn) net.Conn {
			carrier = &terminalCountConn{Conn: conn}
			return carrier
		},
		observationTimeout: time.Second,
		wrapTransport: func(tr *ordered.Transport) syntra.Transport {
			return &terminalMarkedTransport{Transport: tr, result: writeResult}
		},
		observeContext: func(ctx context.Context, o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
			if ctx.Value(terminalSendKey{}) == true && reads.Add(1) == 2 {
				close(entered)
				<-release
				if ctx.Err() != nil {
					t.Error("observation watchdog expired before the final denial was returned")
				}
				o.State = syntra.TerminalDenied
			}
			return o, nil
		},
	})
	c := f.connect(t)
	done := make(chan error, 1)
	go func() { _, err := c.Call(f.ctx, retireMethod, nil, 3000); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("after-encryption send observation was not reached")
	}
	if carrier.writes.Load() != 4 { // M2 and Ready each write one prefix and body.
		t.Fatal("receipt reached carrier before final observation")
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-done; err == nil {
		t.Fatal("denial at final validation allowed receipt")
	}
	if err := <-writeResult; !errors.Is(err, securechannel.ErrAuth) {
		t.Fatalf("final gate failed for %v, want authority denial rather than deadline", err)
	}
	if reads.Load() != 2 || carrier.writes.Load() != 4 || f.authority.commits.Load() != 1 {
		t.Fatal("final denial changed commit accounting or handed ciphertext to carrier")
	}
}

// terminalContextIO holds only the receipt and honors its exact write context.
type terminalContextIO struct {
	ordered.MessageIO
	writes  int
	entered chan context.Context
}

// SupportsTerminalReceipt preserves the explicit TCP carrier opt-in.
func (*terminalContextIO) SupportsTerminalReceipt() bool { return true }

// WriteMessage lets establishment finish, then waits for receipt cancellation.
func (m *terminalContextIO) WriteMessage(ctx context.Context, p []byte) error {
	m.writes++
	if m.writes != 3 {
		return m.MessageIO.WriteMessage(ctx, p)
	}
	m.entered <- ctx
	<-ctx.Done()
	return ctx.Err()
}

// TestTerminalTCPOrderedWriteDeadlineBoundsCarrier checks wall and trusted
// elapsed cutoff while the carrier is blocked, independently of the 3s RPC and
// host receipt budget. The observer remains valid throughout both cases.
func TestTerminalTCPOrderedWriteDeadlineBoundsCarrier(t *testing.T) {
	for _, elapsed := range []bool{false, true} {
		t.Run(map[bool]string{false: "wall", true: "elapsed"}[elapsed], func(t *testing.T) {
			entered := make(chan context.Context, 1)
			var jump atomic.Int64
			origin := time.Now()
			clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) {
				return time.Since(origin) + time.Duration(jump.Load()), true
			}))
			budget, err := ordered.NewEstablishmentBudget(clock, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			writeTimeout := 40 * time.Millisecond
			if elapsed {
				writeTimeout = time.Second
			}
			f := terminalTCP(t, terminalTCPOptions{
				serverOptions: ordered.Options{Budget: budget, WriteTimeout: writeTimeout},
				wrapRecords: func(io ordered.MessageIO) ordered.MessageIO {
					return &terminalContextIO{MessageIO: io, entered: entered}
				},
			})
			c := f.connect(t)
			done := make(chan error, 1)
			go func() { _, err := c.Call(f.ctx, retireMethod, nil, 3000); done <- err }()
			var writeCtx context.Context
			select {
			case writeCtx = <-entered:
			case <-time.After(time.Second):
				t.Fatal("receipt write was not reached")
			}
			if deadline, ok := writeCtx.Deadline(); !ok || time.Until(deadline) > writeTimeout {
				t.Error("carrier context does not retain ordered write deadline")
			}
			if elapsed {
				jump.Store(int64(1500 * time.Millisecond)) // below the host/RPC cutoff
			}
			select {
			case <-writeCtx.Done():
			case <-time.After(200 * time.Millisecond):
				t.Error("ordered deadline did not cancel blocked carrier")
			}
			// Canceling the client also provides bounded cleanup on the red path.
			_ = c.Close()
			if err := <-done; err == nil || f.authority.commits.Load() != 1 {
				t.Fatal("blocked receipt succeeded or changed commit accounting")
			}
		})
	}
}
