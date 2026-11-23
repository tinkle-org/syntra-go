// File terminal_outcome_test.go exercises authority-selected results over native TCP.
package tcp_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
)

// TestTerminalTCPApplicationOutcome waits for an actual in-commit observer to
// see the withdrawal before publishing the application result. Both calls use
// the same handler and successful Commit return; only durable-result evidence differs.
func TestTerminalTCPApplicationOutcome(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   uint8
		want []byte
	}{
		{"protobuf-true", 1, []byte{0x08, 0x01}},
		{"protobuf-false", 2, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pending := make(chan struct{})
			var once sync.Once
			var result atomic.Uint32
			f := terminalTCP(t, terminalTCPOptions{
				outcomes: [][]byte{{0x08, 0x01}, {}}, observationTimeout: 100 * time.Millisecond,
				commit: func(ctx context.Context) {
					select {
					case <-pending:
						result.Store(uint32(tc.id))
					case <-ctx.Done():
					}
				},
				observe: func(o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
					if o.State == syntra.TerminalOwnedCommitted {
						o.OutcomeID = uint8(result.Load())
						o.State = syntra.TerminalOwnedOutcome
						if o.OutcomeID == 0 {
							o.State = syntra.TerminalOwnedPending
							once.Do(func() { close(pending) })
						}
					}
					return o, nil
				},
			})
			got, err := f.connect(t).Call(f.ctx, retireMethod, nil, 3000)
			if err != nil || !bytes.Equal(got, tc.want) || f.authority.commits.Load() != 1 {
				t.Fatalf("result = %x, %v; commits = %d", got, err, f.authority.commits.Load())
			}
		})
	}
}

// TestTerminalTCPFixedLogoutAndOutcomeOnOneHost serves both policy shapes
// without restarting the host or reactivating the withdrawn Logout enrollment.
func TestTerminalTCPFixedLogoutAndOutcomeOnOneHost(t *testing.T) {
	const logout = "/example.Authority/Logout"
	secondKey, err := securechannel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	secondHandle := [8]byte{2}
	outcome := &terminalAuthority{revoked: new(atomic.Bool), contextObservation: func(_ context.Context, o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
		o.State, o.OutcomeID = syntra.TerminalOwnedOutcome, 2
		return o, nil
	}}
	f := terminalTCP(t, terminalTCPOptions{
		connections: 2, method: logout, payload: []byte{}, observationTimeout: 100 * time.Millisecond,
		handler: func(ctx context.Context, req *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return nil, syntra.CompleteTerminalReceipt(ctx, req.GetMethod(), 1)
		},
		configure: func(host *syntra.HostConfig, server *securechannel.ServerConfig) {
			host.TerminalMethods[retireMethod] = syntra.TerminalMethodPolicy{
				OutcomePayloads: [][]byte{{}, {0x08, 0x01}}, Authority: outcome, ObservationTimeout: 100 * time.Millisecond,
			}
			firstLookup := server.LookupKey
			server.LookupKey = func(ctx context.Context, c securechannel.Context) (securechannel.Key, error) {
				if c.Handle == secondHandle && c.Epoch == 1 && !outcome.revoked.Load() {
					return secondKey, nil
				}
				return firstLookup(ctx, c)
			}
		},
	})
	first := f.connect(t)
	got, err := first.Call(f.ctx, logout, nil, 2000)
	if err != nil || len(got) != 0 || f.authority.commits.Load() != 1 || outcome.commits.Load() != 0 {
		t.Fatalf("Logout = %x, %v; fixed/outcome commits = %d/%d", got, err, f.authority.commits.Load(), outcome.commits.Load())
	}
	select {
	case <-first.Done():
	case <-f.ctx.Done():
		t.Fatal("Logout connection did not retire")
	}
	security := f.security
	security.AuthorizationKey, security.Context.Handle = secondKey, secondHandle
	second, err := tcp.Dial(f.ctx, f.address, security, syntra.ClientConfig{}, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	got, err = second.Call(f.ctx, retireMethod, nil, 2000)
	if err != nil || !bytes.Equal(got, []byte{0x08, 0x01}) || f.authority.commits.Load() != 1 || outcome.commits.Load() != 1 {
		t.Fatalf("Retire = %x, %v; fixed/outcome commits = %d/%d", got, err, f.authority.commits.Load(), outcome.commits.Load())
	}
}

// TestTerminalTCPOutcomeRequiresProof denies a reply even when Commit returned
// normally. In particular, no unresolved result can default to false/empty.
func TestTerminalTCPOutcomeRequiresProof(t *testing.T) {
	for _, fault := range []string{"unknown", "pending", "pending-with-id", "zero-id", "unlisted-id", "fixed-proof", "wrong-operation", "active-with-id", "outcome-on-fixed", "pending-on-fixed", "fixed-with-id"} {
		t.Run(fault, func(t *testing.T) {
			opts := terminalTCPOptions{outcomes: [][]byte{{1}, {}}, observationTimeout: 100 * time.Millisecond}
			if fault == "outcome-on-fixed" || fault == "pending-on-fixed" || fault == "fixed-with-id" {
				opts.outcomes = nil
			}
			opts.observe = func(o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
				if o.State == syntra.TerminalActive {
					if fault == "active-with-id" {
						o.OutcomeID = 1
					}
					return o, nil
				}
				o.State, o.OutcomeID = syntra.TerminalOwnedOutcome, 1
				switch fault {
				case "unknown":
					o.State, o.OutcomeID = syntra.TerminalUnknown, 0
				case "pending", "pending-on-fixed":
					o.State, o.OutcomeID = syntra.TerminalOwnedPending, 0
				case "pending-with-id":
					o.State = syntra.TerminalOwnedPending
				case "zero-id":
					o.OutcomeID = 0
				case "unlisted-id":
					o.OutcomeID = 3
				case "fixed-proof":
					o.State, o.OutcomeID = syntra.TerminalOwnedCommitted, 0
				case "wrong-operation":
					o.Transition.Operation = "other"
				case "fixed-with-id":
					o.State = syntra.TerminalOwnedCommitted
				}
				return o, nil
			}
			f := terminalTCP(t, opts)
			wantCommits := int32(1)
			if fault == "active-with-id" {
				wantCommits = 0
			}
			if got, err := f.connect(t).Call(f.ctx, retireMethod, nil, 2000); err == nil || len(got) != 0 || f.authority.commits.Load() != wantCommits {
				t.Fatalf("result = %x, %v; commits = %d", got, err, f.authority.commits.Load())
			}
		})
	}
}

// TestTerminalTCPOutcomePinnedThroughHandoff changes only the final read, after
// the selected bytes are encrypted. Even another allowlisted ID must abort.
func TestTerminalTCPOutcomePinnedThroughHandoff(t *testing.T) {
	for _, fault := range []string{"id", "revision", "reservation", "pending", "active", "denied", "error"} {
		t.Run(fault, func(t *testing.T) {
			write := make(chan error, 1)
			var reads atomic.Int32
			f := terminalTCP(t, terminalTCPOptions{
				outcomes: [][]byte{{1}, {}}, observationTimeout: 100 * time.Millisecond,
				wrapTransport: func(tr *ordered.Transport) syntra.Transport {
					return &terminalMarkedTransport{Transport: tr, result: write}
				},
				observeContext: func(ctx context.Context, o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
					o.State, o.OutcomeID = syntra.TerminalOwnedOutcome, 1
					if ctx.Value(terminalSendKey{}) == true && reads.Add(1) == 2 {
						switch fault {
						case "id":
							o.OutcomeID++
						case "revision":
							o.Revision++
						case "reservation":
							o.Transition.ReservationID[0]++
						case "pending":
							o.State, o.OutcomeID = syntra.TerminalOwnedPending, 0
						case "active":
							o.State, o.OutcomeID, o.Revision = syntra.TerminalActive, 0, o.Transition.ExpectedRevision
						case "denied":
							o.State, o.OutcomeID = syntra.TerminalDenied, 0
						case "error":
							return o, errors.New("result store unavailable")
						}
					}
					return o, nil
				},
			})
			if got, err := f.connect(t).Call(f.ctx, retireMethod, nil, 2000); err == nil || len(got) != 0 || reads.Load() != 2 {
				t.Fatalf("result = %x, %v; send reads = %d", got, err, reads.Load())
			}
			select {
			case err := <-write:
				if err == nil {
					t.Fatal("final proof change allowed local write")
				}
			case <-f.ctx.Done():
				t.Fatal("send did not finish")
			}
		})
	}
}
