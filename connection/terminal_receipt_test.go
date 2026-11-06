// File terminal_receipt_test.go rejects uncoordinated custom record pumps.
package connection_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
)

// unsupportedTerminalAuthority detects any work past unsupported-driver preflight.
type unsupportedTerminalAuthority struct{ commits, observes atomic.Int32 }

// Commit counts mutations that unsupported record pumps must never reach.
func (a *unsupportedTerminalAuthority) Commit(context.Context, syntra.TerminalTransition) error {
	a.commits.Add(1)
	return nil
}

// Observe counts reads that unsupported record pumps must never reach.
func (a *unsupportedTerminalAuthority) Observe(_ context.Context, transition syntra.TerminalTransition) (syntra.TerminalObservation, error) {
	a.observes.Add(1)
	return syntra.TerminalObservation{State: syntra.TerminalActive, Transition: transition, Revision: 1}, nil
}

// TestTerminalCustomMessageIORejectsBeforeMutation checks that ordinary custom
// MessageIO cannot silently inherit terminal authority or coordinated I/O support.
func TestTerminalCustomMessageIORejectsBeforeMutation(t *testing.T) {
	authority := &unsupportedTerminalAuthority{}
	cfg := hostConfig()
	cfg.TerminalMethods = map[string]syntra.TerminalMethodPolicy{echoMethod: {SuccessPayload: []byte("retired"), Authority: authority, ObservationTimeout: time.Millisecond}}
	cfg.Handler = func(ctx context.Context, _ *syntra.RpcRequest) (*syntra.RpcResult, error) {
		return nil, syntra.CompleteTerminalReceipt(ctx, "operation", 1)
	}
	cc, server := fixture(t, cfg, connection.ServerOptions{})
	a, b := recordPair() // valid ordinary MessageIO, no terminal coordination declaration
	opts := testOptions()
	opts.EnableTerminalReceipts = true
	done := make(chan error, 1)
	go func() { done <- server.Accept(context.Background(), b, opts) }()
	client, err := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{Credential: []byte("explicit")}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Call(context.Background(), echoMethod, nil, 1000); err == nil {
		t.Fatal("custom record pump silently inherited terminal support")
	}
	if authority.commits.Load() != 0 || authority.observes.Load() != 0 {
		t.Fatal("unsupported preflight called authority")
	}
	_ = client.Close()
	join(t, done)
}
