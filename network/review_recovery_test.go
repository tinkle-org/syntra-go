package network

import (
	"context"
	"sync/atomic"
	"testing"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
)

type closingNegotiation struct {
	RecoverySession
	connection <-chan *connection.Client
}

func (p *closingNegotiation) Negotiate(ctx context.Context) error {
	if err := p.RecoverySession.Negotiate(ctx); err != nil {
		return err
	}
	conn := <-p.connection
	if err := conn.Close(); err != nil {
		return err
	}
	// Successful wire negotiation is not successful readiness once this exact
	// connection has already closed, even if the negotiation result is nil.
	return nil
}

func TestClosedRecoveryNegotiationConsumesFiniteAttempt(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	l, security, factory := managedRecovery(t, n, negotiationSource{})
	connections := make(chan *connection.Client, 1)
	var attempts, completions atomic.Int32
	cfg := reconnectConfig()
	cfg.MaxAttempts = 1
	cfg.RecoveryFactory = func(core *syntra.Client) (RecoverySession, error) {
		profile, err := factory(core)
		if err != nil {
			return nil, err
		}
		return &closingNegotiation{RecoverySession: profile, connection: connections}, nil
	}
	cfg.DeferCompletion = func(*ordered.EstablishmentBudget) (func() error, error) {
		return func() error { completions.Add(1); return nil }, nil
	}
	c, err := n.ClientWithSetup(cfg, func(ctx context.Context, b *ordered.EstablishmentBudget, prepare func(*syntra.Client) error) (*connection.Client, error) {
		if attempts.Add(1) != 1 {
			return nil, FailureConfiguration
		}
		conn, err := tcp.Dial(ctx, l.LocalAddr().String(), security, syntra.ClientConfig{Prepare: prepare}, ordered.Options{Budget: b})
		if err == nil {
			connections <- conn
		}
		return conn, err
	})
	if err != nil {
		t.Fatal(err)
	}
	status := phase(t, c, Exhausted)
	if status.Attempts != 1 || !status.Failure.Retryable() || attempts.Load() != 1 {
		t.Fatalf("closed negotiation renewed its allowance: status=%+v attempts=%d", status, attempts.Load())
	}
	if completions.Load() != 0 {
		t.Fatal("closed negotiation reached establishment completion")
	}
	if _, err := c.RecoveryClient(); err == nil {
		t.Fatal("closed recovery client was published")
	}
}
