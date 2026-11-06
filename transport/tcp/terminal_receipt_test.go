// File terminal_receipt_test.go exercises terminal results over encrypted TCP.
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
	"github.com/tinkle-org/syntra-go/transport/tcp"
)

// terminalAuthority models a volatile conditional transaction and fresh read hooks.
type terminalAuthority struct {
	mu                 sync.Mutex
	committed          *syntra.TerminalTransition
	revoked            *atomic.Bool
	commits            atomic.Int32
	ownedReads         atomic.Int32
	afterCommit        func(context.Context)
	observation        func(syntra.TerminalObservation) (syntra.TerminalObservation, error)
	contextObservation func(context.Context, syntra.TerminalObservation) (syntra.TerminalObservation, error)
}

// Commit atomically records exact ownership and withdraws ordinary Returning access.
func (a *terminalAuthority) Commit(ctx context.Context, transition syntra.TerminalTransition) error {
	a.mu.Lock()
	if ctx.Err() != nil || a.committed != nil || transition.ExpectedRevision != 1 {
		a.mu.Unlock()
		return errors.New("compare failed")
	}
	a.committed = &transition
	a.revoked.Store(true)
	a.commits.Add(1)
	a.mu.Unlock()
	if a.afterCommit != nil {
		a.afterCommit(ctx)
	}
	return nil
}

// Observe snapshots authority state before applying an optional controlled fault.
func (a *terminalAuthority) Observe(ctx context.Context, transition syntra.TerminalTransition) (syntra.TerminalObservation, error) {
	a.mu.Lock()
	if ctx.Err() != nil {
		a.mu.Unlock()
		return syntra.TerminalObservation{}, ctx.Err()
	}
	observation := syntra.TerminalObservation{State: syntra.TerminalActive, Transition: transition, Revision: 1}
	if a.committed == nil {
		a.mu.Unlock()
		if a.observation != nil {
			return a.observation(observation)
		}
		return observation, nil
	}
	observation = syntra.TerminalObservation{State: syntra.TerminalOwnedCommitted, Transition: *a.committed, Revision: 2}
	a.mu.Unlock()
	a.ownedReads.Add(1)
	if a.contextObservation != nil {
		return a.contextObservation(ctx, observation)
	}
	if a.observation != nil {
		return a.observation(observation)
	}
	return observation, nil
}

// TestTerminalReceiptTCP pins the observable self-withdrawal result, not just a
// coordinator's internal state. The authority fixture is volatile, not durable.
func TestTerminalReceiptTCP(t *testing.T) {
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	ak, err := securechannel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var revoked atomic.Bool
	authority := &terminalAuthority{revoked: &revoked}
	sc := securechannel.ServerConfig{StaticKey: key, ServerKeyID: 7, Scope: "terminal-fixture", Carrier: securechannel.TCP,
		LookupKey: func(context.Context, securechannel.Context) (securechannel.Key, error) {
			if revoked.Load() {
				return securechannel.Key{}, errors.New("withdrawn")
			}
			return ak, nil
		}}
	host, err := syntra.OpenHost(syntra.HostConfig{
		TerminalMethods: map[string]syntra.TerminalMethodPolicy{"/example.Authority/Retire": {SuccessPayload: []byte("retired"), Authority: authority, ObservationTimeout: 10 * time.Millisecond}},
		ChannelPolicy:   func(context.Context, syntra.ChannelIdentity, []byte) (string, error) { return "fixture", nil },
		Authorize:       syntra.AllowAllAuthorize,
		Handler: func(ctx context.Context, _ *syntra.RpcRequest) (*syntra.RpcResult, error) {
			err := syntra.CompleteTerminalReceipt(ctx, "fixture-retire", 1)
			return nil, err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		done <- tcp.Accept(ctx, conn, sc, host, ordered.Options{EnableTerminalReceipts: true})
	}()
	cc := securechannel.ClientConfig{ServerPublicKey: key.Public(), AuthorizationKey: ak,
		Context: securechannel.Context{Mode: securechannel.Returning, Carrier: securechannel.TCP, ServerKeyID: 7, Scope: sc.Scope, Epoch: 1, Handle: [8]byte{1}}}
	client, err := tcp.Dial(ctx, listener.Addr().String(), cc, syntra.ClientConfig{}, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	got, err := client.Call(ctx, "/example.Authority/Retire", nil, 1000)
	if err != nil || string(got) != "retired" {
		t.Errorf("terminal receipt = %q, %v; want retired", got, err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("server did not join")
	}
}
