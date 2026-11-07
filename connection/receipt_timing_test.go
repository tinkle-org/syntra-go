// File receipt_timing_test.go checks metadata through the public connection owner.
package connection_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
)

// TestReceiptReadyWrapperPreservesTrustedBudget keeps ordinary (nonterminal)
// request timing through Accept's readiness wrapper and root session ownership.
func TestReceiptReadyWrapperPreservesTrustedBudget(t *testing.T) {
	cc, sc, err := channelConfigs(securechannel.Returning)
	if err != nil {
		t.Fatal(err)
	}
	opts, age := clockOptions(t)
	var authorized atomic.Int32
	cfg := hostConfig()
	cfg.RequestBudget = func(string, string, []byte) (time.Duration, bool) {
		age.Store(int64(80 * time.Millisecond))
		return 40 * time.Millisecond, true
	}
	cfg.Authorize = func(context.Context, string, string) error { authorized.Add(1); return nil }
	host, err := syntra.OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	a, b := recordPair()
	accepted := make(chan error, 1)
	go func() { accepted <- connection.Accept(context.Background(), b, sc, host, opts) }()
	defer func() { _ = a.Close(); _ = b.Close(); join(t, accepted) }()
	client, err := connection.Connect(context.Background(), a, cc, syntra.ClientConfig{Credential: []byte("explicit")}, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err = client.Call(ctx, echoMethod, nil, 1000)
	var rpc *syntra.RpcError
	if !errors.As(err, &rpc) || rpc.Code != syntra.ErrorCodeDeadlineExceeded {
		t.Fatalf("trusted selector suspension was forgiven through readiness wrapper: %v", err)
	}
	if authorized.Load() != 0 {
		t.Fatal("expired ordinary request reached authorization")
	}
}
