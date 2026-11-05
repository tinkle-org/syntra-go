package syntrahttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
)

// Keep real authenticated Hosts in a controlled registry after selected peers
// retire. This models the stale Host references a fanout snapshot can retain
// while connection cleanup closes recipients concurrently. The live server
// remains the sole owner of actual sockets, Hosts and admission reservations.
func directFanoutFixture(t *testing.T, failedRecipients int) (*Server, *connection.Client) {
	t.Helper()
	cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	live := startServer(t, sc, hostConfig(), nil, ServerLimits{})
	healthy := connectTo(t, live, cc, nil)
	hosts := live.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("healthy authenticated hosts = %d, want 1", len(hosts))
	}
	healthyHost := hosts[0]
	fanout := &Server{registry: map[Route]*associationOwner{
		routeFromRandom([32]byte{1}): {host: healthyHost, principal: "principal"},
	}}
	for i := 0; i < failedRecipients; i++ {
		// Retire one peer before creating the next, keeping the real listener's
		// conservative byte reservation within its normal two-association cap.
		peer := connectTo(t, live, cc, nil)
		hosts = live.Hosts()
		if len(hosts) != 2 {
			t.Fatalf("authenticated hosts = %d, want 2", len(hosts))
		}
		var retiring *syntra.Host
		for _, host := range hosts {
			if host != healthyHost {
				retiring = host
			}
		}
		if retiring == nil {
			t.Fatal("retiring authenticated host missing")
		}
		if err := peer.Close(); err != nil {
			t.Fatal(err)
		}
		awaitCondition(t, func() bool {
			status := live.Status()
			return status.Associations == 1 && status.Sockets == 2
		})
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := retiring.Wait(ctx)
		cancel()
		if err != nil {
			t.Fatalf("retiring host did not close: %v", err)
		}
		fanout.registry[routeFromRandom([32]byte{byte(i + 2)})] = &associationOwner{
			host: retiring, principal: "principal",
		}
	}
	return fanout, healthy
}

// Walk joined errors left-to-right without assuming how repeated errors.Join
// calls nest their slices. Count actual error leaves, not their rendered text.
func fanoutErrorLeaves(err error) []error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var leaves []error
		for _, child := range joined.Unwrap() {
			leaves = append(leaves, fanoutErrorLeaves(child)...)
		}
		return leaves
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if child := wrapped.Unwrap(); child != nil {
			return fanoutErrorLeaves(child)
		}
	}
	return []error{err}
}

func checkFanoutFailures(t *testing.T, err error, count int) {
	t.Helper()
	if err == nil {
		t.Fatal("closed recipients did not return an aggregate error")
	}
	if _, ok := err.(interface{ Unwrap() []error }); !ok {
		t.Fatalf("NotifyAll returned the first error instead of joining failures: %T", err)
	}
	leaves := fanoutErrorLeaves(err)
	if len(leaves) != count {
		t.Fatalf("aggregate contains %d recipient errors, want %d", len(leaves), count)
	}
	seen := make(map[*syntra.RpcError]struct{}, count)
	for _, leaf := range leaves {
		var rpc *syntra.RpcError
		if !errors.As(leaf, &rpc) || rpc.Code != syntra.ErrorCodeFailedPrecondition {
			t.Fatalf("closed recipient failure lost its typed code: %v", leaf)
		}
		if !errors.Is(err, rpc) {
			t.Fatal("recipient failure is not accessible through the aggregate")
		}
		if _, duplicate := seen[rpc]; duplicate {
			t.Fatal("aggregate repeated one error instead of retaining distinct recipient failures")
		}
		seen[rpc] = struct{}{}
	}
	var first *syntra.RpcError
	if !errors.As(err, &first) || first != leaves[0] {
		t.Fatal("errors.As did not retain the aggregate's left-to-right error order")
	}
}

func receiveFanout(t *testing.T, client *connection.Client, want []byte) {
	t.Helper()
	select {
	case notification, ok := <-client.Notifications():
		if !ok || notification == nil || !bytes.Equal(notification.Payload, want) {
			t.Fatalf("healthy recipient notification = %v, want payload %q", notification, want)
		}
	case <-time.After(time.Second):
		t.Fatal("failed recipient prevented notification to the healthy recipient")
	}
}

func TestDirectNotifyAllContinuesAfterClosedRecipient(t *testing.T) {
	fanout, healthy := directFanoutFixture(t, 1)
	// Every broadcast must deliver, regardless of the registry's iteration order.
	// The joined-error assertion also deterministically rejects a naked
	// first-error return even when that particular iteration visits healthy first.
	for i := 0; i < 100; i++ {
		payload := []byte(fmt.Sprintf("direct fanout %03d", i))
		err := fanout.NotifyAll(payload)
		receiveFanout(t, healthy, payload)
		checkFanoutFailures(t, err, 1)
	}
}

func TestDirectNotifyAllJoinsEveryFailedRecipient(t *testing.T) {
	fanout, healthy := directFanoutFixture(t, 2)
	payload := []byte("healthy delivery with two closed recipients")
	err := fanout.NotifyAll(payload)
	// Two distinct retained failures make this fail an early return for
	// every possible map order, independently of whether healthy was visited.
	checkFanoutFailures(t, err, 2)
	receiveFanout(t, healthy, payload)
}
