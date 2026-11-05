package syntra

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAlignmentAbandonedAuthenticationRetainsSharedExecutionCharge(t *testing.T) {
	budget, err := NewExecutionBudget(1)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	h, err := OpenHost(HostConfig{
		ExecutionBudget:  budget,
		HandshakeTimeout: 30 * time.Millisecond,
		Policy: func(context.Context, []byte) (string, error) {
			close(entered)
			<-release
			return "late", nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	a, peer := LoopbackPair()
	defer peer.Close()
	done := make(chan error, 1)
	go func() { done <- h.Serve(context.Background(), a) }()
	raw := mustMarshal(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if err := peer.Send(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("policy did not start")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("handshake = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("noncooperative policy blocked handshake shutdown")
	}
	if budget.Live() != 1 {
		t.Fatalf("abandoned callback charge = %d", budget.Live())
	}
	replacement, err := OpenHost(HostConfig{ExecutionBudget: budget, Policy: StaticPolicy("replacement", true)})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	b, replacementPeer := LoopbackPair()
	defer replacementPeer.Close()
	go func() { done <- replacement.Serve(context.Background(), b) }()
	if err := replacementPeer.Send(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		alignmentCode(t, err, ErrorCodeResourceExhausted)
	case <-time.After(time.Second):
		t.Fatal("replacement ignored shared callback capacity")
	}
}
