package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func applicationAdmissionListener(t *testing.T, n *Network, admit func(context.Context, *ordered.EstablishmentBudget) (func(), error)) (*HTTPListener, Connector) {
	t.Helper()
	cc, sc := trust(t, securechannel.HTTP)
	cc.AllowHTTPCandidate, sc.AllowHTTPCandidate = true, true
	authority, err := syntrahttp.NewAuthority("localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	l, err := n.ListenHTTP(syntrahttp.ServerConfig{Address: "127.0.0.1:0", Authority: authority, Security: sc, Host: listenerConfig(sc).Host, AdmitAssociation: admit})
	if err != nil {
		t.Fatal(err)
	}
	return l, func(ctx context.Context, budget *ordered.EstablishmentBudget) (*connection.Client, error) {
		return syntrahttp.Dial(ctx, netip.MustParseAddrPort(l.LocalAddr().String()), authority, nil, cc, syntra.ClientConfig{}, ordered.Options{Budget: budget})
	}
}

type externalDialResult struct {
	client *connection.Client
	err    error
}

func startExternalDial(ctx context.Context, connector Connector) <-chan externalDialResult {
	result := make(chan externalDialResult, 1)
	go func() {
		budget, err := ordered.NewEstablishmentBudget(nil, 2*time.Second)
		if err != nil {
			result <- externalDialResult{err: err}
			return
		}
		client, err := connector(ctx, budget)
		result <- externalDialResult{client: client, err: err}
	}()
	return result
}

func TestApplicationHTTPAdmissionUsesCallbackQuota(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxCallbacks = 1
	n := testNetwork(t, cfg)
	gate := make(chan struct{})
	var gateOnce sync.Once
	t.Cleanup(func() { gateOnce.Do(func() { close(gate) }) })
	var calls, active, maximum, releases atomic.Int32
	entered := make(chan struct{}, 2)
	l, dial := applicationAdmissionListener(t, n, func(context.Context, *ordered.EstablishmentBudget) (func(), error) {
		calls.Add(1)
		now := active.Add(1)
		for old := maximum.Load(); now > old && !maximum.CompareAndSwap(old, now); old = maximum.Load() {
		}
		defer active.Add(-1)
		entered <- struct{}{}
		<-gate
		return func() { releases.Add(1) }, nil
	})
	ctx := testContext(t)
	first := startExternalDial(ctx, dial)
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first application admission did not enter")
	}
	if report := n.Snapshot().Shutdown; report.LiveCallbacks != 1 || l.Snapshot().Callbacks != 1 {
		t.Fatalf("unaccounted application admission: %+v", report)
	}
	second := startExternalDial(ctx, dial)
	until(t, func() bool { return maximum.Load() > 1 || l.Snapshot().Server.Rejected > 0 })
	if calls.Load() != 1 || maximum.Load() != 1 {
		t.Fatalf("callback quota bypassed: calls=%d maximum=%d", calls.Load(), maximum.Load())
	}
	select {
	case result := <-second:
		if result.client != nil {
			_ = result.client.Close()
			t.Fatal("second admission bypassed the occupied callback slot")
		}
		if result.err == nil {
			t.Fatal("busy admission did not report failure")
		}
	case <-ctx.Done():
		t.Fatal("busy association was not rejected")
	}
	gateOnce.Do(func() { close(gate) })
	result := <-first
	if result.err != nil {
		t.Fatal(result.err)
	}
	if err := result.client.Close(); err != nil {
		t.Fatal(err)
	}
	until(t, func() bool { return releases.Load() == 1 && l.Snapshot().Admitted == 0 })
	if maximum.Load() != 1 || releases.Load() != 1 {
		t.Fatal("application admission/release was not serialized exactly once")
	}
}

func TestApplicationHTTPReleaseWaitsForCallbackQuotaDuringShutdown(t *testing.T) {
	openEntered, openGate := make(chan struct{}), make(chan struct{})
	releaseEntered, releaseGate := make(chan struct{}), make(chan struct{})
	var openOnce, releaseOnce sync.Once
	cfg := DefaultConfig()
	cfg.MaxCallbacks = 1
	cfg.CloseTimeout = 20 * time.Millisecond
	cfg.StreamHost = StreamHostFunc(func(ctx context.Context, _ string) (net.Conn, error) {
		close(openEntered)
		<-openGate
		return nil, ctx.Err()
	})
	n := testNetwork(t, cfg)
	t.Cleanup(func() { openOnce.Do(func() { close(openGate) }); releaseOnce.Do(func() { close(releaseGate) }) })
	var releases atomic.Int32
	l, dial := applicationAdmissionListener(t, n, func(context.Context, *ordered.EstablishmentBudget) (func(), error) {
		return func() { releases.Add(1); close(releaseEntered); <-releaseGate }, nil
	})
	result := <-startExternalDial(testContext(t), dial)
	if result.err != nil {
		t.Fatal(result.err)
	}
	openDone := make(chan error, 1)
	go func() {
		budget, _ := ordered.NewEstablishmentBudget(nil, 2*time.Second)
		_, err := n.Open(context.Background(), "occupied-callback", budget)
		openDone <- err
	}()
	<-openEntered
	if err := result.client.Close(); err != nil {
		t.Fatal(err)
	}
	until(t, func() bool { return l.Snapshot().Server.Completed == 1 })
	if releases.Load() != 0 || l.Snapshot().Admitted != 1 {
		t.Fatal("release bypassed the occupied quota or dropped the retained lease")
	}
	report := n.Shutdown(context.Background())
	if report.Complete || report.LiveCallbacks != 1 || report.LiveConnections != 1 {
		t.Fatalf("cleanup ownership lost while quota was full: %+v", report)
	}
	openOnce.Do(func() { close(openGate) })
	if err := <-openDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected owned open completion: %v", err)
	}
	select {
	case <-releaseEntered:
	case <-time.After(time.Second):
		t.Fatal("mandatory release was discarded at shutdown")
	}
	report = n.Snapshot().Shutdown
	if report.LiveCallbacks != 1 || l.Snapshot().Callbacks != 1 || report.LiveConnections != 1 || report.Complete {
		t.Fatalf("release invocation was not charged: %+v", report)
	}
	select {
	case <-l.Done():
		t.Fatal("listener completed before application release returned")
	default:
	}
	releaseOnce.Do(func() { close(releaseGate) })
	select {
	case <-n.Done():
	case <-time.After(3 * time.Second):
		t.Fatalf("release completion not joined: %+v", n.Snapshot())
	}
	if releases.Load() != 1 || n.Snapshot().Shutdown.LiveConnections != 0 {
		t.Fatal("release was duplicated or admission leaked")
	}
}
