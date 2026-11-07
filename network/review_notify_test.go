package network

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

func receiveNotice(t *testing.T, client *connection.Client, want string) {
	t.Helper()
	ctx := testContext(t)
	select {
	case note, ok := <-client.Notifications():
		if !ok || string(note.GetPayload()) != want {
			t.Fatalf("notification=%v open=%v want=%q", note, ok, want)
		}
	case <-ctx.Done():
		t.Fatalf("healthy client missed notification %q", want)
	}
}

func TestNotifySkipsGatedUnauthenticatedSession(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	gate, entered := make(chan struct{}), make(chan struct{})
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(gate) }) })
	cfg := listenerConfig(sc)
	cfg.Host.ChannelPolicy = func(ctx context.Context, _ syntra.ChannelIdentity, credential []byte) (string, error) {
		if string(credential) == "held" {
			close(entered)
			select {
			case <-gate:
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		return "device", nil
	}
	l, err := n.ListenTCP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t)
	healthy, err := tcp.Dial(ctx, l.LocalAddr().String(), cc, syntra.ClientConfig{}, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = healthy.Close() })
	pending := make(chan externalDialResult, 1)
	go func() {
		client, err := tcp.Dial(ctx, l.LocalAddr().String(), cc, syntra.ClientConfig{Credential: []byte("held")}, ordered.Options{})
		pending <- externalDialResult{client: client, err: err}
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("pending authentication did not enter")
	}
	if err := l.NotifyAll([]byte("all")); err != nil {
		t.Fatalf("unauthenticated session poisoned broadcast: %v", err)
	}
	receiveNotice(t, healthy, "all")
	if err := l.NotifyDirected("device", []byte("directed")); err != nil {
		t.Fatal(err)
	}
	receiveNotice(t, healthy, "directed")
	release.Do(func() { close(gate) })
	result := <-pending
	if result.err != nil {
		t.Fatal(result.err)
	}
	_ = result.client.Close()
}

// The peer receives Ready, but the server's write does not return yet. Its
// ACTIVE notification queue therefore has a deterministic bounded backlog.
type deliveredWriteGate struct {
	net.Conn
	block     func(int, []byte) bool
	writes    int
	gated     bool
	entered   chan struct{}
	release   <-chan struct{}
	closed    chan struct{}
	closeOnce sync.Once
	err       error
}

func (c *deliveredWriteGate) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.writes++
	if err == nil && !c.gated && c.block(c.writes, p) {
		c.gated = true
		close(c.entered)
		select {
		case <-c.release:
		case <-c.closed:
			return n, net.ErrClosed
		}
	}
	return n, err
}
func (c *deliveredWriteGate) Close() error {
	c.closeOnce.Do(func() { close(c.closed); c.err = c.Conn.Close() })
	return c.err
}

type backlogListener struct {
	net.Listener
	first   bool
	entered chan struct{}
	release <-chan struct{}
}

func (l *backlogListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil || l.first {
		return conn, err
	}
	l.first = true
	return &deliveredWriteGate{Conn: conn, block: func(write int, _ []byte) bool { return write == 4 }, entered: l.entered, release: l.release, closed: make(chan struct{})}, nil
}

type backlogTLSProvider struct {
	tlsstream.Provider
	accepted atomic.Int32
	entered  chan struct{}
	release  <-chan struct{}
}

func (p *backlogTLSProvider) Accept(ctx context.Context, conn net.Conn, authority tlsstream.Authority) (tlsstream.Result, error) {
	ordinal := p.accepted.Add(1)
	result, err := p.Provider.Accept(ctx, conn, authority)
	if err != nil || ordinal > 2 {
		return result, err
	}
	poll := false
	result.Conn = &deliveredWriteGate{Conn: result.Conn, entered: p.entered, release: p.release, closed: make(chan struct{}), block: func(_ int, body []byte) bool {
		if bytes.HasPrefix(body, []byte("HTTP/1.1 200 ")) {
			poll = true
			return false
		}
		return poll
	}}
	return result, nil
}

const (
	backlogNotificationsPerKind = 8
	// Receiving a notification does not join the server's active Send. Leave
	// room for the entire healthy burst even if no writer slot is released.
	backlogWriterCapacity = 2 * backlogNotificationsPerKind
)

func assertBacklogDoesNotSkipHealthy(t *testing.T, badHost *syntra.Host, healthy *connection.Client, all func([]byte) error, directed func(string, []byte) error) {
	t.Helper()
	for i := 0; i < backlogWriterCapacity; i++ {
		if err := badHost.NotifyDirected("device", []byte("fills-bounded-queue")); err != nil {
			t.Fatalf("fill backlogged queue at %d: %v", i, err)
		}
	}
	for _, send := range []struct {
		payload string
		notify  func([]byte) error
	}{
		{"all", all},
		{"directed", func(payload []byte) error { return directed("device", payload) }},
	} {
		for i := 0; i < backlogNotificationsPerKind; i++ {
			err := send.notify([]byte(send.payload))
			var rpc *syntra.RpcError
			if !errors.As(err, &rpc) || rpc.Code != syntra.ErrorCodeResourceExhausted {
				t.Fatalf("backlog error was not preserved: %v", err)
			}
			receiveNotice(t, healthy, send.payload)
		}
	}
}

func TestNotifyContinuesPastBoundedTCPBacklog(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.TCP)
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gate, entered := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	t.Cleanup(func() { release.Do(func() { close(gate) }) })
	cfg := listenerConfig(sc)
	cfg.Listener = &backlogListener{Listener: raw, entered: entered, release: gate}
	cfg.Host.WriterCapacity = backlogWriterCapacity
	l, err := n.ListenTCP(cfg)
	if err != nil {
		_ = raw.Close()
		t.Fatal(err)
	}
	ctx := testContext(t)
	bad, err := tcp.Dial(ctx, l.LocalAddr().String(), cc, syntra.ClientConfig{}, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bad.Close() })
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("backlogged Ready write did not enter")
	}
	l.mu.Lock()
	var badHost *syntra.Host
	for session := range l.sessions {
		badHost = session.host
	}
	l.mu.Unlock()
	if badHost == nil {
		t.Fatal("missing backlogged host")
	}
	healthy, err := tcp.Dial(ctx, l.LocalAddr().String(), cc, syntra.ClientConfig{}, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = healthy.Close() })
	assertBacklogDoesNotSkipHealthy(t, badHost, healthy, l.NotifyAll, l.NotifyDirected)
	release.Do(func() { close(gate) })
}

func TestNotifyContinuesPastBoundedHTTPSBacklog(t *testing.T) {
	n := testNetwork(t, DefaultConfig())
	cc, sc := trust(t, securechannel.HTTPS)
	cc.AllowHTTPCandidate, sc.AllowHTTPCandidate = true, true
	authority, err := syntrahttp.NewAuthority("localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	gate, entered := make(chan struct{}), make(chan struct{})
	var release sync.Once
	defer release.Do(func() { close(gate) })
	t.Cleanup(func() { release.Do(func() { close(gate) }) })
	provider := tlsProvider(t)
	serverTLS := &backlogTLSProvider{Provider: provider, entered: entered, release: gate}
	hostcfg := listenerConfig(sc).Host
	hostcfg.WriterCapacity = backlogWriterCapacity
	l, err := n.ListenHTTPS(syntrahttp.ServerConfig{Address: "127.0.0.1:0", Authority: authority, Security: sc, TLS: serverTLS, Host: hostcfg})
	if err != nil {
		t.Fatal(err)
	}
	// Initial managed controls enable native admission asynchronously. Wait
	// before dialing so startup rejection cannot replace the backlog scenario.
	until(t, func() bool { return !l.Snapshot().Server.Paused })
	ctx := testContext(t)
	destination := netip.MustParseAddrPort(l.LocalAddr().String())
	bad, err := syntrahttp.Dial(ctx, destination, authority, provider, cc, syntra.ClientConfig{}, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = bad.Close() })
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("backlogged HTTPS Ready write did not enter")
	}
	hosts := l.server.Hosts()
	if len(hosts) != 1 {
		t.Fatalf("backlogged host count=%d", len(hosts))
	}
	healthy, err := syntrahttp.Dial(ctx, destination, authority, provider, cc, syntra.ClientConfig{}, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = healthy.Close() })
	assertBacklogDoesNotSkipHealthy(t, hosts[0], healthy, l.NotifyAll, l.NotifyDirected)
	release.Do(func() { close(gate) })
}
