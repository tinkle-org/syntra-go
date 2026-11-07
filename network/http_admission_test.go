package network

import (
	"bufio"
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
	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func TestSharedAdmissionTCPHTTPFIFOAndIdleDoesNotHoard(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[secure], func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.MaxConnections = 1
			n := testNetwork(t, cfg)
			cc, sc := trust(t, securechannel.TCP)
			first, err := n.ListenTCP(listenerConfig(sc))
			if err != nil {
				t.Fatal(err)
			}
			last, err := n.ListenTCP(listenerConfig(sc))
			if err != nil {
				t.Fatal(err)
			}
			http, connector := managedHTTP(t, n, secure, nil)
			if n.admission.Available() != 1 || http.Snapshot().Admitted != 0 {
				t.Fatal("idle listeners reserved shared admission")
			}
			// Do not let initial paused admission reject the one-shot idle socket.
			until(t, func() bool { return !http.Snapshot().Server.Paused })
			// Even accepted sockets without an open header remain native/unbound;
			// neither stream is an application association yet.
			idle, err := net.Dial("tcp", http.LocalAddr().String())
			if err != nil {
				t.Fatal(err)
			}
			until(t, func() bool { return http.Snapshot().Server.UnboundStreams == 1 })
			if n.admission.Available() != 1 || http.Snapshot().WaitingAdmission != 0 {
				t.Fatal("idle HTTP socket hoarded shared admission")
			}
			_ = idle.Close()
			until(t, func() bool { return http.Snapshot().Server.Sockets == 0 })
			active, err := n.Client(reconnectConfig(), tcpConnector(first.LocalAddr().String(), cc))
			if err != nil {
				t.Fatal(err)
			}
			phase(t, active, CoreReady)
			waitingHTTP, err := n.Client(reconnectConfig(), connector)
			if err != nil {
				t.Fatal(err)
			}
			until(t, func() bool { return http.Snapshot().WaitingAdmission == 1 })
			waitingTCP, err := n.Client(reconnectConfig(), tcpConnector(last.LocalAddr().String(), cc))
			if err != nil {
				t.Fatal(err)
			}
			until(t, func() bool { return last.Snapshot().WaitingAdmission == 1 })
			active.Stop()
			phase(t, waitingHTTP, CoreReady)
			st := http.Snapshot()
			if st.Admitted != 1 || st.Server.Associations != 1 || st.Server.Sockets != 2 || n.admission.InUse() != 1 {
				t.Fatalf("two-stream admission: %+v in-use=%d", st, n.admission.InUse())
			}
			if waitingTCP.Snapshot().Phase == CoreReady || last.Snapshot().Admitted != 0 {
				t.Fatal("TCP waiter overtook earlier HTTP waiter")
			}
			waitingHTTP.Stop()
			phase(t, waitingTCP, CoreReady)
			st = http.Snapshot()
			if st.Admitted != 0 || st.Server.Associations != 0 || st.Server.Sockets != 0 || st.Server.ReservedBytes != 0 {
				t.Fatalf("HTTP permit handed off before native cleanup: %+v", st)
			}
			waitingTCP.Stop()
			until(t, func() bool { return n.admission.Available() == 1 })
		})
	}
}

func TestManagedHTTPSRecoverySourceRetainsNativeAndSharedAdmission(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConnections = 1
	cfg.CloseTimeout = 20 * time.Millisecond
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	source := &blockingRecoverySource{entered: make(chan struct{}), release: make(chan struct{})}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(source.release) }); n.Shutdown(testContext(t)) })
	service, err := syntra.NewRecoveryService(source, syntra.DefaultRecoveryLimits())
	if err != nil {
		t.Fatal(err)
	}
	cc, sc := trust(t, securechannel.HTTPS)
	cc.AllowHTTPCandidate = true
	sc.AllowHTTPCandidate = true
	authority, err := syntrahttp.NewAuthority("localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	provider := tlsProvider(t)
	host := listenerConfig(sc).Host
	host.Recovery = service
	http, err := n.ListenHTTPS(syntrahttp.ServerConfig{Address: "127.0.0.1:0", Authority: authority, Security: sc, TLS: provider, Host: host})
	if err != nil {
		t.Fatal(err)
	}
	store, err := syntra.NewMemoryRecoveryStore(syntra.DefaultRecoveryStoreLimits())
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewRecoveryFactory("device", store, syntra.DefaultRecoveryLimits(), &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: syntra.RecoveryCapability})
	if err != nil {
		t.Fatal(err)
	}
	reconnect := reconnectConfig()
	reconnect.RecoveryFactory = factory
	client, err := n.ClientWithSetup(reconnect, func(ctx context.Context, b *ordered.EstablishmentBudget, prepare func(*syntra.Client) error) (*connection.Client, error) {
		return syntrahttp.Dial(ctx, netip.MustParseAddrPort(http.LocalAddr().String()), authority, provider, cc, syntra.ClientConfig{Prepare: prepare}, ordered.Options{Budget: b})
	})
	if err != nil {
		t.Fatal(err)
	}
	phase(t, client, RecoveryNegotiated)
	bound, err := client.RecoveryClient()
	if err != nil {
		t.Fatal(err)
	}
	profile := bound.Value.(*RecoveryProfile).RecoveryClient
	sub, err := profile.Subscribe(testContext(t), &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("selector")}, []byte("stable"), syntra.RecoveryInitialLiveOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = profile.CatchUp(testContext(t), &pb.RecoveryCatchUpRequest{ProfileVersion: 1, SubscriptionHandle: sub.Response.SubscriptionHandle}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("source did not enter recovery egress")
	}
	tcpClient, tcpServer := trust(t, securechannel.TCP)
	tcp, err := n.ListenTCP(listenerConfig(tcpServer))
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := n.Client(reconnectConfig(), tcpConnector(tcp.LocalAddr().String(), tcpClient))
	if err != nil {
		t.Fatal(err)
	}
	until(t, func() bool { return tcp.Snapshot().WaitingAdmission == 1 })
	client.Stop()
	// Core Serve's bounded drain can return while an uncooperative source is
	// still running. Host.Wait, native reservations and the shared lease must
	// all remain owned, rather than only preserving a listener-level observer.
	time.Sleep(300 * time.Millisecond)
	st := http.Snapshot()
	if st.Admitted != 1 || st.Server.Associations != 1 || st.Server.Sockets != 2 || st.Server.ReservedBytes == 0 || n.admission.InUse() != 1 {
		t.Fatalf("retained source lost admission/native ownership: %+v in-use=%d", st, n.admission.InUse())
	}
	if tcp.Snapshot().Admitted != 0 || waiting.Snapshot().Phase == CoreReady {
		t.Fatal("source released shared admission before exiting")
	}
	release.Do(func() { close(source.release) })
	phase(t, waiting, CoreReady)
	st = http.Snapshot()
	if st.Admitted != 0 || st.Server.Associations != 0 || st.Server.Sockets != 0 || st.Server.ReservedBytes != 0 {
		t.Fatalf("retired HTTP source retained resources after handoff: %+v", st)
	}
	waiting.Stop()
	until(t, func() bool { return n.admission.Available() == 1 })
}

func TestManagedHTTPComposesCallerAdmissionAndReleasesAfterNativeCleanup(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxConnections = 1
	n := testNetwork(t, cfg)
	_, sc := trust(t, securechannel.HTTP)
	sc.AllowHTTPCandidate = true
	authority, err := syntrahttp.NewAuthority("localhost:443")
	if err != nil {
		t.Fatal(err)
	}
	var calls, releases, authenticated atomic.Int32
	host := listenerConfig(sc).Host
	base := host.ChannelPolicy
	host.ChannelPolicy = func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
		authenticated.Add(1)
		return base(ctx, id, credential)
	}
	var listener *HTTPListener
	bound := make(chan struct{})
	listener, err = n.ListenHTTP(syntrahttp.ServerConfig{Address: "127.0.0.1:0", Authority: authority, Security: sc, Host: host, AdmitAssociation: func(ctx context.Context, b *ordered.EstablishmentBudget) (func(), error) {
		calls.Add(1)
		if n.admission.InUse() != 1 || ctx.Err() != nil || b.Check() != nil {
			t.Error("managed admission must precede caller admission")
		}
		return func() {
			<-bound
			st := listener.Snapshot()
			if st.Server.Associations != 0 || st.Server.Sockets != 0 || st.Server.ReservedBytes != 0 || n.admission.InUse() != 1 {
				t.Errorf("caller release preceded native cleanup: %+v", st)
			}
			releases.Add(1)
		}, errors.New("private admission rejection")
	}})
	if err != nil {
		t.Fatal(err)
	}
	close(bound)
	// The parent installs initial controls asynchronously; wait until its native
	// listener is enabled before exercising the caller's explicit denial.
	until(t, func() bool { return !listener.Snapshot().Server.Paused })
	// Use only U, without a body or an unrelated unbound D socket. A denied
	// association must finish its native teardown before either hook releases.
	raw, err := net.Dial("tcp", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(time.Second))
	_, err = raw.Write([]byte("POST /syntra/1.0/http/open HTTP/1.1\r\nHost: localhost:443\r\nCache-Control: no-store\r\nAccept: application/octet-stream\r\nContent-Length: 83\r\nContent-Type: application/octet-stream\r\n\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(raw).ReadString('\n')
	if err != nil || line != "HTTP/1.1 503 Service Unavailable\r\n" {
		t.Fatalf("caller admission was replaced: %q %v", line, err)
	}
	until(t, func() bool { return n.admission.Available() == 1 })
	if calls.Load() != 1 || releases.Load() != 1 || authenticated.Load() != 0 {
		t.Fatalf("caller hook calls/releases/authentication: %d/%d/%d", calls.Load(), releases.Load(), authenticated.Load())
	}
}
