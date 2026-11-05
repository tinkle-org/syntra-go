package syntrahttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func nativeRequest(t *testing.T, s *Server, header, body []byte) ([]byte, error) {
	t.Helper()
	c, e := net.Dial("tcp", s.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if e = writeUnit(c, header, body); e != nil {
		return nil, e
	}
	return readHeader(c)
}

func TestAssociationQuotaRejectsBeforeBody(t *testing.T) {
	cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	s := startServer(t, sc, hostConfig(), nil, ServerLimits{Associations: 1, Handshakes: 1})
	client := connectTo(t, s, cc, nil)
	head, _ := requestHeader(Open, testAuthority(t), Route{}, 0, 83)
	got, e := nativeRequest(t, s, head, nil)
	if e != nil || !bytes.HasPrefix(got, []byte("HTTP/1.1 503 ")) {
		t.Fatalf("association quota: %q %v", got, e)
	}
	st := s.Status()
	if st.Associations != 1 || st.ReservedBytes < s.reservation {
		t.Fatalf("quota counters: %+v", st)
	}
	callEcho(t, client, []byte("existing association survives"))
}

func TestSingleAssociationHTTPSQuotaAdmitsBothTLSStreams(t *testing.T) {
	cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTPS)
	provider := testProvider(t)
	s := startServer(t, sc, hostConfig(), provider, ServerLimits{Associations: 1, Handshakes: 1, UnboundStreams: 2, Sockets: 4})
	client := connectTo(t, s, cc, provider)
	callEcho(t, client, []byte("one association owns two TLS streams"))
}

func TestPrincipalQuotaDoesNotGrantFromRoute(t *testing.T) {
	cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	s := startServer(t, sc, hostConfig(), nil, ServerLimits{PrincipalAssociations: 1})
	client := connectTo(t, s, cc, nil)
	second, e := Dial(context.Background(), netip.MustParseAddrPort(s.Addr().String()), testAuthority(t), nil, cc, syntra.ClientConfig{Credential: []byte("explicit")}, ordered.Options{})
	if second != nil || e == nil {
		if second != nil {
			_ = second.Close()
		}
		t.Fatal("principal quota admitted a second association")
	}
	awaitCondition(t, func() bool { return s.Status().Associations == 1 })
	callEcho(t, client, []byte("first principal lease remains usable"))
	_ = client.Close()
	awaitCondition(t, func() bool { return s.Status().Associations == 0 })
	client = connectTo(t, s, cc, nil)
	callEcho(t, client, []byte("lease released after cleanup"))
}

func TestOpenRateQuotaIsNativeAndPreBody(t *testing.T) {
	_, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	s := startServer(t, sc, hostConfig(), nil, ServerLimits{OpensPerSecond: 1, OpenBurst: 1, SourceOpensPerSecond: 1, SourceOpenBurst: 1})
	head, _ := requestHeader(Open, testAuthority(t), Route{}, 0, 83)
	if got, e := nativeRequest(t, s, head, bytes.Repeat([]byte{1}, 83)); e == nil {
		t.Fatalf("invalid M1 accepted: %q", got)
	}
	awaitCondition(t, func() bool { return s.Status().Associations == 0 })
	got, e := nativeRequest(t, s, head, nil)
	if e != nil || !bytes.HasPrefix(got, []byte("HTTP/1.1 429 ")) {
		t.Fatalf("rate quota: %q %v", got, e)
	}
}

func TestUnboundQuotaAndMemoryConfiguration(t *testing.T) {
	_, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTP)
	cfg := ServerConfig{Address: "127.0.0.1:0", Authority: testAuthority(t), Security: sc, Host: hostConfig(), Limits: ServerLimits{AggregateBytes: 1}}
	if s, e := Bind(cfg); s != nil || !errors.Is(e, ordered.ErrOptions) {
		if s != nil {
			_ = s.Close()
		}
		t.Fatal("unfunded runtime reservation accepted")
	}
	s := startServer(t, sc, hostConfig(), nil, ServerLimits{UnboundStreams: 1})
	first, e := net.Dial("tcp", s.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	awaitCondition(t, func() bool { return s.Status().UnboundStreams == 1 })
	st := s.Status()
	if st.ReservedBytes != unboundBytes || st.Sockets != 1 {
		t.Fatalf("unbound reservation: %+v", st)
	}
	second, e := net.Dial("tcp", s.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, e = second.Read(b[:])
	if e == nil {
		t.Fatal("unbound quota admitted extra socket")
	}
	if ne, ok := e.(net.Error); ok && ne.Timeout() {
		t.Fatal("over-quota socket was not closed")
	}
	_ = first.Close()
	awaitCondition(t, func() bool {
		st := s.Status()
		return st.Sockets == 0 && st.UnboundStreams == 0 && st.ReservedBytes == 0
	})
}

func TestOwnedRunCancellationAndCloseBeforeRun(t *testing.T) {
	_, sc := securityConfigs(t, securechannel.Bootstrap, securechannel.HTTP)
	cfg := ServerConfig{Address: "127.0.0.1:0", Authority: testAuthority(t), Security: sc, Host: hostConfig()}
	s, e := Bind(cfg)
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	peer, e := net.Dial("tcp", s.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	awaitCondition(t, func() bool { return s.Status().Sockets == 1 })
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("Run failed to join")
	}
	if !s.Status().Stopped || s.Status().ReservedBytes != 0 {
		t.Fatal("Run returned before cleanup")
	}
	_ = peer.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, e := peer.Read(b[:]); !errors.Is(e, io.EOF) {
		t.Fatalf("owned socket not closed: %v", e)
	}
	s, e = Bind(cfg)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil || !s.Status().Stopped {
		t.Fatal("unstarted listener did not close", e)
	}
}
