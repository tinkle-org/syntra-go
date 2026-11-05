package websocket

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

type observingConn struct {
	net.Conn
	writes, closes atomic.Int32
}

func (c *observingConn) Write(p []byte) (int, error) { c.writes.Add(1); return c.Conn.Write(p) }
func (c *observingConn) Close() error                { c.closes.Add(1); return c.Conn.Close() }

type trustedObservation struct{ role tlsstream.Role }

func (p trustedObservation) result(c net.Conn, a tlsstream.Authority) (tlsstream.Result, error) {
	return tlsstream.Result{Conn: c, Metadata: tlsstream.Metadata{Authority: a, Role: p.role, Version: tls.VersionTLS13, ALPN: "http/1.1"}}, nil
}
func (p trustedObservation) Connect(_ context.Context, c net.Conn, a tlsstream.Authority) (tlsstream.Result, error) {
	return p.result(c, a)
}
func (p trustedObservation) Accept(_ context.Context, c net.Conn, a tlsstream.Authority) (tlsstream.Result, error) {
	return p.result(c, a)
}

func TestTLSUpgradeRejectsProofBeforeHTTP(t *testing.T) {
	for _, mismatch := range []string{"authority", "role", "budget", "scheme", "binding", "options"} {
		t.Run(mismatch, func(t *testing.T) {
			a, peer := net.Pipe()
			defer peer.Close()
			raw := &observingConn{Conn: a}
			budget := testBudget(t)
			authority, _ := tlsstream.NewAuthority("localhost", 443)
			role := tlsstream.Client
			if mismatch == "role" {
				role = tlsstream.Server
			}
			var proof *tlsstream.Verified
			var err error
			if role == tlsstream.Server {
				proof, err = tlsstream.Accept(context.Background(), raw, trustedObservation{role}, authority, budget)
			} else {
				proof, err = tlsstream.Connect(context.Background(), raw, trustedObservation{role}, authority, budget)
			}
			if err != nil {
				t.Fatal(err)
			}
			url := "wss://localhost" + EndpointPath
			security := securechannel.ClientConfig{Context: securechannel.Context{Carrier: securechannel.WSS}}
			opts := ordered.Options{Budget: budget}
			switch mismatch {
			case "authority":
				url = "wss://other.invalid" + EndpointPath
			case "budget":
				opts.Budget = testBudget(t)
			case "scheme":
				url = "ws://localhost" + EndpointPath
			case "binding":
				security.Context.Carrier = securechannel.WS
			case "options":
				opts.MaxPending = -1
			}
			client, err := ConnectTLS(context.Background(), proof, url, security, syntra.ClientConfig{}, opts)
			if client != nil || err == nil {
				t.Fatal("bad configuration accepted")
			}
			if raw.writes.Load() != 0 || raw.closes.Load() != 1 {
				t.Fatalf("writes=%d closes=%d", raw.writes.Load(), raw.closes.Load())
			}
		})
	}
}

func TestServerUpgradeRejectsBeforeResponse(t *testing.T) {
	base := "GET " + EndpointPath + " HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: AAECAwQFBgcICQoLDA0ODw==\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: " + Subprotocol + "\r\n"
	for _, request := range []string{
		"GET /wrong HTTP/1.1\r\n" + base[len("GET "+EndpointPath+" HTTP/1.1\r\n"):] + "\r\n",
		base + "Origin: null\r\n\r\n", base + "Cookie: private\r\n\r\n",
	} {
		a, peer := net.Pipe()
		raw := &observingConn{Conn: a}
		done := make(chan struct{})
		go func() { defer close(done); defer peer.Close(); _, _ = peer.Write([]byte(request)) }()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := upgrade(ctx, raw, tlsstream.Authority{}, false, testBudget(t))
		cancel()
		if !errors.Is(err, securechannel.ErrConfig) || raw.writes.Load() != 0 || raw.closes.Load() != 1 {
			t.Fatalf("err=%v writes=%d closes=%d", err, raw.writes.Load(), raw.closes.Load())
		}
		<-done
	}
}
