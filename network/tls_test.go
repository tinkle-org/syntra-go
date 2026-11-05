package network

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
	"github.com/tinkle-org/syntra-go/transport/websocket"
)

func tlsProvider(t *testing.T) *tlsstream.StandardProvider {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	p, err := tlsstream.NewStandardProvider(&tls.Config{RootCAs: pool}, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestManagedWSAndWSSListeners(t *testing.T) {
	for _, carrier := range []securechannel.Carrier{securechannel.WS, securechannel.WSS} {
		t.Run(string(carrier), func(t *testing.T) {
			n := testNetwork(t, DefaultConfig())
			cc, sc := trust(t, carrier)
			cfg := listenerConfig(sc)
			var provider *tlsstream.StandardProvider
			var authority tlsstream.Authority
			var l *Listener
			var err error
			if carrier == securechannel.WSS {
				provider = tlsProvider(t)
				authority, err = tlsstream.NewAuthority("localhost", 443)
				if err != nil {
					t.Fatal(err)
				}
				cfg.TLS = provider
				cfg.Authority = authority
				l, err = n.ListenWSS(cfg)
			} else {
				l, err = n.ListenWS(cfg)
			}
			if err != nil {
				t.Fatal(err)
			}
			c, err := n.Client(reconnectConfig(), func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
				raw, e := n.Open(ctx, l.LocalAddr().String(), b)
				if e != nil {
					return nil, e
				}
				if carrier == securechannel.WS {
					return websocket.Connect(ctx, raw, "ws://"+l.LocalAddr().String()+websocket.EndpointPath, cc, syntra.ClientConfig{}, ordered.Options{Budget: b})
				}
				verified, e := tlsstream.Connect(ctx, raw, provider, authority, b)
				if e != nil {
					return nil, e
				}
				return websocket.ConnectTLS(ctx, verified, "wss://localhost"+websocket.EndpointPath, cc, syntra.ClientConfig{}, ordered.Options{Budget: b})
			})
			if err != nil {
				t.Fatal(err)
			}
			phase(t, c, CoreReady)
			if err := l.NotifyAll([]byte("push")); err != nil {
				t.Fatal(err)
			}
			got, err := c.NextNotification(testContext(t))
			if err != nil || string(got.Value.Payload) != "push" {
				t.Fatalf("push=%+v error=%v", got, err)
			}
			gotCall, err := c.Call(testContext(t), "/test.Service/Echo", []byte("secure"), 1000)
			if err != nil || string(gotCall.Value) != "secure" {
				t.Fatalf("call=%+v error=%v", gotCall, err)
			}
		})
	}
}

type countedConn struct {
	net.Conn
	reads, writes atomic.Int32
}

func (c *countedConn) Read(p []byte) (int, error)  { c.reads.Add(1); return c.Conn.Read(p) }
func (c *countedConn) Write(p []byte) (int, error) { c.writes.Add(1); return c.Conn.Write(p) }

func TestTLSProviderWrapsApplicationSuppliedStream(t *testing.T) {
	provider := tlsProvider(t)
	authority, err := tlsstream.NewAuthority("localhost", 443)
	if err != nil {
		t.Fatal(err)
	}
	cc, sc := trust(t, securechannel.WSS)
	left, right := net.Pipe()
	raw := &countedConn{Conn: left}
	cfg := DefaultConfig()
	cfg.StreamHost = StreamHostFunc(func(context.Context, string) (net.Conn, error) { return raw, nil })
	n := testNetwork(t, cfg)
	host, err := syntra.OpenHost(listenerConfig(sc).Host)
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	serverCtx, cancel := context.WithCancel(testContext(t))
	defer cancel()
	served := make(chan error, 1)
	go func() {
		b, e := ordered.NewEstablishmentBudget(nil, time.Second)
		if e != nil {
			served <- e
			return
		}
		v, e := tlsstream.Accept(serverCtx, right, provider, authority, b)
		if e == nil {
			e = websocket.AcceptTLS(serverCtx, v, authority, sc, host, ordered.Options{Budget: b})
		}
		served <- e
	}()
	c, err := n.Client(reconnectConfig(), func(ctx context.Context, b *ordered.EstablishmentBudget) (*connection.Client, error) {
		conn, e := n.Open(ctx, "platform-stream", b)
		if e != nil {
			return nil, e
		}
		v, e := tlsstream.Connect(ctx, conn, provider, authority, b)
		if e != nil {
			return nil, e
		}
		return websocket.ConnectTLS(ctx, v, "wss://localhost"+websocket.EndpointPath, cc, syntra.ClientConfig{}, ordered.Options{Budget: b})
	})
	if err != nil {
		t.Fatal(err)
	}
	phase(t, c, CoreReady)
	got, err := c.Call(testContext(t), "/test.Service/Echo", []byte("custom TLS"), 1000)
	if err != nil || string(got.Value) != "custom TLS" || raw.reads.Load() == 0 || raw.writes.Load() == 0 {
		t.Fatalf("call=%+v error=%v reads=%d writes=%d", got, err, raw.reads.Load(), raw.writes.Load())
	}
	c.Stop()
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("TLS stream server did not finish")
	}
}
