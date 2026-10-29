package websocket

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ws "github.com/coder/websocket"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func configs(t testing.TB, carrier securechannel.Carrier) (securechannel.ClientConfig, securechannel.ServerConfig) {
	t.Helper()
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	return securechannel.ClientConfig{Context: securechannel.Context{Mode: securechannel.Bootstrap, Carrier: carrier, Scope: "test"}, ServerPublicKey: key.Public()}, securechannel.ServerConfig{StaticKey: key, Scope: "test", Carrier: carrier, AllowBootstrap: true}
}

func TestWSAndTrustedWSSRoundTrip(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "ws", true: "wss"}[secure], func(t *testing.T) {
			carrier := securechannel.WS
			if secure {
				carrier = securechannel.WSS
			}
			cc, sc := configs(t, carrier)
			accepted := make(chan *ordered.Transport, 1)
			errs := make(chan error, 1)
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tr, err := Accept(context.Background(), w, r, sc, Options{})
				if err != nil {
					errs <- err
					return
				}
				accepted <- tr
			}))
			var opts Options
			if secure {
				srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
				srv.StartTLS()
				roots := x509.NewCertPool()
				roots.AddCert(srv.Certificate())
				opts.HTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
			} else {
				srv.Start()
			}
			defer srv.Close()
			address := "ws" + strings.TrimPrefix(srv.URL, "http")
			client, err := Dial(context.Background(), address, cc, opts)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			var server *ordered.Transport
			select {
			case server = <-accepted:
			case err := <-errs:
				t.Fatal(err)
			case <-time.After(time.Second):
				t.Fatal("accept stalled")
			}
			defer server.Close()
			if _, ok := server.ChannelIdentity(); ok {
				t.Fatal("premature confirmation")
			}
			for _, size := range []int{1, 65515, 65516, ordered.MaxFrame} {
				want := bytes.Repeat([]byte{byte(size)}, size)
				done := make(chan error, 1)
				go func() { done <- client.Send(context.Background(), want) }()
				got, err := server.Recv(context.Background())
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("size %d: %v", size, err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
			id, ok := server.ChannelIdentity()
			if !ok || id.Carrier != carrier.String() {
				t.Fatalf("identity %+v %v", id, ok)
			}
			// Control traffic must remain separate from SC1 records.
			recvCtx, cancel := context.WithCancel(context.Background())
			a, b := make(chan error, 1), make(chan error, 1)
			go func() { _, err := server.Recv(recvCtx); a <- err }()
			go func() { _, err := client.Recv(recvCtx); b <- err }()
			if err := client.Ping(context.Background()); err != nil {
				t.Fatal(err)
			}
			cancel()
			client.Close()
			server.Close()
			for _, done := range []chan error{a, b} {
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Fatal("Recv did not stop")
				}
			}
		})
	}
}

func TestRejectSubprotocolCarrierOriginAndInsecureTLS(t *testing.T) {
	cc, sc := configs(t, securechannel.WS)
	for _, protocol := range []string{"", "syntra", "SYNTRA.SC1.DRAFT1"} {
		r := httptest.NewRequest("GET", "http://test/", nil)
		r.Header.Set("Sec-WebSocket-Protocol", protocol)
		w := httptest.NewRecorder()
		if _, err := Accept(context.Background(), w, r, sc, Options{}); err == nil || w.Code != http.StatusBadRequest {
			t.Fatalf("subprotocol %q: %d %v", protocol, w.Code, err)
		}
	}
	r := httptest.NewRequest("GET", "https://test/", nil)
	r.Header.Set("Sec-WebSocket-Protocol", Subprotocol)
	w := httptest.NewRecorder()
	if _, err := Accept(context.Background(), w, r, sc, Options{}); err == nil {
		t.Fatal("TLS carrier mismatch accepted")
	}
	for _, address := range []string{"http://example.test", "https://example.test", "ftp://example.test", "ws://user:pass@example.test"} {
		if _, err := Dial(context.Background(), address, cc, Options{}); !errors.Is(err, securechannel.ErrConfig) {
			t.Fatalf("URL %s: %v", address, err)
		}
	}
	unsafe := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	if _, err := Dial(context.Background(), "ws://example.test", cc, Options{HTTPClient: unsafe}); !errors.Is(err, securechannel.ErrConfig) {
		t.Fatal("insecure verification accepted")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = Accept(context.Background(), w, r, sc, Options{}) }))
	defer srv.Close()
	_, response, err := ws.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), &ws.DialOptions{Subprotocols: []string{Subprotocol}, HTTPHeader: http.Header{"Origin": []string{"https://evil.example"}}})
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatal("cross origin upgrade accepted")
	}
}

func TestRedirectsRefusedAndDefaultTLSVerified(t *testing.T) {
	cc, _ := configs(t, securechannel.WSS)
	targetHit := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetHit = true }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer redirect.Close()
	address := "wss" + strings.TrimPrefix(redirect.URL, "https")
	if _, err := Dial(context.Background(), address, cc, Options{}); err == nil {
		t.Fatal("untrusted test certificate accepted")
	}
	roots := x509.NewCertPool()
	roots.AddCert(redirect.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	if _, err := Dial(context.Background(), address, cc, Options{HTTPClient: client}); err == nil {
		t.Fatal("redirect accepted")
	}
	if targetHit {
		t.Fatal("WSS redirect downgraded")
	}
}

func TestExactSubprotocolSelectedAmongCaseVariants(t *testing.T) {
	_, sc := configs(t, securechannel.WS)
	done := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr, err := Accept(context.Background(), w, r, sc, Options{})
		if tr != nil {
			tr.Close()
		}
		done <- err
	}))
	defer srv.Close()
	client, _, err := ws.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), &ws.DialOptions{Subprotocols: []string{strings.ToUpper(Subprotocol), Subprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	if client.Subprotocol() != Subprotocol {
		t.Fatalf("negotiated %q", client.Subprotocol())
	}
	client.CloseNow()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handshake socket did not close")
	}
}

// rawPeer completes SC1, then exposes the actual WS wire for malformed and
// fragmented-frame tests. It uses real loopback sockets, never NetConn.
func rawPeer(t *testing.T, limits ordered.Options) (*ws.Conn, net.Conn, *securechannel.Channel, <-chan *ordered.Transport) {
	t.Helper()
	cc, sc := configs(t, securechannel.WS)
	accepted := make(chan *ordered.Transport, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr, err := Accept(context.Background(), w, r, sc, Options{Limits: limits})
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- tr
	}))
	t.Cleanup(srv.Close)
	var raw net.Conn
	httpClient := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, address)
		raw = c
		return c, err
	}}}
	c, _, err := ws.Dial(context.Background(), "ws"+strings.TrimPrefix(srv.URL, "http"), &ws.DialOptions{HTTPClient: httpClient, Subprotocols: []string{Subprotocol}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.CloseNow() })
	i, first, err := securechannel.Begin(cc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Write(ctx, ws.MessageBinary, first); err != nil {
		t.Fatal(err)
	}
	_, reply, err := c.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := i.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ch.Close)
	return c, raw, ch, accepted
}

func maskedFrame(fin bool, opcode byte, p []byte) []byte {
	first := opcode
	if fin {
		first |= 128
	}
	out := []byte{first, 128}
	if len(p) < 126 {
		out[1] |= byte(len(p))
	} else {
		out[1] |= 126
		out = binary.BigEndian.AppendUint16(out, uint16(len(p)))
	}
	out = append(out, 0, 0, 0, 0) // zero mask is valid RFC framing, useful deterministically
	return append(out, p...)
}

func TestWSFragmentationAndCoalescing(t *testing.T) {
	_, raw, ch, accepted := rawPeer(t, ordered.Options{})
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()
	stream := binary.BigEndian.AppendUint32(nil, 5)
	stream = append(stream, "first"...)
	stream = binary.BigEndian.AppendUint32(stream, 6)
	stream = append(stream, "second"...)
	record, err := ch.Encrypt(nil, stream)
	if err != nil {
		t.Fatal(err)
	}
	wire := maskedFrame(false, 2, record[:3])
	wire = append(wire, maskedFrame(true, 0, record[3:])...)
	if _, err := raw.Write(wire); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"first", "second"} {
		frame, err := server.Recv(context.Background())
		if err != nil || string(frame) != want {
			t.Fatalf("%q %v", frame, err)
		}
	}
}

func TestWSSlowPartialHeaderAndFragmentTimeout(t *testing.T) {
	for _, partial := range [][]byte{{0x82}, maskedFrame(false, 2, []byte{1})} {
		t.Run(string(partial), func(t *testing.T) {
			_, raw, _, accepted := rawPeer(t, ordered.Options{RecordTimeout: 30 * time.Millisecond})
			server := <-accepted
			if server == nil {
				t.Fatal("accept failed")
			}
			defer server.Close()
			done := make(chan error, 1)
			go func() { _, err := server.Recv(context.Background()); done <- err }()
			select {
			case err := <-done:
				t.Fatalf("idle timeout: %v", err)
			case <-time.After(45 * time.Millisecond):
			}
			if _, err := raw.Write(partial); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("partial message accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("assembly clock missed partial WS header/fragment")
			}
		})
	}
}

func TestWSRejectTextOversizedAndBadTag(t *testing.T) {
	for _, kind := range []string{"text", "oversize", "bad-tag"} {
		t.Run(kind, func(t *testing.T) {
			c, _, ch, accepted := rawPeer(t, ordered.Options{})
			server := <-accepted
			if server == nil {
				t.Fatal("accept failed")
			}
			defer server.Close()
			done := make(chan error, 1)
			go func() { _, err := server.Recv(context.Background()); done <- err }()
			p := make([]byte, 17)
			typ := ws.MessageBinary
			switch kind {
			case "text":
				typ = ws.MessageText
			case "oversize":
				p = make([]byte, 65536)
			case "bad-tag":
				var err error
				p, err = ch.Encrypt(nil, []byte{0, 0, 0, 1, 7})
				if err != nil {
					t.Fatal(err)
				}
				p[len(p)-1] ^= 1
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = c.Write(ctx, typ, p)
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid message accepted")
				}
			case <-time.After(time.Second):
				t.Fatal("invalid message stalled")
			}
			if _, ok := server.ChannelIdentity(); ok {
				t.Fatal("invalid message confirmed identity")
			}
		})
	}
}
