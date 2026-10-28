package websocket

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	ws "github.com/coder/websocket"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func TestEveryPartialWireFrameHasAssemblyBudget(t *testing.T) {
	ping := maskedFrame(true, 9, []byte("ping"))
	for _, test := range []struct {
		name    string
		partial []byte
	}{
		{"ping-header", []byte{0x89}},
		{"close-header", []byte{0x88}},
		{"reserved-header", []byte{0x83}},
		{"ping-payload", ping[:len(ping)-1]},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, raw, _, accepted := rawPeer(t, ordered.Options{RecordTimeout: 30 * time.Millisecond})
			server := <-accepted
			if server == nil {
				t.Fatal("accept failed")
			}
			defer server.Close()
			done := make(chan error, 1)
			go func() { _, err := server.Recv(context.Background()); done <- err }()
			if _, err := raw.Write(test.partial); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("partial frame accepted")
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("started frame escaped 30ms assembly budget")
			}
			if err := server.Send(context.Background(), []byte("reuse")); !errors.Is(err, ordered.ErrClosed) {
				t.Fatalf("partial frame left channel usable: %v", err)
			}
		})
	}
}

func TestCompletedIdleControlsDoNotSetDataDeadline(t *testing.T) {
	client, _, _, accepted := rawPeer(t, ordered.Options{RecordTimeout: 30 * time.Millisecond})
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serverDone, clientDone := make(chan error, 1), make(chan error, 1)
	go func() { _, err := server.Recv(ctx); serverDone <- err }()
	go func() { _, _, err := client.Reader(ctx); clientDone <- err }()
	defer func() {
		cancel()
		server.Close()
		client.CloseNow()
		for _, done := range []chan error{serverDone, clientDone} {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("control reader did not stop")
			}
		}
	}()
	for i := 0; i < 2; i++ {
		pingCtx, stop := context.WithTimeout(ctx, time.Second)
		err := client.Ping(pingCtx)
		stop()
		if err != nil {
			t.Fatal(err)
		} // pong confirms the entire control was handled
		select {
		case err := <-serverDone:
			serverDone <- err
			t.Fatalf("idle control imposed data timeout: %v", err)
		case <-time.After(60 * time.Millisecond):
		}
	}
}

func TestCompletedControlPreservesFragmentAssemblyDeadline(t *testing.T) {
	_, raw, _, accepted := rawPeer(t, ordered.Options{RecordTimeout: 30 * time.Millisecond})
	server := <-accepted
	if server == nil {
		t.Fatal("accept failed")
	}
	defer server.Close()
	done := make(chan error, 1)
	go func() { _, err := server.Recv(context.Background()); done <- err }()
	wire := append(maskedFrame(false, 2, []byte{1}), maskedFrame(true, 9, []byte("ping"))...)
	if _, err := raw.Write(wire); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unfinished data message accepted")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("completed control disarmed the unfinished data message's budget")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type signaledBody struct {
	io.ReadWriteCloser
	once    sync.Once
	reading chan struct{}
}

func (b *signaledBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.reading) })
	return b.ReadWriteCloser.Read(p)
}

func TestInvalidUpgradeDrainHonorsDialCancellation(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "http-client-timeout"} {
		t.Run(mode, func(t *testing.T) {
			cc, _ := configs(t, securechannel.WS)
			closed := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, buffer, err := http.NewResponseController(w).Hijack()
				if err != nil {
					close(closed)
					return
				}
				defer conn.Close()
				defer close(closed)
				_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: invalid\r\n\r\n")
				if buffer.Flush() != nil {
					return
				}
				var p [1]byte
				_, _ = conn.Read(p[:]) // silent upgraded body until the client aborts
			}))
			defer srv.Close()
			reading := make(chan struct{})
			base := http.DefaultTransport.(*http.Transport).Clone()
			defer base.CloseIdleConnections()
			client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				response, err := base.RoundTrip(r)
				if err == nil && response.StatusCode == http.StatusSwitchingProtocols {
					response.Body = &signaledBody{ReadWriteCloser: response.Body.(io.ReadWriteCloser), reading: reading}
				}
				return response, err
			})}
			ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
			defer cancel()
			if mode == "http-client-timeout" {
				client.Timeout = 150 * time.Millisecond
			}
			done := make(chan error, 1)
			started := time.Now()
			go func() {
				tr, err := Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), cc, Options{HTTPClient: client})
				if tr != nil {
					tr.Close()
				}
				done <- err
			}()
			select {
			case <-reading:
			case <-time.After(time.Second):
				t.Fatal("invalid 101 never entered validation drain")
			}
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-done:
				want := context.DeadlineExceeded
				if mode == "cancel" {
					want = context.Canceled
				}
				if !errors.Is(err, want) {
					t.Fatalf("Dial = %v, want %v", err, want)
				}
				if time.Since(started) >= time.Second {
					t.Fatal("Dial waited for independent 3s body-drain timeout")
				}
			case <-time.After(time.Second):
				t.Fatal("invalid 101 body ignored establishment cancellation")
			}
			select {
			case <-closed:
			case <-time.After(time.Second):
				t.Fatal("upgraded body was not closed")
			}
		})
	}
}

func TestSuccessfulDialDisarmsUpgradeCancellation(t *testing.T) {
	cc, sc := configs(t, securechannel.WS)
	accepted := make(chan *ordered.Transport, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr, _ := Accept(context.Background(), w, r, sc, Options{})
		accepted <- tr
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	client, err := Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), cc, Options{HTTPClient: &http.Client{Timeout: time.Second}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		cancel()
		t.Fatal("accept failed")
	}
	defer server.Close()
	cancel() // includes the context used by the temporary HTTP takeover hook
	done := make(chan error, 1)
	go func() { done <- client.Send(context.Background(), []byte("still-live")) }()
	frame, err := server.Recv(context.Background())
	if err != nil || string(frame) != "still-live" {
		t.Fatalf("successful connection retained handshake cancellation: %q %v", frame, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestDelayedUpgradeCannotOutliveEstablishmentLifetime(t *testing.T) {
	cc, sc := configs(t, securechannel.WS)
	entered, release, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(stopped)
		close(entered)
		<-release
		tr, _ := Accept(context.Background(), w, r, sc, Options{})
		if tr != nil {
			tr.Close()
		}
	}))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tr, err := Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), cc, Options{Limits: ordered.Options{Lifetime: 30 * time.Millisecond}})
		if tr != nil {
			tr.Close()
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("upgrade request did not arrive")
	}
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("delayed upgrade = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("upgrade reset or ignored Lifetime")
	}
}

func TestAcceptRejectsRealTLS12BeforeSC1(t *testing.T) {
	_, sc := configs(t, securechannel.WSS)
	type result struct {
		version   uint16
		err       error
		transport *ordered.Transport
	}
	checked := make(chan result, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr, err := Accept(context.Background(), w, r, sc, Options{})
		checked <- result{r.TLS.Version, err, tr}
		if tr != nil {
			tr.Close()
		}
	}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c, response, err := ws.Dial(ctx, "wss"+strings.TrimPrefix(srv.URL, "https"), &ws.DialOptions{HTTPClient: client, Subprotocols: []string{Subprotocol}})
	if c != nil {
		c.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("TLS 1.2 upgraded: response=%v err=%v", response, err)
	}
	select {
	case got := <-checked:
		if got.version != tls.VersionTLS12 || !errors.Is(got.err, securechannel.ErrConfig) || got.transport != nil {
			t.Fatalf("TLS rejection = %+v", got)
		}
	case <-ctx.Done():
		t.Fatal("TLS 1.2 waited for SC1 M1 instead of rejecting upgrade")
	}
}
