// peer serves only neutral integration RPCs over the production SC1 adapters.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/tests/integration/internal/fixture"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	ws "github.com/tinkle-org/syntra-go/transport/websocket"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	path := flag.String("config", "/provision.json", "test provisioning path")
	cert := flag.String("cert", "/server.pem", "TLS certificate path")
	key := flag.String("key", "/server-key.pem", "TLS key path")
	address := flag.String("listen", ":8080", "listen address")
	flag.Parse()
	if err := run(*path, *cert, *key, *address); err != nil {
		// No configuration, credentials, request bytes or TLS keys in logs.
		slog.Error("fixture_failed")
		os.Exit(1)
	}
}

func run(path, certPath, keyPath, address string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	var cfg fixture.Config
	err = json.NewDecoder(io.LimitReader(f, 16<<10)).Decode(&cfg)
	_ = f.Close()
	if err != nil {
		return err
	}
	sc, err := cfg.Server()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	host, err := syntra.OpenHost(syntra.HostConfig{
		ChannelPolicy: func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			principal, err := cfg.ChannelPolicy(ctx, id, credential)
			if err != nil {
				slog.Info("channel_policy_rejected", "credential_present", len(credential) != 0)
			}
			return principal, err
		},
		Authorize:      fixture.Authorize,
		DefaultTimeout: 20 * time.Second, WriteTimeout: 2 * time.Second,
		Handler: func(ctx context.Context, req *syntra.RpcRequest) (*syntra.RpcResult, error) {
			if req.GetMethod() == fixture.WaitMethod {
				var token uint64
				if len(req.GetPayload()) == 8 {
					token = binary.BigEndian.Uint64(req.GetPayload())
				}
				slog.Info("wait_started", "token", token)
				<-ctx.Done()
				slog.Info("wait_finished", "token", token)
				return nil, ctx.Err()
			}
			return syntra.NewSuccessResult(bytes.Clone(req.GetPayload())), nil
		},
	})
	if err != nil {
		return err
	}
	defer host.Close()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	limits := ordered.Options{HandshakeTimeout: 3 * time.Second, WriteTimeout: 2 * time.Second}
	var workers sync.WaitGroup
	var admission sync.Mutex
	stopping := false
	begin := func() bool {
		admission.Lock()
		defer admission.Unlock()
		if stopping {
			return false
		}
		workers.Add(1)
		return true
	}
	// Include pre-handshake sockets in shutdown, too.
	var sockets sync.Map
	serve := func(conn net.Conn) {
		defer workers.Done()
		defer sockets.Delete(conn)
		defer conn.Close()
		tr, err := tcp.Server(ctx, conn, sc, limits)
		if err == nil {
			defer tr.Close()
			_ = host.Serve(ctx, tr)
		}
	}
	var server *http.Server
	if cfg.Protocol != "tcp" {
		server = &http.Server{
			ReadHeaderTimeout: 3 * time.Second,
			// TLS handshake diagnostics must not dump caller-controlled input.
			ErrorLog: log.New(io.Discard, "", 0),
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !begin() {
					http.Error(w, "stopping", http.StatusServiceUnavailable)
					return
				}
				defer workers.Done()
				if r.URL.Path != "/sc1" {
					http.NotFound(w, r)
					return
				}
				tr, err := ws.Accept(ctx, w, r, sc, ws.Options{Limits: limits})
				if err == nil {
					defer tr.Close()
					_ = host.Serve(ctx, tr)
				}
			}),
		}
		if cfg.Protocol == "wss" {
			cert, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				return err
			}
			listener = tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13})
		}
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		admission.Lock()
		stopping = true
		admission.Unlock()
		_ = listener.Close()
		if server != nil {
			_ = server.Close()
		}
		sockets.Range(func(k, _ any) bool { _ = k.(net.Conn).Close(); return true })
		_ = host.Close()
	}()
	// Readiness is emitted only after validation, TLS loading and binding.
	slog.Info("listener_bound", "protocol", cfg.Protocol, "mode", cfg.Mode)
	if server != nil {
		err = server.Serve(listener)
	} else {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				err = acceptErr
				break
			}
			if !begin() {
				_ = conn.Close()
				continue
			}
			sockets.Store(conn, struct{}{})
			go serve(conn)
		}
	}
	wasCanceled := ctx.Err() != nil
	cancel()
	<-stopped
	workers.Wait()
	slog.Info("fixture_stopped")
	if wasCanceled {
		return nil
	}
	return err
}
