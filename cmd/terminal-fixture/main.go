// Command terminal-fixture is a loopback interoperability fixture with public,
// static test provisioning and a volatile authority. NEVER deploy it as a service.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
)

const method = "/example.Authority/Retire"
const scope = "terminal-fixture"

// privateKeyHex is public, static loopback-fixture provisioning shared with the
// other SDK's fixture. It is not a production server secret.
const privateKeyHex = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"

// fixtureHandle is the public eight-byte enrollment selector shared by fixtures.
var fixtureHandle = [8]byte{7, 7, 7, 7, 7, 7, 7, 7}

// fixtureKey returns the fixed public test AK; never use it outside loopback.
func fixtureKey() securechannel.Key {
	var key securechannel.Key
	for i := range key {
		key[i] = 8
	}
	return key
}

// fixtureAuthority is deliberately volatile and proves no production durability.
// The lock represents one conditional application transaction, including receipt
// conditions. Later independent denial would need its own advancing revision.
type fixtureAuthority struct {
	mu          sync.Mutex
	owner       *syntra.TerminalTransition
	scenario    string
	commits     int
	handlers    int
	denials     int
	committing  bool
	gapObserved chan struct{}
}

// Commit conditionally records exactly one transition; gap waits for a real read.
func (a *fixtureAuthority) Commit(ctx context.Context, transition syntra.TerminalTransition) error {
	a.mu.Lock()
	if ctx.Err() != nil || a.owner != nil || transition.ExpectedRevision != 1 {
		a.mu.Unlock()
		return errors.New("fixture conditional transition refused")
	}
	a.owner = &transition
	a.commits++
	a.committing = true
	emit(map[string]any{"event": "transition", "recorded": true, "durable_storage_proven": false})
	a.mu.Unlock()
	if a.scenario == "gap" {
		select {
		case <-a.gapObserved:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	a.mu.Lock()
	a.committing = false
	a.mu.Unlock()
	emit(map[string]any{"event": "commit_return"})
	return nil
}

// Observe records gap evidence only while the commit callback is still pending.
func (a *fixtureAuthority) Observe(ctx context.Context, transition syntra.TerminalTransition) (syntra.TerminalObservation, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil {
		return syntra.TerminalObservation{}, ctx.Err()
	}
	if a.owner == nil {
		return syntra.TerminalObservation{State: syntra.TerminalActive, Transition: transition, Revision: 1}, nil
	}
	if a.scenario == "deny" {
		emit(map[string]any{"event": "authority_outcome", "state": "HardDenied"})
		return syntra.TerminalObservation{State: syntra.TerminalDenied}, nil
	}
	if a.scenario == "unknown" {
		emit(map[string]any{"event": "authority_outcome", "state": "Unknown"})
		return syntra.TerminalObservation{State: syntra.TerminalUnknown}, nil
	}
	if a.scenario == "gap" && a.committing && a.gapObserved != nil {
		select {
		case <-a.gapObserved:
		default:
			emit(map[string]any{"event": "gap_observed", "before_callback_return": true})
			close(a.gapObserved)
		}
	}
	return syntra.TerminalObservation{State: syntra.TerminalOwnedCommitted, Transition: *a.owner, Revision: 2}, nil
}

// lookup rejects fresh Returning handshakes once the fixture transition is recorded.
func (a *fixtureAuthority) lookup(ctx context.Context, c securechannel.Context) (securechannel.Key, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.owner != nil {
		a.denials++
		emit(map[string]any{"event": "fresh_denied", "before_handler": true})
		return securechannel.Key{}, securechannel.ErrAuth
	}
	if ctx.Err() != nil || a.owner != nil || c.Epoch != 2 || c.Handle != fixtureHandle {
		return securechannel.Key{}, securechannel.ErrAuth
	}
	return fixtureKey(), nil
}

// emit writes one JSON event without private authority or key diagnostics.
func emit(value any) {
	if err := json.NewEncoder(os.Stdout).Encode(value); err != nil {
		slog.Error("fixture output failed")
		os.Exit(1)
	}
}

// main validates finite loopback provisioning before starting either fixture role.
func main() {
	mode := flag.String("mode", "client", "server or client; static fixture provisioning only")
	address := flag.String("addr", "127.0.0.1:7443", "explicit loopback TCP address")
	connections := flag.Int("connections", 1, "server accepted connections (1..16; no automatic replay)")
	timeout := flag.Duration("timeout", 30*time.Second, "whole fixture lifetime")
	payload := flag.String("payload", "", "opaque client input; receipt remains fixed retired")
	drop := flag.Bool("drop-receipt", false, "server: fail after a partial receipt prefix")
	scenario := flag.String("scenario", "owned", "owned, gap, deny, or unknown; client expects the selected outcome")
	probe := flag.Bool("probe", false, "client: fresh Returning only; never invoke a method")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	if *connections < 1 || *connections > 16 || *timeout <= 0 {
		logger.Error("invalid fixture limits")
		os.Exit(2)
	}
	if *scenario != "owned" && *scenario != "gap" && *scenario != "deny" && *scenario != "unknown" {
		logger.Error("invalid fixture scenario")
		os.Exit(2)
	}
	endpoint, err := net.ResolveTCPAddr("tcp", *address)
	if err != nil || endpoint.IP == nil || !endpoint.IP.IsLoopback() {
		logger.Error("fixture requires an explicit loopback address")
		os.Exit(2)
	}
	private, err := hex.DecodeString(privateKeyHex)
	if err != nil || len(private) != 32 {
		logger.Error("invalid public fixture provisioning")
		os.Exit(1)
	}
	var privateKey securechannel.Key
	copy(privateKey[:], private)
	static, err := securechannel.NewStaticKey(privateKey)
	if err != nil {
		logger.Error("fixture key setup failed")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	switch *mode {
	case "server":
		err = serve(ctx, endpoint.String(), *connections, *drop, *scenario, static)
	case "client":
		err = call(ctx, endpoint.String(), *payload, *scenario, *probe, static)
	default:
		err = errors.New("mode must be server or client")
	}
	if err != nil {
		logger.Error("fixture failed", "error", err)
		os.Exit(1)
	}
}

// serve owns both accepted sockets and verifies state after joined shutdown.
func serve(ctx context.Context, address string, count int, drop bool, scenario string, static securechannel.StaticKey) error {
	authority := &fixtureAuthority{scenario: scenario, gapObserved: make(chan struct{})}
	server, err := connection.NewServer(syntra.HostConfig{
		ChannelPolicy: func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			if ctx.Err() != nil || id.Mode != "returning" || id.Scope != scope || id.Epoch != 2 || id.Handle != fixtureHandle || string(credential) != "terminal-fixture" {
				return "", securechannel.ErrAuth
			}
			return "fixture-principal", nil
		},
		Authorize: func(ctx context.Context, _ string, name string) error {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if name != method {
				return syntra.NewRpcError(syntra.ErrorCodePermissionDenied, "fixture method denied")
			}
			return nil
		},
		TerminalMethods: map[string]syntra.TerminalMethodPolicy{method: {SuccessPayload: []byte("retired"), Authority: authority, ObservationTimeout: 20 * time.Millisecond}},
		Handler: func(ctx context.Context, _ *syntra.RpcRequest) (*syntra.RpcResult, error) {
			authority.mu.Lock()
			authority.handlers++
			authority.mu.Unlock()
			err := syntra.CompleteTerminalReceipt(ctx, "fixture-retire", 1)
			emit(map[string]any{"event": "local_write", "complete": err == nil, "peer_receipt_proven": false})
			return nil, err
		},
	}, securechannel.ServerConfig{StaticKey: static, ServerKeyID: 1, Scope: scope, Carrier: securechannel.TCP, LookupKey: authority.lookup}, connection.ServerOptions{MaxConnections: count})
	if err != nil {
		return err
	}
	defer server.Close()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	emit(map[string]any{"event": "listening", "address": listener.Addr().String()})
	var workers sync.WaitGroup
	defer workers.Wait()
	for i := 0; i < count; i++ {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		if drop {
			conn = &dropConn{Conn: conn}
		}
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			err := server.Accept(ctx, tcp.New(conn, nil), ordered.Options{EnableTerminalReceipts: true})
			emit(map[string]any{"event": "connection_closed", "connection": index, "failed": err != nil})
		}(i + 1)
	}
	workers.Wait()
	if err := server.Close(); err != nil {
		return err
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.owner == nil || authority.commits != 1 || authority.handlers != 1 || (count == 2 && authority.denials != 1) {
		return errors.New("fixture state/count assertion failed")
	}
	emit(map[string]any{"event": "summary", "commits": authority.commits, "handlers": authority.handlers, "denials": authority.denials, "closed": count})
	return nil
}

// call distinguishes establishment failure from a typed post-ready outcome.
func call(ctx context.Context, address, payload, scenario string, probe bool, static securechannel.StaticKey) error {
	client, err := tcp.Dial(ctx, address, securechannel.ClientConfig{ServerPublicKey: static.Public(), AuthorizationKey: fixtureKey(),
		Context: securechannel.Context{Mode: securechannel.Returning, Carrier: securechannel.TCP, ServerKeyID: 1, Epoch: 2, Handle: fixtureHandle, Scope: scope}}, syntra.ClientConfig{Credential: []byte("terminal-fixture")}, ordered.Options{})
	if err != nil {
		if probe && (errors.Is(err, ordered.ErrIO) || errors.Is(err, securechannel.ErrAuth) || errors.Is(err, ordered.ErrClosed)) {
			emit(map[string]any{"event": "probe", "establishment_denied": true, "calls": 0})
			return nil
		}
		return fmt.Errorf("fixture establishment: %w", err)
	}
	defer client.Close()
	if probe {
		return errors.New("fresh Returning unexpectedly established")
	}
	emit(map[string]any{"event": "established"})
	result, err := client.Call(ctx, method, []byte(payload), 2000)
	if err != nil {
		var rpc *syntra.RpcError
		if !errors.As(err, &rpc) {
			return errors.New("fixture expected typed RPC error")
		}
		code := "unexpected"
		if rpc.Code == syntra.ErrorCodeUnavailable {
			code = "Unavailable"
		}
		if rpc.Code == syntra.ErrorCodeUnauthenticated {
			code = "Unauthenticated"
		}
		if scenario == "deny" && (code == "Unauthenticated" || code == "Unavailable") || scenario == "unknown" && code == "Unavailable" {
			emit(map[string]any{"event": "result", "outcome": "unknown", "code": code, "receipts": 0, "replayed": false})
			if closeErr := client.Close(); closeErr != nil {
				return closeErr
			}
			return nil
		}
		return err
	}
	if scenario == "deny" || scenario == "unknown" || string(result) != "retired" {
		return errors.New("unexpected fixture result")
	}
	emit(map[string]any{"event": "result", "outcome": "observed", "payload": string(result), "receipts": 1, "durable_storage_proven": false})
	if err := client.Close(); err != nil {
		return err
	}
	return nil
}

// dropConn creates deliberate carrier loss after nonce consumption. There is no
// retry and no attempt to append another frame after the partial prefix.
type dropConn struct {
	net.Conn
	writes int
}

// Write fails the receipt prefix after M2 and Ready have each written two units.
func (c *dropConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes != 5 {
		return c.Conn.Write(p)
	}
	n, _ := c.Conn.Write(p[:1])
	return n, errors.New("fixture forced partial receipt loss")
}
