// File terminal_matrix_test.go exercises opt-in retirement through real sockets.
package tcp_test

import (
	"bytes"
	"context"
	"errors"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
)

// retireMethod identifies the neutral terminal operation shared by TCP fixtures.
const retireMethod = "/example.Authority/Retire"

// terminalTCPFixture owns all sockets and workers started by one test.
type terminalTCPFixture struct {
	host      *syntra.Host
	authority *terminalAuthority
	client    *connection.Client
	security  securechannel.ClientConfig
	address   string
	done      chan error
	ctx       context.Context
	budget    *syntra.ExecutionBudget
}

// terminalTCPOptions injects bounded authority and transport faults per fixture.
type terminalTCPOptions struct {
	connections                  int
	ownedServer                  bool
	serverOptions                ordered.Options
	disabledHost, disabledDriver bool
	payload                      []byte
	revision                     uint64
	commit                       func(context.Context)
	observe                      func(syntra.TerminalObservation) (syntra.TerminalObservation, error)
	wrap                         func(net.Conn) net.Conn
	wrapRecords                  func(ordered.MessageIO) ordered.MessageIO
	wrapTransport                func(*ordered.Transport) syntra.Transport
	observeContext               func(context.Context, syntra.TerminalObservation) (syntra.TerminalObservation, error)
	observationTimeout           time.Duration
	handler                      func(context.Context, *syntra.RpcRequest) (*syntra.RpcResult, error)
}

// terminalTCP starts a real encrypted loopback responder and registers joined cleanup.
func terminalTCP(t *testing.T, options terminalTCPOptions) *terminalTCPFixture {
	t.Helper()
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		t.Fatal(err)
	}
	ak, err := securechannel.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var revoked atomic.Bool
	authority := &terminalAuthority{revoked: &revoked, afterCommit: options.commit, observation: options.observe, contextObservation: options.observeContext}
	security := securechannel.ServerConfig{StaticKey: key, ServerKeyID: 7, Scope: "terminal-fixture", Carrier: securechannel.TCP,
		LookupKey: func(_ context.Context, c securechannel.Context) (securechannel.Key, error) {
			if revoked.Load() || c.Epoch != 1 || c.Handle != [8]byte{1} {
				return securechannel.Key{}, errors.New("withdrawn")
			}
			return ak, nil
		}}
	policy := syntra.TerminalMethodPolicy{SuccessPayload: []byte("retired"), Authority: authority, ObservationTimeout: 10 * time.Millisecond}
	if options.observationTimeout != 0 {
		policy.ObservationTimeout = options.observationTimeout
	}
	if options.payload != nil {
		policy.SuccessPayload = options.payload
	}
	revision := options.revision
	if revision == 0 {
		revision = 1
	}
	budget, err := syntra.NewExecutionBudget(16)
	if err != nil {
		t.Fatal(err)
	}
	cfg := syntra.HostConfig{ExecutionBudget: budget,
		ChannelPolicy:   func(context.Context, syntra.ChannelIdentity, []byte) (string, error) { return "fixture", nil },
		Authorize:       syntra.AllowAllAuthorize,
		TerminalMethods: map[string]syntra.TerminalMethodPolicy{retireMethod: policy},
		Handler: func(ctx context.Context, req *syntra.RpcRequest) (*syntra.RpcResult, error) {
			if req.GetMethod() != retireMethod {
				return syntra.NewSuccessResult(req.GetPayload()), nil
			}
			return nil, syntra.CompleteTerminalReceipt(ctx, "fixture-operation", revision)
		}}
	if options.handler != nil {
		cfg.Handler = options.handler
	}
	if options.disabledHost {
		cfg.TerminalMethods = nil
	}
	host, err := syntra.OpenHost(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var server *connection.Server
	if options.ownedServer {
		_ = host.Close()
		server, err = connection.NewServer(cfg, security, connection.ServerOptions{})
		if err != nil {
			t.Fatal(err)
		}
		host = server.Host
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	f := &terminalTCPFixture{host: host, authority: authority, address: listener.Addr().String(), done: make(chan error, 1), ctx: ctx, budget: budget,
		security: securechannel.ClientConfig{ServerPublicKey: key.Public(), AuthorizationKey: ak, Context: securechannel.Context{Mode: securechannel.Returning, Carrier: securechannel.TCP, ServerKeyID: 7, Scope: security.Scope, Epoch: 1, Handle: [8]byte{1}}}}
	go func() {
		var workers sync.WaitGroup
		defer func() { workers.Wait(); f.done <- nil }()
		for i := 0; i < max(1, options.connections); i++ {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if options.wrap != nil {
				conn = options.wrap(conn)
			}
			opts := options.serverOptions
			opts.EnableTerminalReceipts = !options.disabledDriver
			workers.Add(1)
			go func() {
				defer workers.Done()
				if options.wrapTransport != nil {
					tr, err := ordered.Server(ctx, tcp.New(conn, opts.Budget), security, opts)
					if err == nil {
						defer tr.Close()
						_ = host.Serve(ctx, options.wrapTransport(tr))
					}
					return
				}
				if options.wrapRecords != nil {
					_ = connection.Accept(ctx, options.wrapRecords(tcp.New(conn, opts.Budget)), security, host, opts)
					return
				}
				if server != nil {
					_ = server.Accept(ctx, tcp.New(conn, opts.Budget), opts)
					return
				}
				_ = tcp.Accept(ctx, conn, security, host, opts)
			}()
		}
	}()
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		if f.client != nil {
			_ = f.client.Close()
		}
		_ = host.Close()
		if server != nil {
			_ = server.Close()
		}
		joinCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := host.Wait(joinCtx); err != nil {
			t.Error("retained host work did not join", err)
		}
		select {
		case <-f.done:
		case <-joinCtx.Done():
			t.Error("accept did not join")
		}
	})
	return f
}

// TestTerminalTCPOwnedServerForwardsCapability covers connection.Server's owned wrapper.
func TestTerminalTCPOwnedServerForwardsCapability(t *testing.T) {
	f := terminalTCP(t, terminalTCPOptions{ownedServer: true})
	c := f.connect(t)
	got, err := c.Call(f.ctx, retireMethod, nil, 1000)
	if err != nil || string(got) != "retired" {
		t.Fatalf("owned wrapper = %q, %v", got, err)
	}
}

// TestTerminalTCPReservationDoesNotTransfer rejects both an existing sibling and
// fresh Returning handshake while permitting only the original terminal result.
func TestTerminalTCPReservationDoesNotTransfer(t *testing.T) {
	committed, release := make(chan struct{}), make(chan struct{})
	f := terminalTCP(t, terminalTCPOptions{connections: 3, commit: func(context.Context) { close(committed); <-release }})
	c := f.connect(t)
	sibling, err := tcp.Dial(f.ctx, f.address, f.security, syntra.ClientConfig{}, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer sibling.Close()
	done := make(chan error, 1)
	go func() {
		got, err := c.Call(f.ctx, retireMethod, nil, 3000)
		if err == nil && string(got) != "retired" {
			err = errors.New("wrong receipt")
		}
		done <- err
	}()
	<-committed
	if _, err := sibling.Call(f.ctx, "/example.Echo/Echo", nil, 500); err == nil {
		close(release)
		t.Fatal("sibling inherited permit")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	fresh, err := tcp.Dial(f.ctx, f.address, f.security, syntra.ClientConfig{}, ordered.Options{})
	if fresh != nil {
		_ = fresh.Close()
	}
	if err == nil {
		t.Fatal("fresh Returning inherited permit")
	}
}

// connect establishes the fixture's initiating client and retains it for cleanup.
func (f *terminalTCPFixture) connect(t *testing.T) *connection.Client {
	t.Helper()
	c, err := tcp.Dial(f.ctx, f.address, f.security, syntra.ClientConfig{}, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	f.client = c
	return c
}

// TestTerminalTCPPreflightAndEvidence checks constructor rejection before socket
// setup and preserves the runtime preflight and authority-evidence matrix.
func TestTerminalTCPPreflightAndEvidence(t *testing.T) {
	for _, name := range []string{"host-disabled", "driver-disabled", "oversize-frame", "wrong-revision", "unknown", "external-denial", "store-error", "wrong-owner", "wrong-scope", "uncommitted", "read-timeout"} {
		t.Run(name, func(t *testing.T) {
			o := terminalTCPOptions{}
			switch name {
			case "host-disabled":
				o.disabledHost = true
			case "driver-disabled":
				o.disabledDriver = true
			case "oversize-frame":
				terminalRejectOversizePolicy(t, bytes.Repeat([]byte{'x'}, 1020))
				return // invalid configuration must not reach terminalTCP or open sockets
			case "wrong-revision":
				o.revision = 9
			default:
				o.observe = func(observation syntra.TerminalObservation) (syntra.TerminalObservation, error) {
					if observation.State == syntra.TerminalActive {
						return observation, nil
					}
					switch name {
					case "unknown":
						observation.State = syntra.TerminalUnknown
					case "external-denial":
						observation.State = syntra.TerminalDenied
					case "store-error":
						return syntra.TerminalObservation{}, errors.New("private store diagnostic")
					case "wrong-owner":
						observation.Transition.ReservationID[0]++
					case "wrong-scope":
						observation.Transition.Channel.Scope = "other"
					case "uncommitted":
						observation.State = syntra.TerminalActive
						observation.Revision = 1
					case "read-timeout":
						time.Sleep(25 * time.Millisecond)
					}
					return observation, nil
				}
			}
			f := terminalTCP(t, o)
			c := f.connect(t)
			got, err := c.Call(f.ctx, retireMethod, nil, 1000)
			if err == nil || len(got) != 0 {
				t.Fatalf("ineligible result = %q, %v", got, err)
			}
			if (name == "host-disabled" || name == "driver-disabled" || name == "wrong-revision") && f.authority.commits.Load() != 0 {
				t.Fatal("preflight mutated authority")
			}
		})
	}
}

// terminalRejectOversizePolicy checks refusal without constructing a channel,
// listener, or client, and without invoking the authority's commit operation.
func terminalRejectOversizePolicy(t *testing.T, payload []byte) {
	t.Helper()
	authority := &terminalAuthority{revoked: new(atomic.Bool)}
	host, err := syntra.OpenHost(syntra.HostConfig{
		TerminalMethods: map[string]syntra.TerminalMethodPolicy{retireMethod: {
			SuccessPayload: payload, Authority: authority, ObservationTimeout: 10 * time.Millisecond,
		}},
	})
	if host != nil {
		defer host.Close()
	}
	if err == nil || host != nil {
		t.Errorf("oversized policy not rejected by constructor: host present=%t, error=%v", host != nil, err)
	}
	if authority.commits.Load() != 0 {
		t.Fatal("constructor rejection mutated authority")
	}
}

// terminalWorstCasePayloadSize measures the complete frame at the same maximum
// version and request-ID varint widths used by constructor validation.
func terminalWorstCasePayloadSize(t *testing.T, size int) []byte {
	t.Helper()
	for n := 0; n <= 1024; n++ {
		payload := bytes.Repeat([]byte{'x'}, n)
		frame, err := syntra.MarshalFrame(syntra.NewResultFrame(math.MaxUint32, math.MaxUint64, syntra.NewSuccessResult(payload)))
		if err != nil {
			t.Fatal(err)
		}
		if len(frame) == size {
			return payload
		}
	}
	t.Fatalf("cannot construct exact %d-byte frame", size)
	return nil
}

// TestTerminalTCPCompleteFrameCeilingAndSnapshot accepts an exact worst-case
// budget over TCP with copied payload storage and rejects one byte more at boot.
func TestTerminalTCPCompleteFrameCeilingAndSnapshot(t *testing.T) {
	for _, size := range []int{1024, 1025} {
		t.Run(map[int]string{1024: "worst-case-1024-accepted-over-TCP", 1025: "worst-case-1025-rejected-by-constructor"}[size], func(t *testing.T) {
			payload := terminalWorstCasePayloadSize(t, size)
			if size == 1025 {
				terminalRejectOversizePolicy(t, payload)
				return
			}
			want := append([]byte(nil), payload...)
			f := terminalTCP(t, terminalTCPOptions{payload: payload})
			clear(payload) // caller's storage is no longer the configured template
			c := f.connect(t)
			got, err := c.Call(f.ctx, retireMethod, nil, 1000)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("bounded copied template: %d, %v", len(got), err)
			}
			// This fixture negotiates v1 and makes its first call with ID 1;
			// its actual result is smaller than the configured worst-case frame.
			frame, err := syntra.MarshalFrame(syntra.NewResultFrame(1, 1, syntra.NewSuccessResult(got)))
			if err != nil || len(frame) >= 1024 {
				t.Fatalf("actual TCP result frame = %d bytes, %v; want below 1024", len(frame), err)
			}
		})
	}
}

// TestTerminalTCPInsufficientBudgetDoesNotMutate reserves the teardown tail before commit.
func TestTerminalTCPInsufficientBudgetDoesNotMutate(t *testing.T) {
	f := terminalTCP(t, terminalTCPOptions{})
	c := f.connect(t)
	if _, err := c.Call(f.ctx, retireMethod, nil, 20); err == nil {
		t.Fatal("insufficient teardown budget accepted")
	}
	if f.authority.commits.Load() != 0 {
		t.Fatal("short budget started mutation")
	}
}

// TestTerminalTCPRetiredHandlerContextCannotReserve rejects a saved callback scope
// without fencing a later unrelated live request on the same connection.
func TestTerminalTCPRetiredHandlerContextCannotReserve(t *testing.T) {
	saved := make(chan context.Context, 1)
	f := terminalTCP(t, terminalTCPOptions{handler: func(ctx context.Context, _ *syntra.RpcRequest) (*syntra.RpcResult, error) {
		saved <- ctx
		return syntra.NewSuccessResult([]byte("ordinary")), nil
	}})
	c := f.connect(t)
	if _, err := c.Call(f.ctx, retireMethod, nil, 1000); err != nil {
		t.Fatal(err)
	}
	if err := syntra.CompleteTerminalReceipt(context.WithoutCancel(<-saved), "late-operation", 1); err == nil {
		t.Fatal("retired callback regained scope")
	}
	if f.authority.commits.Load() != 0 {
		t.Fatal("late context mutated authority")
	}
	if _, err := c.Call(f.ctx, retireMethod, nil, 1000); err != nil {
		t.Fatal("rejected late reservation fenced an unrelated active call", err)
	}
}

// TestTerminalTCPDisconnectPrincipalStillAborts preserves immediate withdrawal,
// without pretending that abort rolls back an already committed transition.
func TestTerminalTCPDisconnectPrincipalStillAborts(t *testing.T) {
	committed, release := make(chan struct{}), make(chan struct{})
	f := terminalTCP(t, terminalTCPOptions{commit: func(context.Context) { close(committed); <-release }})
	c := f.connect(t)
	done := make(chan error, 1)
	go func() { _, err := c.Call(f.ctx, retireMethod, nil, 1000); done <- err }()
	<-committed
	if err := f.host.DisconnectPrincipal("fixture"); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err == nil {
		t.Fatal("ordinary disconnect became a receipt drain")
	}
	if f.authority.commits.Load() != 1 {
		t.Fatal("disconnect implied transaction rollback")
	}
}

// TestTerminalTCPOwnCommitVisibleBeforeCallbackReturn lets the supervisor observe
// owned state while Commit is held at a synchronization barrier.
func TestTerminalTCPOwnCommitVisibleBeforeCallbackReturn(t *testing.T) {
	visible, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	f := terminalTCP(t, terminalTCPOptions{
		commit: func(context.Context) { <-release },
		observe: func(o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
			if o.State == syntra.TerminalOwnedCommitted {
				once.Do(func() { close(visible) })
			}
			return o, nil
		},
	})
	c := f.connect(t)
	done := make(chan error, 1)
	go func() {
		got, err := c.Call(f.ctx, retireMethod, nil, 2000)
		if err == nil && string(got) != "retired" {
			err = errors.New("wrong receipt")
		}
		done <- err
	}()
	select {
	case <-visible:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("supervisor did not recognize committed ownership")
	}
	if f.authority.commits.Load() != 1 {
		t.Fatal("missing conditional commit")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// TestTerminalTCPDeadlineRetainsActualCallbackCharge retires the carrier at cutoff
// while retaining the execution slot of a callback that has not actually returned.
func TestTerminalTCPDeadlineRetainsActualCallbackCharge(t *testing.T) {
	committed, release := make(chan struct{}), make(chan struct{})
	f := terminalTCP(t, terminalTCPOptions{commit: func(context.Context) { close(committed); <-release }})
	c := f.connect(t)
	done := make(chan error, 1)
	go func() { _, err := c.Call(f.ctx, retireMethod, nil, 120); done <- err }()
	<-committed
	if err := <-done; err == nil {
		close(release)
		t.Fatal("stalled commit callback produced success")
	}
	if f.budget.Live() != 1 {
		close(release)
		t.Fatal("surviving callback lost execution charge")
	}
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		close(release)
		t.Fatal("deadline did not retire carrier")
	}
	close(release)
}

// TestTerminalTCPCancelBeforeSelection rejects success and closes the carrier when
// cancellation wins before terminal result selection.
func TestTerminalTCPCancelBeforeSelection(t *testing.T) {
	committed := make(chan struct{})
	f := terminalTCP(t, terminalTCPOptions{commit: func(ctx context.Context) { close(committed); <-ctx.Done() }})
	c := f.connect(t)
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan error, 1)
	go func() { _, err := c.Call(ctx, retireMethod, nil, 1000); done <- err }()
	<-committed
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancellation became success")
	}
	select {
	case <-c.Done():
	case <-time.After(time.Second):
		t.Fatal("cancellation did not retire carrier")
	}
	if f.authority.commits.Load() != 1 {
		t.Fatal("cancel falsely implied rollback")
	}
}

// terminalFaultConn injects a partial stream write at the third record's prefix
// (M2 and Ready precede it). Close interrupts the held write just like a socket.
type terminalFaultConn struct {
	net.Conn
	writes  int
	entered chan struct{}
	release chan struct{}
	closed  chan struct{}
	once    sync.Once
	drop    bool
}

// Close releases a held partial write and closes the real socket idempotently.
func (c *terminalFaultConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// Write stalls or drops the third record after a single prefix byte was emitted.
func (c *terminalFaultConn) Write(p []byte) (int, error) {
	c.writes++
	if c.writes != 5 {
		return c.Conn.Write(p)
	}
	n, err := c.Conn.Write(p[:1])
	close(c.entered)
	if err != nil {
		return n, err
	}
	if c.drop {
		return n, errors.New("injected partial write")
	}
	select {
	case <-c.release:
		return n, nil
	case <-c.closed:
		return n, net.ErrClosed
	}
}

// TestTerminalTCPPartialReceiptLossIsUnknown rejects complete receipt success
// after a partial prefix, without replaying or rolling back the authority commit.
func TestTerminalTCPPartialReceiptLossIsUnknown(t *testing.T) {
	entered := make(chan struct{})
	f := terminalTCP(t, terminalTCPOptions{wrap: func(conn net.Conn) net.Conn {
		return &terminalFaultConn{Conn: conn, entered: entered, closed: make(chan struct{}), drop: true}
	}})
	c := f.connect(t)
	got, err := c.Call(f.ctx, retireMethod, nil, 1000)
	if err == nil || len(got) != 0 {
		t.Fatalf("partial receipt = %q, %v", got, err)
	}
	<-entered
	if f.authority.commits.Load() != 1 {
		t.Fatal("loss changed commit or replayed it")
	}
}

// TestTerminalTCPSelectedSuccessIgnoresLateCancel retains the first selected
// result when cancellation arrives after ciphertext handoff.
func TestTerminalTCPSelectedSuccessIgnoresLateCancel(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	f := terminalTCP(t, terminalTCPOptions{wrap: func(conn net.Conn) net.Conn {
		return &terminalFaultConn{Conn: conn, entered: entered, release: release, closed: make(chan struct{})}
	}})
	conn, err := net.Dial("tcp", f.address)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := ordered.Client(f.ctx, tcp.New(conn, nil), f.security, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	hello, err := syntra.MarshalFrame(syntra.NewHelloFrame(&syntra.ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Send(f.ctx, hello); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Recv(f.ctx); err != nil {
		t.Fatal(err)
	}
	request, _ := syntra.MarshalFrame(syntra.NewRequestFrame(1, 1, &syntra.RpcRequest{Method: retireMethod, TimeoutMs: 1000}))
	if err := tr.Send(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	<-entered // selected success has reached its one-use carrier handoff
	cancel, _ := syntra.MarshalFrame(syntra.NewCancelFrame(1, 1))
	if err := tr.Send(f.ctx, cancel); err != nil {
		close(release)
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	close(release)
	raw, err := tr.Recv(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := syntra.UnmarshalFrame(raw)
	if err != nil || frame.GetRequestId() != 1 || string(frame.GetResult().GetPayload()) != "retired" {
		t.Fatalf("late cancel replaced selected success: %v, %v", frame, err)
	}
}

// TestTerminalTCPProtocolFailureWhileFencedWins preserves fatal request-ID replay
// checks while ordinary admission is fenced and Commit has not returned.
func TestTerminalTCPProtocolFailureWhileFencedWins(t *testing.T) {
	committed, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	f := terminalTCP(t, terminalTCPOptions{commit: func(context.Context) { close(committed); <-release }})
	conn, err := net.Dial("tcp", f.address)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := ordered.Client(f.ctx, tcp.New(conn, nil), f.security, ordered.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()
	hello, _ := syntra.MarshalFrame(syntra.NewHelloFrame(&syntra.ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if err := tr.Send(f.ctx, hello); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Recv(f.ctx); err != nil {
		t.Fatal(err)
	}
	request, _ := syntra.MarshalFrame(syntra.NewRequestFrame(1, 1, &syntra.RpcRequest{Method: retireMethod, TimeoutMs: 2000}))
	if err := tr.Send(f.ctx, request); err != nil {
		t.Fatal(err)
	}
	<-committed
	if err := tr.Send(f.ctx, request); err != nil {
		t.Fatal(err)
	} // fatal reused request ID, not new admission
	done := make(chan error, 1)
	go func() { _, err := tr.Recv(f.ctx); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("protocol violation became receipt")
		}
	case <-time.After(150 * time.Millisecond):
		t.Fatal("fence hid fatal protocol violation")
	}
}

// TestTerminalTCPBlockedReceiptRepollsAndRetires observes injected denial/unknown
// and real socket retirement before the longer RPC/receipt deadline can mask it.
func TestTerminalTCPBlockedReceiptRepollsAndRetires(t *testing.T) {
	for _, fault := range []string{"deadline", "denial", "unknown"} {
		t.Run(fault, func(t *testing.T) {
			entered := make(chan struct{})
			observed := make(chan struct{})
			closed := make(chan struct{})
			var observedOnce sync.Once
			var fail atomic.Bool
			f := terminalTCP(t, terminalTCPOptions{
				wrap: func(conn net.Conn) net.Conn {
					return &terminalFaultConn{Conn: conn, entered: entered, closed: closed}
				},
				observe: func(o syntra.TerminalObservation) (syntra.TerminalObservation, error) {
					if fail.Load() {
						o.State = syntra.TerminalDenied
						if fault == "unknown" {
							o.State = syntra.TerminalUnknown
						}
						observedOnce.Do(func() { close(observed) })
					}
					return o, nil
				},
			})
			c := f.connect(t)
			done := make(chan error, 1)
			timeout := uint32(3000)
			if fault == "deadline" {
				timeout = 200
			}
			go func() { _, err := c.Call(f.ctx, retireMethod, nil, timeout); done <- err }()
			<-entered
			if fault != "deadline" {
				fail.Store(true)
				select {
				case <-observed:
				case <-time.After(150 * time.Millisecond):
					t.Fatal("injected authority state was never observed")
				}
				select {
				case <-closed:
				case <-time.After(150 * time.Millisecond):
					t.Fatal("authority failure did not retire socket before RPC/watchdog deadline")
				}
				select {
				case <-c.Done():
				case <-time.After(150 * time.Millisecond):
					t.Fatal("peer did not observe socket retirement before RPC/watchdog deadline")
				}
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("blocked/denied write became success")
				}
			case <-time.After(time.Second):
				t.Fatal("blocked receipt not interrupted")
			}
			if f.authority.commits.Load() != 1 {
				t.Fatal("transport loss replayed or rolled back commit")
			}
		})
	}
}

// TestTerminalTCPPartialOrdinaryBarrier waits for a full active ordinary frame
// before mutation and discards all queued ordinary output across the fence.
func TestTerminalTCPPartialOrdinaryBarrier(t *testing.T) {
	for _, drop := range []bool{false, true} {
		t.Run(map[bool]string{false: "finish-before-commit", true: "failure-no-commit"}[drop], func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var attempts atomic.Int32
			f := terminalTCP(t, terminalTCPOptions{wrap: func(conn net.Conn) net.Conn {
				return &terminalFaultConn{Conn: conn, entered: entered, release: release, closed: make(chan struct{}), drop: drop}
			}, commit: func(context.Context) { attempts.Add(1) }})
			c := f.connect(t)
			if err := f.host.NotifyAll(bytes.Repeat([]byte{'a'}, 70000)); err != nil {
				t.Fatal(err)
			}
			<-entered
			if !drop {
				if err := f.host.NotifyAll([]byte("must-not-leak")); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() {
				got, err := c.Call(f.ctx, retireMethod, nil, 1000)
				if err == nil && string(got) != "retired" {
					err = errors.New("wrong receipt")
				}
				done <- err
			}()
			if !drop {
				time.Sleep(30 * time.Millisecond)
				if attempts.Load() != 0 {
					close(release)
					t.Fatal("mutation started inside partial ordinary frame")
				}
				close(release)
			}
			err := <-done
			if drop && (err == nil || f.authority.commits.Load() != 0) {
				t.Fatal("partial ordinary failure allowed mutation/receipt")
			}
			if !drop && err != nil {
				t.Fatal(err)
			}
			if !drop {
				for n := range c.Notifications() {
					if string(n.GetPayload()) == "must-not-leak" {
						t.Fatal("queued notification leaked")
					}
				}
			}
		})
	}
}

// TestTerminalTCPQuiescenceUsesElapsedBudget rejects a clock jump during a
// blocked ordinary frame without starting the authority mutation.
func TestTerminalTCPQuiescenceUsesElapsedBudget(t *testing.T) {
	entered, handlerEntered := make(chan struct{}), make(chan struct{})
	var jump atomic.Int64
	origin := time.Now()
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Since(origin) + time.Duration(jump.Load()), true }))
	budget, err := ordered.NewEstablishmentBudget(clock, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	f := terminalTCP(t, terminalTCPOptions{serverOptions: ordered.Options{Budget: budget},
		wrap: func(conn net.Conn) net.Conn {
			return &terminalFaultConn{Conn: conn, entered: entered, closed: make(chan struct{})}
		},
		handler: func(ctx context.Context, _ *syntra.RpcRequest) (*syntra.RpcResult, error) {
			close(handlerEntered)
			return nil, syntra.CompleteTerminalReceipt(ctx, "fixture-operation", 1)
		},
	})
	c := f.connect(t)
	if err := f.host.NotifyAll([]byte("active frame")); err != nil {
		t.Fatal(err)
	}
	<-entered
	done := make(chan error, 1)
	go func() { _, err := c.Call(f.ctx, retireMethod, nil, 1000); done <- err }()
	<-handlerEntered
	time.Sleep(20 * time.Millisecond)
	jump.Store(int64(2 * time.Second))
	select {
	case <-c.Done():
	case <-time.After(150 * time.Millisecond):
		t.Fatal("quiescence renewed budget across elapsed-clock jump")
	}
	if err := <-done; err == nil {
		t.Fatal("clock jump became success")
	}
	if f.authority.commits.Load() != 0 {
		t.Fatal("clock-expired barrier started mutation")
	}
}
