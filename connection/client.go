package connection

import (
	"context"
	"errors"
	"sync"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tcp"
	ws "github.com/tinkle-org/syntra-go/transport/websocket"
)

const (
	// DialTimeout bounds total socket, SC1, and core hello establishment.
	// Each adapter handshake and the core hello also retain their own limits.
	DialTimeout = 10 * time.Second
	// ShutdownTimeout is the default bounded join budget for clients and servers.
	ShutdownTimeout = 5 * time.Second
)

var (
	ErrConfig          = errors.New("connection: invalid configuration")
	ErrClosed          = errors.New("connection: server closed")
	ErrShutdownTimeout = errors.New("connection: shutdown did not complete within budget")
)

// Client owns a running core session and its transport. Construct it using a
// Dial function or Connect; the zero value is invalid. The embedded client
// exposes Call and Notifications. Do not replace it or call its Run method.
// Use this wrapper's Close to stop and join the owned run lifetime.
type Client struct {
	*syntra.Client
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.Mutex
	closing bool
	err     error
}

// DialTCP establishes TCP, SC1, and core readiness within one ten-second budget,
// shortened by ctx. Successful connections are independent of ctx: the caller
// must Close them. There is no retry or protocol fallback.
func DialTCP(ctx context.Context, address string, channelcfg securechannel.ClientConfig, corecfg syntra.ClientConfig, opts ordered.Options) (*Client, error) {
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	t, err := tcp.Dial(ctx, address, channelcfg, opts)
	if err != nil {
		return nil, publicError(err)
	}
	return connect(ctx, t, corecfg)
}

// DialWebSocket establishes WS/WSS, SC1, and core readiness within one
// ten-second budget, shortened by ctx. ctx governs establishment only; callers
// must Close the returned client. The URL and channel carrier must agree.
func DialWebSocket(ctx context.Context, address string, channelcfg securechannel.ClientConfig, corecfg syntra.ClientConfig, opts ws.Options) (*Client, error) {
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	t, err := ws.Dial(ctx, address, channelcfg, opts)
	if err != nil {
		return nil, publicError(err)
	}
	return connect(ctx, t, corecfg)
}

// Connect takes ownership of an already established transport, including on
// failure, and waits for core readiness. The total establishment budget is ten
// seconds, shortened by ctx; the core hello retains its five-second limit.
// Send/Recv must honor contexts, and Close must promptly interrupt I/O, as
// required by syntra.Transport. The returned run lifetime is independent of
// ctx, so callers must Close it explicitly.
func Connect(ctx context.Context, t syntra.Transport, corecfg syntra.ClientConfig) (*Client, error) {
	ctx, cancel := context.WithTimeout(ctx, DialTimeout)
	defer cancel()
	return connect(ctx, t, corecfg)
}

func connect(ctx context.Context, t syntra.Transport, cfg syntra.ClientConfig) (*Client, error) {
	if t == nil {
		return nil, ErrConfig
	}
	if err := ctx.Err(); err != nil {
		_ = t.Close()
		return nil, err
	}
	core, err := syntra.OpenClient(cfg)
	if err != nil {
		// Close is part of the transport contract and must return promptly.
		_ = t.Close()
		return nil, publicError(err)
	}
	lifetime, cancel := context.WithCancel(context.Background())
	c := &Client{Client: core, cancel: cancel, done: make(chan struct{})}
	runDone := make(chan error, 1)
	go func() { runDone <- core.Run(lifetime, t) }()
	// The watcher both interrupts I/O and joins Run. Only this goroutine
	// publishes the terminal error, and it never logs transport or policy data.
	go func() {
		var runErr error
		select {
		case runErr = <-runDone:
		case <-lifetime.Done():
			_ = t.Close()
			_ = core.Close()
			runErr = <-runDone
		}
		cancel()
		c.mu.Lock()
		if !c.closing {
			c.err = publicError(runErr)
		}
		c.mu.Unlock()
		close(c.done)
	}()
	if err := core.WaitReady(ctx); err != nil {
		c.cancel()
		<-c.done
		_ = c.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		c.mu.Lock()
		terminal := c.err
		c.mu.Unlock()
		if terminal != nil {
			return nil, terminal
		}
		return nil, publicError(err)
	}
	return c, nil
}

// Done closes after the run pump and its watcher have finished.
func (c *Client) Done() <-chan struct{} { return c.done }

// Wait joins the owned run lifetime, returning its sanitized terminal error.
// A local Close is a clean shutdown. Canceling ctx only stops this wait.
func (c *Client) Wait(ctx context.Context) error {
	select {
	case <-c.done:
	default:
		select {
		case <-c.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close cancels the run lifetime, interrupts transport I/O, and joins for at
// most five seconds. It is safe to call concurrently and repeatedly. A timeout
// means a supplied transport violated its cancellation/Close contract; Done
// closes when that transport eventually releases the pump.
func (c *Client) Close() error {
	c.mu.Lock()
	c.closing = true
	c.mu.Unlock()
	c.cancel()
	timer := time.NewTimer(ShutdownTimeout)
	defer timer.Stop()
	select {
	case <-c.done:
		return nil
	case <-timer.C:
		return ErrShutdownTimeout
	}
}

// Keep codes useful without retaining messages from caller-supplied transports,
// callbacks, HTTP URLs, or authentication data.
func publicError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	var rpc *syntra.RpcError
	if errors.As(err, &rpc) {
		return syntra.NewRpcError(rpc.Code, "connection: session failed")
	}
	for _, known := range []error{securechannel.ErrConfig, securechannel.ErrAuth, ordered.ErrOptions, ordered.ErrProtocol, ordered.ErrIO, ordered.ErrClosed, ordered.ErrBusy} {
		if errors.Is(err, known) {
			return known
		}
	}
	return syntra.NewRpcError(syntra.ErrorCodeUnavailable, "connection: transport failed")
}
