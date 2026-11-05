package connection

import (
	"context"
	"errors"
	"sync"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

// ShutdownTimeout bounds the default wait for owned resources to finish.
const ShutdownTimeout = 5 * time.Second

var (
	ErrConfig          = errors.New("connection: invalid configuration")
	ErrClosed          = errors.New("connection: server closed")
	ErrShutdownTimeout = errors.New("connection: shutdown did not complete within budget")
)

// Client owns a running session and its carrier. Construct it with Connect;
// the zero value is invalid. The embedded client exposes Call and Notifications.
// Do not replace it or call Run. Close stops and joins the owned lifetime.
type Client struct {
	*syntra.Client
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.Mutex
	closing   bool
	err       error
	transport *ordered.Transport
}

// Connect takes ownership of carrier, including on failure, establishes an
// encrypted channel, and waits for validated core readiness. Carrier must obey
// ordered.MessageIO's bounded-read, cancellation, and prompt Close contract.
//
// ctx bounds establishment only. After success the caller must Close the client.
// To include carrier setup in the same attempt, create an EstablishmentBudget
// before setup, use its Context there, and pass it in opts.Budget. An omitted
// budget begins here; no new budget is started between encryption and Ready.
func Connect(ctx context.Context, carrier ordered.MessageIO, channelcfg securechannel.ClientConfig, corecfg syntra.ClientConfig, opts ordered.Options) (*Client, error) {
	if carrier == nil {
		return nil, ErrConfig
	}
	opts, err := establishmentOptions(opts)
	if err != nil {
		_ = carrier.Close()
		return nil, publicError(err)
	}
	core, err := syntra.OpenClient(corecfg)
	if err != nil {
		_ = carrier.Close()
		return nil, publicError(err)
	}
	t, err := ordered.Client(ctx, carrier, channelcfg, opts)
	if err != nil {
		_ = core.Close()
		return nil, publicError(err)
	}
	establish, stop := t.EstablishmentContextWithTimeout(ctx, corecfg.HandshakeTimeout)
	defer stop()
	lifetime, cancel := context.WithCancel(context.Background())
	c := &Client{Client: core, cancel: cancel, done: make(chan struct{}), transport: t}
	runDone := make(chan error, 1)
	go func() { runDone <- core.Run(lifetime, t) }()
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
		_ = t.Close()
		_ = core.Close()
		c.mu.Lock()
		c.captureTerminalLocked(runErr)
		c.mu.Unlock()
		close(c.done)
	}()
	readyErr := core.WaitReady(establish)
	if readyErr == nil {
		readyErr = establishmentError(ctx, t)
	}
	if readyErr == nil {
		opts.Budget.Release()
		readyErr = opts.Budget.Check()
	}
	if readyErr != nil {
		cancel()
		<-c.done
		if err := establishmentError(ctx, t); err != nil {
			return nil, err
		}
		if c.err != nil {
			return nil, c.err
		}
		return nil, publicError(readyErr)
	}
	return c, nil
}

// Done closes only after the run pump and all owned cleanup have finished.
func (c *Client) Done() <-chan struct{} { return c.done }

// TerminalError returns the sanitized failure before joined Done. The first
// specific failure supersedes generic loss and stays sticky.
func (c *Client) TerminalError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.captureTerminalLocked(nil)
	return c.err
}

func (c *Client) captureTerminalLocked(runErr error) {
	if specificFailure(c.err) {
		return
	}
	for _, cause := range []error{c.Client.TerminalError(), c.transport.TerminalError(), runErr} {
		if cause == nil || c.closing && c.transport.LocalStopError(cause) {
			continue
		}
		if c.err == nil || specificFailure(cause) {
			c.err = publicError(cause)
			if specificFailure(c.err) {
				return
			}
		}
	}
}

func specificFailure(err error) bool {
	if err == nil {
		return false
	}
	for _, known := range []error{securechannel.ErrConfig, securechannel.ErrAuth, securechannel.ErrRecord, securechannel.ErrLimit, ordered.ErrOptions, ordered.ErrProtocol} {
		if errors.Is(err, known) {
			return true
		}
	}
	var rpc *syntra.RpcError
	if errors.As(err, &rpc) {
		return rpc.Code != syntra.ErrorCodeCancelled && rpc.Code != syntra.ErrorCodeUnavailable && rpc.Code != syntra.ErrorCodeDeadlineExceeded
	}
	return !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) &&
		!errors.Is(err, ErrClosed) && !errors.Is(err, ordered.ErrClosed) && !errors.Is(err, ordered.ErrIO) && !errors.Is(err, securechannel.ErrClosed)
}

// IsClosed reports a stop request or the core admission fence promptly.
func (c *Client) IsClosed() bool {
	c.mu.Lock()
	closing := c.closing
	c.mu.Unlock()
	return closing || c.Client.IsClosed() || c.TerminalError() != nil
}

// Suspend invalidates elapsed continuity and cancels admission without joining
// carrier cleanup. It is safe to call while an owner's state lock is held.
func (c *Client) Suspend() {
	c.mu.Lock()
	c.captureTerminalLocked(nil)
	c.closing = true
	c.transport.Suspend()
	c.mu.Unlock()
	c.cancel()
	go c.Client.Close()
}

// Wait joins the owned lifetime and returns its sanitized terminal error.
// A local Close is clean. Canceling ctx only stops this wait.
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

// Close cancels the lifetime, interrupts I/O, and joins within ShutdownTimeout.
// It is safe concurrently and repeatedly. On timeout, ownership is retained:
// Done closes when cleanup finishes and a later Close can join it again.
func (c *Client) Close() error {
	c.mu.Lock()
	c.captureTerminalLocked(nil)
	c.closing = true
	c.transport.Stop()
	c.mu.Unlock()
	c.cancel()
	ctx, stop := context.WithTimeout(context.Background(), ShutdownTimeout)
	defer stop()
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ErrShutdownTimeout
	}
}

func establishmentOptions(opts ordered.Options) (ordered.Options, error) {
	o, err := opts.Normalize()
	if err == nil && o.Budget == nil {
		o.Budget, err = ordered.NewEstablishmentBudget(nil, o.AttemptTimeout)
	}
	return o, err
}

func contextError(ctx context.Context) error {
	if ctx.Err() == nil {
		return nil
	}
	if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return ctx.Err()
}

// Resample trusted elapsed time after synchronous core work as well as after
// cancellation. The context's periodic sampler may not have run yet.
func establishmentError(parent context.Context, t *ordered.Transport) error {
	ctx, cancel := t.EstablishmentContext(parent)
	defer cancel()
	return contextError(ctx)
}

// Preserve useful codes without retaining carrier or policy diagnostics.
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
	for _, known := range []error{ErrConfig, ErrClosed, securechannel.ErrConfig, securechannel.ErrAuth, securechannel.ErrRecord, securechannel.ErrClosed, securechannel.ErrLimit, ordered.ErrOptions, ordered.ErrProtocol, ordered.ErrIO, ordered.ErrClosed, ordered.ErrBusy} {
		if errors.Is(err, known) {
			return known
		}
	}
	return syntra.NewRpcError(syntra.ErrorCodeUnavailable, "connection: carrier failed")
}
