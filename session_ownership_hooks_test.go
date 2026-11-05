package syntra

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
)

func TestHostWaitRetainsRecoveryEgressAfterServeReturns(t *testing.T) {
	source := &recoveryBlockingEmitter{recoveryTestSource: newRecoveryTestSource(), entered: make(chan struct{}), release: make(chan struct{}), ignoreCancellation: true}
	var release sync.Once
	defer release.Do(func() { close(source.release) })
	p, _, _ := runtimeStartBlockedRecovery(t, source)
	awaitSignal(t, source.entered, "recovery provider")
	if err := p.host.Close(); err != nil {
		t.Fatal(err)
	}
	err := runtimeAwait(t, p.done)
	p.done <- err
	select {
	case <-p.host.Done():
		t.Fatal("Host relinquished ownership of blocked recovery egress")
	default:
	}
	ctx, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	if err := p.host.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("Wait ignored retained egress", err)
	}
	release.Do(func() { close(source.release) })
	ctx, stopJoin := context.WithTimeout(context.Background(), time.Second)
	defer stopJoin()
	if err := p.host.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

type hookTerminalTransport struct {
	Transport
	failure                   error
	trigger, closing, release chan struct{}
	reads                     atomic.Int32
	once                      sync.Once
}

func (t *hookTerminalTransport) Recv(ctx context.Context) ([]byte, error) {
	if t.reads.Add(1) == 1 {
		return t.Transport.Recv(ctx)
	}
	select {
	case <-t.trigger:
		return nil, t.failure
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *hookTerminalTransport) Close() error {
	t.once.Do(func() { close(t.closing) })
	<-t.release
	return t.Transport.Close()
}

func TestRootTerminalCausePrecedesJoinedCleanup(t *testing.T) {
	for _, failure := range []error{NewRpcError(ErrorCodeUnauthenticated, "admission ended"), securechannel.ErrRecord} {
		t.Run(failure.Error(), func(t *testing.T) {
			tr := &hookTerminalTransport{failure: failure, trigger: make(chan struct{}), closing: make(chan struct{}), release: make(chan struct{})}
			c, _, _ := alignmentClient(t, ClientConfig{}, func(base Transport) Transport { tr.Transport = base; return tr })
			var release sync.Once
			defer release.Do(func() { close(tr.release) })
			close(tr.trigger)
			awaitSignal(t, tr.closing, "retained close")
			if c.TerminalError() != failure {
				t.Fatal("run failure flattened or delayed", c.TerminalError())
			}
			closed := make(chan struct{})
			go func() { _ = c.Close(); close(closed) }()
			release.Do(func() { close(tr.release) })
			awaitSignal(t, closed, "local close")
			if c.TerminalError() != failure {
				t.Fatal("local close masked run failure", c.TerminalError())
			}
		})
	}
}
