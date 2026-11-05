package ordered_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

// Exercise typed code discovery through As, not a concrete-type assertion or
// diagnostic-string matching.
type resultError struct{ code syntra.ErrorCode }

func (e resultError) Error() string { return "private result diagnostic" }
func (e resultError) As(target any) bool {
	p, ok := target.(**syntra.RpcError)
	if ok {
		*p = syntra.NewRpcError(e.code, "private result diagnostic")
	}
	return ok
}

type terminalPropagationIO struct {
	ordered.MessageIO
	reads, writes         atomic.Int32
	reading, resume, lost chan struct{}
	failure               error
	once                  sync.Once
}

func (m *terminalPropagationIO) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	if m.reads.Add(1) < 3 {
		return m.MessageIO.ReadMessage(ctx, dst)
	}
	close(m.reading)
	<-m.resume
	return nil, m.failure
}

func (m *terminalPropagationIO) WriteMessage(ctx context.Context, p []byte) error {
	if m.writes.Add(1) < 3 {
		return m.MessageIO.WriteMessage(ctx, p)
	}
	return ordered.ErrIO
}

func (m *terminalPropagationIO) Close() error {
	m.once.Do(func() { close(m.lost) })
	return m.MessageIO.Close()
}

func propagationWait(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("propagation barrier did not finish")
	}
}

func TestConnectionTerminalUpgradesGenericLossAfterLocalStop(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"authentication", securechannel.ErrAuth},
		{"protocol", ordered.ErrProtocol},
		{"root-code", resultError{syntra.ErrorCodeUnauthenticated}},
		{"invalid-argument", resultError{syntra.ErrorCodeInvalidArgument}},
		{"failed-precondition", resultError{syntra.ErrorCodeFailedPrecondition}},
		{"unimplemented", resultError{syntra.ErrorCodeUnimplemented}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cc, sc := regressionConfigs(t)
			a, b := regressionPair()
			carrier := &terminalPropagationIO{MessageIO: a, reading: make(chan struct{}), resume: make(chan struct{}), lost: make(chan struct{}), failure: tc.err}
			var resume sync.Once
			defer resume.Do(func() { close(carrier.resume) })
			host, err := syntra.OpenHost(syntra.HostConfig{
				ChannelPolicy: func(context.Context, syntra.ChannelIdentity, []byte) (string, error) { return "principal", nil },
				Authorize:     syntra.AllowAllAuthorize,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			accepted := make(chan error, 1)
			go func() { accepted <- connection.Accept(context.Background(), b, sc, host, ordered.Options{}) }()
			c, err := connection.Connect(context.Background(), carrier, cc, syntra.ClientConfig{}, ordered.Options{})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				resume.Do(func() { close(carrier.resume) })
				_ = c.Close()
				regressionJoin(t, accepted)
			}()
			propagationWait(t, carrier.reading)
			called := make(chan error, 1)
			go func() { _, err := c.Call(context.Background(), "/example.Echo/Echo", nil, 0); called <- err }()
			propagationWait(t, carrier.lost)
			if err := c.TerminalError(); err != ordered.ErrIO {
				t.Fatalf("initial generic failure = %v", err)
			}
			c.Suspend()
			resume.Do(func() { close(carrier.resume) })
			propagationWait(t, c.Done())
			regressionJoin(t, called)
			got := c.Wait(context.Background())
			var want *syntra.RpcError
			if errors.As(tc.err, &want) {
				var rpc *syntra.RpcError
				if !errors.As(got, &rpc) || rpc.Code != want.Code || strings.Contains(got.Error(), "private") {
					t.Fatalf("root code lost or diagnostic retained: %v", got)
				}
			} else if !errors.Is(got, tc.err) {
				t.Fatalf("generic failure masked security failure: %v", got)
			}
			if got != c.TerminalError() {
				t.Fatal("joined and immediate terminal results disagree")
			}
		})
	}
}
