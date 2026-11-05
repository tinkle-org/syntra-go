package syntra

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestWriterCallCancellationAfterHandoffIsIsolated(t *testing.T) {
	for _, expiry := range []bool{false, true} {
		name := "cancellation"
		if expiry {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			gate := &alignmentGatedSend{entered: make(chan struct{}), release: make(chan struct{})}
			c, peer, ctx := alignmentClient(t, ClientConfig{}, func(tr Transport) Transport {
				gate.Transport = tr
				return gate
			})
			var release sync.Once
			t.Cleanup(func() { release.Do(func() { close(gate.release) }) })
			callCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			budget := uint32(3000)
			want := ErrorCodeCancelled
			if expiry {
				budget = 100
				want = ErrorCodeDeadlineExceeded
			}
			first := make(chan error, 1)
			go func() { _, err := c.Call(callCtx, "/example.Echo/First", nil, budget); first <- err }()
			select {
			case <-gate.entered:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			if !expiry {
				cancel()
			}
			select {
			case err := <-first:
				alignmentCode(t, err, want)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			release.Do(func() { close(gate.release) })
			f := alignmentRecv(t, ctx, peer)
			if f.GetRequest().GetMethod() != "/example.Echo/First" {
				t.Fatal("handed-off request was not sent")
			}
			if !expiry {
				cancelFrame := alignmentRecv(t, ctx, peer)
				if cancelFrame.GetCancel() == nil || cancelFrame.GetRequestId() != f.GetRequestId() {
					t.Fatal("missing advisory cancellation after request")
				}
			}
			second := make(chan error, 1)
			go func() { _, err := c.Call(ctx, "/example.Echo/Second", nil, 3000); second <- err }()
			f = alignmentRecv(t, ctx, peer)
			if f.GetRequest().GetMethod() != "/example.Echo/Second" {
				t.Fatal("unexpected frame after abandoned call")
			}
			alignmentReply(t, ctx, peer, f.GetRequestId())
			select {
			case err := <-second:
				if err != nil {
					t.Fatal("call cancellation stopped shared session", err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}

type writerFindingsTransport struct {
	Transport
	send func(context.Context) error
}

func (tr *writerFindingsTransport) Send(ctx context.Context, raw []byte) error {
	f, err := UnmarshalFrame(raw)
	if err != nil {
		return err
	}
	if f.GetHello() == nil {
		return tr.send(ctx)
	}
	return tr.Transport.Send(ctx, raw)
}

func TestWriterSendErrorUsesTransportError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want ErrorCode
	}{
		{"transport-failure", errors.New("send failed"), ErrorCodeUnavailable},
		{"transport-canceled", fmt.Errorf("send: %w", context.Canceled), ErrorCodeCancelled},
		{"transport-deadline", fmt.Errorf("send: %w", context.DeadlineExceeded), ErrorCodeDeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _, ctx := alignmentClient(t, ClientConfig{}, func(tr Transport) Transport {
				return &writerFindingsTransport{Transport: tr, send: func(context.Context) error { return tc.err }}
			})
			_, err := c.Call(ctx, "/example.Echo/Echo", nil, 3000)
			alignmentCode(t, err, tc.want)
		})
	}
}

func TestWriterSendUsesConfiguredTimeout(t *testing.T) {
	for _, control := range []bool{false, true} {
		name := "request"
		if control {
			name = "control"
		}
		t.Run(name, func(t *testing.T) {
			const timeout = 100 * time.Millisecond
			bound := make(chan time.Duration, 1)
			finished := make(chan error, 1)
			c, _, ctx := alignmentClient(t, ClientConfig{DefaultTimeout: timeout}, func(tr Transport) Transport {
				return &writerFindingsTransport{Transport: tr, send: func(ctx context.Context) error {
					deadline, ok := ctx.Deadline()
					if !ok {
						bound <- -1
					} else {
						bound <- time.Until(deadline)
					}
					<-ctx.Done()
					finished <- ctx.Err()
					return ctx.Err()
				}}
			})
			if control {
				c.enqueueControl(mustMarshal(NewCancelFrame(1, 1)))
			} else {
				result := make(chan error, 1)
				go func() { _, err := c.Call(ctx, "/example.Echo/Echo", nil, 3000); result <- err }()
				defer func() { alignmentCode(t, <-result, ErrorCodeDeadlineExceeded) }()
			}
			select {
			case remaining := <-bound:
				if remaining <= 0 || remaining > timeout {
					t.Errorf("Send deadline remaining = %v, want (0, %v]", remaining, timeout)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			select {
			case err := <-finished:
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		})
	}
}
