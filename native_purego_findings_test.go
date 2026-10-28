//go:build !syntranative

package syntra

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func requireFindingCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	var rpcErr *RpcError
	if !errors.As(err, &rpcErr) || rpcErr.Code != want {
		t.Fatalf("error = %v, want code %v", err, want)
	}
}

func TestPureGoFailedMarshalDoesNotRegisterCall(t *testing.T) {
	cfg, err := resolveClientConfig(ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}
	core, err := newClientCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer core.close()
	ready, err := MarshalFrame(NewReadyFrame(1, &ServerReady{ConnectionId: "marshal-regression"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.activate(ready); err != nil {
		t.Fatal(err)
	}
	c := core.(*goClientCore)
	// The payload fits its own limit, but envelope overhead exceeds the wire
	// limit. Repeated failures must neither exhaust slots nor create timers.
	payload := make([]byte, MaxPayloadBytes)
	for id := uint64(1); id <= MaxConcurrentRPCs+1; id++ {
		raw, err := c.beginCall(id, "/example.Echo/Echo", payload, 1000)
		requireFindingCode(t, err, ErrorCodeResourceExhausted)
		if len(raw) != 0 || c.tracker.Pending() != 0 {
			t.Fatalf("failed marshal retained request %d: bytes=%d pending=%d", id, len(raw), c.tracker.Pending())
		}
	}
	if ids := c.reapExpired(time.Now().Add(time.Hour)); len(ids) != 0 {
		t.Fatalf("untransmitted calls expired: %v", ids)
	}
	// Reuse the same ID after failure and complete a near-bound request.
	raw, err := c.beginCall(1, "/example.Echo/Echo", payload[:MaxFrameBytes-128], 1000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalFrame(raw); err != nil {
		t.Fatal(err)
	}
	result, err := MarshalFrame(NewResultFrame(1, 1, NewSuccessResult(nil)))
	if err != nil {
		t.Fatal(err)
	}
	ids, _, fatal := c.onFrame(result)
	if fatal != nil || len(ids) != 1 || ids[0] != 1 || c.tracker.Pending() != 0 {
		t.Fatalf("completion = %v, %v; pending=%d", ids, fatal, c.tracker.Pending())
	}
}

func newActiveFindingHost(t *testing.T, config HostConfig) *goHostCore {
	t.Helper()
	cfg, err := resolveHostConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	core, err := newHostCore(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = core.close() })
	h := core.(*goHostCore)
	hello, err := MarshalFrame(NewHelloFrame(&ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.acceptHello(hello); err != nil {
		t.Fatal(err)
	}
	if _, err := h.authComplete("notification-regression"); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestPureGoHostConfiguredDefaultTimeout(t *testing.T) {
	const budget = 137 * time.Millisecond
	h := newActiveFindingHost(t, HostConfig{DefaultTimeout: budget})
	for _, tc := range []struct {
		id      uint64
		timeout uint32
		budget  time.Duration
	}{
		{1, 0, budget},
		{2, 5000, 5 * time.Second},
	} {
		raw, err := MarshalFrame(NewRequestFrame(1, tc.id, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: tc.timeout}))
		if err != nil {
			t.Fatal(err)
		}
		before := time.Now()
		if _, _, fatal := h.onFrame(raw); fatal != nil {
			t.Fatal(fatal)
		}
		after := time.Now()
		deadline := h.outstanding[tc.id].deadline
		if deadline.Before(before.Add(tc.budget)) || deadline.After(after.Add(tc.budget)) {
			t.Fatalf("request %d deadline = %v, want arrival + %v", tc.id, deadline, tc.budget)
		}
	}
	if ids := h.reapExpired(h.outstanding[1].deadline); len(ids) != 1 || ids[0] != 1 {
		t.Fatalf("host default expiry = %v", ids)
	}
}

func TestPureGoHostNotificationBackpressure(t *testing.T) {
	h := newActiveFindingHost(t, HostConfig{})

	// Multiple producers race while the transport is not draining. This
	// checks the documented 256-frame admission bound under contention.
	var accepted, rejected, unexpected atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 16; j++ {
				err := h.notify([]byte("queued"))
				var rpcErr *RpcError
				switch {
				case err == nil:
					accepted.Add(1)
				case errors.As(err, &rpcErr) && rpcErr.Code == ErrorCodeResourceExhausted:
					rejected.Add(1)
				default:
					unexpected.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 256 || rejected.Load() != 256 || unexpected.Load() != 0 {
		t.Fatalf("accepted=%d rejected=%d unexpected=%d", accepted.Load(), rejected.Load(), unexpected.Load())
	}

	// A saturated notification backlog must not suppress terminal RPC
	// errors or deadline results that share the outbound queue.
	badRequest, err := proto.Marshal(NewRequestFrame(1, 7, &RpcRequest{Method: "invalid"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, fatal := h.onFrame(badRequest); fatal != nil {
		t.Fatal(fatal)
	}
	request, err := MarshalFrame(NewRequestFrame(1, 8, &RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, fatal := h.onFrame(request); fatal != nil {
		t.Fatal(fatal)
	}
	if ids := h.reapExpired(time.Now().Add(time.Hour)); len(ids) != 1 || ids[0] != 8 {
		t.Fatalf("expired = %v", ids)
	}
	for i := 0; i < 258; i++ {
		raw, ok := h.nextOutbound()
		if !ok {
			t.Fatalf("queue ended at %d", i)
		}
		f, err := UnmarshalFrame(raw)
		if err != nil {
			t.Fatal(err)
		}
		if i < 256 {
			if string(f.GetNotification().GetPayload()) != "queued" {
				t.Fatalf("notification %d = %v", i, f)
			}
		} else {
			wantID, wantCode := uint64(7), ErrorCodeInvalidArgument
			if i == 257 {
				wantID, wantCode = 8, ErrorCodeDeadlineExceeded
			}
			if f.GetRequestId() != wantID || f.GetResult().GetError().GetCode() != wantCode {
				t.Fatalf("terminal result = %v", f)
			}
		}
	}
	if _, ok := h.nextOutbound(); ok {
		t.Fatal("extra queued frame")
	}
	if err := h.notify(nil); err != nil {
		t.Fatalf("notification admission did not recover: %v", err)
	}
	raw, ok := h.nextOutbound()
	if !ok {
		t.Fatal("missing recovered notification")
	}
	if f, err := UnmarshalFrame(raw); err != nil || BodyKindOf(f) != BodyKindNotification {
		t.Fatalf("recovered notification = %v, %v", f, err)
	}
}
