// File receipt_wrapper_test.go checks outer receive policy on the stock driver.
package ordered

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
)

// receiptPolicyTransport inherits timed receive but overrides ordinary Recv.
type receiptPolicyTransport struct {
	*Transport
	recv func(context.Context) ([]byte, error)
}

// Recv applies outer policy instead of the embedded driver's promoted method.
func (t *receiptPolicyTransport) Recv(ctx context.Context) ([]byte, error) {
	return t.recv(ctx)
}

// TestReceiptHostHonorsEmbeddedDriverFilter permits Hello, then rejects before
// reading a request. No flag selection, authorization or handler may see it.
func TestReceiptHostHonorsEmbeddedDriverFilter(t *testing.T) {
	var age atomic.Int64
	tr, client, m := timingReceiver(t, &age, Options{})
	var flags, authorizations, handlers atomic.Int32
	host, err := syntra.OpenHost(syntra.HostConfig{
		Policy: func(context.Context, []byte) (string, error) { return "principal", nil },
		RequestBudget: func(string, string, []byte) (time.Duration, bool) {
			flags.Add(1)
			return time.Second, true
		},
		Authorize: func(context.Context, string, string) error { authorizations.Add(1); return nil },
		Handler: func(context.Context, *syntra.RpcRequest) (*syntra.RpcResult, error) {
			handlers.Add(1)
			return syntra.NewSuccessResult(nil), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	hello, _ := syntra.MarshalFrame(syntra.NewHelloFrame(&syntra.ClientHello{MinVersion: 1, MaxVersion: 1}, 1))
	request, _ := syntra.MarshalFrame(syntra.NewRequestFrame(1, 1, &syntra.RpcRequest{Method: "/example.Echo/Echo", TimeoutMs: 1000}))
	putRecord(t, m, client, append(envelope(hello), envelope(request)...))
	denied := errors.New("wrapper denied receive")
	var calls, underlying atomic.Int32
	wrapper := &receiptPolicyTransport{Transport: tr, recv: func(ctx context.Context) ([]byte, error) {
		if calls.Add(1) > 1 {
			return nil, denied
		}
		underlying.Add(1)
		return tr.Recv(ctx)
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := host.Serve(ctx, wrapper); err == nil {
		t.Fatal("rejected request did not stop the host")
	}
	if calls.Load() != 2 || underlying.Load() != 1 || flags.Load() != 0 || authorizations.Load() != 0 || handlers.Load() != 0 {
		t.Fatalf("promoted receive bypassed policy: recv=%d underlying=%d flags=%d authorize=%d handlers=%d", calls.Load(), underlying.Load(), flags.Load(), authorizations.Load(), handlers.Load())
	}
}
