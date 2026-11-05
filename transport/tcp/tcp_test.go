package tcp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func TestRecordsBoundedRoundTrip(t *testing.T) {
	for _, size := range []int{17, securechannel.HandshakeSize, securechannel.MaxContext + securechannel.HandshakeSize, 65535} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			a, b := net.Pipe()
			left, right := New(a, nil), New(b, nil)
			defer left.Close()
			defer right.Close()
			want := bytes.Repeat([]byte{byte(size)}, size)
			done := make(chan error, 1)
			go func() { done <- left.WriteMessage(context.Background(), want) }()
			storage := make([]byte, 0, size)
			got, err := right.ReadMessage(context.Background(), storage)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("read: %d, %v", len(got), err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if &got[0] != &storage[:cap(storage)][0] {
				t.Fatal("did not reuse caller storage")
			}
		})
	}
}

func TestRejectLengthBeforeBody(t *testing.T) {
	for _, n := range []uint16{0, 16, 33, 65535} {
		a, b := net.Pipe()
		carrier := New(a, nil)
		done := make(chan struct{})
		go func() {
			defer close(done)
			defer b.Close()
			var prefix [2]byte
			binary.BigEndian.PutUint16(prefix[:], n)
			_, _ = b.Write(prefix[:])
			var p [1]byte
			_, _ = b.Read(p[:])
		}()
		_, err := carrier.ReadMessage(context.Background(), make([]byte, 0, 32))
		if !errors.Is(err, ordered.ErrProtocol) {
			t.Fatalf("length %d: %v", n, err)
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("failure did not close stream")
		}
	}
}

func TestCancellationOwnsAndInterruptsBothDirections(t *testing.T) {
	for _, write := range []bool{false, true} {
		a, b := net.Pipe()
		carrier := New(a, nil)
		defer b.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		var err error
		if write {
			err = carrier.WriteMessage(ctx, make([]byte, 17))
		} else {
			_, err = carrier.ReadMessage(ctx, make([]byte, 0, 17))
		}
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		if _, err := b.Read(make([]byte, 1)); err == nil {
			t.Fatal("stream remained open")
		}
	}
}

type jumpWriter struct {
	net.Conn
	age    *atomic.Int64
	writes int
}

func (c *jumpWriter) Write(p []byte) (int, error) {
	c.writes++
	c.age.Store(int64(time.Second))
	return len(p), nil
}
func TestPrefixCrossingBudgetNeverWritesPayload(t *testing.T) {
	var age atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	b, _ := ordered.NewEstablishmentBudget(clock, time.Second)
	a, peer := net.Pipe()
	defer peer.Close()
	raw := &jumpWriter{Conn: a, age: &age}
	err := New(raw, b).WriteMessage(context.Background(), make([]byte, 17))
	if !errors.Is(err, context.DeadlineExceeded) || raw.writes != 1 {
		t.Fatalf("writes=%d err=%v", raw.writes, err)
	}
}

func TestLoopbackSessionsPushWithoutCall(t *testing.T) {
	for _, mode := range []securechannel.Mode{securechannel.Bootstrap, securechannel.Returning} {
		t.Run(mode.String(), func(t *testing.T) {
			key, err := securechannel.GenerateStaticKey()
			if err != nil {
				t.Fatal(err)
			}
			cc := securechannel.ClientConfig{Context: securechannel.Context{Mode: mode, Carrier: securechannel.TCP, Scope: "native"}, ServerPublicKey: key.Public()}
			sc := securechannel.ServerConfig{StaticKey: key, Carrier: securechannel.TCP, Scope: "native", AllowBootstrap: mode == securechannel.Bootstrap}
			if mode == securechannel.Returning {
				cc.AuthorizationKey, err = securechannel.GenerateKey()
				if err != nil {
					t.Fatal(err)
				}
				cc.Context.Epoch, cc.Context.Handle = 1, [8]byte{1}
				sc.Lookup = func(context.Context, securechannel.Context) (securechannel.Enrollment, error) {
					return securechannel.Enrollment{Key: cc.AuthorizationKey, Principal: "device", ExpiresAt: time.Now().Add(time.Hour)}, nil
				}
			}
			host, err := syntra.OpenHost(syntra.HostConfig{
				ChannelPolicy: func(context.Context, syntra.ChannelIdentity, []byte) (string, error) { return "native", nil },
				Authorize:     syntra.AllowAllAuthorize,
				Handler: func(_ context.Context, request *syntra.RpcRequest) (*syntra.RpcResult, error) {
					return syntra.NewSuccessResult(request.GetPayload()), nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var age atomic.Int64
			clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
			clientBudget, err := ordered.NewEstablishmentBudget(clock, 80*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			serverBudget, err := ordered.NewEstablishmentBudget(clock, 80*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err == nil {
					err = Accept(ctx, conn, sc, host, ordered.Options{Budget: serverBudget})
				}
				done <- err
			}()
			client, err := Dial(ctx, listener.Addr().String(), cc, syntra.ClientConfig{}, ordered.Options{Budget: clientBudget})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := host.NotifyAll([]byte("unsolicited")); err != nil {
				t.Fatal(err)
			}
			select {
			case n := <-client.Notifications():
				if string(n.GetPayload()) != "unsolicited" {
					t.Fatal("wrong push")
				}
			case <-ctx.Done():
				t.Fatal("missing push")
			}
			// The first push also crosses the server's committed Ready boundary.
			// Advance the same clock used by setup and the active channel, then
			// let any wall-time setup watchdog expire before exercising both ways.
			age.Store(int64(100 * time.Millisecond))
			if err := clientBudget.Check(); err != nil {
				t.Fatalf("client setup cutoff not released: %v", err)
			}
			if err := serverBudget.Check(); err != nil {
				t.Fatalf("server setup cutoff not released: %v", err)
			}
			time.Sleep(100 * time.Millisecond)
			if err := host.NotifyAll([]byte("after cutoff")); err != nil {
				t.Fatal(err)
			}
			select {
			case n := <-client.Notifications():
				if string(n.GetPayload()) != "after cutoff" {
					t.Fatal("wrong post-cutoff push")
				}
			case <-ctx.Done():
				t.Fatal("missing post-cutoff push")
			}
			got, err := client.Call(ctx, "/example.Echo/Echo", []byte("after cutoff"), 0)
			if err != nil || string(got) != "after cutoff" {
				t.Fatalf("post-cutoff call = %q, %v", got, err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("accept did not join")
			}
		})
	}
}
