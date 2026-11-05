package routes

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/proxy"
	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
)

type bufferConn struct {
	bytes.Buffer
	maxWrite   int
	closed     bool
	writes     int
	afterWrite func()
}

func (c *bufferConn) Write(p []byte) (int, error) {
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.maxWrite > 0 {
		p = p[:min(len(p), c.maxWrite)]
	}
	c.writes++
	n, err := c.Buffer.Write(p)
	if c.afterWrite != nil {
		c.afterWrite()
	}
	return n, err
}
func (c *bufferConn) Close() error                     { c.closed = true; return nil }
func (c *bufferConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *bufferConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *bufferConn) SetDeadline(time.Time) error      { return nil }
func (c *bufferConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bufferConn) SetWriteDeadline(time.Time) error { return nil }

func forwardFixture(t *testing.T, raw net.Conn, upload bool, b *ordered.EstablishmentBudget) *forwardConn {
	t.Helper()
	creds, err := proxy.NewCredentials([]byte("u"), []byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	defer creds.Close()
	p, err := proxy.NewProxy(proxy.Config{Endpoint: localAddress(1080), Kind: proxy.HTTPConnect, Credentials: creds})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	a, err := syntrahttp.NewAuthority("origin.invalid:80")
	if err != nil {
		t.Fatal(err)
	}
	return newForwardConn(raw, p, a, upload, b)
}
func requestHead(op syntrahttp.Operation, n int, route string, counter uint64) []byte {
	s := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: origin.invalid:80\r\nCache-Control: no-store\r\nAccept: application/octet-stream\r\nContent-Length: %d\r\n", op.Path(), n)
	if n > 0 {
		s += "Content-Type: application/octet-stream\r\n"
	}
	if op != syntrahttp.Open {
		s += "Syntra-Route: " + route + "\r\n"
	}
	if op == syntrahttp.Send {
		s += fmt.Sprintf("Syntra-Upload: %d\r\n", counter)
	}
	if op == syntrahttp.Poll {
		s += fmt.Sprintf("Syntra-Poll: %d\r\n", counter)
	}
	return []byte(s + "\r\n")
}
func forwardWire(head, body []byte) []byte {
	s := strings.Replace(string(head), "POST /", "POST http://origin.invalid:80/", 1)
	s = strings.TrimSuffix(s, "\r\n") + "Proxy-Authorization: Basic dTpw\r\n\r\n"
	return append([]byte(s), body...)
}

func TestForwardEveryHeaderSplitAndTinyWritesPreserveBodies(t *testing.T) {
	body := bytes.Repeat([]byte{1}, 83)
	copy(body[40:], "\r\n\r\n")
	head := requestHead(syntrahttp.Open, len(body), "", 0)
	expected := forwardWire(head, body)
	for split := 0; split <= len(head); split++ {
		raw := &bufferConn{maxWrite: 1}
		c := forwardFixture(t, raw, true, nil)
		if n, err := c.Write(head[:split]); err != nil || n != split {
			t.Fatalf("split %d prefix %d: %v", split, n, err)
		}
		if n, err := c.Write(head[split:]); err != nil || n != len(head)-split {
			t.Fatalf("split %d suffix %d: %v", split, n, err)
		}
		before := append([]byte(nil), body...)
		if err := stream.WriteAll(c, body); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(body, before) {
			t.Fatal("body mutated")
		}
		if !bytes.Equal(raw.Bytes(), expected) {
			t.Fatalf("split %d wire mismatch", split)
		}
		if err := c.Close(); err != nil {
			t.Fatal(err)
		}
		for _, b := range c.head {
			if b != 0 {
				t.Fatal("header scratch retained")
			}
		}
	}
}

func TestForwardInvalidHeadersEmitNothing(t *testing.T) {
	head := string(requestHead(syntrahttp.Open, 83, "", 0))
	for _, bad := range []string{strings.Replace(head, "Host: origin.invalid:80", "Host: other.invalid:80", 1), strings.Replace(head, syntrahttp.Open.Path(), "/unknown", 1), strings.Replace(head, syntrahttp.Open.Path(), syntrahttp.Open.Path()+"?route=x", 1), strings.Replace(head, "\r\n\r\n", "\r\nProxy-Authorization: Basic injected\r\n\r\n", 1), strings.Replace(head, "\r\n\r\n", "\r\nAuthorization: injected\r\n\r\n", 1), strings.Replace(head, "\r\n\r\n", "\r\nCookie: injected\r\n\r\n", 1), strings.Replace(head, "\r\n\r\n", "\r\nHost: origin.invalid:80\r\n\r\n", 1), strings.Repeat("x", syntrahttp.MaxHeaders+1)} {
		raw := &bufferConn{}
		c := forwardFixture(t, raw, true, nil)
		if _, err := c.Write([]byte(bad)); !errors.Is(err, ordered.ErrProtocol) {
			t.Fatalf("malformed header: %v", err)
		}
		if raw.Len() != 0 {
			t.Fatal("invalid header emitted bytes")
		}
		if _, err := c.Write([]byte(head)); err == nil {
			t.Fatal("failed stream reused")
		}
	}
	raw := &bufferConn{}
	c := forwardFixture(t, raw, false, nil)
	if _, err := c.Write([]byte(head)); err == nil || raw.Len() != 0 {
		t.Fatal("Open accepted on download lane")
	}
}

func TestForwardEnforcesLaneRouteAndCounterContinuity(t *testing.T) {
	route := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	for _, upload := range []bool{false, true} {
		raw := &bufferConn{}
		c := forwardFixture(t, raw, upload, nil)
		if upload {
			if err := stream.WriteAll(c, append(requestHead(syntrahttp.Open, 83, "", 0), make([]byte, 83)...)); err != nil {
				t.Fatal(err)
			}
		}
		op, n := syntrahttp.Poll, 0
		if upload {
			op, n = syntrahttp.Send, 17
		}
		for i := uint64(0); i < 2; i++ {
			p := append(requestHead(op, n, route, i), make([]byte, n)...)
			if err := stream.WriteAll(c, p); err != nil {
				t.Fatal(err)
			}
		}
		before := raw.Len()
		if _, err := c.Write(requestHead(op, n, other, 2)); !errors.Is(err, ordered.ErrProtocol) {
			t.Fatal("route changed")
		}
		if raw.Len() != before {
			t.Fatal("invalid route emitted bytes")
		}
		raw = &bufferConn{}
		c = forwardFixture(t, raw, false, nil)
		if _, err := c.Write(requestHead(syntrahttp.Poll, 0, route, 1)); !errors.Is(err, ordered.ErrProtocol) || raw.Len() != 0 {
			t.Fatal("counter skip accepted")
		}
	}
}

func TestForwardPartialWireCancellationRetiresWithoutBodyOrReplay(t *testing.T) {
	var age atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	b, err := ordered.NewEstablishmentBudget(clock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	raw := &bufferConn{maxWrite: 4, afterWrite: func() { age.Store(int64(time.Second)) }}
	c := forwardFixture(t, raw, true, b)
	head := requestHead(syntrahttp.Open, 83, "", 0)
	n, err := c.Write(append(head, make([]byte, 83)...))
	if !errors.Is(err, context.DeadlineExceeded) || n != len(head) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if raw.Len() != 4 || raw.writes != 1 {
		t.Fatalf("writes=%d bytes=%d", raw.writes, raw.Len())
	}
	if _, err := c.Write(head); err == nil {
		t.Fatal("canceled stream reused")
	}
}

func TestForwardCloseInterruptsBlockedHeaderWrite(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	c := forwardFixture(t, left, true, nil)
	done := make(chan error, 1)
	go func() { _, err := c.Write(requestHead(syntrahttp.Open, 83, "", 0)); done <- err }()
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close blocked behind write")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked write succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("writer not interrupted")
	}
	var one [1]byte
	if _, err := right.Read(one[:]); err != io.EOF {
		t.Fatal(err)
	}
}
