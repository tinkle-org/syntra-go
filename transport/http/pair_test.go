package syntrahttp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func rawPair(t *testing.T) (*clientPair, *serverPair) {
	t.Helper()
	u, us := net.Pipe()
	d, ds := net.Pipe()
	client, e := ClientPair(u, d, testAuthority(t), ordered.Options{})
	if e != nil {
		t.Fatal(e)
	}
	cp := client.(*clientPair)
	ready := make(chan *serverPair, 1)
	setup := make(chan error, 1)
	attached := make(chan struct{})
	a, r := testAuthority(t), testRoute(t)
	go func() {
		h, e := readHeader(us)
		if e != nil {
			setup <- e
			return
		}
		head, e := ParseRequest(h, a, OriginPolicy{})
		if e != nil {
			setup <- e
			return
		}
		b := make([]byte, head.BodyLen)
		if _, e = io.ReadFull(us, b); e != nil {
			setup <- e
			return
		}
		budget, e := ordered.NewEstablishmentBudget(nil, 15*time.Second)
		if e != nil {
			setup <- e
			return
		}
		sp := newServerPair(us, b, a, OriginPolicy{}, r, budget)
		go sp.runDownload()
		go func() {
			defer close(attached)
			h, e := readHeader(ds)
			if e != nil {
				_ = sp.Close()
				return
			}
			head, e := ParseRequest(h, a, OriginPolicy{})
			if e == nil {
				e = sp.awaitOpen(context.Background())
			}
			if e != nil || !sp.attachDownload(ds, head) {
				_ = sp.Close()
			}
		}()
		if _, e = sp.ReadMessage(context.Background(), make([]byte, 0, 400)); e != nil {
			setup <- e
			return
		}
		ready <- sp
		setup <- sp.WriteMessage(context.Background(), bytes.Repeat([]byte{2}, 48))
	}()
	if e := cp.WriteMessage(context.Background(), bytes.Repeat([]byte{1}, 83)); e != nil {
		t.Fatal(e)
	}
	if _, e := cp.ReadMessage(context.Background(), make([]byte, 0, 48)); e != nil {
		t.Fatal(e)
	}
	sp := <-ready
	if e := <-setup; e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_ = cp.Close()
		_ = sp.Close()
		_ = us.Close()
		_ = ds.Close()
		select {
		case <-sp.done:
		case <-time.After(time.Second):
			t.Error("poll owner did not join")
		}
		select {
		case <-attached:
		case <-time.After(time.Second):
			t.Error("attachment owner did not join")
		}
	})
	return cp, sp
}

func TestRawPairCountersAreTerminal(t *testing.T) {
	for _, which := range []string{"upload-replay", "route", "upload-overflow", "poll-counter", "poll-overflow"} {
		t.Run(which, func(t *testing.T) {
			c, s := rawPair(t)
			ctx, stop := context.WithTimeout(context.Background(), time.Second)
			defer stop()
			if which == "poll-counter" || which == "poll-overflow" {
				c.dCounter = 1
				if which == "poll-overflow" {
					c.dCounter = math.MaxUint64
				}
				if _, e := c.ReadMessage(ctx, make([]byte, 0, MaxRecord)); e == nil {
					t.Fatal("poll counter accepted")
				}
			} else {
				read := make(chan error, 1)
				go func() { _, e := s.ReadMessage(ctx, make([]byte, 0, MaxRecord)); read <- e }()
				switch which {
				case "upload-replay":
					c.uCounter = 1
				case "route":
					c.uRoute.value = string(bytes.Repeat([]byte{'b'}, 64))
				case "upload-overflow":
					c.uCounter = math.MaxUint64
				}
				if e := c.WriteMessage(ctx, bytes.Repeat([]byte{3}, 17)); e == nil {
					t.Fatal("upload violation accepted")
				}
				select {
				case e := <-read:
					if e == nil {
						t.Fatal("server accepted violation")
					}
				case <-time.After(time.Second):
					t.Fatal("server remained blocked")
				}
			}
			if c.check(context.Background()) == nil {
				t.Fatal("pair revived after error")
			}
		})
	}
}

func TestRawPairBoundedReadAndCancellation(t *testing.T) {
	c, s := rawPair(t)
	read := make(chan error, 1)
	go func() { _, e := c.ReadMessage(context.Background(), make([]byte, 0, 16)); read <- e }()
	if e := s.WriteMessage(context.Background(), bytes.Repeat([]byte{5}, 17)); e != nil && !errors.Is(e, ordered.ErrClosed) && !errors.Is(e, ordered.ErrIO) {
		t.Fatal(e)
	}
	select {
	case e := <-read:
		if !errors.Is(e, ordered.ErrProtocol) {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("bounded reader did not fail")
	}
	if c.check(context.Background()) == nil {
		t.Fatal("bounded read failure did not retire")
	}
}

func TestRawPairCloseExchange(t *testing.T) {
	c, s := rawPair(t)
	done := make(chan error, 1)
	go func() { _, e := s.ReadMessage(context.Background(), make([]byte, 0, MaxRecord)); done <- e }()
	if e := c.Shutdown(context.Background()); e != nil {
		t.Fatal(e)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("close owner not joined")
	}
}

func TestRawPairPollRejectsPipelineAndDisconnect(t *testing.T) {
	for _, pipeline := range []bool{false, true} {
		t.Run(map[bool]string{false: "disconnect", true: "pipeline"}[pipeline], func(t *testing.T) {
			c, s := rawPair(t)
			result := make(chan error, 1)
			go func() { _, e := c.ReadMessage(context.Background(), make([]byte, 0, MaxRecord)); result <- e }()
			select {
			case <-s.attached:
			case <-time.After(time.Second):
				t.Fatal("download not attached")
			}
			if pipeline {
				h, _ := requestHeader(Poll, c.authority, c.dRoute, 1, 0)
				_ = c.d.SetWriteDeadline(time.Now().Add(time.Second))
				_, _ = c.d.Write(h)
			} else {
				_ = c.d.Close()
			}
			select {
			case e := <-result:
				if e == nil {
					t.Fatal("invalid poll survived")
				}
			case <-time.After(time.Second):
				t.Fatal("poll failure did not interrupt reader")
			}
			if c.check(context.Background()) == nil {
				t.Fatal("poll failure revived association")
			}
		})
	}
}

func TestRawPairSelectedWriteCancellationJoins(t *testing.T) {
	c, s := rawPair(t)
	// Send a valid poll but never read its response. The selected output must
	// remain owned until cancellation interrupts the write and its worker joins.
	h, _ := requestHeader(Poll, c.authority, c.dRoute, 0, 0)
	if _, e := c.d.Write(h); e != nil {
		t.Fatal(e)
	}
	ctx, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if e := s.WriteMessage(ctx, bytes.Repeat([]byte{7}, MaxRecord)); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal(e)
	}
	select {
	case <-s.done:
	case <-time.After(time.Second):
		t.Fatal("selected output worker not joined")
	}
}

func TestRawPairUnsolicitedRecord(t *testing.T) {
	c, s := rawPair(t)
	result := make(chan []byte, 1)
	go func() {
		b, e := c.ReadMessage(context.Background(), make([]byte, 0, MaxRecord))
		if e != nil {
			result <- nil
		} else {
			result <- b
		}
	}()
	want := bytes.Repeat([]byte{8}, 17)
	if e := s.WriteMessage(context.Background(), want); e != nil {
		t.Fatal(e)
	}
	select {
	case got := <-result:
		if !bytes.Equal(got, want) {
			t.Fatal("unsolicited record changed")
		}
	case <-time.After(time.Second):
		t.Fatal("unsolicited output needed an upload")
	}
}
