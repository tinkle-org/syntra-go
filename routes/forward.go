package routes

import (
	"bytes"
	"math"
	"net"
	"sync"
	"sync/atomic"

	"github.com/tinkle-org/syntra-go/proxy"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/stream"
)

// forwardConn adapts only complete, codec-validated origin headers. Each lane
// owns a proxy socket; bodies pass through unchanged without buffering/replay.
type forwardConn struct {
	net.Conn
	proxy            *proxy.ProxyConfig
	authority        syntrahttp.Authority
	upload           bool
	mu               sync.Mutex
	closed           atomic.Bool
	head             [syntrahttp.MaxHeaders]byte
	used, remaining  int
	opened, finished bool
	route            syntrahttp.Route
	hasRoute         bool
	counter          uint64
}

func newForwardConn(raw net.Conn, p *proxy.ProxyConfig, a syntrahttp.Authority, upload bool, b *ordered.EstablishmentBudget) *forwardConn {
	return &forwardConn{Conn: stream.New(raw, b), proxy: p, authority: a, upload: upload}
}

func (c *forwardConn) Close() error {
	c.closed.Store(true)
	err := c.Conn.Close()
	c.mu.Lock()
	clear(c.head[:])
	c.used = 0
	c.mu.Unlock()
	return err
}
func (c *forwardConn) fail() error {
	c.closed.Store(true)
	clear(c.head[:])
	c.used = 0
	_ = c.Conn.Close()
	return ordered.ErrProtocol
}

func (c *forwardConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed.Load() {
		return 0, ordered.ErrProtocol
	}
	consumed := 0
	for len(p) > 0 {
		if c.remaining > 0 {
			n := min(len(p), c.remaining)
			written, err := c.Conn.Write(p[:n])
			if written < 0 || written > n {
				return consumed, c.fail()
			}
			consumed += written
			c.remaining -= written
			p = p[written:]
			if err != nil {
				_ = c.fail()
				return consumed, err
			}
			if written == 0 {
				return consumed, c.fail()
			}
			continue
		}
		if c.finished {
			return consumed, c.fail()
		}
		if c.used == len(c.head) {
			return consumed, c.fail()
		}
		c.head[c.used] = p[0]
		c.used++
		p = p[1:]
		consumed++
		if c.used >= 4 && bytes.Equal(c.head[c.used-4:c.used], []byte("\r\n\r\n")) {
			if err := c.rewrite(); err != nil {
				_ = c.fail()
				return consumed, err
			}
		}
	}
	return consumed, nil
}

func (c *forwardConn) rewrite() error {
	head := c.head[:c.used]
	parsed, err := syntrahttp.ParseRequest(head, c.authority, syntrahttp.OriginPolicy{})
	if err != nil {
		return ordered.ErrProtocol
	}
	switch {
	case c.upload && !c.opened && parsed.Operation == syntrahttp.Open:
		c.opened = true
	case c.upload && c.opened && parsed.Operation == syntrahttp.Send || !c.upload && parsed.Operation == syntrahttp.Poll:
		if c.counter == math.MaxUint64 || parsed.Counter != c.counter {
			return ordered.ErrProtocol
		}
		c.counter++
	case c.upload && c.opened && parsed.Operation == syntrahttp.Close:
		c.finished = true
	default:
		return ordered.ErrProtocol
	}
	if parsed.Operation != syntrahttp.Open {
		if c.hasRoute && c.route != parsed.Route {
			return ordered.ErrProtocol
		}
		c.route = parsed.Route
		c.hasRoute = true
	}
	lineEnd := bytes.Index(head, []byte("\r\n"))
	if lineEnd < 0 {
		return ordered.ErrProtocol
	}
	if bytes.Count(head, []byte("\r\n"))-2 >= syntrahttp.MaxFields {
		return ordered.ErrProtocol
	}
	start := "POST http://" + c.authority.String() + parsed.Operation.Path() + " HTTP/1.1\r\n"
	rest := head[lineEnd+2 : len(head)-2]
	if len(start) > syntrahttp.MaxStartLine || len(start)+len(rest)+2 > syntrahttp.MaxHeaders {
		return ordered.ErrProtocol
	}
	var scratch [syntrahttp.MaxHeaders]byte
	wire := scratch[:0]
	defer clear(scratch[:])
	wire = append(wire, start...)
	wire = append(wire, rest...)
	wire, err = c.proxy.AppendForwardAuthorization(wire)
	if err != nil {
		return err
	}
	if len(wire)+2 > len(scratch) {
		return ordered.ErrProtocol
	}
	wire = append(wire, '\r', '\n')
	if err := stream.WriteAll(c.Conn, wire); err != nil {
		return err
	}
	clear(head)
	c.used = 0
	c.remaining = parsed.BodyLen
	return nil
}
