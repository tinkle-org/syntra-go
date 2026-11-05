package connection_test

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

// recordCarrier has bounded queues and records. Close interrupts both peers
// without closing data queues that a concurrent writer might still use.
type recordCarrier struct {
	in, out  chan []byte
	done     chan struct{}
	once     *sync.Once
	closes   atomic.Int32
	reading  chan struct{}
	readOnce sync.Once
}

var _ ordered.MessageIO = (*recordCarrier)(nil)

func recordPair() (*recordCarrier, *recordCarrier) {
	a, b := make(chan []byte, 8), make(chan []byte, 8)
	done, once := make(chan struct{}), new(sync.Once)
	return &recordCarrier{in: a, out: b, done: done, once: once, reading: make(chan struct{})},
		&recordCarrier{in: b, out: a, done: done, once: once, reading: make(chan struct{})}
}

func (c *recordCarrier) ReadMessage(ctx context.Context, dst []byte) ([]byte, error) {
	c.readOnce.Do(func() { close(c.reading) })
	if err := c.check(ctx); err != nil {
		return nil, err
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, io.EOF
	case msg := <-c.in:
		if err := c.check(ctx); err != nil {
			return nil, err
		}
		if len(msg) > cap(dst) {
			return nil, ordered.ErrProtocol
		}
		return append(dst[:0], msg...), nil
	}
}

func (c *recordCarrier) WriteMessage(ctx context.Context, msg []byte) error {
	if err := c.check(ctx); err != nil {
		return err
	}
	if len(msg) > securechannel.MaxCiphertext {
		return ordered.ErrProtocol
	}
	copyOfMessage := append([]byte(nil), msg...)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return io.EOF
	case c.out <- copyOfMessage:
		return c.check(ctx)
	}
}

func (c *recordCarrier) check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-c.done:
		return io.EOF
	default:
		return nil
	}
}

func (c *recordCarrier) Close() error {
	c.closes.Add(1)
	c.once.Do(func() { close(c.done) })
	return nil
}

// Inject a trusted elapsed source so the tests also run on platforms where the
// default elapsed source is unavailable. The test process never suspends.
func testOptions() ordered.Options {
	origin := time.Now()
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) {
		return time.Since(origin), true
	}))
	budget, err := ordered.NewEstablishmentBudget(clock, 3*time.Second)
	if err != nil {
		panic(err)
	}
	return ordered.Options{Budget: budget}
}

func channelConfigs(mode securechannel.Mode) (securechannel.ClientConfig, securechannel.ServerConfig, error) {
	key, err := securechannel.GenerateStaticKey()
	if err != nil {
		return securechannel.ClientConfig{}, securechannel.ServerConfig{}, err
	}
	client := securechannel.ClientConfig{
		Context:         securechannel.Context{Mode: mode, Carrier: securechannel.TCP, Scope: "memory"},
		ServerPublicKey: key.Public(),
	}
	server := securechannel.ServerConfig{StaticKey: key, Carrier: client.Context.Carrier, Scope: "memory", AllowBootstrap: mode == securechannel.Bootstrap}
	if mode == securechannel.Returning {
		psk, err := securechannel.GenerateKey()
		if err != nil {
			return client, server, err
		}
		client.Context.Epoch, client.Context.Handle = 1, [8]byte{1}
		client.AuthorizationKey = psk
		server.Lookup = func(ctx context.Context, route securechannel.Context) (securechannel.Enrollment, error) {
			if ctx.Err() != nil || route != client.Context {
				return securechannel.Enrollment{}, errors.New("unknown enrollment")
			}
			return securechannel.Enrollment{Key: psk, Principal: "device", ExpiresAt: time.Now().Add(time.Hour)}, nil
		}
	}
	return client, server, nil
}
