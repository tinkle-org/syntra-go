package routes

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func TestSetupConstructorsComposePreparationOnceBeforeRun(t *testing.T) {
	for _, cross := range []bool{false, true} {
		t.Run(map[bool]string{false: "homogeneous", true: "cross-carrier"}[cross], func(t *testing.T) {
			cc, sc := integrationSecurity(t, securechannel.Returning, securechannel.HTTP)
			var stage, policyCalls atomic.Int32
			host := integrationHost(&policyCalls)
			basePolicy := host.ChannelPolicy
			host.ChannelPolicy = func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
				if stage.Load() != 2 {
					return "", securechannel.ErrAuth
				}
				return basePolicy(ctx, id, credential)
			}
			origin := integrationOrigin(t, sc, nil, host)
			r := Route{Kind: HTTP, Address: netip.MustParseAddrPort(origin.Addr().String()), Authority: integrationAuthority(t)}
			cfg := configFor(r)
			cfg.Options.AttemptTimeout = 2 * time.Second
			var prepared *syntra.Client
			inputs := func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
				return cc, syntra.ClientConfig{Credential: []byte("protected-hello"), Prepare: func(c *syntra.Client) error {
					if !stage.CompareAndSwap(0, 1) {
						return securechannel.ErrConfig
					}
					prepared = c
					return nil
				}}, nil
			}
			var connector ConnectorWithSetup
			var err error
			if cross {
				connector, err = NewCrossCarrierWithSetup(cfg, CrossCarrierPolicy{[]securechannel.Carrier{securechannel.TCP, securechannel.HTTP}}, inputs)
			} else {
				connector, err = NewWithSetup(cfg, inputs)
			}
			if err != nil {
				t.Fatal(err)
			}
			// This is the supervisor's structural connector signature.
			var structural func(context.Context, *ordered.EstablishmentBudget, func(*syntra.Client) error) (*connection.Client, error) = connector
			b := newBudget(t, 3*time.Second)
			complete, err := b.DeferCompletion()
			if err != nil {
				t.Fatal(err)
			}
			client, err := structural(context.Background(), b, func(c *syntra.Client) error {
				if c != prepared || !stage.CompareAndSwap(1, 2) {
					return securechannel.ErrConfig
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if stage.Load() != 2 || prepared != client.Client || policyCalls.Load() != 1 {
				t.Fatal("preparation was not composed once before protected readiness")
			}
			if err := complete(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := client.Call(ctx, "/route.Echo/Echo", []byte("prepared"), 0); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSetupFailurePropagatesAndNeverStartsHTTPOrSelectsAgain(t *testing.T) {
	for _, failBase := range []bool{true, false} {
		t.Run(map[bool]string{true: "application", false: "supervisor"}[failBase], func(t *testing.T) {
			cc, _ := integrationSecurity(t, securechannel.Bootstrap, securechannel.HTTP)
			r := Route{Kind: HTTP, Address: localAddress(1), Authority: integrationAuthority(t)}
			later := r
			later.Address = localAddress(2)
			cfg := configFor(r, later)
			var baseCalls, setupCalls, dials, writes atomic.Int32
			cfg.Dialer = func(_ context.Context, _ string, address string) (net.Conn, error) {
				if address != r.Address.String() {
					t.Error("setup failure selected later endpoint")
				}
				dials.Add(1)
				return &countedWrites{bufferConn: &bufferConn{}, writes: &writes}, nil
			}
			connector, err := NewWithSetup(cfg, func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
				return cc, syntra.ClientConfig{Prepare: func(*syntra.Client) error {
					baseCalls.Add(1)
					if failBase {
						return securechannel.ErrAuth
					}
					return nil
				}}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			client, err := connector(context.Background(), newBudget(t, time.Second), func(*syntra.Client) error { setupCalls.Add(1); return securechannel.ErrAuth })
			if client != nil || !errors.Is(err, securechannel.ErrAuth) {
				t.Fatalf("preparation failure changed: %v", err)
			}
			if baseCalls.Load() != 1 || setupCalls.Load() != map[bool]int32{true: 0, false: 1}[failBase] || dials.Load() != 2 || writes.Load() != 0 {
				t.Fatalf("base=%d setup=%d dials=%d writes=%d", baseCalls.Load(), setupCalls.Load(), dials.Load(), writes.Load())
			}
		})
	}
}

type countedWrites struct {
	*bufferConn
	writes *atomic.Int32
}

func (c *countedWrites) Write(p []byte) (int, error) { c.writes.Add(1); return c.bufferConn.Write(p) }

func TestDeferredCompletionKeepsOriginalRawGateAfterCoreReady(t *testing.T) {
	cc, sc := integrationSecurity(t, securechannel.Bootstrap, securechannel.HTTP)
	var calls atomic.Int32
	origin := integrationOrigin(t, sc, nil, integrationHost(&calls))
	r := Route{Kind: HTTP, Address: netip.MustParseAddrPort(origin.Addr().String()), Authority: integrationAuthority(t)}
	cfg := configFor(r)
	cfg.Options.AttemptTimeout = 2 * time.Second
	connector, err := NewWithSetup(cfg, func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error) {
		return cc, syntra.ClientConfig{Credential: []byte("protected-hello")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var age atomic.Int64
	clock := securechannel.NewClockWithSource(securechannel.ElapsedFunc(func() (time.Duration, bool) { return time.Duration(age.Load()), true }))
	b, err := ordered.NewEstablishmentBudget(clock, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := b.DeferCompletion()
	if err != nil {
		t.Fatal(err)
	}
	client, err := connector(context.Background(), b, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	age.Store(int64(2 * time.Second))
	if err := b.Check(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("core Ready bypassed deferred gate: %v", err)
	}
	if err := complete(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deferred completion revived expired owner: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := client.Call(ctx, "/route.Echo/Echo", nil, 0); err == nil {
		t.Fatal("expired deferred session admitted I/O")
	}
}
