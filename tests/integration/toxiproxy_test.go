package integration_test

import (
	"context"
	"testing"
	"time"

	toxi "github.com/Shopify/toxiproxy/v2/client"
	tctoxi "github.com/testcontainers/testcontainers-go/modules/toxiproxy"
	"github.com/testcontainers/testcontainers-go/network"
	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/tests/integration/internal/fixture"
)

func (s *suite) testProxy(t *testing.T, upstream *peer) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c, err := tctoxi.Run(ctx, s.proxyImage,
		tctoxi.WithProxy("peer", upstream.alias+":8080"),
		network.WithNetwork([]string{"toxi-" + upstream.alias}, s.network),
	)
	if c != nil && c.Container != nil {
		cleanupContainer(t, c)
	}
	if err != nil {
		t.Fatal(err)
	}
	control := "http://" + mappedAddress(t, ctx, c, tctoxi.ControlPort)
	api := toxi.NewClient(control)
	proxy, err := api.Proxy("peer")
	if err != nil {
		t.Fatal(err)
	}
	// The control API is infrastructure only; all protocol RPCs remain SC1
	// TCP/WS/WSS through the proxy on its random mapped data port.
	p := *upstream
	p.address = mappedAddress(t, ctx, c, "8666/tcp")
	for _, fault := range []string{"stall", "reset"} {
		t.Run(fault, func(t *testing.T) {
			session := p.connect(t)
			echo(t, session.client, []byte("before fault"))
			kind, attributes := "timeout", toxi.Attributes{"timeout": 0}
			if fault == "reset" {
				kind = "reset_peer"
			}
			if _, err := proxy.AddToxic("fault", kind, "downstream", 1, attributes); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := proxy.RemoveToxic("fault"); err != nil {
					t.Errorf("remove toxic: %v", err)
				}
			})
			callCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
			defer stop()
			start := time.Now()
			_, err := session.client.Call(callCtx, fixture.EchoMethod, []byte("fault probe"), 750)
			if time.Since(start) > operationBound {
				t.Fatal("faulted call exceeded 5s bound")
			}
			if fault == "stall" {
				wantCode(t, err, syntra.ErrorCodeDeadlineExceeded)
			} else {
				wantCode(t, err, syntra.ErrorCodeUnavailable)
			}
			session.close(t)
		})
		// Subtest cleanup removes its toxic before a fresh successful session.
		recovered := p.connect(t)
		echo(t, recovered.client, []byte("after fault removal"))
		recovered.close(t)
	}
}
