package network

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/tinkle-org/syntra-go/securechannel"
	syntrahttp "github.com/tinkle-org/syntra-go/transport/http"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func TestHTTPListenerAssociationCompletionEvents(t *testing.T) {
	for name, associations := range map[string]int{"idle": 0, "two_associations": 2} {
		t.Run(name, func(t *testing.T) {
			n := testNetwork(t, DefaultConfig())
			_, sc := trust(t, securechannel.HTTP)
			sc.AllowHTTPCandidate = true
			authority, err := syntrahttp.NewAuthority("localhost:443")
			if err != nil {
				t.Fatal(err)
			}
			server, err := syntrahttp.Bind(syntrahttp.ServerConfig{Address: "127.0.0.1:0", Authority: authority, Security: sc, Host: listenerConfig(sc).Host})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			t.Cleanup(func() { _ = server.Close(); _ = server.Wait(testContext(t)) })
			// Drive run synchronously after Stop so the assertion joins its entire
			// defer, not just Done publication. Admission leases can be tested
			// independently of the native association's stream handling.
			l := &HTTPListener{network: n, server: server, online: true, ctx: ctx, cancel: cancel, epoch: ctx, cancelEpoch: cancel, wake: make(chan struct{}, 1), done: make(chan struct{})}
			var releases []func()
			for i := 0; i < associations; i++ {
				budget, err := ordered.NewEstablishmentBudget(nil, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer budget.Release()
				release, err := l.admit(testContext(t), budget)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				releases = append(releases, release)
			}
			assertEvents := func(completed int) {
				t.Helper()
				n.mu.Lock()
				defer n.mu.Unlock()
				admitted, finished := 0, 0
				for _, event := range n.events {
					if event.Address != l.LocalAddr().String() {
						continue
					}
					switch event.Kind {
					case ConnectionAdmitted:
						admitted++
					case ConnectionCompleted:
						finished++
					}
				}
				if admitted != associations || finished != completed {
					t.Fatalf("admitted/completed events = %d/%d, want %d/%d", admitted, finished, associations, completed)
				}
			}
			assertEvents(0)
			var wg sync.WaitGroup
			for _, release := range releases {
				for i := 0; i < 8; i++ {
					wg.Add(1)
					go func(release func()) { defer wg.Done(); release() }(release)
				}
			}
			wg.Wait()
			assertEvents(associations)
			if l.Snapshot().Admitted != 0 || n.admission.InUse() != 0 {
				t.Fatal("association release retained admission")
			}
			l.Stop()
			l.run()
			assertEvents(associations)
		})
	}
}
