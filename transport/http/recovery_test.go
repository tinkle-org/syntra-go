package syntrahttp

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	"github.com/tinkle-org/syntra-go/transport/tlsstream"
)

// A fixed, bounded application history with two independently confirmable
// transitions. A fresh connection can resume at either issued checkpoint.
type recoverySource struct{}

func (recoverySource) Authorize(ctx context.Context, principal string, selector []byte, _ syntra.RecoveryHook) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if principal != "principal" || string(selector) != "feed" {
		return syntra.NewRpcError(syntra.ErrorCodePermissionDenied, "denied")
	}
	return nil
}
func (s recoverySource) Capture(ctx context.Context, principal string, selector []byte) (syntra.RecoveryProviderStream, error) {
	if err := s.Authorize(ctx, principal, selector, syntra.RecoveryHookSubscribe); err != nil {
		return syntra.RecoveryProviderStream{}, err
	}
	return syntra.RecoveryProviderStream{Identity: []byte("stream"), Generation: 7, Boundary: []byte("c")}, nil
}
func (recoverySource) CurrentGeneration(ctx context.Context, principal string, identity []byte) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if principal != "principal" || string(identity) != "stream" {
		return 0, syntra.NewRpcError(syntra.ErrorCodePermissionDenied, "denied")
	}
	return 7, nil
}
func (s recoverySource) ValidateIssued(ctx context.Context, principal string, stream syntra.RecoveryProviderStream, checkpoint []byte) error {
	g, err := s.CurrentGeneration(ctx, principal, stream.Identity)
	if err != nil {
		return err
	}
	if stream.Generation != g || string(stream.Boundary) != "c" {
		return syntra.NewRpcError(syntra.ErrorCodeInvalidArgument, "invalid stream")
	}
	switch string(checkpoint) {
	case "a", "b", "c":
		return nil
	}
	return syntra.NewRpcError(syntra.ErrorCodeInvalidArgument, "unknown checkpoint")
}
func (s recoverySource) Replay(ctx context.Context, principal string, stream syntra.RecoveryProviderStream, from, marker []byte, budget syntra.RecoveryPageBudget) (syntra.RecoveryProviderPage, error) {
	if err := s.ValidateIssued(ctx, principal, stream, from); err != nil {
		return syntra.RecoveryProviderPage{}, err
	}
	if budget.MaxBatches < 1 || budget.MaxEntryTotalBytes < 2 || budget.MaxEntryBytes < 2 {
		return syntra.RecoveryProviderPage{}, syntra.NewRpcError(syntra.ErrorCodeResourceExhausted, "page budget")
	}
	page := syntra.RecoveryProviderPage{}
	switch string(from) {
	case "a":
		if len(marker) != 0 {
			return page, syntra.NewRpcError(syntra.ErrorCodeInvalidArgument, "invalid marker")
		}
		page.Batches = []syntra.RecoveryStoredBatch{{Generation: 7, Predecessor: []byte("a"), Result: []byte("b"), Payload: []byte("AB")}}
		page.Result, page.Marker = []byte("b"), []byte("more")
	case "b":
		if len(marker) != 0 && string(marker) != "more" {
			return page, syntra.NewRpcError(syntra.ErrorCodeInvalidArgument, "invalid marker")
		}
		page.Batches = []syntra.RecoveryStoredBatch{{Generation: 7, Predecessor: []byte("b"), Result: []byte("c"), Payload: []byte("BC")}}
		page.Result = []byte("c")
	case "c":
		page.Result = []byte("c")
	}
	return page, nil
}
func (s recoverySource) Snapshot(ctx context.Context, principal string, stream syntra.RecoveryProviderStream) (syntra.RecoveryProviderSnapshot, error) {
	if err := s.ValidateIssued(ctx, principal, stream, []byte("c")); err != nil {
		return syntra.RecoveryProviderSnapshot{}, err
	}
	return syntra.RecoveryProviderSnapshot{Key: []byte("state"), Boundary: []byte("c"), Pages: 1, PageBytes: 4}, nil
}
func (s recoverySource) SnapshotPage(ctx context.Context, principal string, stream syntra.RecoveryProviderStream, snapshot syntra.RecoveryProviderSnapshot, index uint32) ([]byte, error) {
	if err := s.ValidateIssued(ctx, principal, stream, snapshot.Boundary); err != nil {
		return nil, err
	}
	if index != 0 || string(snapshot.Key) != "state" || snapshot.Pages != 1 || snapshot.PageBytes != 4 {
		return nil, syntra.NewRpcError(syntra.ErrorCodeInvalidArgument, "invalid page")
	}
	return []byte("ABBC"), nil
}

func TestHTTPRecoveryAttachmentNegotiationAndReconnectReplay(t *testing.T) {
	for _, carrier := range []securechannel.Carrier{securechannel.HTTP, securechannel.HTTPS} {
		t.Run(carrier.String(), func(t *testing.T) {
			cc, sc := securityConfigs(t, securechannel.Returning, carrier)
			limits := syntra.DefaultRecoveryLimits()
			service, err := syntra.NewRecoveryService(recoverySource{}, limits)
			if err != nil {
				t.Fatal(err)
			}
			host := hostConfig()
			host.Recovery = service
			var provider tlsstream.Provider
			if carrier == securechannel.HTTPS {
				provider = testProvider(t)
			}
			s := startServer(t, sc, host, provider, ServerLimits{})
			store, err := syntra.NewMemoryRecoveryStore(syntra.DefaultRecoveryStoreLimits())
			if err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(context.Background(), 8*time.Second)
			defer stop()
			scope := syntra.PersistenceScope{Principal: "principal", Stream: "feed"}
			if err = store.Commit(ctx, scope, nil, syntra.DurableRecord{Generation: 7, Checkpoint: []byte("a"), ApplicationState: []byte("initial")}); err != nil {
				t.Fatal(err)
			}
			var oldHandle []byte
			for round := 0; round < 2; round++ {
				budget, err := ordered.NewEstablishmentBudget(nil, 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				finish, err := budget.DeferCompletion()
				if err != nil {
					t.Fatal(err)
				}
				if err = finish(); !errors.Is(err, ordered.ErrOptions) {
					t.Fatal("completion preceded core readiness")
				}
				var profile *syntra.RecoveryClient
				corecfg := syntra.ClientConfig{Credential: []byte("explicit"), Prepare: func(core *syntra.Client) error {
					var e error
					profile, e = syntra.NewRecoveryClient(core, "principal", store, limits)
					return e
				}}
				client, err := Dial(ctx, netip.MustParseAddrPort(s.Addr().String()), testAuthority(t), provider, cc, corecfg, ordered.Options{Budget: budget})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				if profile == nil {
					t.Fatal("recovery was not prepared before Run")
				}
				if _, err = syntra.NewRecoveryClient(client.Client, "principal", store, limits); err == nil {
					t.Fatal("late recovery attachment accepted")
				}
				if _, err = profile.Negotiate(ctx, &pb.RecoveryNegotiateRequest{ProfileVersion: 1, MinVersion: 1, MaxVersion: 1, Capability: syntra.RecoveryCapability}); err != nil {
					t.Fatal(err)
				}
				if err = finish(); err != nil {
					t.Fatal(err)
				}
				from, want, payload := "a", "b", "AB"
				if round == 1 {
					from, want, payload = "b", "c", "BC"
				}
				sub, err := profile.Subscribe(ctx, &pb.RecoverySubscribeRequest{ProfileVersion: 1, StreamSelector: []byte("feed"), StartCheckpoint: []byte(from)}, []byte("feed"), syntra.RecoveryResumeDurable)
				if err != nil {
					t.Fatal(err)
				}
				handle := sub.Response.SubscriptionHandle
				if sub.Restored == nil || string(sub.Restored.Checkpoint) != from || bytes.Equal(oldHandle, handle) {
					t.Fatal("durable resume or fresh handle failed")
				}
				if _, err = profile.Replay(ctx, &pb.RecoveryReplayRequest{ProfileVersion: 1, SubscriptionHandle: handle, FromCheckpoint: []byte(from), MaxBatches: 1, MaxBytes: 4096}); err != nil {
					t.Fatal(err)
				}
				event, err := profile.NextEvent(ctx, handle)
				if err != nil || event.Batch == nil || string(event.Batch.BatchPayload) != payload || string(event.Batch.ResultCheckpoint) != want {
					t.Fatalf("replay event: %+v %v", event, err)
				}
				confirm := &pb.RecoveryConfirmRequest{ProfileVersion: 1, SubscriptionHandle: handle, Generation: 7, Checkpoint: []byte(want)}
				if _, err = profile.Confirm(ctx, confirm); err == nil {
					t.Fatal("confirmation preceded persistence")
				}
				state := append(append([]byte(nil), sub.Restored.ApplicationState...), event.Batch.BatchPayload...)
				if err = profile.Persist(ctx, handle, state); err != nil {
					t.Fatal(err)
				}
				if _, err = profile.Confirm(ctx, confirm); err != nil {
					t.Fatal(err)
				}
				if round == 1 {
					event, err = profile.NextEvent(ctx, handle)
					if err != nil || !event.CaughtUp {
						t.Fatalf("recovery completion: %+v %v", event, err)
					}
				}
				if dropped, bytes := client.LossTotals(); dropped != 0 || bytes != 0 {
					t.Fatal("recovery used lossy generic ingress")
				}
				select {
				case <-client.Notifications():
					t.Fatal("recovery escaped into generic notifications")
				default:
				}
				oldHandle = append([]byte(nil), handle...)
				profile.Close()
				if err = client.Close(); err != nil {
					t.Fatal(err)
				}
				awaitCondition(t, func() bool { return s.Status().Associations == 0 })
			}
			saved, err := store.Load(ctx, scope)
			if err != nil || saved == nil || string(saved.Checkpoint) != "c" || string(saved.ApplicationState) != "initialABBC" {
				t.Fatalf("recovered durable state: %+v %v", saved, err)
			}
		})
	}
}

func TestHTTPSLongPollPushWithoutRPC(t *testing.T) {
	cc, sc := securityConfigs(t, securechannel.Returning, securechannel.HTTPS)
	provider := testProvider(t)
	s := startServer(t, sc, hostConfig(), provider, ServerLimits{})
	client := connectTo(t, s, cc, provider)
	// Cross one empty long-poll response and issue a new poll, with no RPC or
	// upload since hello. TLS read timeouts must preserve the same connection.
	timer := time.NewTimer(pollHold + 150*time.Millisecond)
	defer timer.Stop()
	select {
	case <-client.Done():
		t.Fatal("idle HTTPS poll closed the client")
	case <-timer.C:
	}
	for _, payload := range []string{"after empty poll", "next push"} {
		if err := s.NotifyAll([]byte(payload)); err != nil {
			t.Fatal(err)
		}
		select {
		case n := <-client.Notifications():
			if n == nil || string(n.Payload) != payload {
				t.Fatal("wrong long-poll notification")
			}
		case <-client.Done():
			t.Fatal("HTTPS push closed client")
		case <-time.After(2 * time.Second):
			t.Fatal("HTTPS push required an RPC")
		}
	}
}

var _ syntra.RecoverySource = recoverySource{}
