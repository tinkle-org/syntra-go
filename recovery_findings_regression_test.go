package syntra

import (
	"bytes"
	"context"
	"errors"
	"testing"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/proto"
)

func TestRecoveryFindingsPublishCheckFailures(t *testing.T) {
	for _, site := range []struct {
		name  string
		check int
	}{{"before-issued-validation", 1}, {"after-issued-validation", 2}} {
		t.Run(site.name, func(t *testing.T) {
			for _, scenario := range []string{"generation-retirement", "local-auth-retirement", "nonretirement-error", "revocation", "canceled-retirement"} {
				t.Run(scenario, func(t *testing.T) {
					base := newRecoveryTestSource()
					source := &recoveryReviewSource{recoveryTestSource: base}
					h := recoveryReviewHost(t, source)
					old := recoveryTestSubscribeHost(t, h, "")
					if scenario == "generation-retirement" {
						base.generation = 8
					}
					healthy := recoveryTestSubscribeHost(t, h, "")
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					failure := NewRpcError(ErrorCodePermissionDenied, "local authorization ended")
					if scenario == "nonretirement-error" {
						failure = NewRpcError(ErrorCodeUnavailable, "generation lookup failed")
					} else if scenario == "revocation" {
						failure = NewRpcError(ErrorCodeUnauthenticated, "principal withdrawn")
					}
					checks, validations := 0, 0
					source.authorize = func(_ context.Context, _ string, _ []byte, hook RecoveryHook) error {
						if hook != RecoveryHookEmit {
							t.Fatalf("unexpected authorization hook %q", hook)
						}
						checks++
						if checks == site.check {
							switch scenario {
							case "local-auth-retirement", "revocation":
								return failure
							case "canceled-retirement":
								cancel()
								return failure
							}
						}
						return nil
					}
					source.generation = func(context.Context, string, []byte) (uint64, error) {
						if checks == site.check && scenario == "nonretirement-error" {
							return 0, failure
						}
						if scenario == "generation-retirement" && checks >= site.check {
							return 8, nil
						}
						return 7, nil
					}
					// The new generation can issue d while an old-generation handle
					// is still waiting for its retirement check.
					source.validate = func(_ context.Context, p string, stream RecoveryProviderStream, cp []byte) error {
						validations++
						if p != "alice" || string(stream.Identity) != "stable" || string(cp) != "d" || (stream.Generation != 7 && stream.Generation != 8) {
							t.Fatal("unexpected issued-checkpoint validation")
						}
						return nil
					}
					batch := RecoveryStoredBatch{healthy.Generation, []byte("c"), []byte("d"), []byte("CD")}
					err := h.Publish(ctx, []byte("stable"), batch)
					continues := scenario == "generation-retirement" || scenario == "local-auth-retirement"
					if continues {
						if err != nil {
							t.Errorf("slot-local retirement stopped publication: %v", err)
						}
					} else if scenario == "revocation" {
						if !h.Revoked() || recoveryErrorCode(err) != ErrorCodeUnauthenticated {
							t.Errorf("principal withdrawal lost: revoked=%v, err=%v", h.Revoked(), err)
						}
					} else if !errors.Is(err, failure) {
						t.Errorf("Publish error = %v, want original %v", err, failure)
					}
					oldSlot, healthySlot := h.slots[string(old.SubscriptionHandle)], h.slots[string(healthy.SubscriptionHandle)]
					if oldSlot.retired != (scenario != "nonretirement-error") || len(oldSlot.held) != 0 || string(oldSlot.liveTail) != "c" {
						t.Error("failed check changed old slot delivery or retirement state")
					}
					if scenario == "generation-retirement" && oldSlot.terminal.GetTrailer().GetNextGeneration() != 8 {
						t.Error("old generation lost its next-generation control")
					}
					if healthySlot.retired {
						t.Error("healthy slot retired")
					}
					if continues {
						if len(healthySlot.held) != 1 || string(healthySlot.liveTail) != "d" {
							t.Error("healthy same-identity slot did not receive publication")
						} else if got := healthySlot.held[0].GetBatch(); got.Generation != healthy.Generation || !bytes.Equal(got.BatchPayload, batch.Payload) || !bytes.Equal(got.SubscriptionHandle, healthy.SubscriptionHandle) {
							t.Error("healthy slot received wrong batch")
						}
						if h.Revoked() {
							t.Error("slot-local retirement revoked connection")
						}
					} else if len(healthySlot.held) != 0 || string(healthySlot.liveTail) != "c" || checks != site.check {
						t.Error("fatal check failure continued fanout")
					}
					wantValidations := site.check - 1
					if continues {
						wantValidations++
					}
					if validations != wantValidations {
						t.Errorf("issued validations = %d, want %d", validations, wantValidations)
					}
				})
			}
		})
	}
}

func TestRecoveryFindingsInboxAdmissionLimits(t *testing.T) {
	for _, replay := range []bool{false, true} {
		name := "live"
		if replay {
			name = "replay"
		}
		t.Run(name, func(t *testing.T) {
			small := &pb.RecoveryBatch{ProfileVersion: 1, SubscriptionHandle: []byte("a"), Generation: 7, ResultCheckpoint: []byte("d"), BatchPayload: []byte("CD")}
			maximum := proto.Clone(small).(*pb.RecoveryBatch)
			maximum.BatchPayload = make([]byte, 262144)
			maximum.BatchPayload = maximum.BatchPayload[:len(maximum.BatchPayload)-(proto.Size(maximum)-262144)]
			if proto.Size(maximum) != 262144 {
				t.Fatal("fixture is not an exactly maximum-size batch")
			}
			accounted := func(b *pb.RecoveryBatch) int {
				if replay {
					return len(recoveryTestEncode(t, b)) + 32
				}
				return len(recoveryTestEncode(t, recoveryNotification(b))) + 32
			}
			smallSize, maxSize := accounted(small), accounted(maximum)
			for _, tc := range []struct {
				name                                   string
				seed, lease, other, release, maximum   bool
				streamBytes, connectionBytes, messages int
				overflow                               bool
			}{
				{name: "first-maximum", maximum: true},
				{name: "queued-stream-bytes", seed: true, streamBytes: 2*smallSize - 1, overflow: true},
				{name: "leased-stream-bytes", seed: true, lease: true, streamBytes: 2*smallSize - 1, overflow: true},
				{name: "nonempty-stream-maximum", seed: true, maximum: true, overflow: true},
				{name: "leased-stream-maximum", seed: true, lease: true, maximum: true, overflow: true},
				{name: "stream-exact-cap", seed: true, streamBytes: 2 * smallSize},
				{name: "first-maximum-connection-cap", maximum: true, connectionBytes: maxSize - 1, overflow: true},
				{name: "queued-connection-cap", seed: true, other: true, maximum: true, connectionBytes: smallSize + maxSize - 1, overflow: true},
				{name: "leased-connection-cap", seed: true, lease: true, other: true, maximum: true, connectionBytes: smallSize + maxSize - 1, overflow: true},
				{name: "connection-exact-cap", seed: true, other: true, connectionBytes: 2 * smallSize},
				{name: "queued-message-cap", seed: true, messages: 1, overflow: true},
				{name: "leased-message-cap", seed: true, lease: true, messages: 1, overflow: true},
				{name: "released-stream-is-empty", seed: true, lease: true, release: true, maximum: true, messages: 1},
			} {
				t.Run(tc.name, func(t *testing.T) {
					limits := DefaultRecoveryLimits()
					if tc.streamBytes != 0 {
						limits.QueuedBytesPerStream = tc.streamBytes
					}
					if tc.connectionBytes != 0 {
						limits.QueuedBytesPerConnection = tc.connectionBytes
					}
					if tc.messages != 0 {
						limits.QueuedMessagesPerStream = tc.messages
					}
					inbox, err := NewRecoveryInbox(limits)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(inbox.Close)
					if err := inbox.Enable(); err != nil {
						t.Fatal(err)
					}
					for _, handle := range []string{"a", "b"} {
						if err := inbox.begin(); err != nil {
							t.Fatal(err)
						}
						if err := inbox.register([]byte(handle), 7, handle); err != nil {
							t.Fatal(err)
						}
					}
					push := func(b *pb.RecoveryBatch) {
						t.Helper()
						var err error
						if replay {
							err = inbox.pushReplay(&pb.RecoveryReplayPage{BatchPayloads: [][]byte{recoveryTestEncode(t, b)}})
						} else {
							err = inbox.Push(recoveryTestEncode(t, recoveryNotification(b)))
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					seedHandle := []byte("a")
					if tc.other {
						seedHandle = []byte("b")
					}
					if tc.seed {
						seed := proto.Clone(small).(*pb.RecoveryBatch)
						seed.SubscriptionHandle = seedHandle
						push(seed)
						if tc.lease {
							n, _, err := inbox.tryPop(seedHandle, true, false)
							if err != nil || !proto.Equal(n.GetBatch(), seed) {
								t.Fatalf("seed lease = %v, %v", n, err)
							}
						}
						if tc.release {
							inbox.release(seedHandle)
						}
					}
					batch := small
					if tc.maximum {
						batch = maximum
					}
					push(batch)
					n, _, err := inbox.tryPop([]byte("a"), true, false)
					if err != nil {
						t.Fatal(err)
					}
					if tc.overflow {
						trailer := n.GetTrailer()
						if !trailer.GetTerminated() || string(trailer.GetTerminateReason()) != "local-queue-exhausted" || string(trailer.GetSubscriptionHandle()) != "a" || trailer.GetGeneration() != 7 {
							t.Fatal("limit did not produce target-local overflow control")
						}
					} else if !proto.Equal(n.GetBatch(), batch) {
						t.Fatal("valid batch was not admitted")
					}
					wantBytes := accounted(batch)
					if tc.overflow {
						wantBytes = 0
					}
					if tc.seed && !tc.release && (!tc.overflow || tc.other) {
						wantBytes += smallSize
					}
					if got := inbox.Counts().DataBytes; got != wantBytes {
						t.Errorf("retained bytes including leases = %d, want %d", got, wantBytes)
					}
					if tc.other {
						if _, active := inbox.status(seedHandle); !active {
							t.Error("connection overflow damaged other stream")
						}
					}
				})
			}
		})
	}
}

type recoveryFindingsCloseTransport struct {
	Transport
	closes int
	err    error
}

func (t *recoveryFindingsCloseTransport) Close() error {
	t.closes++
	return t.err
}

func TestRecoveryFindingsIngressCloseForwarding(t *testing.T) {
	failure := errors.New("underlying close failed")
	for _, tc := range []struct {
		name  string
		inbox bool
		err   error
	}{
		{"nil-inbox-success", false, nil},
		{"nil-inbox-error", false, failure},
		{"inbox-success", true, nil},
		{"inbox-error", true, failure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var inbox *RecoveryInbox
			if tc.inbox {
				var err error
				inbox, err = NewRecoveryInbox(DefaultRecoveryLimits())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(inbox.Close)
			}
			underlying := &recoveryFindingsCloseTransport{err: tc.err}
			wrapped := WrapRecoveryTransport(underlying, nil, inbox)
			// Recover here so both nil-inbox cases report failures and forwarding
			// assertions still run on the unfixed baseline.
			var got error
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Errorf("Close panicked: %v", p)
					}
				}()
				got = wrapped.Close()
			}()
			if got != tc.err || underlying.closes != 1 {
				t.Errorf("Close = %v, calls = %d; want %v, 1", got, underlying.closes, tc.err)
			}
			if inbox != nil {
				if _, closed := inbox.ingressState(); !closed {
					t.Error("Close left inbox open")
				}
			}
		})
	}
}
