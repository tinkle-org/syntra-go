package syntra

import (
	"bytes"
	"context"
	"testing"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
)

func TestRuntimeSnapshotAnswerPreservesEarlierNotificationAdmission(t *testing.T) {
	host, connection, ctx := newWithdrawalReviewConnection(t, testHostConfig())
	const requestID = 41
	request := &RpcRequest{Method: RecoverySnapshotOffer, TimeoutMs: 5000, Payload: recoveryTestEncode(t, &pb.RecoverySnapshotOfferRequest{ProfileVersion: 1, SubscriptionHandle: []byte("subscription"), Generation: 7})}
	if _, _, fatal := connection.core.onFrame(mustMarshal(NewRequestFrame(1, requestID, request))); fatal != nil {
		t.Fatal(fatal)
	}
	if id, _, ok := connection.core.takePending(); !ok || id != requestID {
		t.Fatal("snapshot request was not admitted")
	}
	batch := recoveryTestEncode(t, recoveryNotification(&pb.RecoveryBatch{ProfileVersion: 1, SubscriptionHandle: []byte("subscription"), Generation: 7, PredecessorCheckpoint: []byte("c"), ResultCheckpoint: []byte("d"), BatchPayload: []byte("previous-phase")}))
	// There is deliberately no serve loop, wake consumer, or expiry tick to
	// flush this earlier core admission before the answer path is exercised.
	if err := connection.core.notify(batch); err != nil {
		t.Fatal(err)
	}
	probe := newWriterProbe()
	writer := newHostWriter(probe, 5*time.Second)
	connection.writer = writer
	t.Cleanup(func() { _ = writer.shutdown() })
	descriptor := recoveryTestEncode(t, &pb.RecoverySnapshotDescriptor{ProfileVersion: 1, SubscriptionHandle: []byte("subscription"), SnapshotHandle: []byte("snapshot"), BoundaryCheckpoint: []byte("snapshot-boundary"), TotalPages: 1, PageBytesMax: 32})
	if err := host.answer(ctx, probe, connection, requestID, NewSuccessResult(descriptor)); err != nil {
		t.Fatal(err)
	}
	hostWriterSignal(t, probe.entered, "first ordered Send")
	awaitHostWriterState(t, writer, func(count, _ int, _ bool) bool { return count == 2 })
	close(probe.release)
	drain, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writer.drain(drain); err != nil {
		t.Fatal(err)
	}
	first, err := UnmarshalFrame(<-probe.sent)
	if err != nil {
		t.Fatal(err)
	}
	second, err := UnmarshalFrame(<-probe.sent)
	if err != nil {
		t.Fatal(err)
	}
	if first.GetNotification() == nil || !bytes.Equal(first.GetNotification().GetPayload(), batch) {
		t.Fatalf("first frame = %v; earlier notification must precede snapshot descriptor", first)
	}
	if second.GetRequestId() != requestID || !validSuccess(second.GetResult()) || !bytes.Equal(second.GetResult().GetPayload(), descriptor) {
		t.Fatalf("second frame = %v; want snapshot descriptor result", second)
	}
	if raw, ok := connection.core.nextOutbound(); ok {
		t.Fatalf("earlier notification remained queued after descriptor: %x", raw)
	}
	select {
	case raw := <-probe.sent:
		t.Fatalf("unexpected frame after descriptor: %x", raw)
	default:
	}
}
