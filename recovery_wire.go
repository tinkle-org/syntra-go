package syntra

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	RecoveryCapability             = "syntra.update-recovery/1"
	RecoveryProfileVersion  uint32 = 1
	RecoveryMethodPrefix           = "/syntra.v1.UpdateRecovery/"
	RecoveryNegotiate              = RecoveryMethodPrefix + "Negotiate"
	RecoverySubscribe              = RecoveryMethodPrefix + "Subscribe"
	RecoveryReplay                 = RecoveryMethodPrefix + "Replay"
	RecoveryCatchUp                = RecoveryMethodPrefix + "CatchUp"
	RecoveryConfirm                = RecoveryMethodPrefix + "Confirm"
	RecoverySnapshotConfirm        = RecoveryMethodPrefix + "SnapshotConfirm"
	RecoverySnapshotOffer          = RecoveryMethodPrefix + "SnapshotOffer"
	RecoverySnapshotFetch          = RecoveryMethodPrefix + "SnapshotFetch"
	RecoveryUnsubscribe            = RecoveryMethodPrefix + "Unsubscribe"
	RecoveryMaxPayloadBytes        = MaxFrameBytes - 128
)

type RecoveryLimits struct {
	SubscriptionsPerConnection, SubscriptionsPerPrincipal                   int
	PendingRPCsPerConnection                                                int
	QueuedBytesPerStream, QueuedBytesPerConnection, QueuedMessagesPerStream int
	ReplayBatches, ReplayBytes, SnapshotPageBytes, SnapshotPages            int
	MaxConnections, MaxConnectionsPerPrincipal, HandlesPerConnection        int
	RetainedReplyBytes, RetainedReplies, ReplyRetries                       int
	DefaultDeadline, ReplyTTL                                               time.Duration
}

func DefaultRecoveryLimits() RecoveryLimits {
	return RecoveryLimits{64, 256, 16, 262144, 1048576, 256, 64, 262144, 262144, 256,
		1024, 16, 1024, 1048576, 256, 8, 5 * time.Second, 30 * time.Second}
}

func (l RecoveryLimits) Validate() error {
	values := [][2]int{{l.SubscriptionsPerConnection, 64}, {l.SubscriptionsPerPrincipal, 256},
		{l.PendingRPCsPerConnection, 16}, {l.QueuedBytesPerStream, 262144}, {l.QueuedBytesPerConnection, 1048576},
		{l.QueuedMessagesPerStream, 4096}, {l.ReplayBatches, 64}, {l.ReplayBytes, 262144},
		{l.SnapshotPageBytes, 262144}, {l.SnapshotPages, 256}, {l.MaxConnections, 65536},
		{l.MaxConnectionsPerPrincipal, 1024}, {l.HandlesPerConnection, 65536},
		{l.RetainedReplyBytes, 16 << 20}, {l.RetainedReplies, 4096}, {l.ReplyRetries, 1024}}
	for _, v := range values {
		if v[0] < 1 || v[0] > v[1] {
			return recoveryInvalid()
		}
	}
	if l.HandlesPerConnection < l.SubscriptionsPerConnection || l.DefaultDeadline <= 0 || l.DefaultDeadline > 5*time.Second || l.ReplyTTL <= 0 || l.ReplyTTL > time.Hour {
		return recoveryInvalid()
	}
	return nil
}

func recoveryInvalid() error {
	return NewRpcError(ErrorCodeFailedPrecondition, "syntra: invalid recovery state or payload")
}
func recoveryLimit() error {
	return NewRpcError(ErrorCodeResourceExhausted, "syntra: recovery bound reached")
}
func recoveryUnsupported() error {
	return NewRpcError(ErrorCodeUnimplemented, "syntra: recovery operation unavailable")
}

func recoverySanitize(err error) error {
	if err == nil {
		return nil
	}
	code := ErrorCodeInternal
	var rpc *RpcError
	switch {
	case errors.Is(err, context.Canceled):
		code = ErrorCodeCancelled
	case errors.Is(err, context.DeadlineExceeded):
		code = ErrorCodeDeadlineExceeded
	case errors.As(err, &rpc):
		code = rpc.Code
	}
	if code < ErrorCodeCancelled || code > ErrorCodeUnauthenticated {
		code = ErrorCodeInternal
	}
	return NewRpcError(code, "syntra: recovery operation failed")
}
func recoveryOpaque(b []byte, max int, required bool) bool {
	return len(b) <= max && (!required || len(b) > 0)
}
func recoveryCP(b []byte) bool     { return recoveryOpaque(b, 4096, true) }
func recoveryHandle(b []byte) bool { return recoveryOpaque(b, 256, true) }
func recoveryASCII(b []byte) bool {
	for _, c := range b {
		if c > 127 {
			return false
		}
	}
	return true
}

// DecodeRecovery bounds fields before allocation and ignores well-formed unknown fields.
// Ordinary protobuf merge and last-value semantics apply inside profile messages.
func DecodeRecovery(data []byte, m proto.Message) error {
	if m == nil || !m.ProtoReflect().IsValid() {
		return recoveryInvalid()
	}
	if len(data) > RecoveryMaxPayloadBytes {
		return recoveryLimit()
	}
	if err := recoveryScan(data, m.ProtoReflect().Descriptor(), 0); err != nil {
		return err
	}
	if err := (proto.UnmarshalOptions{DiscardUnknown: true, RecursionLimit: 32}).Unmarshal(data, m); err != nil {
		return recoveryInvalid()
	}
	return ValidateRecovery(m)
}

func EncodeRecovery(m proto.Message) ([]byte, error) {
	if err := ValidateRecovery(m); err != nil {
		return nil, err
	}
	if proto.Size(m) > RecoveryMaxPayloadBytes {
		return nil, recoveryLimit()
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

func recoveryScan(data []byte, d protoreflect.MessageDescriptor, depth int) error {
	if depth > 32 {
		return recoveryLimit()
	}
	if d.Name() == "RecoveryBatch" && len(data) > 262144 {
		return recoveryLimit()
	}
	entries, total := 0, 0
	for len(data) > 0 {
		n, t, k := protowire.ConsumeTag(data)
		if k < 0 || n < 1 || n > protowire.MaxValidNumber {
			return recoveryInvalid()
		}
		data = data[k:]
		f := d.Fields().ByNumber(n)
		if f == nil {
			var err error
			k, err = recoverySkipUnknown(n, t, data, depth)
			if err != nil {
				return err
			}
			data = data[k:]
			continue
		}
		switch f.Kind() {
		case protoreflect.Uint32Kind, protoreflect.Uint64Kind, protoreflect.BoolKind:
			if t != protowire.VarintType {
				return recoveryInvalid()
			}
			v, z := protowire.ConsumeVarint(data)
			if z < 0 || (f.Kind() == protoreflect.Uint32Kind && v > 1<<32-1) {
				return recoveryInvalid()
			}
			data = data[z:]
		case protoreflect.BytesKind, protoreflect.StringKind, protoreflect.MessageKind:
			if t != protowire.BytesType {
				return recoveryInvalid()
			}
			b, z := protowire.ConsumeBytes(data)
			if z < 0 {
				return recoveryInvalid()
			}
			data = data[z:]
			if f.Kind() == protoreflect.MessageKind {
				if err := recoveryScan(b, f.Message(), depth+1); err != nil {
					return err
				}
				continue
			}
			max := 4096
			switch f.Name() {
			case "stream_selector":
				max = 1024
			case "capability", "subscription_handle", "snapshot_handle", "terminate_reason":
				max = 256
			case "batch_payload", "batch_payloads", "page_bytes":
				max = 262144
			}
			if len(b) > max {
				return recoveryLimit()
			}
			if f.Kind() == protoreflect.StringKind && !recoveryASCII(b) {
				return recoveryInvalid()
			}
			if f.Name() == "batch_payloads" {
				entries++
				total += len(b)
				if entries > 64 || total > 262144 {
					return recoveryLimit()
				}
				if err := recoveryScan(b, (&pb.RecoveryBatch{}).ProtoReflect().Descriptor(), depth+1); err != nil {
					return err
				}
			}
		default:
			return recoveryInvalid()
		}
	}
	return nil
}

func recoverySkipUnknown(number protowire.Number, typ protowire.Type, data []byte, depth int) (int, error) {
	if depth >= 32 {
		return 0, recoveryLimit()
	}
	if typ != protowire.StartGroupType {
		if typ == protowire.EndGroupType {
			return 0, recoveryInvalid()
		}
		n := protowire.ConsumeFieldValue(number, typ, data)
		if n < 0 {
			return 0, recoveryInvalid()
		}
		return n, nil
	}
	position := 0
	for position < len(data) {
		numberIn, typIn, n := protowire.ConsumeTag(data[position:])
		if n < 0 || numberIn < 1 || numberIn > protowire.MaxValidNumber {
			return 0, recoveryInvalid()
		}
		position += n
		if typIn == protowire.EndGroupType {
			if numberIn != number {
				return 0, recoveryInvalid()
			}
			return position, nil
		}
		n, err := recoverySkipUnknown(numberIn, typIn, data[position:], depth+1)
		if err != nil {
			return 0, err
		}
		position += n
	}
	return 0, recoveryInvalid()
}

// ValidateRecovery validates defined fields; unknown protobuf fields confer no authority.
func ValidateRecovery(m proto.Message) error {
	if m == nil || !m.ProtoReflect().IsValid() {
		return recoveryInvalid()
	}
	r := m.ProtoReflect()
	f := r.Descriptor().Fields().ByName("profile_version")
	if f == nil || r.Get(f).Uint() != 1 {
		return recoveryInvalid()
	}
	ok := false
	switch v := m.(type) {
	case *pb.RecoveryNegotiateRequest:
		ok = v.MinVersion > 0 && v.MaxVersion >= v.MinVersion && len(v.Capability) > 0 && len(v.Capability) <= 256 && recoveryASCII([]byte(v.Capability))
	case *pb.RecoveryNegotiateResponse:
		ok = v.SelectedVersion == 1 && v.MaxSubscriptionsPerConnection > 0 && v.MaxSubscriptionsPerConnection <= 64 && v.MaxPendingRpcsPerConnection > 0 && v.MaxPendingRpcsPerConnection <= 16 && v.MaxPageBytes > 0 && v.MaxPageBytes <= 262144 && v.MaxSnapshotPages > 0 && v.MaxSnapshotPages <= 256
	case *pb.RecoverySubscribeRequest:
		ok = recoveryOpaque(v.StreamSelector, 1024, true) && recoveryOpaque(v.StartCheckpoint, 4096, false)
	case *pb.RecoverySubscribeResponse:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0 && recoveryCP(v.CatchupBoundary)
	case *pb.RecoveryReplayRequest:
		ok = recoveryHandle(v.SubscriptionHandle) && recoveryCP(v.FromCheckpoint) && v.MaxBatches > 0 && v.MaxBatches <= 64 && v.MaxBytes > 0 && v.MaxBytes <= 262144 && recoveryOpaque(v.ContinuationMarker, 4096, false)
	case *pb.RecoveryReplayPage:
		ok = recoveryHandle(v.SubscriptionHandle) && recoveryCP(v.PredecessorCheckpoint) && recoveryCP(v.ResultCheckpoint) && recoveryCP(v.CatchupBoundary) && recoveryOpaque(v.ContinuationMarker, 4096, false) && len(v.BatchPayloads) <= 64
		cursor := v.PredecessorCheckpoint
		total := 0
		var gen uint64
		for _, entry := range v.BatchPayloads {
			total += len(entry)
			if len(entry) > 262144 || total > 262144 {
				return recoveryLimit()
			}
			b := new(pb.RecoveryBatch)
			if err := DecodeRecovery(entry, b); err != nil {
				return err
			}
			if !bytes.Equal(b.SubscriptionHandle, v.SubscriptionHandle) || !bytes.Equal(b.PredecessorCheckpoint, cursor) || (gen != 0 && b.Generation != gen) {
				return recoveryInvalid()
			}
			cursor = b.ResultCheckpoint
			gen = b.Generation
		}
		ok = ok && bytes.Equal(cursor, v.ResultCheckpoint) && ((len(v.ContinuationMarker) == 0) == bytes.Equal(v.ResultCheckpoint, v.CatchupBoundary))
	case *pb.RecoveryReplayComplete:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0 && recoveryCP(v.LiveBoundaryCheckpoint)
	case *pb.RecoveryCatchUpRequest:
		ok = recoveryHandle(v.SubscriptionHandle)
	case *pb.RecoveryCatchUpAccepted:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0 && recoveryCP(v.CatchupBoundary)
	case *pb.RecoverySnapshotOfferRequest:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0
	case *pb.RecoverySnapshotDescriptor:
		ok = recoveryHandle(v.SubscriptionHandle) && recoveryHandle(v.SnapshotHandle) && recoveryCP(v.BoundaryCheckpoint) && v.TotalPages > 0 && v.TotalPages <= 256 && v.PageBytesMax > 0 && v.PageBytesMax <= 262144
	case *pb.RecoverySnapshotFetchRequest:
		ok = recoveryHandle(v.SnapshotHandle) && v.PageIndex < 256
	case *pb.RecoverySnapshotChunk:
		ok = recoveryHandle(v.SnapshotHandle) && v.PageIndex < 256 && recoveryCP(v.BoundaryCheckpoint) && recoveryOpaque(v.PageBytes, 262144, true)
	case *pb.RecoverySnapshotComplete:
		ok = recoveryHandle(v.SnapshotHandle) && recoveryCP(v.BoundaryCheckpoint) && v.TotalPages > 0 && v.TotalPages <= 256 && v.TotalBytes > 0 && v.TotalBytes <= 67108864
	case *pb.RecoveryConfirmRequest:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0 && recoveryCP(v.Checkpoint)
	case *pb.RecoveryConfirmResponse:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0 && recoveryCP(v.ConfirmedCheckpoint)
	case *pb.RecoverySnapshotConfirmRequest:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0 && recoveryCP(v.BoundaryCheckpoint)
	case *pb.RecoverySnapshotInstalled:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0 && recoveryCP(v.BoundaryCheckpoint)
	case *pb.RecoveryUnsubscribeRequest:
		ok = recoveryHandle(v.SubscriptionHandle)
	case *pb.RecoveryUnsubscribeResponse:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0
	case *pb.RecoveryBatch:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0 && recoveryOpaque(v.PredecessorCheckpoint, 4096, false) && recoveryCP(v.ResultCheckpoint) && proto.Size(v) <= 262144
	case *pb.RecoveryBatchTrailer:
		ok = recoveryHandle(v.SubscriptionHandle) && v.Generation > 0 && recoveryOpaque(v.BoundaryCheckpoint, 4096, false)
		switch o := v.Outcome.(type) {
		case *pb.RecoveryBatchTrailer_NextGeneration:
			ok = ok && o.NextGeneration > v.Generation && len(v.TerminateReason) == 0
		case *pb.RecoveryBatchTrailer_CatchupComplete:
			ok = ok && o.CatchupComplete && recoveryCP(v.BoundaryCheckpoint) && len(v.TerminateReason) == 0
		case *pb.RecoveryBatchTrailer_SnapshotRequired:
			ok = ok && o.SnapshotRequired && len(v.TerminateReason) == 0
		case *pb.RecoveryBatchTrailer_Terminated:
			ok = ok && o.Terminated && recoveryOpaque(v.TerminateReason, 256, true) && recoveryASCII(v.TerminateReason)
		default:
			ok = false
		}
	case *pb.RecoveryNotification:
		switch o := v.Notification.(type) {
		case *pb.RecoveryNotification_Batch:
			return ValidateRecovery(o.Batch)
		case *pb.RecoveryNotification_ReplayComplete:
			return ValidateRecovery(o.ReplayComplete)
		case *pb.RecoveryNotification_Trailer:
			return ValidateRecovery(o.Trailer)
		default:
			return recoveryInvalid()
		}
	default:
		return recoveryUnsupported()
	}
	if !ok {
		return recoveryInvalid()
	}
	return nil
}

func IsRecoveryMethod(method string) bool { return strings.HasPrefix(method, RecoveryMethodPrefix) }

func recoveryRequest(method string) proto.Message {
	switch method {
	case RecoveryNegotiate:
		return new(pb.RecoveryNegotiateRequest)
	case RecoverySubscribe:
		return new(pb.RecoverySubscribeRequest)
	case RecoveryReplay:
		return new(pb.RecoveryReplayRequest)
	case RecoveryCatchUp:
		return new(pb.RecoveryCatchUpRequest)
	case RecoveryConfirm:
		return new(pb.RecoveryConfirmRequest)
	case RecoverySnapshotConfirm:
		return new(pb.RecoverySnapshotConfirmRequest)
	case RecoverySnapshotOffer:
		return new(pb.RecoverySnapshotOfferRequest)
	case RecoverySnapshotFetch:
		return new(pb.RecoverySnapshotFetchRequest)
	case RecoveryUnsubscribe:
		return new(pb.RecoveryUnsubscribeRequest)
	}
	return nil
}

func recoveryIdentity(n *pb.RecoveryNotification) ([]byte, uint64) {
	switch o := n.Notification.(type) {
	case *pb.RecoveryNotification_Batch:
		return o.Batch.SubscriptionHandle, o.Batch.Generation
	case *pb.RecoveryNotification_ReplayComplete:
		return o.ReplayComplete.SubscriptionHandle, o.ReplayComplete.Generation
	case *pb.RecoveryNotification_Trailer:
		return o.Trailer.SubscriptionHandle, o.Trailer.Generation
	}
	return nil, 0
}

func recoveryNotification(m proto.Message) *pb.RecoveryNotification {
	n := &pb.RecoveryNotification{ProfileVersion: 1}
	switch v := m.(type) {
	case *pb.RecoveryBatch:
		n.Notification = &pb.RecoveryNotification_Batch{Batch: v}
	case *pb.RecoveryReplayComplete:
		n.Notification = &pb.RecoveryNotification_ReplayComplete{ReplayComplete: v}
	case *pb.RecoveryBatchTrailer:
		n.Notification = &pb.RecoveryNotification_Trailer{Trailer: v}
	}
	return n
}
