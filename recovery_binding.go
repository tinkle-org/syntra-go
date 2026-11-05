package syntra

import (
	"context"
	"errors"

	pb "github.com/tinkle-org/syntra-go/gen/syntra/v1"
)

func (c *Client) attachRecoveryInbox(inbox *RecoveryInbox) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.core == nil || c.done == nil || c.activated == nil || c.closed || c.transport != nil || c.recoveryInbox != nil {
		return recoveryInvalid()
	}
	c.recoveryInbox = inbox
	c.recoveryNegotiations = make(map[uint64]*pb.RecoveryNegotiateRequest)
	return nil
}

// These receive-path hooks run under Client.mu. Only a selected, successful
// response to an admitted negotiation enables routing, before its waiter wakes.
func (c *Client) trackRecoveryCallLocked(id uint64, method string, payload []byte) {
	if c.recoveryInbox == nil || method != RecoveryNegotiate {
		return
	}
	request := new(pb.RecoveryNegotiateRequest)
	if DecodeRecovery(payload, request) == nil {
		c.recoveryNegotiations[id] = request
	}
}

func (c *Client) observeRecoveryResultLocked(id uint64, result *RpcResult) {
	request := c.recoveryNegotiations[id]
	delete(c.recoveryNegotiations, id)
	if request == nil || result.GetError() != nil {
		return
	}
	response := new(pb.RecoveryNegotiateResponse)
	if DecodeRecovery(result.GetPayload(), response) != nil || request.Capability != RecoveryCapability || response.SelectedVersion < request.MinVersion || response.SelectedVersion > request.MaxVersion {
		c.recoveryInbox.Close()
		return
	}
	if c.recoveryInbox.Enable() == nil {
		c.recoveryEnabled = true
	}
}

// routeRecoveryNotificationLocked runs after envelope/version/phase validation
// and before the core's lossy queue. A retired attachment never falls back to
// generic notification delivery on the same connection.
func (c *Client) routeRecoveryNotificationLocked(raw []byte) (bool, error) {
	if c.recoveryInbox == nil {
		return false, nil
	}
	frame, err := UnmarshalFrame(raw)
	if err != nil || frame.GetNotification() == nil {
		return false, nil
	}
	_, closed := c.recoveryInbox.ingressState()
	if closed {
		return true, nil
	}
	if !c.recoveryEnabled {
		return false, nil
	}
	return true, c.recoveryInbox.Push(frame.GetNotification().GetPayload())
}

type recoveryHostContextKey struct{}

// WithRecoveryHostSession binds an admitted handler invocation to the session
// created from that connection's authenticated ACTIVE identity. Never populate
// this from request payloads or reuse it on another connection.
func WithRecoveryHostSession(ctx context.Context, session *RecoveryHostSession) context.Context {
	return context.WithValue(ctx, recoveryHostContextKey{}, session)
}

// RecoveryHostSessionFromContext returns the runtime-owned connection binding
// supplied to host callbacks. A source can retain this handle for connection-
// scoped Publish calls; each call still revalidates authority and session state.
func RecoveryHostSessionFromContext(ctx context.Context) (*RecoveryHostSession, bool) {
	session, ok := ctx.Value(recoveryHostContextKey{}).(*RecoveryHostSession)
	return session, ok && session != nil
}

// Handler is suitable for an explicitly configured generic Host handler. The
// caller supplies a connection-bound context and still performs normal RPC
// authorization. Unknown operations and missing bindings return Unimplemented.
func (s *RecoveryService) Handler(ctx context.Context, request *RpcRequest) (*RpcResult, error) {
	h, ok := RecoveryHostSessionFromContext(ctx)
	if !ok || h == nil || h.service != s {
		return nil, recoveryUnsupported()
	}
	return h.Handler(ctx, request)
}

// runRecoveryEgress is the runtime's managed per-connection worker.
// Its caller cancels and joins it before destroying that connection's core, and
// ends the connection on failure. Admission always targets the owning hostConn.
func (h *Host) runRecoveryEgress(ctx context.Context, connection *hostConn, session *RecoveryHostSession) (resultErr error) {
	if connection == nil || session == nil {
		return recoveryInvalid()
	}
	defer func() {
		if session.Revoked() {
			resultErr = session.Err()
		}
	}()
	ctx = WithRecoveryHostSession(ctx, session)
	for {
		payload, err := session.NextNotification(ctx)
		if err != nil {
			if recoveryTargetedEgressError(ctx, session, err) {
				continue
			}
			return recoverySanitize(err)
		}
		validation, stop := context.WithTimeout(ctx, session.service.limits.DefaultDeadline)
		admitting := false
		err = session.admitNotification(validation, payload, func() error {
			admitting = true
			h.mu.Lock()
			defer h.mu.Unlock()
			_, attached := h.conns[connection]
			valid := attached && !h.closed && !connection.closing && ctx.Err() == nil && connection.recovery == session && connection.connectionID == session.connection.ID && connection.principal == session.connection.Principal && connection.version == session.connection.Version
			if err := session.Err(); err != nil {
				return err
			}
			if !valid {
				return recoveryInvalid()
			}
			return connection.core.notify(payload)
		})
		stop()
		if err != nil {
			if !admitting && recoveryTargetedEgressError(ctx, session, err) {
				continue
			}
			return recoverySanitize(err)
		}
		select {
		case connection.wake <- struct{}{}:
		default:
		}
	}
}

func recoveryTargetedEgressError(ctx context.Context, session *RecoveryHostSession, err error) bool {
	if ctx.Err() != nil || session.Err() != nil {
		return false
	}
	return recoveryTargetedEgressCode(err)
}

func recoveryTargetedEgressCode(err error) bool {
	var rpc *RpcError
	return errors.As(err, &rpc) && (rpc.Code == ErrorCodePermissionDenied || rpc.Code == ErrorCodeFailedPrecondition)
}
