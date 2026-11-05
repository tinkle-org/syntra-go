package syntra

import (
	"context"
	"errors"
)

// Revoked is sticky for this authenticated connection, including after Close.
// Runtime dispatch must inspect it independently of a selected RPC deadline.
func (h *RecoveryHostSession) Revoked() bool { return h.revoked.Load() }

// Err reports principal withdrawal before ordinary connection shutdown.
func (h *RecoveryHostSession) Err() error {
	if h.Revoked() {
		return NewRpcError(ErrorCodeUnauthenticated, "syntra: recovery principal withdrawn")
	}
	if h.closed.Load() {
		return NewRpcError(ErrorCodeUnavailable, "syntra: recovery connection closed")
	}
	return nil
}

func (s *RecoveryService) observeSource(principal string, err error) {
	var rpc *RpcError
	if !errors.As(err, &rpc) || rpc.Code != ErrorCodeUnauthenticated {
		return
	}
	// Never wait for a callback gate here: another connection may be inside a
	// provider callback. Atomics fence its next exposure and wake idle egress.
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, session := range s.sessions {
		if session.connection.Principal == principal {
			if !session.revoked.Swap(true) {
				close(session.revokedDone)
			}
			session.signal()
		}
	}
}

// Observe at the callback boundary, before deadlines or targeted controls can
// replace the original failure. Every source operation shares this policy.
type recoveryObservedSource struct {
	source  RecoverySource
	service *RecoveryService
}

func (s *recoveryObservedSource) Authorize(ctx context.Context, p string, selector []byte, hook RecoveryHook) error {
	err := s.source.Authorize(ctx, p, selector, hook)
	s.service.observeSource(p, err)
	return err
}
func (s *recoveryObservedSource) Capture(ctx context.Context, p string, selector []byte) (RecoveryProviderStream, error) {
	v, err := s.source.Capture(ctx, p, selector)
	s.service.observeSource(p, err)
	return v, err
}
func (s *recoveryObservedSource) CurrentGeneration(ctx context.Context, p string, identity []byte) (uint64, error) {
	v, err := s.source.CurrentGeneration(ctx, p, identity)
	s.service.observeSource(p, err)
	return v, err
}
func (s *recoveryObservedSource) ValidateIssued(ctx context.Context, p string, stream RecoveryProviderStream, checkpoint []byte) error {
	err := s.source.ValidateIssued(ctx, p, stream, checkpoint)
	s.service.observeSource(p, err)
	return err
}
func (s *recoveryObservedSource) Replay(ctx context.Context, p string, stream RecoveryProviderStream, from, marker []byte, budget RecoveryPageBudget) (RecoveryProviderPage, error) {
	v, err := s.source.Replay(ctx, p, stream, from, marker, budget)
	s.service.observeSource(p, err)
	return v, err
}
func (s *recoveryObservedSource) Snapshot(ctx context.Context, p string, stream RecoveryProviderStream) (RecoveryProviderSnapshot, error) {
	v, err := s.source.Snapshot(ctx, p, stream)
	s.service.observeSource(p, err)
	return v, err
}
func (s *recoveryObservedSource) SnapshotPage(ctx context.Context, p string, stream RecoveryProviderStream, snapshot RecoveryProviderSnapshot, index uint32) ([]byte, error) {
	v, err := s.source.SnapshotPage(ctx, p, stream, snapshot, index)
	s.service.observeSource(p, err)
	return v, err
}
