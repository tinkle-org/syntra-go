package syntra

import (
	"bytes"
	"context"
	"errors"
	"sync"
)

// PersistenceScope binds state to the application's principal namespace and stable stream.
// These labels are not authentication credentials.
type PersistenceScope struct{ Principal, Stream string }

func (s PersistenceScope) String() string   { return "PersistenceScope([REDACTED])" }
func (s PersistenceScope) GoString() string { return s.String() }
func (s PersistenceScope) validate() error {
	if len(s.Principal) == 0 || len(s.Stream) == 0 {
		return PersistenceCorrupt
	}
	if len(s.Principal) > 1024 || len(s.Stream) > 1024 {
		return PersistenceOverLimit
	}
	return nil
}

type DurableRecord struct {
	Generation                   uint64
	Checkpoint, ApplicationState []byte
}
type ExpectedPosition struct {
	Generation uint64
	Checkpoint []byte
}

func (r DurableRecord) String() string      { return "DurableRecord([REDACTED])" }
func (r DurableRecord) GoString() string    { return r.String() }
func (r ExpectedPosition) String() string   { return "ExpectedPosition([REDACTED])" }
func (r ExpectedPosition) GoString() string { return r.String() }
func (r DurableRecord) Position() *ExpectedPosition {
	return &ExpectedPosition{r.Generation, bytes.Clone(r.Checkpoint)}
}
func cloneRecoveryRecord(r DurableRecord) DurableRecord {
	return DurableRecord{r.Generation, bytes.Clone(r.Checkpoint), bytes.Clone(r.ApplicationState)}
}

type PersistenceError uint8

const (
	PersistenceUnavailable PersistenceError = iota + 1
	PersistenceCorrupt
	PersistenceConflict
	PersistenceOverLimit
)

func (e PersistenceError) Error() string {
	switch e {
	case PersistenceUnavailable:
		return "syntra: recovery persistence unavailable"
	case PersistenceCorrupt:
		return "syntra: corrupt recovery persistence"
	case PersistenceConflict:
		return "syntra: recovery persistence conflict"
	case PersistenceOverLimit:
		return "syntra: recovery persistence bound reached"
	}
	return "syntra: recovery persistence failure"
}

func (e PersistenceError) Code() ErrorCode {
	switch e {
	case PersistenceUnavailable:
		return ErrorCodeUnavailable
	case PersistenceCorrupt:
		return ErrorCodeDataLoss
	case PersistenceConflict:
		return ErrorCodeAborted
	case PersistenceOverLimit:
		return ErrorCodeResourceExhausted
	default:
		return ErrorCodeInternal
	}
}

// CommitUnknown means a write may have become durable. Reload and reconcile on a
// fresh connection; neither confirm nor blindly retry the application write.
type CommitUnknown struct{}

func (*CommitUnknown) Error() string {
	return "syntra: recovery commit outcome unknown; reconciliation required"
}
func (*CommitUnknown) Code() ErrorCode { return ErrorCodeUnknown }

// RecoveryPersistence commits the FULL opaque state and its scoped position as one
// application persistence point. Nil expected requires absence. Exact full-record
// duplicates are no-ops even with a stale expected position. A cancelled commit
// that may have taken effect must return *CommitUnknown rather than rollback evidence.
type RecoveryPersistence interface {
	Load(context.Context, PersistenceScope) (*DurableRecord, error)
	Commit(context.Context, PersistenceScope, *ExpectedPosition, DurableRecord) error
}

type RecoveryStoreLimits struct{ MaxRecords, MaxStateBytes, MaxTotalBytes int }

func DefaultRecoveryStoreLimits() RecoveryStoreLimits {
	return RecoveryStoreLimits{256, 64 << 20, 256 << 20}
}

// MemoryRecoveryStore is a bounded, concurrency-safe reference. It is NOT durable.
type MemoryRecoveryStore struct {
	mu       sync.Mutex
	limits   RecoveryStoreLimits
	records  map[PersistenceScope]DurableRecord
	total    int
	failNext bool
}

func NewMemoryRecoveryStore(l RecoveryStoreLimits) (*MemoryRecoveryStore, error) {
	if l.MaxRecords < 1 || l.MaxStateBytes < 1 || l.MaxTotalBytes < 1 || l.MaxStateBytes > int(^uint(0)>>1)-6224 {
		return nil, PersistenceOverLimit
	}
	return &MemoryRecoveryStore{limits: l, records: make(map[PersistenceScope]DurableRecord)}, nil
}
func (s *MemoryRecoveryStore) FailNextCommit() { s.mu.Lock(); s.failNext = true; s.mu.Unlock() }
func (s *MemoryRecoveryStore) Load(ctx context.Context, scope PersistenceScope) (*DurableRecord, error) {
	if err := scope.validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.records[scope]
	if !ok {
		return nil, nil
	}
	r = cloneRecoveryRecord(r)
	return &r, nil
}
func recoveryRecordBytes(scope PersistenceScope, r DurableRecord) int {
	return 80 + len(scope.Principal) + len(scope.Stream) + len(r.Checkpoint) + len(r.ApplicationState)
}
func (s *MemoryRecoveryStore) Commit(ctx context.Context, scope PersistenceScope, expected *ExpectedPosition, r DurableRecord) error {
	if err := scope.validate(); err != nil {
		return err
	}
	if r.Generation == 0 || len(r.Checkpoint) == 0 {
		return PersistenceCorrupt
	}
	if len(r.Checkpoint) > 4096 || len(r.ApplicationState) > s.limits.MaxStateBytes {
		return PersistenceOverLimit
	}
	if expected != nil {
		if expected.Generation == 0 || len(expected.Checkpoint) == 0 {
			return PersistenceCorrupt
		}
		if len(expected.Checkpoint) > 4096 {
			return PersistenceOverLimit
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.records[scope]
	if exists && old.Generation == r.Generation && bytes.Equal(old.Checkpoint, r.Checkpoint) && bytes.Equal(old.ApplicationState, r.ApplicationState) {
		return nil
	}
	if exists != (expected != nil) || (exists && (old.Generation != expected.Generation || !bytes.Equal(old.Checkpoint, expected.Checkpoint))) {
		return PersistenceConflict
	}
	base := s.total
	count := len(s.records)
	if exists {
		base -= recoveryRecordBytes(scope, old)
	} else {
		count++
	}
	n := recoveryRecordBytes(scope, r)
	if count > s.limits.MaxRecords || n > s.limits.MaxTotalBytes || base > s.limits.MaxTotalBytes-n {
		return PersistenceOverLimit
	}
	if s.failNext {
		s.failNext = false
		return PersistenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.records[scope] = cloneRecoveryRecord(r)
	s.total = base + n
	return nil
}

// RecoveryProgress observations are independent: submitted does not imply received.
type RecoveryProgress struct{ LocallyDurable, ConfirmSent, PeerAcknowledged *ExpectedPosition }

func cloneRecoveryPosition(p *ExpectedPosition) *ExpectedPosition {
	if p == nil {
		return nil
	}
	return &ExpectedPosition{p.Generation, bytes.Clone(p.Checkpoint)}
}
func cloneRecoveryProgress(p RecoveryProgress) RecoveryProgress {
	return RecoveryProgress{cloneRecoveryPosition(p.LocallyDurable), cloneRecoveryPosition(p.ConfirmSent), cloneRecoveryPosition(p.PeerAcknowledged)}
}
func recoveryCommitUnknown(err error) bool {
	var unknown *CommitUnknown
	return errors.As(err, &unknown)
}
