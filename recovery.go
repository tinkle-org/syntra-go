package syntra

// Recovery helpers for the Go binding: durable position/effects atomicity,
// bounded duplicate suppression, staged snapshots, and independently
// scheduled bounded checkpoint reconciliation.
//
// These mirror the Rust recovery drivers (crates/syntra-runtime/src/
// recovery/{store,cache,snapshot,driver,reconcile}.rs) so both stacks share
// one contract:
//   - persist position+effects atomically, confirm only on success;
//   - answer duplicates from a bounded cache without re-applying effects;
//   - stage snapshots without interpretation and install only when complete;
//   - route batches to exactly one subscription (never NotifyAll broadcast);
//   - reconcile missing final updates on an independent schedule without
//     requiring another update (idle peers converge).

import (
	"sort"
	"sync"
	"time"
)

// Checkpoint is one independently ordered stream position: the stable
// stream identity plus its continuity generation and opaque cursors.
// Cursors are compared by equality only; the reconciler never orders,
// increments, or parses them.
type Checkpoint struct {
	// Stream is the stable stream identity (persists across reconnects).
	Stream string
	// Generation is the continuity epoch.
	Generation uint64
	// Base is the state required before applying the batch.
	Base []byte
	// Result is the state reached after applying the complete batch.
	Result []byte
}

// CommittedPosition is the last confirmed position for one stream.
type CommittedPosition struct {
	Stream     string
	Generation uint64
	Committed  []byte
}

// StoreError is a persistence failure. It never carries checkpoint bytes.
type StoreError struct {
	Code    ErrorCode
	Message string
}

func (e *StoreError) Error() string {
	if e == nil {
		return "syntra: nil StoreError"
	}
	return "syntra: " + ErrorCodeName(e.Code) + ": " + e.Message
}

// DurableStore persists positions with durable position/effects atomicity:
// StoreAtomic either records both the position and its effects digest or
// records neither and returns an error. Load returns the last atomically
// stored position.
type DurableStore interface {
	Load(stream string) *CommittedPosition
	StoreAtomic(pos CommittedPosition, effectsDigest []byte) error
}

// MemoryStore is an in-memory DurableStore for drivers, embeds, and tests.
// FailNext injects exactly one Unavailable failure on the next write;
// FailAlways fails every write until cleared.
type MemoryStore struct {
	mu         sync.Mutex
	positions  map[string]CommittedPosition
	digests    map[string][]byte
	FailNext   bool
	FailAlways bool
}

// NewMemoryStore returns an empty store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{positions: make(map[string]CommittedPosition), digests: make(map[string][]byte)}
}

// Load returns the last durably stored position for stream, or nil. The
// returned position deep-copies committed bytes so callers can never alias
// (or mutate) store state.
func (s *MemoryStore) Load(stream string) *CommittedPosition {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pos, ok := s.positions[stream]
	if !ok {
		return nil
	}
	cp := pos
	cp.Committed = append([]byte(nil), pos.Committed...)
	return &cp
}

// StoreAtomic records pos and effectsDigest atomically, or records nothing
// on injected failure. The caller must not confirm on error. Both the
// position's committed bytes and the digest are deep-copied so later caller
// mutation cannot alias durable state.
func (s *MemoryStore) StoreAtomic(pos CommittedPosition, effectsDigest []byte) error {
	if s == nil {
		return &StoreError{Code: ErrorCodeInternal, Message: "syntra: nil store"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FailAlways || s.FailNext {
		s.FailNext = false
		return &StoreError{Code: ErrorCodeUnavailable, Message: "syntra: persistence unavailable"}
	}
	digest := append([]byte(nil), effectsDigest...)
	cp := pos
	cp.Committed = append([]byte(nil), pos.Committed...)
	s.digests[pos.Stream] = digest
	s.positions[pos.Stream] = cp
	return nil
}

// DuplicateCache is a bounded FIFO cache of recently confirmed result keys.
// A hit answers a duplicate without re-applying effects; a miss goes
// through the normal persist/confirm path. Insertion beyond capacity
// evicts the oldest entry first. It never grows without bound.
type DuplicateCache struct {
	mu       sync.Mutex
	capacity int
	order    [][]byte
	set      map[string]struct{}
}

// NewDuplicateCache returns a cache holding at most capacity keys.
// Zero capacity caches nothing.
func NewDuplicateCache(capacity int) *DuplicateCache {
	return &DuplicateCache{capacity: capacity, set: make(map[string]struct{})}
}

// Contains reports whether key was recently confirmed and retained.
func (c *DuplicateCache) Contains(key []byte) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.set[string(key)]
	return ok
}

// Insert records a confirmed result. Duplicate inserts are no-ops. Beyond
// capacity the oldest entry is evicted first.
func (c *DuplicateCache) Insert(key []byte) {
	if c == nil || c.capacity <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	k := string(key)
	if _, ok := c.set[k]; ok {
		return
	}
	for len(c.order) >= c.capacity {
		old := c.order[0]
		c.order = c.order[1:]
		delete(c.set, string(old))
	}
	cp := make([]byte, len(key))
	copy(cp, key)
	c.order = append(c.order, cp)
	c.set[k] = struct{}{}
}

// Len returns entries currently retained.
func (c *DuplicateCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.set)
}

// StagedSnapshot stages bounded snapshot pages under a provider-proven
// boundary. Pages are stored without interpretation and assembled only when
// every page 0..totalPages-1 has arrived exactly once.
type StagedSnapshot struct {
	mu       sync.Mutex
	handle   []byte
	boundary []byte
	total    int
	pageMax  int
	pages    [][]byte
	filled   []bool
}

// NewStagedSnapshot begins staging totalPages pages under boundary.
// Bounds: 1 <= totalPages <= 256, 1 <= pageMax <= 262144.
func NewStagedSnapshot(handle, boundary []byte, totalPages, pageMax int) (*StagedSnapshot, error) {
	if totalPages < 1 || totalPages > 256 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: snapshot total pages out of bound")
	}
	if pageMax < 1 || pageMax > 262144 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: snapshot page bytes out of bound")
	}
	if len(boundary) == 0 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: snapshot boundary must be non-empty")
	}
	return &StagedSnapshot{
		handle:   append([]byte(nil), handle...),
		boundary: append([]byte(nil), boundary...),
		total:    totalPages,
		pageMax:  pageMax,
		pages:    make([][]byte, totalPages),
		filled:   make([]bool, totalPages),
	}, nil
}

// StagePage stores one page. Out-of-range indexes, oversized pages, and
// boundary mismatches fail. Re-staging identical bytes is idempotent;
// different bytes for the same index fail.
func (s *StagedSnapshot) StagePage(index int, bytes, boundary []byte) error {
	if s == nil {
		return NewRpcError(ErrorCodeInternal, "syntra: nil staged snapshot")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= s.total {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: snapshot page index out of range")
	}
	if string(boundary) != string(s.boundary) {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: snapshot boundary mismatch")
	}
	if len(bytes) > s.pageMax {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: snapshot page exceeds bound")
	}
	if s.filled[index] {
		if string(s.pages[index]) != string(bytes) {
			return NewRpcError(ErrorCodeInvalidArgument, "syntra: snapshot page conflict")
		}
		return nil
	}
	cp := make([]byte, len(bytes))
	copy(cp, bytes)
	s.pages[index] = cp
	s.filled[index] = true
	return nil
}

// Install assembles staged pages in order. It fails when any page is missing.
func (s *StagedSnapshot) Install() ([]byte, error) {
	if s == nil {
		return nil, NewRpcError(ErrorCodeInternal, "syntra: nil staged snapshot")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []byte
	for i := 0; i < s.total; i++ {
		if !s.filled[i] {
			return nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: snapshot incomplete")
		}
		out = append(out, s.pages[i]...)
	}
	return out, nil
}

// Boundary returns the provider-proven boundary subsequent batches chain from.
func (s *StagedSnapshot) Boundary() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.boundary...)
}

// ReconcilerConfig bounds checkpoint reconciliation.
type ReconcilerConfig struct {
	// TickInterval is the minimum interval between ticks.
	TickInterval time.Duration
	// MaxStreamsPerTick caps streams that may report per tick.
	MaxStreamsPerTick int
}

// CheckpointReconciler discovers missing final updates without requiring
// another update: on an independently scheduled tick it compares the last
// observed result against the last confirmed position and reports streams
// whose observed result differs from committed. The tick is bounded and
// idle peers converge without any new batch.
type CheckpointReconciler struct {
	mu       sync.Mutex
	config   ReconcilerConfig
	lastTick time.Time
	// Stored cursor slices are owned and immutable: NoteObserved copies
	// inputs and replaces whole entries, never mutating their backing arrays.
	observed map[string]Checkpoint
}

// NewCheckpointReconciler returns a reconciler with the given bounds.
func NewCheckpointReconciler(cfg ReconcilerConfig) *CheckpointReconciler {
	if cfg.MaxStreamsPerTick <= 0 {
		cfg.MaxStreamsPerTick = 16
	}
	return &CheckpointReconciler{config: cfg, observed: make(map[string]Checkpoint)}
}

// NoteObserved records the last observed (validated or completed)
// checkpoint for the stream, including the final batch of a stream that
// then goes idle. Base and Result bytes are deep-copied so later caller
// mutation cannot alias reconciler state.
func (r *CheckpointReconciler) NoteObserved(cp Checkpoint) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	cp.Base = append([]byte(nil), cp.Base...)
	cp.Result = append([]byte(nil), cp.Result...)
	r.observed[cp.Stream] = cp
}

// Forget stops tracking a stream.
func (r *CheckpointReconciler) Forget(stream string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.observed, stream)
}

// Tick reconciles up to MaxStreamsPerTick streams. For each tracked stream
// whose last observed generation or result differs from committed, it
// returns a needs-recovery entry keyed by stream. Streams already converged
// (same generation and byte-identical result) return nothing. The tick runs
// even when no batch arrived since the last tick. At most MaxStreamsPerTick
// entries are returned in stream order for determinism. Ticks closer than
// TickInterval are no-ops.
//
// The committed callback runs WITHOUT the reconciler lock held: it may
// safely call back into NoteObserved/Forget without deadlocking. The
// observed set is snapshotted under lock first; lastTick advances before
// callbacks run so concurrent ticks stay gated.
func (r *CheckpointReconciler) Tick(now time.Time, committed func(stream string) (result []byte, generation uint64, ok bool)) []string {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	if !r.lastTick.IsZero() && now.Sub(r.lastTick) < r.config.TickInterval {
		r.mu.Unlock()
		return nil
	}
	r.lastTick = now
	snap := make(map[string]Checkpoint, len(r.observed))
	for s, cp := range r.observed {
		// The snapshot retains the immutable owned slices even if a callback
		// replaces or forgets this entry after we release the lock.
		snap[s] = cp
	}
	max := r.config.MaxStreamsPerTick
	r.mu.Unlock()
	var streams []string
	for s := range snap {
		streams = append(streams, s)
	}
	sort.Strings(streams)
	var out []string
	for _, s := range streams {
		if max > 0 && len(out) >= max {
			break
		}
		obs := snap[s]
		result, gen, ok := committed(s)
		if !ok {
			continue
		}
		if obs.Generation != gen || string(obs.Result) != string(result) {
			out = append(out, s)
		}
	}
	return out
}
