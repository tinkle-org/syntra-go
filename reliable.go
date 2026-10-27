// Reliable-session contract for the Go binding: validation plus bounded
// in-memory managers mirroring syntra-core::reliable and
// syntra-runtime::reliable.
//
// OPTIONAL capability syntra.reliable-session/1, post-ACTIVE generic-RPC
// control, no envelope changes, reserved values preserved, app payloads
// opaque (equality only), no exactly-once claims, no custom crypto
// (crypto/rand lookup handles only), production traffic requires TLS.
package syntra

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ReliableSessionCapability is the optional capability identifier.
const ReliableSessionCapability = "syntra.reliable-session/1"

const (
	sessionIDLen         = 16
	deliveryIDLen        = 16
	resumeCredentialLen  = 32
	maxResumeCredLen     = 256
	maxReliablePrincipal = 512
)

const (
	defaultMaxSessions        = 1024
	defaultMaxRetained        = 128
	defaultMaxRetainedBytes   = 1 << 20
	defaultMaxTombstones      = 128
	defaultMaxResumeCreds     = 1024
	defaultMaxControlQueue    = 64
	defaultMaxControlBytes    = 64 << 10
	defaultResultRetentionMs  = 5 * 60 * 1000
	defaultTombstoneRetention = 5 * 60 * 1000
	defaultResumeLifetimeMs   = 24 * 60 * 60 * 1000
)

const (
	minIdleTimeoutMs   = uint32(2000)
	maxIdleTimeoutMs   = uint32(300000)
	minKeepaliveMs     = uint32(1000)
	maxKeepaliveMs     = uint32(60000)
	defaultIdleMs      = uint32(30000)
	defaultKeepaliveMs = uint32(10000)
)

// SessionID is a 16-byte opaque session identity, distinct from connection_id.
type SessionID [sessionIDLen]byte

// DeliveryID is a 16-byte stable delivery key, distinct from request_id.
type DeliveryID [deliveryIDLen]byte

// LeaseProposal is the client-proposed keepalive lease (zero = host default).
type LeaseProposal struct {
	IdleTimeoutMs       uint32
	KeepaliveIntervalMs uint32
}

// ConfirmedLease is the host-confirmed bounded lease.
type ConfirmedLease struct {
	IdleTimeoutMs       uint32
	KeepaliveIntervalMs uint32
}

// SessionSignal is a typed lifecycle signal (existing codes only).
type SessionSignal string

const (
	SignalDraining    SessionSignal = "draining"
	SignalGoingAway   SessionSignal = "going-away"
	SignalOverloaded  SessionSignal = "overloaded"
	SignalFenced      SessionSignal = "fenced"
	SignalExpired     SessionSignal = "expired"
	SignalRevoked     SessionSignal = "revoked"
	SignalIdleTimeout SessionSignal = "idle-timeout"
)

// SignalCode maps a signal to its existing wire code (no new codes).
func SignalCode(s SessionSignal) ErrorCode {
	switch s {
	case SignalDraining, SignalGoingAway, SignalIdleTimeout:
		return ErrorCodeUnavailable
	case SignalOverloaded:
		return ErrorCodeResourceExhausted
	case SignalFenced:
		return ErrorCodeFailedPrecondition
	case SignalExpired, SignalRevoked:
		return ErrorCodeUnauthenticated
	default:
		return ErrorCodeUnknown
	}
}

// ParseSessionSignal parses a control-payload signal name (exact match).
func ParseSessionSignal(name string) (SessionSignal, error) {
	switch SessionSignal(name) {
	case SignalDraining, SignalGoingAway, SignalOverloaded, SignalFenced, SignalExpired, SignalRevoked, SignalIdleTimeout:
		return SessionSignal(name), nil
	default:
		return "", NewRpcError(ErrorCodeInvalidArgument, "syntra: unknown session signal")
	}
}

// ValidateSessionID checks 16 non-zero bytes.
func ValidateSessionID(id []byte) (SessionID, error) {
	if len(id) != sessionIDLen {
		return SessionID{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: session id must be 16 bytes")
	}
	var out SessionID
	copy(out[:], id)
	if out == (SessionID{}) {
		return SessionID{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: session id must not be all zero")
	}
	return out, nil
}

// ValidateDeliveryID checks 16 non-zero bytes.
func ValidateDeliveryID(id []byte) (DeliveryID, error) {
	if len(id) != deliveryIDLen {
		return DeliveryID{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: delivery id must be 16 bytes")
	}
	var out DeliveryID
	copy(out[:], id)
	if out == (DeliveryID{}) {
		return DeliveryID{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: delivery id must not be all zero")
	}
	return out, nil
}

// ValidateResumeCredential checks opaque handle bounds (16..256, 32-byte v1).
func ValidateResumeCredential(cred []byte) ([]byte, error) {
	if len(cred) == 0 || len(cred) > maxResumeCredLen {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: resume credential length out of bounds")
	}
	if len(cred) != resumeCredentialLen && len(cred) < 16 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: resume credential too short")
	}
	zero := true
	for _, b := range cred {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: resume credential must not be all zero")
	}
	out := make([]byte, len(cred))
	copy(out, cred)
	return out, nil
}

// ValidateEpoch checks nonzero.
func ValidateEpoch(epoch uint64) error {
	if epoch == 0 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: attachment epoch must be nonzero")
	}
	return nil
}

// CheckEpochAdvance enforces monotonic fencing (proposed > current).
func CheckEpochAdvance(current, proposed uint64) error {
	if proposed == 0 {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: attachment epoch must be nonzero")
	}
	if proposed <= current {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: stale attachment epoch; fenced")
	}
	return nil
}

// NextEpoch advances the fencing epoch (u64::MAX is terminal).
func NextEpoch(current uint64) (uint64, error) {
	if current == ^uint64(0) {
		return 0, NewRpcError(ErrorCodeFailedPrecondition, "syntra: attachment epoch exhausted; retire the session")
	}
	return current + 1, nil
}

// NegotiateLease applies host defaults, clamps, and enforces keepalive < idle.
func NegotiateLease(p LeaseProposal) (ConfirmedLease, error) {
	idle := p.IdleTimeoutMs
	if idle == 0 {
		idle = defaultIdleMs
	}
	keepalive := p.KeepaliveIntervalMs
	if keepalive == 0 {
		keepalive = defaultKeepaliveMs
	}
	if p.IdleTimeoutMs != 0 && (p.IdleTimeoutMs < minIdleTimeoutMs || p.IdleTimeoutMs > maxIdleTimeoutMs) {
		return ConfirmedLease{}, NewRpcError(ErrorCodeOutOfRange, "syntra: idle timeout out of range")
	}
	if p.KeepaliveIntervalMs != 0 && (p.KeepaliveIntervalMs < minKeepaliveMs || p.KeepaliveIntervalMs > maxKeepaliveMs) {
		return ConfirmedLease{}, NewRpcError(ErrorCodeOutOfRange, "syntra: keepalive interval out of range")
	}
	if idle > maxIdleTimeoutMs {
		idle = maxIdleTimeoutMs
	}
	if keepalive > maxKeepaliveMs {
		keepalive = maxKeepaliveMs
	}
	maxKeep := idle / 2
	if maxKeep < minKeepaliveMs {
		maxKeep = minKeepaliveMs
	}
	if keepalive >= idle {
		keepalive = maxKeep
		if keepalive >= idle {
			if idle <= 1 {
				return ConfirmedLease{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: keepalive must be less than idle timeout")
			}
			keepalive = idle - 1
		}
	} else if keepalive > maxKeep {
		keepalive = maxKeep
	}
	if keepalive == 0 || idle == 0 || keepalive >= idle {
		return ConfirmedLease{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: keepalive must be less than idle timeout")
	}
	return ConfirmedLease{IdleTimeoutMs: idle, KeepaliveIntervalMs: keepalive}, nil
}

// CheckDuplicateContent requires byte-identical (method, payload) on resend.
func CheckDuplicateContent(expectedMethod string, expectedPayload []byte, actualMethod string, actualPayload []byte) error {
	if expectedMethod != actualMethod || string(expectedPayload) != string(actualPayload) {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: delivery id reused with different content; rejected")
	}
	return nil
}

// ReconcileOutcome mirrors the Rust contract.
type ReconcileOutcome string

const (
	ReconcileRetained  ReconcileOutcome = "retained"
	ReconcileForgotten ReconcileOutcome = "forgotten"
	ReconcileUnknown   ReconcileOutcome = "unknown"
	ReconcilePending   ReconcileOutcome = "pending"
)

// StoredOutcome is a retained terminal result (opaque payload or typed error).
type StoredOutcome struct {
	Payload []byte
	Err     *RpcError
}

// ControlBounds documents every reliable-session bound.
type ControlBounds struct {
	MaxSessions          int
	MaxRetainedResults   int // Shared pending + retained count per session.
	MaxRetainedBytes     int // Shared owned method/payload + terminal outcome bytes.
	MaxTombstones        int
	MaxResumeCredentials int
	MaxControlQueue      int
	MaxControlBytes      int
	ResultRetention      time.Duration
	TombstoneRetention   time.Duration
	ResumeLifetime       time.Duration
}

// DefaultControlBounds returns the normative v1 defaults.
func DefaultControlBounds() ControlBounds {
	return ControlBounds{
		MaxSessions: defaultMaxSessions, MaxRetainedResults: defaultMaxRetained,
		MaxRetainedBytes: defaultMaxRetainedBytes, MaxTombstones: defaultMaxTombstones,
		MaxResumeCredentials: defaultMaxResumeCreds, MaxControlQueue: defaultMaxControlQueue,
		MaxControlBytes: defaultMaxControlBytes, ResultRetention: defaultResultRetentionMs * time.Millisecond,
		TombstoneRetention: defaultTombstoneRetention * time.Millisecond, ResumeLifetime: defaultResumeLifetimeMs * time.Millisecond,
	}
}

type retainedEntry struct {
	method     string
	payload    []byte
	outcome    StoredOutcome
	retainedAt time.Time
}

type pendingEntry struct {
	method  string
	payload []byte
}

type tombstoneEntry struct {
	code       ErrorCode
	retainedAt time.Time
	// digest retains the request identity (method, payload) for
	// duplicate-content validation while the tombstone is live.
	// Fixed-size FNV-1a 64-bit digest plus lengths (mirroring Rust
	// ContentDigest), count-bounded by MaxTombstones, so no additional
	// byte budget is required (total overhead bounded).
	// hasContent false means the tombstone was created without prior
	// request content (never-seen DID); the first live resend adopts
	// its digest for future validation.
	digest     contentDigest
	hasContent bool
}

type forgottenEntry struct {
	digest      contentDigest
	hasContent  bool
	forgottenAt time.Time
}

// contentDigest is the bounded content identity for terminal markers,
// mirroring Rust ContentDigest: method/payload lengths plus FNV-1a 64-bit
// hash. Fixed size and count-bounded, so tombstone and forgotten markers
// remain bounded without charging the shared retained-byte budget (which
// continues to cover pending + retained only, preserving
// Forget-releases-bytes for different DIDs). Lengths are checked explicitly
// so length mismatches reject even on hash collision; a hash collision could
// cause false idempotent acceptance but requires identical lengths plus a
// 64-bit collision (negligible for in-memory, short-lived markers).
type contentDigest struct {
	methodLen  int
	payloadLen int
	hash       uint64
}

func digestContent(method string, payload []byte) contentDigest {
	const offset uint64 = 14695981039346656037
	const prime uint64 = 1099511628211
	h := offset
	for _, b := range []byte(method) {
		h ^= uint64(b)
		h *= prime
	}
	h ^= 0xff
	h *= prime
	for _, b := range payload {
		h ^= uint64(b)
		h *= prime
	}
	var lb [8]byte
	binary.LittleEndian.PutUint64(lb[:], uint64(len(method)))
	for _, b := range lb {
		h ^= uint64(b)
		h *= prime
	}
	binary.LittleEndian.PutUint64(lb[:], uint64(len(payload)))
	for _, b := range lb {
		h ^= uint64(b)
		h *= prime
	}
	return contentDigest{methodLen: len(method), payloadLen: len(payload), hash: h}
}

func checkDigest(expected contentDigest, method string, payload []byte) error {
	if expected.methodLen != len(method) || expected.payloadLen != len(payload) {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: delivery id reused with different content; rejected")
	}
	if expected.hash != digestContent(method, payload).hash {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: delivery id reused with different content; rejected")
	}
	return nil
}

type resumeEntry struct {
	session   SessionID
	principal string
	version   uint32
	issuedAt  time.Time
	expiresAt time.Time
}

// QueuedSignal is one buffered lifecycle signal for a session.
type QueuedSignal struct {
	ID     SessionID
	Signal SessionSignal
}

type sessionState struct {
	principal        string
	version          uint32
	epoch            uint64
	lastActivity     time.Time
	lease            ConfirmedLease
	activeConnection string
	hasActive        bool
	outcomes         map[DeliveryID]retainedEntry
	outcomeBytes     int
	tombstones       map[DeliveryID]tombstoneEntry
	// forgotten retains bounded Forgotten markers per removed/expired outcome
	// (bounded by MaxRetainedResults, independent from MaxTombstones) so
	// Reconcile returns Forgotten for expired/forgotten IDs and Unknown only
	// for never-seen IDs. Each marker retains a content digest (when known)
	// for duplicate-content validation while live; digests are fixed 32
	// bytes and count-bounded, so they do not charge MaxRetainedBytes
	// (which covers pending + retained only). Expired forgotten markers are
	// replaced with Pending as a new decision.
	forgotten map[DeliveryID]forgottenEntry
	// Pending and retained entries share the count and byte budgets, including
	// owned method/payload metadata. Live work never expires: only a terminal
	// result or tombstone releases its pending reservation.
	pending      map[DeliveryID]pendingEntry
	pendingBytes int
}

// ReliableManager is the bounded Go manager (sync, no goroutines, explicit drain).
type ReliableManager struct {
	mu       sync.Mutex
	bounds   ControlBounds
	sessions map[SessionID]*sessionState
	resume   map[string]resumeEntry
	revoked  map[string]time.Time
	signals  []QueuedSignal
	draining bool
}

// NewReliableManager constructs a bounded manager.
func NewReliableManager(bounds ControlBounds) (*ReliableManager, error) {
	if bounds.MaxSessions <= 0 || bounds.MaxRetainedResults <= 0 || bounds.MaxTombstones <= 0 ||
		bounds.MaxResumeCredentials <= 0 || bounds.MaxControlQueue <= 0 || bounds.MaxControlBytes <= 0 ||
		bounds.ResultRetention <= 0 || bounds.TombstoneRetention <= 0 || bounds.ResumeLifetime <= 0 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: control bounds must be nonzero")
	}
	if bounds.MaxRetainedBytes <= 0 {
		return nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: control byte bounds must be nonzero")
	}
	return &ReliableManager{
		bounds: bounds, sessions: make(map[SessionID]*sessionState),
		resume: make(map[string]resumeEntry), revoked: make(map[string]time.Time),
	}, nil
}

func newSessionID() (SessionID, error) {
	var out SessionID
	if _, err := rand.Read(out[:]); err != nil {
		return SessionID{}, NewRpcError(ErrorCodeInternal, fmt.Sprintf("syntra: session id RNG failed: %v", err))
	}
	if out == (SessionID{}) {
		return SessionID{}, NewRpcError(ErrorCodeInternal, "syntra: session id RNG returned zero")
	}
	return out, nil
}

func newResumeCredential() ([]byte, error) {
	out := make([]byte, resumeCredentialLen)
	if _, err := rand.Read(out); err != nil {
		return nil, NewRpcError(ErrorCodeInternal, fmt.Sprintf("syntra: resume RNG failed: %v", err))
	}
	zero := true
	for _, b := range out {
		if b != 0 {
			zero = false
			break
		}
	}
	if zero {
		return nil, NewRpcError(ErrorCodeInternal, "syntra: resume RNG returned zero")
	}
	return out, nil
}

// pruneExpiredCredentialsLocked drops resume and revoked handles whose
// resume lifetime has passed. Callers must hold m.mu. The except key (if
// non-empty) is retained so the credential being validated keeps its
// existing expired/revoked error instead of turning into unknown.
func (m *ReliableManager) pruneExpiredCredentialsLocked(now time.Time, except string) {
	for k, e := range m.resume {
		if k == except {
			continue
		}
		if now.After(e.expiresAt) {
			delete(m.resume, k)
		}
	}
	for k, exp := range m.revoked {
		if k == except {
			continue
		}
		if now.After(exp) {
			delete(m.revoked, k)
		}
	}
}

// CreateSession issues a fresh session (epoch 1 + fresh resume handle).
func (m *ReliableManager) CreateSession(now time.Time, principal string, version uint32, p LeaseProposal) (SessionID, uint64, []byte, ConfirmedLease, error) {
	if principal == "" || len(principal) > maxReliablePrincipal {
		return SessionID{}, 0, nil, ConfirmedLease{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: principal length out of bounds")
	}
	if version == 0 {
		return SessionID{}, 0, nil, ConfirmedLease{}, NewRpcError(ErrorCodeInvalidArgument, "syntra: version must be nonzero")
	}
	lease, err := NegotiateLease(p)
	if err != nil {
		return SessionID{}, 0, nil, ConfirmedLease{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.draining {
		return SessionID{}, 0, nil, ConfirmedLease{}, NewRpcError(ErrorCodeUnavailable, "syntra: draining; no new sessions")
	}
	if len(m.sessions) >= m.bounds.MaxSessions {
		return SessionID{}, 0, nil, ConfirmedLease{}, NewRpcError(ErrorCodeResourceExhausted, "syntra: too many reliable sessions")
	}
	m.pruneExpiredCredentialsLocked(now, "")
	if len(m.resume) >= m.bounds.MaxResumeCredentials {
		return SessionID{}, 0, nil, ConfirmedLease{}, NewRpcError(ErrorCodeResourceExhausted, "syntra: too many resume credentials")
	}
	sid, err := newSessionID()
	if err != nil {
		return SessionID{}, 0, nil, ConfirmedLease{}, err
	}
	if _, dup := m.sessions[sid]; dup {
		return SessionID{}, 0, nil, ConfirmedLease{}, NewRpcError(ErrorCodeInternal, "syntra: session id collision")
	}
	cred, err := newResumeCredential()
	if err != nil {
		return SessionID{}, 0, nil, ConfirmedLease{}, err
	}
	if _, dup := m.resume[string(cred)]; dup {
		return SessionID{}, 0, nil, ConfirmedLease{}, NewRpcError(ErrorCodeInternal, "syntra: resume credential collision")
	}
	m.sessions[sid] = &sessionState{
		principal: principal, version: version, epoch: 1,
		lastActivity: now, lease: lease,
		outcomes: make(map[DeliveryID]retainedEntry), tombstones: make(map[DeliveryID]tombstoneEntry),
		forgotten: make(map[DeliveryID]forgottenEntry), pending: make(map[DeliveryID]pendingEntry),
	}
	m.resume[string(cred)] = resumeEntry{session: sid, principal: principal, version: version, issuedAt: now, expiresAt: now.Add(m.bounds.ResumeLifetime)}
	return sid, 1, cred, lease, nil
}

// Attach binds a connection (fresh or resume with fencing + rotation).
// On resume it rotates the credential and returns the freshly generated
// resume credential for the next resume; callers must thread it forward.
// The fenced connection (if any) is returned for observability.
func (m *ReliableManager) Attach(now time.Time, sid SessionID, resumeCred []byte, connectionID, principal string, version uint32, p LeaseProposal) (uint64, ConfirmedLease, string, []byte, error) {
	if connectionID == "" || len(connectionID) > 256 {
		return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: connection_id length out of bounds")
	}
	lease, err := NegotiateLease(p)
	if err != nil {
		return 0, ConfirmedLease{}, "", nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.draining {
		return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeUnavailable, "syntra: draining; no new attachments")
	}
	st, ok := m.sessions[sid]
	if !ok {
		return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeUnauthenticated, "syntra: unknown session")
	}
	if st.principal != principal {
		return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeUnauthenticated, "syntra: principal mismatch for session")
	}
	if st.version != version {
		return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: version mismatch for session")
	}
	// Enforce the idle timeout on this session before attaching: a stale
	// active past its lease is detached and an IdleTimeout signal is
	// queued (push errors propagate instead of dropping silently).
	if idle := idleTimeoutOf(st); idle > 0 && st.hasActive && now.Sub(st.lastActivity) > idle {
		st.hasActive = false
		st.activeConnection = ""
		if err := m.pushSignalLocked(sid, SignalIdleTimeout); err != nil {
			return 0, ConfirmedLease{}, "", nil, err
		}
	}
	if len(resumeCred) > 0 {
		cred, err := ValidateResumeCredential(resumeCred)
		if err != nil {
			return 0, ConfirmedLease{}, "", nil, err
		}
		if _, revoked := m.revoked[string(cred)]; revoked {
			return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeUnauthenticated, "syntra: resume credential revoked")
		}
		entry, ok := m.resume[string(cred)]
		if !ok {
			return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeUnauthenticated, "syntra: unknown resume credential")
		}
		if entry.session != sid {
			return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeUnauthenticated, "syntra: resume credential audience mismatch")
		}
		if entry.principal != principal || entry.version != version {
			return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeUnauthenticated, "syntra: resume credential binding mismatch")
		}
		if now.After(entry.expiresAt) {
			return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeUnauthenticated, "syntra: resume credential expired")
		}
		proposed, err := NextEpoch(st.epoch)
		if err != nil {
			return 0, ConfirmedLease{}, "", nil, err
		}
		if err := CheckEpochAdvance(st.epoch, proposed); err != nil {
			return 0, ConfirmedLease{}, "", nil, err
		}
		// Reserve fence capacity before consuming the caller's credential.
		// Under m.mu no concurrent mutation can invalidate this check.
		hadActive := st.hasActive
		if hadActive && (len(m.signals) >= m.bounds.MaxControlQueue ||
			(len(m.signals)+1)*32 > m.bounds.MaxControlBytes) {
			return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeResourceExhausted, "syntra: control queue full; back off")
		}
		fresh, err := newResumeCredential()
		if err != nil {
			return 0, ConfirmedLease{}, "", nil, err
		}
		m.pruneExpiredCredentialsLocked(now, string(cred))
		if len(m.resume)+len(m.revoked)+1 > m.bounds.MaxResumeCredentials*2 {
			return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeResourceExhausted, "syntra: too many resume credentials")
		}
		delete(m.resume, string(cred))
		m.revoked[string(cred)] = now.Add(m.bounds.ResumeLifetime)
		m.resume[string(fresh)] = resumeEntry{session: sid, principal: st.principal, version: st.version, issuedAt: now, expiresAt: now.Add(m.bounds.ResumeLifetime)}
		fenced := ""
		if hadActive {
			fenced = st.activeConnection
		}
		st.epoch = proposed
		st.activeConnection = connectionID
		st.hasActive = true
		st.lastActivity = now
		st.lease = lease
		if hadActive {
			if err := m.pushSignalLocked(sid, SignalFenced); err != nil {
				return 0, ConfirmedLease{}, "", nil, err
			}
		}
		return proposed, lease, fenced, fresh, nil
	}
	if st.hasActive {
		return 0, ConfirmedLease{}, "", nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: session already attached; present resume credential")
	}
	if err := ValidateEpoch(st.epoch); err != nil {
		return 0, ConfirmedLease{}, "", nil, err
	}
	st.activeConnection = connectionID
	st.hasActive = true
	st.lastActivity = now
	st.lease = lease
	return st.epoch, lease, "", nil, nil
}

// idleTimeoutOf returns the session idle deadline. Zero means no timeout.
func idleTimeoutOf(st *sessionState) time.Duration {
	if st == nil || st.lease.IdleTimeoutMs == 0 {
		return 0
	}
	return time.Duration(st.lease.IdleTimeoutMs) * time.Millisecond
}

// addForgottenLocked inserts a bounded Forgotten marker for did, evicting
// the oldest marker when at capacity. Callers MUST hold m.mu.
// The marker retains a content digest (when hasContent) for live
// duplicate-content validation; digests are fixed size and count-bounded.
func (m *ReliableManager) addForgottenLocked(st *sessionState, did DeliveryID, digest contentDigest, hasContent bool, now time.Time) {
	if st.forgotten == nil {
		st.forgotten = make(map[DeliveryID]forgottenEntry)
	}
	if _, dup := st.forgotten[did]; !dup && len(st.forgotten) >= m.bounds.MaxRetainedResults {
		var oldest DeliveryID
		var oldestAt time.Time
		first := true
		for k, e := range st.forgotten {
			if first || e.forgottenAt.Before(oldestAt) {
				oldest, oldestAt, first = k, e.forgottenAt, false
			}
		}
		if !first {
			delete(st.forgotten, oldest)
		}
	}
	st.forgotten[did] = forgottenEntry{digest: digest, hasContent: hasContent, forgottenAt: now}
}

// addForgottenForContentLocked is a convenience wrapper that digests
// (method, payload) before delegating to addForgottenLocked.
func (m *ReliableManager) addForgottenForContentLocked(st *sessionState, did DeliveryID, method string, payload []byte, now time.Time) {
	m.addForgottenLocked(st, did, digestContent(method, payload), true, now)
}

// copyOutcome deep-copies a StoredOutcome so caller slices and the caller's
// Err pointer can never alias retained state.
func copyOutcome(in StoredOutcome) StoredOutcome {
	out := StoredOutcome{}
	if in.Err != nil {
		cp := *in.Err
		cp.Message = strings.Clone(in.Err.Message)
		out.Err = &cp
	} else if in.Payload != nil {
		out.Payload = append([]byte(nil), in.Payload...)
	}
	return out
}

// sweepIdleLocked detaches idle-timed-out actives and queues IdleTimeout
// signals. Callers MUST hold m.mu. It returns swept IDs and the first
// queue error, if any; detached sessions stay detached even when the
// signal queue is full.
func (m *ReliableManager) sweepIdleLocked(now time.Time) ([]SessionID, error) {
	var ids []SessionID
	var firstErr error
	for sid, st := range m.sessions {
		idle := idleTimeoutOf(st)
		if idle <= 0 || !st.hasActive {
			continue
		}
		if now.Sub(st.lastActivity) > idle {
			st.hasActive = false
			st.activeConnection = ""
			ids = append(ids, sid)
			if err := m.pushSignalLocked(sid, SignalIdleTimeout); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return ids, firstErr
}

// SweepIdle enforces idle timeouts across sessions: actives past their
// lease IdleTimeoutMs are detached and an IdleTimeout signal is queued per
// session. It returns swept IDs and the first queue error, if any.
func (m *ReliableManager) SweepIdle(now time.Time) ([]SessionID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sweepIdleLocked(now)
}

// CheckIdle reports whether the session's active connection is past its
// idle timeout without mutating state.
func (m *ReliableManager) CheckIdle(now time.Time, sid SessionID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[sid]
	if !ok {
		return false, NewRpcError(ErrorCodeFailedPrecondition, "syntra: unknown session for idle check")
	}
	idle := idleTimeoutOf(st)
	if idle <= 0 || !st.hasActive {
		return false, nil
	}
	return now.Sub(st.lastActivity) > idle, nil
}

// RecordResult retains a terminal outcome (duplicate-content checked).
// The caller passes the attachment epoch it holds; stale/zero/future epochs
// are rejected with FAILED_PRECONDITION before ANY mutation or activity
// refresh (mirroring Rust record_result expected_epoch fencing and Go
// NoteDispatch epoch ordering (now, sid, epoch, did, ...)).
// Activity (lastActivity) is refreshed only when accepting a terminal result:
// new insert, expired-marker replacement, and idempotent live duplicate.
// Failed admission (epoch mismatch, content mismatch, budget exhaustion,
// unknown session) preserves markers, bytes, and activity.
func (m *ReliableManager) RecordResult(now time.Time, sid SessionID, epoch uint64, did DeliveryID, method string, payload []byte, outcome StoredOutcome) (ReconcileOutcome, error) {
	if did == (DeliveryID{}) {
		return "", NewRpcError(ErrorCodeInvalidArgument, "syntra: delivery id must not be all zero")
	}
	if len(payload) > MaxFrameBytes {
		return "", NewRpcError(ErrorCodeResourceExhausted, "syntra: payload exceeds envelope bound")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[sid]
	if !ok {
		return "", NewRpcError(ErrorCodeFailedPrecondition, "syntra: unknown session for result")
	}
	// Fencing: a fenced connection (epoch advanced by resume) must not
	// complete work. Zero, stale, and future epochs all fail with
	// FAILED_PRECONDITION before any mutation or activity refresh.
	if epoch != st.epoch {
		return "", NewRpcError(ErrorCodeFailedPrecondition, "syntra: stale attachment epoch; fenced connection cannot complete")
	}
	pending, wasPending := st.pending[did]
	if wasPending {
		if err := CheckDuplicateContent(pending.method, pending.payload, method, payload); err != nil {
			return "", err
		}
	}
	existing, hasOutcome := st.outcomes[did]
	hasExpiredOutcome := false
	if hasOutcome {
		if now.Sub(existing.retainedAt) > m.bounds.ResultRetention {
			hasExpiredOutcome = true
		} else {
			if err := CheckDuplicateContent(existing.method, existing.payload, method, payload); err != nil {
				return "", err
			}
			st.lastActivity = now
			return ReconcileRetained, nil
		}
	}
	// Compute replacement admission without mutating stale state.
	// Failure must preserve markers, timestamps, bytes, and activity.
	entryBytes := len(method) + len(payload)
	if outcome.Err != nil {
		entryBytes += len(outcome.Err.Message)
	} else {
		entryBytes += len(outcome.Payload)
	}
	count := len(st.outcomes) + len(st.pending)
	pendingBytes := st.pendingBytes
	outcomeBytes := st.outcomeBytes
	if wasPending {
		count--
		pendingBytes -= len(pending.method) + len(pending.payload)
	}
	if hasExpiredOutcome {
		count--
		outcomeBytes -= len(existing.method) + len(existing.payload)
		if existing.outcome.Err != nil {
			outcomeBytes -= len(existing.outcome.Err.Message)
		} else {
			outcomeBytes -= len(existing.outcome.Payload)
		}
	}
	if count >= m.bounds.MaxRetainedResults {
		return "", NewRpcError(ErrorCodeResourceExhausted, "syntra: retained result budget exhausted")
	}
	if entryBytes > m.bounds.MaxRetainedBytes-outcomeBytes-pendingBytes {
		return "", NewRpcError(ErrorCodeResourceExhausted, "syntra: retained result bytes exhausted")
	}
	// Commit only after all admission checks pass. Expired retained state is
	// replaced (not left as Forgotten, since the new terminal supersedes it).
	if hasExpiredOutcome {
		delete(st.outcomes, did)
		st.outcomeBytes = outcomeBytes
	}
	delete(st.tombstones, did)
	st.outcomes[did] = retainedEntry{method: strings.Clone(method), payload: append([]byte(nil), payload...), outcome: copyOutcome(outcome), retainedAt: now}
	st.outcomeBytes += entryBytes
	delete(st.forgotten, did)
	clearPending(st, did)
	st.lastActivity = now
	return ReconcileRetained, nil
}

// NoteDispatch validates the active attachment epoch and reserves owned
// method/payload metadata before dispatch. Identical duplicates are idempotent;
// callers must use Reconcile to distinguish new work from Pending/Retained.
// Pending and retained entries share MaxRetainedResults/MaxRetainedBytes.
// Pending survives retention sweeps until a terminal result or tombstone.
// Live terminal markers suppress dispatch (with duplicate-content validation
// against the retained digest); expired markers are replaced with
// Pending only after count and byte admission succeeds.
func (m *ReliableManager) NoteDispatch(now time.Time, sid SessionID, epoch uint64, did DeliveryID, method string, payload []byte) error {
	if err := ValidateEpoch(epoch); err != nil {
		return err
	}
	if did == (DeliveryID{}) {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: delivery id must not be all zero")
	}
	if len(payload) > MaxFrameBytes {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: payload exceeds envelope bound")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.draining {
		return NewRpcError(ErrorCodeUnavailable, "syntra: draining; no new dispatches")
	}
	st, ok := m.sessions[sid]
	if !ok {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: unknown session for dispatch")
	}
	if epoch != st.epoch || !st.hasActive {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: stale or inactive attachment; fenced")
	}
	if idle := idleTimeoutOf(st); idle > 0 && now.Sub(st.lastActivity) > idle {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: attachment idle lease expired")
	}
	if existing, ok := st.pending[did]; ok {
		if err := CheckDuplicateContent(existing.method, existing.payload, method, payload); err != nil {
			return err
		}
		st.lastActivity = now
		return nil
	}
	existing, hasOutcome := st.outcomes[did]
	if hasOutcome && now.Sub(existing.retainedAt) <= m.bounds.ResultRetention {
		if err := CheckDuplicateContent(existing.method, existing.payload, method, payload); err != nil {
			return err
		}
		st.lastActivity = now
		return nil
	}
	// Live tombstone/forgotten fast paths must still validate request
	// identity. Same-delivery-ID different-content is rejected with
	// FAILED_PRECONDITION (never merged); identical resends stay idempotent.
	// Markers created without prior content (never-seen DID tombstoned or
	// forgotten) adopt the first live resend's digest for future validation.
	if tombstone, ok := st.tombstones[did]; ok && now.Sub(tombstone.retainedAt) <= m.bounds.TombstoneRetention {
		incoming := digestContent(method, payload)
		if tombstone.hasContent {
			if incoming != tombstone.digest {
				return NewRpcError(ErrorCodeFailedPrecondition, "syntra: delivery id reused with different content; rejected")
			}
			st.lastActivity = now
			return nil
		}
		// Adopt content for a previously content-less tombstone.
		tombstone.digest = incoming
		tombstone.hasContent = true
		st.tombstones[did] = tombstone
		st.lastActivity = now
		return nil
	}
	if fent, ok := st.forgotten[did]; ok && now.Sub(fent.forgottenAt) <= m.bounds.ResultRetention {
		incoming := digestContent(method, payload)
		if fent.hasContent {
			if incoming != fent.digest {
				return NewRpcError(ErrorCodeFailedPrecondition, "syntra: delivery id reused with different content; rejected")
			}
			st.lastActivity = now
			return nil
		}
		fent.digest = incoming
		fent.hasContent = true
		st.forgotten[did] = fent
		st.lastActivity = now
		return nil
	}
	// Compute replacement admission without retiring stale terminal state.
	// Failure must preserve its marker, timestamp, bytes, and activity.
	count := len(st.pending) + len(st.outcomes)
	outcomeBytes := st.outcomeBytes
	if hasOutcome {
		count--
		outcomeBytes -= len(existing.method) + len(existing.payload)
		if existing.outcome.Err != nil {
			outcomeBytes -= len(existing.outcome.Err.Message)
		} else {
			outcomeBytes -= len(existing.outcome.Payload)
		}
	}
	if count >= m.bounds.MaxRetainedResults {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: pending dispatch budget exhausted")
	}
	entryBytes := len(method) + len(payload)
	if entryBytes > m.bounds.MaxRetainedBytes-outcomeBytes-st.pendingBytes {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: pending dispatch bytes exhausted")
	}
	delete(st.outcomes, did)
	delete(st.tombstones, did)
	delete(st.forgotten, did)
	st.outcomeBytes = outcomeBytes
	st.pending[did] = pendingEntry{method: strings.Clone(method), payload: append([]byte(nil), payload...)}
	st.pendingBytes += entryBytes
	st.lastActivity = now
	return nil
}

// clearPending releases a reservation only after a terminal admission commits.
func clearPending(st *sessionState, did DeliveryID) {
	if pending, ok := st.pending[did]; ok {
		st.pendingBytes -= len(pending.method) + len(pending.payload)
		delete(st.pending, did)
	}
}

// Reconcile returns retained/forgotten/unknown/pending for a delivery ID.
// Unknown is returned only for never-seen IDs; expired outcomes and
// expired tombstones resolve to Forgotten via a bounded marker.
// Pending means dispatched but no terminal outcome yet: callers MUST
// resend the same delivery ID and wait, MUST NOT dispatch as new.
func (m *ReliableManager) Reconcile(now time.Time, sid SessionID, did DeliveryID) (ReconcileOutcome, *StoredOutcome, error) {
	if did == (DeliveryID{}) {
		return "", nil, NewRpcError(ErrorCodeInvalidArgument, "syntra: delivery id must not be all zero")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[sid]
	if !ok {
		return "", nil, NewRpcError(ErrorCodeFailedPrecondition, "syntra: unknown session for reconcile")
	}
	entry, ok := st.outcomes[did]
	if !ok {
		if tomb, tok := st.tombstones[did]; tok {
			if now.Sub(tomb.retainedAt) <= m.bounds.TombstoneRetention {
				out := StoredOutcome{Err: NewRpcError(tomb.code, "syntra: tombstoned delivery")}
				return ReconcileRetained, &out, nil
			}
			// Expired tombstones are seen IDs: they become Forgotten,
			// never Unknown. Propagate the tombstone digest when known so
			// live-forgotten validation still rejects mismatched resends.
			// Leave a bounded marker and fall through.
			delete(st.tombstones, did)
			if tomb.hasContent {
				m.addForgottenLocked(st, did, tomb.digest, true, now)
			} else {
				m.addForgottenLocked(st, did, contentDigest{}, false, now)
			}
			return ReconcileForgotten, nil, nil
		}
		if fent, fok := st.forgotten[did]; fok {
			if now.Sub(fent.forgottenAt) <= m.bounds.ResultRetention {
				return ReconcileForgotten, nil, nil
			}
			delete(st.forgotten, did)
		}
		if _, pok := st.pending[did]; pok {
			return ReconcilePending, nil, nil
		}
		return ReconcileUnknown, nil, nil
	}
	if now.Sub(entry.retainedAt) > m.bounds.ResultRetention {
		freed := len(entry.method) + len(entry.payload)
		if entry.outcome.Err != nil {
			freed += len(entry.outcome.Err.Message)
		} else {
			freed += len(entry.outcome.Payload)
		}
		delete(st.outcomes, did)
		st.outcomeBytes -= freed
		if st.outcomeBytes < 0 {
			st.outcomeBytes = 0
		}
		// Expired outcome becomes Forgotten with its request digest so the
		// live-forgotten window still enforces duplicate-content.
		m.addForgottenLocked(st, did, digestContent(entry.method, entry.payload), true, now)
		return ReconcileForgotten, nil, nil
	}
	out := copyOutcome(entry.outcome)
	return ReconcileRetained, &out, nil
}

// pushSignalLocked queues one lifecycle signal, bounding the control queue.
// Callers MUST hold m.mu. Full queues drop the signal with backpressure
// (matching the Rust control-queue bound) rather than growing unbounded.
func (m *ReliableManager) pushSignalLocked(sid SessionID, sig SessionSignal) error {
	if len(m.signals) >= m.bounds.MaxControlQueue {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: control queue full; back off")
	}
	if (len(m.signals)+1)*32 > m.bounds.MaxControlBytes {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: control queue bytes exhausted")
	}
	m.signals = append(m.signals, QueuedSignal{ID: sid, Signal: sig})
	return nil
}

// Detach clears the active connection when it matches (idempotent; unknown
// sessions are a no-op, mirroring the Rust runtime).
func (m *ReliableManager) Detach(sid SessionID, connectionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if st, ok := m.sessions[sid]; ok {
		if st.activeConnection == connectionID {
			st.activeConnection = ""
			st.hasActive = false
		}
	}
}

// Forget rejects live pending work, discards one retained outcome, and retains
// a bounded Forgotten marker (bounded by MaxRetainedResults, independent from
// MaxTombstones) so Reconcile reports Forgotten rather than Unknown.
// The marker retains the outcome's request digest when known so the live
// forgotten window still enforces duplicate-content validation.
func (m *ReliableManager) Forget(sid SessionID, did DeliveryID) (bool, error) {
	if did == (DeliveryID{}) {
		return false, NewRpcError(ErrorCodeInvalidArgument, "syntra: delivery id must not be all zero")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[sid]
	if !ok {
		return false, NewRpcError(ErrorCodeFailedPrecondition, "syntra: unknown session for forget")
	}
	if _, pending := st.pending[did]; pending {
		return false, NewRpcError(ErrorCodeFailedPrecondition, "syntra: cannot forget live pending delivery")
	}
	entry, ok := st.outcomes[did]
	if !ok {
		if _, fok := st.forgotten[did]; fok {
			return false, nil
		}
		m.addForgottenLocked(st, did, contentDigest{}, false, time.Now())
		return true, nil
	}
	digest := digestContent(entry.method, entry.payload)
	freed := len(entry.method) + len(entry.payload)
	if entry.outcome.Err != nil {
		freed += len(entry.outcome.Err.Message)
	} else {
		freed += len(entry.outcome.Payload)
	}
	delete(st.outcomes, did)
	st.outcomeBytes -= freed
	if st.outcomeBytes < 0 {
		st.outcomeBytes = 0
	}
	m.addForgottenLocked(st, did, digest, true, time.Now())
	return true, nil
}

// RecordTombstone records a terminal tombstone (deadline/cancel only;
// UNAVAILABLE is unknown-outcome and must never be tombstoned) for a
// delivery ID. The caller must establish that execution is terminal and can
// no longer produce effects; a cancellation request or elapsed deadline alone
// is insufficient to release live Pending work. First-write-wins: a live
// duplicate with the same code is idempotent (retainedAt untouched); a live
// duplicate with a different code is rejected without overwriting. Outcomes
// and tombstones are exclusive:
// tombstoning a delivery ID with a live retained outcome is rejected with
// FAILED_PRECONDITION and preserves the outcome.
// Expired-retained handling (explicit): an expired retained outcome is retired
// (bytes freed, digest propagated to a transient Forgotten marker) and the
// tombstone is then admitted as the new terminal; if tombstone admission
// fails (budget exhausted) the expired outcome is preserved (no mutation).
// The new tombstone retains the pending request digest when live pending work
// exists for the DID (common deadline/cancel path); otherwise it starts
// content-less and adopts the first live resend's digest in NoteDispatch.
func (m *ReliableManager) RecordTombstone(now time.Time, sid SessionID, did DeliveryID, code ErrorCode) error {
	if did == (DeliveryID{}) {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: delivery id must not be all zero")
	}
	if code != ErrorCodeDeadlineExceeded && code != ErrorCodeCancelled {
		return NewRpcError(ErrorCodeInvalidArgument, "syntra: tombstones only for deadline/cancel")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[sid]
	if !ok {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: unknown session for tombstone")
	}
	var expiredOutcome *retainedEntry
	if existing, dup := st.outcomes[did]; dup {
		if now.Sub(existing.retainedAt) <= m.bounds.ResultRetention {
			return NewRpcError(ErrorCodeFailedPrecondition, "syntra: delivery id already has a retained outcome")
		}
		cpy := existing
		expiredOutcome = &cpy
	}
	// Check tombstone budget before mutating expired outcome (preserve on failure).
	if existing, dup := st.tombstones[did]; dup {
		if now.Sub(existing.retainedAt) > m.bounds.TombstoneRetention {
			// Expired tombstone: retire with Forgotten (propagating its
			// digest when known), then insert fresh below.
			delete(st.tombstones, did)
			if existing.hasContent {
				m.addForgottenLocked(st, did, existing.digest, true, now)
			} else {
				m.addForgottenLocked(st, did, contentDigest{}, false, now)
			}
		} else if existing.code == code {
			return nil
		} else {
			return NewRpcError(ErrorCodeFailedPrecondition, "syntra: tombstone code mismatch for delivery id")
		}
	} else if len(st.tombstones) >= m.bounds.MaxTombstones {
		return NewRpcError(ErrorCodeResourceExhausted, "syntra: tombstone budget exhausted")
	}
	// Admit expired-outcome retirement only after tombstone budget succeeds.
	if expiredOutcome != nil {
		freed := len(expiredOutcome.method) + len(expiredOutcome.payload)
		if expiredOutcome.outcome.Err != nil {
			freed += len(expiredOutcome.outcome.Err.Message)
		} else {
			freed += len(expiredOutcome.outcome.Payload)
		}
		delete(st.outcomes, did)
		st.outcomeBytes -= freed
		if st.outcomeBytes < 0 {
			st.outcomeBytes = 0
		}
		// Transient Forgotten for expiry history; deleted below when the
		// tombstone commits as the new terminal.
		m.addForgottenLocked(st, did, digestContent(expiredOutcome.method, expiredOutcome.payload), true, now)
	}
	var digest contentDigest
	hasContent := false
	// Capture content for future resend validation: prefer pending
	// (executing work), else the expired retained just observed, else copy
	// a live forgotten digest for consistency, else content-less (the first
	// live resend after tombstoning will define it). Mirrors Rust
	// record_tombstone content priority.
	if pending, ok := st.pending[did]; ok {
		digest = digestContent(pending.method, pending.payload)
		hasContent = true
	} else if expiredOutcome != nil {
		digest = digestContent(expiredOutcome.method, expiredOutcome.payload)
		hasContent = true
	} else if fent, ok := st.forgotten[did]; ok && now.Sub(fent.forgottenAt) <= m.bounds.ResultRetention && fent.hasContent {
		digest = fent.digest
		hasContent = true
	}
	st.tombstones[did] = tombstoneEntry{code: code, retainedAt: now, digest: digest, hasContent: hasContent}
	delete(st.forgotten, did)
	clearPending(st, did)
	return nil
}

// TombstoneOf returns the tombstone code when present and unexpired.
func (m *ReliableManager) TombstoneOf(now time.Time, sid SessionID, did DeliveryID) (ErrorCode, bool, error) {
	if did == (DeliveryID{}) {
		return 0, false, NewRpcError(ErrorCodeInvalidArgument, "syntra: delivery id must not be all zero")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.sessions[sid]
	if !ok {
		return 0, false, NewRpcError(ErrorCodeFailedPrecondition, "syntra: unknown session for tombstone lookup")
	}
	entry, ok := st.tombstones[did]
	if !ok {
		return 0, false, nil
	}
	if now.Sub(entry.retainedAt) > m.bounds.TombstoneRetention {
		return 0, false, nil
	}
	return entry.code, true, nil
}

// Revoke withdraws one resume credential (rotation already revokes the
// predecessor; this covers explicit revocation).
func (m *ReliableManager) Revoke(now time.Time, cred []byte) (bool, error) {
	validated, err := ValidateResumeCredential(cred)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.revoked[string(validated)]; dup {
		removed := false
		if _, ok := m.resume[string(validated)]; ok {
			delete(m.resume, string(validated))
			removed = true
		}
		return removed, nil
	}
	m.pruneExpiredCredentialsLocked(now, string(validated))
	if _, ok := m.resume[string(validated)]; !ok {
		if _, dup := m.revoked[string(validated)]; !dup {
			return false, nil
		}
	}
	resumeCount := len(m.resume)
	if _, ok := m.resume[string(validated)]; ok {
		resumeCount--
	}
	if resumeCount+len(m.revoked) >= m.bounds.MaxResumeCredentials*2 {
		return false, NewRpcError(ErrorCodeResourceExhausted, "syntra: revocation set exhausted; retire sessions")
	}
	removed := false
	if _, ok := m.resume[string(validated)]; ok {
		delete(m.resume, string(validated))
		removed = true
	}
	m.revoked[string(validated)] = now.Add(m.bounds.ResumeLifetime)
	return removed, nil
}

// Signal queues one lifecycle signal for a known session.
func (m *ReliableManager) Signal(sid SessionID, sig SessionSignal) error {
	if _, err := ParseSessionSignal(string(sig)); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[sid]; !ok {
		return NewRpcError(ErrorCodeFailedPrecondition, "syntra: unknown session for signal")
	}
	return m.pushSignalLocked(sid, sig)
}

// DrainSignals dequeues up to limit queued signals (bounded by
// MaxControlQueue, at least one when limit > 0).
func (m *ReliableManager) DrainSignals(limit int) []QueuedSignal {
	if limit <= 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	capped := limit
	if capped > m.bounds.MaxControlQueue {
		capped = m.bounds.MaxControlQueue
	}
	if capped > len(m.signals) {
		capped = len(m.signals)
	}
	out := make([]QueuedSignal, capped)
	copy(out, m.signals[:capped])
	m.signals = append([]QueuedSignal(nil), m.signals[capped:]...)
	return out
}

// ReapExpired discards retained outcomes, tombstones, and resume handles
// past retention, returning per-kind counts. Expired outcomes leave a bounded
// Forgotten marker (bounded by MaxRetainedResults, independent from
// MaxTombstones); expired Forgotten markers beyond retention are dropped.
// Expired resume and revoked handles share the resume lifetime; both are
// reaped here and counted together in resumes. Live pending work is never
// reaped. Idle attachments are detached even if their signal cannot be queued;
// err reports the first queue failure while retention cleanup still completes.
func (m *ReliableManager) ReapExpired(now time.Time) (outcomes, tombstones, resumes int, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err = m.sweepIdleLocked(now)
	for _, st := range m.sessions {
		for did, entry := range st.outcomes {
			if now.Sub(entry.retainedAt) > m.bounds.ResultRetention {
				freed := len(entry.method) + len(entry.payload)
				if entry.outcome.Err != nil {
					freed += len(entry.outcome.Err.Message)
				} else {
					freed += len(entry.outcome.Payload)
				}
				delete(st.outcomes, did)
				st.outcomeBytes -= freed
				if st.outcomeBytes < 0 {
					st.outcomeBytes = 0
				}
				m.addForgottenLocked(st, did, digestContent(entry.method, entry.payload), true, now)
				outcomes++
			}
		}
		for did, fent := range st.forgotten {
			if now.Sub(fent.forgottenAt) > m.bounds.ResultRetention {
				delete(st.forgotten, did)
			}
		}
		for did, entry := range st.tombstones {
			if now.Sub(entry.retainedAt) > m.bounds.TombstoneRetention {
				delete(st.tombstones, did)
				// Expired tombstones are seen IDs: they become Forgotten,
				// never Unknown. Propagate the digest when known.
				if entry.hasContent {
					m.addForgottenLocked(st, did, entry.digest, true, now)
				} else {
					m.addForgottenLocked(st, did, contentDigest{}, false, now)
				}
				tombstones++
			}
		}
	}
	for key, entry := range m.resume {
		if now.After(entry.expiresAt) {
			delete(m.resume, key)
			resumes++
		}
	}
	for key, exp := range m.revoked {
		if now.After(exp) {
			delete(m.revoked, key)
			resumes++
		}
	}
	return outcomes, tombstones, resumes, err
}

// DrainForShutdown enters draining, detaches active connections, queues a
// going-away signal per detached session, and returns the drained session
// IDs with pending signals plus the count of signals dropped to a full
// queue. Dropped signals are reported, never swallowed.
func (m *ReliableManager) DrainForShutdown() ([]SessionID, []QueuedSignal, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.draining = true
	var ids []SessionID
	dropped := 0
	var firstErr error
	for sid, st := range m.sessions {
		if st.hasActive {
			ids = append(ids, sid)
			st.hasActive = false
			st.activeConnection = ""
			if err := m.pushSignalLocked(sid, SignalGoingAway); err != nil {
				dropped++
				if firstErr == nil {
					firstErr = err
				}
			}
		}
	}
	capped := len(m.signals)
	if capped > m.bounds.MaxControlQueue {
		capped = m.bounds.MaxControlQueue
	}
	out := make([]QueuedSignal, capped)
	copy(out, m.signals[:capped])
	m.signals = append([]QueuedSignal(nil), m.signals[capped:]...)
	return ids, out, dropped, firstErr
}
