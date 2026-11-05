// Package securechannel implements Syntra 1.0's integral encryption kernel.
package securechannel

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/flynn/noise"
)

const (
	MaxCiphertext = 65535
	MaxPlaintext  = MaxCiphertext - 16
	HandshakeSize = 48
	MaxScopeBytes = 255
	MaxContext    = len(domain) + 24 + MaxScopeBytes
	MaxFrame      = 1 << 20
	MaxRecords    = 1 << 32
	MaxAge        = 24 * time.Hour
	Protocol      = "syntra.1.0"
	domain        = Protocol
)

var (
	ErrConfig = errors.New("syntra: invalid configuration")
	ErrAuth   = errors.New("syntra: authentication failed")
	ErrRecord = errors.New("syntra: invalid record")
	ErrClosed = errors.New("syntra: channel closed")
	ErrLimit  = errors.New("syntra: channel limit reached")
)

type Mode uint8

const (
	Bootstrap Mode = 1
	Returning Mode = 2
)

func (m Mode) String() string {
	if m == Bootstrap {
		return "bootstrap"
	}
	if m == Returning {
		return "returning"
	}
	return "invalid"
}

type Carrier uint8

const (
	TCP   Carrier = 1
	WS    Carrier = 2
	WSS   Carrier = 3
	HTTP  Carrier = 4
	HTTPS Carrier = 5
)

func (c Carrier) String() string {
	switch c {
	case TCP:
		return "tcp"
	case WS:
		return "ws"
	case WSS:
		return "wss"
	case HTTP:
		return "http"
	case HTTPS:
		return "https"
	}
	return "invalid"
}

// Key is authorization material. Formatting it never renders its bytes.
type Key [32]byte

func (Key) String() string             { return "[redacted key]" }
func (Key) GoString() string           { return "[redacted key]" }
func (Key) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "[redacted key]") }

func GenerateKey() (Key, error) {
	return generateKey(rand.Reader)
}

func generateKey(random io.Reader) (Key, error) {
	var k Key
	_, err := io.ReadFull(random, k[:])
	return k, err
}

// StaticKey keeps the private key out of diagnostics. Public returns a copy.
type StaticKey struct {
	private Key
	public  [32]byte
}

func (StaticKey) String() string   { return "[server static key]" }
func (StaticKey) GoString() string { return "[server static key]" }
func (StaticKey) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "[server static key]")
}

func GenerateStaticKey() (StaticKey, error) {
	k, err := GenerateKey()
	if err != nil {
		return StaticKey{}, err
	}
	return NewStaticKey(k)
}

func NewStaticKey(private Key) (StaticKey, error) {
	if private == (Key{}) {
		return StaticKey{}, ErrConfig
	}
	k, err := ecdh.X25519().NewPrivateKey(private[:])
	if err != nil {
		return StaticKey{}, ErrConfig
	}
	out := StaticKey{private: private}
	copy(out.public[:], k.PublicKey().Bytes())
	return out, nil
}

func (k StaticKey) Public() [32]byte { return k.public }

// Context is public routing data authenticated by the Noise prologue. Scope is
// an exact, provisioned UTF-8 identifier; no URL or Unicode normalization occurs.
type Context struct {
	Mode        Mode
	Carrier     Carrier
	ServerKeyID uint32
	Epoch       uint64
	Handle      [8]byte
	Scope       string
}

func (c Context) Validate() error {
	return c.ValidateWithHTTPCandidate(false)
}

// ValidateWithHTTPCandidate admits candidate carrier codes only by explicit policy.
func (c Context) ValidateWithHTTPCandidate(allow bool) error {
	if (c.Mode != Bootstrap && c.Mode != Returning) || !validCarrier(c.Carrier, allow) ||
		len(c.Scope) == 0 || len(c.Scope) > MaxScopeBytes || !utf8.ValidString(c.Scope) {
		return ErrConfig
	}
	if c.Mode == Bootstrap && (c.Epoch != 0 || c.Handle != ([8]byte{})) {
		return ErrConfig
	}
	if c.Mode == Returning && (c.Epoch == 0 || c.Handle == ([8]byte{})) {
		return ErrConfig
	}
	return nil
}

func validCarrier(c Carrier, allow bool) bool {
	return c >= TCP && c <= WSS || allow && (c == HTTP || c == HTTPS)
}

// AppendContext appends the canonical prologue. Adequately sized dst avoids an
// allocation. The same bytes prefix the initiator's first handshake message.
func AppendContext(dst []byte, c Context) ([]byte, error) {
	return AppendContextWithHTTPCandidate(dst, c, false)
}

// AppendContextWithHTTPCandidate encodes the exact candidate carrier code when allowed.
func AppendContextWithHTTPCandidate(dst []byte, c Context, allow bool) ([]byte, error) {
	if err := c.ValidateWithHTTPCandidate(allow); err != nil {
		return nil, err
	}
	dst = append(dst, domain...)
	dst = append(dst, byte(c.Mode), byte(c.Carrier))
	dst = binary.BigEndian.AppendUint32(dst, c.ServerKeyID)
	dst = binary.BigEndian.AppendUint64(dst, c.Epoch)
	dst = append(dst, c.Handle[:]...)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(c.Scope)))
	return append(dst, c.Scope...), nil
}

func ParseContext(data []byte) (Context, error) {
	return ParseContextWithHTTPCandidate(data, false)
}

// ParseContextWithHTTPCandidate applies the caller's candidate admission policy.
func ParseContextWithHTTPCandidate(data []byte, allow bool) (Context, error) {
	const fixed = len(domain) + 24
	if len(data) < fixed || len(data) > MaxContext || string(data[:len(domain)]) != domain {
		return Context{}, ErrAuth
	}
	p := data[len(domain):]
	n := int(binary.BigEndian.Uint16(p[22:24]))
	if len(p) != 24+n {
		return Context{}, ErrAuth
	}
	c := Context{Mode: Mode(p[0]), Carrier: Carrier(p[1]), ServerKeyID: binary.BigEndian.Uint32(p[2:6]), Epoch: binary.BigEndian.Uint64(p[6:14]), Scope: string(p[24:])}
	copy(c.Handle[:], p[14:22])
	if c.ValidateWithHTTPCandidate(allow) != nil {
		return Context{}, ErrAuth
	}
	return c, nil
}

// ParseFirst accepts exactly one context followed by a 48-byte Noise message.
// The returned suffix borrows input; parsing does not establish an identity.
func ParseFirst(input []byte) (Context, []byte, error) {
	return parseFirst(input, false)
}

func parseFirst(input []byte, allow bool) (Context, []byte, error) {
	if len(input) < len(domain)+24+1+HandshakeSize || len(input) > MaxContext+HandshakeSize {
		return Context{}, nil, ErrAuth
	}
	n := len(input) - HandshakeSize
	c, err := ParseContextWithHTTPCandidate(input[:n], allow)
	if err != nil {
		return Context{}, nil, err
	}
	return c, input[n:], nil
}

type ClientConfig struct {
	AllowHTTPCandidate bool
	Context            Context
	ServerPublicKey    [32]byte
	AuthorizationKey   Key
}

// Enrollment is returned by a host-owned, protected credential store. Lookup
// must honor ctx and must not create or update an enrollment on a handshake.
type Enrollment struct {
	Key       Key
	Principal string
	ExpiresAt time.Time
	Revoked   bool
}

type Lookup func(context.Context, Context) (Enrollment, error)

// KeyLookup resolves only cryptographic admission material. It must validate
// scope, epoch, expiry and revocation, honor cancellation, and have no principal
// granting effects. A parsed context is not proof of possession.
type KeyLookup func(context.Context, Context) (Key, error)

type ServerConfig struct {
	AllowHTTPCandidate bool
	StaticKey          StaticKey
	ServerKeyID        uint32
	Scope              string
	Carrier            Carrier
	AllowBootstrap     bool
	Lookup             Lookup
	LookupKey          KeyLookup
	// Authorize checks a confirmed identity. The ordered driver serializes it
	// before initial frame delivery, record dispatch/delivery, writes and idle
	// lifecycle checks. It must honor ctx. Key possession alone grants no principal.
	Authorize func(context.Context, VerifiedIdentity) error
}

func (c ServerConfig) Validate() error {
	if c.StaticKey.private == (Key{}) || len(c.Scope) == 0 || len(c.Scope) > MaxScopeBytes || !utf8.ValidString(c.Scope) || !validCarrier(c.Carrier, c.AllowHTTPCandidate) {
		return ErrConfig
	}
	if !c.AllowBootstrap && c.Lookup == nil && c.LookupKey == nil {
		return ErrConfig
	}
	if c.Lookup != nil && c.LookupKey != nil {
		return ErrConfig
	}
	return nil
}

// Peer is evidence for host policy, not an implicit application principal.
type Peer struct {
	Context       Context
	Principal     string
	ExpiresAt     time.Time
	HandshakeHash [32]byte
}

// VerifiedIdentity can only be issued by a confirmed responder channel.
// Bootstrap confirms participation, not enrollment authority.
type VerifiedIdentity struct {
	peer    Peer
	valid   bool
	channel *Channel
}

func (v VerifiedIdentity) Context() Context        { return v.peer.Context }
func (v VerifiedIdentity) HandshakeHash() [32]byte { return v.peer.HandshakeHash }

func (c ServerConfig) CheckIdentity(ctx context.Context, identity VerifiedIdentity) error {
	if !identity.valid || identity.channel == nil || identity.channel.CheckLive() != nil || c.Check(ctx, identity.peer) != nil {
		return ErrAuth
	}
	if c.Authorize != nil && c.Authorize(ctx, identity) != nil {
		return ErrAuth
	}
	if ctx.Err() != nil || identity.channel.CheckLive() != nil {
		return ErrAuth
	}
	return nil
}

func (c ServerConfig) Check(ctx context.Context, peer Peer) error {
	if ctx.Err() != nil || peer.Context.ValidateWithHTTPCandidate(c.AllowHTTPCandidate) != nil {
		return ErrAuth
	}
	if peer.Context.Scope != c.Scope || peer.Context.Carrier != c.Carrier || peer.Context.ServerKeyID != c.ServerKeyID {
		return ErrAuth
	}
	if peer.Context.Mode == Bootstrap {
		if !c.AllowBootstrap {
			return ErrAuth
		}
		return nil
	}
	if peer.Context.Mode != Returning {
		return ErrAuth
	}
	if c.LookupKey != nil {
		key, err := c.LookupKey(ctx, peer.Context)
		defer clear(key[:])
		if err != nil || ctx.Err() != nil || key == (Key{}) {
			return ErrAuth
		}
		return nil
	}
	if c.Lookup == nil {
		return ErrAuth
	}
	e, err := c.Lookup(ctx, peer.Context)
	defer clear(e.Key[:])
	if err != nil || ctx.Err() != nil || e.Revoked || e.Key == (Key{}) || e.Principal == "" || e.Principal != peer.Principal || e.ExpiresAt.IsZero() || !time.Now().Before(e.ExpiresAt) {
		return ErrAuth
	}
	return nil
}

func suite() noise.CipherSuite {
	return noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
}

// Initiator is single-use. No handshake or cipher-state export is provided.
type Initiator struct {
	mu      sync.Mutex
	hs      *noise.HandshakeState
	context Context
	clock   *Clock
}

func Begin(c ClientConfig) (*Initiator, []byte, error) {
	return BeginWithClock(c, NewClock())
}

// BeginWithClock preserves an origin captured before carrier establishment.
func BeginWithClock(c ClientConfig, clock *Clock) (*Initiator, []byte, error) {
	return beginWithClock(c, rand.Reader, clock)
}

func begin(c ClientConfig, random io.Reader) (*Initiator, []byte, error) {
	return beginWithClock(c, random, NewClock())
}

func beginWithClock(c ClientConfig, random io.Reader, clock *Clock) (*Initiator, []byte, error) {
	if err := clock.Check(); err != nil {
		return nil, nil, err
	}
	if c.Context.ValidateWithHTTPCandidate(c.AllowHTTPCandidate) != nil || c.ServerPublicKey == ([32]byte{}) {
		return nil, nil, ErrConfig
	}
	if (c.Context.Mode == Returning) != (c.AuthorizationKey != (Key{})) {
		return nil, nil, ErrConfig
	}
	prologue, _ := AppendContextWithHTTPCandidate(nil, c.Context, c.AllowHTTPCandidate)
	nc := noise.Config{CipherSuite: suite(), Random: random, Pattern: noise.HandshakeNK, Initiator: true, Prologue: prologue, PeerStatic: c.ServerPublicKey[:]}
	if c.Context.Mode == Returning {
		nc.PresharedKey = c.AuthorizationKey[:]
		nc.PresharedKeyPlacement = 0
	}
	hs, err := noise.NewHandshakeState(nc)
	if err != nil {
		return nil, nil, ErrAuth
	}
	msg, _, _, err := hs.WriteMessage(prologue, nil)
	if err != nil {
		disposeHandshake(hs)
		return nil, nil, ErrAuth
	}
	if len(msg) != len(prologue)+HandshakeSize {
		disposeHandshake(hs)
		return nil, nil, ErrAuth
	}
	if err := clock.Check(); err != nil {
		disposeHandshake(hs)
		return nil, nil, err
	}
	return &Initiator{hs: hs, context: c.Context, clock: clock}, msg, nil
}

func (i *Initiator) Close() {
	if i != nil {
		i.mu.Lock()
		defer i.mu.Unlock()
		disposeHandshake(i.hs)
		i.hs = nil
	}
}

func (i *Initiator) Finish(message []byte) (*Channel, error) {
	if i == nil {
		return nil, ErrClosed
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.hs == nil {
		return nil, ErrClosed
	}
	defer func() { disposeHandshake(i.hs); i.hs = nil }()
	if err := i.clock.Check(); err != nil {
		return nil, err
	}
	if len(message) != HandshakeSize {
		return nil, ErrAuth
	}
	payload, c1, c2, err := i.hs.ReadMessage(nil, message)
	if err != nil || len(payload) != 0 || c1 == nil || c2 == nil {
		return nil, ErrAuth
	}
	if err := i.clock.Check(); err != nil {
		return nil, err
	}
	peer := Peer{Context: i.context}
	copy(peer.HandshakeHash[:], i.hs.ChannelBinding())
	return newChannel(c1, c2, peer, false, i.clock), nil
}

// Respond authenticates M1 and emits M2, but does NOT confirm a fresh client.
// Confirmation becomes true only after a transport record authenticates.
func Respond(ctx context.Context, c ServerConfig, message []byte) (*Channel, []byte, error) {
	return RespondWithClock(ctx, c, message, NewClock())
}

func RespondWithClock(ctx context.Context, c ServerConfig, message []byte, clock *Clock) (*Channel, []byte, error) {
	return respondWithClock(ctx, c, message, rand.Reader, clock)
}

func respond(ctx context.Context, c ServerConfig, message []byte, random io.Reader) (*Channel, []byte, error) {
	return respondWithClock(ctx, c, message, random, NewClock())
}

func respondWithClock(ctx context.Context, c ServerConfig, message []byte, random io.Reader, clock *Clock) (*Channel, []byte, error) {
	if err := clock.Check(); err != nil {
		return nil, nil, err
	}
	if c.Validate() != nil {
		return nil, nil, ErrConfig
	}
	wire, suffix, err := parseFirst(message, c.AllowHTTPCandidate)
	if err != nil || wire.Scope != c.Scope || wire.Carrier != c.Carrier || wire.ServerKeyID != c.ServerKeyID {
		return nil, nil, ErrAuth
	}
	if ctx.Err() != nil {
		return nil, nil, ErrAuth
	}
	prologue := message[:len(message)-len(suffix)]
	peer := Peer{Context: wire}
	var psk Key
	defer clear(psk[:])
	if wire.Mode == Bootstrap {
		if !c.AllowBootstrap {
			return nil, nil, ErrAuth
		}
	} else if c.LookupKey != nil {
		psk, err = c.LookupKey(ctx, wire)
		if err != nil || ctx.Err() != nil || psk == (Key{}) {
			return nil, nil, ErrAuth
		}
	} else {
		if c.Lookup == nil {
			return nil, nil, ErrAuth
		}
		e, lookupErr := c.Lookup(ctx, wire)
		valid := lookupErr == nil && ctx.Err() == nil && !e.Revoked && e.Key != (Key{}) && e.Principal != "" && !e.ExpiresAt.IsZero() && time.Now().Before(e.ExpiresAt)
		psk = e.Key
		peer.Principal, peer.ExpiresAt = e.Principal, e.ExpiresAt
		clear(e.Key[:])
		if !valid {
			return nil, nil, ErrAuth
		}
	}
	if err := clock.Check(); err != nil {
		return nil, nil, err
	}
	nc := noise.Config{CipherSuite: suite(), Random: random, Pattern: noise.HandshakeNK, Prologue: prologue, StaticKeypair: noise.DHKey{Private: c.StaticKey.private[:], Public: c.StaticKey.public[:]}}
	if wire.Mode == Returning {
		nc.PresharedKey = psk[:]
		nc.PresharedKeyPlacement = 0
	}
	hs, err := noise.NewHandshakeState(nc)
	if err != nil {
		return nil, nil, ErrAuth
	}
	defer disposeHandshake(hs)
	payload, _, _, err := hs.ReadMessage(nil, suffix)
	if err != nil || len(payload) != 0 || ctx.Err() != nil {
		return nil, nil, ErrAuth
	}
	m2, c1, c2, err := hs.WriteMessage(nil, nil)
	if err != nil || len(m2) != HandshakeSize || c1 == nil || c2 == nil {
		return nil, nil, ErrAuth
	}
	if err := clock.Check(); err != nil {
		return nil, nil, err
	}
	if ctx.Err() != nil {
		return nil, nil, ErrAuth
	}
	copy(peer.HandshakeHash[:], hs.ChannelBinding())
	return newChannel(c2, c1, peer, true, clock), m2, nil
}

func disposeHandshake(hs *noise.HandshakeState) {
	if hs != nil {
		k := hs.LocalEphemeral()
		clear(k.Private)
		// Dropping the state releases library-internal key-schedule/PSK copies.
		// Go and this dependency do not guarantee erasure of every secret copy.
	}
}

type channelDirection struct {
	cipher *noise.CipherState
}

// Channel owns non-copyable, ordered cipher states. Send and receive may run
// concurrently; cryptographic transitions use one short lock. Failure is terminal.
type Channel struct {
	send, recv channelDirection
	mu         sync.Mutex
	peer       Peer
	confirmed  bool
	responder  bool
	closed     bool
	terminal   error
	clock      *Clock
	maxAge     time.Duration
	maxRecords uint64
}

func newChannel(send, recv *noise.CipherState, peer Peer, responder bool, clock *Clock) *Channel {
	return &Channel{send: channelDirection{cipher: send}, recv: channelDirection{cipher: recv}, peer: peer, responder: responder, clock: clock, maxAge: MaxAge, maxRecords: MaxRecords}
}

func (c *Channel) Peer() (Peer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peer, c.checkLive() == nil && c.responder && c.confirmed
}

func (c *Channel) VerifiedIdentity() (VerifiedIdentity, bool) {
	peer, ok := c.Peer()
	if !ok {
		return VerifiedIdentity{}, false
	}
	return VerifiedIdentity{peer: peer, valid: true, channel: c}, true
}

func (c *Channel) Age() time.Duration { return c.clock.Age() }

// Clock returns the shared establishment origin and continuity gate.
func (c *Channel) Clock() *Clock { return c.clock }

// CheckLive checks closure and expiry without admitting another record. A
// successful final record retains its cipher states until the next operation.
func (c *Channel) CheckLive() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkLive()
}

// Check retires a channel whose age or either directional budget is exhausted.
func (c *Channel) Check() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.check()
}

func (c *Channel) check() error {
	if err := c.checkLive(); err != nil {
		return err
	}
	if c.send.cipher.Nonce() >= c.maxRecords || c.recv.cipher.Nonce() >= c.maxRecords {
		c.failLocked(ErrLimit)
		return ErrLimit
	}
	return nil
}

func (c *Channel) checkLive() error {
	if c.closed || c.send.cipher == nil || c.recv.cipher == nil {
		return ErrClosed
	}
	if c.clock.Age() >= c.maxAge || (!c.peer.ExpiresAt.IsZero() && !time.Now().Before(c.peer.ExpiresAt)) {
		c.failLocked(ErrLimit)
		return ErrLimit
	}
	return nil
}

func (c *Channel) Encrypt(dst, plaintext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return nil, err
	}
	if c.responder && !c.confirmed {
		c.failLocked(ErrAuth)
		return nil, ErrAuth
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		c.failLocked(ErrRecord)
		return nil, ErrRecord
	}
	out, err := c.send.cipher.Encrypt(dst, nil, plaintext)
	if err != nil {
		c.failLocked(ErrRecord)
		return nil, ErrRecord
	}
	return out, nil
}

func (c *Channel) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.check(); err != nil {
		return nil, err
	}
	if len(ciphertext) < 17 || len(ciphertext) > MaxCiphertext {
		c.failLocked(ErrRecord)
		return nil, ErrRecord
	}
	out, err := c.recv.cipher.Decrypt(dst, nil, ciphertext)
	if err != nil {
		c.failLocked(ErrRecord)
		return nil, ErrRecord
	}
	c.confirmed = true
	return out, nil
}

func (c *Channel) closeLocked() {
	c.closed = true
	c.send.cipher, c.recv.cipher = nil, nil
}

func (c *Channel) failLocked(err error) {
	if c.terminal == nil {
		c.terminal = err
	}
	c.closeLocked()
}

// TerminalError retains a typed kernel failure after cipher-state retirement.
func (c *Channel) TerminalError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.terminal
}

func (c *Channel) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLocked()
}
