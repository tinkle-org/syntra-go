// Package securechannel implements the SC1 draft-1 Noise construction without
// socket I/O. Its wire contract is documented in SC1.md at the module root.
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
	domain        = "syntra.sc1.draft1"
)

var (
	ErrConfig = errors.New("sc1: invalid configuration")
	ErrAuth   = errors.New("sc1: authentication failed")
	ErrRecord = errors.New("sc1: invalid record")
	ErrClosed = errors.New("sc1: channel closed")
	ErrLimit  = errors.New("sc1: channel limit reached")
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
	TCP Carrier = 1
	WS  Carrier = 2
	WSS Carrier = 3
)

func (c Carrier) String() string {
	switch c {
	case TCP:
		return "tcp"
	case WS:
		return "ws"
	case WSS:
		return "wss"
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
	if (c.Mode != Bootstrap && c.Mode != Returning) || c.Carrier < TCP || c.Carrier > WSS ||
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

// AppendContext appends the canonical prologue. Adequately sized dst avoids an
// allocation. The same bytes prefix the initiator's first handshake message.
func AppendContext(dst []byte, c Context) ([]byte, error) {
	if err := c.Validate(); err != nil {
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
	if c.Validate() != nil {
		return Context{}, ErrAuth
	}
	return c, nil
}

type ClientConfig struct {
	Context          Context
	ServerPublicKey  [32]byte
	AuthorizationKey Key
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

type ServerConfig struct {
	StaticKey      StaticKey
	ServerKeyID    uint32
	Scope          string
	Carrier        Carrier
	AllowBootstrap bool
	Lookup         Lookup
}

func (c ServerConfig) Validate() error {
	if c.StaticKey.private == (Key{}) || len(c.Scope) == 0 || len(c.Scope) > MaxScopeBytes || !utf8.ValidString(c.Scope) || c.Carrier < TCP || c.Carrier > WSS {
		return ErrConfig
	}
	if !c.AllowBootstrap && c.Lookup == nil {
		return ErrConfig
	}
	return nil
}

// Peer is evidence for host policy, not an implicit application principal.
type Peer struct {
	Context   Context
	Principal string
	ExpiresAt time.Time
}

func (c ServerConfig) Check(ctx context.Context, peer Peer) error {
	if peer.Context.Scope != c.Scope || peer.Context.Carrier != c.Carrier || peer.Context.ServerKeyID != c.ServerKeyID {
		return ErrAuth
	}
	if peer.Context.Mode == Bootstrap {
		if !c.AllowBootstrap {
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
	hs      *noise.HandshakeState
	context Context
}

func Begin(c ClientConfig) (*Initiator, []byte, error) {
	return begin(c, rand.Reader)
}

func begin(c ClientConfig, random io.Reader) (*Initiator, []byte, error) {
	if c.Context.Validate() != nil || c.ServerPublicKey == ([32]byte{}) {
		return nil, nil, ErrConfig
	}
	if (c.Context.Mode == Returning) != (c.AuthorizationKey != (Key{})) {
		return nil, nil, ErrConfig
	}
	prologue, _ := AppendContext(nil, c.Context)
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
	return &Initiator{hs: hs, context: c.Context}, msg, nil
}

func (i *Initiator) Close() {
	if i != nil {
		disposeHandshake(i.hs)
		i.hs = nil
	}
}

func (i *Initiator) Finish(message []byte) (*Channel, error) {
	if i == nil || i.hs == nil {
		return nil, ErrClosed
	}
	defer i.Close()
	if len(message) != HandshakeSize {
		return nil, ErrAuth
	}
	payload, c1, c2, err := i.hs.ReadMessage(nil, message)
	if err != nil || len(payload) != 0 || c1 == nil || c2 == nil {
		return nil, ErrAuth
	}
	return newChannel(c1, c2, Peer{Context: i.context}), nil
}

// Respond authenticates M1 and emits M2, but does NOT confirm a fresh client.
// Confirmation becomes true only after a transport record authenticates.
func Respond(ctx context.Context, c ServerConfig, message []byte) (*Channel, []byte, error) {
	return respond(ctx, c, message, rand.Reader)
}

func respond(ctx context.Context, c ServerConfig, message []byte, random io.Reader) (*Channel, []byte, error) {
	if c.Validate() != nil {
		return nil, nil, ErrConfig
	}
	if len(message) < HandshakeSize || len(message) > MaxContext+HandshakeSize {
		return nil, nil, ErrAuth
	}
	prologue := message[:len(message)-HandshakeSize]
	wire, err := ParseContext(prologue)
	if err != nil || wire.Scope != c.Scope || wire.Carrier != c.Carrier || wire.ServerKeyID != c.ServerKeyID {
		return nil, nil, ErrAuth
	}
	peer := Peer{Context: wire}
	var psk Key
	defer clear(psk[:])
	if wire.Mode == Bootstrap {
		if !c.AllowBootstrap {
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
			// Unknown/invalid records still take the Noise verification path.
			psk, err = generateKey(random)
			if err != nil {
				return nil, nil, ErrAuth
			}
		}
		if !valid {
			peer.Principal = ""
		}
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
	payload, _, _, err := hs.ReadMessage(nil, message[len(prologue):])
	if err != nil || len(payload) != 0 || (wire.Mode == Returning && peer.Principal == "") || ctx.Err() != nil {
		return nil, nil, ErrAuth
	}
	m2, c1, c2, err := hs.WriteMessage(nil, nil)
	if err != nil || len(m2) != HandshakeSize {
		return nil, nil, ErrAuth
	}
	return newChannel(c2, c1, peer), m2, nil
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
	sync.Mutex
	cipher *noise.CipherState
}

// Channel owns non-copyable, ordered cipher states. Send and receive may run
// concurrently; individual directions are serialized. Failure is terminal.
type Channel struct {
	send, recv channelDirection
	mu         sync.Mutex
	peer       Peer
	confirmed  bool
	closed     bool
	created    time.Time
	maxAge     time.Duration
	maxRecords uint64
}

func newChannel(send, recv *noise.CipherState, peer Peer) *Channel {
	return &Channel{send: channelDirection{cipher: send}, recv: channelDirection{cipher: recv}, peer: peer, created: time.Now(), maxAge: 24 * time.Hour, maxRecords: 1 << 32}
}

func (c *Channel) Peer() (Peer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peer, c.confirmed && !c.closed
}

func (c *Channel) check(cipher *noise.CipherState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || cipher == nil {
		return ErrClosed
	}
	if time.Since(c.created) >= c.maxAge || cipher.Nonce() >= c.maxRecords || (!c.peer.ExpiresAt.IsZero() && !time.Now().Before(c.peer.ExpiresAt)) {
		c.closed = true
		return ErrLimit
	}
	return nil
}

func (c *Channel) Encrypt(dst, plaintext []byte) ([]byte, error) {
	c.send.Lock()
	defer c.send.Unlock()
	if err := c.check(c.send.cipher); err != nil {
		return nil, err
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintext {
		return nil, ErrRecord
	}
	out, err := c.send.cipher.Encrypt(dst, nil, plaintext)
	if err != nil {
		c.fail()
		return nil, ErrRecord
	}
	return out, nil
}

func (c *Channel) Decrypt(dst, ciphertext []byte) ([]byte, error) {
	c.recv.Lock()
	defer c.recv.Unlock()
	if err := c.check(c.recv.cipher); err != nil {
		return nil, err
	}
	if len(ciphertext) < 17 || len(ciphertext) > MaxCiphertext {
		c.fail()
		return nil, ErrRecord
	}
	out, err := c.recv.cipher.Decrypt(dst, nil, ciphertext)
	if err != nil {
		c.fail()
		return nil, ErrRecord
	}
	c.mu.Lock()
	c.confirmed = true
	c.mu.Unlock()
	return out, nil
}

func (c *Channel) fail() { c.mu.Lock(); c.closed = true; c.mu.Unlock() }

func (c *Channel) Close() {
	c.fail()
	c.send.Lock()
	c.send.cipher = nil
	c.send.Unlock()
	c.recv.Lock()
	c.recv.cipher = nil
	c.recv.Unlock()
}
