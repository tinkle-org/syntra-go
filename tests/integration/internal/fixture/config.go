// Package fixture is test-only provisioning shared by the harness and peer.
package fixture

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/securechannel"
)

const (
	Scope        = "integration.example.echo"
	Principal    = "integration-peer"
	EchoMethod   = "/example.Echo/Echo"
	WaitMethod   = "/example.Echo/Wait"
	DeniedMethod = "/example.Echo/Denied"
	TLSName      = "peer.integration.test"
)

// Config contains neutral test credentials. Never format or log its contents.
type Config struct {
	Protocol      string
	Mode          string
	Static        securechannel.Key
	Authorization securechannel.Key
	Credential    []byte
}

func (Config) String() string             { return "[test provisioning]" }
func (Config) GoString() string           { return "[test provisioning]" }
func (Config) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("[test provisioning]")) }

// Provision deterministically derives TEST-ONLY keys, never deployment keys.
// A distinct generation rotates both the static and enrollment keys.
func Provision(protocol, mode, generation string) Config {
	static := sha256.Sum256([]byte("syntra integration static " + generation))
	ak := sha256.Sum256([]byte("syntra integration enrollment " + generation))
	credential := sha256.Sum256([]byte("syntra integration bootstrap " + generation))
	return Config{protocol, mode, securechannel.Key(static), securechannel.Key(ak), credential[:]}
}

func (c Config) Carrier() securechannel.Carrier {
	switch c.Protocol {
	case "tcp":
		return securechannel.TCP
	case "ws":
		return securechannel.WS
	case "wss":
		return securechannel.WSS
	default:
		return 0
	}
}

func (c Config) Context() securechannel.Context {
	out := securechannel.Context{Mode: securechannel.Returning, Carrier: c.Carrier(), ServerKeyID: 1, Scope: Scope, Epoch: 1, Handle: [8]byte{1}}
	if c.Mode == "bootstrap" {
		out.Mode, out.Epoch, out.Handle = securechannel.Bootstrap, 0, [8]byte{}
	}
	return out
}

func (c Config) Client() (securechannel.ClientConfig, error) {
	s, err := securechannel.NewStaticKey(c.Static)
	if err != nil {
		return securechannel.ClientConfig{}, err
	}
	cc := securechannel.ClientConfig{Context: c.Context(), ServerPublicKey: s.Public()}
	if c.Mode == "returning" {
		cc.AuthorizationKey = c.Authorization
	}
	return cc, cc.Context.Validate()
}

func (c Config) Server() (securechannel.ServerConfig, error) {
	if c.Mode != "bootstrap" && c.Mode != "returning" {
		return securechannel.ServerConfig{}, errors.New("invalid fixture mode")
	}
	s, err := securechannel.NewStaticKey(c.Static)
	if err != nil {
		return securechannel.ServerConfig{}, err
	}
	expires := time.Now().Add(time.Hour)
	sc := securechannel.ServerConfig{
		StaticKey: s, ServerKeyID: 1, Scope: Scope, Carrier: c.Carrier(), AllowBootstrap: c.Mode == "bootstrap",
		Lookup: func(ctx context.Context, wire securechannel.Context) (securechannel.Enrollment, error) {
			if ctx.Err() != nil || wire != c.Context() || c.Mode != "returning" {
				return securechannel.Enrollment{}, securechannel.ErrAuth
			}
			return securechannel.Enrollment{Key: c.Authorization, Principal: Principal, ExpiresAt: expires}, nil
		},
	}
	return sc, sc.Validate()
}

func (c Config) HelloCredential() []byte {
	if c.Mode == "bootstrap" {
		return append([]byte(nil), c.Credential...)
	}
	return nil
}

func (c Config) ChannelPolicy(ctx context.Context, id syntra.ChannelIdentity, cred []byte) (string, error) {
	wire := c.Context()
	if ctx.Err() != nil || id.Mode != wire.Mode.String() || id.Carrier != c.Protocol || id.Scope != Scope || id.Epoch != wire.Epoch || id.Handle != wire.Handle {
		return "", securechannel.ErrAuth
	}
	if c.Mode == "returning" && id.Principal == Principal && len(cred) == 0 {
		return Principal, nil
	}
	if c.Mode == "bootstrap" && id.Principal == "" && subtle.ConstantTimeCompare(cred, c.Credential) == 1 {
		return Principal, nil
	}
	return "", securechannel.ErrAuth
}

func Authorize(ctx context.Context, principal, method string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if principal != Principal {
		return syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "unaccepted test principal")
	}
	if method != EchoMethod && method != WaitMethod {
		return syntra.NewRpcError(syntra.ErrorCodePermissionDenied, "method denied")
	}
	return nil
}
