# SC1 draft-1 implementation

This document describes the implementation in `securechannel/` and
`transport/{ordered,tcp,websocket}/`. **SC1 draft-1 is an implementation-specific
draft. It has not been accepted upstream or independently security-audited.**
The domain and WebSocket subprotocol below identify this draft only.

The upstream design reference is [RFC 0007 at specification commit
`e27fa275f647ccc925b7cf79eb2dd332f20a3d02`](https://github.com/tinkle-org/syntra/blob/e27fa275f647ccc925b7cf79eb2dd332f20a3d02/rfcs/0007-secure-channel-device-authorization.md).
That proposal leaves wire and lifecycle decisions for review; this document
records the concrete local choices without asserting upstream conformance.
See [AUDIT.md](AUDIT.md) for evidence and outstanding work.

Use **Go 1.26.10** for current verification and production builds, for example
`export GOTOOLCHAIN=go1.26.10` before running the commands below. Production
binaries require a security-patched toolchain. The Go 1.23 module floor and
Go 1.23.12 CI lane are API/build compatibility checks, not security
recommendations. See [SECURITY.md](SECURITY.md#dependencies-and-assurance) for
the zero-reachable-vulnerability scan on Go 1.26.10 and its limits.

## Construction and trust

| Mode byte | API constant | Noise name | Client material |
| --- | --- | --- | --- |
| 1 | `securechannel.Bootstrap` | `Noise_NK_25519_ChaChaPoly_SHA256` | Authenticated, pinned server public key; no authorization key |
| 2 | `securechannel.Returning` | `Noise_NKpsk0_25519_ChaChaPoly_SHA256` | Same server pin plus a provisioned 32-byte authorization key |

Both modes use X25519, ChaCha20-Poly1305 and SHA-256 through
`github.com/flynn/noise v1.1.0`. `GenerateStaticKey` and `GenerateKey` use
`crypto/rand`; each handshake uses fresh Noise ephemeral randomness. There is
no deterministic RNG option, cipher-state serialization, nonce restoration,
in-place rekey, suite negotiation or automatic downgrade/fallback. Reconnect
always performs a fresh handshake and starts new ordered cipher states.

Bootstrap requires `ServerConfig.AllowBootstrap`. It authenticates the pinned
server, **not an enrolled client principal**. Returning mode proves possession
of a high-entropy authorization key. Neither a public handle nor successful
M1 processing alone establishes a freshly confirmed client session. A replayed
M1 may elicit M2, but cannot confirm the responder's new channel without an
authenticated client record under the new keys. The encrypted `ClientHello`
normally supplies that first record. No application data is carried in either
Noise handshake payload.

The server pin and endpoint scope must come from an authenticated provisioning
source. Scope is an exact UTF-8 identifier, not a URL-derived identity; there
is no Unicode or URL normalization. Context bytes, handles, lengths, timing
and carrier metadata are public. Protecting payloads does not hide them.

## Canonical context: `AppendContext`

All offsets are zero-based, and ranges are half-open. Let
`D = len("syntra.sc1.draft1") = 17` and `S = len([]byte(Scope))`.

| Offset | Bytes | Field |
| --- | ---: | --- |
| `[0,D)` | 17 | Exact ASCII domain `syntra.sc1.draft1`, with no terminator |
| `[D,D+1)` = `[17,18)` | 1 | Mode: bootstrap 1, returning 2 |
| `[D+1,D+2)` = `[18,19)` | 1 | Carrier: TCP 1, WS 2, WSS 3 |
| `[D+2,D+6)` = `[19,23)` | 4 | `ServerKeyID`, unsigned big-endian u32 |
| `[D+6,D+14)` = `[23,31)` | 8 | `Epoch`, unsigned big-endian u64 |
| `[D+14,D+22)` = `[31,39)` | 8 | `Handle`, opaque bytes |
| `[D+22,D+24)` = `[39,41)` | 2 | Scope byte length, unsigned big-endian u16 |
| `[D+24,D+24+S)` = `[41,41+S)` | S | Exact valid UTF-8 scope bytes; 1–255 bytes |

The total is **`len(domain) + 24 + S`**, or 42–296 bytes. There is no padding,
optional field or trailing content. `ParseContext` requires the exact declared
length. Bootstrap requires zero epoch and an all-zero handle; returning mode
requires a nonzero epoch and a handle that is not all zero. `ServerKeyID` has
no nonzero constraint. Carrier, scope and server-key ID must match the server's
configuration.

These canonical bytes are both the public prefix of M1 and the complete Noise
prologue. Altering any field changes the authenticated handshake context.

## Handshake and record wire format

- **M1:** canonical context followed by exactly 48 Noise bytes (32-byte
  ephemeral public key and the 16-byte tag for an empty handshake payload).
  Its total size is `len(context) + 48`, or 90–344 bytes.
- **M2:** exactly 48 Noise bytes, with an empty handshake payload.
- **Transport record:** 1–65,519 plaintext bytes plus a 16-byte AEAD tag:
  17–65,535 ciphertext bytes. Empty plaintext records are rejected.

### TCP

Every message, **including M1 and M2**, is encoded as:

```text
u16BE(message byte length) || message bytes
```

The length excludes its own two bytes. TCP packet boundaries have no meaning.
Partial reads/writes and coalesced packets are handled by the adapter. Zero
lengths, over-capacity handshake messages and incomplete messages fail.

### WebSocket and secure WebSocket

Each binary WebSocket **message** contains exactly one M1, M2 or ciphertext
record. There is **no SC1 u16 prefix** inside it. WebSocket fragmentation is
reassembled by `coder/websocket`; WebSocket frames are not SC1 records. Text,
oversized, truncated and unauthenticatable messages fail. Compression is
disabled. The exact, case-sensitive subprotocol `syntra.sc1.draft1` is required.
Control ping/pong messages stay outside SC1 application data; `Transport.Ping`
requires a concurrent `Recv` to process the pong.

`websocket.Dial` accepts explicit `ws://` or `wss://` URLs and refuses redirects.
For inspectable `*http.Transport` clients it clones TLS settings, requires
certificate verification and enforces TLS 1.3 or newer. A custom RoundTripper
owns its TLS policy. Servers configure TLS themselves. `Accept` uses `r.TLS`
to distinguish WS from WSS and does not trust forwarded headers to change the
authenticated carrier. Configure origin admission through `OriginPatterns`;
the default retains the library's same-origin checks.

There is no HTTP/HTTPS request-response transport or plan for one in this
implementation. HTTP is used only for the WebSocket upgrade. UDP is deferred.

### Authenticated frame stream

The plaintext stream in each direction is:

```text
u32BE(serialized Frame byte length) || serialized Frame || next prefix || ...
```

Serialized frames are 1–1,048,576 bytes (1 MiB). The four-byte frame length is
encrypted with the frame stream and may itself span records. Frames may span
records; a receiver also accepts multiple frame envelopes in one record.
`Send` serializes a whole envelope against other sends, and `Recv` returns one
owned frame at a time. Receivers validate lengths before frame allocation.

The core Protobuf `Frame` schema is unchanged. Application payloads remain
opaque. AEAD associated data for transport records is **empty**: neither the
TCP length header nor WebSocket framing is passed as ciphertext header AD.
Those outer boundaries delimit records; authenticated stream ordering and the
encrypted u32 frame length protect reconstruction. Tampering is terminal,
not a resynchronization opportunity.

## Limits, cancellation and ownership

`ordered.Options` applies to TCP directly and to WebSocket through
`websocket.Options.Limits`:

| Option | Zero/default | Accepted nonzero range |
| --- | --- | --- |
| `HandshakeTimeout` | 5s | Positive, at most 5s |
| `WriteTimeout` | 5s | Positive, at most 5s |
| `FrameTimeout` | 5s | Positive, at most 5s |
| `RecordTimeout` | 5s | Positive, at most 5s |
| `Lifetime` | 24h | Positive, at most 24h |
| `MaxPending` | 32 | 1–1,024 |

`MaxPending` includes the active operation in each direction. Excess admission
fails immediately with `ordered.ErrBusy`; admitted waiters honor cancellation.
Send and receive are serialized independently, permitting full duplex.

Dial's handshake budget includes connection establishment/upgrade and SC1.
On an established carrier the handshake has one absolute budget. An idle
record read has no assembly timeout until its first wire byte; then the
record clock includes partial headers and all fragments. The frame clock
begins at the first authenticated frame-prefix byte, including bytes buffered
with a preceding frame, and is never refreshed by later records. Caller
deadlines can shorten all operations. A successful handshake does not bind
the transport lifetime to that handshake context.

The adapter enforces an absolute lifetime, including handshake time, even on
an idle socket. The channel also refuses use at 24h or after **2^32 records in
either direction**, and observes the initial enrollment expiry. There is no
automatic reconnect or key rotation. Reconnect requires a fresh handshake.

TCP `Client` and `Server` take ownership of the supplied `net.Conn`, including
on handshake failure. `Dial` and WebSocket `Accept`/`Dial` return an owned
`*ordered.Transport`. `Client.Run` and `Host.Serve` then own their transport
on the running session's terminal paths. Close is abortive: it immediately
starts socket shutdown, cancels work, joins operations and lifecycle checking,
clears reusable scratch and releases cipher-state references. It does not
wait for a graceful WebSocket close handshake. Completion of `Close` is bounded
by the underlying I/O and host `Lookup` honoring cancellation; Go cannot
forcibly stop a callback that violates that contract.

Malformed received records, authentication failure and I/O failure after
encryption terminate the transport. No retry may reuse consumed nonces. A
locally rejected plaintext length in the socket-free `Channel.Encrypt` does
not consume a nonce. Public errors deliberately avoid secret-bearing carrier
diagnostics; they do not promise constant-time lookup or denial behavior.

## Credential records and session policy

`ServerConfig.Lookup(ctx, context)` is a host-owned, read-only lookup into a
protected store. Records are scoped by the full provisioned routing tuple
(server-key ID, carrier, exact scope, handle and epoch), and contain:

- A nonzero 32-byte `Enrollment.Key` and a nonempty `Principal`.
- A **required**, nonzero, future `ExpiresAt`.
- A `Revoked` flag that denies admission when set.

The key and principal for a handle/epoch must be immutable. A different key
needs a new enrollment tuple: `ServerConfig.Check` rechecks validity and
principal, but does not compare the current key with the handshake key.
Lookup must honor its context and must never create/update an enrollment in
response to a handshake. Unknown, expired, revoked and invalid returning
records all deny authentication; invalid records still take a Noise
verification path with random substitute material.

After the first authenticated client record, the adapter triggers a check
and checks again on a **one-second ticker**, each lookup bounded by a
**one-second context**. Failure aborts even an idle confirmed connection.
Ticker scheduling plus lookup latency means this is not a promise of exact
one-second revocation propagation. Before confirmation, the absolute lifetime
still applies. Hosts should use `DisconnectPrincipal` when they need an
explicit immediate disconnect as well as rejecting future admissions.

`ChannelIdentityProvider` exposes confirmed channel evidence. It does not
automatically assign an RPC identity. `HostConfig.ChannelPolicy`, when set,
replaces `Policy`, requires fresh channel confirmation, and sees the explicit
`ClientHello.credential`. An empty credential never implicitly means “use the
channel principal.” The host verifies its root/application identity separately,
checks that it is the **same principal**, and checks current channel validity
and admission policy **before ServerReady**. The periodic checker is not a
substitute for this admission check. Every method still needs `Authorize`;
nil selects `DenyAllAuthorize`.

### Provisioning boundary and audited TODO

**Only explicit authenticated out-of-band provisioning is supported.** The
host generates the authorization key with `GenerateKey` and independently
generates a random eight-byte handle with `crypto/rand`, rejecting zero and
checking collisions in the scoped store. A handle must not be a key prefix,
hash of a key, principal-derived value or counter.

Store transactionality, secure delivery, client acknowledgement, retry/recovery
after lost delivery, protected client storage, revocation dissemination and
rotation workflow are host responsibilities. This module implements **no
enrollment RPC or end-to-end issuance/rotation workflow**. Bootstrap does not
implement one implicitly. These are open integration/audit TODOs, not completed
security features.

## Executable example: explicit same-principal policy

Save the following as a Go file outside the repository packages, then run it
from the module root with `go run /absolute/path/to/example.go tcp` or `ws`.
`connection.NewServer` owns session orchestration and admission;
`DialTCP`/`DialWebSocket` return ready-to-call clients. The in-process fixture
simulates already authenticated out-of-band provisioning; it is not an
issuance protocol or persistent store.

```go
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
	scws "github.com/tinkle-org/syntra-go/transport/websocket"
)

func main() {
	carrier := "tcp"
	if len(os.Args) == 2 {
		carrier = os.Args[1]
	}
	if err := run(carrier); err != nil {
		log.Fatal(err)
	}
}

func run(kind string) error {
	if kind != "tcp" && kind != "ws" {
		return fmt.Errorf("choose tcp or ws")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	static, err := securechannel.GenerateStaticKey()
	if err != nil {
		return err
	}
	ak, err := securechannel.GenerateKey()
	if err != nil {
		return err
	}
	var rootCredential [32]byte // Independent application identity credential.
	if _, err := rand.Read(rootCredential[:]); err != nil {
		return err
	}
	const principal = "example-device"
	const method = "/example.Echo/Echo"
	route := securechannel.Context{
		Mode: securechannel.Returning, Carrier: securechannel.TCP,
		ServerKeyID: 7, Epoch: 1, Scope: "example/echo",
	}
	if kind == "ws" {
		route.Carrier = securechannel.WS
	}
	store := make(map[securechannel.Context]securechannel.Enrollment)
	for { // Independent random handle, with scoped collision rejection.
		if _, err := rand.Read(route.Handle[:]); err != nil {
			return err
		}
		if route.Handle == ([8]byte{}) {
			continue
		}
		if _, exists := store[route]; !exists {
			break
		}
	}
	store[route] = securechannel.Enrollment{
		Key: ak, Principal: principal, ExpiresAt: time.Now().Add(time.Hour),
	}
	sc := securechannel.ServerConfig{
		StaticKey: static, ServerKeyID: route.ServerKeyID,
		Scope: route.Scope, Carrier: route.Carrier,
		Lookup: func(ctx context.Context, c securechannel.Context) (securechannel.Enrollment, error) {
			if err := ctx.Err(); err != nil {
				return securechannel.Enrollment{}, err
			}
			return store[c], nil // Immutable fixture; a real store checks every tuple field.
		},
	}
	cc := securechannel.ClientConfig{
		Context: route, ServerPublicKey: static.Public(), AuthorizationKey: ak,
	}
	deny := func() error {
		return syntra.NewRpcError(syntra.ErrorCodeUnauthenticated, "credential not accepted")
	}
	verifyRoot := func(ctx context.Context, credential []byte) (string, error) {
		if ctx.Err() != nil || subtle.ConstantTimeCompare(credential, rootCredential[:]) != 1 {
			return "", deny()
		}
		return principal, nil
	}
	authorize := func(ctx context.Context, p, m string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if p != principal || m != method {
			return syntra.NewRpcError(syntra.ErrorCodePermissionDenied, "access denied")
		}
		return nil
	}
	hostConfig := syntra.HostConfig{
		ChannelPolicy: func(ctx context.Context, id syntra.ChannelIdentity, credential []byte) (string, error) {
			if id.Mode != "returning" || id.Carrier != route.Carrier.String() || id.Scope != route.Scope {
				return "", deny()
			}
			current := route
			current.Handle, current.Epoch = id.Handle, id.Epoch
			checkCtx, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			if sc.Check(checkCtx, securechannel.Peer{Context: current, Principal: id.Principal}) != nil {
				return "", deny()
			}
			p, err := verifyRoot(ctx, credential) // Verify separately from the channel AK.
			if err != nil || p == "" || p != id.Principal {
				return "", deny()
			}
			// Current admission for this echo-only service, before ServerReady.
			if err := authorize(ctx, p, method); err != nil {
				return "", err
			}
			return p, nil
		},
		Authorize: authorize, // Rechecked for every method invocation.
		Handler: func(_ context.Context, req *syntra.RpcRequest) (*syntra.RpcResult, error) {
			return syntra.NewSuccessResult(req.GetPayload()), nil
		},
	}
	server, err := connection.NewServer(hostConfig, sc, connection.ServerOptions{})
	if err != nil {
		return err
	}
	defer server.Close()
	coreConfig := syntra.ClientConfig{Credential: rootCredential[:]}
	var client *connection.Client
	var served chan error
	switch kind {
	case "tcp":
		listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
		if listenErr != nil {
			return listenErr
		}
		served = make(chan error, 1)
		go func() { served <- server.ServeTCP(ctx, listener) }()
		client, err = connection.DialTCP(ctx, listener.Addr().String(), cc, coreConfig, ordered.Options{})
	case "ws":
		httpServer := httptest.NewServer(server.WebSocketHandler())
		defer httpServer.Close()
		client, err = connection.DialWebSocket(ctx,
			"ws"+strings.TrimPrefix(httpServer.URL, "http"), cc, coreConfig, scws.Options{})
	}
	if err != nil {
		return err
	}
	defer client.Close()
	// Dial has already validated ServerReady; no core pump or warmup RPC is needed.
	out, err := client.Call(ctx, method, []byte("hello"), 1000)
	if err != nil {
		return err
	}
	fmt.Println(string(out)) // hello
	if err := client.Close(); err != nil {
		return err
	}
	if err := server.Close(); err != nil {
		return err
	}
	if served != nil {
		return <-served // ServeTCP owns and closes its listener.
	}
	return nil
}
```

For WSS, provision `Carrier: securechannel.WSS`, serve TLS on the accepting
server, and dial `wss://` with the appropriate certificate trust. The Noise
server pin remains required independently of TLS certificate validation.

## Connection orchestration

`connection.DialTCP` and `DialWebSocket` establish the socket/upgrade, SC1 and
validated core `ServerReady` within one **10-second total budget**, shortened
by the caller. The adapter and core hello/policy/ready exchange retain their
own five-second handshake limits. A successful client's run lifetime is
independent of its dial context. Close it explicitly; `Client.Close` cancels
and joins for at most five seconds. `Done` observes completion, and `Wait(ctx)`
returns a sanitized terminal error; canceling a wait does not close the client.
Readiness is a snapshot, not a guarantee against a subsequent disconnect.

`connection.NewServer` requires an explicit `HostConfig.ChannelPolicy` and
owns its host. Method authorization remains fail-closed. Use one server per
fixed carrier (TCP, WS or WSS), with these `ServerOptions`:

| Option | Zero/default | Accepted nonzero range |
| --- | --- | --- |
| `MaxConnections` | 128 | 1–4,096, including handshakes |
| `MaxHandshakes` | 16 | 1–256, through SC1, core hello/policy and the successful ready write |
| `ShutdownTimeout` | 5s | Positive, at most 5s |
| `TCP` | `ordered.Options{}` | Adapter limits above |
| `WebSocket` | `websocket.Options{}` | Adapter limits plus origin/HTTP-client options |

Admission is shared across that server's connections. Excess TCP sockets close
before a connection goroutine starts; excess WS/WSS upgrades receive HTTP 503.
These are concurrent admission limits, not connection-rate limits.
`ServeTCP` owns its listener; cancellation, listener failure or `Server.Close`
stops the server and joins admitted sockets/sessions within its shutdown budget.
`WebSocketHandler` uses the server lifecycle after upgrade, not `r.Context()`.
The application owns the HTTP server's header limits, header timeout and TLS,
and must call the connection server's `Close` as well as HTTP shutdown because
HTTP shutdown does not close hijacked sockets. Server close includes raw
half-handshake sockets. A cancellation-violating callback/transport may yield
`connection.ErrShutdownTimeout`; the budget does not forcibly terminate it.

For lower-level control, `tcp.Client`/`Server` wrap caller-supplied `net.Conn`
endpoints, `tcp.Dial` opens a socket, and WebSocket `Accept`/`Dial` perform their
carrier handshake. `connection.Connect` takes an established `syntra.Transport`,
owns it even on failure, and starts/joins the client pump while waiting for
core readiness. Alternatively, `syntra.Client.WaitReady` waits for a validated
ready exchange when the caller separately runs `Client.Run`; it performs no
I/O itself and returns failure after session termination. These helpers do not
reconnect, replay RPCs, retry enrollment or fall back between modes/carriers.

### Post-ready host writer

After hello/ready, `Host.Serve` uses one asynchronous FIFO writer per connection.
Admission snapshots serialized bytes and never waits for socket I/O. Queued
plus active writes are bounded to **256 frames and 8 MiB**, including terminal
results and notifications. Saturation terminates `Serve` with
`RESOURCE_EXHAUSTED`; a failed/timed-out send also terminates the connection.
`HostConfig.WriteTimeout` defaults to five seconds per send. The session loop
continues dispatch, cancellation and deadline work during a blocked write.

This writer budget is separate from the pure-Go core's notification admission
budget (256 frames/8 MiB shared backlog). Notification enqueue success reports
admission, not transport completion or peer acknowledgement. On authorization
revocation, the host cancels other callbacks, enqueues the denial and attempts
an actual-send drain for up to **200ms** before closing; delivery can fail.
Writer shutdown cancels its context, closes transport I/O and joins for up to
**one second** after transport close. Custom transports must honor cancellation
and return promptly from `Close`.

## Secret lifetime and assurance limits

`Key` diagnostic formatting is redacted; generated hello messages, raw buffers
and arbitrary application logging are not automatically redacted. Do not log
credentials, whole hellos, authorization keys or private keys.

The code clears accessible ephemeral private buffers and reusable record
scratch, drops handshake/cipher references, and releases Go hello credential
references after emission or close. **Go and the Noise library do not guarantee
erasure of all internal copies**, expanded cipher keys, compiler temporaries or
garbage-collected memory. The native ABI also lacks an explicit post-hello
credential-release operation. These constraints and the completion-timestamp
ABI gap remain in [AUDIT.md](AUDIT.md#remaining-gaps-and-audited-todos).

Local tests cover canonical encoding, negative handshakes, fresh confirmation,
record failures, framing, limits, cancellation, TCP sockets and WS/WSS. Tests
against a separately configured instance of the same Noise library are useful
integration checks; they are not independent Rust interoperability or a
cryptographic audit. Benchmarks and separate tooling are documented in
[BENCHMARKS.md](BENCHMARKS.md).
