# Connecting Syntra 1.0

The SDK provides a core and socket-free session runtime, plus optional networking
packages selected by imports. Use managed clients/listeners and built-in carriers,
or supply ordered, message-oriented I/O. Syntra 1.0 (`syntra.1.0`) includes its
Noise handshake and encrypted record stream. The application provisions trusted
keys and configures credential and method policies.

The data path is:

```text
application RPC or notification payload
    -> internal protobuf Frame
    -> bounded frame stream inside authenticated encrypted records
    -> built-in carrier or application-supplied ordered.MessageIO
```

`syntra.Transport` is the internal frame boundary used by the session pump.
`ordered.Transport` implements it by encrypting outgoing frames and assembling
inbound frames from authenticated records. `MarshalFrame`, `UnmarshalFrame`,
and `LoopbackPair` are useful for internal embedding and tests; they do not
establish an encrypted connection by themselves.

## Record I/O contract

Custom record I/O implements:

```go
type MessageIO interface {
	ReadMessage(context.Context, []byte) ([]byte, error)
	WriteMessage(context.Context, []byte) error
	Close() error
}
```

Preserve message boundaries and order in each direction. Handshake messages
and subsequent ciphertext records each occupy one message. Do not combine or
split those messages at this interface. Encrypted records can contain parts of
a frame or multiple frames; the ordered driver handles frame assembly.

`ReadMessage(ctx, dst)` appends into `dst[:0]`. It must reject a message larger
than `cap(dst)` before reading or allocating its body, and must never return an
oversized allocation. `WriteMessage` must finish using its input before it
returns. Each direction has at most one I/O caller; reads and writes may run
concurrently. Both operations must return promptly when their context ends.

`Close` may run concurrently and must immediately interrupt both directions.
Make it safe for repeated calls. Errors must not contain credentials, keys,
payloads, or private diagnostics. A blocked implementation that ignores
cancellation or close can prevent session shutdown.

`connection.Connect` and `connection.Accept` take ownership of the supplied I/O,
including on failure. They compose `ordered.Client`/`Server` with the session
pump and retain the establishment deadline through readiness. Use their returned
client or serving result to observe the connection lifecycle.

## Provisioning and authentication

Use `securechannel.ClientConfig` and `securechannel.ServerConfig` to supply the
provisioned key material and exact public context. Obtain the server public key
through a trusted channel. The context binds scope, key identifier, mode, epoch,
handle and carrier identifier to the handshake. Scope bytes are exact; the SDK
does not normalize them.

Bootstrap mode uses the provisioned server key. Returning mode also requires
the authorization key associated with the provisioned context. Key storage,
issuance, expiry, revocation and rotation are application-owned. Lookup callbacks
must honor contexts and validate the current binding; parsing a context or
receiving the first handshake message is not identity proof.

The responder confirms client participation by authenticating a client record.
The encrypted hello supplies that record. `HostConfig.ChannelPolicy` then
receives fresh channel evidence and the explicit hello credential. Verify the
credential, apply current admission policy, check the intended principal binding,
and return a nonempty principal. Confirmed key possession alone does not select
the RPC principal. Bootstrap participation does not imply an enrollment.

`HostConfig.Authorize` runs before each method's handler effects. Nil denies
every method. A per-method denial can leave the connection usable; an
`UNAUTHENTICATED` result signals an invalid binding and ends the session after
a bounded denial drain. Handlers must respect their contexts.

**Optional terminal receipt:** `HostConfig.TerminalMethods` and
`ordered.Options.EnableTerminalReceipts` opt an authorized handler into
`CompleteTerminalReceipt(ctx, operation, expectedRevision)`. It fences ordinary
traffic, establishes a full-frame barrier before the configured authority's
conditional commit, and permits only one fixed result with fresh exact-owned
evidence, then closes. Call before mutation; a nil return reports complete local
writing, not peer receipt or joined cleanup. Both defaults are off; ordinary
withdrawal and `DisconnectPrincipal` remain immediate abort. The supported stock
composition is ordered/TCP; raw/custom paths without coordination, other stock carriers, and
hosts with Recovery reject before mutation. See
[implementation and authority contract](TERMINAL_RECEIPT_DESIGN.md) for the
1024-byte complete-frame bound, total deadline/teardown tail, typed adapter,
explicit last-observation race, and evidence limits. Authority callback contexts
are SDK-owned; bind application identity through the transition's scope and current
authority rather than assuming downstream request-context values are preserved.
The [bidirectional TCP fixture report](TERMINAL_RECEIPT_INTEROP.md) records its
exact run separately from the [manual integration handoff](TERMINAL_RECEIPT_HANDOFF.md).

## Run a client

The [README example](README.md#make-a-call) creates an establishment budget before
carrier setup and passes it to `connection.Connect`. Connect establishes
encryption, starts the root session and waits for validated `ServerReady` within
the original attempt deadline. It uses `ordered.Transport.EstablishmentContext`
for readiness; it does not start another attempt after the Noise handshake.

Connect's context bounds establishment only. A successful client owns an
independent run lifetime: always call its `Close`. `Wait(ctx)` observes the
sanitized terminal error; canceling that wait does not stop the connection.
`Done()` closes after the pump and owned cleanup finish. Do not call `Run` on
the embedded client. `Close` waits up to five seconds; on timeout, ownership is
retained and a later `Close` can join cleanup.

For direct session embedding, `OpenClient` constructs a client without I/O and
`Client.Run` is single-use. `Client.WaitReady` observes validated readiness or
termination. Preserve the ordered transport's original `EstablishmentContext`
when waiting for readiness. Readiness is a snapshot; a later call can still
observe a disconnect. A connection ID is diagnostic data, not an authenticator
or resume token.

`Call` takes a canonical `/package.Service/Method` name and opaque payload.
The SDK correlates requests, results and advisory cancellation. It does not
automatically reconnect. Managed networking can reconnect with explicit bounds;
neither layer replays arbitrary application calls.

## Managed networking

`network.New(network.DefaultConfig())` constructs a `Network` owner. It uses
ordinary Go goroutines, `net.Conn`, and Go runtime netpoll support, with no
independent reactor or scheduler. Importing the root or `securechannel` package
does not pull in `network`, `routes`, `proxy`, or the carrier implementations.

`Network.Client` registers one reconnect supervisor; `network.NewClient` creates
a standalone supervisor. Constructors return owners, not promises of readiness.
Use `Snapshot` and `WaitChange` to observe `CoreReady`, `Blocked`, `Exhausted`, or
shutdown. Calls without a usable generation fail immediately.

This helper takes a caller-owned Network, an explicitly provisioned TCP address,
and an input callback that returns fresh security and hello settings on every
attempt. The caller owns shutdown of the Network and client. The callback must
honor its context and return a TCP-bound context and trusted server key.

```go
package example

import (
	"net/netip"
	"time"

	"github.com/tinkle-org/syntra-go/network"
	"github.com/tinkle-org/syntra-go/routes"
)

func ManagedTCP(n *network.Network, address netip.AddrPort, inputs routes.Inputs) (*network.Client, error) {
	route := routes.Route{Kind: routes.TCP, Address: address}
	connector, err := routes.New(routes.RouteConfig{
		Routes:    []routes.Route{route},
		Allowlist: []routes.Endpoint{route.Endpoint()},
	}, inputs)
	if err != nil {
		return nil, err
	}
	return n.Client(network.ReconnectConfig{
		AttemptTimeout:          10 * time.Second,
		ReconnectBudget:         time.Minute,
		MaxAttempts:             5,
		BaseBackoff:             100 * time.Millisecond,
		MaxBackoff:              5 * time.Second,
		CloseTimeout:            time.Second,
		InitialNetworkAvailable: true,
	}, network.Connector(connector))
}
```

A connector has signature
`func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error)`.
It must return an already core-ready connection made by a carrier's Connect or
`connection.Connect`, and join work it starts before returning. Carry the same
budget through stream open, proxy, TLS, upgrade, Noise, hello, and Ready.
Never replace the budget or move a connection between owners.

Retry policy is finite and explicit. Only I/O, timeout, and closed failures retry
automatically; authentication, configuration, framing, protocol, and unknown
failures block until `Retry`. The outage budget includes initial pause/offline
time, backoff, attempts, and cleanup. `Retry` renews the outage/attempt allowance
and retains the backoff exponent until readiness.

`Call` returns `GenerationValue[[]byte]` or a sanitized `*network.CallError`.
Generation zero means no usable generation was admitted. A nonzero generation
with `OutcomeUnknown` means the peer might have observed the operation. No
application mutation is replayed. Retained application completions must check
`IsGenerationCurrent` before delivery.

### Built-in carriers and routes

| Carrier | Code | Setup |
| --- | --- | --- |
| TCP | `1` | `transport/tcp.Connect`, `Accept`, or `Dial`; managed `ListenTCP` |
| WS | `2` | `transport/websocket.Connect` / `Accept`; managed `ListenWS`; loopback binding, URL host, and peers only |
| WSS | `3` | TLS provider and single-use proof, then `ConnectTLS` / `AcceptTLS`; managed `ListenWSS` |
| HTTP candidate | `4` | `transport/http.ConnectStreams` or `Dial`; managed `ListenHTTP` |
| HTTPS candidate | `5` | TLS on both streams through `ConnectTLSStreams` / `ConnectTLSPair` or `Dial`; managed `ListenHTTPS` |

Codes `1..3` form the standard default policy. Codes `4/5` require per-config
`AllowHTTPCandidate` on both `securechannel.ClientConfig` and
`securechannel.ServerConfig`. The default context validators, encoders, parsers,
and handshake paths reject them. The opt-in does not change another
configuration or turn HTTP/HTTPS into default carriers.

`routes.New` / `NewWithSetup` require a homogeneous carrier and validate the
entire route list and allowlist before effects. Each invocation selects exactly
one endpoint in round-robin order and calls `Inputs` for fresh provisioning.
`NewCrossCarrier` / `NewCrossCarrierWithSetup` require an explicit
`CrossCarrierPolicy.PermittedCarriers`; WS is excluded. There is no within-attempt
fallback, redirect, discovery, trust learning, or retry after refusal.

Routes include direct TCP, WS, WSS, HTTP, HTTPS; TCP/WSS/HTTP/HTTPS tunnels; and
explicit HTTP forward routing. Direct and proxy socket addresses are numeric;
URL/HTTP authority remains a separate allowlisted identity. `proxy` supports
explicit SOCKS5 and HTTP CONNECT tunnels, preserving remote hostname resolution
and keeping hop credentials separate from the encrypted hello credential.
Proxy configurations and TLS providers must remain valid throughout connector
use. Close credential-owning proxy configurations after all uses finish.

### StreamHost and TLSProvider

`network.Config.StreamHost` can supply application-owned platform sockets:

```go
type StreamHost interface {
	Open(ctx context.Context, address string) (net.Conn, error)
}
```

`Open` returns a connected stream, honors cancellation, and joins dial/cleanup
work before returning. Ownership of any returned stream transfers even with an
error. `Network.Open(ctx, address, budget)` invokes this interface under the
original attempt and Network quotas, closes returned streams on failure, and
transfers successful streams to the connector. Without a configured host it
uses `TCPStreamHost` with `net.Dialer`. A bare `net.Conn` makes no TLS claim.

`network.TLSProvider` aliases `tlsstream.Provider`. Its `Connect` and `Accept`
wrap the exact supplied owned stream, authenticate TLS 1.3 for a provisioned
authority and role, negotiate `http/1.1`, disable early data, and preserve I/O
gates and cancellation. The provider must not redial, detach I/O, or implement
HTTP requests/responses. The carrier owns upgrade and HTTP association traffic;
Noise still authenticates encrypted records and the hello credential still
selects the application principal.

`tlsstream.NewStandardProvider(clientConfig, serverConfig)` provides this boundary
using `crypto/tls`; either role configuration may be nil. It clones configuration,
performs fresh certificate verification, disables resumption/tickets, and rejects
verification bypasses, incompatible versions/ALPN, dynamic server configs, and
key logging. Application callbacks and keys must be concurrency-safe and honor
the handshake context; current trust/revocation policy remains application-owned.

`tlsstream.Connect` / `Accept` return a single-use `Verified` value bound to
authority, role, and the same attempt budget. Carriers consume it before HTTP
bytes. Its metadata is a trusted local observation: an arbitrary provider can
lie about TLS, and the wrapper cannot supply remote cryptographic proof that
the provider performed it. See [SECURITY.md](SECURITY.md).

HTTP/HTTPS use two distinct persistent streams, upload and download, for one
canonical authority and association. The download lane is serviced continuously
while idle; it does not depend on issuing an RPC. Native HTTP sends no cookies
or HTTP authentication. Origin is absent by default; accepting a present Origin
requires an exact explicit policy. HTTP responses acknowledge carrier admission,
not application completion or durable delivery.

### Managed listeners and shutdown

`Network.ListenTCP`, `ListenWS`, and `ListenWSS` take `ListenerConfig`, including
server security, explicit `Host.ChannelPolicy`, host authorization/handler,
options, and a positive `MaxConnections`. Supply a bind address or a
`net.Listener` (ownership transfers on successful construction).
WSS also requires `TLS` and `Authority`. `ListenHTTP` / `ListenHTTPS` take
`transport/http.ServerConfig` with explicit authority, candidate security, host
policy, options, and finite server limits; HTTPS requires TLS for both streams.

Listeners expose `LocalAddr`, value `Snapshot`s, fenced `NotifyAll` /
`NotifyDirected`, controls, `CloseContext`, and `Done`. The Network supplies FIFO
shared connection admission; `ListenerConfig.Admission` can add a bound shared
across Networks. TCP/WS/WSS listeners hold at most one accepted socket awaiting
shared admission and read no establishment bytes before admission. HTTP acquires
shared admission after a validated open header, before its handshake body or
credential lookup; idle and download-attachment streams do not acquire extra
association permits. Native HTTP limits also bound pre-association sockets,
TLS handshakes, associations, reserved bytes, and open rates.

`network.DefaultConfig()` bounds operations to 256, shared connections to 128,
and callbacks/execution leases to 128. Service owners, calls, stream opens, and
notification waits share the operation quota. `ReconnectConfig.MaxCalls` bounds
concurrent calls and notification waits per client (default 128). Callback work
and permits remain charged through actual return and complete teardown.

`Pause`, `Resume`, `NetworkAvailable`, and `PlatformWake` retire current sessions
and partial establishment. Parent pause/offline controls take precedence over
client controls. An individually stopped service stays stopped. `Stop` initiates
teardown; `Shutdown(ctx)` and `CloseContext(ctx)` bound the caller's wait, not the
owned work's lifetime. An incomplete report/error retains ownership. `Done`
closes only after actual completion. `Report.LiveCallbacks` and
`LiveExecutions` can overlap and must not be added together.

### Receiving live updates

Running root and connection clients receive automatically through
`Notifications()`, without issuing RPCs. `LossTotals` / `WaitLossChange` expose
the generic queue's dropped count and bytes. Managed clients continuously drain
those notifications and expose `NextNotification(ctx)` returning a
`GenerationValue[network.Notification]`. Each wait snapshots one generation and
cannot move into a successor; concurrent consumers share its queue.

The managed queue defaults to 128 notifications and 4 MiB. Overflow drops the
newest payload. `Status` and delivered notifications contain cumulative
generation-local `DroppedCount` / `DroppedBytes`; nil payload denotes loss-only
delivery. Loss observations do not acknowledge delivery or provide durable
catch-up. Use typed recovery when updates must be persisted and recovered.

`Network.Events()` is a separate bounded lifecycle log with independent cursors.
`Events.Next(ctx)` reports `EventLossError` for overwritten entries, then
continues at the oldest retained event. `Snapshot` / `WaitChange` remain available
independently of log consumption.

## Run a host

This helper serves one supplied I/O endpoint using `connection.Accept`. Pass
`ordered.Options{Budget: budget}` when carrier setup used an earlier budget.
The application provides callbacks that verify the explicit credential with
confirmed channel evidence and authorize the bound principal for the method.

```go
package example

import (
	"context"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func ServeEcho(ctx context.Context, records ordered.MessageIO,
	encryption securechannel.ServerConfig, opts ordered.Options,
	authenticate syntra.ChannelPolicy, authorize syntra.AuthorizeFunc,
) error {
	if authenticate == nil || authorize == nil {
		_ = records.Close()
		return syntra.NewRpcError(syntra.ErrorCodeInvalidArgument, "policies required")
	}
	host, err := syntra.OpenHost(syntra.HostConfig{
		ChannelPolicy: authenticate,
		Authorize:     authorize,
		Handler: func(ctx context.Context, req *syntra.RpcRequest) (*syntra.RpcResult, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if req.GetMethod() != "/example.Echo/Echo" {
				return nil, syntra.NewRpcError(syntra.ErrorCodeUnimplemented, "unknown method")
			}
			return syntra.NewSuccessResult(req.GetPayload()), nil
		},
	})
	if err != nil {
		_ = records.Close()
		return err
	}
	defer host.Close()

	return connection.Accept(ctx, records, encryption, host, opts)
}
```

`connection.Accept` blocks for the connection lifetime and joins carrier cleanup
before returning. Its context governs both establishment and the active session.
The original attempt deadline bounds authentication policy and the ready write,
then retires without limiting the activated session. The caller owns the host.

For multiple connections, share one `Host` across concurrent `Accept` calls.
Each call creates independent session state. `HostConfig.ExecutionBudget` bounds
authentication, handlers and recovery egress workers; nil uses the process-wide
1,024-slot budget. `Host.Close` closes the host and current sessions.

`connection.NewServer` optionally owns the host and admission. Pass each
application-supplied endpoint to `Server.Accept(ctx, records, opts)`.
`ServerOptions.MaxConnections` includes pending handshakes, defaults to 128,
and permits at most 4,096. `Server.Close` stops admission, cancels connections,
closes carriers and the host, and joins within `ShutdownTimeout` (default and
maximum five seconds). `Wait` and `Done` observe eventual shutdown completion
if that wait times out. The embedder still owns carrier setup and deployment-wide
resource controls.

## Budgets and ownership

`ordered.Options` defaults to a 15-second establishment attempt, a shared
five-second Noise/encrypted-hello phase, ten-second writes, 30-second record and
frame budgets, and a 24-hour channel lifetime. Time options can be shortened.
`MaxPending` includes active and waiting operations per direction: default 32,
maximum 1,024. Excess admission returns `ErrBusy`.

Create `ordered.NewEstablishmentBudget(nil, timeout)` before application carrier
setup, use its `Context` for setup, then pass the same pointer through
`ordered.Options.Budget` to Connect or Accept. A budget is single-use; timeout
must be positive and no more than 15 seconds. A trusted elapsed clock can replace
nil when the embedder manages lifecycle continuity. If the budget is omitted,
the attempt begins at Connect or Accept. The deadline is retained through
encryption, hello, authentication policy and readiness.

Ciphertext records are limited to 65,535 bytes, including a 16-byte tag. The
plaintext frame stream carries a four-byte length prefix; a serialized frame
is limited to 1 MiB including its protobuf envelope. The separate payload size
limit does not reserve envelope overhead. Channels also enforce a maximum of
2^32 records per direction.

Root sessions default to a five-second hello/authentication/ready budget,
30-second RPC timeout and 120-second maximum RPC timeout. Default outstanding
RPC capacity is 32; supported configured capacities are 16 through 1,024.
The host's asynchronous writer defaults to a 256-frame queued-plus-active cap
and also enforces an 8 MiB byte cap. Saturation terminates the connection;
successful queue admission is not acknowledgement. `HostConfig.WriteTimeout`
defaults to ten seconds and bounds a complete post-handshake send. The ordered
driver's `WriteTimeout` also defaults to ten seconds across all records in that
frame. A failed or timed-out write terminates the connection.

Close interrupts record I/O before joining operations and clearing scratch.
`ordered.Transport.CloseContext` bounds the caller's wait; a timeout does not
mean cleanup has completed. A later `Close` can still join it. Keep callbacks
and I/O cancellation-aware, and observe serving/run results during shutdown.

## Attaching update recovery

Recovery is an optional, explicitly configured capability within Syntra 1.0.
Its typed payloads travel through ordinary encrypted RPCs and notifications.
Application payload/state bytes remain opaque; the SDK imports no
application-domain schemas and does not replay arbitrary application mutations.

On the client, call `NewRecoveryClient` with the root client, the authenticated
principal's persistence namespace, application `RecoveryPersistence`, and
validated `RecoveryLimits`. Construction attaches one immutable inbox. It must
happen before `Client.Run`; a second attachment or attachment after Run starts
fails. With `connection.Connect`, supply a `ClientConfig.Prepare` callback of
type `func(*syntra.Client) error` and construct the recovery client there,
retaining it for subsequent operations. Prepare runs once before `OpenClient`
returns and before transport I/O; an error closes the partially built client.

After Connect returns ready, call `RecoveryClient.Negotiate` for
`syntra.update-recovery/1`. A validated successful negotiation response enables
runtime ingress routing before the response waiter wakes. Until negotiation,
ordinary notifications retain their ordinary behavior. Once enabled, the
runtime routes recovery notifications into the attached inbox before the
generic lossy queue. Mixed payload protocols require explicit demultiplexing.
A closed attachment never falls back to ordinary notification delivery on the
same connection. Replace the connection when replacing the identity context.

For managed recovery, construct `network.NewRecoveryFactory` with a principal
namespace, application persistence, limits, and negotiation request. Set
`ReconnectConfig.RecoveryFactory` and use `Network.ClientWithSetup` or
`network.NewClientWithSetup`. A `ConnectorWithSetup` must compose the supplied
preparer into `ClientConfig.Prepare`, invoke it exactly once before Run for the
returned client, and propagate errors. `routes.NewWithSetup` and
`NewCrossCarrierWithSetup` do this composition; convert their result to
`network.ConnectorWithSetup` when passing it to the owner.

Every generation attaches a fresh recovery client and negotiates a fresh profile.
Required recovery retains the original establishment budget through negotiation;
calls and profile access stay unavailable until `RecoveryNegotiated`. `CoreReady`
alone does not imply recovery readiness, restored subscriptions, or catch-up.
`RecoveryClient()` returns a generation-tagged session; the standard factory
returns `*network.RecoveryProfile` with its typed core recovery client. Check
`IsGenerationCurrent` again before delivering retained profile results.

On the host, construct `RecoveryService` with application `RecoverySource` and
limits, then set `HostConfig.Recovery` before creating the host, including when
using `connection.NewServer`. After authentication, the runtime opens a
`RecoveryHostSession` bound to that connection's ID, principal and version. It
dispatches recovery methods, manages notification egress through the owning
connection's bounded writer, revalidates before admission, and closes and joins
the recovery session on teardown. Normal per-method `Authorize` runs before
every recovery operation; the source also authorizes stream operations.

Host callbacks can obtain the runtime-owned binding with
`RecoveryHostSessionFromContext` for connection-scoped `Publish` calls.
Publication still revalidates authority and continuity. A nil
`HostConfig.Recovery` leaves recovery methods unsupported; enabling the service
does not bypass explicit capability negotiation.

Subscribe with an explicit intent: initial live-only, resume durable state, or
snapshot the current generation. Stable stream identity comes from the
application. Selectors and connection-local handles are not durable identities.
Replay and catch-up preserve the captured boundary; retention misses can require
a snapshot without inventing a new generation.

The client offers a batch through `NextEvent`. Build the full replacement
application state and call `Persist`, which atomically commits that state with
generation `G` and checkpoint in the principal/stream scope. Then call `Confirm`.
For snapshots, fetch and stage all pages, obtain `SnapshotBytes`, construct and
persist the complete installed state, and then call `SnapshotConfirm`.

`RecoveryPersistence.Commit` uses generation/checkpoint compare-and-swap; nil
expected means no record may exist. An exact duplicate of the full record is a
no-op. A durable implementation must commit application state and position at
one persistence point. `CommitUnknown` fences recovery: close the affected
connection, reload, and reconcile on a fresh connection instead of blindly
retrying the application write or sending confirmation.

`RecoveryProgress` reports local durability, confirmation submission and peer
acknowledgement independently. Bounded retries apply only to the recovery
operations designed for exact retries; they do not cover arbitrary RPCs or
application writes. `MemoryRecoveryStore` is a bounded volatile reference.
Application effects outside the persistence transaction need their own
consistency contract; the SDK makes no exactly-once guarantee.
