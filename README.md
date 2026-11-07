# Syntra Go

Syntra Go is a pure-Go SDK for Syntra 1.0 (`syntra.1.0`). It provides a core and
socket-free session runtime, encrypted connections, credential-based session
admission, concurrent RPCs, notifications, and optional typed update recovery.
Import `network`, `routes`, `proxy`, and the carrier packages to add managed
networking. The networking layer uses ordinary Go goroutines and Go's netpoll
support; it does not create its own reactor or scheduler runtime.

Noise encryption is integral to Syntra 1.0. The generated protobuf `Frame` is
the internal envelope carried inside encrypted records. Encoding a `Frame`
alone does not establish a Syntra connection or define a plaintext protocol.

Applications can supply ordered record I/O or use the built-in carriers and
managed clients/listeners. Trusted key provisioning, credential verification,
per-method authorization, identity, and persistence belong to the application.

## Install

```sh
go get github.com/tinkle-org/syntra-go
```

The module requires Go 1.23.0 or later. CI uses Go 1.26.10 for current checks and
Go 1.23.12 for compatibility. Build deployed applications with a security-patched
toolchain. The compatibility floor is not a runtime security recommendation.

## Make a call

This helper takes an application callback that establishes `ordered.MessageIO`,
a provisioned encryption configuration, and an explicit hello credential. One
budget covers carrier setup, encryption, authentication and readiness. The peer
must serve `/example.Echo/Echo` and authorize that method. `connection.Connect`
owns the supplied I/O and returns a ready client; the helper makes one call and
closes the client.

```go
package example

import (
	"context"
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/connection"
	"github.com/tinkle-org/syntra-go/securechannel"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func Echo(ctx context.Context, setup func(context.Context) (ordered.MessageIO, error),
	encryption securechannel.ClientConfig, credential []byte,
) ([]byte, error) {
	budget, err := ordered.NewEstablishmentBudget(nil, 15*time.Second)
	if err != nil {
		return nil, err
	}
	establish, cancel := budget.Context(ctx)
	defer cancel()

	records, err := setup(establish)
	if err != nil {
		return nil, err
	}
	client, err := connection.Connect(establish, records, encryption,
		syntra.ClientConfig{Credential: credential}, ordered.Options{Budget: budget})
	if err != nil {
		return nil, err
	}
	defer client.Close()
	return client.Call(ctx, "/example.Echo/Echo", []byte("hello"), 1000)
}
```

The final argument to `Call` is the requested timeout in milliseconds. Zero
selects the configured default. Cancellation and timeouts do not roll back
application effects or establish that retrying is safe.

See [CONNECTION.md](CONNECTION.md) for the I/O contract, host setup, readiness,
ownership, and limits.

## Packages and session APIs

- `network.New(network.DefaultConfig())` creates a bounded owner for managed
  clients and listeners. `Network.Client` supervises reconnects;
  `ListenTCP`, `ListenWS`, `ListenWSS`, `ListenHTTP`, and `ListenHTTPS` own
  listeners, admission, sessions, and teardown.
- `routes` builds allowlisted, one-endpoint-per-attempt connectors with fresh
  security inputs. `proxy` provides explicit bounded tunnels and hop credentials.
- `transport/tcp`, `transport/websocket`, and `transport/http` implement carriers;
  `transport/tlsstream` wraps owned streams using application TLS or its
  `StandardProvider`. `transport/stream` supplies shared stream I/O gates.
- `connection` composes encryption and session readiness with `Connect` and
  `Accept`. `NewServer` optionally owns a host and bounds admitted connections.
- The root `syntra` package contains frame validation and codecs, `OpenClient`,
  `Client.Run`, `Client.WaitReady`, `Client.Call`, `OpenHost`, and `Host.Serve`.
- `securechannel` implements the protocol's Noise handshake, identity evidence,
  encrypted records, and bounded frame assembly.
- `transport/ordered` connects that encryption to application-owned
  `MessageIO` and exposes a frame-level `syntra.Transport` to sessions.
- `gen/syntra/v1` contains generated protobuf messages for internal envelopes
  and typed recovery payloads.

The root and `securechannel` dependency graphs exclude the optional networking
packages. The standard carrier codes are TCP `1`, WS `2` (loopback only), and
WSS `3`. HTTP `4` and HTTPS `5` are explicit candidates: both peers must set
`AllowHTTPCandidate` on their own security configuration. Default validation,
parsing, encoding, and handshakes reject those candidates. Cross-carrier route
selection requires an explicit policy and excludes WS. See
[managed networking](CONNECTION.md#managed-networking) for setup and ownership.

`HostConfig.ChannelPolicy` verifies confirmed channel evidence and the explicit
hello credential, returning the principal to bind to the session. When it is
configured, it replaces `HostConfig.Policy`. A channel principal does not
automatically authenticate the hello credential. Missing credential policy
denies admission; missing `HostConfig.Authorize` denies every method.

`HostConfig.Authorize` runs for every method before handler effects. Handlers
receive a context bounded by the call budget and must stop and join their own
work when it ends. Return `NewSuccessResult` for success or a typed `RpcError`
with safe public text for a method failure.

### Optional request-wide host cap

`HostConfig.RequestBudget` is an optional `RequestBudgetFunc`:

```go
func(principal, method string, payload []byte) (time.Duration, bool)
```

It runs for live application requests after envelope/method/payload bounds and
before `Authorize`, outside protocol locks and raw I/O. It must be pure, prompt,
bounded and concurrency-safe;
do not perform authorization, storage or network work. Payload is untrusted opaque
borrowed data: do not mutate or retain it. Built-in `RecoveryMethodPrefix` routes
skip this application selector and retain their original read-only budget and
trusted-clock enforcement. Already-expired or invalid original budgets also skip
the selector; application policy cannot rescue them. The SDK has no
application-specific method names, payload schema, or terminal-operation duration
built in.

Returning `false` leaves timeout selection unchanged; nil disables selection.
Returning `true` selects a cap measured from **original complete-frame receipt**,
including receive-queue time, selector execution and initial authorization. Zero
expires immediately; a negative duration (including negative arithmetic overflow)
fails closed without authorization. Larger caps never extend the peer timeout,
default timeout, `MaxTimeout`, or an earlier serving-context deadline. Duration
addition against the trusted elapsed origin is checked for overflow. The core's
expiry/cancel/result decisions and callback context share the selected deadline.
There is no timer reset at handler or terminal reservation entry. Missing
`Authorize` still denies every method, and built-in recovery keeps its normal
authorization and routing.

`RequestBudgetFromContext(ctx) (RequestBudget, bool)` exposes read-only SDK timing
to authorizers, handlers and terminal authority adapters. `Deadline()` returns the
selected Go deadline; `Remaining()` and `Err()` also check trusted elapsed time
when the driver supplies `TerminalReceiptDriver.TerminalClock`. The clock's age
is captured at frame receipt before queueing or authorization, so time spent
suspended is not forgiven at terminal reservation. Discontinuity, regression and
invalid elapsed arithmetic fail closed. Drivers without that clock retain normal
context/wall timing; this does not grant unsupported terminal receipt capability.
Ordinary expiry cancellation is supervised at the existing 10-ms pump cadence;
callback boundaries and terminal decisions check the budget independently.

Adapters must honor their callback context as well as this SDK budget: a child
context or an individual observation can have an earlier deadline. Timeout does
not undo durable external work. Noncooperative callbacks retain their execution
charges until actual return and cannot restore expired receipt eligibility.

Every terminal authority callback, including periodic driver refresh observations
whose parent has no request values, receives a derived SDK budget. Commit's
budget excludes the teardown tail. Observe's budget is additionally clamped by
the per-read timeout and any earlier parent context/budget. Its `Deadline()`
matches the actual callback context deadline; both reflect the permit's wall and
trusted elapsed cutoffs immediately, rather than relying only on later watchdog
polling. Derivation retains the original clock origin and never extends an
absolute elapsed cutoff. Legacy/manual permits without a captured request budget
derive directly from their actual absolute permit cutoffs.

This adds a field to exported `HostConfig`; use keyed composite literals.
Downstream unkeyed literals can require a source update.

`Host.NotifyDirected` targets all connections of a principal. `Host.NotifyAll`
broadcasts to active connections. Successful enqueue is not a delivery
acknowledgement. Running clients receive live updates automatically through
`Notifications()` even when no RPC is issued. Ordinary notifications use a
bounded, lossy queue; `LossTotals` and `WaitLossChange` expose loss observations.
Managed clients continuously drain that queue and expose generation-bound
`NextNotification(ctx)`, with dropped-count and dropped-byte totals. Those
generation-local counters are not durable recovery checkpoints.

## Optional terminal receipt

An explicitly authorized self-withdrawing operation can call
`CompleteTerminalReceipt(ctx, operation, expectedRevision)` inside its handler.
It requires fixed non-sensitive bytes and a typed conditional-transition authority
in `HostConfig.TerminalMethods`, plus `ordered.Options.EnableTerminalReceipts`.
Both are disabled by default. Call it before mutation; the configured authority's
`Commit` performs the conditional transition. `terminal_receipt.go` also requires
a confirmed Returning-mode channel binding: Bootstrap rejects before reservation
or mutation, even with successful authentication, method authorization, and both
opt-ins. The SDK fences ordinary traffic and reaches a full outbound-frame
boundary first, then attempts only the exact owned
result and closes. A nil return means complete local writing, not peer receipt or
joined cleanup. Loss remains unknown; nothing is automatically retried or replayed.

The verified stock composition is ordered/TCP, including connection ownership
wrappers. Other stock carriers, uncoordinated custom paths, and hosts with Recovery
reject before mutation. See [the implementation contract and fixture](TERMINAL_RECEIPT_DESIGN.md)
for authority evidence, the 1024-byte complete-frame limit, deadline/teardown
budgets, and last-observation race. Existing clients parse the same `RpcResult`;
there is no new wire message or peer option. Ordinary withdrawal and
`Host.DisconnectPrincipal` are unchanged. The
[20-case bidirectional fixture report](TERMINAL_RECEIPT_INTEROP.md) is bounded SDK
evidence, not production durability or application acceptance. See the
[handoff](TERMINAL_RECEIPT_HANDOFF.md) for manual merge/release and consumer order.

## Optional update recovery

Recovery uses typed RPC and notification payloads within the same encrypted
protocol. Set `HostConfig.Recovery` to a `RecoveryService`; the runtime opens and
manages a recovery session for each authenticated connection. On the client,
`NewRecoveryClient` attaches one immutable inbox before `Client.Run`. With
`connection.Connect`, construct it in `ClientConfig.Prepare`. After readiness,
explicitly negotiate `syntra.update-recovery/1` to enable recovery traffic.
Managed clients use a configured recovery factory and pre-Run preparer to attach
and negotiate a fresh recovery profile for every connection generation;
`CoreReady` and `RecoveryNegotiated` are separate states.

The APIs cover subscriptions, replay, catch-up, confirmation, snapshot transfer,
and unsubscribe. `RecoveryInbox` routes recovery traffic before the ordinary
lossy notification queue. Host sessions bind handles to one authenticated
connection and recheck stream authorization and generation. See
[CONNECTION.md](CONNECTION.md#attaching-update-recovery) for setup and lifecycle.

The application implements `RecoverySource` for stream history, issued-checkpoint
validation, publication ordering, and immutable snapshots. It implements
`RecoveryPersistence` to commit the full opaque application state with its
position. `PersistenceScope` contains the principal namespace and stable stream;
`DurableRecord` contains generation `G`, checkpoint, and full application state.
`Commit` compares the expected generation/checkpoint and updates the whole record
atomically. A nil expected position requires absence; an exact full-record
duplicate is a no-op.

Persist a batch or complete snapshot before confirming it. `RecoveryProgress`
keeps locally durable, confirm-sent, and peer-acknowledged positions separate.
`CommitUnknown` requires reload and reconciliation on a fresh connection. The
bounded `MemoryRecoveryStore` is volatile. Recovery does not provide exactly-once
application effects or make arbitrary RPC replay safe.
The SDK treats application state and payloads as opaque bytes and imports no
application-domain schemas.

## Development

```sh
CGO_ENABLED=0 go build -mod=readonly ./...
CGO_ENABLED=0 go test -mod=readonly -count=1 ./...
go vet -mod=readonly ./...
go test -mod=readonly -race -count=1 ./...
go test -mod=readonly -race -count=1 ./network ./routes ./proxy ./transport/...
```

Generation uses Buf 1.59.0 and the Go protobuf plugin v1.36.6 revision 1. The
protobuf runtime is v1.36.6. Generated output is committed under `gen/`.

```sh
buf generate --template buf.gen.yaml
python3 scripts/check-go-package.py
python3 scripts/check-generated.py
```

CI checks Buf `FILE` compatibility except `FILE_SAME_GO_PACKAGE`; the local
package check enforces canonical `go_package` options in compiled descriptors.
The required network integration lane uses real loopback sockets without Docker,
checks structured test execution, and runs alongside dependency-isolation and
default candidate-rejection checks.

Read [CONTRIBUTING.md](CONTRIBUTING.md) for checks,
[BENCHMARKS.md](BENCHMARKS.md) for measurement boundaries,
[SECURITY.md](SECURITY.md) for security responsibilities and private reports,
and [AUDIT.md](AUDIT.md) for verification scope and evidence limits.
