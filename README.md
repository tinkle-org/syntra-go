# Syntra Go

Go implementation of Syntra v1 with generated Protobuf types, bounded codecs,
client/host sessions, reliable-session and recovery helpers, and experimental
SC1 draft-1 channels over TCP, WebSocket and secure WebSocket.

**SC1 is an implementation-specific draft, not an accepted upstream profile or
an independently audited secure channel.** Read [SC1.md](SC1.md) for the exact
wire format and runnable examples, and [AUDIT.md](AUDIT.md) for implementation
evidence, limitations and unresolved upstream questions. The core `Frame`
schema is unchanged. Schema and fixture provenance is in
[MIGRATION.md](MIGRATION.md).

## Install

```sh
go get github.com/tinkle-org/syntra-go
```

```go
import (
    syntra "github.com/tinkle-org/syntra-go"
    syntrav1 "github.com/tinkle-org/syntra-go/gen/syntra/v1"
)
```

Use **Go 1.26.10** for production builds and current verification. The module's
**Go 1.23.0** floor and CI's Go 1.23.12 lane establish API/build compatibility;
they are not a secure-runtime recommendation. Production binaries must be built
with a security-patched toolchain. The Go 1.26.10 scan found zero reachable
vulnerabilities in the analyzed root module; see [SECURITY.md](SECURITY.md#dependencies-and-assurance).

Select the recommended toolchain for the commands below with
`export GOTOOLCHAIN=go1.26.10`. Current dependency pins are:

| Dependency | Version |
| --- | --- |
| `google.golang.org/protobuf` | v1.36.6 |
| `github.com/flynn/noise` | v1.1.0 |
| `github.com/coder/websocket` | v1.8.15 |
| `golang.org/x/crypto` (indirect) | v0.38.0 |
| `golang.org/x/sys` (indirect) | v0.33.0 |

There are no releases yet; future releases use root `vX.Y.Z` tags.

## Default: pure Go

The default build needs neither CGO nor a native library. `go get` fetches Go
sources only; this module never downloads native binaries. In this build,
`NativeAvailable()` returns false and `CheckABI()` returns nil.

```sh
CGO_ENABLED=0 go build -mod=readonly ./...
CGO_ENABLED=0 go test -mod=readonly -count=1 ./...
```

## APIs and scope

| Area | APIs / source |
|---|---|
| Wire types | `gen/syntra/v1/*.pb.go`, with core aliases such as `Frame`, `RpcRequest`, and `RpcResult` in package `syntra` |
| Protocol core | `syntra.go`: bounds, `RpcError`, frame/handshake/RPC validation, encoding/decoding, handshake machine, correlation tracking |
| Sessions | `Transport`, `LoopbackPair`, `OpenClient`, `Client.Run`, `Client.Call`, `OpenHost`, `Host.Serve`, `HandlerFunc` and explicit authorization in `session.go` |
| Notifications | `Host.NotifyAll`, `Host.NotifyDirected`, `Client.Notifications`, `LossTotals`, `WaitLossChange` |
| Channel authentication | `ChannelIdentityProvider`, `ChannelIdentity`, `ChannelPolicy`, `Host.DisconnectPrincipal` |
| Ready-to-call connections | `connection.DialTCP`, `DialWebSocket`, `Connect`, `Client.Wait`/`Done`/`Close`; low-level `syntra.Client.WaitReady` |
| Admission-controlled servers | `connection.NewServer`, `Server.ServeTCP`, `WebSocketHandler`, `ServerOptions`, `Server.Close` |
| Socket-free SC1 | `securechannel.Begin`, `Initiator.Finish`, `Respond`, `Channel`, `Context`, `AppendContext`, `ServerConfig.Check` |
| Ordered encrypted frames | `transport/ordered.Options`, `Transport.Send`, `Recv`, `Close`, optional carrier `Ping` |
| TCP carrier | `transport/tcp.Client`, `Server`, `Dial` |
| WS/WSS carrier | `transport/websocket.Accept`, `Dial`, `Options` |
| Reliable sessions | `ReliableManager`, identity/epoch validation, leases, and bounded in-memory control state in `reliable.go` |
| Recovery helpers | `DurableStore`, `MemoryStore`, `DuplicateCache`, `StagedSnapshot`, and `CheckpointReconciler` in `recovery.go` |
| Core backends | `native_purego.go` by default; `native.go` with `-tags syntranative` |

`Transport.Send` and `Recv` exchange exactly one serialized `Frame` at a time.
The supplied SC1 adapters add encrypted record framing and bounded socket I/O.
Applications may supply another `Transport` that meets the same boundary,
cancellation, close and receive-allocation contracts. Upstream's production
TLS baseline remains in effect; this experimental draft does not supersede it.

Credential verification is host-owned. `CredentialPolicy` verifies opaque
hello bytes and returns a nonempty principal; a nil policy rejects admission.
For SC1, `HostConfig.ChannelPolicy` replaces that policy and requires freshly
confirmed channel evidence. It must explicitly verify the hello credential,
the current enrollment and the intended principal binding. A channel principal
does not implicitly authorize an empty hello credential.

`HostConfig.Authorize` runs before every method's handler effects. **Nil selects
`DenyAllAuthorize`.** Use a principal-aware policy, or `AllowAllAuthorize` for an
explicit allow-all deployment. `StaticPolicy` is a test/example convenience,
not a credential verifier. A permission denial leaves the connection usable;
an expired/revoked binding reported as `UNAUTHENTICATED` cancels other callbacks,
attempts a 200ms drain of the queued RPC error, then closes the connection.
`DisconnectPrincipal` closes current matching
connections, including idle push-only connections; admission policy must also
deny future connections.

### Connect and call

Use `connection.NewServer(hostConfig, channelConfig, connection.ServerOptions{})`
and `server.ServeTCP(ctx, listener)` to accept TCP connections. `NewServer`
requires an explicit `ChannelPolicy`; nil `Authorize` still denies methods.
The client is ready to call when dialing succeeds:

```go
client, err := connection.DialTCP(ctx, address, channelConfig,
    syntra.ClientConfig{Credential: credential}, ordered.Options{})
if err != nil {
    return err
}
defer client.Close()
result, err := client.Call(ctx, "/example.Echo/Echo", []byte("hello"), 1000)
```

Imports are `github.com/tinkle-org/syntra-go/connection`, the root package as
`syntra`, and `github.com/tinkle-org/syntra-go/transport/ordered`. The complete
[executable example in SC1.md](SC1.md#executable-example-explicit-same-principal-policy)
includes provisioning fixtures, an explicit same-principal channel/root policy,
`ServerConfig.Check` before ready and per-method authorization. It also shows
`DialWebSocket` with `Server.WebSocketHandler`.

Dialing has a **10-second total establishment budget**, including socket/upgrade,
SC1 and core readiness, shortened by the caller's context. Each SC1/core
handshake retains its own five-second limit. The returned client's lifetime is
independent of the dial context: always close it; use `Wait` or `Done` to observe
termination. There is no automatic reconnect, RPC replay or fallback.

`ServerOptions` defaults to **128 connections and 16 handshakes**, with maxima
of 4,096 and 256. Connection admission includes handshakes; the handshake slot
is held through SC1, core hello/policy and the ready write. Shutdown joins owned
listeners, raw handshake sockets and sessions within a default/max **five-second**
budget. WS/WSS callers also own HTTP header limits/timeouts, TLS configuration
and HTTP shutdown. See [SC1.md](SC1.md#connection-orchestration) for ownership
and lower-level `Connect`/`WaitReady` APIs.

After hello/ready, each host connection uses an asynchronous FIFO writer.
Queued plus active writes are bounded to **256 frames and 8 MiB**; saturation
terminates `Serve` with `RESOURCE_EXHAUSTED`. The session loop continues
cancellation, deadline and dispatch work during a socket stall. Each write
defaults to a five-second timeout; shutdown cancels/closes I/O and joins the
writer with a one-second bound, subject to the transport's close contract.

Application payload schemas, identity systems, messenger subscriptions,
presence, JSON gateways, service discovery and gRPC clients are outside the
module's scope. There is no HTTP/HTTPS request-response transport planned;
HTTP is used for the WebSocket upgrade. UDP is deferred. Reliable-session
helpers do not claim exactly-once effects or make arbitrary RPC retries safe.
Recovery cursors and payloads stay opaque; the helpers are not a complete
subscription/recovery service.

### Resource and compatibility behavior

- A serialized frame is limited to 1 MiB, including envelope overhead. A
  payload at the separate 1 MiB payload limit can therefore fail encoding.
  Failed request encoding does not reserve a call slot or start its timer.
- The pure-Go host admits a notification only while its per-connection shared
  outbound backlog has fewer than 256 frames and the resulting serialized
  backlog is at most 8 MiB. Saturation rejects the newest notification with
  `RESOURCE_EXHAUSTED`; terminal RPC results remain admissible to that core
  queue. The separate host-writer cap covers all queued/active outbound frames,
  including terminal results. Its 8 MiB budget is distinct from the core's
  8 MiB notification admission budget.
  `NotifyAll` and `NotifyDirected` aggregate per-connection enqueue failures
  with `errors.Join` (inspectable with `errors.As`); only successful enqueues
  wake their pumps. No matching connections is a no-op, and successful enqueue
  is not acknowledgement or delivery. `NotifyDirected` isolates principals,
  not individual subscriptions belonging to the same principal.
- SC1 limits ciphertext records to 65,535 bytes and plaintext to 65,519 bytes;
  the encrypted frame stream may span records. Lifetime is at most 24 hours
  or 2^32 records per direction. Pending transport operations default to 32
  per direction, configurable up to 1,024. See [SC1.md](SC1.md) for exact clocks,
  cancellation requirements and revocation checks.
- Unknown fields alongside a known body are tolerated. Unknown top-level
  content without a known body yields `UNIMPLEMENTED`; a genuinely empty body
  yields `INVALID_ARGUMENT`. Body tags are 10–15; 16–17 remain reserved. The
  upstream distinction between unknown bodies and metadata remains unresolved
  in upstream RFC 0001 B5. Reserved tags 16–17, duplicate body/outcome fields,
  malformed unknown fields and nesting beyond depth 32 are rejected by the
  bounded codec on decode and emission; opaque payload bytes are not parsed.

## Optional native backend

`-tags syntranative` selects the CGO adapter to the Rust production
core. It requires CGO, a C compiler, and a compatible `syntra-ffi` library built
with `--features production`. The adapter declares the C ABI inline in
`native.go`, so compiling Go does not require a C header checkout or include
path. The authoritative ABI header lives with the Rust implementation at
`crates/syntra-ffi/include/syntra_production.h`.

With a compatible Rust checkout at sibling `../syntra-rs`, run these commands
from this repository root. `LIBDIR` is absolute so the linker and loader see
the same directory even when Go executes package tests elsewhere:

```sh
SYNTRA_RS="$(realpath ../syntra-rs)"
CARGO_TARGET_DIR="$SYNTRA_RS/target" cargo +1.88.0 build --manifest-path "$SYNTRA_RS/Cargo.toml" --locked -p syntra-ffi --features production
LIBDIR="$SYNTRA_RS/target/debug"
```

Linux:

```sh
CGO_ENABLED=1 CGO_LDFLAGS="-L$LIBDIR" \
  LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
  go test -mod=readonly -tags syntranative -count=1 ./...
```

Darwin:

```sh
CGO_ENABLED=1 CGO_LDFLAGS="-L$LIBDIR" \
  DYLD_LIBRARY_PATH="$LIBDIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
  go test -mod=readonly -tags syntranative -count=1 ./...
```

The tag alone does not supply the library. `CheckABI()` verifies production ABI
version 1. Owned output buffers are released through `syntra_ffi_free`; handles
are closed once. FFI-layer status failures and per-RPC error frames remain
separate. The test-fixture loopback ABI is not the production adapter ABI.
Native CI builds the production library from
[`syntra-rs` commit `fca1063515d3966be71e9844346e7cbc53769c76`](https://github.com/tinkle-org/syntra-rs/commit/fca1063515d3966be71e9844346e7cbc53769c76)
and runs the native-tagged tests and race detector. Keep this immutable pin
in sync through reviewed changes when the native dependency is updated.

SC1 carriers remain Go implementations with either core backend. ABI v1
does not accept handler-completion timestamps or expose explicit post-hello
credential release. The pure-Go completion-publication fix therefore does
not establish identical native deadline arbitration or secret lifetime;
see [AUDIT.md](AUDIT.md#remaining-gaps-and-audited-todos).

## Generate and check

Generated files are committed under `gen/`. Use Buf CLI **1.59.0**, the remote
Go plugin **v1.36.6 revision 1**, and `paths=source_relative`, as pinned in
`buf.gen.yaml`. All eight logical schema paths have explicit Go import mappings
to this module. The `.proto` snapshots and embedded descriptors intentionally
retain their original `go_package` option; do not rewrite them by hand.

```sh
buf generate --template buf.gen.yaml
python3 scripts/check-generated.py
```

The drift check uses Python's standard library and generates into a temporary
directory, then compares the complete `.pb.go` file set and bytes. It requires
Buf and access to its remote plugin service, but no local `protoc` or Rust.
`session.proto` and `capabilities.proto` produce descriptor-only Go files.

Run from the repository root:

```sh
gofmt -l .                         # must print nothing
go test -mod=readonly -count=1 ./...
CGO_ENABLED=0 go test -mod=readonly -count=1 ./...
go vet -mod=readonly ./...
go test -mod=readonly -race -count=1 ./...
```

CI uses Go **1.26.10**, with Go **1.23.12** for API/build compatibility only.
Root tests and benchmarks require no Docker. See
[BENCHMARKS.md](BENCHMARKS.md) for timing boundaries and benchmark commands;
separate container tooling is documented in
[tests/integration/README.md](tests/integration/README.md).

Tests include Protobuf vectors, schema fixtures, unit regressions and local
carrier integration tests. Same-library Noise checks and native-core tests
are not independent Rust SC1 interoperability or a security audit. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
