# Syntra Go

Transport-independent Go implementation of the Syntra v1 protocol, extracted
from the existing Go module in [`tinkle-org/syntra`](https://github.com/tinkle-org/syntra).
It includes generated Protobuf types, validation and codec helpers, client/host
sessions, and the existing reliable-session and recovery helpers.

This extraction preserves the source snapshot's APIs and behavior. It does
not add a Noise or SC1 implementation. See [MIGRATION.md](MIGRATION.md) for the
exact source commit, import migration, and schema/fixture provenance.

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

The module requires Go 1.22 or newer and pins
`google.golang.org/protobuf v1.36.6`. There are no releases in this repository
yet; future releases will use root `vX.Y.Z` tags. Old nested-module tags do not
version this module.

## Default: pure Go

The default build needs neither CGO nor a native library. `go get` fetches Go
sources only; this module never downloads native binaries. In this build,
`NativeAvailable()` returns false and `CheckABI()` returns nil.

```sh
CGO_ENABLED=0 go build -mod=readonly ./...
CGO_ENABLED=0 go test -mod=readonly -count=1 ./...
```

## Existing APIs and scope

| Area | APIs / source |
|---|---|
| Wire types | `gen/syntra/v1/*.pb.go`, with core aliases such as `Frame`, `RpcRequest`, and `RpcResult` in package `syntra` |
| Protocol core | `syntra.go`: bounds, `RpcError`, frame/handshake/RPC validation, encoding/decoding, handshake machine, correlation tracking |
| Sessions | `Transport`, `LoopbackPair`, `OpenClient`, `Client.Call`, `OpenHost`, `Host.Serve`, `Host.NotifyAll`, `HandlerFunc`, and `StaticPolicy` in `session.go` |
| Reliable sessions | `ReliableManager`, identity/epoch validation, leases, and bounded in-memory control state in `reliable.go` |
| Recovery helpers | `DurableStore`, `MemoryStore`, `DuplicateCache`, `StagedSnapshot`, and `CheckpointReconciler` in `recovery.go` |
| Core backends | `native_purego.go` by default; `native.go` with `-tags syntranative` |

`Transport.Send` and `Recv` exchange exactly one serialized `Frame` at a time.
Socket I/O, TCP/WebSocket framing, and TLS belong to transport adapters supplied
by the application. Production traffic retains the source snapshot's TLS
baseline. These APIs do not provide a Noise-record transport.

Credential verification is host-owned: `CredentialPolicy` accepts opaque bytes
and resolves an opaque principal. Per-method authorization uses
`HostConfig.Authorize` before handler effects. A nil hook preserves the existing
allow-everything behavior, which differs from the Rust handler's fail-closed
default. Set `DenyAllAuthorize` for fail-closed behavior or
`AllowAllAuthorize` for an explicit allow policy.

Application payload schemas, credential formats, messenger subscriptions,
presence, JSON gateways, service discovery, and gRPC clients are outside the
module's scope. Reliable-session helpers do not claim exactly-once effects or
make arbitrary RPC retries safe. Recovery cursors and payloads stay opaque.

### Resource and compatibility behavior

- A serialized frame is limited to 1 MiB, including envelope overhead. A
  payload at the separate 1 MiB payload limit can therefore fail encoding.
  Failed request encoding does not reserve a call slot or start its timer.
- The pure-Go host admits notifications while its per-connection shared
  outbound backlog has fewer than 256 frames. Saturation rejects the newest
  notification with `RESOURCE_EXHAUSTED`; terminal RPC errors and expiry results
  remain admissible. Draining restores admission; each queued frame is bounded
  to 1 MiB. `Host.NotifyAll` ignores per-connection core errors, so a nil result
  is not proof of enqueue or delivery.
- Unknown fields alongside a known body are tolerated. Unknown top-level
  content without a known body yields `UNIMPLEMENTED`; a genuinely empty body
  yields `INVALID_ARGUMENT`. Body tags are 10–15; 16–17 remain reserved. The
  upstream distinction between unknown bodies and metadata remains unresolved
  in RFC 0001 B5; this extraction does not introduce a new discriminator.

## Optional native backend

`-tags syntranative` selects the existing CGO adapter to the Rust production
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

CI uses Go **1.26.4**. Tests include the copied Protobuf conformance vectors and
`tests/schema/fixtures/frames.json`; passing them is not a claim of full
cross-language or native conformance. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[SECURITY.md](SECURITY.md).
