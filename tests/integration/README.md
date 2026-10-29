# SC1 container integration tests

This is a separate Go module with a Go 1.26.0 language floor. Use the patched
Go 1.26.10 toolchain (also pinned in the fixture builder), a **running Docker
daemon**, and permission to build images/create
containers and networks. The root library retains its own Go version and has no
Testcontainers/Docker dependency. `replace github.com/tinkle-org/syntra-go => ../..`
tests the current worktree, including uncommitted production changes.

From this directory:

```sh
export GOTOOLCHAIN=go1.26.10

# Compile all test packages and the fixture without contacting Docker:
go test -mod=readonly -run '^$' ./...
go build -mod=readonly -o /tmp/syntra-integration-peer ./cmd/peer
go vet -mod=readonly ./...

# Include the integration harness's test-only helper dependencies in the scan:
govulncheck -test ./...

# Run the real suite (missing/unhealthy Docker FAILS; it never skips):
go test -mod=readonly -count=1 -timeout=10m -v ./...

# Narrow to one carrier/mode while still requiring containers:
go test -mod=readonly -count=1 -timeout=10m -v -run '^TestSC1/tcp/returning$' .
```

The fixture image can also be built manually from the **repository root**:

```sh
docker build -f tests/integration/Dockerfile -t syntra-integration-peer .
docker build -f tests/integration/Dockerfile --target toxiproxy -t syntra-integration-toxiproxy .
```

The multi-stage Dockerfile pins `golang:1.26.10` to its multi-platform manifest
digest and uses scratch runtimes. The harness builds the peer and Toxiproxy images
once per suite from the root context, then reuses one immutable provisioned peer per carrier/mode
group. Each test opens its own connection. Peers, fault proxies, the custom
network and the built image are cleaned up. Replacement peers in the restart
cases have newly provisioned static/enrollment keys and newly generated TLS
material; mapped endpoints are rediscovered rather than assumed stable.

## Coverage

All three production adapters (`transport/tcp`, `transport/ordered`, and
`transport/websocket`) are used directly with root `Client`/`Host` sessions.
There is no dependency on a high-level connection wrapper.

For **TCP, WS, WSS**, in both **returning and bootstrap** mode:

- Structured listener-bound readiness followed by real SC1 handshake, confirmed
  ClientHello/ServerReady and echo RPC; port readiness alone cannot pass.
- Echo of empty, 64 KiB and `MaxFrameBytes - 128` byte payloads (near the serialized
  envelope limit, spanning multiple encrypted records).
- Sixteen concurrent 64 KiB echo callers with independent payload checks.
- Cancellation and deadline of a server-observed pending handler, completion
  observation and successful subsequent RPC on the same connection.
- Explicit per-method authorization denial and continued usability.
- Rejection of an incorrect server static key; returning mode additionally
  rejects an incorrect authorization key. Bootstrap rejects empty/wrong explicit
  hello credentials. Rejection is observed in a server-local policy event; the
  client sees terminal `UNAVAILABLE` because the schema has no pre-ACTIVE typed
  authentication-error carrier.
- Closing the client with sixteen observed pending RPCs, and stopping/replacing the
  server with a pending RPC. Calls must finish within a bounded wait. After
  replacement, stale static/enrollment material fails and fresh material works.
- WSS verifies a dynamically generated private test CA and hostname with TLS 1.3
  required at both ends. Wrong hostname and untrusted CA fail. Verification is
  never disabled.

For each returning-mode carrier, released Testcontainers/Toxiproxy `v0.44.0`
and Shopify client `v2.12.0` inject a downstream indefinite stall and a TCP reset
through the `toxiproxy` Dockerfile target. That target builds the released server
from the checksum-verified `github.com/Shopify/toxiproxy/v2@v2.12.0` module using
its own locked dependencies. The upstream GHCR image denies anonymous pulls in
the development environment, so both local and CI tests use this source build.
Each test first proves a real RPC works,
then asserts bounded failure, removes its toxic, and proves a fresh session
works. The proxy and peer share a custom Docker network; both control/data host
endpoints use `Host()` + `MappedPort()` (including remote Docker hosts).

HTTP/HTTPS are not protocol test targets; HTTP is used only as the WS upgrade
mechanism and Toxiproxy control plane. UDP is excluded. This suite does not yet
cover packet-level tampering, malformed-record fuzzing, enrollment revocation,
automatic reconnection/backoff, or exhaustive fault combinations. Restart means
a replacement fixture with rotated provisioning, not transparent session resume.

## Logs and CI

Set `SYNTRA_INTEGRATION_LOG_DIR` to retain at most 128 KiB of output per image build and
64 KiB of logs per container. Provisioning files, certificates and private keys
are never artifacts; fixture output contains structured lifecycle events and
neutral numeric call tokens only. Keys are deterministic **test-only** inputs;
TLS key material is randomly generated per peer, copied into its container and
trusted only by that peer's test client.

`.github/workflows/integration.yml` runs on a Docker-capable Ubuntu runner and
uploads bounded logs when present. It is a separate check; branch protection
must require `Integration / integration` if integration should gate merging.

`.github/workflows/benchmarks.yml` runs the root module's full in-memory benchmark
suite with `go test -mod=readonly -run '^$' -bench . -benchmem -count=3
-benchtime=100ms -cpu=1,4 -timeout=10m ./...`, including wire/session, WebSocket
net.Pipe and securechannel cases, and uploads raw samples plus revision/toolchain.
Timing is report-only: no fixed ns/op threshold, container benchmark or baseline
comparison gate is used. Benchmark execution errors still fail the job.

## Local verification status

Latest run: 2026-10-28, Docker Desktop 4.84.0 / Engine 29.6.2, Linux arm64
containers, Go 1.26.10 host and fixture-builder toolchains, current worktree.

```text
GOTOOLCHAIN=go1.26.10 go test -mod=readonly -count=1 -timeout=10m -v ./...
--- PASS: TestSC1 (36.00s)
ok github.com/tinkle-org/syntra-go/tests/integration 36.236s
```

All six carrier/mode groups and all three returning-mode Toxiproxy stall/reset
pairs passed, with no skips. This includes image builds, real handshakes/RPCs,
trusted WSS/TLS rejection cases, rotated-key replacements and pending-call
shutdown. Bounded build/container logs were retained through the log-directory
setting above.

### Integration vulnerability scan

Measured on 2026-10-28: `GOTOOLCHAIN=go1.26.10 govulncheck -test ./...` with
govulncheck v1.9.0 and database updated 2026-10-27 21:16:18 UTC **passed with zero
reachable vulnerabilities**, including the test-only harness dependencies.

The integration module pins these fixes and their dependency updates:

| Dependency | Previous version | Current version | Fix |
| --- | --- | --- | --- |
| `golang.org/x/crypto` | `v0.54.0` | `v0.56.0` | GO-2026-6355 and GO-2026-6354 |
| `github.com/moby/go-archive` | `v0.2.0` | `v0.3.0` | GO-2026-6253 |
| `github.com/klauspost/compress` | `v1.18.6` | `v1.18.7` | Transitive dependency update |
| `github.com/moby/sys/user` | `v0.4.0` | `v0.4.1` | Transitive dependency update |

The full Docker suite above passed with these pins, including image-build
archive operations; no API adaptation was required. `go mod tidy`, `go mod
verify` and `go vet -mod=readonly ./...` also passed with Go 1.26.10.

The verbose scan reported zero package-level findings and one module-only
advisory, GO-2026-5932, for the unmaintained `golang.org/x/crypto/openpgp` package.
That package is not imported by this suite and the advisory has no fixed release;
it does not produce a reachable finding or fail govulncheck. This scan does not
audit the separately source-built Toxiproxy server's own locked module graph.
