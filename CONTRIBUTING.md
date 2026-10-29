# Contributing to Syntra Go

Run commands from the repository root. **Go 1.23.0 is the module floor**; CI's
current and recommended production toolchain is **Go 1.26.10**. The floor is an
API/build compatibility constraint, not a secure-runtime recommendation.
Production binaries require a security-patched toolchain. Current pins are
Protobuf v1.36.6, flynn/noise v1.1.0,
coder/websocket v1.8.15, x/crypto v0.38.0 and x/sys v0.33.0. Keep dependency
versions and checksums consistent unless updating them is part of the change.

Read [SC1.md](SC1.md) for the implementation-specific draft-1 contract and
[AUDIT.md](AUDIT.md) for completed local reviews and open gaps. Keep claims tied
to evidence: this channel is neither accepted upstream nor independently
audited. Reference upstream specification commit
[`e27fa275f647ccc925b7cf79eb2dd332f20a3d02`](https://github.com/tinkle-org/syntra/tree/e27fa275f647ccc925b7cf79eb2dd332f20a3d02)
when discussing draft requirements, and identify a new reviewed pin when that
reference changes.

## Checks

```sh
export GOTOOLCHAIN=go1.26.10
gofmt -l .                         # must print nothing
CGO_ENABLED=0 go build -mod=readonly ./...
go test -mod=readonly -count=1 ./...
CGO_ENABLED=0 go test -mod=readonly -count=1 ./...
go vet -mod=readonly ./...
go test -mod=readonly -race -count=1 ./...
go mod verify
git diff --exit-code -- go.mod go.sum
```

The race detector requires CGO and a C compiler, but the default-tag tests
still exercise the pure-Go backend. Native tests require a compatible Rust
production library; follow [README.md](README.md#optional-native-backend).

Compatibility: CI tests Go **1.23.12** and **1.26.10**, using `GOTOOLCHAIN=local`
to prevent silent upgrades, plus compile-only `GOOS/GOARCH` targets. To check
the minimum locally, run `GOTOOLCHAIN=go1.23.12 go test -mod=readonly ./...`.
That lane verifies API/build compatibility only; it does not recommend Go 1.23
for production security. Use Go 1.26.10 for current security verification.
Use `go version` and `go env GOTOOLCHAIN` to record which toolchain actually ran.

Root tests and benchmarks do not require Docker. Timing boundaries, accounting
and commands are in [BENCHMARKS.md](BENCHMARKS.md). Container integration tooling
has a separate module documented in
[tests/integration/README.md](tests/integration/README.md) and is not run by root
`go test ./...`. Follow its own tooling instructions and record
the actual peer revisions; a same-implementation container round trip does
not establish independent cross-language SC1 interoperability.

Security checks:

```sh
export GOTOOLCHAIN=go1.26.10
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
govulncheck ./...
go install honnef.co/go/tools/cmd/staticcheck@2025.1.1
staticcheck ./...
```

CI checks the default build with `staticcheck ./...` and the native build with
`staticcheck -tags syntranative ./...` in the job that provisions its Rust
library and linker environment. Rebuild analysis tools with the selected Go
toolchain. `govulncheck` gates reachable
vulnerabilities. The Go 1.26.10 scan reported zero reachable vulnerabilities
and 20 additional vulnerabilities in required modules that were not reachable
in the analyzed call graph. Recheck when dependencies or reachable code paths
change; dependency presence and code reachability are different scan findings.
See [SECURITY.md](SECURITY.md#dependencies-and-assurance) for the toolchain result.

Fuzz and negative tests:

```sh
go test -mod=readonly -run 'TestFuzzSeedCorpus' -count=1 -v ./...
go test -mod=readonly -fuzz=FuzzUnmarshalFrame -fuzztime=30s .
go test -mod=readonly -fuzz=FuzzDuplicateContent -fuzztime=30s .
go test -mod=readonly -fuzz=FuzzParseContext -fuzztime=30s ./securechannel
go test -mod=readonly -fuzz=FuzzContextRoundTrip -fuzztime=30s ./securechannel
```

PR CI runs 30s core smoke runs; weekly Scheduled runs 5m core campaigns.
Run the SC1 context targets explicitly when touching their parsers. Conformance
vectors in `conformance/` must keep passing. Local fixture tests, carrier
integration tests, native-core checks and true independent Rust wire interop
are separate evidence; name the level actually exercised.

Workflows (all actions SHA-pinned, `contents: read`, timeouts, concurrency
cancel for PRs):

- `Go` – fast required PR/main checks (`pure-go`, `generated-go`,
  `native-go`, `compat`, `security`, `fuzz-smoke`, `actionlint`,
  aggregator `ci-success`). Require `ci-success`
  in the main-branch ruleset; do not require individual jobs.
- `CodeQL` – Go analysis on push/main/PR/weekly (optional, does not gate).
- `Scheduled` – weekly extended fuzz/security.
- `Integration` – separate Docker-based connectivity/fault checks; see
  [tests/integration/README.md](tests/integration/README.md).
- `Benchmarks` – report-only `-bench . ./...` samples across root-module packages,
  including wire/session, securechannel and transport cases; see
  [BENCHMARKS.md](BENCHMARKS.md).
- `Release Please` – push-to-main-only automation using conventional commits.
  Merging a release PR pushes the root `vX.Y.Z` tag and opens the GitHub
  Release; the Go proxy and pkg.go.dev index from the tag. No binaries are
  published and PRs cannot trigger it. It authenticates with the built-in
  `GITHUB_TOKEN` (no secret setup required); because pushes made with
  `GITHUB_TOKEN` do not trigger other workflows, checks on release PRs run
  once the PR opens.

A `dependency-review` gate is intentionally absent: the action reports the
repository does not support it until an admin enables Dependency graph
(Settings → Code security). Re-add the gate once supported; Dependabot and
`govulncheck` cover updates and reachable vulnerabilities meanwhile.

Dependabot updates `gomod` and `github-actions` weekly; update SHAs via
Dependabot PRs after review, never floating tags.

Use neutral opaque payloads and local test fixtures. For behavior changes,
include a focused regression that asserts observable behavior. Report existing
test failures separately rather than changing semantics to make unrelated
checks pass. Describe which backend and checks you exercised in your pull request.

For channel changes, preserve fresh RNG use, exact context bytes, carrier
binding, record ordering, bounds, cancellation and abortive close ownership.
Exercise fragmented prefixes/messages, partial I/O, invalid tags, stalled
writes and revocation as appropriate. Keep host callbacks context-aware and
verify policy before handler effects. Exercise `connection` readiness, bounded
server admission through the ready write and owned shutdown when changing
orchestration. Writer tests must preserve FIFO snapshot ownership, active-plus-
queued count/byte accounting, loop progress during stalls, bounded terminal
drains and cancellation/join behavior. SC1 issuance/delivery/ack recovery,
rotation, subscription routing and reliable execution-terminal proofs remain
open integration work; do not describe them as implemented merely because a
primitive/helper regression passes. Go/Noise/native secret erasure and native
completion-time limitations must remain explicit until evidence changes.

## Schema and generated code

Read [MIGRATION.md](MIGRATION.md) for source provenance and import mappings.
Schema and fixture updates should record their upstream source revision.
Normative protocol changes belong in the upstream
RFC/specification process first.

Use Buf CLI 1.59.0 with the remote Go plugin v1.36.6 revision 1 configured in
`buf.gen.yaml`. Generated files are committed and must not be hand-edited.
Keep the logical proto import mappings complete when adding schema files;
changing `go_package` in the snapshots is not an import-path migration step.

```sh
buf format --diff --exit-code
buf lint
buf build
python3 scripts/check-generated.py
```

The drift script needs Python 3 and remote plugin access and only writes to a
temporary directory. To intentionally regenerate committed Go output, run
`buf generate --template buf.gen.yaml`, then inspect the resulting diff.
Wire compatibility and cross-language conformance remain upstream concerns;
the local fixture tests and byte-drift check cover only their stated scope.

## Reports and releases

Open ordinary Go implementation issues and pull requests in
[`tinkle-org/syntra-go`](https://github.com/tinkle-org/syntra-go).
Follow [SECURITY.md](SECURITY.md) for private vulnerability reports.
There are no releases yet. Future releases use repository-root `vX.Y.Z` tags.
