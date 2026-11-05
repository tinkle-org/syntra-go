# Contributing to Syntra Go

Use the repository root for the commands below. The module floor is Go 1.23.0;
CI checks Go 1.23.12 compatibility and uses Go 1.26.10 for current verification.
Use a security-patched toolchain for deployed applications. Record `go version`
with reported results.

Read [CONNECTION.md](CONNECTION.md) before changing connection or session
behavior. Syntra 1.0 includes Noise encryption. The protobuf `Frame` is an
internal envelope. The core and socket-free runtime can use application-supplied
ordered record I/O or optional managed networking selected by imports. Managed
networking uses Go goroutines/netpoll and explicit ownership and quotas.

## Local checks

```sh
export GOTOOLCHAIN=go1.26.10
go version
gofmt -l .
CGO_ENABLED=0 go build -mod=readonly ./...
CGO_ENABLED=0 go test -mod=readonly -count=1 ./...
go vet -mod=readonly ./...
go test -mod=readonly -race -count=1 ./...
go mod verify
git diff --check
```

`gofmt -l .` should print nothing. The race detector requires CGO and a C
compiler for instrumentation. The SDK itself builds with CGO disabled. The
SDK tests include in-memory fixtures and real loopback TCP, WS, WSS, HTTP, HTTPS,
and proxy integrations. They require local sockets but no Docker or external
services.

For minimum-version compatibility:

```sh
GOTOOLCHAIN=go1.23.12 CGO_ENABLED=0 go test -mod=readonly -count=1 ./...
```

Security analysis uses the selected toolchain and its standard library:

```sh
export GOTOOLCHAIN=go1.26.10
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
govulncheck ./...
go install honnef.co/go/tools/cmd/staticcheck@2025.1.1
staticcheck ./...
```

These are reproduction commands, not a recorded clean scan. Record the source
revision, working-tree state, toolchain, command and output when publishing a
result. See [AUDIT.md](AUDIT.md).

## Schemas and generated output

Use Buf CLI 1.59.0. `buf.gen.yaml` pins the remote Go plugin to v1.36.6
revision 1 with `paths=source_relative`; the protobuf runtime is also v1.36.6.
Edit schemas under `proto/` and regenerate output under `gen/`. Do not edit
generated Go files by hand.

```sh
buf format --diff --exit-code
buf lint
buf build
python3 scripts/check-go-package.py
buf generate --template buf.gen.yaml
python3 -m unittest discover -s scripts -p 'test_*.py' -v
python3 scripts/check-generated.py
```

The drift check generates into a temporary directory and compares the complete
generated file set and bytes. It requires Python 3, Buf, and access to the remote
plugin service. CI checks Buf `FILE` compatibility against the pull request base,
excluding `FILE_SAME_GO_PACKAGE`. `scripts/check-go-package.py` enforces the
canonical `go_package` option in every compiled schema descriptor. Inspect
schema and generated-code diffs together.

## Focused verification

Add a regression for observable behavior when changing protocol or lifecycle
semantics. Use neutral payloads and local fixtures. Exercise applicable size
bounds, fragmented records, invalid authentication, cancellation, stalled I/O,
readiness, and shutdown paths. Preserve buffer ownership and record ordering.
Application callbacks and record I/O must honor cancellation; tests should join
the workers they start.

Recovery changes need runtime attachment and explicit negotiation tests,
including `ClientConfig.Prepare`, the immutable pre-Run inbox, and
`HostConfig.Recovery` connection binding and teardown. Exercise connection and
principal isolation, generation/checkpoint continuity, full-state CAS conflicts,
lost confirmations, and unknown persistence outcomes. Persistence and source
callbacks remain application-owned contracts.

Managed networking changes need real loopback coverage for idle push without
RPCs, notification loss and generation fencing, reconnect and fresh recovery
negotiation, authentication/proxy refusal without fallback, pause/offline/wake,
shared FIFO admission, finite quotas, and incomplete shutdown retaining work.
Keep TLS provider tests on the exact supplied stream; exercise TLS 1.3,
`http/1.1`, authority validation, and rejection before carrier bytes. HTTP/HTTPS
candidate tests must cover default rejection and per-config opt-in on both peers.

```sh
go test -mod=readonly -race -count=1 ./network ./routes ./proxy ./transport/...
go test -mod=readonly -count=1 -run '^TestHTTPCandidatePolicyIsScoped$' -v ./securechannel
go test -mod=readonly -count=1 -run '^Example' -v ./connection
```

The required `network-integration` CI job runs those networking packages with
the race detector. It parses `go test -json` events to require actual run/pass
events for each selected package and named integration cases, including both
candidate carriers and every direct/proxy HTTP route in both authentication
modes. Missing or skipped required coverage fails. `dependency-isolation` checks
the root and `securechannel` production dependency graphs for optional networking
and socket/TLS imports, and verifies execution of
`TestHTTPCandidatePolicyIsScoped` and its four carrier/mode subtests.

```sh
go test -mod=readonly -run TestFuzzSeedCorpus -count=1 ./...
go test -mod=readonly -fuzz=FuzzUnmarshalFrame -fuzztime=30s .
go test -mod=readonly -fuzz=FuzzDuplicateContent -fuzztime=30s .
go test -mod=readonly -fuzz=FuzzParseContext -fuzztime=30s ./securechannel
go test -mod=readonly -fuzz=FuzzContextRoundTrip -fuzztime=30s ./securechannel
```

CI runs build, test, vet, race, generation, compatibility, security analysis,
fuzz smoke, and workflow lint checks. `ci-success` aggregates the required Go
jobs, including network integration and dependency isolation. Scheduled checks
run longer fuzz campaigns and security analysis. Configure fuzz targets only
after their functions exist in the selected package; package tests also execute
the existing fuzz seed corpora.
Benchmarks are report-only; see [BENCHMARKS.md](BENCHMARKS.md).

Describe the exercised paths and actual results in pull requests. Report
unrelated failures separately. Use [SECURITY.md](SECURITY.md) for private
vulnerability reports.
