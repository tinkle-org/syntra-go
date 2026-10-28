# Contributing to Syntra Go

Run commands from the repository root. Go 1.22 is the module floor; CI uses
Go 1.26.4. Keep the pinned Protobuf v1.36.6 runtime and its checksums unless a
dependency update is explicitly part of the change.

## Checks

```sh
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

Compatibility: CI validates the declared Go 1.22 floor with
`GOTOOLCHAIN=local` (no silent upgrades) and the current 1.26.4 toolchain,
plus compile-only `GOOS/GOARCH` targets. Run the 1.22 toolchain locally via
`GOTOOLCHAIN=go1.22.12 go env GOROOT` (or an installed Go 1.22 toolchain with
`GOTOOLCHAIN=local`) when changing language features.

Security (all pinned, no silent ignores):

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
govulncheck ./...
go install honnef.co/go/tools/cmd/staticcheck@2025.1.1
staticcheck -tags syntranative ./...
```

`staticcheck` uses `-tags syntranative` so shared helpers used only by the
native backend are not reported as unused. `govulncheck` gates reachable
vulnerabilities; standard-library fixes in newer patches are tracked via
Dependabot, not blanket exclusions.

Fuzz and negative tests:

```sh
go test -mod=readonly -run 'TestFuzzSeedCorpus' -count=1 -v ./...
go test -mod=readonly -fuzz=FuzzUnmarshalFrame -fuzztime=30s .
go test -mod=readonly -fuzz=FuzzDuplicateContent -fuzztime=30s .
```

PR CI runs 30s smoke runs; weekly Scheduled runs 5m campaigns. Conformance
vectors in `conformance/` must keep passing.

Workflows (all actions SHA-pinned, `contents: read`, timeouts, concurrency
cancel for PRs):

- `Go` – fast required PR/main checks (`pure-go`, `generated-go`,
  `native-go`, `compat`, `security`, `fuzz-smoke`, `actionlint`,
  aggregator `ci-success`). Require `ci-success`
  in the main-branch ruleset; do not require individual jobs.
- `CodeQL` – Go analysis on push/main/PR/weekly (optional, does not gate).
- `Scheduled` – weekly extended fuzz/security.
- `Release Please` – push-to-main-only automation using conventional commits.
  Merging a release PR pushes the root `vX.Y.Z` tag and opens the GitHub
  Release; the Go proxy and pkg.go.dev index from the tag. No binaries are
  published and PRs cannot trigger it. An admin must create the
  `RELEASE_PLEASE_TOKEN` secret (PAT or App token) or release PRs get no
  checks; the token lives only in that workflow.

A `dependency-review` gate is intentionally absent: the action reports the
repository does not support it until an admin enables Dependency graph
(Settings → Code security). Re-add the gate once supported; Dependabot and
`govulncheck` cover updates and reachable vulnerabilities meanwhile.

Dependabot updates `gomod` and `github-actions` weekly; update SHAs via
Dependabot PRs after review, never floating tags.

Use neutral opaque payloads and local test fixtures. For behavior changes,
include a focused regression that asserts observable behavior. Report existing
test failures separately rather than changing semantics to make a module move
pass. Describe which backend and checks you exercised in your pull request.

## Schema and generated code

Read [MIGRATION.md](MIGRATION.md) for the extraction commit, path mappings, and
upstream protocol authority. Schema and fixture updates should record their
upstream source revision. Normative protocol changes belong in the upstream
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
There are no releases yet. Future releases use repository-root `vX.Y.Z` tags;
the old nested-module release process does not apply here.
