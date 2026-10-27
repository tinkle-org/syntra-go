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
```

The race detector requires CGO and a C compiler, but the default-tag tests
still exercise the pure-Go backend. Native tests require a compatible Rust
production library; follow [README.md](README.md#optional-native-backend).

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
