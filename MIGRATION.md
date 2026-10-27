# Migration from the monorepo Go module

## Source snapshot

This repository extracts the existing Go implementation from
[`tinkle-org/syntra` commit `2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`](https://github.com/tinkle-org/syntra/tree/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c).
The source directory is `bindings/go/`. This is a repository/module split;
runtime behavior, public API shapes, protocol fields, and the optional production
native ABI are preserved. It does not implement the proposed Noise/SC1 design.

| Source path | Extracted path |
|---|---|
| `bindings/go/*.go`, `go.mod`, `go.sum`, `README.md` | Repository root (module/import paths and README adapted) |
| `bindings/go/gen/syntra/v1/*.pb.go` | `gen/syntra/v1/*.pb.go` (byte-identical) |
| `LICENSE` | `LICENSE` |
| `proto/` | `proto/` (byte-identical schema snapshot) |
| `buf.yaml` | `buf.yaml` (same module/lint/breaking policy, adapted comments) |
| `conformance/test-vectors/protobuf/` | Same path (snapshot) |
| `tests/schema/go/codec_test.go` | `tests/schema/codec_test.go` (import and fixture path adapted) |
| `tests/schema/fixtures/frames.json` | Same path (snapshot) |

The schema codec tests use the root `go.mod`; there is no nested test module.
Existing Go tests have only their import and relocated fixture paths adapted.
The Go 1.22 module floor, Protobuf v1.36.6 runtime, and `go.sum` are retained.

## Import changes

| Old import | New import |
|---|---|
| `github.com/tinklehq/syntra/bindings/go` | `github.com/tinkle-org/syntra-go` |
| `github.com/tinklehq/syntra/bindings/go/gen/syntra/v1` | `github.com/tinkle-org/syntra-go/gen/syntra/v1` |

The package names remain `syntra` and `syntrav1`. Update handwritten imports
and the module requirement in downstream consumers together, including imports
in tests and application-generated code.

**Go type identity changes with the import path.** A generated `Frame` from the
old package is a different Go type from `Frame` in the new package, despite
identical schemas and wire encoding. Root package aliases refer to the new
generated package; they do not bridge the old module. Avoid linking both copies
of the generated package into one process: registering the same Protobuf file
and message names twice can cause registry conflicts. Migrate the dependency
graph consistently; identical wire bytes alone do not make Go values assignable.

## Schema, fixture, and protocol authority

The copied `proto/`, generated Go files, Protobuf vectors, and JSON codec
fixtures are reproducible snapshots of the source commit. Protocol authority
remains in the upstream
[`specifications/`](https://github.com/tinkle-org/syntra/tree/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c/specifications),
[`rfcs/`](https://github.com/tinkle-org/syntra/tree/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c/rfcs),
[`proto/`](https://github.com/tinkle-org/syntra/tree/2a91da7fdb96f3e75badf07614c14e4f85c9ba1c/proto),
and conformance definitions. This extraction creates no independent wire-schema
or normative-specification fork. Future snapshot updates should identify the
reviewed upstream commit and regenerate with the pinned tools.

The original `go_package` strings remain in `.proto` files and embedded
generated descriptors. They are provenance/schema metadata, not handwritten
Go imports to replace. `buf.gen.yaml` passes `M<logical-path>=<new-import>`
options for all eight files to select this module's Go package without changing
the source or descriptor bytes. Generation uses the original Buf 1.59.0 / Go
plugin v1.36.6 revision 1 pins; `scripts/check-generated.py` compares generated
output in temporary storage without updating committed files.

## Native dependency and versioning

The pure-Go backend is the default and has no Rust dependency. The optional
`syntranative` backend still requires a compatible production Rust library and
ABI version 1. `native.go` contains inline C declarations; no header include
checkout is needed to compile Go. See the sibling `../syntra-rs` build/link and
Darwin/Linux loader commands in [README.md](README.md#optional-native-backend).
Cross-repository native CI builds the production library from
[`syntra-rs` commit `fca1063515d3966be71e9844346e7cbc53769c76`](https://github.com/tinkle-org/syntra-rs/commit/fca1063515d3966be71e9844346e7cbc53769c76)
with Rust 1.88.0 and runs native-tagged Go tests, including the race detector.
ABI version agreement alone is not proof of behavioral compatibility.

There are **no releases yet** in `tinkle-org/syntra-go`. Future Go releases use
root semantic-version tags such as `vX.Y.Z`. Old monorepo nested tags such as
`bindings/go/vX.Y.Z` do not identify releases of this module. Release automation
and historical release tags are not carried over by this extraction.
