# Cross-language TCP receipt fixture evidence

## Review rerun

The current review matrix is archived under
[`docs/evidence/terminal-receipt-review-20261106-r4/`](docs/evidence/terminal-receipt-review-20261106-r4/):
[`report.json`](docs/evidence/terminal-receipt-review-20261106-r4/report.json),
[`SHA256SUMS`](docs/evidence/terminal-receipt-review-20261106-r4/SHA256SUMS), and
[`ARCHIVE_SHA256SUMS`](docs/evidence/terminal-receipt-review-20261106-r4/ARCHIVE_SHA256SUMS).
The report embeds both complete source manifests. Text logs and case results are
retained; binaries are omitted. Verify retained bytes using the instructions in
the [archive index](docs/evidence/README.md). These relative links become hosted
only when the maintainer commits and publishes the files.

This is a new execution against the review fixes, not a reconstruction of the
unavailable historical run-2. It uses the current **18 harness tests**, including
stdout-drain, cleanup-failure, refused local-write, process-group exit-race, and
archive integrity regressions. A Go-server deny/unknown outcome additionally
requires exactly one `local_write` event with `complete: false`; partial-loss
cases may still report a complete local write. Rust's fresh-denial marker now
requires an actual native authentication refusal for the exact withdrawn binding,
outside the side-effect-free key lookup.

The earlier [r3 review execution](docs/evidence/terminal-receipt-review-20261106-r3/report.json)
is also retained. The r4 source snapshot includes the final non-sensitive-payload
comment in the Rust policy example. Repeated executions are not additional
distinct protocol cases.

## Historical run-2

Run on 2026-11-06 against the **uncommitted working trees** of both SDKs on
`feat/scoped-terminal-receipt`. No chorus/libtinkle edits, runtime edits,
dependency overrides, version changes, publication, commits, or pushes were
performed by this harness task. Existing parent Go fixture provisioning was
preserved. `formal_conformance: false`; `fixture_durable: false`.

## Reproduce

From `syntra-go`, choose an output directory that does **not** already exist,
with an existing parent outside both source checkouts:

```sh
python3 scripts/terminal-interop.py --output \
  /tmp/terminal-receipt-interop-NEW
```

The harness runs its Python regression tests, then builds the actual working
trees using `GOTOOLCHAIN=go1.26.10` for `./cmd/terminal-fixture` and
`cargo +1.88.0 build --locked -p syntra-net --features tcp --example terminal_receipt`.
Both binaries and the Rust target directory are inside the fresh output directory.
No dependency replacement or lockfile update is requested. Run harness tests
separately with:

```sh
python3 -m unittest discover -s scripts -p test_terminal_interop.py
```

Each case starts a new server on loopback port zero and reads its announced
address. Exactly one independent opposite-language SDK client establishes and
calls `/example.Authority/Retire` with empty input. There is no mutation retry.
A separate fresh Returning probe sends **no RPC**. Go uses `-mode client -probe`;
Rust uses `probe ADDR`. The server must emit a `fresh_denied` marker for the
withdrawn Returning binding, then verify one stored transition, one commit, one
handler invocation, one fresh denial, and two closed connections. A refused probe
connection alone is insufficient evidence.

In the current sibling Rust source,
`syntra-rs/crates/syntra-net/examples/terminal_receipt.rs`, `Store::lookup` is
side-effect-free: it checks the requested handle/epoch and reads withdrawal
state without counting or emitting evidence. `accept_probe` records denial
outside that callback only after native accept returns channel Authentication
failure for the exact parsed fixture context (Returning mode, TCP, server key ID,
scope, handle, and epoch), with the transition present and one handler/commit.
These later source checks do not retroactively strengthen run-2 evidence.

For `gap`, the authority callback records the transition and waits on a
channel/notification until an actual owned observation witnesses it while that
callback is pending. Event ordering must be transition, gap observation, callback
return. This does not claim that the receipt arrived before callback return.

The proxy parses only big-endian u16 record lengths and relays opaque bytes.
Fragmented cases split all six records into writes of at most three bytes;
this is not a claim about IP packet boundaries. Loss cases relay M2 and Ready,
then forward exactly the two-byte prefix plus one ciphertext byte of server
record **3**, and shut down both directions. Both observed loss records were
37 bytes including prefix, with exactly 3 bytes forwarded. The harness does not
use the Go fixture's older write-count-based `-drop-receipt` switch.

Children have deadlines and bounded, concurrently drained stdio. Failure cleanup
signals private process groups, reaps children, and joins retained stdio/proxy
threads. Proxy logs contain counts, not ciphertext, decrypted frames, or keys.

## Actual results

`go-to-rust` means **Go server / Rust client**; `rust-to-go` means the reverse.

| Scenario | Network | Go server / Rust client | Rust server / Go client |
|---|---|---|---|
| owned | direct | PASS: exact `retired` | PASS: exact `retired` |
| owned | fragmented | PASS: exact `retired` | PASS: exact `retired` |
| gap | direct | PASS: pending-callback observation + `retired` | PASS: pending-callback observation + `retired` |
| gap | fragmented | PASS: pending-callback observation + `retired` | PASS: pending-callback observation + `retired` |
| deny | direct | PASS: typed authority HardDenied; client Unavailable, 0 receipts | PASS: typed authority HardDenied; client Unavailable, 0 receipts |
| unknown | direct | PASS: typed authority Unknown; client Unavailable, 0 receipts | PASS: typed authority Unknown; client Unavailable, 0 receipts |
| owned | partial loss | PASS: record-3 cutoff; client Unavailable, 0 receipts | PASS: record-3 cutoff; client Unavailable, 0 receipts |

**14 distinct cases passed; 0 failed.** All 14 also passed the separate fresh
Returning denial and checked server-state/closure assertions. The deny cases
do **not** establish receipt of an Unauthenticated wire result: the server's
typed hard-denial observation closes the fenced connection, and both clients
observed typed `Unavailable`. Client construction/establishment errors, arbitrary
errors, deadlines, and unexpected successful results cannot pass as unknown
mutation outcomes. The harness permits a typed Unauthenticated result only for
the deny scenario, but none was observed in this run.

Eight harness tests passed **in run-2**, including negative evidence validation, real
loopback proxy byte preservation/cutoff, and timeout/nonzero-exit/stdio-limit
cleanup. No runtime bug was exposed by this matrix. No fixture processes remained
after the run; all proxy worker join assertions passed.

`test_output_directory_policy` was added after run-2 when output-directory
validation was made portable, raising that later suite to **nine test methods**.
Three subsequent orchestration regressions brought that suite to **twelve**;
they ensure the fresh no-RPC probe starts after the result is observed but before
client/proxy cleanup can consume the server's accept window. The run-2
`unit-tests.stderr.log` was recorded as `Ran 8 tests`; its historical count and
hashes are not changed retroactively. Six review regressions bring the latest
suite to **eighteen**, as recorded by the new archive.

An earlier retained `run1` reported 8/14 PASS: six proxy cases failed the harness's
incorrect expectation of four client records. Actual fixture traffic is three
records in each direction (client M1/Hello/request; server M2/Ready/result).
The validator and regression tests were corrected; `run2` below is a new complete
build/run, not a relabeling of those failures or additional distinct coverage.

## Exact provenance and checksums

Original run-2 output directory (local, not a reviewer-accessible archive):

`/var/folders/xv/g_j4t2793xdbd_wnr290xgyw0000gn/T/opencode/terminal-receipt-interop-20261106-run2`

The historical `report.json` records the complete matrix, source file hashes
(including uncommitted/untracked code), branch/revision/status, build commands/environment,
toolchain versions, binary hashes and per-log/per-case hashes. `SHA256SUMS`
additionally checksums the report and both binaries. The original run recorded
verification of all entries with `shasum -a 256 -c SHA256SUMS` from that directory.

At the 2026-11-06 documentation review, the directory and both original files were absent;
the parent `opencode/` directory contained only `.DS_Store`. No original bytes
were available to archive, inspect for sensitive content, or rehash. The values
below remain historical recorded values, not independently reverified checksums.
No reviewer-ready archive or hosted evidence link is claimed.

The intended archive is `docs/evidence/terminal-receipt-interop-20261106-run2/`.
It requires the original bytes, report/manifest hash verification, and inspection
of the embedded source manifests; reconstruction or relabeling a new run is not
a substitute. Any partial archive must identify omitted artifacts: without the
compiled binaries, a full manifest check is unavailable.

- Go: `go version go1.26.10 darwin/arm64`.
- Rust: `rustc 1.88.0 (6b00bc388 2025-06-23)`, host
  `aarch64-apple-darwin`; `cargo 1.88.0 (873a06493 2025-05-10)`.
- Go HEAD: `3993457af7d36ffdb0fbe7f6615ab597a1e95abe`.
- Rust HEAD: `72f4cb16f7832226549d7464ce4073a2e40954f3`.

SHA-256 values:

| Artifact | SHA-256 |
|---|---|
| Go working-tree source manifest | `7ee1bfb78635cb596359bd9e9b96fb6208dd2e2c5e300bd8b019ee3b16671077` |
| Rust working-tree source manifest | `28690d2fc14b1c6b3678be0e995c83319865a761f7fd6f98f44c9c7aec6d2c2c` |
| Go binary | `9cb12279e6c4a83395d78148f63420cf23b7f65d0c260a55325f4cbbd2ac7dfa` |
| Rust binary | `2b08ce549a685dfda45e81f368dae779096db34207e94fa012f1149aefce7965` |
| `report.json` | `1d167f2a09d60406a26de087dd45b4f2730edbf09aaf4c439c91a7eae25221f4` |

Source manifests matched before/after execution (`source_stable: true`). This
evidence note was written **after** that run and is therefore not included in
its Go source manifest. Future parent edits require another fresh run.

These are volatile in-memory test authorities with public fixture provisioning.
The results establish this bounded two-SDK TCP fixture matrix only, not durable
storage, application acceptance, formal protocol conformance, or production
revocation/distribution guarantees.
