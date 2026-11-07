# Cross-language TCP receipt fixture evidence

## Request-wide deadline regression matrix

The `feat/request-wide-deadlines` fixture adds six **direct TCP** cases to the
unchanged fourteen baseline direction/scenario/network combinations (20 distinct
cases total). Each added scenario runs Go host / Rust client and Rust host / Go
client against the working-tree SDK APIs; Rust is the contract source of truth.

| Scenario | Peer timeout | Host cap | Required outcome |
|---|---|---|---|
| `budget-cap` | 120 s | 1.5 s | Exact fixed `retired` receipt |
| `budget-short` | 1 s | 1.5 s | Exact fixed `retired` receipt; cap must not extend the shorter peer allowance |
| `budget-late` | 120 s | 600 ms | Retained commit finishes after cutoff; typed failure and zero receipts |

The selector records only input-validity and cap metrics. Authorization remains
prompt and nonblocking, including Rust's synchronous hook. A cooperative 200 ms
handler delay spends the original allowance; measured authorization/handler/
commit budgets must keep the selected cutoff rather than restart it. Authority
reads must expose an actual live SDK budget, bounded by the original request and
the configured read timeout (Go: 20 ms; Rust: 100 ms). Any positive read allowance
up to that limit is valid; a prior freshness cutoff can shorten it further. The
fixture measures the SDK budget itself, never a context-deadline substitute.
Every measured callback requires `sdk_budget_present: true`; absence, malformed
evidence, or a legacy `refresh` phase fails validation. Go also checks that the
observation context deadline does not extend the supplied SDK cutoff.

The Go SDK's earlier periodic-observation budget-propagation limitation is now
fixed: periodic driver observations also carry `RequestBudgetFromContext` with
the derived read cutoff. Both SDKs supply the original operation cutoff to
commit, excluding the teardown tail. The validator derives that tail from the
remaining allowance at reservation (one quarter, capped at 250 ms), permitting
50 ms measurement/scheduling slack rather than a fresh per-phase allowance.
No assertion depends on an exact network error arrival time.

`budget-late` is an explicit **test-only uncooperative adapter contract violation**:
admitted external commit work ignores cancellation, retains its execution charge,
and finishes 250 ms after its supplied budget expires. This does not block the
authorizer. The validator requires an expired retained-work marker, the actual
late transition, callback return before joined connection closure, and no receipt.
It additionally requires exactly one `commit_pending` admission marker and at
least one live SDK-budgeted `observe` event strictly after that marker and before
`late_commit`. Initial reservation reads, reads after the delayed mutation, and
reads after callback return cannot satisfy this event-range proof. The range is
opened by the actual commit callback in each fixture; neither poll count nor
exact network-error timing is prescribed.
The fresh no-RPC Returning probe waits for that transition before attempting
authentication; all six cases still require one commit, one handler, one actual
fresh denial, and two joined connection closures. This demonstrates neither
rollback on timeout nor production storage durability.

Use the reproduction commands below with a **new external output directory**.
The harness report now requires all 20 cases and stable before/after source
manifests. Historical fourteen-case results below remain historical; they do not
establish outcomes for these added scenarios. No binaries or large source
manifests need to be archived into either repository. These are bounded volatile
application fixtures, not formal conformance or production application acceptance.

### Latest strict final-run evidence and retained history

Portable report location for each selected output directory (local artifacts, not
a repository archive):

`<output>/report.json`

The same directory holds `SHA256SUMS`, per-case logs/results, binaries and source
manifests. The report's `complete`, `source_stable`, counts and before/after hashes
are authoritative; verify artifact bytes with `shasum -a 256 -c SHA256SUMS` from
that directory. Source edits after a run require another new output directory.

**Latest: `terminal-request-budget-20261107-run4`**, started
2026-11-07 18:48:00 UTC: **20/20 PASS**, zero failures, `complete: true`,
`source_stable: true`. All **31 Python test methods** passed, including the
initial-reads-only negative regression added for the P2 review finding. Both
late-case logs contain SDK-budgeted reads inside the explicit pending-commit
range. The actual working-tree builds used Go 1.26.10 and Rust 1.88.0 `--locked`.
Every artifact in `<output>/SHA256SUMS` was verified successfully.

Run4 exact SHA-256 provenance:

| Artifact | SHA-256 |
|---|---|
| `report.json` | `85546c02148bbcefb0b4cf70c4c181735dc8889d3efaea9924b52b53047b679b` |
| Go working tree, before = after | `b57ae3b1df6bf5859bf558e80175ea9d6d7b2bba38eab994a277a3d085c2984c` |
| Rust working tree, before = after | `705506544d4cf2976e0f3aa95650789fe20bc4a465dbc44de8bf3fcaf1d66f6b` |

This run4 result/provenance entry and subsequent editorial SDK documentation
updates were recorded **after** execution and are not part of its captured source
hashes. Fixture, harness and runtime sources were not edited afterward. The stable
hashes describe the captured run, not the subsequently updated documentation.

The recorded working-tree runs remain unchanged in separately named output
directories. Hashes identify each run's captured snapshots, not the current
checkout; later source/doc edits cannot retroactively regenerate an old result.

- `terminal-request-budget-20261107-run1`: **19/20**, stable sources, incomplete.
  Its Go-host late case exposed missing SDK budgets on periodic driver reads.
- `terminal-request-budget-20261107-run2`: **20/20**, stable sources, complete
  under the then-current validator, which explicitly allowed separately labelled
  bounded refresh contexts without the SDK value. That exception is now removed;
  run2 is not evidence that the new strict per-callback requirement passed.
- `terminal-request-budget-20261107-run3`: **20/20**, stable sources, complete;
  all **30 Python test methods** passed. It required the SDK budget on every
  measured callback but did not require a read inside an explicit pending-commit
  event range. The later P2 validator regression closes that coverage gap;
  run3 is not relabelled as evidence of the new range assertion.

Run3 exact SHA-256 provenance:

| Artifact | SHA-256 |
|---|---|
| `report.json` | `fb4c574243ce33e12bb5592e833a179da583022fccd370176165708bf7726604` |
| Go working tree, before = after | `227ad6f7ae68d11c48f2d45b1a42fc5f016d828d9e3419629a2456ac9b758673` |
| Rust working tree, before = after | `df5a5147fc3c84338521ebf0bc0c5c007db2baec8458a4802909dd0ebbe02cda` |

These request-budget runs are distinct from the older fourteen-case receipt
archives below. No old failures or results have been relabelled.

## Historical 2026-11-06 review rerun

The 2026-11-06 review matrix is archived under
[`docs/evidence/terminal-receipt-review-20261106-r4/`](docs/evidence/terminal-receipt-review-20261106-r4/):
[`report.json`](docs/evidence/terminal-receipt-review-20261106-r4/report.json),
[`SHA256SUMS`](docs/evidence/terminal-receipt-review-20261106-r4/SHA256SUMS), and
[`ARCHIVE_SHA256SUMS`](docs/evidence/terminal-receipt-review-20261106-r4/ARCHIVE_SHA256SUMS).
The report embeds both complete source manifests. Text logs and case results are
retained; binaries are omitted. Verify retained bytes using the instructions in
the [archive index](docs/evidence/README.md). These relative links become hosted
only when the maintainer commits and publishes the files.

That was a new execution against the review fixes, not a reconstruction of the
unavailable historical run-2. It used **18 harness tests** at that revision, including
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
hashes are not changed retroactively. Six review regressions brought the
2026-11-06 review-rerun suite to **eighteen**, as recorded by that archive.

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
