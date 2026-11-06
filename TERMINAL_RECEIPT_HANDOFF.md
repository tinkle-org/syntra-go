# Terminal receipt merge and release handoff

The Go and Rust SDKs implement default-disabled scoped terminal receipts on their
coordinated native TCP paths. The shared protocol checkout contains canonical
adoption. Integration, final-tree verification, SDK publication, and application
acceptance remain separate gates; none is implied by this document.

## Change set and ownership

| Repository | Branch | Scope |
| --- | --- | --- |
| `syntra` | `feat/scoped-terminal-receipt` | Canonical connection/RPC/security/transport requirements and conformance definitions |
| `syntra-go` | `feat/scoped-terminal-receipt` | Root Host, ordered/TCP coordinator, authority API, tests, fixture, and SDK docs |
| `syntra-rs` | `feat/scoped-terminal-receipt` | Runtime coordinator, native TCP integration, authority/context APIs, tests, fixture, and SDK docs |

The shared adoption is uncommitted on branch base `c6a28ab`. It must be reviewed
and merged before being described as the merged current reference. The accepted
RFC alone and the implemented SDKs do not make those adoption edits part of
`main`. No SDK version is allocated here.

The SDK wire inputs are unchanged: receipts use the existing correlated
`Frame`/`RpcResult`, with no new peer option, negotiation, message, protobuf source,
or generated binding. Existing pinned wire-input provenance remains legitimate
for its exact unchanged inputs. It is not a claim that a pin includes every new
normative document or that the feature has been published. Do not fabricate a
publication, force a pin to unpublished material, or relabel input hashes.

## Integration contract

Use the language-specific documents as the API authorities:

- [Go usage and limits](TERMINAL_RECEIPT_DESIGN.md): both
  `HostConfig.TerminalMethods` and `ordered.Options.EnableTerminalReceipts` are
  required. Call `CompleteTerminalReceipt` before mutation. Its success reports
  complete **local writing**, not peer receipt or joined cleanup. Recovery-enabled
  Go hosts refuse before mutation.
- Rust usage and limits, `syntra-rs/TERMINAL_RECEIPT_DESIGN.md`
  (requires a sibling checkout): the factory
  supplies an optional policy bound to verified identity; the context-aware
  handler returns the outcome from `retire` promptly, without awaiting its own
  output. The typed authority replaces the generic connection guard. Actual Host
  recovery attachments are fenced and retired before transition.

Both require a conditional authoritative transition, exact private SDK owner,
nonzero/nonexhausted expected revision, and fresh typed evidence of a strictly
newer revision that stays stable after first observation. Neither callback
success nor an unconditional revoke boolean is proof. SDK-owned Go contexts do
not guarantee downstream context values; bind identity through transition scope
and current application authority. Rust binds the adapter through verified
identity and checks the transition's principal/method/owner.

The fixed result is at most 1,024 serialized Frame bytes, excluding its four-byte
prefix. The total deadline is the earlier of the RPC deadline and five seconds
from reservation, with `min(initial remaining / 4, 250ms)` reserved for teardown.
Go bounds each observation to at most one second; Rust permits 1..=250 ms. These
are implementation constraints, not separate wire settings.

The Rust native pump additionally limits an ordinary frame's whole write to the
authority interval (`read_timeout / 2`), including framing, encryption and
backpressure. With a 100 ms read bound that is 50 ms, even if background reads
continue to find fresh authority. Qualify ordinary traffic against that cap
before enabling the Rust host policy; no bulk-transfer capacity is claimed.

Fencing blocks new ordinary egress. Only an already-active ordinary full frame may
finish before mutation, or the operation aborts. Partial encrypted output is completed
in order or abandoned with cipher retirement, never re-encrypted or replayed.
Observed external denial/unknown state is sticky. A remote change after the last
authoritative read can race carrier output; no delivery guarantee is possible.
Callback/external-work charges persist until actual completion, independently
of local writing, client observation, and joined cleanup.

## Recorded verification

These results were recorded on 2026-11-06. They are not a final-tree fingerprint
or a promise that a later rerun will pass.

| Scope | Recorded result | Boundary |
| --- | --- | --- |
| Go full race suite | All 13 test-bearing packages passed after revision-preflight regression | Repeat after later edits; no aggregate top-level count asserted |
| Go compatibility | CGO-disabled Go 1.23.12 suite passed | Build/API compatibility, not a production toolchain recommendation |
| Go static/format checks | Vet, formatting, and whitespace checks passed | Recheck the final diff |
| Rust runtime | 434 passed with defaults and the same 434 scope without defaults, including stable-newer-revision checks | Do not add repeated scopes as distinct cases |
| Rust net | TCP: 102 passed, including 17 receipt integrations; raw/no-default: 68 passed | No non-TCP receipt support inferred |
| Rust workspace | 681 passing tests/doc-tests under CPU load; one Docker fixture ignored | Feature-gated zero-test entries are not coverage |
| Rust portability/isolation | WASM build and all six isolation graphs passed; FFI production: 14 passed | No browser execution or receipt ABI support |
| Rust lint | Clippy completed | Not warning-free; two existing runtime warnings remain in untouched code |
| Shared adoption | 154 repository tests, 15 schema tests, and validators passed | Thirteen requirements and fourteen registered case groups; no formal execution claim |
| Bidirectional TCP fixture | 14 distinct cases passed | Volatile authorities, not production durability or application acceptance |

The canonical case registry is
`syntra/conformance/README.md#scoped-terminal-receipt-definitions`
(requires a sibling checkout).
Its fourteen `CONF-TRC-*` groups remain `NOT_EXECUTED`. The fourteen SDK interop
cases are a separate bounded matrix, not execution of every registered group.

These SDK design and canonical-adoption destinations are not present at the
recorded run-2 Rust commit or the accepted specification commit. They are plain
checkout paths, not links that incorrectly imply a hosted file or anchor exists.

A final concurrent run exposed a wall-time assumption in the Rust multirecord
barrier test. Its 200 KB frame could exceed the existing 50 ms write budget
under CPU load; authority remained fresh and commit correctly stayed at zero.
The success test now drives elapsed time and waits for an explicit reservation
event, while a separate exact-50-ms test proves fail-closed cutoff. Production
timeouts were not changed. The corrected tests passed 500 focused runs, 50 full
receipt-suite runs and a workspace run under owned CPU load. A fresh interop
report is required for this later test/source snapshot.

## Preserve run-2 evidence

[TERMINAL_RECEIPT_INTEROP.md](TERMINAL_RECEIPT_INTEROP.md) owns the exact run-2
matrix, source manifests, hashes, commands, and evidence limits. Its report is:

```text
/var/folders/xv/g_j4t2793xdbd_wnr290xgyw0000gn/T/opencode/terminal-receipt-interop-20261106-run2/report.json
```

The matrix covers both SDK role directions: owned/gap over direct and fragmented
TCP, deny, unknown, and partial receipt loss. Every case includes a fresh Returning
probe with no RPC, actual authority denial, and checked fixture state/closure.
It proves neither durable storage nor an application Logout result.

Keep that evidence note and report unchanged. Final-tree verification needs a
fresh harness output directory and its own source manifest/report; never replace
the old run's hashes with future values or describe old evidence as a new run.
The reproduction command belongs to the evidence note.

## Manual merge and release order

Only the user authorizes and performs merge/release actions through the existing
repository workflows. This handoff does not authorize commits, pushes, PRs,
publication, version edits, consumer repinning, or application changes.

1. Finish review and final-tree verification in all three existing branches.
   Rerun Go race/static checks, locked Rust workspace and isolated feature scopes,
   shared validators, and the fresh bidirectional fixture matrix after the last
   source/documentation edits. Record failures, ignored scopes, and warnings.
2. Merge the shared canonical adoption first. Verify that the merged reference
   contains the thirteen requirements and fourteen case definitions; do not turn
   registry validation into a formal protocol execution verdict.
3. Merge the reviewed SDK implementations and docs through normal checks. Keep
   exact unchanged wire-input provenance; make any future provenance update a
   separate truthful reviewed change, not a fabricated release dependency.
4. Release the SDKs using their normal automation: Go's
    [release process](RELEASING.md), and Rust's
    [`release-plz.toml`](https://github.com/tinkle-org/syntra-rs/blob/72f4cb16f7832226549d7464ce4073a2e40954f3/release-plz.toml) /
    [Release-plz workflow](https://github.com/tinkle-org/syntra-rs/blob/72f4cb16f7832226549d7464ce4073a2e40954f3/.github/workflows/release-plz.yml).
    These two hosted files were verified at the recorded run-2 Rust commit.
   Let the workflows select versions and perform publication in their required
   order. Verify the actual published artifacts; do not manually invent tags or
   treat an Unreleased entry as availability.
5. Adapt application consumers separately, using a production authority adapter
   and the supported runtime/carrier composition. After publication, select the
   real SDK versions through normal consumer pinning and rerun application
   acceptance without unpublished overrides.

An SDK upgrade alone does not fix a consumer's Logout flow. Production storage
durability, current-authority semantics, protected-store clearing, affected
connection closure, and application observation still need application evidence.
[Issue 17](https://github.com/tinkle-org/syntra-go/issues/17) remains open; describe
the SDK capability as implemented and fixture-tested, not the application as
fixed. No application repositories are changed by this handoff.
