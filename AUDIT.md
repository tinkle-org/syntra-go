# Implementation audit notes

This is an implementation review and evidence ledger for `feat/sc1-connectivity`,
dated 2026-10-28. It is **not an independent security audit, certification or
complete conformance report**. Findings below describe source and regression
coverage; passing local tests does not establish absence of vulnerabilities.

## Final working-tree verification

On 2026-10-28, the following passed on `feat/sc1-connectivity`, using Go
1.26.10 on darwin/arm64 unless another toolchain is named:

- Full root-module race suite, default build with CGO disabled, vet, and
  staticcheck. Go 1.23.12 compatibility tests also passed.
- Native-tagged tests and race tests against the exact Rust pin below, including
  the connection and carrier packages; native-tagged staticcheck passed.
- Actual Docker integration across TCP/WS/WSS in both bootstrap and returning
  modes, including Toxiproxy stalls/resets and verified WSS. The final rerun
  completed in 30.681 seconds with no container cases skipped.
- Root `govulncheck ./...` and integration `govulncheck -test ./...`: zero
  reachable vulnerabilities. Required but unreachable module advisories remain
  visible in each scan's output; no exclusions were added.
- All root-module in-memory benchmarks, three 100ms samples at `-cpu=1,4`.
  Allocation-free phase-header checks, context/prefix encoding and wire scans
  have zero-allocation evidence; full Protobuf decode and RPCs do not.
- Five-second fuzz smoke runs for `FuzzUnmarshalFrame`, `FuzzDuplicateContent`,
  `FuzzParseContext` and `FuzzContextRoundTrip`; these are not long fuzz campaigns.
- Actionlint, Buf format/lint/build, all eight generated Go snapshots, and
  `git diff --check`.

The benchmark harness rejects premature pump termination. During its controlled
joint shutdown, a peer may observe connection closure before parent-context
cancellation propagates; this is not counted as an RPC outcome. A CI output
check rejects failed benchmark samples independently of the command exit code.

Consumed plaintext record scratch is cleared after copying to the caller's
owned frame, and outgoing plaintext scratch is cleared after encryption.
These bounded-buffer cleanups do not imply erasure of all Go or library copies.

## Authority and source pins

- Upstream specification review reference:
  [`tinkle-org/syntra@e27fa275f647ccc925b7cf79eb2dd332f20a3d02`](https://github.com/tinkle-org/syntra/tree/e27fa275f647ccc925b7cf79eb2dd332f20a3d02).
  RFC 0007 and the secure-channel/device-authorization companion documents
  are drafts. [SC1.md](SC1.md) records this implementation's exact draft-1
  domain, context encoding and carrier choices; upstream acceptance is pending.
- Schema/fixture provenance: [MIGRATION.md](MIGRATION.md), including the
  immutable source snapshot at `2a91da7fdb96f3e75badf07614c14e4f85c9ba1c`.
- Optional production Rust ABI dependency:
  [`tinkle-org/syntra-rs@fca1063515d3966be71e9844346e7cbc53769c76`](https://github.com/tinkle-org/syntra-rs/tree/fca1063515d3966be71e9844346e7cbc53769c76),
  ABI v1, built with `production` and Rust 1.88.0 in native CI.
- Go dependencies: Protobuf v1.36.6, flynn/noise v1.1.0,
  coder/websocket v1.8.15, x/crypto v0.38.0 and x/sys v0.33.0.
  Current CI and recommended production toolchain: **Go 1.26.10**. The Go 1.23.0
  module floor and Go 1.23.12 CI lane establish API/build compatibility only,
  not production security. Production binaries require a security-patched
  toolchain and standard library.

The specification pin, schema snapshot and native implementation pin serve
different purposes. ABI version agreement is not behavioral conformance, and
the native dependency does not provide an independent implementation of these
Go SC1 carriers.

## Completed implementation reviews

“Completed” identifies the stated local review/fix and its regression evidence.
It does not close the broader TODOs listed below.

| Area | Reviewed behavior | Evidence |
| --- | --- | --- |
| Codec emission and decode | Reserved top-level tags cannot be emitted through retained unknown fields; body/outcome multiplicity and malformed unknown wire data are rejected. Credential/frame sizes and combined message/group recursion are bounded at depth 32. Opaque payload/credential bytes remain opaque. | `syntra.go`, `codec_security_test.go`: `TestCodecSecurityReservedEmission`, `InjectedBodiesAndOutcomes`, `CredentialBound`, `CombinedRecursionLimit`, `OpaqueBytesUnchanged`, `MarshalFrameBound` |
| Root admission and authorization | Nil credential policy denies admission; nil method policy denies effects. A channel policy requires fresh transport confirmation and explicit credential handling. Valid error results remain valid handler outcomes. | `channel_auth.go`, `session.go`, `runtime_security_test.go`: `TestRuntimeChannelPolicyRequiresFreshConfirmation`, `EmptyCredentialDoesNotInferChannelPrincipal`, `NilAuthorizeHasNoHandlerEffects`, `HandlerAcceptsErrorResult` |
| Root lifecycle and timeouts | One five-second hello/policy/ready budget; bounded post-handshake writes; terminal paths close owned transports. Worker admission includes callbacks still running after cancellation. Late completions cannot answer another callback's reused ID. | `runtime_security_test.go`, `session_lifecycle_regression_test.go`, including terminal-path, write-stall, non-cooperative callback and reused-ID regressions |
| Asynchronous host writer | Post-ready FIFO snapshot admission is nonblocking, with queued-plus-active limits of 256 frames/8 MiB. The loop handles dispatch, cancel and deadline work during a blocked send. Saturation is terminal; per-write timeout defaults to 5s, revocation drains actual sends for up to 200ms, and writer shutdown has a 1s join after transport close. | `session.go`, `host_writer_test.go`: `TestHostWriterLoopReapsCancelsAndDispatchesDuringStall`, `TestHostWriterFIFOOwnsSnapshotsAndDrainsActualSends`, `TestHostWriterBoundsIncludeActiveFrameAndDiscardOnShutdown`, saturation, revocation and graceful-shutdown regressions |
| Connection orchestration | Dial returns after validated core readiness within a 10s total socket/SC1/core budget. Client lifetime is independently owned. Server admission defaults to 128 connections/16 handshakes, maxima 4,096/256, with handshake slots retained through ready write and a default/max 5s shutdown budget. No reconnect/replay/fallback. | `client_ready.go`, `connection/`, including readiness/lifetime, core-handshake admission, silent handshakes, total dial budget, active/half-handshake close, origin and uncooperative-policy tests |
| Caller credential ownership | `OpenClient` copies caller credential bytes. Session and pure-Go core references are released after hello emission or close; caller buffers remain caller-owned. | `TestRuntimeCredentialOwnershipAndRelease`, `session.go`, `native_purego.go` |
| Pure-Go completion publication | A completion published before its deadline is preserved when the loop observes it later; publication/reaping share a lock and the core records completion time. | `TestRuntimePureGoCompletionTimestampSurvivesReap`, `TestRuntimePureGoPublishedCompletionSurvivesBlockedWriter`, `completionRecorder` in `session.go`, `native_purego.go` |
| Notification admission/reporting | Pure-Go notification enqueue checks shared count and serialized-byte backlog; drained queue entries release references. Directed and broadcast enqueue errors are aggregated, and only successful enqueues wake pumps. | `TestRuntimePureGoNotificationByteBacklogBound`, `native_purego.go`, `Host.NotifyAll`/`NotifyDirected` in `session.go`, session notification tests |
| SC1 primitive and context boundary | Exact draft context bytes, NK/NKpsk0 suite selection, wrong keys/context rejection, empty handshake payloads, replayed M1 without fresh confirmation, record ordering/failure/limits and redacted key formatting. | `securechannel/channel_test.go`, `channel_fuzz_test.go`; `TestNoiseSuiteInteroperability` configures the same Noise dependency independently of the wrapper |
| Ordered carrier boundary | Prefixes across records, coalesced frames, absolute frame clocks, admission limits, cancellation, idle lifetime close and confirmed-peer lifecycle rechecks. | `transport/ordered/transport_test.go` |
| TCP and WS/WSS binding | TCP short writes, coalescing, partial record deadlines and real sockets; WS binary-message boundaries, fragmentation, partial-header deadlines, origin/subprotocol/carrier rejection and trusted WSS. | `transport/tcp/tcp_test.go`, `transport/websocket/websocket_test.go` |

Test names abbreviated in table cells after the first name retain that row's
`TestCodecSecurity` or `TestRuntime` prefix. Coverage is local unit/integration
evidence, not a result from an external reviewer.

## Remaining gaps and audited TODOs

### Native ABI completion time and credential release

`completionRecorder` is implemented by the pure-Go core. Native ABI v1 has no
completion-timestamp parameter, so native answer/deadline arbitration still
uses answer-processing time. A valid completion published on time can therefore
lose to a delayed loop in the native backend. A Go regression for the pure-Go
fix is not proof that the native behavior is fixed.

The native client receives a credential copy at open. Go drops its own
references after hello emission, but the ABI has no explicit operation for
releasing the native retained credential at that point. This is an upstream
ABI/lifetime gap. Neither buffer frees nor Go `clear` establish erasure of all
native, Go, Noise key-schedule, cipher or compiler-generated copies.

### Enrollment issuance, revocation and rotation

Only explicit authenticated out-of-band provisioning is supported. Generate
the 32-byte authorization key and independently random, collision-checked
eight-byte handle; store immutable key/principal bindings under the scoped
handle/epoch tuple with a required expiry. `Lookup` is host-owned and must
honor cancellation. The adapter checks confirmed peers on a one-second ticker
with one-second lookup contexts, and closes on denial. Exact revocation latency
also includes scheduling and store latency.

There is no enrollment RPC, atomic issuance/delivery/ack recovery, client
storage implementation, or complete key-rotation workflow. `ServerConfig.Check`
rechecks record validity and principal, not equality with the original key;
in-place key substitution under the same handle/epoch is unsupported. Hosts
must check current enrollment and separately verified root identity before
ready, then check current method policy on every call. See the executable
same-principal example in [SC1.md](SC1.md).

### Events, subscription scope and recovery

Notifications carry opaque payloads. `NotifyDirected` routes to all connections
of one principal; it is not a subscription-handle router. Multiple subscriptions
of the same principal require additional host-owned isolation and per-stream
termination. The recovery helpers in `recovery.go` supply store/cache/snapshot/
checkpoint building blocks, not a complete RFC 0006 RPC service, capability
negotiation, routing driver or durable application transaction implementation.
`MemoryStore` is volatile. Reconnect/resubscribe, lost confirmations, generation
invalidation, scheduling, resource budgets and authorization need end-to-end
review and independent interoperability evidence. These gaps remain open.

### Reliable tombstones and tokenless mutations

`ReliableManager.RecordTombstone` requires the caller to establish that execution
is terminal and cannot produce further effects. A timeout or cancellation
request alone does not prove that. The API has no execution-completion proof
token and clears pending work when a tombstone is recorded; misuse can admit a
resend while prior effects still run. `Forget`/`ForgetAt` and tombstone helpers
are host-local, tokenless APIs, not authorized network endpoints. An exposing
service must enforce principal/session/epoch ownership and lifecycle fencing.
Durable outcome/effects atomicity and safe retry admission remain integration
TODOs; bounded caches and helper tests do not provide exactly-once effects.

### Independent assurance and operational limits

- No independent cryptographic review or Rust SC1 interoperability result is
  claimed. Same-library Noise tests, Go-to-Go carrier tests, native-core tests
  and independent cross-language wire interoperability are distinct evidence.
- Production entry points always use `crypto/rand.Reader`. Private helpers
  accept a reader for deterministic entropy-failure tests; there is no public
  RNG override. `TestEntropyFailureFailsClosed` verifies failure in key
  generation, both Noise roles, and unknown-enrollment dummy-key work.
- Record scratch and admitted operations are bounded per connection.
  `connection.Server` supplies aggregate connection/handshake admission per
  server; rate limits, cross-server memory/CPU budgets and store timing/privacy
  remain host responsibilities. The post-ready writer's 256-frame/8 MiB
  queued-plus-active cap covers terminal results as well as notifications and
  is distinct from the core's 8 MiB notification admission cap. Queue admission
  is not delivery; revocation's 200ms terminal drain may fail.
- Close initiates immediate abort, then joins. A custom carrier or `Lookup`
  that ignores cancellation can prevent it from completing. Host callback
  grace periods cannot forcibly kill application code.
- Custom WebSocket RoundTrippers own TLS verification policy; accepting servers
  own TLS configuration and proxy deployment. SC1 does not repeal upstream's
  production TLS policy. Public routing data and traffic lengths remain visible.

## Upstream conflicts still unresolved

### Additional conformance and release work

- The runtime terminates on malformed result envelopes and bodyless input.
  Some pinned mandatory manifests require an affected-RPC-only error or a
  usable connection instead. These expectations need explicit reconciliation
  and wire-observable tests; ordinary unit passes do not close those cases.
- Positive `MaxConcurrent` values below 16 are configurable without a negotiated
  lower-limit binding. Public conformance declarations must not describe such
  configurations as satisfying the baseline concurrency floor.
- Reliable-session helpers permit tokenless reattachment after detach, reject
  over-maximum lease proposals instead of clamping, and can replace a live
  tombstone with a later result. These are draft-extension findings, not proof
  that the extension has an accepted wire runtime.
- No manifest-driven runner or complete per-`CONF-*` evidence declaration is
  supplied. Same-Go container tests and native-core linkage are not independent
  Rust SC1 interoperability. No UDP or HTTP/HTTPS implementation is claimed.
- Generated-code drift is checked, but automated upstream-source identity and
  a pinned schema-breaking baseline remain separate release work. Release
  publication is not yet gated on a complete protocol evidence declaration.

Disjoint version ranges now return `FAILED_PRECONDITION` at the shared host
admission boundary, including with the native backend. Retry-code helpers
express eligibility for an application decision, not safe replay permission.

At the specification pin above, [RFC 0001](https://github.com/tinkle-org/syntra/blob/e27fa275f647ccc925b7cf79eb2dd332f20a3d02/rfcs/0001-public-idl-layout.md)
and companion draft RFCs record incompatible requirements:

| Question | Open issue and local observation |
| --- | --- |
| Typed handshake errors (B1) | The envelope has no legal pre-ACTIVE typed failure carrier: results require nonzero request IDs, hello/ready use zero, and pre-ACTIVE results are forbidden. Local errors plus close do not satisfy the promised remote typed error. No new field or result convention is allocated here. |
| Pre-ACTIVE notifications (B2) | Event text permits ignoring them, while handshake/framing rules require rejection. The local handshake expects hello/ready and rejects other bodies; this does not resolve the upstream conflict. |
| Completed request-ID reuse (B3) | Core reuse after terminal completion conflicts with stale-ID rejection in replay security. Local late-callback isolation protects the current callback, but is not a normative lifetime/replay-policy decision. |
| Unknown body versus metadata (B5) | No discriminator separates unknown top-level metadata from an unknown body. The codec rejects unknown-only bodies as unsupported and retains unknown fields beside a known body; this is not a new upstream allocation. |
| Limits, capabilities and outcome races (B7/B8/B10) | Capability/limit negotiation is unbound; a maximum-size payload may exceed the maximum envelope; cancellation/deadline/outcome rules still need reconciliation. Local resource limits and completion ordering are implementation behavior, not a suite-wide resolution. |

## Reproduce the local evidence

From the root, without Docker:

```sh
export GOTOOLCHAIN=go1.26.10
CGO_ENABLED=0 go test -mod=readonly -count=1 ./...
go test -mod=readonly -race -count=1 ./...
go vet -mod=readonly ./...
```

Use [README.md](README.md#optional-native-backend) for the separately built native
library and native-tag checks. [BENCHMARKS.md](BENCHMARKS.md) describes wire/session
and package-local SC1 handshake/record/framing measurements. The benchmark
workflow uses `-bench . ./...` across root-module packages. Root `go test ./...`
does not run the separate module under
[tests/integration/](tests/integration/README.md). Container/tooling success must name
the two actual peer implementations and revisions before it can support a
cross-language interoperability claim. Record command, toolchain, platform,
source revision and working-tree state with any reported result.

### Verification status (2026-10-28)

Results cover the working tree on `feat/sc1-connectivity`, based on
`188007a882f79183b2d37808803530f1eb6bc723`, with connectivity/runtime development
in progress. They are not a frozen release attestation.

- Full root-module tests, race tests and vet passed with Go 1.26.4 on
  darwin/arm64, as reported by the parent verification run. These functional
  results retain their actual toolchain; Go 1.26.4 is not recommended for
  production security.
- `GOTOOLCHAIN=go1.23.12 go test ./...` passed in the parent verification run,
  establishing API/build compatibility only.
- The exact high-level Go example in [SC1.md](SC1.md) passed with
  `GOTOOLCHAIN=go1.26.10 go run -mod=readonly` in both `tcp` and `ws` modes,
  each printing `hello`.
  Documentation code-fence/local-link checks and whitespace checks also passed.
- The integration agent records a full Docker suite pass in **62.472s**, using
  Go 1.26.10 for both host and fixture builder on the current worktree. All six
  TCP/WS/WSS × bootstrap/returning groups and all three returning-mode Toxiproxy
  stall/reset pairs passed, with no skips. See
  [the integration verification record](tests/integration/README.md#local-verification-status).
- The WebSocket net.Pipe adapter/header/observer microbenchmarks passed a
  `-benchtime=1x` smoke run on Go 1.26.10, darwin/arm64. This is execution
  verification, not a new performance baseline. Actionlint passed with the
  updated workflow pins.
- Native-tagged tests and native race tests also passed on Go 1.26.10 against
  the pinned Rust production library. The timestamp and notification-byte-cap
  tests explicitly apply only to the pure-Go core; native test passes do not
  close the ABI gaps listed above.
  Fuzz-campaign results are not recorded here. Independent Rust SC1 wire
  interoperability and upstream draft acceptance remain unverified.

### Security scan evidence

The parent reported the following root-module scans on 2026-10-28:

| Toolchain | Reachable vulnerabilities |
| --- | --- |
| Go 1.26.4 | 15, in the standard library |
| Go 1.26.9 | One, `crypto/x509` [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809) |
| Go 1.26.10 | **Zero**, using `GOTOOLCHAIN=go1.26.10 govulncheck ./...` |

The Go 1.26.10 scan also reported 20 vulnerabilities in required modules that
were not reachable in the analyzed call graph, including unused x/crypto SSH
paths. No x/crypto pin change was needed for this scan result. This is a
reachable-code finding for the selected toolchain/build, not a dependency-wide
audit or a claim that the compatibility-floor runtime is secure. Production
builds must use the patched toolchain. Re-run scans after changes to code paths,
dependencies or vulnerability data. Original benchmark measurements remain
labeled Go 1.26.4 in [BENCHMARKS.md](BENCHMARKS.md).

The separate integration module's `govulncheck -test ./...` result is clean on
Go 1.26.10: zero reachable vulnerabilities, including the test-only harness
dependencies. See [that scan record](tests/integration/README.md#integration-vulnerability-scan).
It has a different dependency graph from the root production module and is not
covered by the root scan's zero-reachable result.
