# Verification scope

This document identifies verification surfaces for the current Syntra 1.0 SDK.
It is not an independent security audit, certification, or release attestation.

## Evidence in the source tree

- Codec tests exercise malformed envelopes, duplicate fields, reserved tags,
  size bounds, and opaque payload handling.
- Session and writer tests exercise admission, per-method authorization,
  deadlines, cancellation, bounded output, and teardown.
- `securechannel` tests exercise handshake and record behavior, invalid keys
  and context, clocks, framing bounds, and parser fuzz seeds.
- `transport/ordered` tests exercise record I/O, fragmented frame assembly,
  ordering, budgets, confirmation, and close behavior.
- Connection tests exercise shared establishment deadlines through readiness,
  admission, owned lifetimes, and shutdown. Buffered-decrypt completion races
  distinguish local cipher closure from actual record/authentication failures;
  specific security failures supersede generic connection loss.
- Managed `network` tests exercise real loopback TCP, WS/WSS, and candidate
  HTTP/HTTPS listeners and clients, idle push, notification loss, generation
  fences, bounded reconnects, pause/offline/wake, FIFO shared admission, and
  retained callbacks/recovery workers during incomplete shutdown.
  Shutdown-accounting regressions distinguish pending waits from joined owner
  failures, require one failure event/count before stopped publication, and
  preserve the failed lifecycle after cleanup. Listener tests cover transient
  accept/setup backoff, controls, existing RPC progress and terminal admission
  failure. Exact virtual-time boundaries run on Go 1.25+; portable real-time
  classification/accounting tests also run on the compatibility toolchain.
- `routes` and `proxy` tests exercise endpoint/authority allowlists, fresh inputs,
  explicit cross-carrier policy, direct and tunneled connections, HTTP forwarding,
  hop credential separation, refusal without fallback, and original budgets.
- `transport/tcp`, `transport/websocket`, `transport/http`, `transport/stream`,
  and `transport/tlsstream` tests exercise framing/upgrade bounds, two-stream
  association ownership, HTTP quotas, TLS authority/role/attempt binding,
  standard TLS verification failures, cancellation, and close behavior.
  Source/global rate regressions verify token isolation, full-registry 503
  precedence, and source charging when shared admission rejects an attempt.
- Typed recovery tests exercise runtime attachment and negotiation,
  connection/stream isolation, generation fencing, replay, snapshot staging,
  full-state CAS, lost confirmations, and unknown commit outcomes.
- CI configuration specifies build, test, race, vet, static analysis,
  vulnerability scanning, protobuf generation drift, canonical `go_package`
  enforcement, and Buf `FILE` compatibility except `FILE_SAME_GO_PACKAGE`.
- The required `network-integration` lane runs
  `go test -race ./network ./routes ./proxy ./transport/...` without Docker.
  Structured test events must demonstrate actual
  package execution and named integration tests, including HTTP/HTTPS and proxy
  route subtests. The required `dependency-isolation` lane checks root and
  `securechannel` production dependencies and executes
  `TestHTTPCandidatePolicyIsScoped` for default rejection and explicit opt-in.

Test source and CI configuration identify intended coverage. They do not, by
themselves, establish a passing result for a particular revision. Tests with
local fixtures and the same cryptographic dependency do not establish
independent protocol interoperability or cryptographic assurance.

## Recording results

Use the commands in [CONTRIBUTING.md](CONTRIBUTING.md). Record the source revision,
working-tree state, platform, actual `go version`, command, and result. For fuzz
campaigns, record the target and duration; for benchmarks, retain raw samples
and the measurement boundaries in [BENCHMARKS.md](BENCHMARKS.md).

CI is configured for Go 1.26.10 and a Go 1.23.12 compatibility lane; the module
floor is Go 1.23.0. Record the actual toolchain for each run, particularly for
standard-library vulnerability analysis.

## Local evidence and limits

The current local working tree was checked on Darwin/arm64 with Go 1.26.10.
The complete test suite, race detector, vet, pinned staticcheck 2025.1.1, and
CGO-disabled builds and tests passed across the core, runtime, recovery, networking,
routes, proxies and every carrier. Go 1.23.12 CGO-disabled compatibility tests also
passed. These identify local results, not a committed release or an independent
audit; a configured workflow is not evidence that hosted CI has run.

Protobuf format, lint, build, compatibility, canonical package and generated-byte
drift checks passed, together with 28 schema/generation-script tests and workflow
lint. Networking structured-execution assertions, dependency isolation, candidate
policy tests, local documentation links/anchors, compilation of complete examples,
and a one-iteration benchmark smoke run also passed.

Focused race regressions exercised clean shutdown, overlapping terminal failures,
finite recovery retry budgets, callback accounting and notification isolation
repeatedly. Linux amd64/arm64, Darwin amd64 and Windows amd64 builds were
compile-checked with CGO disabled; they were not executed on those targets.

Ten-second fuzz campaigns passed for `FuzzUnmarshalFrame`, `FuzzParseContext`,
`FuzzHTTPHeaders` and `FuzzRecordFrames`. The current reachable-vulnerability scan
reported no vulnerabilities in its analyzed call graph and 21 in required modules
outside that graph. This does not establish a vulnerability-free dependency set.
Repeat verification for the final committed revision and retain the exact results.

Application record I/O and platform streams, provider honesty and TLS trust,
identity policy, durable storage transactions, stream publication ordering,
and deployment resource controls require verification in the embedding
application. Recovery attachment and fresh per-generation negotiation must be
exercised on that application's connection path. See
[CONNECTION.md](CONNECTION.md) and [SECURITY.md](SECURITY.md).
