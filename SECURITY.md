# Security policy

## Status and scope

Syntra Go is in development and has no releases yet. Maintainers review
reports against the development branch on a best-effort basis; no released
version support window has been established.

This repository implements the Syntra v1 core, an optional production Rust ABI
adapter, and experimental SC1 draft-1 channels over TCP and WS/WSS. **The SC1
draft is not accepted upstream and has not received an independent security
audit.** Its exact local contract is in [SC1.md](SC1.md); implementation review
evidence and open findings are in [AUDIT.md](AUDIT.md). Specification review is
pinned to [`syntra@e27fa275f647ccc925b7cf79eb2dd332f20a3d02`](https://github.com/tinkle-org/syntra/tree/e27fa275f647ccc925b7cf79eb2dd332f20a3d02).
Schema/fixture provenance is recorded in [MIGRATION.md](MIGRATION.md).
The draft does not replace upstream's production TLS baseline.

## Security boundaries

- Hosts own credential verification, root identity, per-method authorization,
  enrollment storage and application payload semantics. Nil `Policy` denies
  admission; nil `HostConfig.Authorize` selects `DenyAllAuthorize`.
  `StaticPolicy` is a test/example convenience. `AllowAllAuthorize` is an
  explicit permissive choice.
- `ChannelPolicy` replaces ordinary credential policy and requires freshly
  confirmed transport evidence. Hosts must verify the explicit hello
  credential separately, bind the intended principal (in returning mode the
  example requires the same principal as the channel; bootstrap mode admits
  via `ClientHello.credential` without requiring a channel principal or
  enrollment record), recheck current enrollment and admission
  before ready, and authorize every method. Empty credentials never imply
  channel-principal acceptance. A public handle, M1 or diagnostic connection
  ID grants no authority by itself.
- Only authenticated out-of-band SC1 provisioning is supported. Authorization
  keys are independently generated secrets, and handles are independent random
  eight-byte values with scoped collision checks. Expiry is required; key and
  principal are immutable under a handle/epoch. Transactional issuance,
  delivery/ack recovery, protected client storage and rotation are host-owned,
  unimplemented workflows. Confirmed-peer rechecks use a one-second ticker
  and one-second lookup contexts; this is not instantaneous revocation.
- Supplied adapters bound records, frames, assembly/write/handshake time,
  lifetime and admitted operations. `connection.Server` also bounds aggregate
  admission per server: 128 connections/16 handshakes by default, configurable
  up to 4,096/256. Handshake slots remain occupied through the core ready write;
  shutdown owns listeners, raw handshake sockets and active sessions, with a
  default/max five-second join budget. Hosts still own rate limits, cross-server
  resource budgets, store policy and HTTP header/TLS configuration.
- After hello/ready, the asynchronous host writer admits FIFO snapshots with
  a 256-frame/8 MiB queued-plus-active bound, distinct from the core's 8 MiB
  notification admission cap. Saturation terminates the session; socket stalls
  do not block the session loop. Writes default to five-second timeouts.
  Revocation cancels other callbacks and attempts a 200ms denial drain before
  closing. Writer shutdown cancels/closes I/O and uses a one-second join bound.
  Custom `Transport`, carrier I/O and `Lookup` implementations must honor
  cancellation and close contracts.
- `connection.DialTCP`/`DialWebSocket` bound socket, SC1 and core readiness to
  ten seconds total, shortened by the caller. Successful clients have an
  independently owned lifetime and must be closed. These helpers do not
  reconnect, replay RPCs, retry enrollment or fall back to another carrier/mode.
- WSS dialing enforces TLS 1.3 and certificate verification for inspectable
  standard HTTP transports and rejects custom TLS dial hooks (`DialTLSContext`,
  `DialTLS`) as unsupported; custom RoundTrippers own their TLS policy.
  Accepting servers own TLS configuration, origin policy and secure proxy
  deployment. Forwarded headers do not change `Accept`'s `r.TLS` carrier binding.
- SC1 protects authenticated payload records, not traffic length, timing or
  public routing context. There is no ciphertext header AD. Encryption does
  not make RPC retries idempotent, prevent repeated application operations or
  provide exactly-once effects. Subscription routing and reliable tombstone
  admission still require host-level review.

### Secret retention and diagnostics

Do not log whole hellos, credentials, authorization/private keys, raw payloads
or private policy errors. SC1 `Key` formatting is redacted, but generated
Protobuf String/JSON/reflection output and application logging can disclose
hello credentials. Policy callbacks returning typed RPC errors must use safe
public messages.

The implementation clears accessible scratch/ephemeral buffers and releases
Go credential references after hello emission or close. Go, the Noise library
and the native ABI do **not** guarantee erasure of all secret copies or expanded
keys. ABI v1 has no explicit post-hello credential-release operation and no
handler-completion timestamp input. Pure-Go completion timing fixes do not
establish native parity. See the open ABI findings in [AUDIT.md](AUDIT.md).

## Dependencies and assurance

**Go 1.26.10 is the recommended production and current CI toolchain.** Build
production binaries with a security-patched toolchain so they include the
patched standard library. The module's Go 1.23.0 floor and Go 1.23.12 CI lane
verify API/build compatibility only; neither is a secure-runtime recommendation.

The parent security verification on 2026-10-28 found:

| Analyzed toolchain | Root-module `govulncheck ./...` result |
| --- | --- |
| Go 1.26.4 | 15 reachable standard-library vulnerabilities |
| Go 1.26.9 | One reachable `crypto/x509` vulnerability, [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809) |
| Go 1.26.10 | **Zero reachable vulnerabilities**; 20 additional vulnerabilities in required modules reported as not reachable |

The clean reachable-code result applies to the analyzed root-module paths and
toolchain, not every dependency function, build variant or future application.
The separate integration module has its own dependency graph and
[scan report](tests/integration/README.md#integration-vulnerability-scan), which
records zero reachable vulnerabilities on Go 1.26.10, including the test-only
harness dependencies; the root scan does not cover that tooling.
The root scan's reported `x/crypto/ssh` code is unused by the analyzed root
paths; that result did not require an x/crypto version change. Re-scan when
reachable code, dependencies or the vulnerability database changes. The
production build must use the patched
toolchain; a passing API-compatibility test does not supply those runtime fixes.

Current dependency pins are Protobuf v1.36.6,
flynn/noise v1.1.0, coder/websocket v1.8.15, x/crypto v0.38.0 and x/sys v0.33.0.
The Noise library supplies the established primitives and NK/NKpsk0 handshake;
the local context binding, lifecycle and framing still need independent review.
The optional native core is pinned separately in [README.md](README.md#optional-native-backend).

Checksums, dependency updates, static analysis, reachable-vulnerability scanning,
fuzzing and regression tests each address a limited class of failures. None
is an audit or a guarantee that all dependencies or deployment paths are safe.
Tests using the same Noise library on both sides and Go-to-Go WS/WSS/TCP tests
are not independent Rust SC1 interoperability evidence. Report actual peer
implementations/revisions and exercised paths with conformance results.

## Private vulnerability reports

Use GitHub's private vulnerability reporting for
[`tinkle-org/syntra-go`](https://github.com/tinkle-org/syntra-go/security/advisories/new)
(Security → Report a vulnerability). If that channel is unavailable, contact
the repository maintainers through GitHub to arrange a private channel before
sharing vulnerability details. Do not put vulnerability details in a public
issue or pull request.

Include the affected commit/version, backend (pure Go or `syntranative`),
platform, impact, and a minimal reproducer using neutral fixtures. For native
reports, include the Rust revision and build features. Do not include real
credentials, customer data, or private deployment diagnostics.

Maintainers triage privately, coordinate fixes and disclosure with the
reporter, and credit reporters only with consent. Reports that affect shared
schemas, protocol rules, or the Rust implementation are coordinated with the
upstream maintainers.
