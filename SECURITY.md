# Security policy

## Scope

Syntra Go implements the Syntra 1.0 core and socket-free runtime with optional
managed networking selected by imports. The networking layer uses ordinary Go
goroutines/netpoll. Noise encryption, record authentication and ordering are
integral to the protocol, including over TLS carriers. The protobuf `Frame` is an
internal envelope inside encrypted records. See [CONNECTION.md](CONNECTION.md)
for connection, stream ownership, and managed lifecycle contracts.

This policy and the checks described in [AUDIT.md](AUDIT.md) do not constitute
an independent security audit or a guarantee of deployment security.

## Application responsibilities

Provision the server public key through a trusted channel. Protect private and
authorization keys in application-owned storage. Returning connections require
the configured authorization material; bootstrap participation does not grant
an application principal. Public routing context, handles, and diagnostic
connection IDs are not credentials.

Verify the explicit hello credential in `HostConfig.ChannelPolicy`, bind it to
the intended confirmed channel evidence, and return a nonempty principal. An
empty credential never implicitly selects the channel principal. With ordinary
`HostConfig.Policy`, the application verifies the credential itself; nil policy
denies admission. `StaticPolicy` does not verify credentials.

Authorize every method using `HostConfig.Authorize` before handler effects.
Nil selects `DenyAllAuthorize`. `AllowAllAuthorize` is an explicit permissive
choice. Check current expiry and revocation according to the application's
identity policy. `PERMISSION_DENIED` denies a method while leaving the session
usable; `UNAUTHENTICATED` ends the session after a bounded denial drain.
`DisconnectPrincipal` closes matching current connections; admission policy must
also deny future attempts.

Custom embedders supply ordered message I/O with bounded receive allocation,
context cancellation, and close that interrupts both directions. Start an
`ordered.EstablishmentBudget` before carrier setup and pass it through
`ordered.Options.Budget` so Connect or Accept retains the deadline through
readiness. `connection.NewServer` can bound admitted connections; the embedder
owns deployment-wide rate, memory and work budgets. Session and record limits
do not replace those controls. Callbacks must honor contexts and join work they
spawn. The SDK cannot forcibly stop application code.

## Networking and TLS boundaries

The built-in carriers are TCP (`1`), loopback-only WS (`2`), and WSS (`3`).
HTTP (`4`) and HTTPS (`5`) are explicit candidates, rejected by default context
validation, parsing, encoding, and handshakes. Each participating client/server
security config must set `AllowHTTPCandidate`; there is no process-wide opt-in.
Cross-carrier routes require an explicit permitted-carrier policy and exclude WS.
Allowlist the actual socket endpoint and the authority/target independently.
Routes select one endpoint per attempt; authentication or proxy refusal does not
trigger direct fallback, redirects, or trust learning.

`StreamHost.Open(ctx, address)` transfers a connected owned stream, honors
cancellation, and joins all dial/cleanup work. Use `Network.Open` inside an owned
connector with the original establishment budget. A returned `net.Conn` alone
does not prove TLS, authority, or an authenticated application principal.

`TLSProvider` is trusted application code. It wraps the exact supplied stream
with authenticated TLS 1.3, no early data, and `http/1.1` ALPN for a provisioned
authority and role. It must preserve cancellation/ownership, verify chain,
hostname, validity time and current application trust, and never redial or
detach I/O. HTTP request/response processing belongs to the carrier, not the
provider. `tlsstream.StandardProvider` uses `crypto/tls`, fresh verification,
and no session resumption/tickets; it rejects verification bypasses and key
logging. Its application callbacks and keys still require appropriate bounds
and current trust/revocation policy.

Single-use TLS proofs bind local metadata to authority, role, and the original
attempt budget before carrier bytes. A trusted custom provider can lie about
its metadata: these checks cannot remotely prove it performed TLS. Provision
and verify the Noise server key and encrypted hello credential independently of
TLS. HTTP/1.1 authority validation and Noise authentication are both required;
neither an HTTP success response nor a public association selector authenticates
an application principal. HTTPS requires TLS on both upload and download streams.
Proxy hop credentials must never become origin or hello credentials. Plain proxy
negotiation can expose hop credentials on that hop; protect and provision it
according to the application's network policy.

Managed Network quotas bound operations, connections, callbacks, and execution
leases. Listener bounds include partial establishment and complete teardown;
HTTP also bounds sockets, associations, handshakes, reserved bytes, and open
rates. These are finite admission limits, not a bound on all process memory or
application-private allocations. Callbacks remain charged until they return.
`Stop` initiates cancellation; a timed-out `Shutdown` / `CloseContext` retains
ownership and outstanding permits. Observe `Done` for actual completion and
keep application/TLS/persistence callbacks cancellation-aware.

Live updates are received without an RPC. Ordinary `Notifications()` and managed
`NextNotification` queues are bounded and lossy; managed loss counters are local
to one connection generation. They are not durable delivery evidence or recovery
progress. Generation-tagged results must be checked before application delivery.

Encryption does not conceal public routing context, traffic length or timing.
Timeouts and cancellation do not prove rollback. A successful enqueue is not
delivery evidence, and a retryable error code does not make an operation
idempotent.

## Recovery and persistence

Configure `HostConfig.Recovery` and construct `NewRecoveryClient` before Run,
using `ClientConfig.Prepare` when Connect owns the client lifecycle. The runtime
binds host recovery sessions to authenticated connections and attaches one
immutable client inbox. Explicitly negotiate after readiness to enable recovery
routing before the lossy notification queue. Authorize stream operations as
well as RPC methods; the normal `HostConfig.Authorize` policy still applies.
Managed clients require a configured recovery factory and a pre-Run preparer,
attaching and negotiating a fresh profile per generation. `CoreReady` does not
mean `RecoveryNegotiated`, restored subscriptions, or completed durable catch-up.

Application-owned `RecoverySource` implementations must validate issued
checkpoints against principal, stable stream and generation, including across
restart and retention pruning. Capture and publication must share an ordering
boundary. Snapshot content and its boundary must remain bound for the transfer.

`RecoveryPersistence` must atomically commit the full application state and
generation/checkpoint using the expected position. `MemoryRecoveryStore` is
volatile. If a commit may have taken effect, return `CommitUnknown`; reload and
reconcile on a fresh connection before further confirmation. Local durability,
confirmation submission, and peer acknowledgement are separate observations.
These contracts do not provide exactly-once application effects.
Application state and payloads are opaque; the SDK imports no application-domain
schemas. Reconnection and recovery never authorize arbitrary mutation replay.

## Secrets and diagnostics

Do not log credentials, whole hellos, private keys, authorization keys, raw
application payloads, or private policy errors. Generated protobuf formatting,
JSON and reflection can expose credential bytes. Typed `RpcError` messages must
contain only safe public text.

The SDK clears accessible scratch and releases credential references during
normal cleanup. Go and cryptographic library internals can retain other copies;
complete secret erasure is not guaranteed.

## Toolchains and analysis

The module floor is Go 1.23.0. CI uses Go 1.26.10 for current verification and
Go 1.23.12 for API/build compatibility. Build deployed binaries with a
security-patched toolchain so they include its standard-library fixes.

CI configures checksum verification, static analysis, reachable-vulnerability
scanning, fuzzing and regression tests. A configured check is not evidence of
its latest result. Local results and their scope are recorded in [AUDIT.md](AUDIT.md). Follow
[CONTRIBUTING.md](CONTRIBUTING.md) to reproduce checks and record the actual
toolchain and scope.

## Private vulnerability reports

Use the project's Security tab to report a vulnerability privately. If private
reporting is unavailable, contact the maintainers to arrange a private channel
before sending details. Keep vulnerability details out of public issues and
pull requests.

Include the affected version or commit, platform, toolchain, impact and a minimal
reproducer with neutral fixtures. Do not include real credentials, customer
data or private deployment diagnostics. Maintainers coordinate fixes and
disclosure with the reporter and credit reporters only with consent.
