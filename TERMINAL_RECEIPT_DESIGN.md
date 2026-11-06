# Scoped terminal receipts

A scoped terminal receipt lets one authorized, self-withdrawing operation attempt
one fixed success result on its initiating encrypted connection. It is disabled
by default. Authority withdrawal is not delayed until the client receives a reply,
and a lost reply never restores authority or authorizes an automatic retry.

## Enable the supported path

The supported stock composition is the root `Host`, the ordered encrypted driver,
and TCP. Both `HostConfig.TerminalMethods` in `session.go` and
`ordered.Options.EnableTerminalReceipts` in `transport/ordered/transport.go` must be
enabled. Existing channel authentication and `HostConfig.Authorize` still apply.
`CompleteTerminalReceipt` in `terminal_receipt.go` additionally requires a
confirmed Returning-mode channel binding. Bootstrap mode rejects before
reservation or mutation, even with successful authentication, method
authorization, and both opt-ins.

The following helper configures only the terminal policy. Supply the application's
credential policy, method authorization, and handler separately:

```go
package example

import (
	"time"

	syntra "github.com/tinkle-org/syntra-go"
	"github.com/tinkle-org/syntra-go/transport/ordered"
)

func EnableRetirement(cfg *syntra.HostConfig, opts *ordered.Options,
	authority syntra.TerminalAuthority,
) {
	cfg.TerminalMethods = map[string]syntra.TerminalMethodPolicy{
		"/example.Authority/Retire": {
			SuccessPayload:     []byte("retired"),
			Authority:          authority,
			ObservationTimeout: 100 * time.Millisecond,
		},
	}
	opts.EnableTerminalReceipts = true
}
```

Pass the options to the server's ordered/connection acceptance path. The payload
must be fixed, non-sensitive application bytes; `OpenHost` copies it. The limit is
**1,024 bytes for the complete serialized correlated `Frame`**, not just its
payload, excluding the four-byte frame-stream prefix.
Constructor validation marshals the full result at maximum version/request-ID
varint widths and rejects oversized templates before any connection or callback
can start. The per-request complete-frame check remains in place too.

Inside the authorized handler, call `CompleteTerminalReceipt` **before** making
the terminal mutation. Only the configured authority's `Commit` performs it:

```go
package example

import (
	"context"

	syntra "github.com/tinkle-org/syntra-go"
)

// expectedRevision comes from trusted current application authority, not input.
func RetirementHandler(expectedRevision uint64) syntra.HandlerFunc {
	return func(ctx context.Context, _ *syntra.RpcRequest) (*syntra.RpcResult, error) {
		err := syntra.CompleteTerminalReceipt(ctx, "retire-enrollment", expectedRevision)
		return nil, err // The terminal path owns the result; do not send another.
	}
}
```

Configure this handler only for the authorized retirement method. The operation
must be nonempty and at most 256 bytes. `expectedRevision` must be nonzero and
less than the maximum `uint64` value; exhausted revisions reject before mutation.
The SDK privately binds the handler context to the live call. Public request IDs,
connection labels, or a caller-created context cannot manufacture this permission.

`CompleteTerminalReceipt` is synchronous: `nil` means **complete local write**,
not peer receipt, protected client storage, or joined cleanup. It writes without
waiting for the handler to return. Do not spawn and abandon it; handlers must join
the work they start. Failure after commit is an unknown outcome, not rollback.

## Implement the authority adapter

The public types are defined in `terminal_receipt.go`:

```go
type TerminalAuthority interface {
	Commit(context.Context, TerminalTransition) error
	Observe(context.Context, TerminalTransition) (TerminalObservation, error)
}
```

`TerminalTransition` contains the SDK-generated private `ReservationID`, bound
principal and channel identity, server key ID, handshake hash, method, application
operation, and expected revision. Atomically compare the expected active revision
and persist the complete transition owner, the newer revision, and every
application condition represented by the fixed success payload. Do not log or
expose the reservation, or accept it from a peer.

Contexts passed to authority callbacks are SDK-owned. Do not assume that arbitrary
downstream request-context values are preserved or constitute identity. Bind the
transaction using `TerminalTransition`, its exact scope/enrollment, and current
authoritative application state.

`Observe` must start a fresh authoritative read covering expiry, enrollment/key
policy, application authority, and superseding denial. Callback success, an
unconditional revocation boolean, an already-revoked record, or a generic key
lookup error is not ownership proof. The SDK cannot establish storage durability
from the adapter interface.

Owned evidence must be visible as soon as the transaction commits, even while
`Commit` is still returning. The supervisor must not classify that interval as
external withdrawal or unknown state merely because the callback is pending.

| Observation | Required evidence and decision |
| --- | --- |
| `TerminalActive` | Exact transition and revision equal to expected; remain fenced without ordinary output or a receipt |
| `TerminalOwnedCommitted` | Exact transition and strictly newer revision; eligible only for the reserved result and remaining gates |
| `TerminalDenied` | External withdrawal, expiry, or superseding denial; sticky abort |
| `TerminalUnknown`, error, timeout, or mismatched evidence | Sticky abort |

The first accepted owned revision is pinned. Later reads must report that same
revision: `7 -> 11` is valid, but then changing owned evidence to `12` aborts even
with the same owner. Returning Active after an owned commit also aborts. Delayed
positive evidence cannot clear failure. An external denial must remain observable
after the owned commit; retaining only a first-owner tombstone is insufficient.

`ObservationTimeout` must be positive and at most **one second**. Each read has
its own elapsed and context deadline within the original operation budget.
Observations serialize, and an independent watchdog interrupts I/O on timeout even
if a callback ignores cancellation. Such callbacks retain execution and cleanup
charges until they actually return. `Commit` must honor its context budget too.

## Fencing and output ownership

The implementation spans `terminal_receipt.go`, `session.go`, and
`transport/ordered/terminal_receipt.go`:

1. Validate method policy, supported transport, private live call ownership,
   revision, frame size, and available budget before mutation.
2. Reserve one connection-local result, fence new dispatch and ordinary egress,
   discard unstarted output, suppress notifications, and cancel siblings.
3. Wait for any active ordinary **complete frame** to finish while authority is
   valid. If a partial frame cannot finish, close without starting `Commit`.
4. Join prior generic authority checks, validate Active, and install the shared
   typed classifier across reader, writer, and idle supervision before `Commit`.
5. Obtain exact owned evidence, select the result once, encrypt it, and freshly
   observe authority again before consuming the private one-use handoff.
6. Finish that exact ciphertext sequence or abort, close, and retire cipher state.

No unstarted ordinary request result, notification, or queued snapshot can follow
the fence; only the already-active frame may finish during the precommit barrier.
Already-running external effects may survive sibling cancellation; this
mechanism does not roll them back. Readers continue encrypted framing and
protocol/control validation without dispatching protected work.

A partial ciphertext consumes cipher state. The writer must retain it until
completion or abort; it cannot splice frames, reuse a nonce, re-encrypt a
replacement, or replay the receipt. The reservation cannot transfer to a fresh
Returning connection, resume session, or recovery stream.

Cancellation selected before success wins; cancellation after selected success
is ignored under existing selection rules. Hard denial, deadline, fatal protocol
or cryptographic failure, and carrier loss can still defeat output. A denial
already published locally before serialized handoff defeats the permit. Remote
authority can change after the last fresh read, including before the first byte;
accepted carrier bytes cannot be recalled. This is not an atomic
database-to-socket transaction or a delivery guarantee.

## Deadline and cleanup

At reservation start `S`, the absolute deadline and reserved teardown tail are:

```text
D = min(RPC deadline, S + 5 seconds)
T = min(initial remaining time / 4, 250 milliseconds)
write cutoff = D - T
```

Quiescence, commit, proof, selection, and complete local writing share this budget.
A stricter caller deadline wins. No barrier, callback, retry, or close phase starts
a new budget. Both trusted suspend-inclusive elapsed time and request/wall
deadlines apply; unknown continuity and clock regression fail closed.

The Go implementation requires two 10-ms watchdog intervals in the tail and room
for the declared read bound before the write cutoff. Very small budgets reject
before mutation rather than extending the deadline. Terminal supervision polls
at 10 ms without changing the ordinary supervision cadence.

Carrier interruption and cryptographic retirement do not wait for surviving
application effects. Commit remains charged to its actual handler, observations
to their actual executions, and scratch/cleanup owners remain until work stops.
An authority callback may request `Host.Close` or `Host.DisconnectPrincipal`; the
terminal connection's close join is retained asynchronously. It must not await
`Host.Wait`, `Host.Done`, or its own serving result. Those joins include its return.
`Host.DisconnectPrincipal` remains an immediate abort, not a receipt drain.

## Support boundaries

| Composition | Status |
| --- | --- |
| Root `Host` + ordered + TCP, confirmed Returning mode | Supported with authentication, method authorization, and both opt-ins |
| Bootstrap mode | Refused before reservation or mutation, regardless of authentication, authorization, or opt-ins |
| `connection.Accept`, `connection.Server.Accept`, ownership/readiness wrappers | Preserve the same ordered/TCP capability |
| Host with `HostConfig.Recovery` | Refused before mutation; recovery authority callbacks are not coordinated by this Go path |
| Raw frame or loopback driver | Refused before mutation |
| Stock WS/WSS or HTTP/HTTPS | No terminal support; refused before mutation |
| Custom carrier/driver | Unsupported unless it implements the entire coordination contract; ordinary ordered I/O alone is insufficient |

Custom trusted integrations must preserve the exact owner, full-frame barrier,
fresh classification, bounded cancellation/close, and partial-I/O ordering. An
independent generic authority monitor cannot grant receipt permission or have its
denial silently ignored. No support is inherited by another carrier or FFI embed.

## Tests and evidence limits

Current source coverage is in `terminal_receipt_test.go`,
`terminal_review_regression_test.go`, `transport/tcp/terminal_receipt_test.go`,
`transport/tcp/terminal_matrix_test.go`, and
`transport/tcp/terminal_review_regression_test.go`. It covers opt-ins and wrapper
ownership, fixed-frame bounds, exact/sticky evidence, revisions, barriers,
partial loss, cancellation, deadline/read bounds, fatal input, fresh Returning
denial, retained charges, and callback-reentrant host controls.

Recorded verification on 2026-11-06 includes a full race run across all 13
test-bearing packages, `go vet`, formatting, and whitespace checks passing after
the revision-preflight regression. The CGO-disabled Go 1.23.12 compatibility
suite also passed. Reproduce checks against the final tree after any subsequent
edit; no aggregate top-level test count is asserted here.

[Cross-language fixture evidence](TERMINAL_RECEIPT_INTEROP.md) records **14
distinct passing cases** across Go-server/Rust-client and Rust-server/Go-client:
owned and commit/return-gap success over direct and fragmented TCP, denial,
unknown authority, and partial receipt loss. Every case includes a fresh
Returning probe with no RPC and checked authority denial. The recorded run-2
hashes, report location, availability, and limits belong to that note.
It is not evidence for later edits until rerun.

`cmd/terminal-fixture/main.go` is a loopback-only volatile authority fixture, not a
production adapter. See the interop note for reproducible harness use rather than
copying fixture credentials into deployments. Neither fixture success nor local
race tests prove production durability, platform suspend behavior, formal
conformance, custom-carrier support, or application Logout acceptance.

## Reference and adoption

The shared contract is connection §6 at
`syntra/specifications/connection.md#6-scoped-terminal-receipt`
(requires a sibling checkout), with linked RPC, security, and transport
requirements. That section is not present at the accepted
specification commit `c6a28abf2c52b3f21a7362366d3f5891f33601d5`, so no pinned
hosted URL for this uncommitted adoption is claimed.
The sibling shared branch contains canonical adoption of thirteen
`SNTR-TRC-*` requirements and fourteen
registered case groups; registration is not formal execution. Its uncommitted
adoption changes must merge before they can be cited as the merged reference.
The SDK uses existing `Frame`/`RpcResult`; no wire message, peer option,
negotiation, protobuf source, or generated binding change is required.

See [the merge and release handoff](TERMINAL_RECEIPT_HANDOFF.md) for verification
and manual release ordering. [Issue 17](https://github.com/tinkle-org/syntra-go/issues/17)
remains open: the SDK capability is implemented and fixture-tested, but consumer
adaptation and application acceptance are separate obligations.
