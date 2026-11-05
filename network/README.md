# Managed networking

`NewClient` starts one reconnect supervisor. `Network.Client` additionally
registers it with a bounded network owner. Constructors return an owner, not a
promise of readiness. Observe `Snapshot` / `WaitChange`; calls made without a
usable generation fail immediately.

Reconnect durations and attempt counts are explicit:

```go
cfg := network.ReconnectConfig{
    AttemptTimeout:          10 * time.Second,
    ReconnectBudget:         time.Minute,
    MaxAttempts:             5,
    BaseBackoff:             100 * time.Millisecond,
    MaxBackoff:              5 * time.Second,
    CloseTimeout:            time.Second,
    InitialNetworkAvailable: true,
}
```

The connector signature is:

```go
type Connector func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error)
```

Every invocation builds fresh credentials and channel inputs and carries the
same budget through dial, TLS, upgrade, channel establishment, and core Ready.
The supplied attempt clock belongs to the generation: controls synchronously
suspend its connection and invalidate partial establishment. Do not substitute another budget or migrate a connection between
owners. Connector callbacks must join any work they start before returning.

Only I/O, timeout, and closed failures retry automatically. Authentication,
configuration, framing, protocol, and unknown failures block until `Retry`.
An outage includes initial pause/offline time, backoff, attempts, and cleanup.
`Retry` renews the explicit outage and attempt allowance, retaining the backoff
exponent until readiness. Managed pause/offline controls take precedence over
individual client controls. Standalone `Resume` and `Retry` permit one offline
attempt.

Calls return a `GenerationValue[[]byte]` or a sanitized `*CallError`. Generation
zero means no generation was admitted. A nonzero generation with
`OutcomeUnknown` means that peer might have observed the operation. Nothing is
replayed on reconnection. Retained application completions must also check
`IsGenerationCurrent` before delivery.

The supervisor continuously drains core notifications even when no RPCs run.
The local queue is bounded by both count and payload bytes. Overflow drops the
newest payload; cumulative generation-local loss is available in `Status` and
`Notification`. A nil notification payload represents loss-only delivery.
`NextNotification` snapshots once and cannot move into a successor generation.

## Recovery

Use `NewRecoveryFactory` with an explicit principal namespace, persistence,
limits, and negotiation request. Pass the resulting factory in
`ReconnectConfig.RecoveryFactory` and construct with `NewClientWithSetup` or
`Network.ClientWithSetup`.

`ConnectorWithSetup` must install the supplied function as
`syntra.ClientConfig.Prepare`, composing it with its own preparer if necessary.
The factory attaches a fresh `NewRecoveryClient` before `Run`; attachment to an
already-connected client is rejected. The connector must call the preparer
exactly once for the returned client. Profiles and negotiation are never reused.

`CoreReady` and `RecoveryNegotiated` are distinct statuses. When a profile is
required, public calls and profile access remain unavailable until negotiation
succeeds. Neither status asserts restored subscriptions or durable catch-up.
`RecoveryClient` returns a generation-tagged `RecoverySession`; the standard
factory returns `*RecoveryProfile`, exposing its typed core recovery client.

Required recovery automatically retains `Budget.DeferCompletion()` before the
connector runs. Its continuation executes only after successful negotiation and
acceptance of the same control revision, before publishing recovery readiness.
Failed, expired, and obsolete attempts close their transport without releasing
the guard. Applications do not have to configure a completion hook.

`ReconnectConfig.DeferCompletion` optionally injects additional prompt completion
checks for tests or policy. The actual budget guard remains mandatory and checks
the original cutoff after any injected function returns; injection cannot
substitute for or bypass that guard.

## Network and listeners

`New(DefaultConfig())` owns ordinary goroutines with explicit operation,
connection, and callback quotas. Service owners, calls, and `Open` operations
share the operation quota, including generation-bound notification waits.
`MaxCalls` bounds concurrent calls and notification waits on each client.
Callback work remains charged until it returns.

`ListenTCP`, `ListenWS`, and `ListenWSS` consume `ListenerConfig`. Each listener
has a local connection bound and participates in the Network's FIFO shared
admission. `Admission` can add a bound shared across owners. A listener holds at
most one accepted socket awaiting shared admission and reads no establishment
bytes before admission. Idle endpoints hold no shared permits. Permits survive
setup, active sessions, callback cancellation, and complete teardown.

Known transient socket-accept and accepted-socket setup failures retry after
100 ms. Controls can interrupt waiting but do not reset that cutoff; existing
connections continue running during backoff. Unknown accept errors, broken
listener state and closed admission are terminal. Failed setup closes the socket
and releases its local permit before any retry or authentication work.

WS requires loopback binding and peers. WSS requires an explicit `TLSProvider`
and provisioned `TLSAuthority`. The TLS provider wraps the exact supplied socket;
a bare `net.Conn` never establishes a TLS claim. A configured `StreamHost` may
supply application-owned platform sockets through `Network.Open` inside a
connector. On successful return the connector owns that stream. `Listener`
exposes fenced `NotifyAll` / `NotifyDirected` methods and value snapshots.
Notification fan-out skips unauthenticated sessions and attempts every eligible
recipient. A returned joined, sanitized error reports partial queue admission;
successful recipients are not rolled back or automatically replayed.

`ListenHTTP` and `ListenHTTPS` accept `syntrahttp.ServerConfig` and retain the
bound server's complete `Run` lifetime. Both client and server security configs
must set `AllowHTTPCandidate`; HTTPS requires a TLS provider for both streams.
Authority, limits, host policy, and options are explicit. The association server
owns the stream pair and continuously services the download lane while idle.
`HTTPListener` exposes the same controls, notification methods, `LocalAddr`,
`Snapshot`, `CloseContext`, and `Done` ownership boundary.

`Pause`, `Resume`, `NetworkAvailable`, and `PlatformWake` retire current sessions
and partial establishment. Stopping an individual service is terminal even when
its parent later resumes. `Stop` signals ownership teardown. `Shutdown(ctx)`
and `CloseContext(ctx)` bound caller waiting; an incomplete report/error retains
all outstanding ownership. `Done` closes only after actual completion. Callers
must explicitly stop owners they no longer need.

Caller wait expiry and a joined owner's final failure are distinct outcomes.
Pending waits retain ownership without incrementing `Report.FailedSupervisors`.
A failed or overdue owner is counted exactly once after cleanup joins, before
`ClientStopped` is emitted, and retains `ShutdownIncomplete` even when `Done` is
closed. Thus `Report.Complete` can be true with a nonzero failure count. Repeated
close and shutdown calls preserve the settled outcome; they do not recount it.

## Completion and observability

The supervisor directly uses `Suspend`, `IsClosed`, and the retained sanitized
`TerminalError` to fence admission and result delivery before transport cleanup
joins. Managed hosts support `HostConfig.Recovery`; their connection leases stay
owned through `Host.Close` and `Host.Wait`, including source callbacks and egress
that outlive `Serve`'s bounded drain.

`Report.LiveCallbacks` counts managed application invocations.
`Report.LiveExecutions` counts retained root execution leases, including recovery
source/egress workers. Ordinary host callbacks can appear in both counters, so
the counters are not additive. Completion requires both lifetimes to join.

`Events()` creates an independent cursor over the bounded lifecycle event log.
`Events.Next(ctx)` returns `EventLossError` when a slow observer loses entries;
the next call continues at the oldest retained event. `Config.EventCapacity`
defaults to 128. Current status remains available from owned value snapshots
and `WaitChange`, independent of event-log consumption.
