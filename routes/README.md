# Explicit routes

`New(RouteConfig, Inputs)` constructs a homogeneous connector.
`NewCrossCarrier(RouteConfig, CrossCarrierPolicy, Inputs)` requires explicit
carrier permissions and excludes plaintext WebSocket. Both return
`(Connector, error)` and validate all routes and all allowlist entries before
application inputs or network effects. Lists contain 1–256 entries each.

```go
type Connector func(context.Context, *ordered.EstablishmentBudget) (*connection.Client, error)
type ConnectorWithSetup func(context.Context, *ordered.EstablishmentBudget, func(*syntra.Client) error) (*connection.Client, error)
type Inputs func(context.Context, Endpoint) (securechannel.ClientConfig, syntra.ClientConfig, error)
```

`Route` selects `Kind`, `Address`, `Proxy`, `Target`, `URL`, `Authority`, and `TLS`.
`Route.Endpoint()` returns its comparable allowlist identity. Provision the
allowlist independently. Direct addresses and proxy addresses are
`netip.AddrPort`; URL and HTTP authority are separate identity fields. A proxy
identity includes both hop and destination. Unknown or extraneous fields fail
validation. The connector snapshots the route list and options.

Supported kinds are `TCP`, `TCPProxy`, `WS`, `WSS`, `WSSProxy`, `HTTP`, `HTTPS`,
`HTTPProxy`, `HTTPSProxy`, and `HTTPForward`. HTTP kinds are candidate bindings
4/5 and require an explicit `ClientConfig.AllowHTTPCandidate` boolean. WSS and
HTTPS require an application TLS provider. Proxied WSS/HTTP authorities must
match their tunnel destination. Plain WS requires loopback socket and URL host.

Each invocation selects exactly one endpoint round-robin and calls `Inputs`
outside the selection mutex. The returned security context must match the
selected carrier. There is no automatic discovery, retry, redirect, upgrade to a
different carrier, or direct fallback. A supervisor can convert the named
connector type explicitly; this package has no supervisor dependency.

`NewWithSetup(RouteConfig, Inputs)` and
`NewCrossCarrierWithSetup(RouteConfig, CrossCarrierPolicy, Inputs)` return
`(ConnectorWithSetup, error)` for supervisors that install per-attempt profiles.
The supplied preparation callback is composed after the application's
`ClientConfig.Prepare`. Each runs once before `Run`; an application preparation
failure prevents the supervisor callback, and either error aborts that attempt.
The original inputs configuration is not mutated. The connector is structurally
convertible to `network.ConnectorWithSetup`.

`RouteConfig.Dialer` optionally supplies the socket opener. Its shape is
`func(context.Context, string, string) (net.Conn, error)`. It receives `"tcp"`
and a validated numeric address. The default is `net.Dialer.DialContext`.

## Attempt integration

The supplied budget pointer is retained through dialing, proxy negotiation,
TLS proofs, carrier setup, encryption, and protected readiness.
`Options.Budget` must be empty in stored configuration. The connector calls the
budget's typed `Check` and `Cap` methods before selection. `Cap` shortens in
place relative to the original start, including time already spent by the
supervisor. Checks before inputs, dialing, and each raw I/O operation retain the
same clock and cutoff. Protected readiness releases the setup gate through the
connection owner. A supervisor can call `DeferCompletion` before invoking the
connector to retain that gate through profile negotiation; routes do not release
the deferred continuation.

The HTTP composition uses `transport/http.ConnectStreams`,
`ConnectTLSStreams`, and the exported `ParseRequest` codec. `HTTPForward` opens
two proxy sockets, validates each complete origin header before emitting bytes,
enforces lane/route/counter continuity, rewrites the request target to
absolute-form, and appends hop-only Basic authentication. Bodies are passed
through without modification or replay. It sends no CONNECT request. Candidate
permission is read directly from `securechannel.ClientConfig.AllowHTTPCandidate`,
and context validation uses that same explicit permission. Reflection is used
only to compare the identity of distinct pair sockets without panicking on
`net.Conn` implementations with incomparable dynamic values.
