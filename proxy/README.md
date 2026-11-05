# Explicit proxy tunnels

```go
creds, err := proxy.NewCredentials(username, password)
cfg, err := proxy.NewProxy(proxy.Config{
    Endpoint: proxyAddress, // netip.AddrPort
    Kind: proxy.Socks5,    // or proxy.HTTPConnect
    Credentials: creds,   // optional
})
conn, err := proxy.Tunnel(ctx, cfg, target, budget)
```

Check each construction error before proceeding. `NewProxy` copies credential
octets; close the original credentials when done constructing configurations,
and close the configuration after its last use. Owned copies and authentication
scratch buffers are cleared. Caller copies, allocator history, and socket
buffers are outside that guarantee. Formatting is redacted for every verb.

`NewIPTarget(netip.Addr, uint16)` and `NewHostnameTarget(string, uint16)` require
explicit nonzero ports. Hostnames use bounded ASCII DNS labels and are sent to
the proxy without local resolution. Socket addresses reject unspecified,
multicast, zero-port, and scoped values. SOCKS credentials accept raw 1–255-byte
fields. HTTP Basic additionally requires printable ASCII and excludes a colon
in the username.

`Tunnel` returns a raw owned `net.Conn`; continue carrier establishment with the
same budget pointer. `TunnelStream` negotiates an already connected owned stream.
`TunnelWithDialer` optionally overrides socket opening. Failure retires partial
streams. Each invocation performs one attempt with no direct fallback.

Malformed or truncated replies return `ordered.ErrProtocol`; authentication,
HTTP 401/403/407, and SOCKS ruleset denial return `securechannel.ErrAuth`.
Unsupported SOCKS commands/address types return `securechannel.ErrConfig`.
Other refusals are sanitized I/O failures. Peer diagnostics are never retained.
HTTP response heads are bounded to 16 KiB, 64 fields, and 4 KiB per line. Every
2xx response immediately enters tunnel mode without consuming tunnel bytes.

Proxy authentication is cleartext to the configured hop. It never becomes an
encrypted-hello credential or an origin Authorization header. A tunnel alone
does not attest TLS or endpoint trust. `AppendForwardAuthorization` is reserved
for an explicitly chosen HTTP forward stream; its caller must clear the encoded
header and keep it scoped to that hop.
