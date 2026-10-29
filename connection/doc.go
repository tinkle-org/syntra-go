// Package connection orchestrates SC1 adapters and Syntra sessions for callers
// that need a ready-to-call client or a bounded, admission-controlled server.
// It performs no application RPCs, stores no enrollment data, and never retries
// or falls back to another carrier or security mode.
//
// DialTCP and DialWebSocket return only after core ServerReady validation. Their
// contexts bound establishment (ten seconds total by default, shortened by the
// caller); the owned Client.Run lifetime is independent. Always defer Close on
// a successful client. Wait observes terminal run errors without requiring an
// application-owned error watcher. Connect provides the same ownership for an
// already established syntra.Transport obeying its cancellation contract.
//
// NewServer builds its Host from an explicit ChannelPolicy. Authorize retains
// the core's deny-all default. Configure enrollment Lookup and fail-closed
// lifecycle checks on securechannel.ServerConfig. Server.Close owns the Host,
// listeners and admitted sockets, including half-handshakes. For HTTP carriers,
// configure the caller-owned http.Server's header limits, header timeout, and
// TLS policy, and close the connection Server when shutting down HTTP.
package connection
