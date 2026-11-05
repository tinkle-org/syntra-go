// Package connection composes encrypted ordered-message carriers with Syntra
// sessions. Embedders supply ordered.MessageIO implementations; Connect returns
// a ready client and Accept serves a carrier on a caller-owned Host. NewServer
// optionally owns the Host, bounds admission, and joins accepted carriers.
//
// Create ordered.EstablishmentBudget before carrier setup, use Budget.Context
// for that setup, then pass the same pointer in ordered.Options.Budget. Each
// budget belongs to one attempt. Encryption, hello, policy, and Ready retain
// the original absolute deadline. If Budget is omitted, the attempt starts at
// Connect or Accept. A trusted elapsed clock can be injected when constructing
// the budget for platforms requiring embedder-managed lifecycle continuity.
//
// Connect's context controls establishment. Successful clients own independent
// run lifetimes: always Close them. Wait observes terminal errors and Done marks
// completed cleanup. Accept's context controls its whole connection lifetime.
// All supplied carriers must bound reads, honor contexts, and promptly interrupt
// both I/O directions on Close. Shutdown timeouts retain the cleanup owner.
//
// Configure an explicit Host ChannelPolicy to bind the confirmed channel and
// hello credential to an application principal. Per-method Authorize remains
// deny-all unless configured, for example with syntra.AllowAllAuthorize.
// Carrier routing and enrollment checks belong in securechannel configuration.
package connection
