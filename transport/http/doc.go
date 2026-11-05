// Package syntrahttp implements the explicitly selected Syntra HTTP/HTTPS
// carrier. HTTP is an outer record envelope; Noise, application credentials,
// authorization, hello, Ready, RPCs and notifications remain in connection and
// ordered. A successful send response acknowledges carrier admission only.
//
// Each association exclusively owns two distinct persistent connections, U for
// uploads and D for polls, to one canonical authority and provisioned route and
// policy generation. Raw net.Conn values cannot establish those network facts.
// ConnectStreams is HTTP only; HTTPS requires two single-use tlsstream proofs
// from the trusted application TLS provider and the same original budget.
// There is no proxy discovery, redirect, retry, replacement stream or resumption.
//
// The transient random route selector is public routing data, never a credential
// or principal. Native errors have fixed empty responses. Origin is absent for
// native clients; accepting a present Origin requires an exact explicit policy.
// Cookies and HTTP authentication are never used. Application authentication
// always evaluates the encrypted hello credential and confirmed channel identity.
//
// Server reservations cover this carrier and conservative runtime frame storage.
// Application handlers, credential stores, recovery services and TLS providers
// must independently bound their private allocations and honor cancellation.
// Close and Wait retain ownership until the actual workers return, including
// slow application policy.
// Source admission runs before the shared rate bucket. A source-quota rejection
// does not spend other sources' shared capacity, and a full source registry
// returns 503 before body reads. An admitted source remains charged when the
// shared rate bucket rejects its attempt with 429.
package syntrahttp
