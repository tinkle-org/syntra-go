# Security policy

## Status and scope

Syntra Go is in development and has no releases yet. Maintainers review
reports against the development branch on a best-effort basis; no released
version support window has been established.

This repository contains the extracted Go implementation and an optional
production Rust ABI adapter. The source snapshot and upstream specification
authority are recorded in [MIGRATION.md](MIGRATION.md). This extraction does
not supply Noise/SC1 cryptography or change the existing TLS baseline.
Applications own secure transports, credential verification, authorization,
and payload semantics. In particular, a nil `HostConfig.Authorize` hook retains
the existing allow-everything behavior documented in [README.md](README.md).

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
