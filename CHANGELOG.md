# Changelog

## Unreleased

### Added

- Default-disabled scoped terminal receipts through `HostConfig.TerminalMethods`
  and `ordered.Options.EnableTerminalReceipts`; both opt-ins are required.
  `CompleteTerminalReceipt` coordinates fencing, the full-frame barrier, a
  conditional `TerminalAuthority.Commit`, fresh typed observations, and one fixed
  correlated result before retirement. Success means complete local writing, not
  peer receipt or joined cleanup; loss is unknown and never automatically replayed.
- Root Host + ordered/TCP support, including connection ownership/readiness
  wrappers. Recovery-enabled Go hosts, raw drivers, other stock carriers, and
  uncoordinated custom paths refuse before mutation. Ordinary withdrawal defaults
  and wire messages are unchanged. See [usage and limits](TERMINAL_RECEIPT_DESIGN.md).
- Optional `HostConfig.RequestBudget` selects a receipt-origin host cap before
  authorization. `RequestBudgetFromContext` exposes readonly remaining time to
  authorization, handlers, and terminal authority callbacks.
- `FrameReceipt`, `CaptureFrameReceipt`, and `FrameReceiptTransport` preserve
  completing-batch timing for direct transport consumers. The package-level
  `RecvWithReceipt` helper runs ordinary receive policy while obtaining original
  timing for copying and buffering adapters. Drivers publish the original receipt
  through `FrameReceipt.Publish`; root receives retain the ordinary `Recv` path.

### Changed

- `HostConfig` has a new field. Nonempty unkeyed literals written against the
  previous version no longer compile; convert them to keyed literals before
  upgrading. Empty `HostConfig{}` literals remain valid.

## 1.0.0-rc.2 (2026-11-07)

## What's Changed
* feat(receipt): add opt-in scoped terminal receipts by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/18
* test(network): synchronize native HTTP admission fixtures by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/20


**Full Changelog**: https://github.com/tinkle-org/syntra-go/compare/v1.0.0-rc.1...v1.0.0-rc.2

## 1.0.0-rc.1 (2026-11-05)

## What's Changed
* refactor: extract existing Go implementation from syntra by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/1
* fix(ci): use GITHUB_TOKEN for release-please instead of missing RELEASE_PLEASE_TOKEN by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/8
* feat(sc1): RFC 0007 secure channel with TCP, WS and WSS connectivity by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/10
* feat(sdk)!: establish the pure-Go Syntra 1.0 SDK by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/11
* chore(ci): gate releases on verification and document RC promotion by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/13
* chore: configure release candidate versions by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/12
* test: stabilize readiness and reconnect fixtures by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/14
* test: bound benchmark admission to the writer byte budget by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/15
* fix(release): explicitly bootstrap the first RC version by @oscarlaw in https://github.com/tinkle-org/syntra-go/pull/16

## New Contributors
* @oscarlaw made their first contribution in https://github.com/tinkle-org/syntra-go/pull/1

**Full Changelog**: https://github.com/tinkle-org/syntra-go/commits/v1.0.0-rc.1
