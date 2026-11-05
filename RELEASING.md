# Releasing Syntra Go

Syntra Go is distributed as source through the root Go module
`github.com/tinkle-org/syntra-go`. Release Please owns version changes,
`CHANGELOG.md`, immutable `vX.Y.Z` tags, and GitHub Releases. There is no binary
upload or separate package-registry publish step. The current module path
supports major versions zero and one; a future v2 needs a module-path migration
and updated release validation.

## CI and publication

The `Go` workflow runs on pull requests and pushes to `main`. Its `ci-success`
job includes release metadata validation alongside build, tests, race checks,
compatibility, generation, security, fuzz smoke, and workflow linting. Keep
`ci-success` required in branch protection. Metadata checks compare the proposed
manifest against the base commit, reject version regressions, and require a
changed version to match the configured release channel and first changelog
entry. A configuration-only channel switch leaves the previous manifest intact.

Only a successful `main` push run calls the reusable `Release Please` workflow.
Only its publication job has write permissions. An older run skips release
automation if `main` has already advanced; the newer commit must pass CI first.
Main runs are not automatically cancelled during publication. The SHA check is
not an atomic lock against a concurrent push, so avoid merging other changes
while releasing a candidate.

After a new release is created, a read-only job checks out its exact tag,
compares its commit with Release Please's reported SHA, validates the GitHub
prerelease flag, and builds and tests the tagged source with CGO disabled. It
also downloads the exact module version through `proxy.golang.org`, with fresh
caches and no direct-VCS fallback, and checks the returned path, version,
checksums, and origin commit when available. Proxy propagation gets six bounded
attempts. This is post-publication verification, not an atomic publishing gate:
a failure cannot undo an already-public tag or release.

The workflow uses the built-in `GITHUB_TOKEN`, not a PAT. GitHub suppresses new
workflow runs for PRs, tags, and releases created with that token. Consequently,
verification runs in the calling workflow rather than on a release event.
Generated release PRs may have no checks until a maintainer closes and reopens
them using their own account. Do that after the bot's latest update and require
fresh checks before merging; do not bypass branch protection. A GitHub App token
could automate those PR events later, but is not required by this setup.

## Start the RC series

Merge the RC configuration separately from the generated release PR. Preserve
the existing package settings and set these top-level properties in
`release-please-config.json`:

```json
{
  "versioning": "prerelease",
  "prerelease-type": "rc.1",
  "prerelease": true
}
```

`rc.1` is the initial suffix, not a value to edit for each candidate. The
prerelease strategy increments the numeric suffix of an existing prerelease.
With the initial `0.0.0` manifest and the pending breaking changes, the expected
first candidate is `1.0.0-rc.1`. The manifest's bootstrap value is not a release.

Wait for the configuration merge's `Go` run and Release Please job to finish.
Inspect the generated PR's actual manifest and changelog, not just its title.
If it still proposes stable `1.0.0`, do not merge it. Check the release job logs
and configuration instead. Release Please may update the existing release PR;
a new PR number is not required.

Merge the generated RC release PR only after review and successful checks.
Watch the merge's `Go` run through `release / verify-release`, then verify that
the GitHub release is a prerelease with the expected tag. In a separate consumer
module, test the explicit candidate version:

```sh
go get github.com/tinkle-org/syntra-go@v1.0.0-rc.1
go test ./...
```

Do not use `@latest` to select an RC when a stable release exists. A tag permits
Go module discovery; it is not proof that pkg.go.dev indexing has completed.

## Subsequent candidates

Merge candidate fixes through ordinary PRs with conventional commit messages,
such as `fix: correct connection cleanup`. Keep RC configuration enabled and let
Release Please propose the next candidate. For this initial 1.0 series,
`1.0.0-rc.1` should advance to `1.0.0-rc.2`. Always inspect the actual proposed
version, especially when new features or breaking changes land. Do not manually
increment the manifest or change `prerelease-type` to `rc.2`.

Each candidate follows the same review, merge, and tagged-module verification
sequence. Test the actual tagged version in downstream applications before
deciding to promote it.

## Promote to stable

Promotion is a separate reviewed configuration PR after an RC has been accepted.
Set `prerelease` to `false` and `versioning` to `default`, and remove
`prerelease-type`. Check for per-package overrides as well as top-level values.
Leave `.release-please-manifest.json` at the last released RC version.

To request exactly `1.0.0` rather than relying on an inferred bump, preserve this
message in the configuration PR's squash-merge commit, including the footer:

```text
chore: prepare stable 1.0.0 release

Release-As: 1.0.0
```

The footer is consumed from the merged commit body, not merely the PR title.
It is a one-time request; avoid a persistent `release-as` config override that
would force the same version on later runs. Wait for CI and inspect the new
release PR for manifest `1.0.0`, stable release configuration, and complete
release notes. Check that the stable notes describe the public 1.0 API and not
only the small delta since the last RC. Merge the release PR when ready, and
verify the new `v1.0.0` release is not marked as a prerelease.

The stable tag is a new release commit containing release bookkeeping. Do not
rename, delete, or move the RC tag. Compare source changes since the accepted
RC and rerun downstream tests against `v1.0.0`. Future stable versions can then
follow conventional-commit version bumps. Enter another RC series only through
an explicit configuration change.

## Failures and retries

If pre-publication CI fails, fix it before retrying; no release should be created
by that failed run. If only tagged-module verification fails after publication,
rerun that failed job from the original `Go` workflow run after investigating or
allowing proxy propagation. Do not rerun successful publication merely to retry
verification, and do not recreate the tag.

If publication itself fails partway, inspect the GitHub release, tag, merged PR
labels, and action logs before retrying. A tag/release may already exist even if
the job failed. Resolve the cause and retry only as appropriate for that state;
never force-push a released tag. Published defects normally require a new RC or
patch version.

For local metadata and workflow changes, run:

```sh
python3 scripts/check-release.py
python3 -m unittest discover -s scripts -p 'test_*.py' -v
actionlint .github/workflows/*.yml
git diff --check
```

On a released checkout, also run
`python3 scripts/check-release.py --tag v1.0.0-rc.1`, substituting its actual tag.
These local checks do not prove hosted Actions permissions or public proxy
availability. See the upstream [Release Please action documentation](https://github.com/googleapis/release-please-action)
and [version override documentation](https://github.com/googleapis/release-please#how-do-i-change-the-version-number).
