"""Check this repository's single-module RC/stable release metadata, offline."""

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
VERSION = re.compile(r"(0|1)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?")


def object_json(content):
    value = json.loads(content)
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object")
    return value


def version_key(version):
    match = VERSION.fullmatch(version) if isinstance(version, str) else None
    if not match:
        raise ValueError(f"expected a v0/v1 stable version or numbered RC, found {version!r}")
    major, minor, patch, rc = match.groups()
    return int(major), int(minor), int(patch), rc is None, int(rc or 0)


def check(root, tag=None, base_ref=None, github_release=None):
    config = object_json((root / "release-please-config.json").read_text())
    manifest = object_json((root / ".release-please-manifest.json").read_text())
    packages = config.get("packages")
    if not isinstance(packages, dict) or set(packages) != {"."}:
        raise ValueError("expected exactly one release package at the repository root")
    if not isinstance(packages["."], dict) or set(manifest) != {"."}:
        raise ValueError("expected one root package config and one root manifest version")
    options = dict(config, **packages["."])
    if options.get("release-type") != "go":
        raise ValueError("expected release-type go")
    if options.get("include-component-in-tag") is not False or options.get("include-v-in-tag", True) is not True:
        raise ValueError("Go module tags must use vX.Y.Z without a component prefix")
    prerelease = options.get("prerelease", False)
    strategy = options.get("versioning", "default")
    if not isinstance(prerelease, bool) or strategy not in ("default", "prerelease"):
        raise ValueError("expected boolean prerelease and default/prerelease versioning")
    if prerelease and (strategy != "prerelease" or options.get("prerelease-type") != "rc.1"):
        raise ValueError("RC releases require versioning=prerelease and prerelease-type=rc.1")
    if options.get("draft", False) is not False or options.get("skip-github-release", False) is not False:
        raise ValueError("this workflow requires published, non-draft GitHub releases")
    version = manifest["."]
    current = version_key(version)
    initial = options.get("initial-version")
    if initial is not None:
        version_key(initial)
    if version == "0.0.0" and prerelease and (not initial or "-rc." not in initial):
        raise ValueError("first RC release requires an explicit numbered initial-version")
    if version == "0.0.0" and initial:
        if ("-rc." in initial) != prerelease or version_key(initial) <= current:
            raise ValueError("initial-version must advance bootstrap and match the release channel")
    override = options.get("release-as")
    if override:
        version_key(override)
        if ("-rc." in override) != prerelease:
            raise ValueError("release-as does not match the configured release channel")

    changed = False
    if base_ref:
        if not re.fullmatch(r"[0-9a-f]{40}", base_ref):
            raise ValueError("base-ref must be a full commit SHA")
        # The all-zero before SHA denotes a newly created branch.
        if base_ref != "0" * 40:
            previous = object_json(subprocess.check_output(
                ["git", "show", f"{base_ref}:.release-please-manifest.json"],
                cwd=root, text=True,
            ))["."]
            changed = version != previous
            if changed and current <= version_key(previous):
                raise ValueError("release manifest version must increase")

    # An unchanged manifest describes the previous release. A channel-switch
    # PR must be allowed to leave that historical version untouched.
    if tag is not None or changed:
        if tag is not None and tag != f"v{version}":
            raise ValueError("release tag must exactly match the manifest version")
        if version == "0.0.0":
            raise ValueError("0.0.0 is only a bootstrap marker, not a release")
        if ("-rc." in version) != prerelease:
            raise ValueError("release version does not match the configured RC/stable channel")
        changelog = (root / "CHANGELOG.md").read_text()
        heading = re.search(r"^## (?:\[)?([^\]\s]+)", changelog, re.MULTILINE)
        if not heading or heading.group(1) != version:
            raise ValueError("first changelog release heading must match the manifest version")

    if github_release is not None:
        if tag is None:
            raise ValueError("GitHub release verification requires --tag")
        release = object_json(github_release.read_text())
        if release.get("tag_name") != tag or release.get("draft") is not False:
            raise ValueError("GitHub release must be published with the expected tag")
        if release.get("prerelease") is not prerelease:
            raise ValueError("GitHub prerelease flag does not match the configured channel")


def main(root=ROOT, argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", help="also check the exact published tag and changelog")
    parser.add_argument("--base-ref", help="compare manifest against this full commit SHA")
    parser.add_argument("--github-release", type=Path, help="GitHub release API JSON to verify")
    args = parser.parse_args(argv)
    try:
        check(root, args.tag, args.base_ref, args.github_release)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Release metadata check failed: {error}", file=sys.stderr)
        return 1
    print("Release metadata checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
