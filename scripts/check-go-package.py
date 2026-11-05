#!/usr/bin/env python3
"""Require canonical Go bindings in every schema file's compiled descriptor."""

import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
GO_PACKAGE = "github.com/tinkle-org/syntra-go/gen/syntra/v1;syntrav1"


def main(root=ROOT):
    try:
        schema = root / "proto"
        expected_files = {
            path.relative_to(schema).as_posix()
            for path in schema.rglob("*.proto")
            if path.is_file()
        }
        if not expected_files:
            raise ValueError("No schema files found under proto/")

        result = subprocess.run(
            [
                "buf", "build", "--as-file-descriptor-set", "--exclude-imports",
                "--exclude-source-info", "-o", "-#format=json",
            ],
            cwd=root, check=True, capture_output=True, text=True,
        )
        descriptors = json.loads(result.stdout).get("file", [])
        seen = set()
        problems = []
        for descriptor in descriptors:
            name = descriptor["name"]
            if name in seen:
                problems.append(f"Duplicate schema descriptor: {name}")
            seen.add(name)
            actual = descriptor.get("options", {}).get("goPackage")
            if actual != GO_PACKAGE:
                problems.append(
                    f"proto/{name}: expected go_package {GO_PACKAGE!r}, found {actual!r}"
                )

        for name in sorted(expected_files - seen):
            problems.append(f"Schema file missing from Buf build: proto/{name}")
        for name in sorted(seen - expected_files):
            problems.append(f"Unexpected schema descriptor: {name}")
        if problems:
            print("\n".join(problems), file=sys.stderr)
            return 1
        print(f"Canonical go_package matches across all {len(seen)} schema files.")
        return 0
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError) as error:
        print(f"Go package check failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
