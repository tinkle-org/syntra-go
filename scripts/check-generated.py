#!/usr/bin/env python3
"""Check pinned Go generation in temporary storage without changing the tree."""

import difflib
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
BUF_VERSION = "1.59.0"


def generated_files(directory):
    return {path.relative_to(directory): path for path in directory.rglob("*.pb.go")}


def main():
    try:
        version = subprocess.run(
            ["buf", "--version"], check=True, capture_output=True, text=True
        ).stdout.strip()
        if version != BUF_VERSION:
            print(f"Expected Buf {BUF_VERSION}, found {version}", file=sys.stderr)
            return 1

        with tempfile.TemporaryDirectory(prefix="syntra-go-generation-") as temporary:
            subprocess.run(
                [
                    "buf", "generate", "--template", "buf.gen.yaml",
                    "--output", temporary,
                ],
                cwd=ROOT,
                check=True,
            )
            committed = generated_files(ROOT / "gen")
            generated = generated_files(Path(temporary) / "gen")
            if not generated:
                print("Generation produced no .pb.go files", file=sys.stderr)
                return 1

            drift = False
            for path in sorted(committed.keys() | generated.keys()):
                if path not in committed:
                    print(f"Missing committed generated file: gen/{path}", file=sys.stderr)
                    drift = True
                elif path not in generated:
                    print(f"Unexpected committed generated file: gen/{path}", file=sys.stderr)
                    drift = True
                elif committed[path].read_bytes() != generated[path].read_bytes():
                    drift = True
                    sys.stderr.writelines(difflib.unified_diff(
                        committed[path].read_text().splitlines(keepends=True),
                        generated[path].read_text().splitlines(keepends=True),
                        fromfile=f"committed/gen/{path}",
                        tofile=f"generated/gen/{path}",
                    ))

            if drift:
                return 1
            print(f"Generated Go files match ({len(generated)} files).")
            return 0
    except (OSError, subprocess.CalledProcessError) as error:
        print(f"Generation check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
