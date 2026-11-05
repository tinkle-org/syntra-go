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
    return {
        path.relative_to(directory): path
        for path in directory.rglob("*")
        if path.is_file()
    }


def main(root=ROOT):
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
                cwd=root,
                check=True,
            )
            committed = generated_files(root / "gen")
            generated = generated_files(Path(temporary) / "gen")
            if not any(path.name.endswith(".pb.go") for path in generated):
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
                else:
                    committed_bytes = committed[path].read_bytes()
                    generated_bytes = generated[path].read_bytes()
                    if committed_bytes == generated_bytes:
                        continue
                    drift = True
                    print(f"Generated file differs: gen/{path}", file=sys.stderr)
                    sys.stderr.writelines(difflib.unified_diff(
                        committed_bytes.decode("utf-8", errors="replace").splitlines(keepends=True),
                        generated_bytes.decode("utf-8", errors="replace").splitlines(keepends=True),
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
