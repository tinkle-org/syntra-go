"""Exercise regeneration checks with a mocked Buf process and isolated trees."""

import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "check_generated", Path(__file__).with_name("check-generated.py")
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class GenerationCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="syntra-go-drift-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output_directory = None
        self.calls = []

    def write_files(self, directory, files):
        for name, content in files.items():
            path = directory / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)

    def run_check(self, committed, generated, version=CHECK.BUF_VERSION, error=None):
        self.write_files(self.root / "gen", committed)
        # Generation must never write to the checkout, even when it fails.
        self.write_files(self.root, {"proto/untouched.proto": b"schema sentinel\n"})
        before = self.snapshot()

        def run(command, **kwargs):
            self.calls.append(command)
            self.assertTrue(kwargs["check"])
            if command == ["buf", "--version"]:
                return subprocess.CompletedProcess(command, 0, stdout=version + "\n")
            self.assertEqual(command[:4], ["buf", "generate", "--template", "buf.gen.yaml"])
            self.assertEqual(command[4], "--output")
            self.assertEqual(kwargs["cwd"], self.root)
            self.output_directory = Path(command[5])
            self.assertTrue(self.output_directory.is_dir())
            self.assertNotEqual(self.output_directory, self.root)
            self.write_files(self.output_directory / "gen", generated)
            if error is not None:
                raise error
            return subprocess.CompletedProcess(command, 0)

        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(CHECK.subprocess, "run", side_effect=run):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = CHECK.main(self.root)
        self.assertEqual(self.snapshot(), before)
        if self.output_directory is not None:
            self.assertFalse(self.output_directory.exists(), "temporary output leaked")
        return result, stdout.getvalue(), stderr.getvalue()

    def snapshot(self):
        return {
            path.relative_to(self.root): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }

    def test_identical_nested_files(self):
        files = {"syntra/v1/a.pb.go": b"generated\n", "syntra/v1/b.pb.go": b"other\n"}
        result, stdout, stderr = self.run_check(files, files)
        self.assertEqual(result, 0)
        self.assertIn("match (2 files)", stdout)
        self.assertEqual(stderr, "")

    def test_changed_bytes_report_diff(self):
        result, _, stderr = self.run_check({"a.pb.go": b"old\n"}, {"a.pb.go": b"new\n"})
        self.assertEqual(result, 1)
        self.assertIn("Generated file differs: gen/a.pb.go", stderr)
        self.assertIn("-old\n+new\n", stderr)

    def test_newline_only_drift(self):
        result, _, stderr = self.run_check({"a.pb.go": b"same\r\n"}, {"a.pb.go": b"same\n"})
        self.assertEqual(result, 1)
        self.assertIn("Generated file differs", stderr)

    def test_non_utf8_drift_is_reported(self):
        result, _, stderr = self.run_check({"a.pb.go": b"\xff"}, {"a.pb.go": b"\xfe"})
        self.assertEqual(result, 1)
        self.assertIn("Generated file differs", stderr)

    def test_missing_committed_file(self):
        result, _, stderr = self.run_check({}, {"nested/a.pb.go": b"new\n"})
        self.assertEqual(result, 1)
        self.assertIn("Missing committed generated file: gen/nested/a.pb.go", stderr)

    def test_obsolete_committed_file(self):
        result, _, stderr = self.run_check(
            {"a.pb.go": b"same", "old.pb.go": b"old"}, {"a.pb.go": b"same"}
        )
        self.assertEqual(result, 1)
        self.assertIn("Unexpected committed generated file: gen/old.pb.go", stderr)

    def test_renamed_file_with_identical_bytes(self):
        result, _, stderr = self.run_check({"old.pb.go": b"same"}, {"new.pb.go": b"same"})
        self.assertEqual(result, 1)
        self.assertIn("Missing committed generated file: gen/new.pb.go", stderr)
        self.assertIn("Unexpected committed generated file: gen/old.pb.go", stderr)

    def test_non_protobuf_committed_files_are_part_of_the_file_set(self):
        result, _, stderr = self.run_check(
            {"a.pb.go": b"same", "extra.txt": b"extra"}, {"a.pb.go": b"same"}
        )
        self.assertEqual(result, 1)
        self.assertIn("Unexpected committed generated file: gen/extra.txt", stderr)

    def test_non_protobuf_generated_files_are_part_of_the_file_set(self):
        result, _, stderr = self.run_check(
            {"a.pb.go": b"same"}, {"a.pb.go": b"same", "extra.txt": b"extra"}
        )
        self.assertEqual(result, 1)
        self.assertIn("Missing committed generated file: gen/extra.txt", stderr)

    def test_empty_generation_fails(self):
        result, _, stderr = self.run_check({"a.pb.go": b"old"}, {})
        self.assertEqual(result, 1)
        self.assertIn("Generation produced no .pb.go files", stderr)

    def test_empty_trees_do_not_pass(self):
        result, _, stderr = self.run_check({}, {})
        self.assertEqual(result, 1)
        self.assertIn("Generation produced no .pb.go files", stderr)

    def test_generation_without_go_protobuf_output_fails(self):
        result, _, stderr = self.run_check({}, {"extra.txt": b"not protobuf output"})
        self.assertEqual(result, 1)
        self.assertIn("Generation produced no .pb.go files", stderr)

    def test_wrong_buf_version_stops_before_generation(self):
        result, _, stderr = self.run_check({}, {}, version="1.58.0")
        self.assertEqual(result, 1)
        self.assertIn("Expected Buf 1.59.0, found 1.58.0", stderr)
        self.assertEqual(self.calls, [["buf", "--version"]])

    def test_failed_generation_cleans_partial_output(self):
        result, _, stderr = self.run_check(
            {"a.pb.go": b"old"}, {"partial.pb.go": b"partial"},
            error=subprocess.CalledProcessError(1, ["buf", "generate"]),
        )
        self.assertEqual(result, 1)
        self.assertIn("Generation check failed", stderr)

    def test_missing_buf_is_reported(self):
        stderr = io.StringIO()
        with mock.patch.object(CHECK.subprocess, "run", side_effect=FileNotFoundError("buf")):
            with contextlib.redirect_stderr(stderr):
                self.assertEqual(CHECK.main(self.root), 1)
        self.assertIn("Generation check failed", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
