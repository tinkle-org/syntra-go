"""Check Go option enforcement and complete descriptor coverage in isolated trees."""

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "check_go_package", Path(__file__).with_name("check-go-package.py")
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class GoPackageCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="syntra-go-options-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def descriptor(self, name, package=CHECK.GO_PACKAGE):
        result = {"name": name}
        if package is not None:
            result["options"] = {"goPackage": package}
        return result

    def run_check(self, names, descriptors, raw_output=None, error=None):
        for name in names:
            path = self.root / "proto" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// Schema fixture; compilation is mocked.\n")
        output = json.dumps({"file": descriptors}) if raw_output is None else raw_output
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(CHECK.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(["buf", "build"], 0, stdout=output)
            run.side_effect = error
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = CHECK.main(self.root)
            if names:
                run.assert_called_once_with(
                    [
                        "buf", "build", "--as-file-descriptor-set", "--exclude-imports",
                        "--exclude-source-info", "-o", "-#format=json",
                    ],
                    cwd=self.root, check=True, capture_output=True, text=True,
                )
            else:
                run.assert_not_called()
        return result, stdout.getvalue(), stderr.getvalue()

    def test_all_schema_files_including_nested_and_empty_files_are_checked(self):
        names = ["syntra/v1/a.proto", "syntra/v1/empty.proto", "nested/added.proto"]
        result, stdout, stderr = self.run_check(names, [self.descriptor(n) for n in names])
        self.assertEqual(result, 0)
        self.assertIn("all 3 schema files", stdout)
        self.assertEqual(stderr, "")

    def test_wrong_package_in_newly_added_file_is_rejected(self):
        names = ["syntra/v1/a.proto", "nested/new.proto"]
        result, _, stderr = self.run_check(names, [
            self.descriptor(names[0]), self.descriptor(names[1], "wrong/package;wrong"),
        ])
        self.assertEqual(result, 1)
        self.assertIn("proto/nested/new.proto: expected go_package", stderr)

    def test_missing_option_is_rejected(self):
        result, _, stderr = self.run_check(["a.proto"], [self.descriptor("a.proto", None)])
        self.assertEqual(result, 1)
        self.assertIn("found None", stderr)

    def test_import_path_without_canonical_alias_is_rejected(self):
        result, _, stderr = self.run_check(["a.proto"], [
            self.descriptor("a.proto", CHECK.GO_PACKAGE.split(";")[0]),
        ])
        self.assertEqual(result, 1)
        self.assertIn("expected go_package", stderr)

    def test_empty_option_is_rejected(self):
        result, _, stderr = self.run_check(["a.proto"], [self.descriptor("a.proto", "")])
        self.assertEqual(result, 1)
        self.assertIn("found ''", stderr)

    def test_schema_excluded_from_buf_build_is_rejected(self):
        result, _, stderr = self.run_check(
            ["a.proto", "nested/omitted.proto"], [self.descriptor("a.proto")]
        )
        self.assertEqual(result, 1)
        self.assertIn("Schema file missing from Buf build: proto/nested/omitted.proto", stderr)

    def test_unexpected_descriptor_is_rejected(self):
        result, _, stderr = self.run_check(["a.proto"], [
            self.descriptor("a.proto"), self.descriptor("unexpected.proto"),
        ])
        self.assertEqual(result, 1)
        self.assertIn("Unexpected schema descriptor: unexpected.proto", stderr)

    def test_duplicate_descriptor_is_rejected(self):
        result, _, stderr = self.run_check(["a.proto"], [self.descriptor("a.proto")] * 2)
        self.assertEqual(result, 1)
        self.assertIn("Duplicate schema descriptor: a.proto", stderr)

    def test_empty_schema_does_not_pass(self):
        result, _, stderr = self.run_check([], [])
        self.assertEqual(result, 1)
        self.assertIn("No schema files found", stderr)

    def test_empty_descriptor_set_does_not_pass(self):
        result, _, stderr = self.run_check(["a.proto"], [])
        self.assertEqual(result, 1)
        self.assertIn("Schema file missing from Buf build", stderr)

    def test_invalid_descriptor_json_is_reported(self):
        result, _, stderr = self.run_check(["a.proto"], [], raw_output="invalid JSON")
        self.assertEqual(result, 1)
        self.assertIn("Go package check failed", stderr)

    def test_failed_build_preserves_diagnostics(self):
        result, _, stderr = self.run_check(
            ["a.proto"], [], error=subprocess.CalledProcessError(
                1, ["buf", "build"], stderr="schema compilation failed"
            ),
        )
        self.assertEqual(result, 1)
        self.assertIn("schema compilation failed", stderr)

    def test_missing_buf_is_reported(self):
        result, _, stderr = self.run_check(["a.proto"], [], error=FileNotFoundError("buf"))
        self.assertEqual(result, 1)
        self.assertIn("Go package check failed", stderr)


if __name__ == "__main__":
    unittest.main()
