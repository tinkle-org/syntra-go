"""Regression tests for release channels, transitions, and published metadata."""

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
    "check_release", Path(__file__).with_name("check-release.py")
)
assert SPEC is not None and SPEC.loader is not None
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ReleaseCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="syntra-release-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.config = {
            "release-type": "go",
            "packages": {".": {"include-component-in-tag": False}},
        }
        self.write_version("0.0.0")

    def write_json(self, name, value):
        (self.root / name).write_text(json.dumps(value))

    def write_version(self, version):
        self.write_json(".release-please-manifest.json", {".": version})
        (self.root / "CHANGELOG.md").write_text(f"# Changelog\n\n## {version} (2026-11-05)\n")

    def rc(self):
        self.config.update({"versioning": "prerelease", "prerelease-type": "rc.1", "prerelease": True, "initial-version": "1.0.0-rc.1"})

    def test_first_rc_requires_explicit_initial_version(self):
        self.rc()
        del self.config["initial-version"]
        self.assertEqual(self.run_check()[0], 1)
        self.config["initial-version"] = "1.0.0"
        self.assertEqual(self.run_check()[0], 1)
        self.config["initial-version"] = "1.0.0-rc.1"
        self.assertEqual(self.run_check()[0], 0)
        self.config["initial-version"] = "invalid"
        self.assertEqual(self.run_check()[0], 1)

    def test_initial_version_advances_bootstrap_and_matches_channel(self):
        self.config["initial-version"] = "1.0.0-rc.1"
        self.assertEqual(self.run_check()[0], 1)
        self.rc()
        self.config["initial-version"] = "0.0.0-rc.1"
        self.assertEqual(self.run_check()[0], 1)

    def run_check(self, *args):
        self.write_json("release-please-config.json", self.config)
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = CHECK.main(self.root, list(args))
        return code, stderr.getvalue()

    def test_bootstrap_stable_or_rc_config(self):
        self.assertEqual(self.run_check()[0], 0)
        self.rc()
        self.assertEqual(self.run_check()[0], 0)

    def test_valid_numbered_rc_and_stable_tags(self):
        for version in ("1.0.0-rc.1", "1.0.0-rc.2", "1.0.0-rc.10", "1.0.0"):
            with self.subTest(version=version):
                self.rc()
                self.config["prerelease"] = "-rc." in version
                self.write_version(version)
                self.assertEqual(self.run_check("--tag", "v" + version)[0], 0)

    def test_invalid_versions(self):
        for version in (None, 1, "1.0", "v1.0.0", "1.0.0-rc", "1.0.0-rc.0", "1.0.0-rc.01", "01.0.0", "2.0.0", "1.0.0+build", "1.0.0-rc.1\n"):
            with self.subTest(version=version):
                self.write_version(version)
                self.assertEqual(self.run_check()[0], 1)

    def test_mismatched_or_bootstrap_tag_rejected(self):
        self.assertEqual(self.run_check("--tag", "v0.0.0")[0], 1)
        self.write_version("1.0.0")
        for tag in ("1.0.0", "v1.0.1", "refs/heads/main", "--help"):
            with self.subTest(tag=tag):
                self.assertEqual(self.run_check("--tag=" + tag)[0], 1)

    def test_release_channel_mismatch_rejected(self):
        self.rc()
        self.write_version("1.0.0")
        self.assertEqual(self.run_check("--tag", "v1.0.0")[0], 1)
        self.config["prerelease"] = False
        self.write_version("1.0.0-rc.1")
        self.assertEqual(self.run_check("--tag", "v1.0.0-rc.1")[0], 1)

    def test_invalid_channel_config_rejected(self):
        self.rc()
        for key, value in (("prerelease", "true"), ("versioning", "default"), ("prerelease-type", "rc"), ("draft", True), ("skip-github-release", True)):
            with self.subTest(key=key):
                with mock.patch.dict(self.config, {key: value}):
                    self.assertEqual(self.run_check()[0], 1)

    def test_package_overrides_take_precedence(self):
        self.rc()
        self.config["packages"]["."].update({"prerelease": False})
        self.write_version("1.0.0")
        self.assertEqual(self.run_check("--tag", "v1.0.0")[0], 0)

    def test_root_module_tag_convention_enforced(self):
        for key, value in (("release-type", "node"), ("include-component-in-tag", True), ("include-v-in-tag", False)):
            with self.subTest(key=key):
                with mock.patch.dict(self.config["packages"]["."], {key: value}):
                    self.assertEqual(self.run_check()[0], 1)

    def test_release_as_matches_channel(self):
        self.config["release-as"] = "1.0.0"
        self.assertEqual(self.run_check()[0], 0)
        self.rc()
        self.assertEqual(self.run_check()[0], 1)

    def test_missing_or_wrong_changelog_rejected(self):
        self.write_version("1.0.0")
        (self.root / "CHANGELOG.md").write_text("## 1.0.1\n\n## 1.0.0\n")
        self.assertEqual(self.run_check("--tag", "v1.0.0")[0], 1)
        (self.root / "CHANGELOG.md").unlink()
        self.assertEqual(self.run_check("--tag", "v1.0.0")[0], 1)

    def compare(self, previous):
        with mock.patch.object(CHECK.subprocess, "check_output", return_value=json.dumps({".": previous})):
            return self.run_check("--base-ref", "a" * 40)

    def test_channel_transition_leaves_previous_manifest_untouched(self):
        self.write_version("1.0.0-rc.2")
        self.assertEqual(self.compare("1.0.0-rc.2")[0], 0)

    def test_new_release_requires_matching_channel(self):
        self.rc()
        self.write_version("1.0.0")
        self.assertEqual(self.compare("0.0.0")[0], 1)

    def test_version_must_increase_including_numeric_rc_order(self):
        self.rc()
        self.write_version("1.0.0-rc.10")
        self.assertEqual(self.compare("1.0.0-rc.2")[0], 0)
        self.assertEqual(self.compare("1.0.0")[0], 1)
        self.write_version("1.0.0")
        self.config["prerelease"] = False
        self.assertEqual(self.compare("1.0.0-rc.10")[0], 0)

    def test_invalid_or_unavailable_base_fails_closed(self):
        self.assertEqual(self.run_check("--base-ref", "main")[0], 1)
        with mock.patch.object(CHECK.subprocess, "check_output", side_effect=subprocess.CalledProcessError(128, "git")):
            self.assertEqual(self.run_check("--base-ref", "a" * 40)[0], 1)
        self.assertEqual(self.run_check("--base-ref", "0" * 40)[0], 0)

    def test_github_release_classification(self):
        self.rc()
        self.write_version("1.0.0-rc.1")
        release = {"tag_name": "v1.0.0-rc.1", "prerelease": True, "draft": False}
        path = self.root / "release.json"
        self.write_json(path.name, release)
        args = ("--tag", release["tag_name"], "--github-release", str(path))
        self.assertEqual(self.run_check(*args)[0], 0)
        for key, value in (("tag_name", "v1.0.0"), ("prerelease", False), ("draft", True)):
            with self.subTest(key=key):
                self.write_json(path.name, dict(release, **{key: value}))
                self.assertEqual(self.run_check(*args)[0], 1)

    def test_malformed_files_report_failure(self):
        for content in ("{", "[]", "null"):
            with self.subTest(content=content):
                (self.root / ".release-please-manifest.json").write_text(content)
                self.assertEqual(self.run_check()[0], 1)


if __name__ == "__main__":
    unittest.main()
