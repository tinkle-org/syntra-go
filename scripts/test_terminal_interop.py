"""Regression checks for the receipt harness's fail-closed evidence validator."""
import importlib.util
import contextlib
import io
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "terminal_interop", Path(__file__).with_name("terminal-interop.py"))
interop = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(interop)


class OutputDirectoryTests(unittest.TestCase):
    """Output selection is portable, nonoverwriting and isolated from both checkouts."""

    def test_output_directory_policy(self):
        """Accept a fresh external directory; reject unsafe paths without source writes."""
        cases = ("portable", "missing-parent", "inside-go", "inside-rust",
                 "go-root", "rust-root", "existing-directory", "existing-file",
                 "symlink-into-go", "dangling-symlink")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                base = Path(tmp).resolve()
                roots = {name: base / name for name in ("go", "rust")}
                for root in roots.values():
                    root.mkdir()
                    (root / "source.txt").write_text("unchanged fixture source\n")
                parent = base / "portable-evidence"
                parent.mkdir()
                output = parent / "new-run"
                if case == "missing-parent":
                    output = parent / "missing" / "new-run"
                elif case.startswith("inside-"):
                    output = roots[case.removeprefix("inside-")] / "new-run"
                elif case.endswith("-root"):
                    output = roots[case.removesuffix("-root")]
                elif case == "existing-directory":
                    output.mkdir()
                    (output / "report.json").write_text("preserve archived report\n")
                elif case == "existing-file":
                    output.write_text("preserve existing file\n")
                elif case == "symlink-into-go":
                    (parent / "alias").symlink_to(roots["go"], target_is_directory=True)
                    output = parent / "alias" / "new-run"
                elif case == "dangling-symlink":
                    output.symlink_to(parent / "absent", target_is_directory=True)
                sources_before = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                                  for root in roots.values() for p in root.rglob("*")}
                paths_before = set(base.rglob("*"))
                if case == "portable":
                    prepared = interop.prepare_output(output, roots)
                    self.assertEqual(output, prepared)
                    self.assertTrue(prepared.is_dir())
                    self.assertEqual([], list(prepared.iterdir()))
                    # A second attempt must not reuse even an empty output directory.
                    with self.assertRaises(ValueError):
                        interop.prepare_output(output, roots)
                else:
                    with self.assertRaises(ValueError):
                        interop.prepare_output(output, roots)
                    self.assertEqual(paths_before, set(base.rglob("*")))
                sources_after = {p: (p.read_bytes(), p.stat().st_mtime_ns)
                                 for root in roots.values() for p in root.rglob("*")}
                self.assertEqual(sources_before, sources_after)
                if case == "existing-directory":
                    self.assertEqual("preserve archived report\n", (output / "report.json").read_text())
                elif case == "existing-file":
                    self.assertEqual("preserve existing file\n", output.read_text())

    def test_archive_preserves_exact_evidence_and_refuses_invalid_inputs(self):
        """Archive reviewable bytes with checked hashes, without copying binaries or overwriting."""
        for case in ("valid", "tampered", "traversal", "absolute", "existing", "missing-parent"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output = root / "output"
                output.mkdir()
                data = {"report.json": b'{"sources":{"go":{"files":[]}}}\n',
                        "case/case.json": b'{"status":"PASS"}\n',
                        "unit-tests.stderr.log": b"archived test output\n",
                        "terminal-fixture": b"excluded fake executable"}
                for name, value in data.items():
                    path = output / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(value)
                manifest = {name: interop.sha256(output / name) for name in data}
                original = "".join(f"{digest}  {name}\n" for name, digest in sorted(manifest.items()))
                (output / "SHA256SUMS").write_text(original)
                archive = root / "archive"
                if case == "tampered":
                    (output / "report.json").write_text("changed report\n")
                elif case == "traversal":
                    manifest["../report.json"] = "invalid"
                elif case == "absolute":
                    manifest[str(root / "report.json")] = "invalid"
                elif case == "existing":
                    archive.mkdir()
                    (archive / "report.json").write_text("preserve existing archive\n")
                elif case == "missing-parent":
                    archive = root / "missing" / "archive"
                if case != "valid":
                    with self.assertRaises((ValueError, FileExistsError)):
                        interop.archive_evidence(output, archive, manifest)
                    if case == "existing":
                        self.assertEqual("preserve existing archive\n", (archive / "report.json").read_text())
                    else:
                        self.assertFalse(archive.exists())
                    continue
                interop.archive_evidence(output, archive, manifest)
                for name, value in data.items():
                    if name == "terminal-fixture":
                        self.assertFalse((archive / name).exists())
                    else:
                        self.assertEqual(value, (archive / name).read_bytes())
                self.assertEqual(original, (archive / "SHA256SUMS").read_text())
                retained = (archive / "ARCHIVE_SHA256SUMS").read_text().splitlines()
                self.assertEqual(3, len(retained))
                for entry in retained:
                    digest, name = entry.split("  ", 1)
                    self.assertEqual(digest, interop.sha256(archive / name))

    def test_archive_failure_removes_only_owned_partial_archive(self):
        """Copy and manifest write failures remove partial exports, preserving other data."""
        for failure in ("copy", "manifest"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp).resolve()
                output, archive = root / "output", root / "archive"
                output.mkdir()
                data = {"report.json": b"report\n", "case.json": b"case\n",
                        "SHA256SUMS": b"source checksums\n"}
                for name, value in data.items():
                    (output / name).write_bytes(value)
                manifest = {name: interop.sha256(output / name)
                            for name in ("report.json", "case.json")}
                unrelated = root / "unrelated"
                unrelated.mkdir()
                (unrelated / "report.json").write_bytes(b"keep unrelated report\n")
                original_open = Path.open
                original_copy = interop.shutil.copyfileobj
                copies = 0

                def copy(source, target):
                    """Fail the second selected copy after leaving a partial file."""
                    nonlocal copies
                    copies += 1
                    if failure == "copy" and copies == 2:
                        target.write(source.read(1))
                        raise OSError("injected copy failure")
                    original_copy(source, target)

                @contextlib.contextmanager
                def open_file(path, *args, **kwargs):
                    """Inject an actual archive-manifest write failure after partial output."""
                    with original_open(path, *args, **kwargs) as target:
                        if failure == "manifest" and path == archive / "ARCHIVE_SHA256SUMS":
                            def write(value):
                                """Leave partial manifest bytes before reporting the write error."""
                                target.write(value[:1])
                                raise OSError("injected manifest failure")
                            yield mock.Mock(wraps=target, write=mock.Mock(side_effect=write))
                        else:
                            yield target

                with mock.patch.object(interop.shutil, "copyfileobj", side_effect=copy), \
                        mock.patch.object(Path, "open", open_file):
                    with self.assertRaisesRegex(OSError, f"injected {failure} failure"):
                        interop.archive_evidence(output, archive, manifest)
                self.assertFalse(archive.exists())
                self.assertEqual({"output", "unrelated"}, {p.name for p in root.iterdir()})
                self.assertEqual(b"keep unrelated report\n", (unrelated / "report.json").read_bytes())
                for name, value in data.items():
                    self.assertEqual(value, (output / name).read_bytes())

    def test_archive_failure_preserves_post_creation_replacement(self):
        """A copy-time rename cannot authorize cleanup of an unrelated replacement."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            output, archive, moved = root / "output", root / "archive", root / "moved"
            output.mkdir()
            (output / "report.json").write_bytes(b"source report\n")
            manifest = {"report.json": interop.sha256(output / "report.json")}
            failure = OSError("injected copy failure after replacement")

            def replace_then_fail(source, target):
                """Replace the owned directory after opening its first target file."""
                target.write(source.read(1))
                archive.rename(moved)
                archive.mkdir()
                (archive / "report.json").write_bytes(b"unrelated replacement\n")
                raise failure

            with mock.patch.object(interop.shutil, "copyfileobj", side_effect=replace_then_fail), \
                    mock.patch.object(interop.shutil, "rmtree", wraps=interop.shutil.rmtree) as cleanup:
                with self.assertRaises(OSError) as raised:
                    interop.archive_evidence(output, archive, manifest)
            self.assertIs(failure, raised.exception)
            cleanup.assert_not_called()
            self.assertEqual(b"unrelated replacement\n", (archive / "report.json").read_bytes())
            self.assertEqual(b"source report\n", (output / "report.json").read_bytes())
            self.assertEqual(b"s", (moved / "report.json").read_bytes())

    def test_archive_never_removes_preexisting_or_racing_destination(self):
        """Exclusive creation failures preserve another owner's directory, file or link."""
        for racing in (False, True):
            for kind in ("directory", "file", "symlink", "dangling"):
                with self.subTest(racing=racing, kind=kind), tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp).resolve()
                    output, archive, other = root / "output", root / "archive", root / "other"
                    output.mkdir()
                    (output / "report.json").write_text("source report\n")
                    manifest = {"report.json": interop.sha256(output / "report.json")}

                    def create_destination():
                        """Create unrelated data at the requested destination before its mkdir."""
                        if kind == "directory":
                            archive.mkdir()
                            (archive / "report.json").write_text("keep directory\n")
                        elif kind == "file":
                            archive.write_text("keep file\n")
                        else:
                            if kind == "symlink":
                                other.mkdir()
                                (other / "report.json").write_text("keep link target\n")
                            archive.symlink_to(other, target_is_directory=True)

                    validate = interop.validate_archive_destination

                    def validate_then_race(path):
                        """Model a competing creator after validation but before exclusive mkdir."""
                        resolved = validate(path)
                        create_destination()
                        return resolved

                    if not racing:
                        create_destination()
                    with mock.patch.object(interop, "validate_archive_destination",
                                           side_effect=validate_then_race if racing else validate):
                        with self.assertRaises((ValueError, FileExistsError)):
                            interop.archive_evidence(output, archive, manifest)
                    if kind == "directory":
                        self.assertEqual("keep directory\n", (archive / "report.json").read_text())
                    elif kind == "file":
                        self.assertEqual("keep file\n", archive.read_text())
                    else:
                        self.assertTrue(archive.is_symlink())
                        self.assertEqual(other, archive.readlink())
                        if kind == "symlink":
                            self.assertEqual("keep link target\n", (other / "report.json").read_text())
                        else:
                            self.assertFalse(other.exists())


class ArchiveCLITests(unittest.TestCase):
    """Reject invalid archive paths before work and retain reports on export failure."""

    def test_invalid_archive_fails_before_snapshots_or_builds(self):
        """Existing paths, dangling links and absent parents never start expensive work."""
        for variant in ("directory", "file", "symlink", "dangling", "missing-parent", "output"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                output, archive = root / "output", root / "archive"
                if variant == "directory":
                    archive.mkdir()
                elif variant == "file":
                    archive.write_text("preserve existing archive\n")
                elif variant in ("symlink", "dangling"):
                    target = root / "target"
                    if variant == "symlink":
                        target.mkdir()
                    archive.symlink_to(target, target_is_directory=True)
                elif variant == "missing-parent":
                    archive = root / "missing" / "archive"
                else:
                    archive = output
                args = ["terminal-interop.py", "--output", str(output), "--archive", str(archive)]
                stderr = io.StringIO()
                with mock.patch.object(sys, "argv", args), \
                        mock.patch.object(interop, "snapshot", return_value={}) as snapshot, \
                        mock.patch.object(interop, "build", side_effect=AssertionError("unexpected build")) as build, \
                        contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(SystemExit) as error:
                        interop.main()
                self.assertEqual(2, error.exception.code)
                snapshot.assert_not_called()
                build.assert_not_called()
                self.assertIn("archive", stderr.getvalue())
                self.assertNotIn("Traceback", stderr.getvalue())
                if variant == "dangling":
                    self.assertTrue(archive.is_symlink())
                    self.assertFalse(target.exists())
                elif variant == "file":
                    self.assertEqual("preserve existing archive\n", archive.read_text())

    def run_main(self, root, archive_error=None, with_archive=True):
        """Exercise CLI reporting with synthetic builds, never executing either SDK."""
        output, archive = root / "output", root / "archive"
        args = ["terminal-interop.py", "--output", str(output)]
        if with_archive:
            args.extend(["--archive", str(archive)])

        def build(command, directory, folder, name, env=None):
            """Create only the fake binary paths required by provenance hashing."""
            self.assertFalse(archive.exists(), "archiving must follow source snapshots")
            if name == "build-go":
                binary = folder / "terminal-fixture"
            elif name == "build-rust":
                binary = folder / "rust-target/debug/examples/terminal_receipt"
            else:
                return
            binary.parent.mkdir(parents=True, exist_ok=True)
            binary.write_bytes(b"test-only fake binary\n")

        stdout = io.StringIO()
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", args))
            stack.enter_context(mock.patch.object(interop, "snapshot", return_value={
                "revision": "fixture", "branch": "fixture", "working_tree_sha256": "fixture"}))
            stack.enter_context(mock.patch.object(interop, "build", side_effect=build))
            stack.enter_context(mock.patch.object(interop.subprocess, "check_output", return_value=b"fixture toolchain"))
            stack.enter_context(mock.patch.object(interop, "run_case", side_effect=lambda case, *args: dict(case, status="PASS")))
            if archive_error is not None:
                stack.enter_context(mock.patch.object(interop, "archive_evidence", side_effect=archive_error))
            stack.enter_context(contextlib.redirect_stdout(stdout))
            code = interop.main()
        return code, output, archive, stdout.getvalue()

    def test_archive_error_is_recorded_without_losing_report_checksums(self):
        """An export exception returns failure while preserving matrix results and evidence."""
        for error in (PermissionError("archive denied"), ValueError("archive changed"), RuntimeError("archive failed")):
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as tmp:
                code, output, _, stdout = self.run_main(Path(tmp), error)
                self.assertEqual(1, code)
                report = json.loads((output / "report.json").read_text())
                self.assertTrue(report["complete"], "the successful matrix must remain distinguishable")
                self.assertEqual(f"{type(error).__name__}: {error}", report["archive_error"])
                manifest = dict(line.split("  ", 1)[::-1]
                                for line in (output / "SHA256SUMS").read_text().splitlines())
                self.assertEqual(interop.sha256(output / "report.json"), manifest["report.json"])
                self.assertIn(str(output / "report.json"), stdout)
                self.assertIn(str(error), stdout)
                self.assertNotIn("Traceback", stdout)

    def test_successful_runs_preserve_optional_archival(self):
        """A valid optional archive copies the final report; omitting it still succeeds."""
        for with_archive in (False, True):
            with self.subTest(with_archive=with_archive), tempfile.TemporaryDirectory() as tmp:
                code, output, archive, _ = self.run_main(Path(tmp), with_archive=with_archive)
                self.assertEqual(0, code)
                if with_archive:
                    self.assertEqual((output / "report.json").read_bytes(), (archive / "report.json").read_bytes())
                    self.assertEqual((output / "SHA256SUMS").read_bytes(), (archive / "SHA256SUMS").read_bytes())
                else:
                    self.assertFalse(archive.exists())


class EvidenceTests(unittest.TestCase):
    """No setup failure or untriggered fault may count as a receipt case."""

    def events(self):
        """Return minimal evidence for one successful owned case."""
        return ([{"event": "transition", "recorded": True},
                 {"event": "connection_closed", "connection": 1},
                 {"event": "fresh_denied", "before_handler": True},
                 {"event": "connection_closed", "connection": 2},
                 {"event": "summary", "commits": 1, "handlers": 1,
                  "denials": 1, "closed": 2}],
                [{"event": "established"}, {"event": "result", "outcome": "observed",
                  "payload": "retired", "receipts": 1}],
                [{"event": "probe", "establishment_denied": True, "calls": 0}])

    def test_matrix_has_fourteen_distinct_cases(self):
        """Count distinct direction/scenario/network combinations, not attempts."""
        cases = interop.matrix()
        self.assertEqual(14, len(cases))
        self.assertEqual(14, len({c["id"] for c in cases}))

    def test_owned_and_invalid_evidence(self):
        """Reject setup failures, duplicate commits, missing denial/closure and bad payloads."""
        for invalid in (None, "setup", "twice", "denial", "payload", "closed"):
            with self.subTest(invalid=invalid):
                server, client, probe = self.events()
                if invalid == "setup":
                    client.pop(0)
                elif invalid == "twice":
                    server[-1]["commits"] = 2
                elif invalid == "denial":
                    server.pop(2)
                elif invalid == "payload":
                    client[-1]["payload"] = "not-retired"
                elif invalid == "closed":
                    server.pop(1)
                args = ({"scenario": "owned", "network": "direct"},
                        server, client, probe, None)
                if invalid is None:
                    interop.validate_case(*args)
                else:
                    with self.assertRaises(AssertionError):
                        interop.validate_case(*args)

    def test_unknown_requires_typed_post_establishment_failure(self):
        """Only post-ready Unavailable is an accepted unknown outcome."""
        for code in ("Unavailable", "DeadlineExceeded", "setup", "Unauthenticated"):
            with self.subTest(code=code):
                server, client, probe = self.events()
                server.insert(1, {"event": "authority_outcome", "state": "Unknown"})
                client[-1] = {"event": "result", "outcome": "unknown",
                              "code": code, "receipts": 0}
                args = ({"scenario": "unknown", "network": "direct"},
                        server, client, probe, None)
                if code == "Unavailable":
                    interop.validate_case(*args)
                else:
                    with self.assertRaises(AssertionError):
                        interop.validate_case(*args)

    def test_partial_loss_requires_exact_trigger(self):
        """A missing, wrong-record, empty or complete forward is not partial loss."""
        for record, forwarded, length in ((3, 3, 50), (2, 3, 50), (3, 0, 50),
                                           (3, 1, 50), (3, 2, 50), (3, 52, 50)):
            with self.subTest(record=record, forwarded=forwarded):
                server, client, probe = self.events()
                client[-1] = {"event": "result", "outcome": "unknown",
                              "code": "Unavailable", "receipts": 0}
                stats = {"fault_record": record, "partial_bytes": forwarded,
                         "fault_record_bytes": length + 2, "server_records": 3,
                         "client_records": 3, "workers_joined": True,
                         "errors": []}
                args = ({"scenario": "owned", "network": "partial-loss"},
                        server, client, probe, stats)
                if record == 3 and 2 < forwarded < length + 2:
                    interop.validate_case(*args)
                else:
                    with self.assertRaises(AssertionError):
                        interop.validate_case(*args)

    def test_go_denial_requires_incomplete_local_write(self):
        """Authority refusal cannot pass if Go reports successful receipt handoff."""
        for scenario in ("deny", "unknown"):
            for complete in (False, True, None, "missing"):
                with self.subTest(scenario=scenario, complete=complete):
                    server, client, probe = self.events()
                    state = "HardDenied" if scenario == "deny" else "Unknown"
                    server.insert(1, dict(event="authority_outcome", state=state))
                    if complete != "missing":
                        server.insert(2, dict(event="local_write", complete=complete))
                    client[-1] = dict(event="result", outcome="unknown",
                                      code="Unavailable", receipts=0)
                    args = (dict(server="go", scenario=scenario, network="direct"),
                            server, client, probe, None)
                    if complete is False:
                        interop.validate_case(*args)
                    else:
                        with self.assertRaises(AssertionError):
                            interop.validate_case(*args)

    def test_gap_requires_observation_while_callback_pending(self):
        """A late or absent observation cannot stand in for a pending callback read."""
        for variant in ("valid", "absent", "late"):
            with self.subTest(variant=variant):
                server, client, probe = self.events()
                gap = {"event": "gap_observed", "before_callback_return": True}
                returned = {"event": "commit_return"}
                if variant == "valid":
                    server[1:1] = [gap, returned]
                elif variant == "late":
                    server[1:1] = [returned, gap]
                args = ({"scenario": "gap", "network": "direct"}, server, client, probe, None)
                if variant == "valid":
                    interop.validate_case(*args)
                else:
                    with self.assertRaises(AssertionError):
                        interop.validate_case(*args)

    def test_proxy_sequence_and_fragmentation_are_mandatory(self):
        """Require three records per direction and splits across all six records."""
        for count, splits in ((3, 6), (4, 6), (3, 0), (2, 6)):
            with self.subTest(count=count, splits=splits):
                server, client, probe = self.events()
                stats = dict(workers_joined=True, errors=[], client_records=count,
                             server_records=3, split_records=splits, fragment_writes=120)
                args = ({"scenario": "owned", "network": "fragmented"}, server, client, probe, stats)
                if count == 3 and splits == 6:
                    interop.validate_case(*args)
                else:
                    with self.assertRaises(AssertionError):
                        interop.validate_case(*args)


class OrchestrationTests(unittest.TestCase):
    """A fresh handshake must not depend on old-connection cleanup finishing."""

    def exercise(self, network, failure=None):
        """Model a ready result with client exit gated on handling the fresh probe."""
        trace = []
        processes = {}
        probe_handled = False
        process_type = interop.Process
        server_events, client_events, probe_events = EvidenceTests().events()
        initial_server = [dict(event="listening", address="127.0.0.1:12345"),
                          server_events[0], server_events[1]]
        proxy = mock.Mock()
        proxy.address = "127.0.0.1:12346"
        proxy.stats = dict(client_records=3, server_records=3, fragment_writes=120,
                           split_records=6, workers_joined=False, errors=[])

        def close_proxy():
            """Record joined ownership separately from scheduling the fresh probe."""
            trace.append("proxy.close")
            proxy.stats["workers_joined"] = True

        proxy.close.side_effect = close_proxy

        def start(command, directory, prefix, timeout):
            """Return bounded-process doubles without invoking either SDK binary."""
            nonlocal probe_handled
            label = prefix.name
            trace.append(label + ".start")
            proc = mock.Mock(spec=process_type)
            processes[label] = proc
            proc.events = {"server": initial_server, "client": client_events,
                           "probe": probe_events}[label]
            if label == "client" and failure == "missing-result":
                proc.events = []

            def event(name):
                """An exited construction failure cannot manufacture a result event."""
                trace.append(label + ".event." + name)
                events = interop.matching(proc.events, name)
                if not events:
                    raise RuntimeError("missing structured event")
                return events[0]

            def wait():
                """Client cleanup stays blocked until the separate probe is handled."""
                nonlocal probe_handled
                trace.append(label + ".wait")
                if label == "probe":
                    probe_handled = True
                    initial_server.extend(e for e in server_events[2:]
                                          if failure != "missing-denial" or e["event"] != "fresh_denied")
                if label == "client":
                    if failure in ("missing-result", "client-exit"):
                        raise RuntimeError("client exited unsuccessfully")
                    if not probe_handled:
                        raise RuntimeError("client cleanup blocked until fresh probe handled")

            proc.wait_event.side_effect = event
            proc.wait.side_effect = wait
            def close():
                """Model a late cleanup failure after all case evidence was validated."""
                trace.append(label + ".close")
                if label == "server" and failure == "cleanup":
                    raise RuntimeError("injected cleanup failure")

            proc.close.side_effect = close
            return proc

        case = dict(id="orchestration", server="rust", client="go",
                    scenario="owned", network=network)
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(interop, "Process", side_effect=start), \
                mock.patch.object(interop, "Proxy", return_value=proxy):
            result = interop.run_case(case, dict(go="unused-go", rust="unused-rust"),
                                      dict(go=Path(tmp), rust=Path(tmp)), Path(tmp))
        return result, trace, processes, proxy

    def test_probe_precedes_client_exit_and_proxy_join(self):
        """Already-observable results arm the probe before either old-owner wait."""
        for network in ("direct", "fragmented"):
            with self.subTest(network=network):
                result, trace, processes, proxy = self.exercise(network)
                self.assertEqual("PASS", result["status"], result)
                self.assertLess(trace.index("client.event.result"), trace.index("probe.start"))
                self.assertLess(trace.index("probe.wait"), trace.index("client.wait"))
                if network == "fragmented":
                    self.assertLess(trace.index("probe.start"), trace.index("proxy.close"))
                    self.assertTrue(proxy.stats["workers_joined"])
                for proc in processes.values():
                    proc.close.assert_called_once()

    def test_missing_result_never_starts_probe_and_cleans_up(self):
        """Setup failure closes all existing owners without launching a probe."""
        for network in ("direct", "fragmented"):
            with self.subTest(network=network):
                result, trace, processes, proxy = self.exercise(network, "missing-result")
                self.assertEqual("FAIL", result["status"])
                self.assertNotIn("probe", processes)
                for proc in processes.values():
                    proc.close.assert_called_once()
                if network == "fragmented":
                    proxy.close.assert_called_once()
                    self.assertTrue(proxy.stats["workers_joined"])

    def test_result_does_not_replace_exit_or_server_denial_checks(self):
        """A result plus failed exit or absent actual server denial still fails."""
        for failure in ("client-exit", "missing-denial"):
            with self.subTest(failure=failure):
                result, trace, processes, proxy = self.exercise("fragmented", failure)
                self.assertEqual("FAIL", result["status"])
                for proc in processes.values():
                    proc.close.assert_called_once()
                self.assertTrue(proxy.stats["workers_joined"])

    def test_cleanup_failure_cannot_leave_pass(self):
        """Case success is published only after every retained owner closes successfully."""
        result, trace, processes, _ = self.exercise("direct", "cleanup")
        self.assertEqual("FAIL", result["status"], result)
        self.assertIn("injected cleanup failure", result["failure"])
        for proc in processes.values():
            proc.close.assert_called_once()


class ProxyTests(unittest.TestCase):
    """Exercise actual loopback fragmentation and the third-record cutoff."""

    def test_relay_and_partial_cutoff(self):
        """Use real sockets to verify preserved records versus exactly three lost-frame bytes."""
        for mode in ("fragmented", "partial-loss"):
            with self.subTest(mode=mode):
                listener = socket.socket()
                self.addCleanup(listener.close)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(3)
                errors = []
                record = struct.pack("!H", 17) + bytes(17)

                def backend():
                    """Read three records, then emit the three server records."""
                    try:
                        with listener.accept()[0] as conn:
                            conn.settimeout(3)
                            if interop.recv_exact(conn, 3 * len(record)) != 3 * record:
                                raise AssertionError("relay changed opaque bytes")
                            conn.sendall(3 * record)
                    except Exception as error:
                        errors.append(type(error).__name__)

                worker = threading.Thread(target=backend)
                worker.start()
                proxy = interop.Proxy("%s:%d" % listener.getsockname(), mode)
                try:
                    host, port = proxy.address.rsplit(":", 1)
                    with socket.create_connection((host, int(port)), timeout=3) as client:
                        client.sendall(3 * record)
                        received = bytearray()
                        while chunk := client.recv(1024):
                            received.extend(chunk)
                    expected = 3 * record if mode == "fragmented" else 2 * record + record[:3]
                    self.assertEqual(expected, received)
                finally:
                    proxy.close()
                    worker.join(4)
                self.assertFalse(worker.is_alive())
                self.assertFalse(errors)
                self.assertFalse(proxy.stats["errors"])
                self.assertTrue(proxy.stats["workers_joined"])
                self.assertEqual(3, proxy.stats["server_records"])
                self.assertEqual(3, proxy.stats["client_records"])
                if mode == "partial-loss":
                    self.assertEqual(3, proxy.stats["fault_record"])
                    self.assertEqual(3, proxy.stats["partial_bytes"])
                    self.assertEqual(len(record), proxy.stats["fault_record_bytes"])
                else:
                    self.assertEqual(6, proxy.stats["split_records"])


class ProcessTests(unittest.TestCase):
    """Timeout, oversized stdio and nonzero exits cannot pass as unknown outcomes."""

    def test_process_failures_are_reaped(self):
        """Bounded children and log readers must join for every failure type."""
        for code, deadline in (("raise SystemExit(2)", 3),
                               ("import threading; threading.Event().wait()", 0.1),
                               ("print('x' * 4097)", 3)):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                proc = interop.Process([sys.executable, "-c", code], tmp,
                                       Path(tmp) / "child", deadline)
                try:
                    with self.assertRaises(RuntimeError):
                        proc.wait()
                finally:
                    proc.close()
                self.assertIsNotNone(proc.child.poll())
                self.assertTrue(all(not t.is_alive() for t in proc.readers))

    def test_exited_child_event_waits_for_stdout_drain(self):
        """An exited child's buffered event remains eligible until stdout reaches EOF."""
        release = threading.Event()
        waiting = threading.Event()
        outcomes = []

        class DelayedStdout(interop.Process):
            """Hold stdout draining behind a barrier while the real child exits."""

            def _read(self, pipe, path, name):
                """Keep stderr live and release stdout only after the event waiter blocks."""
                if name == "stdout":
                    release.wait(3)
                super()._read(pipe, path, name)

        with tempfile.TemporaryDirectory() as tmp:
            proc = DelayedStdout([sys.executable, "-c", 'print(\'{"event":"ready"}\')'],
                                 tmp, Path(tmp) / "child", 5)
            original_wait = proc.condition.wait

            def condition_wait(timeout):
                """Signal a real condition wait rather than depending on scheduling sleeps."""
                waiting.set()
                return original_wait(timeout)

            def wait_event():
                """Capture success or refusal so the parent can always join the waiter."""
                try:
                    outcomes.append(proc.wait_event("ready", timeout=2))
                except RuntimeError as error:
                    outcomes.append(error)

            waiter = threading.Thread(target=wait_event)
            try:
                proc.child.wait(timeout=2)
                with mock.patch.object(proc.condition, "wait", side_effect=condition_wait):
                    waiter.start()
                    self.assertTrue(waiting.wait(1), outcomes)
                    release.set()
                    waiter.join(3)
                self.assertFalse(waiter.is_alive())
                self.assertEqual([dict(event="ready")], outcomes)
                proc.wait()
            finally:
                release.set()
                if waiter.ident is not None:
                    waiter.join(3)
                proc.close()

    def test_missing_event_still_rejects_exit_and_stdio_failure(self):
        """Draining stdout does not turn absent markers or malformed output into evidence."""
        for code in ("pass", "print('x' * 4097)"):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as tmp:
                proc = interop.Process([sys.executable, "-c", code], tmp,
                                       Path(tmp) / "child", 3)
                try:
                    with self.assertRaisesRegex(RuntimeError, "missing ready event"):
                        proc.wait_event("ready", timeout=1)
                finally:
                    proc.close()
                self.assertIsNotNone(proc.child.poll())
                self.assertTrue(all(not t.is_alive() for t in proc.readers))

    def test_group_signal_reaps_only_exit_races_not_live_permission_failures(self):
        """Retry after bounded owned-child reap without hiding live or persistent EPERM."""
        for variant in ("missing", "reaped-missing", "reaped-group", "live", "persistent"):
            with self.subTest(variant=variant):
                proc = interop.Process.__new__(interop.Process)
                proc.child = mock.Mock(pid=12345)
                denied = PermissionError("injected group denial")
                errors = [ProcessLookupError()] if variant == "missing" else [denied]
                if variant == "reaped-missing":
                    errors.append(ProcessLookupError())
                elif variant == "persistent":
                    errors.append(PermissionError("remaining group denied"))
                elif variant == "reaped-group":
                    errors.append(None)
                if variant == "live":
                    proc.child.wait.side_effect = interop.subprocess.TimeoutExpired("child", 2)
                with mock.patch.object(interop.os, "killpg", side_effect=errors) as kill:
                    if variant in ("live", "persistent"):
                        with self.assertRaises(PermissionError) as raised:
                            proc._signal(interop.signal.SIGTERM)
                        if variant == "live":
                            self.assertIs(denied, raised.exception)
                    else:
                        proc._signal(interop.signal.SIGTERM)
                if variant == "missing":
                    proc.child.wait.assert_not_called()
                else:
                    proc.child.wait.assert_called_once_with(timeout=2)
                self.assertEqual(1 if variant in ("missing", "live") else 2,
                                 kill.call_count)


if __name__ == "__main__":
    unittest.main()
