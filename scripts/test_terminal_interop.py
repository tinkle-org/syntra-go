"""Regression checks for the receipt harness's fail-closed evidence validator."""
import importlib.util
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
        for record, forwarded, length in ((3, 3, 50), (2, 3, 50), (3, 0, 50), (3, 52, 50)):
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
                if record == 3 and 0 < forwarded < length + 2:
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
            proc.close.side_effect = lambda: trace.append(label + ".close")
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


if __name__ == "__main__":
    unittest.main()
