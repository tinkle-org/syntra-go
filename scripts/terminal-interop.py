#!/usr/bin/env python3
"""Bounded loopback SDK receipt matrix. No runtime patches or mutation retries.

Builds actual working trees (Go go1.26.10, Rust 1.88.0 --locked). Output MUST
not exist, must have an existing parent, and must be outside both source trees.
The proxy reads only u16 record lengths and opaque encrypted bytes;
it never decrypts, decodes application frames, or records ciphertext/keys.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import struct
import subprocess
import threading
import time


def matrix():
    """Return the fourteen distinct cases, without counting reruns as coverage."""
    cases = []
    for server, client in (("go", "rust"), ("rust", "go")):
        for scenario, network in ((s, n) for s in ("owned", "gap")
                                  for n in ("direct", "fragmented")):
            cases.append(dict(id=f"{server}-to-{client}-{scenario}-{network}",
                              server=server, client=client, scenario=scenario, network=network))
        for scenario, network in (("deny", "direct"), ("unknown", "direct"),
                                  ("owned", "partial-loss")):
            cases.append(dict(id=f"{server}-to-{client}-{scenario}-{network}",
                              server=server, client=client, scenario=scenario, network=network))
    return cases


def matching(events, name):
    """Select structured fixture events, never diagnostic substring matches."""
    return [e for e in events if e.get("event") == name]


def validate_case(case, server, client, probe, proxy):
    """Fail closed unless both peer observations and checked server state agree."""
    if not __debug__:
        raise RuntimeError("evidence validation requires Python assertions enabled")
    transitions = matching(server, "transition")
    assert len(transitions) == 1 and transitions[0].get("recorded") is True, "transition"
    assert matching(server, "summary") == [dict(event="summary", commits=1,
                                                handlers=1, denials=1, closed=2)], "state/counts"
    assert sorted(e.get("connection") for e in matching(server, "connection_closed")) == [1, 2], "joined connections"
    denials = matching(server, "fresh_denied")
    assert len(denials) == 1 and denials[0].get("before_handler") is True, "fresh server denial"
    assert matching(probe, "probe") == [dict(event="probe", establishment_denied=True, calls=0)], "fresh probe"
    assert len(matching(client, "established")) == 1, "mutation client never established"
    results = matching(client, "result")
    assert len(results) == 1, "exactly one client result"
    result = results[0]
    negative = case["scenario"] in ("deny", "unknown") or case["network"] == "partial-loss"
    if negative:
        allowed = ("Unavailable", "Unauthenticated") if case["scenario"] == "deny" else ("Unavailable",)
        assert result.get("outcome") == "unknown" and result.get("receipts") == 0, "zero receipts"
        assert result.get("code") in allowed and "payload" not in result, "typed error"
    else:
        assert result.get("outcome") == "observed" and result.get("payload") == "retired" and result.get("receipts") == 1, "exact receipt"
    if case["scenario"] in ("deny", "unknown"):
        state = "HardDenied" if case["scenario"] == "deny" else "Unknown"
        assert any(e.get("state") == state for e in matching(server, "authority_outcome")), "typed authority evidence"
        if case.get("server") == "go":
            writes = matching(server, "local_write")
            assert len(writes) == 1 and writes[0].get("complete") is False, "refused local write"
    if case["scenario"] == "gap":
        gaps = matching(server, "gap_observed")
        returns = matching(server, "commit_return")
        assert len(gaps) == 1 and gaps[0].get("before_callback_return") is True and len(returns) == 1, "gap not observed"
        assert server.index(transitions[0]) < server.index(gaps[0]) < server.index(returns[0]), "gap event order"
    if case["network"] != "direct":
        assert proxy and proxy.get("workers_joined") is True and not proxy.get("errors"), "proxy workers"
        assert proxy.get("client_records") == 3 and proxy.get("server_records") == 3, "record sequence"
    if case["network"] == "partial-loss":
        assert proxy.get("fault_record") == 3, "fault never hit third server record"
        assert 2 < proxy.get("partial_bytes", 0) < proxy.get("fault_record_bytes", 0), "no partial ciphertext loss"
    if case["network"] == "fragmented":
        assert proxy.get("fragment_writes", 0) > 6 and proxy.get("split_records") == 6, "fragmentation not exercised"


class Process:
    """A child with bounded stdio, an absolute deadline and joined reader threads."""
    def __init__(self, command, directory, prefix, timeout, env=None):
        """Start one owned child and bounded readers, tracking stdout EOF separately from exit."""
        self.command = [str(c) for c in command]
        self.events = []
        self.errors = []
        self.condition = threading.Condition()
        self.stdout_done = False
        self.child = subprocess.Popen(self.command, cwd=directory, env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                      start_new_session=True)
        self.expired = False
        self.timer = threading.Timer(timeout, self._expire)
        self.timer.start()
        self.readers = []
        for name, pipe in (("stdout", self.child.stdout), ("stderr", self.child.stderr)):
            thread = threading.Thread(target=self._read, args=(pipe, Path(str(prefix) + f".{name}.log"), name))
            self.readers.append(thread)
            thread.start()

    def _expire(self):
        """Kill a timed-out child even when callers are waiting for a marker."""
        if self.child.poll() is None:
            self.expired = True
            self._signal(signal.SIGKILL)
        with self.condition:
            self.condition.notify_all()

    def _signal(self, sig):
        """Signal the owned group; boundedly reap Darwin's exiting-leader EPERM race."""
        try:
            os.killpg(self.child.pid, sig)
        except ProcessLookupError:
            return
        except PermissionError as denied:
            # Darwin can return EPERM after SIGKILL but before waitpid can reap.
            # Never suppress a live-child denial or skip surviving group members.
            try:
                self.child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                raise denied
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.child.pid, sig)

    def _read(self, pipe, path, name):
        """Drain each pipe concurrently; enforce total and per-line bounds."""
        try:
            total = 0
            with path.open("xb") as log:
                while line := pipe.readline(4097):
                    total += len(line)
                    if len(line) > 4096 or total > 131072:
                        raise ValueError("stdio bound exceeded")
                    log.write(line)
                    log.flush()
                    if name == "stdout" and line.startswith(b"{"):
                        event = json.loads(line)
                        with self.condition:
                            self.events.append(event)
                            self.condition.notify_all()
        except Exception as error:
            self.errors.append(type(error).__name__)
            self._signal(signal.SIGKILL)
        finally:
            pipe.close()
            with self.condition:
                if name == "stdout":
                    self.stdout_done = True
                self.condition.notify_all()

    def wait_event(self, name, timeout=12):
        """Wait on a condition, not port polling or a disposable TCP connection."""
        deadline = time.monotonic() + timeout
        with self.condition:
            while not matching(self.events, name):
                remaining = deadline - time.monotonic()
                if remaining <= 0 or self.expired or self.errors or (
                        self.child.poll() is not None and self.stdout_done):
                    raise RuntimeError(f"missing {name} event")
                self.condition.wait(min(remaining, 0.2))
            return matching(self.events, name)[0]

    def wait(self):
        """Reap and join stdio; nonzero exit or deadline is always a failure."""
        code = self.child.wait()
        self.timer.cancel()
        self.timer.join()
        for reader in self.readers:
            reader.join(2)
        if any(r.is_alive() for r in self.readers) or self.errors or self.expired or code != 0:
            raise RuntimeError(f"child failed: exit={code}, deadline={self.expired}, stdio={self.errors}")

    def close(self):
        """Always terminate, reap, and join; no stale children on failed cases."""
        self.timer.cancel()
        self.timer.join()
        if self.child.poll() is None:
            self._signal(signal.SIGTERM)
            try:
                self.child.wait(2)
            except subprocess.TimeoutExpired:
                self._signal(signal.SIGKILL)
                self.child.wait()
        # Also release inherited pipes if an exited build parent left a worker.
        self._signal(signal.SIGKILL)
        for reader in self.readers:
            reader.join(2)
        if any(r.is_alive() for r in self.readers):
            raise RuntimeError("stdio reader did not join")


def recv_exact(sock, length, allow_eof=False):
    """Read one opaque record part, rejecting truncation rather than misframing."""
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            if not data and allow_eof:
                return None
            raise EOFError("truncated record")
        data.extend(chunk)
    return bytes(data)


class Proxy:
    """Single-connection encrypted record relay, with retained and joined workers."""
    def __init__(self, upstream, mode):
        """Own one loopback listener and its bounded opaque-record relay workers."""
        self.upstream = upstream
        self.mode = mode
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(12)
        self.address = "%s:%d" % self.listener.getsockname()
        self.stopped = threading.Event()
        self.sockets = []
        self.lock = threading.Lock()
        self.stats = dict(client_records=0, server_records=0, fragment_writes=0,
                          split_records=0, fault_record=None, partial_bytes=0,
                          fault_record_bytes=0, errors=[], workers_joined=False)
        self.workers = []
        self.owner = threading.Thread(target=self._serve)
        self.owner.start()

    def _stop(self):
        """Interrupt both directions even if the opposite read is blocked."""
        self.stopped.set()
        with self.lock:
            for sock in self.sockets:
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)
                sock.close()

    def _serve(self):
        """Accept once and connect once; never reconnect or replay a request."""
        try:
            downstream, _ = self.listener.accept()
            with self.lock:
                self.sockets.append(downstream)
            host, port = self.upstream.rsplit(":", 1)
            upstream = socket.create_connection((host, int(port)), timeout=12)
            with self.lock:
                self.sockets.append(upstream)
            for sock in (downstream, upstream):
                sock.settimeout(12)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for source, dest, direction in ((downstream, upstream, "client"), (upstream, downstream, "server")):
                worker = threading.Thread(target=self._relay, args=(source, dest, direction))
                self.workers.append(worker)
                worker.start()
            for worker in self.workers:
                worker.join()
        except Exception as error:
            if not self.stopped.is_set():
                self.stats["errors"].append(type(error).__name__)
        finally:
            self._stop()
            self.listener.close()

    def _relay(self, source, dest, direction):
        """Parse lengths only; record three is the fixture's sole result slot."""
        try:
            while not self.stopped.is_set():
                prefix = recv_exact(source, 2, allow_eof=True)
                if prefix is None:
                    break
                length, = struct.unpack("!H", prefix)
                if length < 17:
                    raise ValueError("invalid encrypted record length")
                record = prefix + recv_exact(source, length)
                self.stats[direction + "_records"] += 1
                index = self.stats[direction + "_records"]
                if self.mode == "partial-loss" and direction == "server" and index == 3:
                    dest.sendall(record[:3])  # full u16 prefix + one ciphertext byte
                    self.stats.update(fault_record=index, partial_bytes=3,
                                      fault_record_bytes=len(record))
                    break
                if self.mode == "fragmented":
                    # These are application write boundaries, not claimed IP packet boundaries.
                    for offset in range(0, len(record), 3):
                        dest.sendall(record[offset:offset + 3])
                        with self.lock:
                            self.stats["fragment_writes"] += 1
                    with self.lock:
                        self.stats["split_records"] += 1
                else:
                    dest.sendall(record)
        except Exception as error:
            if not self.stopped.is_set():
                self.stats["errors"].append(type(error).__name__)
        finally:
            self._stop()

    def close(self):
        """Join owner and both relays before claiming any proxy evidence."""
        self._stop()
        self.listener.close()
        self.owner.join(14)
        self.stats["workers_joined"] = not self.owner.is_alive() and all(not t.is_alive() for t in self.workers)
        if not self.stats["workers_joined"]:
            raise RuntimeError("proxy worker failed to join")


def command(binary, language, mode, address, scenario):
    """Use each independent SDK CLI; probe is explicitly not a method call."""
    if language == "rust":
        return [binary, mode, address, scenario]
    args = [binary, "-mode", "client" if mode == "probe" else mode,
            "-addr", address, "-scenario", scenario, "-timeout", "25s"]
    if mode == "probe":
        args += ["-probe"]
    if mode == "server":
        args += ["-connections", "2"]
    return args


def run_case(case, binaries, roots, output):
    """One fresh server, one mutation, one independent handshake-only probe."""
    folder = output / case["id"]
    folder.mkdir()
    result = dict(case, status="FAIL")
    proxy = None
    try:
        with contextlib.ExitStack() as cleanup:
            def start(language, mode, address, scenario, label):
                """Retain each child in the cleanup stack before using any of its evidence."""
                proc = Process(command(binaries[language], language, mode, address, scenario),
                               roots[language], folder / label, 28)
                cleanup.callback(proc.close)
                return proc
            server = start(case["server"], "server", "127.0.0.1:0", case["scenario"], "server")
            address = server.wait_event("listening")["address"]
            client_address = address
            if case["network"] != "direct":
                proxy = Proxy(address, case["network"])
                cleanup.callback(proxy.close)
                client_address = proxy.address
            scenario = "unknown" if case["network"] == "partial-loss" else case["scenario"]
            client = start(case["client"], "client", client_address, scenario, "client")
            # The result is observable before owned cleanup necessarily joins.
            # Arm the no-RPC probe within the server's second-accept window,
            # independent of client exit or the old proxy's bounded teardown.
            client.wait_event("result")
            probe = start(case["client"], "probe", address, "unknown", "probe")
            probe.wait()
            client.wait()
            server.wait_event("connection_closed")
            if proxy:
                proxy.close()
            server.wait()
            validate_case(case, server.events, client.events, probe.events, proxy.stats if proxy else None)
            result["client_result"] = matching(client.events, "result")[0]
        result["status"] = "PASS"
    except Exception as error:
        result["failure"] = f"{type(error).__name__}: {error}"
    finally:
        if proxy:
            result["proxy"] = proxy.stats
            (folder / "proxy.json").write_text(json.dumps(proxy.stats, indent=2) + "\n")
    (folder / "case.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def sha256(path):
    """Hash bytes without exposing source, fixture keys or log contents."""
    h = hashlib.sha256()
    with path.open("rb") as file:
        while chunk := file.read(65536):
            h.update(chunk)
    return h.hexdigest()


def git(root, *args):
    """Read repository metadata without changing the current feature branch."""
    return subprocess.check_output(["git", *args], cwd=root, timeout=15)


def snapshot(root):
    """Hash every tracked/nonignored untracked file, including uncommitted runtime work."""
    files = []
    for name in sorted(set(git(root, "ls-files", "-c", "-o", "--exclude-standard", "-z").split(b"\0")) - {b""}):
        path = root / os.fsdecode(name)
        if path.is_symlink():
            digest = hashlib.sha256(os.readlink(path).encode()).hexdigest()
        elif path.is_file():
            digest = sha256(path)
        else:
            digest = "deleted"
        files.append(dict(path=os.fsdecode(name), sha256=digest))
    digest = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    return dict(revision=git(root, "rev-parse", "HEAD").decode().strip(),
                branch=git(root, "branch", "--show-current").decode().strip(),
                status=git(root, "status", "--porcelain").decode().splitlines(),
                working_tree_sha256=digest, files=files)


def build(command_args, root, output, name, env=None):
    """Run a bounded build with retained, nonoverwriting stdout/stderr logs."""
    proc = Process(command_args, root, output / name, 300, env)
    try:
        proc.wait()
    finally:
        proc.close()


def prepare_output(output, roots):
    """Create one new external directory without writing inside either checkout."""
    requested = Path(os.path.abspath(output))
    resolved = requested.resolve()
    for root in roots.values():
        source = root.resolve()
        if any(path == source or source in path.parents for path in (requested, resolved)):
            raise ValueError("output must be outside both source checkouts")
    if requested.exists() or requested.is_symlink():
        raise ValueError("output must not already exist")
    if not resolved.parent.is_dir():
        raise ValueError("output parent must already exist")
    resolved.mkdir(exist_ok=False)
    return resolved


def validate_archive_destination(archive):
    """Validate a fresh destination without resolving away an existing dangling link."""
    requested = Path(os.path.abspath(archive))
    if requested.exists() or requested.is_symlink():
        raise ValueError("archive must not already exist")
    resolved = requested.resolve()
    if not resolved.parent.is_dir():
        raise ValueError("archive parent must already exist")
    return resolved


def archive_evidence(output, archive, manifest):
    """Retain exact reviewable text artifacts and manifests, never compiled binaries."""
    archive = validate_archive_destination(archive)
    selected = {name: digest for name, digest in manifest.items()
                if Path(name).suffix in (".json", ".log")}
    for name, digest in selected.items():
        if Path(name).is_absolute() or ".." in Path(name).parts or sha256(output / name) != digest:
            raise ValueError("archive artifact path or checksum mismatch")
    archive.mkdir(exist_ok=False)
    for name in (*selected, "SHA256SUMS"):
        destination = archive / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with (output / name).open("rb") as source, destination.open("xb") as target:
            shutil.copyfileobj(source, target)
    with (archive / "ARCHIVE_SHA256SUMS").open("x") as target:
        for name, digest in sorted(selected.items()):
            target.write(f"{digest}  {name}\n")


def write_report(output, report, mode="x"):
    """Write the report and matching checksums; replace only this run's files on error."""
    with (output / "report.json").open(mode) as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    manifest = dict(report["checksums"])
    manifest["report.json"] = sha256(output / "report.json")
    for value in report.get("binaries", {}).values():
        manifest[str(Path(value["path"]).relative_to(output))] = value["sha256"]
    with (output / "SHA256SUMS").open(mode) as file:
        for name, digest in sorted(manifest.items()):
            file.write(f"{digest}  {name}\n")
    return manifest


def main():
    """Build both working trees and preserve one fresh evidence directory per run."""
    parser = argparse.ArgumentParser(description=__doc__)
    go_root = Path(__file__).resolve().parents[1]
    parser.add_argument("--go-root", type=Path, default=go_root)
    parser.add_argument("--rust-root", type=Path, default=go_root.parent / "syntra-rs")
    parser.add_argument("--output", type=Path, required=True,
                        help="new directory with an existing parent, outside both source checkouts")
    parser.add_argument("--archive", type=Path,
                        help="new text-evidence archive; copied only after source-stability verification")
    args = parser.parse_args()
    if not __debug__:
        parser.error("run without -O; validation assertions must be enabled")
    roots = dict(go=args.go_root.resolve(), rust=args.rust_root.resolve())
    try:
        output = prepare_output(args.output, roots)
        archive = validate_archive_destination(args.archive) if args.archive is not None else None
    except (OSError, ValueError) as error:
        parser.error(str(error))
    env = dict(os.environ, GOTOOLCHAIN="go1.26.10")
    rust_env = dict(os.environ, CARGO_TARGET_DIR=str(output / "rust-target"))
    report = dict(formal_conformance=False, fixture_durable=False, cases=[],
                  started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                  roots={k: str(v) for k, v in roots.items()})
    try:
        report["sources"] = {k: snapshot(v) for k, v in roots.items()}
        report["unit_test_command"] = [os.sys.executable, "-m", "unittest", "discover", "-s", "scripts", "-p", "test_terminal_interop.py"]
        build(report["unit_test_command"], roots["go"], output, "unit-tests")
        report["toolchains"] = dict(
            go=subprocess.check_output(["go", "version"], env=env, timeout=120).decode().strip(),
            rust=subprocess.check_output(["rustc", "+1.88.0", "--version", "--verbose"], timeout=30).decode().strip(),
            cargo=subprocess.check_output(["cargo", "+1.88.0", "--version"], timeout=30).decode().strip(),
            python=os.sys.version)
        binaries = dict(go=output / "terminal-fixture", rust=output / "rust-target/debug/examples/terminal_receipt")
        report["build_commands"] = dict(
            go=["go", "build", "-o", str(binaries["go"]), "./cmd/terminal-fixture"],
            rust=["cargo", "+1.88.0", "build", "--locked", "-p", "syntra-net", "--features", "tcp", "--example", "terminal_receipt"])
        report["build_environment"] = dict(go=dict(GOTOOLCHAIN="go1.26.10"),
                                            rust=dict(CARGO_TARGET_DIR=rust_env["CARGO_TARGET_DIR"]))
        build(report["build_commands"]["go"], roots["go"], output, "build-go", env)
        build(report["build_commands"]["rust"], roots["rust"], output, "build-rust", rust_env)
        report["binaries"] = {k: dict(path=str(v), sha256=sha256(v)) for k, v in binaries.items()}
        for case in matrix():
            result = run_case(case, binaries, roots, output)
            report["cases"].append(result)
            print(f"{result['status']} {case['id']}" + (f": {result['failure']}" if "failure" in result else ""), flush=True)
        report["sources_after"] = {k: snapshot(v) for k, v in roots.items()}
        report["source_stable"] = all(all(report["sources"][k][field] == v[field]
                                             for field in ("revision", "branch", "working_tree_sha256"))
                                      for k, v in report["sources_after"].items())
    except Exception as error:
        report["failure"] = f"{type(error).__name__}: {error}"
    report["passed"] = sum(c["status"] == "PASS" for c in report["cases"])
    report["failed"] = sum(c["status"] != "PASS" for c in report["cases"])
    report["complete"] = len(report["cases"]) == 14 and report["passed"] == 14 and report.get("source_stable", False)
    report["checksums"] = {str(p.relative_to(output)): sha256(p) for p in sorted(output.rglob("*"))
                           if p.is_file() and (p.suffix in (".log", ".json")) and "rust-target" not in p.parts}
    manifest = write_report(output, report)
    if archive is not None:
        try:
            archive_evidence(output, archive, manifest)
        except Exception as error:
            report["archive_error"] = f"{type(error).__name__}: {error}"
            write_report(output, report, mode="w")
    print(f"Evidence: {output / 'report.json'}; {report['passed']}/14 PASS; complete={report['complete']}")
    if "failure" in report:
        print(report["failure"])
    if "archive_error" in report:
        print(f"Archive error: {report['archive_error']}")
    return 0 if report["complete"] and "archive_error" not in report else 1


if __name__ == "__main__":
    raise SystemExit(main())
