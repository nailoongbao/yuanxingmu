"""Offline protocol and POSIX lifecycle checks; no real installations or models."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1] / "bridge.py"
SPEC = importlib.util.spec_from_file_location("windows_bridge", SOURCE)
bridge = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bridge)
POSIX = os.name == "posix"
PORT = 18910
URL = "http://127.0.0.1:18910/#access=" + "A" * 32


class ProtocolTests(unittest.TestCase):
    def test_ready_accepts_only_one_complete_exact_loopback_url(self):
        for ending in (b"\n", b"\r\n"):
            self.assertEqual(bridge.ready_url(URL.encode() + ending, PORT), URL)
        for raw in (URL.encode(), (URL + " \n").encode(), (" " + URL + "\n").encode(),
                    ("prefix " + URL + "\n").encode(), (URL + "?x=1\n").encode(),
                    (URL.replace("18910", "18911") + "\n").encode(),
                    (URL.replace("127.0.0.1", "localhost") + "\n").encode(),
                    (URL.replace("http:", "https:") + "\n").encode(),
                    (URL[:-1] + "\n").encode(), (URL + "A" * 97 + "\n").encode(),
                    (URL + "\n" + URL + "\n").encode(), b"\xff\n"):
            with self.subTest(raw=raw[:40]):
                self.assertIsNone(bridge.ready_url(raw, PORT))

    def test_control_is_bounded_exact_object_or_eof(self):
        self.assertIsNone(bridge.control_command(b""))
        for raw in (b'{"command":"stop"}\n', b' { "command": "stop" }\r\n'):
            self.assertEqual(bridge.control_command(raw), "stop")
        for raw in (b"\n", b'{"command":"stop"}', b'"stop"\n', b'[]\n',
                    b'{"command":"start"}\n', b'{"command":"stop","secret":"x"}\n',
                    b'{"command":"start","command":"stop"}\n', b"\xff\n",
                    b'{"command":"stop"}\n{}\n', b" " * 256 + b"\n"):
            with self.subTest(raw=raw[:40]), self.assertRaises(bridge.BridgeError) as caught:
                bridge.control_command(raw)
            self.assertEqual(caught.exception.code, "invalid_control")

    def test_preparation_errors_and_probe_finish_with_stopped(self):
        home = Path("/home/synthetic")
        events = []
        with mock.patch.object(bridge, "context", return_value=(home, 1000)), \
             mock.patch.object(bridge, "discover", return_value=[]), \
             mock.patch.object(bridge, "event", side_effect=events.append):
            self.assertEqual(bridge.main(["probe"]), 0)
        self.assertEqual([value["event"] for value in events], ["probe", "stopped"])
        self.assertEqual(events[-1]["exit_code"], 0)
        for args in ([], ["start", "/home/synthetic/x", "18701"],
                     ["start", "/home/synthetic/x", "1"],
                     ["start", "/home/synthetic/x", "65536"],
                     ["start", "/home/synthetic/x", "18910 --extra"]):
            events = []
            with mock.patch.object(bridge, "context", return_value=(home, 1000)), \
                 mock.patch.object(bridge, "event", side_effect=events.append):
                self.assertEqual(bridge.main(args), 2)
            self.assertEqual(events[0]["code"], "invalid_arguments")
            self.assertEqual(events[-1], {"event": "stopped", "exit_code": 2})

    def test_start_uses_fixed_interpreter_argv_without_shell(self):
        root = Path("/home/synthetic/installation with spaces")
        with mock.patch.object(bridge, "context", return_value=(root.parent, 1000)), \
             mock.patch.object(bridge, "validate_candidate", return_value=root) as validate, \
             mock.patch.object(bridge, "supervise", return_value=0) as run:
            self.assertEqual(bridge.main(["start", str(root), "18910"]), 0)
        self.assertTrue(validate.call_args.kwargs["check_launcher"])
        self.assertEqual(run.call_args.args[:2], (["/usr/bin/python3", "-I", "-B",
                         str(root / "open-yuanxingmu"), "--no-browser", "--port", "18910"], PORT))
        self.assertEqual(run.call_args.kwargs["cwd"], str(root))

    def test_fixed_errors_do_not_expose_exception_or_source_output(self):
        events = []
        with mock.patch.object(bridge, "context", side_effect=RuntimeError("private-token-never-display")), \
             mock.patch.object(bridge, "event", side_effect=events.append):
            self.assertEqual(bridge.main(["probe"]), 2)
        self.assertNotIn("private-token", json.dumps(events))
        self.assertEqual(events[0]["code"], "startup_failed")
        self.assertEqual(bridge.classify("所选端口已被占用。".encode()), "port_in_use")
        self.assertEqual(bridge.classify("这个工作台已经打开。".encode()), "already_running")
        self.assertEqual(bridge.classify("安装记录不完整。".encode()), "install_invalid")
        self.assertIsNone(bridge.classify(b"private-token-never-display"))

    def test_root_environment_has_distinct_error(self):
        with mock.patch.object(bridge.sys, "platform", "linux"), \
             mock.patch.object(bridge.sys, "version_info", (3, 12)), \
             mock.patch.object(bridge.os, "getuid", return_value=0, create=True):
            with self.assertRaises(bridge.BridgeError) as caught:
                bridge.context()
        self.assertEqual(caught.exception.code, "root_user")


@unittest.skipUnless(POSIX, "POSIX ownership and symlink checks")
class CandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="yxm-bridge-candidates-")
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        self.home.chmod(0o700)
        self.uid = os.getuid()
        self.root = self.home / "yuanxingmu-v07a2"
        self.make_candidate(self.root)

    def make_candidate(self, root):
        root.mkdir(mode=0o700)
        launcher = root / "open-yuanxingmu"
        launcher.write_bytes(b"raise AssertionError('probe must never execute this file')\n")
        launcher.chmod(0o700)
        info = root.stat()
        marker = {"schema_version": 1, "installer_version": "0.4.0a2", "runtime_version": "0.7.0a2",
                  "status": "complete", "install_id": "a" * 32, "root_identity": [info.st_dev, info.st_ino],
                  "launcher_sha256": hashlib.sha256(launcher.read_bytes()).hexdigest()}
        self.write_marker(root, marker)
        return marker

    def write_marker(self, root, marker):
        target = root / "INSTALLATION.json"
        target.write_text(json.dumps(marker), encoding="utf-8")
        target.chmod(0o600)

    def rejected(self, root=None, **kwargs):
        with self.assertRaises(bridge.BridgeError) as caught:
            bridge.validate_candidate(root or self.root, self.home, self.uid, **kwargs)
        self.assertEqual(caught.exception.code, "install_invalid")

    def test_discovery_reads_only_receipts_and_only_known_candidates(self):
        self.make_candidate(self.home / "yuanxingmu")
        self.make_candidate(self.home / "custom-installation")
        original = bridge.read_owned
        def marker_only(path, *args, **kwargs):
            self.assertEqual(path.name, "INSTALLATION.json")
            return original(path, *args, **kwargs)
        with mock.patch.object(bridge, "read_owned", side_effect=marker_only):
            candidates = bridge.discover(self.home, self.uid)
        self.assertEqual([Path(item["root"]).name for item in candidates], ["yuanxingmu-v07a2", "yuanxingmu"])

    def test_versions_status_identity_and_schema_are_rejected(self):
        original = json.loads((self.root / "INSTALLATION.json").read_text())
        for key, value in (("installer_version", "0.4.0a1"), ("runtime_version", "0.7.0a1"),
                           ("status", "installing"), ("schema_version", True),
                           ("root_identity", [0, 0]), ("install_id", "invalid"),
                           ("launcher_sha256", "not-a-hash")):
            with self.subTest(key=key):
                self.write_marker(self.root, dict(original, **{key: value}))
                self.rejected()
        self.write_marker(self.root, original)

    def test_root_marker_and_launcher_symlinks_are_rejected(self):
        alias = self.home / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.rejected(alias)
        marker = self.root / "INSTALLATION.json"
        real = self.root / "saved-marker"
        marker.rename(real)
        marker.symlink_to(real)
        self.rejected()
        marker.unlink()
        real.rename(marker)
        launcher = self.root / "open-yuanxingmu"
        copy = self.root / "saved-launcher"
        launcher.rename(copy)
        launcher.symlink_to(copy)
        self.rejected(check_launcher=True)

    def test_outside_home_relative_alias_and_private_permissions_are_rejected(self):
        self.rejected(self.home.parent)
        self.rejected(str(self.root.relative_to(self.home)))
        self.rejected(str(self.home / ".." / self.home.name / self.root.name))
        self.root.chmod(0o750)
        self.rejected()
        self.root.chmod(0o700)
        (self.root / "INSTALLATION.json").chmod(0o644)
        self.rejected()

    def test_start_checks_file_digest_probe_does_not(self):
        self.assertEqual(bridge.validate_candidate(self.root, self.home, self.uid, True), self.root)
        (self.root / "open-yuanxingmu").write_bytes(b"changed but never executed")
        self.assertEqual(bridge.validate_candidate(self.root, self.home, self.uid), self.root)
        self.rejected(check_launcher=True)

    def test_bad_and_oversized_marker_is_rejected(self):
        path = self.root / "INSTALLATION.json"
        path.write_bytes(b"not json")
        self.rejected()
        with path.open("wb") as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        self.rejected()


@unittest.skipUnless(POSIX, "POSIX process groups and real SIGTERM cleanup")
class ProcessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="yxm-bridge-process-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def wait_for(self, predicate, timeout=6):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.02)
        self.fail("synthetic process did not reach the expected state")

    def run_bridge(self, script):
        reader, writer = os.pipe()
        self.control = os.fdopen(reader, "rb", buffering=0)
        self.writer = os.fdopen(writer, "wb", buffering=0)
        self.events, self.result = [], []
        def execute():
            self.result.append(bridge.supervise([sys.executable, "-I", "-B", "-c", script], PORT,
                                               self.control, self.events.append, cwd=str(self.root)))
        self.worker = threading.Thread(target=execute, daemon=True)
        self.worker.start()
        self.addCleanup(self.finish)

    def finish(self):
        if not self.writer.closed:
            self.writer.close()
        self.worker.join(6)
        self.assertFalse(self.worker.is_alive(), "bridge must wait for and finish its synthetic cleanup")
        self.control.close()

    def slow_script(self, *, ready=False, child=False):
        return "\n".join([
            "import os, pathlib, signal, subprocess, sys, time",
            "root = pathlib.Path('.')",
            "child = None",
            ("child = subprocess.Popen([sys.executable, '-I', '-B', '-c', " + repr(
                "import pathlib,signal,time,sys\n"
                "def stop(*args):\n pathlib.Path('child-cleaned').write_text('done'); sys.exit(0)\n"
                "signal.signal(signal.SIGTERM, stop)\npathlib.Path('child-started').write_text('yes')\n"
                "while True: time.sleep(.02)\n") + "], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)") if child else "",
            "def stop(*args):",
            " signal.signal(signal.SIGTERM, signal.SIG_IGN)",
            " root.joinpath('term').write_text('received')",
            " time.sleep(.7)",
            " if child is not None: child.wait(timeout=3)",
            " root.joinpath('cleaned').write_text('done')",
            " sys.exit(0)",
            "signal.signal(signal.SIGTERM, stop)",
            "if child is not None:",
            " while not root.joinpath('child-started').exists(): time.sleep(.02)",
            "root.joinpath('started').write_text(str(os.getpid()))",
            ("print(" + repr(URL) + ", flush=True)") if ready else "sys.stdout.write('incomplete private output'); sys.stdout.flush()",
            "while True: time.sleep(.02)",
        ])

    def test_stop_before_ready_waits_for_slow_cleanup(self):
        self.run_bridge(self.slow_script())
        self.wait_for(lambda: (self.root / "started").exists())
        started = time.monotonic()
        self.writer.write(b'{"command":"stop"}\n')
        self.finish()
        self.assertGreaterEqual(time.monotonic() - started, .65)
        self.assertTrue((self.root / "cleaned").exists())
        self.assertEqual(self.result, [0])
        self.assertEqual(self.events[-1], {"event": "stopped", "exit_code": 0})
        self.assertNotIn("incomplete private output", json.dumps(self.events))

    def test_eof_terminates_only_owned_group_and_waits_for_cleanup(self):
        sentinel = subprocess.Popen([sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"],
                                    start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def stop_sentinel():
            if sentinel.poll() is None:
                sentinel.terminate()
            sentinel.wait(timeout=5)
        self.addCleanup(stop_sentinel)
        self.run_bridge(self.slow_script(child=True))
        self.wait_for(lambda: (self.root / "started").exists())
        self.writer.close()
        self.finish()
        self.assertIsNone(sentinel.poll())
        self.assertTrue((self.root / "child-cleaned").exists())
        self.assertTrue((self.root / "cleaned").exists())
        self.assertEqual(self.result, [0])

    def test_invalid_control_is_not_echoed_and_cleans_up(self):
        self.run_bridge(self.slow_script())
        self.wait_for(lambda: (self.root / "started").exists())
        self.writer.write(b'{"command":"private-command-never-display"}\n')
        self.finish()
        self.assertEqual(self.result, [2])
        self.assertTrue((self.root / "cleaned").exists())
        self.assertEqual([value["code"] for value in self.events if value["event"] == "error"], ["invalid_control"])
        self.assertNotIn("private-command", json.dumps(self.events))

    def test_ready_once_and_untrusted_output_never_leaks(self):
        prelude = "\n".join([
            "import sys",
            "print('private-stdout-never-display', flush=True)",
            "print('private-stderr-never-display', file=sys.stderr, flush=True)",
            "print(" + repr(URL.replace("18910", "18911")) + ", flush=True)",
            "print('x' * 3000 + " + repr(URL) + ", flush=True)",
            "print(" + repr(URL) + ", file=sys.stderr, flush=True)",
        ])
        script = prelude + "\n" + self.slow_script(ready=True).replace(
            "while True: time.sleep(.02)", "print(" + repr(URL.replace("A" * 32, "B" * 32)) + ", flush=True)\nwhile True: time.sleep(.02)")
        self.run_bridge(script)
        self.wait_for(lambda: any(value["event"] == "ready" for value in self.events))
        self.writer.write(b'{"command":"stop"}\n')
        self.finish()
        self.assertEqual([value for value in self.events if value["event"] == "ready"], [{"event": "ready", "url": URL}])
        serialized = json.dumps(self.events)
        self.assertNotIn("private-stdout", serialized)
        self.assertNotIn("private-stderr", serialized)
        self.assertNotIn("18911", serialized)
        self.assertNotIn("B" * 32, serialized)

    def test_known_launcher_failure_maps_without_raw_output(self):
        self.run_bridge("import sys\nprint('这个工作台已经打开。 private-token', file=sys.stderr, flush=True)\nsys.exit(2)")
        self.worker.join(6)
        self.assertFalse(self.worker.is_alive())
        self.assertEqual(self.result, [2])
        self.assertEqual([value["code"] for value in self.events if value["event"] == "error"], ["already_running"])
        self.assertNotIn("private-token", json.dumps(self.events))

    def test_signal_to_bridge_waits_for_owned_child_cleanup(self):
        harness = ("import runpy,sys; module=runpy.run_path(sys.argv[1]); "
                   "raise SystemExit(module['supervise']([sys.executable,'-I','-B','-c',sys.argv[2]],"
                   "18910,sys.stdin.buffer))")
        process = subprocess.Popen([sys.executable, "-I", "-B", "-c", harness, str(SOURCE), self.slow_script()],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, cwd=str(self.root))
        try:
            self.wait_for(lambda: (self.root / "started").exists())
            started = time.monotonic()
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=6)
            self.assertGreaterEqual(time.monotonic() - started, .65)
            self.assertTrue((self.root / "cleaned").exists())
            self.assertEqual(process.returncode, 0)
            self.assertEqual(stderr, b"")
            self.assertEqual(json.loads(stdout.splitlines()[-1]), {"event": "stopped", "exit_code": 0})
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
                process.communicate(timeout=6)

    def test_disconnected_output_still_waits_for_owned_child_cleanup(self):
        original = bridge.event
        def disappear(value):
            if value["event"] == "ready":
                raise BrokenPipeError("synthetic GUI disconnect")
        control_reader, control_writer = os.pipe()
        try:
            with os.fdopen(control_reader, "rb", buffering=0) as control:
                code = bridge.supervise([sys.executable, "-I", "-B", "-c", self.slow_script(ready=True)],
                                        PORT, control, disappear, cwd=str(self.root))
            self.assertEqual(code, 0)
            self.assertTrue((self.root / "cleaned").exists())
        finally:
            os.close(control_writer)


if __name__ == "__main__":
    unittest.main()
