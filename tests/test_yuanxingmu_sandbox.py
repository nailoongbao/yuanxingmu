from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import queue
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from yuanxingmu import sandbox


class PlatformTests(unittest.TestCase):
    def test_windows_never_builds_an_unsandboxed_command(self):
        with patch.object(sandbox.sys, "platform", "win32"):
            self.assertFalse(sandbox.sandbox_available()["available"])
            with self.assertRaises(sandbox.SandboxUnavailable):
                sandbox.build_command(
                    command=["echo", "synthetic"], workspace=Path("C:/task"),
                    broker_socket=Path("C:/broker.sock"),
                )


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux bubblewrap only")
class SandboxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        supplied = os.environ.get("YUANXINGMU_TEST_BWRAP")
        cls.bwrap = Path(supplied) if supplied else None
        cls.availability = sandbox.sandbox_available(bwrap=cls.bwrap)
        if not cls.availability["available"]:
            raise unittest.SkipTest(str(cls.availability["reason"]))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="yuanxingmu-sandbox-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        self.socket_path = self.root / "broker.sock"
        self.broker = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.broker.bind(str(self.socket_path))
        self.broker.listen()
        self.broker.settimeout(5)
        self.addCleanup(self.broker.close)

    def argv(self, command, **kwargs):
        return sandbox.build_command(
            command=command, workspace=self.workspace, broker_socket=self.socket_path,
            bwrap=self.bwrap, **kwargs,
        )

    def record(self, data):
        destination = os.environ.get("YUANXINGMU_SANDBOX_EVIDENCE_DIR")
        if not destination:
            return
        folder = Path(destination)
        folder.mkdir(parents=True, exist_ok=True)
        data["availability"] = self.availability
        data["sandbox_sha256"] = hashlib.sha256(Path(sandbox.__file__).read_bytes()).hexdigest()
        data["test_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        (folder / f"{self._testMethodName}.json").write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8",
        )

    def run_task(self, argv, *, extra_host_env=None):
        host_env = {"PATH": "/usr/bin:/bin", **(extra_host_env or {})}
        process = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=host_env, close_fds=True, start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=15)
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=5)
            raise
        self.assertEqual(process.returncode, 0, stderr)
        return stdout, stderr

    def test_rejects_broad_home_and_root_mounts(self):
        paths = [Path("/"), Path("/home"), Path.home()]
        if Path("/mnt/c").is_dir():
            paths.append(Path("/mnt/c"))
        for path in paths:
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.argv(["/usr/bin/true"], readonly_paths=[path])

    def test_rejects_broker_parent_and_mutable_socket_location(self):
        with self.assertRaises(ValueError):
            self.argv(["/usr/bin/true"], readonly_paths=[self.root])
        nested = self.workspace / "nested.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(nested))
            with self.assertRaises(ValueError):
                sandbox.build_command(
                    command=["/usr/bin/true"], workspace=self.workspace,
                    broker_socket=nested, bwrap=self.bwrap,
                )

    def test_rejects_unusable_socket_and_control_environment_override(self):
        regular = self.root / "not-a-socket"
        regular.write_text("synthetic", encoding="utf-8")
        with self.assertRaises(ValueError):
            sandbox.build_command(
                command=["/usr/bin/true"], workspace=self.workspace,
                broker_socket=regular, bwrap=self.bwrap,
            )
        with self.assertRaises(ValueError):
            self.argv(["/usr/bin/true"], env={"HOME": "/host-home"})
        with self.assertRaises(ValueError):
            self.argv(["/usr/bin/true"], env={"YUANXINGMU_BROKER_SOCKET": "/other.sock"})

    def test_real_file_network_socket_and_environment_boundaries(self):
        private = self.root / "synthetic-private.txt"
        private.write_text("SYNTHETIC-HOST-PRIVATE-FIXTURE", encoding="utf-8")
        (self.workspace / "outside-link").symlink_to(private)
        readonly = self.root / "public-runtime.txt"
        readonly.write_text("public-runtime-fixture", encoding="utf-8")
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("127.0.0.1", 0))
        tcp.listen()
        tcp.settimeout(0.1)
        self.addCleanup(tcp.close)
        tcp_receipts = []
        stop = threading.Event()
        broker_receipts = queue.Queue()

        def collect_tcp():
            while not stop.is_set():
                try:
                    connection, _ = tcp.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(1)
                    tcp_receipts.append(connection.recv(4096).decode())

        def serve_broker():
            try:
                connection, _ = self.broker.accept()
                with connection:
                    connection.settimeout(2)
                    broker_receipts.put(connection.recv(4096).decode())
                    connection.sendall(b"accepted-synthetic-request\n")
            except BaseException as exc:
                broker_receipts.put(repr(exc))

        tcp_thread = threading.Thread(target=collect_tcp, daemon=True)
        broker_thread = threading.Thread(target=serve_broker, daemon=True)
        tcp_thread.start()
        broker_thread.start()
        code = f'''
import json, os, socket
from pathlib import Path
result = {{}}
Path('/workspace/normal.txt').write_text('ordinary-workspace-write')
for name, path in {{'private': {str(private)!r}, 'symlink': '/workspace/outside-link'}}.items():
    try:
        Path(path).read_text()
        result[name] = 'readable'
    except OSError as error:
        result[name] = type(error).__name__
result['readonly_read'] = Path({str(readonly)!r}).read_text()
try:
    Path({str(readonly)!r}).write_text('attempted-change')
    result['readonly_write'] = 'writable'
except OSError as error:
    result['readonly_write'] = type(error).__name__
try:
    connection = socket.create_connection(('127.0.0.1', {tcp.getsockname()[1]}), timeout=1)
    connection.sendall(b'SYNTHETIC-DIRECT-TCP')
    connection.close()
    result['direct_tcp'] = 'connected'
except OSError as error:
    result['direct_tcp'] = type(error).__name__
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(2)
    connection.connect('/run/yuanxingmu/broker.sock')
    connection.sendall(b'SYNTHETIC-BROKER-REQUEST')
    result['broker_response'] = connection.recv(4096).decode()
result['broker_directory'] = sorted(p.name for p in Path('/run/yuanxingmu').iterdir())
result['inherited_fake_credential'] = os.environ.get('SYNTHETIC_HOST_API_KEY')
result['explicit_setting'] = os.environ.get('YUANXINGMU_CASE')
result['pid'] = os.getpid()
status = Path('/proc/self/status').read_text().splitlines()
result['privileges'] = {{key: next(line.split(':', 1)[1].strip() for line in status if line.startswith(key + ':')) for key in ('NoNewPrivs', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb')}}
result['namespaces'] = {{name: os.readlink('/proc/self/ns/' + name) for name in ('user', 'pid', 'net', 'ipc', 'mnt', 'uts')}}
print(json.dumps(result, sort_keys=True))
'''
        argv = self.argv(
            ["/usr/bin/python3", "-c", code], readonly_paths=[readonly],
            env={"YUANXINGMU_CASE": "explicit-non-secret-setting"},
        )
        try:
            stdout, stderr = self.run_task(
                argv, extra_host_env={"SYNTHETIC_HOST_API_KEY": "FAKE-INHERITED-VALUE"},
            )
        finally:
            stop.set()
            tcp_thread.join(timeout=2)
            broker_thread.join(timeout=6)
        observation = json.loads(stdout)
        broker_receipt = broker_receipts.get(timeout=1)
        host_namespaces = {name: os.readlink("/proc/self/ns/" + name) for name in observation["namespaces"]}
        self.record({
            "argv": argv, "stdout": stdout, "stderr": stderr,
            "observation": observation, "tcp_receipts": tcp_receipts,
            "broker_receipts": [broker_receipt], "host_namespaces": host_namespaces,
            "fixtures": "All data and credential-shaped values are synthetic",
        })
        self.assertEqual((self.workspace / "normal.txt").read_text(), "ordinary-workspace-write")
        self.assertEqual(observation["private"], "FileNotFoundError")
        self.assertEqual(observation["symlink"], "FileNotFoundError")
        self.assertEqual(observation["readonly_read"], "public-runtime-fixture")
        self.assertNotEqual(observation["readonly_write"], "writable")
        self.assertEqual(readonly.read_text(), "public-runtime-fixture")
        self.assertNotEqual(observation["direct_tcp"], "connected")
        self.assertEqual(tcp_receipts, [])
        self.assertEqual(broker_receipt, "SYNTHETIC-BROKER-REQUEST")
        self.assertEqual(observation["broker_response"], "accepted-synthetic-request\n")
        self.assertEqual(observation["broker_directory"], ["broker.sock"])
        self.assertIsNone(observation["inherited_fake_credential"])
        self.assertEqual(observation["explicit_setting"], "explicit-non-secret-setting")
        self.assertEqual(observation["pid"], 1)
        self.assertEqual(observation["privileges"].pop("NoNewPrivs"), "1")
        self.assertTrue(all(int(value, 16) == 0 for value in observation["privileges"].values()))
        for name, value in host_namespaces.items():
            self.assertNotEqual(observation["namespaces"][name], value, name)

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "requires native Linux process-instance evidence")
    def test_background_process_exits_with_task_even_after_setsid(self):
        self.background_probe(cancel=False)

    @unittest.skipUnless(hasattr(os, "pidfd_open"), "requires native Linux process-instance evidence")
    def test_launcher_group_cancellation_exits_background_process(self):
        self.background_probe(cancel=True)

    def background_probe(self, *, cancel):
        observed = queue.Queue()

        def identify_child():
            try:
                connection, _ = self.broker.accept()
                with connection:
                    connection.settimeout(2)
                    peer_pid, _, _ = struct.unpack(
                        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
                    )
                    pidfd = os.pidfd_open(peer_pid)
                    observed.put((peer_pid, pidfd, connection.recv(4096).decode()))
                    connection.sendall(b"observed")
            except BaseException as exc:
                observed.put(exc)

        collector = threading.Thread(target=identify_child, daemon=True)
        collector.start()
        child_code = '''
import socket, time
from pathlib import Path
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.connect('/run/yuanxingmu/broker.sock')
    connection.sendall(b'SYNTHETIC-BACKGROUND')
    connection.recv(100)
Path('/workspace/background-ready').write_text('ready')
time.sleep(120)
'''
        parent_code = f'''
import subprocess, time
from pathlib import Path
child = subprocess.Popen(['/usr/bin/python3', '-c', {child_code!r}], start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(250):
    if Path('/workspace/background-ready').exists():
        break
    time.sleep(0.02)
else:
    raise RuntimeError('background child did not become ready')
print('task-main-exiting', flush=True)
{'time.sleep(120)' if cancel else ''}
'''
        argv = self.argv(["/usr/bin/python3", "-c", parent_code])
        process = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env={"PATH": "/usr/bin:/bin"}, close_fds=True, start_new_session=True,
        )
        try:
            item = observed.get(timeout=6)
            if cancel:
                os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate(timeout=10)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate(timeout=5)
            collector.join(timeout=6)
        if isinstance(item, BaseException):
            raise item
        peer_pid, pidfd, receipt = item
        try:
            exited = bool(select.select([pidfd], [], [], 5)[0])
            self.record({
                "argv": argv, "stdout": stdout, "stderr": stderr,
                "background_host_pid": peer_pid, "background_pidfd_exited": exited,
                "broker_receipts": [receipt], "background_created_new_session": True,
                "launcher_group_cancelled": cancel, "launcher_returncode": process.returncode,
            })
            self.assertEqual(process.returncode, -signal.SIGKILL if cancel else 0)
            if not cancel:
                self.assertEqual(stdout.strip(), "task-main-exiting")
            self.assertEqual(receipt, "SYNTHETIC-BACKGROUND")
            self.assertTrue(exited, "the observed background process instance must exit")
        finally:
            os.close(pidfd)


if __name__ == "__main__":
    unittest.main()
