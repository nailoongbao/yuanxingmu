"""Real local transport checks; these do not run a model or claim model safety."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager, redirect_stderr, redirect_stdout
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import queue
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from unittest.mock import patch

from yuanxingmu import gateway_network as network


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("unused-host", timeout=3)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class _ProviderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.receipts.put((self.command, self.path, dict(self.headers), body))
        self.server.reply(self)


def _json_reply(handler):
    body = b'{"synthetic":"model-response"}'
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


@contextmanager
def _provider(reply=_json_reply):
    class ProviderServer(ThreadingHTTPServer):
        def get_request(self):
            accepted = super().get_request()
            self.connections.put(accepted[1])
            return accepted

    server = ProviderServer(("127.0.0.1", 0), _ProviderHandler)
    server.receipts = queue.Queue()
    server.connections = queue.Queue()
    server.reply = reply
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@contextmanager
def _tcp_once(handler):
    receipts = queue.Queue()
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(5)
    address = listener.getsockname()

    def serve():
        try:
            connection, _ = listener.accept()
            with connection:
                connection.settimeout(5)
                receipts.put(handler(connection))
        except BaseException as exc:
            receipts.put(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield address, receipts
    finally:
        listener.close()
        thread.join(timeout=6)


class GatewayNetworkConfigurationTests(unittest.TestCase):
    def test_rejects_untrusted_upstream_configuration_before_network_activity(self):
        for value in ("http://example.com/v1", "file:///tmp/model", "https://user:pass@example.com/v1",
                      "https://@example.com/v1", "https://example.com/v1?url=elsewhere",
                      "https://example.com/v1#fragment", "https://example.com/\nv1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                network.HostNetwork(Path("unused"), model_url=value, api_key="synthetic", webui_port=18911)
        for key in ("", "secret\r\nHost: another", "contains space", "\u4e0d\u5408\u6cd5"):
            with self.subTest(key=key), self.assertRaises(ValueError):
                network.HostNetwork(Path("unused"), model_url="https://example.com/v1", api_key=key, webui_port=18911)
        with self.assertRaises(ValueError):
            network.HostNetwork(Path("unused"), model_url="https://example.com/v1", api_key="synthetic", webui_port=18701)

    def test_windows_imports_but_never_starts_an_unisolated_bridge(self):
        bridge = network.HostNetwork(Path("unused"), model_url="https://example.com/v1", api_key="synthetic", webui_port=18911)
        with patch.object(network.sys, "platform", "win32"), self.assertRaisesRegex(RuntimeError, "requires_linux"):
            bridge.__enter__()


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux Unix socket bridges only")
class GatewayNetworkTransportTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="yxm-network-")))

    def start(self, provider):
        runtime = self.root / "runtime"
        bridge = network.HostNetwork(runtime,
            model_url=f"http://127.0.0.1:{provider.server_port}/fixed/v1/",
            api_key="SYNTHETIC-HOST-SECRET", webui_port=_free_port())
        self.stack.enter_context(bridge)
        return bridge

    def request(self, bridge, method="POST", path="/v1/chat/completions", body=b'{"input":"synthetic"}', headers=None):
        connection = _UnixHTTP(bridge.runtime / "model.sock")
        try:
            try:
                connection.request(method, path, body=body, headers=headers or {})
            except BrokenPipeError:
                # The bridge may reject headers and close before the body write.
                # Still require a real HTTP response; callers retain their status
                # and independent upstream-receipt assertions.
                pass
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_only_fixed_target_and_host_authorization_reach_upstream(self):
        provider = self.stack.enter_context(_provider())
        bridge = self.start(provider)
        output = io.StringIO()
        body = b'{"messages":[{"content":"SYNTHETIC-PRIVATE-TEXT"}]}'
        with redirect_stdout(output), redirect_stderr(output), patch.dict(os.environ, {
                "HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1"}):
            status, _, data = self.request(bridge, body=body, headers={
                "Host": "caller-selected.invalid", "Authorization": "Bearer CALLER-SECRET",
                "Proxy-Authorization": "caller-proxy", "X-Api-Key": "caller-key",
                "Forwarded": "host=caller-selected.invalid", "Content-Type": "application/octet-stream",
                "Connection": "Upgrade", "Upgrade": "websocket",
            })
        self.assertEqual(status, 200)
        self.assertEqual(data, b'{"synthetic":"model-response"}')
        method, path, headers, received = provider.receipts.get(timeout=1)
        self.assertEqual((method, path, received), ("POST", "/fixed/v1/chat/completions", body))
        self.assertEqual(headers["Host"], f"127.0.0.1:{provider.server_port}")
        self.assertEqual(headers["Authorization"], "Bearer SYNTHETIC-HOST-SECRET")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Connection"], "close")
        for name in ("Proxy-Authorization", "Forwarded", "X-Api-Key", "Upgrade"):
            self.assertNotIn(name, headers)
        self.assertEqual(output.getvalue(), "")

    def test_other_urls_paths_methods_and_ambiguous_http_never_reach_upstream(self):
        provider = self.stack.enter_context(_provider())
        bridge = self.start(provider)
        for method, path in (
                ("CONNECT", "127.0.0.1:443"), ("GET", "/v1/chat/completions"),
                ("POST", "http://127.0.0.1:12345/v1/chat/completions"),
                ("POST", "/v1/chat/completions?url=https://elsewhere.invalid"),
                ("POST", "/v1/models"), ("POST", "/v1/files"),
                ("POST", "//v1/chat/completions"), ("POST", "/v1/chat/completions/")):
            with self.subTest(method=method, path=path):
                status, _, _ = self.request(bridge, method, path)
                self.assertIn(status, (403, 405))
        for framing, status in (
                (b"Content-Length: 0\r\nContent-Length: 0\r\n", 400),
                (b"Transfer-Encoding: chunked\r\n", 400),
                (b"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n", 400),
                (b"Content-Length: -1\r\n", 400),
                (b"Content-Length: 16777217\r\n", 413),
                (b"Content-Length: 9999999999999999999999999999\r\n", 413),
                (b"Expect: 100-continue\r\nContent-Length: 0\r\n", 417)):
            with self.subTest(framing=framing), socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(3)
                connection.connect(str(bridge.runtime / "model.sock"))
                connection.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: synthetic\r\n" + framing + b"\r\n")
                response = http.client.HTTPResponse(connection)
                response.begin()
                self.assertEqual(response.status, status)
                response.read()
        self.assertTrue(provider.receipts.empty())

    def test_redirect_does_not_contact_its_destination_or_reveal_location(self):
        destination = self.stack.enter_context(_provider())

        def redirect(handler):
            handler.send_response(307)
            handler.send_header("Location", f"http://127.0.0.1:{destination.server_port}/arbitrary")
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        provider = self.stack.enter_context(_provider(redirect))
        bridge = self.start(provider)
        status, headers, body = self.request(bridge)
        self.assertEqual(status, 502)
        self.assertNotIn("Location", headers)
        self.assertIn(b"redirect_or_upgrade_refused", body)
        self.assertTrue(destination.receipts.empty())
        self.assertEqual(provider.receipts.qsize(), 1)

    def test_chunked_sse_first_event_arrives_before_upstream_finishes(self):
        release = threading.Event()
        upstream_done = threading.Event()
        self.addCleanup(release.set)

        def stream(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Transfer-Encoding", "chunked")
            handler.end_headers()
            first = b'data: {"synthetic":"first"}\n\n'
            handler.wfile.write(f"{len(first):X}\r\n".encode() + first + b"\r\n")
            handler.wfile.flush()
            release.wait(5)
            last = b"data: [DONE]\n\n"
            handler.wfile.write(f"{len(last):X}\r\n".encode() + last + b"\r\n0\r\n\r\n")
            handler.wfile.flush()
            upstream_done.set()

        provider = self.stack.enter_context(_provider(stream))
        bridge = self.start(provider)
        connection = _UnixHTTP(bridge.runtime / "model.sock")
        self.addCleanup(connection.close)
        connection.request("POST", "/v1/chat/completions", body=b'{"stream":true}')
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.getheader("Content-Type"), "text/event-stream")
        self.assertIsNone(response.getheader("Transfer-Encoding"))
        self.assertEqual(response.readline(), b'data: {"synthetic":"first"}\n')
        self.assertFalse(upstream_done.is_set(), "proxy buffered SSE until the response completed")
        release.set()
        self.assertEqual(response.read(), b"\ndata: [DONE]\n\n")

    def test_host_and_inner_relays_preserve_websocket_upgrade_and_both_directions(self):
        provider = self.stack.enter_context(_provider())
        bridge = self.start(provider)
        payload = b"synthetic-websocket-message"
        mask = b"abcd"
        masked = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
        client_frame = bytes([0x81, 0x80 | len(payload)]) + mask + masked
        server_frame = bytes([0x81, len(payload)]) + payload

        def websocket(connection):
            reader = connection.makefile("rb")
            header = bytearray()
            while not header.endswith(b"\r\n\r\n"):
                header.extend(reader.read(1))
                if len(header) > 8192:
                    raise AssertionError("oversized WebSocket handshake")
            connection.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                               b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")
            # A server-initiated frame must arrive before the client sends its
            # frame: this catches request/response-only pseudo-relays.
            connection.sendall(b"\x89\x04PING")
            received = reader.read(len(client_frame))
            connection.sendall(server_frame)
            reader.close()
            return bytes(header), received

        address, receipts = self.stack.enter_context(_tcp_once(websocket))
        self.stack.enter_context(network._relay(socket.AF_UNIX, str(bridge.runtime / "webui" / "gateway.sock"),
                                                socket.AF_INET, address))
        with socket.create_connection(("127.0.0.1", bridge.webui_port), timeout=3) as connection:
            handshake = (b"GET /synthetic-chat?token=synthetic HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
                         b"Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
            connection.sendall(handshake)
            reader = connection.makefile("rb")
            self.assertIn(b"101", reader.readline())
            while reader.readline() != b"\r\n":
                pass
            self.assertEqual(reader.read(6), b"\x89\x04PING")
            connection.sendall(client_frame)
            self.assertEqual(reader.read(len(server_frame)), server_frame)
            reader.close()
        self.assertEqual(receipts.get(timeout=3), (handshake, client_frame))

    def test_relay_drains_large_buffer_after_client_half_close(self):
        provider = self.stack.enter_context(_provider())
        bridge = self.start(provider)
        payload = b"SYNTHETIC-HALF-CLOSE" * (128 * 1024)

        def receiver(connection):
            digest = hashlib.sha256()
            length = 0
            while data := connection.recv(65536):
                digest.update(data)
                length += len(data)
            response = f"{length}:{digest.hexdigest()}".encode()
            connection.sendall(response)
            connection.shutdown(socket.SHUT_WR)
            return response

        address, receipts = self.stack.enter_context(_tcp_once(receiver))
        self.stack.enter_context(network._relay(socket.AF_UNIX, str(bridge.runtime / "webui" / "gateway.sock"),
                                                socket.AF_INET, address))
        with socket.create_connection(("127.0.0.1", bridge.webui_port), timeout=5) as connection:
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            chunks = []
            while data := connection.recv(4096):
                chunks.append(data)
        expected = f"{len(payload)}:{hashlib.sha256(payload).hexdigest()}".encode()
        self.assertEqual(b"".join(chunks), expected)
        self.assertEqual(receipts.get(timeout=3), expected)

    def test_close_interrupts_active_http_and_releases_socket_and_port(self):
        started, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)

        def wait_for_shutdown(handler):
            started.set()
            release.wait(5)

        provider = self.stack.enter_context(_provider(wait_for_shutdown))
        bridge = self.start(provider)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect(str(bridge.runtime / "model.sock"))
            connection.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: synthetic\r\nContent-Length: 2\r\n\r\n{}")
            self.assertTrue(started.wait(3))
            bridge.close()
            self.assertEqual(connection.recv(1), b"")
        self.assertFalse((bridge.runtime / "model.sock").exists())
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", bridge.webui_port))
        release.set()
        bridge.close()  # Operator stop is safely repeatable.

    def test_cleanup_leaves_replaced_path_untouched_and_start_refuses_existing_path(self):
        provider = self.stack.enter_context(_provider())
        bridge = self.start(provider)
        path = bridge.runtime / "model.sock"
        path.unlink()
        path.write_text("SYNTHETIC-REPLACEMENT")
        bridge.close()
        self.assertEqual(path.read_text(), "SYNTHETIC-REPLACEMENT")
        with self.assertRaisesRegex(ValueError, "already_exists"):
            bridge.__enter__()
        self.assertEqual(path.read_text(), "SYNTHETIC-REPLACEMENT")

    def test_inner_launch_bridges_model_and_cleans_up_after_child_exit(self):
        provider = self.stack.enter_context(_provider())
        bridge = self.start(provider)
        code = """
import http.client, sys
connection = http.client.HTTPConnection('127.0.0.1', 18701, timeout=3)
connection.request('POST', '/v1/chat/completions', body=b'{"synthetic":"inner"}')
response = connection.getresponse()
assert response.status == 200, response.status
assert response.read() == b'{"synthetic":"model-response"}'
connection.close()
sys.exit(7)
"""
        repo = Path(network.__file__).resolve().parent.parent
        process = subprocess.run([sys.executable, "-I", "-B", "-c", network.INNER_BOOTSTRAP, str(repo),
            "--runtime", str(bridge.runtime), "--webui-port", str(bridge.webui_port), "--",
            sys.executable, "-I", "-B", "-c", code], capture_output=True, text=True, timeout=12)
        self.assertEqual(process.returncode, 7, process.stderr)
        self.assertEqual(provider.receipts.qsize(), 1)
        self.assertFalse((bridge.runtime / "webui" / "gateway.sock").exists())
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", network.MODEL_PORT))

    def test_parent_death_stops_inner_gateway_and_gateway_process_group(self):
        provider = self.stack.enter_context(_provider())
        bridge = self.start(provider)
        repo = Path(network.__file__).resolve().parent.parent
        inner_pid = self.root / "inner.pid"
        gateway_pid = self.root / "gateway.pid"
        descendant_pid = self.root / "descendant.pid"
        gateway = """
import os, subprocess, sys, time
from pathlib import Path
Path(sys.argv[1]).write_text(str(os.getpid()))
subprocess.Popen([sys.executable, '-I', '-B', '-c',
    'import os, sys, time; from pathlib import Path; Path(sys.argv[1]).write_text(str(os.getpid())); time.sleep(60)', sys.argv[2]])
time.sleep(60)
"""
        inner_argv = [sys.executable, "-I", "-B", "-c", network.INNER_BOOTSTRAP, str(repo),
            "--runtime", str(bridge.runtime), "--webui-port", str(bridge.webui_port), "--",
            sys.executable, "-I", "-B", "-c", gateway, str(gateway_pid), str(descendant_pid)]
        launcher = """
import json, subprocess, sys, time
from pathlib import Path
process = subprocess.Popen(json.loads(sys.argv[1]))
Path(sys.argv[2]).write_text(str(process.pid))
time.sleep(60)
"""
        # A separate subreaper owns this entire synthetic process tree so the
        # test can prove termination and collect every child without leaving
        # zombies behind or changing the test runner's process semantics.
        driver = """
import ctypes, json, os, signal, subprocess, sys, time
from pathlib import Path
payload = json.loads(sys.argv[1])
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
process = subprocess.Popen(payload['launch'])
paths = [Path(value) for value in payload['markers']]
pids = []
statuses = {}
try:
    deadline = time.monotonic() + 6
    while not all(path.exists() and path.read_text().strip() for path in paths):
        assert time.monotonic() < deadline, 'synthetic process tree did not start'
        assert process.poll() is None, 'synthetic parent exited early'
        time.sleep(0.02)
    pids = [int(path.read_text()) for path in paths]
    process.kill()
    assert process.wait(timeout=3) == -signal.SIGKILL
    adopted = {pids[0], pids[2]}
    deadline = time.monotonic() + 7
    while set(statuses) != adopted:
        try:
            pid, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if pid:
            statuses[pid] = os.waitstatus_to_exitcode(status)
        else:
            assert time.monotonic() < deadline, 'parent-death cleanup left a process running'
            time.sleep(0.02)
    assert set(statuses) == adopted, (pids, statuses)
    # inner owns and reaps Gateway; the subreaper collects inner and the
    # Gateway's orphaned descendant, and verifies Gateway no longer exists.
    assert not Path('/proc/' + str(pids[1])).exists(), 'Gateway survived inner cleanup'
    print(json.dumps({'inner': statuses[pids[0]], 'gateway_gone': True, 'descendant': statuses[pids[2]]}))
finally:
    if process.poll() is None:
        process.kill()
        process.wait(timeout=3)
    for path in paths:
        if path.exists() and path.read_text().strip():
            try:
                os.kill(int(path.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            break
        if not pid:
            time.sleep(0.02)
"""
        payload = {"launch": [sys.executable, "-I", "-B", "-c", launcher, json.dumps(inner_argv), str(inner_pid)],
                   "markers": [str(inner_pid), str(gateway_pid), str(descendant_pid)]}
        result = subprocess.run([sys.executable, "-I", "-B", "-c", driver, json.dumps(payload)],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        statuses = json.loads(result.stdout)
        self.assertEqual(statuses["inner"], 128 + signal.SIGTERM)
        self.assertTrue(statuses["gateway_gone"])
        self.assertIn(statuses["descendant"], (-signal.SIGTERM, -signal.SIGKILL))
        self.assertFalse((bridge.runtime / "webui" / "gateway.sock").exists())
        with socket.socket() as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", network.MODEL_PORT))


class AuditMetadataConfigurationTests(unittest.TestCase):
    def test_default_and_host_factory_have_explicit_schema(self):
        self.assertEqual(network._audit_headers(None), {})
        first = network._audit_headers(network.new_audit_metadata)
        second = network._audit_headers(network.new_audit_metadata)
        self.assertEqual(set(first), {"X-YXM-Audit-Correlation-ID", "X-YXM-Audit-Protocol-Version"})
        self.assertEqual(first["X-YXM-Audit-Protocol-Version"], "1.0")
        self.assertRegex(first["X-YXM-Audit-Correlation-ID"], r"^corr-[0-9a-f]{32}$")
        self.assertNotEqual(first["X-YXM-Audit-Correlation-ID"], second["X-YXM-Audit-Correlation-ID"])

    def test_invalid_provider_and_metadata_fail_without_transport(self):
        valid = network.new_audit_metadata()
        cases = [None, [], {}, {"X-YXM-Audit-Correlation-ID": valid["X-YXM-Audit-Correlation-ID"]},
                 {**valid, "Authorization": "replace-host-key"},
                 {**valid, "X-YXM-Audit-Protocol-Version": "sales-v2"},
                 {**valid, "X-YXM-Audit-Correlation-ID": "bad\r\nHeader: injected"},
                 {**valid, "X-YXM-Audit-Correlation-ID": "corr-" + "a" * 65},
                 {**valid, "X-YXM-Audit-Correlation-ID": "业务标签"}]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                network._audit_headers(lambda: value)
        with self.assertRaisesRegex(ValueError, "provider_invalid"):
            network._audit_headers("not-callable")
        with self.assertRaisesRegex(ValueError, "generation_failed"):
            network._audit_headers(mock.Mock(side_effect=RuntimeError("private provider detail")))

    def test_validated_metadata_does_not_alias_host_mapping(self):
        metadata = network.new_audit_metadata()
        result = network._audit_headers(lambda: metadata)
        metadata["X-YXM-Audit-Protocol-Version"] = "changed"
        self.assertEqual(result["X-YXM-Audit-Protocol-Version"], "1.0")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux Unix socket bridges only")
class AuditMetadataTransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runtime = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _guard(self):
        guard = mock.Mock(side_effect=lambda data, ct: data)
        guard.preflight = mock.Mock(return_value=None)
        return guard

    def _store(self):
        store = mock.Mock()
        ticket = mock.Mock()
        ticket.replay = None
        store.begin = mock.Mock(return_value=ticket)
        store.complete = mock.Mock(side_effect=lambda t, data, ct: data)
        store.finish = mock.Mock()
        store.lookup = mock.Mock(return_value=None)
        return store

    def _post(self, headers=None):
        conn = _UnixHTTP(self.runtime / "model.sock")
        try:
            conn.request("POST", "/v1/chat/completions", body=b'{"model":"test"}', headers=headers or {})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_worker_inbound_headers_are_stripped_and_default_has_no_audit_headers(self):
        with _provider() as upstream:
            port = upstream.server_address[1]
            host_model = network.HostModel(
                self.runtime,
                model_url=f"http://127.0.0.1:{port}/v1/chat/completions",
                api_key="SYNTHETIC-HOST-SECRET",
                output_guard=self._guard(),
                model_store=self._store(),
            )
            with host_model:
                # Worker attempts to inject spoofed headers and custom audit headers
                status, _ = self._post(headers={
                    "X-YXM-Audit-Correlation-ID": "spoofed-by-worker",
                    "X-Custom-Injected-Header": "malicious",
                    "Authorization": "Bearer worker-fake-token",
                })
                self.assertEqual(status, 200)
                cmd, path, headers, body = upstream.receipts.get(timeout=2)
                # Verify worker headers did not enter upstream
                self.assertNotIn("x-custom-injected-header", {k.lower() for k in headers})
                self.assertNotIn("x-yxm-audit-correlation-id", {k.lower() for k in headers})
                self.assertEqual(headers["Authorization"], "Bearer SYNTHETIC-HOST-SECRET")

    def test_host_audit_metadata_provider_injects_permitted_headers(self):
        with _provider() as upstream:
            port = upstream.server_address[1]
            host_model = network.HostModel(
                self.runtime,
                model_url=f"http://127.0.0.1:{port}/v1/chat/completions",
                api_key="SYNTHETIC-HOST-SECRET",
                output_guard=self._guard(),
                model_store=self._store(),
                audit_metadata_provider=network.new_audit_metadata,
            )
            with host_model:
                identifiers = []
                for _ in range(2):
                    status, _ = self._post({"X-YXM-Audit-Correlation-ID": "worker-spoof"})
                    self.assertEqual(status, 200)
                    cmd, path, headers, body = upstream.receipts.get(timeout=2)
                    identifiers.append(headers["X-YXM-Audit-Correlation-ID"])
                    self.assertRegex(identifiers[-1], r"^corr-[0-9a-f]{32}$")
                    self.assertEqual(headers["X-YXM-Audit-Protocol-Version"], "1.0")
                    self.assertEqual(headers["Authorization"], "Bearer SYNTHETIC-HOST-SECRET")
                    self.assertEqual({k for k in headers if k.startswith("X-YXM-Audit-")},
                                     {"X-YXM-Audit-Correlation-ID", "X-YXM-Audit-Protocol-Version"})
                self.assertNotEqual(*identifiers)
                self.assertEqual(upstream.connections.qsize(), 2)

    def test_disallowed_or_invalid_audit_metadata_aborts_before_upstream(self):
        valid = network.new_audit_metadata()
        providers = [lambda: {}, lambda: {"X-YXM-Audit-Task-ID": "task-123"},
                     lambda: {**valid, "X-YXM-Audit-Correlation-ID": "bad\r\nX-Injected: yes"},
                     lambda: {**valid, "X-YXM-Audit-Correlation-ID": "a" * 65},
                     lambda: {**valid, "X-YXM-Audit-Protocol-Version": "unrecognized"},
                     mock.Mock(side_effect=RuntimeError("private provider detail"))]
        actual_connect = http.client.HTTPConnection.connect
        for index, provider in enumerate(providers):
            with self.subTest(case=index):
                with _provider() as upstream:
                    port = upstream.server_address[1]
                    store = self._store()
                    host_model = network.HostModel(
                        self.runtime,
                        model_url=f"http://127.0.0.1:{port}/v1/chat/completions",
                        api_key="SYNTHETIC-HOST-SECRET",
                        output_guard=self._guard(),
                        model_store=store,
                        audit_metadata_provider=provider,
                    )
                    with host_model, patch.object(http.client.HTTPConnection, "connect", autospec=True,
                                                  side_effect=actual_connect) as connect:
                        status, response = self._post()
                        self.assertEqual(status, 500)
                        self.assertNotIn(b"private provider detail", response)
                        connect.assert_not_called()
                        store.begin.assert_not_called()
                        store.finish.assert_not_called()
                        self.assertTrue(upstream.connections.empty())
                        self.assertTrue(upstream.receipts.empty())


if __name__ == "__main__":
    unittest.main()
