"""Fixed network bridges for a Gateway in its own Linux network namespace.

The host holds the model credential and contacts one configured model service.
The inner process receives only Unix socket paths; its TCP listeners stay in the
namespace. These bridges do not inspect or log conversation bodies. The caller
must put ``inner`` in a network namespace and mount only the specified sockets
and the narrow ``runtime/webui`` directory, not the host runtime directory.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import ctypes
import http.client
from http.server import BaseHTTPRequestHandler
import ipaddress
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import stat
import subprocess
import sys
import threading
from urllib.parse import urlsplit


MODEL_PORT = 18701
MAX_MODEL_REQUEST = 16 * 1024 * 1024
INNER_BOOTSTRAP = (
    "import sys; sys.path.insert(0, sys.argv.pop(1)); "
    "from yuanxingmu.gateway_network import inner; raise SystemExit(inner())"
)
_CHILD_BOOTSTRAP = """
import ctypes, os, signal, sys
expected_parent = int(sys.argv.pop(1))
if os.getppid() != expected_parent:
    sys.exit(125)
libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:
    sys.exit(125)
if os.getppid() != expected_parent:
    sys.exit(125)
os.execvpe(sys.argv[1], sys.argv[1:], os.environ)
"""


def _private_directory(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("network_runtime_directory_must_be_private")


def _port(value: int) -> int:
    if type(value) is not int or not 1024 <= value <= 65535 or value == MODEL_PORT:
        raise ValueError("invalid_webui_port")
    return value


def _upstream(value: str) -> tuple[str, str, int | None, str]:
    if not isinstance(value, str) or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("invalid_model_url")
    parsed = urlsplit(value)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment):
        raise ValueError("invalid_model_url")
    if parsed.scheme == "http":
        try:
            loopback = ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            loopback = parsed.hostname == "localhost"
        if not loopback:
            raise ValueError("remote_model_service_requires_https")
    return parsed.scheme, parsed.hostname, parsed.port, parsed.path.rstrip("/") + "/chat/completions"


def _close_socket(connection: socket.socket) -> None:
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    connection.close()


class _TrackedThreads(socketserver.ThreadingMixIn):
    daemon_threads = True
    block_on_close = False

    def __init__(self, *args, **kwargs):
        self.stopping = threading.Event()
        self.connections: set[socket.socket] = set()
        self.connections_lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def track(self, connection: socket.socket) -> None:
        with self.connections_lock:
            if self.stopping.is_set():
                _close_socket(connection)
                raise OSError("network_bridge_stopped")
            self.connections.add(connection)

    def untrack(self, connection: socket.socket) -> None:
        with self.connections_lock:
            self.connections.discard(connection)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(30)
        self.track(connection)
        return connection, address

    def shutdown_request(self, request):
        self.untrack(request)
        super().shutdown_request(request)

    def close_connections(self) -> None:
        self.stopping.set()
        with self.connections_lock:
            connections = list(self.connections)
        for connection in connections:
            _close_socket(connection)

    def handle_error(self, request, client_address):
        # BaseServer prints a traceback by default. Never log request material.
        pass


class _UnixServer(_TrackedThreads, getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)):
    pass


class _TCPServer(_TrackedThreads, socketserver.TCPServer):
    allow_reuse_address = True


class _Serving:
    def __init__(self, server, path: Path | None = None):
        self.server = server
        self.path = path
        self.identity = path.stat() if path is not None else None
        self.thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.close_connections()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        if self.path is not None:
            try:
                current = self.path.lstat()
                if (stat.S_ISSOCK(current.st_mode) and current.st_dev == self.identity.st_dev
                        and current.st_ino == self.identity.st_ino):
                    self.path.unlink()
            except FileNotFoundError:
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()


def _listen(family, address, handler):
    path = Path(address) if family == socket.AF_UNIX else None
    if path is not None and (path.exists() or path.is_symlink()):
        raise ValueError("network_socket_path_already_exists")
    cls = _UnixServer if family == socket.AF_UNIX else _TCPServer
    server = cls(address, handler)
    if path is not None:
        path.chmod(0o600)
    return server, path


class _ModelHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _error(self, status: int, reason: str) -> None:
        body = ('{"error":"' + reason + '"}\n').encode("ascii")
        self.close_connection = True
        self.send_response_only(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def handle_expect_100(self):
        self._error(417, "expectation_not_supported")
        return False

    def _unsupported(self):
        self._error(405, "only_model_chat_post_is_allowed")

    do_CONNECT = do_GET = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_PATCH = do_TRACE = _unsupported

    def do_POST(self):
        self.close_connection = True
        target = self.raw_requestline.split()[1]
        if self.path != "/v1/chat/completions" or target != b"/v1/chat/completions":
            self._error(403, "model_path_not_allowed")
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Expect")
                or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit()):
            self._error(400, "unambiguous_content_length_required")
            return
        # Check digits before conversion so an enormous integer header also fails.
        if len(lengths[0]) > 10 or int(lengths[0]) > MAX_MODEL_REQUEST:
            self._error(413, "model_request_too_large")
            return
        length = int(lengths[0])
        connection = None
        tracked = None
        response_started = False
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                self._error(400, "incomplete_request")
                return
            scheme, hostname, port, path = self.server.upstream
            cls = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            connection = cls(hostname, port, timeout=10)
            connection.connect()
            tracked = connection.sock
            self.server.track(tracked)
            tracked.settimeout(180)
            # No inbound headers, caller-supplied destination, redirects, proxy
            # environment, or inbound Authorization participate in this request.
            connection.request("POST", path, body=body, headers={
                "Authorization": "Bearer " + self.server.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Connection": "close",
            })
            response = connection.getresponse()
            if response.status < 200 or 300 <= response.status < 400:
                self._error(502, "model_upstream_redirect_or_upgrade_refused")
                return
            content_type = response.getheader("Content-Type", "").lower()
            self.send_response_only(response.status)
            self.send_header("Content-Type", "text/event-stream" if content_type.startswith("text/event-stream") else "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            response_started = True
            while not self.server.stopping.is_set():
                # read1 returns available bytes, including an unfinished SSE
                # response, without waiting to fill a buffer or for its EOF.
                data = response.read1(64 * 1024)
                if not data:
                    break
                self.wfile.write(data)
                self.wfile.flush()
        except (OSError, http.client.HTTPException, ValueError):
            if not response_started and not self.server.stopping.is_set():
                self._error(502, "model_upstream_unavailable")
        finally:
            if connection is not None:
                connection.close()
            if tracked is not None:
                self.server.untrack(tracked)
                _close_socket(tracked)


def _pump(left: socket.socket, right: socket.socket, stopped: threading.Event) -> None:
    """Bounded, full-duplex transport preserving TCP half-close and WS frames."""
    peers = {left: right, right: left}
    pending = {left: bytearray(), right: bytearray()}
    readable = {left: True, right: True}
    ended_write = {left: False, right: False}
    limit = 1024 * 1024
    for connection in peers:
        connection.setblocking(False)
    while not stopped.is_set():
        for destination, source in peers.items():
            if not readable[source] and not pending[destination] and not ended_write[destination]:
                destination.shutdown(socket.SHUT_WR)
                ended_write[destination] = True
        readers = [source for source in peers if readable[source] and len(pending[peers[source]]) < limit]
        writers = [destination for destination in peers if pending[destination]]
        if not readers and not writers:
            return
        ready_read, ready_write, _ = select.select(readers, writers, [], 0.2)
        for source in ready_read:
            try:
                data = source.recv(min(64 * 1024, limit - len(pending[peers[source]])))
            except (BlockingIOError, InterruptedError):
                continue
            if data:
                pending[peers[source]].extend(data)
            else:
                readable[source] = False
        for destination in ready_write:
            try:
                sent = destination.send(pending[destination])
            except (BlockingIOError, InterruptedError):
                continue
            if not sent:
                return
            del pending[destination][:sent]


class _RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        destination = socket.socket(self.server.target_family, socket.SOCK_STREAM)
        try:
            self.server.track(destination)
            destination.settimeout(5)
            destination.connect(self.server.target_address)
            _pump(self.request, destination, self.server.stopping)
        except (OSError, ValueError):
            pass
        finally:
            self.server.untrack(destination)
            _close_socket(destination)


def _relay(listen_family, listen_address, target_family, target_address) -> _Serving:
    server, path = _listen(listen_family, listen_address, _RelayHandler)
    server.target_family = target_family
    server.target_address = target_address
    return _Serving(server, path)


class HostNetwork:
    """Host-side fixed model proxy and loopback-only Control UI transport.

    Starts ``runtime/model.sock`` and host ``127.0.0.1:webui_port`` on entry.
    Creates ``runtime/webui``; the inner process owns ``webui/gateway.sock``.
    The host and inner process must use the same absolute runtime paths.
    """

    def __init__(self, runtime: Path, *, model_url: str, api_key: str, webui_port: int):
        self.runtime = Path(runtime).absolute()
        self.upstream = _upstream(model_url)
        if not isinstance(api_key, str) or not api_key or any(ord(c) < 33 or ord(c) > 126 for c in api_key):
            raise ValueError("invalid_model_api_key")
        self.api_key = api_key
        self.webui_port = _port(webui_port)
        self._stack = None

    def __enter__(self):
        if not sys.platform.startswith("linux"):
            raise RuntimeError("gateway_network_namespace_requires_linux")
        if self._stack is not None:
            raise RuntimeError("network_bridge_already_running")
        _private_directory(self.runtime, create=True)
        _private_directory(self.runtime / "webui", create=True)
        with ExitStack() as stack:
            server, path = _listen(socket.AF_UNIX, str(self.runtime / "model.sock"), _ModelHandler)
            server.upstream = self.upstream
            server.api_key = self.api_key
            stack.enter_context(_Serving(server, path))
            stack.enter_context(_relay(socket.AF_INET, ("127.0.0.1", self.webui_port),
                                       socket.AF_UNIX, str(self.runtime / "webui" / "gateway.sock")))
            self._stack = stack.pop_all()
        return self

    def close(self):
        if self._stack is not None:
            stack, self._stack = self._stack, None
            stack.close()

    def __exit__(self, *exception):
        self.close()


def _stop_child(process: subprocess.Popen) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            pass
    # Kill remaining members even when the Gateway itself exited first.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


def inner(argv: list[str] | None = None) -> int:
    """Run inside bwrap: bridges first, then a child with parent-death cleanup.

    ``python -I -B -c INNER_BOOTSTRAP corePath --runtime R --webui-port P --
    node gateway-arguments...``. The caller supplies the namespace, mounts, and
    a clean environment; no model secret is needed or accepted by this entry.
    """
    if not sys.platform.startswith("linux"):
        raise RuntimeError("gateway_network_namespace_requires_linux")
    parser = argparse.ArgumentParser(description="Run a Gateway behind fixed namespace bridges")
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--webui-port", type=int, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a Gateway command after -- is required")
    port = _port(args.webui_port)
    runtime = args.runtime
    if not runtime.is_absolute():
        raise ValueError("absolute_network_runtime_required")
    _private_directory(runtime / "webui")
    if not stat.S_ISSOCK((runtime / "model.sock").lstat().st_mode):
        raise ValueError("model_socket_required")

    def interrupted(signum, frame):
        raise SystemExit(128 + signum)

    previous = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    parent = os.getppid()
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0 or os.getppid() != parent:
        raise RuntimeError("gateway_inner_parent_tracking_failed")
    process = None
    try:
        with ExitStack() as stack:
            stack.enter_context(_relay(socket.AF_INET, ("127.0.0.1", MODEL_PORT),
                                       socket.AF_UNIX, str(runtime / "model.sock")))
            stack.enter_context(_relay(socket.AF_UNIX, str(runtime / "webui" / "gateway.sock"),
                                       socket.AF_INET, ("127.0.0.1", port)))
            process = subprocess.Popen(
                [sys.executable, "-I", "-B", "-c", _CHILD_BOOTSTRAP, str(os.getpid()), *command],
                close_fds=True, start_new_session=True,
            )
            try:
                return process.wait()
            finally:
                _stop_child(process)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(inner())
