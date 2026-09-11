"""Trusted, fixed-destination resource broker. Run outside every worker sandbox.

One OS process owns a state directory. Its lock covers the entire read/authorize/
send interval across all endpoints. This is a single-host prototype, not a
distributed authorization service. No approval result is reusable by a worker.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import sys
import threading
from urllib.parse import urlsplit
import uuid

from .authority import Authority, AuthorizationError
from .client import MAX_MESSAGE

MAX_CONTENT = 256 * 1024


@dataclass(frozen=True)
class Resource:
    path: Path
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class Destination:
    url: str
    labels: tuple[str, ...] = ()
    # Loaded by the trusted host, never returned in describe or mounted in workers.
    headers: dict[str, str] = field(default_factory=dict, repr=False)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _send(destination: Destination, body: str, request_id: str) -> dict:
    """No environment proxies, redirects, model-chosen URLs, or response bodies."""
    url = urlsplit(destination.url)
    factory = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    connection = factory(url.hostname, url.port, timeout=8)
    encoded = json.dumps({"request_id": request_id, "body": body}, ensure_ascii=True).encode()
    target = url.path or "/"
    if url.query:
        target += "?" + url.query
    headers = {**destination.headers, "Content-Type": "application/json", "X-Yuanxingmu-Request": request_id}
    try:
        connection.request("POST", target, encoded, headers)
        response = connection.getresponse()
        response.read(MAX_CONTENT + 1)
        # A redirect is never followed. A failing remote can already have consumed
        # the body; neither an error nor a timeout proves that it was not received.
        return {"http_status": response.status, "outcome": "acknowledged" if 200 <= response.status < 300 else "unconfirmed"}
    finally:
        connection.close()


class _Server(socketserver.ThreadingUnixStreamServer if hasattr(socketserver, "ThreadingUnixStreamServer") else object):
    daemon_threads = True
    block_on_close = True


class Broker:
    """Host-only management API; a worker receives only its mounted Unix socket."""

    def __init__(self, state_dir: Path, resources: dict[str, Resource], destinations: dict[str, Destination]):
        if not sys.platform.startswith("linux") or not hasattr(socket, "AF_UNIX"):
            raise RuntimeError("broker_requires_linux")
        import fcntl
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_dir.chmod(0o700)
        self._file_lock = (self.state_dir / "broker.lock").open("a+b")
        try:
            fcntl.flock(self._file_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._file_lock.close()
            raise RuntimeError("state_already_owned_by_another_broker") from None
        self._lock = threading.RLock()
        self._servers: list[tuple[_Server, threading.Thread, Path]] = []
        self._closed = False
        self.resources = dict(resources)
        self.destinations = dict(destinations)
        self.authority = None
        try:
            binding = self._binding()
            saved = self.state_dir / "bindings.json"
            if saved.exists():
                if json.loads(saved.read_text()) != binding:
                    raise RuntimeError("state_policy_or_resource_changed")
            else:
                with saved.open("x", encoding="utf-8") as stream:
                    json.dump(binding, stream, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
            self.authority = Authority(self.state_dir / "authority.sqlite3")
        except BaseException:
            self._file_lock.close()
            raise

    def _binding(self) -> dict:
        for name in (*self.resources, *self.destinations):
            if not isinstance(name, str) or not name or len(name) > 128:
                raise ValueError("invalid_binding_name")
        resource_binding = {}
        for name, resource in self.resources.items():
            path = Path(resource.path).resolve(strict=True)
            if not path.is_file() or path.stat().st_size > MAX_CONTENT:
                raise ValueError("resource_must_be_a_small_regular_file")
            resource_binding[name] = {"path": str(path), "sha256": _digest(path.read_bytes()), "labels": sorted(resource.labels)}
        destination_binding = {}
        for name, destination in self.destinations.items():
            parsed = urlsplit(destination.url)
            if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise ValueError("invalid_destination_url")
            if parsed.scheme == "http":
                try:
                    loopback = ipaddress.ip_address(parsed.hostname).is_loopback
                except ValueError:
                    loopback = False
                if not loopback:
                    raise ValueError("unencrypted_destination_requires_literal_loopback")
            if any(not isinstance(k, str) or not isinstance(v, str) or "\r" in k + v or "\n" in k + v
                   or k.lower() in ("host", "content-length", "transfer-encoding", "connection", "content-type", "x-yuanxingmu-request")
                   for k, v in destination.headers.items()):
                raise ValueError("invalid_destination_headers")
            destination_binding[name] = {"url": destination.url, "labels": sorted(destination.labels),
                "headers_sha256": _digest(json.dumps(destination.headers, sort_keys=True).encode())}
        return {"version": 1, "resources": resource_binding, "destinations": destination_binding}

    def create_task(self, *, task_id: str | None = None, initial_labels: list[str] | None = None) -> str:
        with self._lock:
            return self.authority.create_root({k: list(v.labels) for k, v in self.resources.items()},
                {k: list(v.labels) for k, v in self.destinations.items()}, task_id=task_id,
                initial_labels=initial_labels)

    def delegate(self, task_id: str, *, resources=None, destinations=None) -> str:
        with self._lock:
            return self.authority.delegate(task_id, resources=resources, destinations=destinations)

    def revoke(self, task_id: str) -> dict:
        with self._lock:
            return self.authority.revoke(task_id)

    def bind_workspace(self, task_id: str, workspace: Path) -> Path:
        """Persist host-selected workspace ownership; never infer identity from its contents."""
        with self._lock:
            if not self.authority.describe(task_id)["active"]:
                raise AuthorizationError("task_revoked")
            work = Path(workspace).resolve(strict=True)
            if not work.is_dir():
                raise ValueError("workspace_must_be_a_directory")
            for protected in [self.state_dir, *(Path(r.path).resolve() for r in self.resources.values())]:
                if protected == work or work in protected.parents or protected in work.parents:
                    raise ValueError("workspace_overlaps_trusted_state_or_resource")
            registry = self.state_dir / "workspaces.json"
            records = json.loads(registry.read_text()) if registry.exists() else {}
            for path, owner in records.items():
                known = Path(path)
                if owner != task_id and (known == work or known in work.parents or work in known.parents):
                    raise AuthorizationError("workspace_already_bound_to_another_task")
            records[str(work)] = task_id
            temporary = registry.with_suffix(".tmp")
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(records, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(registry)
            return work

    def _event(self, task_id: str, operation: str, result: dict, **extra) -> None:
        event = {"time": datetime.now(timezone.utc).isoformat(), "task_id": task_id, "operation": operation,
                 **{k: v for k, v in result.items() if k not in ("content", "body")}, **extra}
        with (self.state_dir / "broker-events.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def dispatch(self, task_id: str, request: dict) -> dict:
        with self._lock:
            operation = request.get("op") if isinstance(request, dict) else None
            try:
                if self._closed:
                    raise AuthorizationError("broker_closed")
                fields = {"read": {"op", "resource"}, "send": {"op", "destination", "body"}, "describe": {"op"}}
                if not isinstance(operation, str) or operation not in fields or set(request) != fields[operation]:
                    raise AuthorizationError("invalid_request")
                if operation == "describe":
                    state = self.authority.describe(task_id)
                    if not state["active"]:
                        raise AuthorizationError("task_revoked")
                    result = {"allowed": True, **state}
                elif operation == "read":
                    name = request["resource"]
                    if not isinstance(name, str) or name not in self.resources:
                        raise AuthorizationError("unknown_resource")
                    decision = self.authority.record_read(task_id, name)
                    content = Path(self.resources[name].path).read_bytes()
                    expected = json.loads((self.state_dir / "bindings.json").read_text())["resources"][name]["sha256"]
                    if len(content) > MAX_CONTENT or _digest(content) != expected:
                        raise AuthorizationError("resource_changed")
                    result = {**decision, "content": content.decode("utf-8")}
                else:
                    name, body = request["destination"], request["body"]
                    if not isinstance(name, str) or name not in self.destinations:
                        raise AuthorizationError("unknown_destination")
                    if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_CONTENT:
                        raise AuthorizationError("invalid_body")
                    decision = self.authority.authorize_send(task_id, name)
                    result = dict(decision)
                    if decision["allowed"]:
                        request_id = uuid.uuid4().hex
                        # Persist intent first; interrupted/unacknowledged attempts
                        # remain distinguishable from attempts never authorized.
                        self._event(task_id, "send_intent", decision, request_id=request_id, body_sha256=_digest(body.encode()))
                        try:
                            delivered = _send(self.destinations[name], body, request_id)
                        except (OSError, http.client.HTTPException, ValueError):
                            delivered = {"outcome": "unknown"}
                        result.update(request_id=request_id, **delivered)
                self._event(task_id, operation, result)
                return result
            except AuthorizationError as exc:
                result = {"allowed": False, "reason": exc.reason}
            except (OSError, ValueError, TypeError):
                result = {"allowed": False, "reason": "broker_operation_failed"}
            self._event(task_id, operation or "invalid", result)
            return result

    def serve(self, task_id: str, socket_path: Path) -> Path:
        """The trusted host binds identity once, before mounting this single socket."""
        with self._lock:
            if self._closed or not self.authority.describe(task_id)["active"]:
                raise AuthorizationError("task_inactive")
            socket_path = Path(socket_path).absolute()
            if len(os.fsencode(socket_path)) > 100:
                raise ValueError("unix_socket_path_too_long")
            socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            broker = self

            class Handler(socketserver.StreamRequestHandler):
                def handle(self):
                    self.connection.settimeout(10)
                    try:
                        raw = self.rfile.readline(MAX_MESSAGE + 1)
                        if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
                            result = {"allowed": False, "reason": "invalid_message"}
                        else:
                            try:
                                request = json.loads(raw)
                            except (ValueError, UnicodeError):
                                request = None
                            result = broker.dispatch(task_id, request)
                        self.wfile.write(json.dumps(result, ensure_ascii=True).encode() + b"\n")
                    except (OSError, ValueError):
                        return

            server = _Server(str(socket_path), Handler)
            socket_path.chmod(0o600)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            self._servers.append((server, thread, socket_path))
            thread.start()
            return socket_path

    def close(self) -> None:
        with self._lock:
            self._closed = True
        for server, thread, path in self._servers:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            path.unlink(missing_ok=True)
        self._servers.clear()
        with self._lock:
            if self.authority is not None:
                self.authority.close()
                self.authority = None
            self._file_lock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
