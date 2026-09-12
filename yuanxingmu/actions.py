"""Host-reviewed actions with fixed targets and a durable, single-use attempt.

Only ``submit`` and ``describe_targets`` belong on an agent-facing API. Review,
editing, cancellation and ``commit`` belong on an authenticated host-only API.
The broker must hold its management lock across commit/revoke and call recover
only after acquiring exclusive ownership of its state directory.

File targets MUST be in separate host-owned directories, never in an agent's
writable mounts. The host must reject overlaps with agent workspaces and trusted
state/credentials. No advisory file lock can enforce that mounting boundary.
Only existing, small UTF-8 regular files are supported; uploads take inline text,
never a local path. This module does not run commands or follow redirects.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
import unicodedata
from urllib.parse import urlencode, urlsplit
import uuid

from .authority import Authority, AuthorizationError, _identifier


MAX_ACTIONS = 128
MAX_PENDING = 16
MAX_LIST = 50
MAX_CONTENT_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 8 * 1024
NETWORK_TIMEOUT_SECONDS = 8
KINDS = frozenset({"message", "upload", "form", "overwrite", "delete"})
_NETWORK = frozenset({"message", "upload", "form"})
_PROVIDERS = frozenset({"standard", "text", "slack", "feishu"})
_KEY = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_FIELD = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
_FORBIDDEN_HEADERS = frozenset({"host", "content-length", "transfer-encoding", "connection",
    "content-type", "x-yuanxingmu-request", "x-yuanxingmu-target", "x-yuanxingmu-action"})
_OUTCOMES = frozenset({"acknowledged", "unconfirmed", "not_started"})


def _now():
    return datetime.now(timezone.utc).isoformat()


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def _has_prior_unconfirmed_action(db, family_id, row, binding_digest):
    """Read only: match the current proposal against uncertain family effects.

    Prior effects include manual attempts and descendant tasks. Request digests
    describe the initial input, which may differ from a human-edited proposal.
    """
    prior = db.execute("""SELECT actions.target_json FROM reviewed_actions AS actions
        JOIN authority_tasks AS tasks ON tasks.id=actions.task_id
        WHERE tasks.family_id=? AND actions.status IN ('executing','unconfirmed')
          AND actions.kind=? AND actions.target_id=? AND actions.proposal_json=?""",
        (family_id, row["kind"], row["target_id"], row["proposal_json"])).fetchall()
    return any(json.loads(previous["target_json"]).get("binding_digest") == binding_digest for previous in prior)


def _text(value, reason, *, maximum=MAX_CONTENT_BYTES, normalize=True):
    if type(value) is not str:
        raise ValueError(reason)
    if normalize:
        value = value.replace("\r\n", "\n")
    allowed = "\n\t" if normalize else "\r\n\t"
    if any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} and c not in allowed for c in value):
        raise ValueError(reason)
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(reason)
    return value


def _key(value, reason):
    if type(value) is not str or not _KEY.fullmatch(value):
        raise AuthorizationError(reason)
    return value


def _relative(value):
    if type(value) is not str or not value or len(value) > 512 or "\\" in value or ":" in value:
        raise ValueError("invalid_action_relative_path")
    parts = value.split("/")
    if len(parts) > 8 or any(not p or p in {".", ".."} or len(p) > 128 for p in parts):
        raise ValueError("invalid_action_relative_path")
    _text(value, "invalid_action_relative_path", maximum=2048)
    if "\n" in value or "\t" in value:
        raise ValueError("invalid_action_relative_path")
    return value


@contextmanager
def _directory(path):
    """Open every absolute ancestor without following a symbolic link."""
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("file_actions_require_posix")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in Path(path).parts[1:]:
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


def _owned_directory(fd):
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise ValueError("action_directory_must_be_host_owned")
    return info


@dataclass(frozen=True, slots=True)
class ActionTarget:
    """Trusted configuration, never constructed from an agent proposal.

    ``port`` is convenience syntax for a loopback test receiver. Production
    callers supply a fixed HTTPS ``url``. Headers and webhook URLs are private
    configuration; ``binding`` contains their hashes, never their secret values.
    ``to_config`` is intentionally host-only and includes configured secrets.
    """

    kind: str
    label: str
    url: str | None = field(default=None, repr=False)
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    provider: str = "standard"
    workspace: Path | None = None
    relative_path: str | None = None
    form_fields: tuple[str, ...] = ()
    port: int | None = None
    _workspace_identity: tuple[int, int] | None = field(default=None, init=False, repr=False)

    def __post_init__(self):
        if type(self.kind) is not str or self.kind not in KINDS:
            raise ValueError("invalid_action_kind")
        label = _text(self.label, "invalid_action_target_label", maximum=512)
        if not label.strip() or "\n" in label or "\t" in label:
            raise ValueError("invalid_action_target_label")
        if type(self.provider) is not str or self.provider not in _PROVIDERS:
            raise ValueError("invalid_action_provider")
        if self.kind != "message" and self.provider != "standard":
            raise ValueError("action_provider_requires_message")
        if type(self.headers) is not dict:
            raise ValueError("invalid_action_headers")
        headers, seen = {}, set()
        for key, value in self.headers.items():
            if (type(key) is not str or not _HEADER.fullmatch(key) or key.lower() in _FORBIDDEN_HEADERS
                    or key.lower() in seen or type(value) is not str or not value.isascii()
                    or len(value) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in value)):
                raise ValueError("invalid_action_headers")
            seen.add(key.lower())
            headers[key] = value
        object.__setattr__(self, "headers", MappingProxyType(headers))
        if not isinstance(self.form_fields, (tuple, list)):
            raise ValueError("invalid_action_form_fields")
        fields = tuple(self.form_fields)
        if (len(fields) > 16
                or any(type(k) is not str or not _FIELD.fullmatch(k) or k in {"constructor", "prototype"} for k in fields)
                or len(set(fields)) != len(fields)
                or (self.kind == "form") != bool(fields)):
            raise ValueError("invalid_action_form_fields")
        object.__setattr__(self, "form_fields", fields)
        if self.kind in _NETWORK:
            if self.workspace is not None or self.relative_path is not None:
                raise ValueError("network_action_cannot_bind_file")
            url = self.url
            if self.port is not None:
                if url is not None or type(self.port) is not int or not 1 <= self.port <= 65535:
                    raise ValueError("invalid_action_port")
                url = f"http://127.0.0.1:{self.port}/{self.kind}"
            if type(url) is not str or not url.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in url):
                raise ValueError("invalid_action_url")
            try:
                parsed = urlsplit(url)
                port = parsed.port
            except ValueError:
                raise ValueError("invalid_action_url") from None
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.fragment or (port is not None and not 1 <= port <= 65535)):
                raise ValueError("invalid_action_url")
            if parsed.scheme == "http":
                try:
                    loopback = ipaddress.ip_address(parsed.hostname).is_loopback
                except ValueError:
                    loopback = False
                if not loopback:
                    raise ValueError("action_http_requires_literal_loopback")
            object.__setattr__(self, "url", url)
        else:
            if self.url is not None or self.port is not None or headers or self.workspace is None:
                raise ValueError("invalid_action_file_target")
            relative = _relative(self.relative_path)
            # Normalize lexical aliases before the broker compares protected
            # roots. resolve() would follow symlinks before our no-follow walk.
            work = Path(os.path.abspath(os.fspath(self.workspace)))
            try:
                with _directory(work) as fd:
                    info = _owned_directory(fd)
            except OSError:
                raise ValueError("invalid_action_workspace") from None
            object.__setattr__(self, "workspace", work)
            object.__setattr__(self, "relative_path", relative)
            object.__setattr__(self, "_workspace_identity", (info.st_dev, info.st_ino))

    def binding(self):
        return {"kind": self.kind, "label": self.label, "provider": self.provider,
                "url_sha256": _digest(self.url), "headers_sha256": _digest(dict(self.headers)),
                "workspace": str(self.workspace) if self.workspace is not None else None,
                "workspace_identity": list(self._workspace_identity) if self._workspace_identity else None,
                "relative_path": self.relative_path, "form_fields": list(self.form_fields)}

    def to_config(self):
        return {"kind": self.kind, "label": self.label, "url": self.url, "headers": dict(self.headers),
                "provider": self.provider, "workspace": str(self.workspace) if self.workspace is not None else None,
                "relative_path": self.relative_path, "form_fields": list(self.form_fields)}

    def describe(self, target_id, *, host=False):
        result = {"target_id": target_id, "kind": self.kind, "label": self.label,
                  "provider": self.provider, "form_fields": list(self.form_fields)}
        if host:
            if self.kind in _NETWORK:
                parsed = urlsplit(self.url)
                # Webhook paths and query strings can contain credentials. The
                # fixed label + binding digest identifies the exact host target.
                result["destination"] = parsed.scheme + "://" + parsed.netloc
            else:
                result["destination"] = str(self.workspace / self.relative_path)
            result["binding_digest"] = _digest(self.binding())
        return result


@contextmanager
def _file_parent(target):
    with _directory(target.workspace) as root_fd:
        root_info = _owned_directory(root_fd)
        if (root_info.st_dev, root_info.st_ino) != target._workspace_identity:
            raise ValueError("action_workspace_changed")
        parent = os.dup(root_fd)
        try:
            parts = target.relative_path.split("/")
            for part in parts[:-1]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
                os.close(parent)
                parent = child
                _owned_directory(parent)
            yield parent, parts[-1]
        finally:
            os.close(parent)


def _file_state(parent, leaf):
    fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        first = os.fstat(fd)
        if (not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or first.st_uid != os.geteuid()
                or first.st_size > MAX_CONTENT_BYTES or first.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)):
            raise ValueError("action_requires_small_regular_file")
        chunks, total = [], 0
        while total <= MAX_CONTENT_BYTES:
            chunk = os.read(fd, min(8192, MAX_CONTENT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        data = b"".join(chunks)
        last = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink, s.st_mode)
        if identity(first) != identity(last) or len(data) > MAX_CONTENT_BYTES:
            raise ValueError("action_file_changed")
        content = _text(data.decode("utf-8"), "action_requires_utf8_file", normalize=False)
        return {"content": content, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                "device": last.st_dev, "inode": last.st_ino, "modified_ns": last.st_mtime_ns,
                "changed_ns": last.st_ctime_ns, "mode": stat.S_IMODE(last.st_mode)}
    finally:
        os.close(fd)


def _snapshot(target):
    try:
        with _file_parent(target) as (parent, leaf):
            return _file_state(parent, leaf)
    except (OSError, ValueError):
        raise AuthorizationError("action_file_unavailable") from None


def validate_proposal(value, targets):
    """Validate only inline proposal data, without reading any local file."""
    if type(value) is not dict or set(value) != {"kind", "target_id", "payload"}:
        raise ValueError("invalid_action_proposal")
    kind, target_id, payload = value["kind"], value["target_id"], value["payload"]
    if type(kind) is not str or kind not in KINDS or type(target_id) is not str or not _KEY.fullmatch(target_id):
        raise ValueError("invalid_action_proposal")
    target = targets.get(target_id)
    if target is None or target.kind != kind:
        raise ValueError("action_target_not_allowed")
    if type(payload) is not dict:
        raise ValueError("invalid_action_payload")
    fields = {"message": {"body"}, "upload": {"filename", "content"}, "form": {"fields"},
              "overwrite": {"content"}, "delete": set()}[kind]
    if set(payload) != fields:
        raise ValueError("invalid_action_payload")
    canonical = {}
    if kind == "message":
        canonical["body"] = _text(payload["body"], "invalid_action_body")
    elif kind in {"upload", "overwrite"}:
        canonical["content"] = _text(payload["content"], "invalid_action_content")
        if kind == "upload":
            filename = payload["filename"]
            if type(filename) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", filename):
                raise ValueError("invalid_action_filename")
            canonical["filename"] = filename
    elif kind == "form":
        submitted = payload["fields"]
        if type(submitted) is not dict or set(submitted) != set(target.form_fields):
            raise ValueError("invalid_action_form_fields")
        canonical["fields"] = {k: _text(submitted[k], "invalid_action_form_value", maximum=8192) for k in target.form_fields}
    if len(_json(canonical).encode("utf-8")) > MAX_CONTENT_BYTES + 2048:
        raise ValueError("action_payload_too_large")
    return {"kind": kind, "target_id": target_id, "payload": canonical}


def _network_body(target, action):
    payload, kind = action["proposal"]["payload"], action["kind"]
    if kind == "message":
        body = {"body": payload["body"]}
        if target.provider in {"text", "slack"}:
            body = {"text": payload["body"]}
        elif target.provider == "feishu":
            body = {"msg_type": "text", "content": {"text": payload["body"]}}
        return "application/json; charset=utf-8", _json(body).encode("utf-8")
    if kind == "form":
        return "application/x-www-form-urlencoded; charset=utf-8", urlencode(payload["fields"]).encode("ascii")
    boundary = "Yuanxingmu_" + action["attempt_id"]
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{payload['filename']}\"\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n").encode("ascii")
    body += payload["content"].encode("utf-8") + f"\r\n--{boundary}--\r\n".encode("ascii")
    return "multipart/form-data; boundary=" + boundary, body


def _perform_network(target, action):
    content_type, body = _network_body(target, action)
    url = urlsplit(target.url)
    factory = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    connection = factory(url.hostname, url.port, timeout=NETWORK_TIMEOUT_SECONDS)
    attempted = False
    try:
        # Explicit connect separates definitely-not-started connection errors
        # from uncertain results after any request bytes could have been sent.
        connection.connect()
        attempted = True
        connection.request("POST", (url.path or "/") + ("?" + url.query if url.query else ""), body,
            {**target.headers, "Content-Type": content_type, "X-Yuanxingmu-Request": action["attempt_id"],
             "X-Yuanxingmu-Target": action["target_id"], "X-Yuanxingmu-Action": action["kind"]})
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE_BYTES + 1)
        accepted = 200 <= response.status < 300 and len(data) <= MAX_RESPONSE_BYTES
        if target.provider == "slack":
            accepted = accepted and data.strip() == b"ok"
        elif target.provider == "feishu":
            try:
                reply = json.loads(data)
                code = reply.get("code", reply.get("StatusCode")) if type(reply) is dict else None
                accepted = accepted and type(code) is int and code == 0
            except (ValueError, UnicodeError):
                accepted = False
        return {"outcome": "acknowledged" if accepted else "unconfirmed", "http_status": response.status}
    except (OSError, http.client.HTTPException, ValueError):
        return {"outcome": "unconfirmed" if attempted else "not_started", "reason": "action_transport_failed"}
    finally:
        connection.close()


def _perform_file(target, action):
    temporary, mutated = None, False
    try:
        with _file_parent(target) as (parent, leaf):
            current = _file_state(parent, leaf)
            if current != action["before"]:
                return {"outcome": "not_started", "reason": "action_file_changed"}
            if action["kind"] == "delete":
                mutated = True
                os.unlink(leaf, dir_fd=parent)
            else:
                temporary = ".yuanxingmu-" + action["attempt_id"]
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
                try:
                    data = action["proposal"]["payload"]["content"].encode("utf-8")
                    with os.fdopen(fd, "wb", closefd=False) as stream:
                        stream.write(data)
                        stream.flush()
                        os.fchmod(fd, current["mode"])
                        os.fsync(fd)
                    # Check again after preparing the replacement. The directory
                    # is host-only; competing host edits are still rejected.
                    if _file_state(parent, leaf) != current:
                        return {"outcome": "not_started", "reason": "action_file_changed"}
                    mutated = True
                    os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
                    temporary = None
                finally:
                    os.close(fd)
                    if temporary is not None:
                        try:
                            os.unlink(temporary, dir_fd=parent)
                        except OSError:
                            pass
            os.fsync(parent)
            return {"outcome": "acknowledged"}
    except (OSError, ValueError):
        return {"outcome": "unconfirmed" if mutated else "not_started", "reason": "action_file_operation_failed"}


_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS reviewed_actions (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES authority_tasks(id),
        request_key TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        kind TEXT NOT NULL,
        target_id TEXT NOT NULL,
        proposal_json TEXT NOT NULL,
        target_json TEXT NOT NULL,
        before_json TEXT,
        digest TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 1),
        status TEXT NOT NULL CHECK (status IN
          ('pending','cancelled','executing','acknowledged','unconfirmed','not_started')),
        attempt_id TEXT UNIQUE,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        approved_at TEXT,
        authorized_at TEXT,
        execution_mode TEXT CHECK(execution_mode IN ('manual','automatic')),
        authorization_source TEXT,
        authorization_sha256 TEXT,
        finished_at TEXT,
        result_json TEXT,
        UNIQUE(task_id,request_key),
        CHECK ((status IN ('pending','cancelled') AND attempt_id IS NULL AND approved_at IS NULL
            AND authorized_at IS NULL AND execution_mode IS NULL AND authorization_source IS NULL
            AND authorization_sha256 IS NULL)
          OR (status IN ('executing','acknowledged','unconfirmed','not_started')
            AND attempt_id IS NOT NULL AND authorized_at IS NOT NULL
            AND execution_mode IS NOT NULL AND authorization_source IS NOT NULL
            AND ((execution_mode='manual' AND approved_at IS NOT NULL
              AND authorization_source='host_confirmation' AND authorization_sha256 IS NULL)
            OR (execution_mode='automatic' AND approved_at IS NULL
              AND authorization_source='frozen_task_scope' AND authorization_sha256 IS NOT NULL)))))""",
    "CREATE INDEX IF NOT EXISTS reviewed_actions_task_created ON reviewed_actions(task_id,created_at DESC)",
)
_PUBLIC = ("id", "kind", "target_id", "digest", "revision", "status", "attempt_id",
           "created_at", "updated_at", "approved_at", "authorized_at", "execution_mode",
           "authorization_source", "authorization_sha256", "finished_at")


def _migrate_approval_ledger(db):
    """Preserve manual records while permitting automatic attempts without approval.

    The old CHECK constraint required approved_at for every attempt. Rebuild it
    transactionally instead of inventing a human approval for automatic sends.
    This runs on host startup, before automatic attempt tables are introduced.
    """
    columns = {row[1] for row in db.execute("PRAGMA table_info(reviewed_actions)")}
    if not columns or "execution_mode" in columns:
        return
    old = ("id", "task_id", "request_key", "request_digest", "kind", "target_id", "proposal_json",
           "target_json", "before_json", "digest", "revision", "status", "attempt_id", "created_at",
           "updated_at", "approved_at", "finished_at", "result_json")
    if columns != set(old):
        raise ValueError("unsupported_action_ledger_schema")
    db.execute(_SCHEMA[0].replace("reviewed_actions (", "reviewed_actions_v2 ("))
    names = ",".join(old)
    db.execute("INSERT INTO reviewed_actions_v2 (" + names + ",authorized_at,execution_mode,authorization_source) "
               "SELECT " + names + ",approved_at,CASE WHEN attempt_id IS NOT NULL THEN 'manual' END,"
               "CASE WHEN attempt_id IS NOT NULL THEN 'host_confirmation' END FROM reviewed_actions ORDER BY rowid")
    db.execute("DROP TABLE reviewed_actions")
    db.execute("ALTER TABLE reviewed_actions_v2 RENAME TO reviewed_actions")


class Actions:
    """Review ledger sharing the authority database and its audit transactions."""

    def __init__(self, authority: Authority, targets: dict[str, ActionTarget], *, check_content=None):
        if type(targets) is not dict or len(targets) > 128:
            raise ValueError("invalid_action_targets")
        configured = {}
        for key, target in targets.items():
            if type(key) is not str or not _KEY.fullmatch(key) or not isinstance(target, ActionTarget):
                raise ValueError("invalid_action_target")
            configured[key] = target
        self.authority = authority
        self.check_content = check_content
        self.targets = MappingProxyType(configured)
        with authority._transaction() as db:
            _migrate_approval_ledger(db)
            for statement in _SCHEMA:
                db.execute(statement)

    def binding(self):
        return {"version": 1, "targets": {key: target.binding() for key, target in sorted(self.targets.items())}}

    def binding_digest(self):
        return _digest(self.binding())

    def describe_targets(self):
        return [target.describe(key) for key, target in sorted(self.targets.items())]

    @staticmethod
    def _row(db, task_id, action_id):
        if type(action_id) is not str or not _ID.fullmatch(action_id):
            raise AuthorizationError("action_not_found")
        row = db.execute("SELECT * FROM reviewed_actions WHERE task_id=? AND id=?", (task_id, action_id)).fetchone()
        if row is None:
            raise AuthorizationError("action_not_found")
        return row

    @staticmethod
    def _public(row, *, content=False):
        value = {key: row[key] for key in _PUBLIC}
        target = json.loads(row["target_json"])
        value["target_label"] = target["label"]
        if content:
            value.update(proposal=json.loads(row["proposal_json"]), target=target,
                         before=json.loads(row["before_json"]) if row["before_json"] else None,
                         result=json.loads(row["result_json"]) if row["result_json"] else None)
        return value

    @staticmethod
    def _match(row, revision, digest):
        if type(revision) is not int or revision < 1:
            raise AuthorizationError("invalid_action_revision")
        if type(digest) is not str or not _DIGEST.fullmatch(digest):
            raise AuthorizationError("invalid_action_digest")
        if row["revision"] != revision or not hmac.compare_digest(row["digest"], digest):
            raise AuthorizationError("action_changed")

    def _event(self, db, task_id, operation, row):
        self.authority._event(db, task_id, operation, True, operation,
            {key: row[key] for key in ("id", "kind", "digest", "revision", "status", "execution_mode",
                                      "authorization_source", "authorization_sha256")})

    def _canonical(self, proposal):
        try:
            return validate_proposal(proposal, self.targets)
        except ValueError as exc:
            raise AuthorizationError(str(exc)) from None

    def _prepare(self, canonical):
        target = self.targets[canonical["target_id"]]
        described = target.describe(canonical["target_id"], host=True)
        before = _snapshot(target) if target.kind not in _NETWORK else None
        digest = _digest({"proposal": canonical, "target": described, "before": before})
        return described, before, digest

    def prior(self, task_id, request_key, proposal):
        """Read-only idempotency lookup before a host reviews a new candidate.

        Pending records also retain a stop signal when the same effect has an
        uncertain prior attempt. This does not authorize execution or reset an
        attempt. The broker performs its current admission check first.
        """
        task_id = _identifier(task_id, "task_id")
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id, require_active=False)
            key = _key(request_key, "invalid_action_request_key")
            request_digest = _digest(self._canonical(proposal))
            previous = db.execute("SELECT * FROM reviewed_actions WHERE task_id=? AND request_key=?", (task_id, key)).fetchone()
            if previous is None:
                return None
            if not hmac.compare_digest(previous["request_digest"], request_digest):
                raise AuthorizationError("action_request_conflict")
            result = self._public(previous)
            if previous["status"] == "pending" and _has_prior_unconfirmed_action(db, task["family_id"], previous,
                    json.loads(previous["target_json"])["binding_digest"]):
                result["reason"] = "automatic_prior_outcome_unconfirmed"
            return result

    def submit(self, task_id, request_key, proposal):
        """Agent proposal only. Return no previous file content or host configuration."""
        def submit(db):
            self.authority._task(db, task_id)
            key = _key(request_key, "invalid_action_request_key")
            canonical = self._canonical(proposal)
            request_digest = _digest(canonical)
            previous = db.execute("SELECT * FROM reviewed_actions WHERE task_id=? AND request_key=?", (task_id, key)).fetchone()
            if previous is not None:
                if not hmac.compare_digest(previous["request_digest"], request_digest):
                    raise AuthorizationError("action_request_conflict")
                return self._public(previous)
            counts = db.execute("SELECT COUNT(*),COALESCE(SUM(status='pending'),0) FROM reviewed_actions WHERE task_id=?", (task_id,)).fetchone()
            if counts[0] >= MAX_ACTIONS or counts[1] >= MAX_PENDING:
                raise AuthorizationError("action_limit")
            target, before, digest = self._prepare(canonical)
            identifier, now = uuid.uuid4().hex, _now()
            db.execute("""INSERT INTO reviewed_actions
                (id,task_id,request_key,request_digest,kind,target_id,proposal_json,target_json,before_json,
                 digest,revision,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,1,'pending',?,?)""",
                (identifier, task_id, key, request_digest, canonical["kind"], canonical["target_id"], _json(canonical),
                 _json(target), _json(before) if before is not None else None, digest, now, now))
            row = self._row(db, task_id, identifier)
            self._event(db, task_id, "action_proposed", row)
            return self._public(row)
        return self.authority._request(task_id, "action_submit", submit)

    def list(self, task_id):
        task_id = _identifier(task_id, "task_id")
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id, require_active=False)
            rows = db.execute("SELECT * FROM reviewed_actions WHERE task_id=? ORDER BY rowid DESC LIMIT ?", (task_id, MAX_LIST)).fetchall()
            return {"actions": [self._public(row) for row in rows], "active": not bool(task["revoked"])}

    def get(self, task_id, action_id):
        task_id = _identifier(task_id, "task_id")
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id, require_active=False)
            return {"action": self._public(self._row(db, task_id, action_id), content=True), "active": not bool(task["revoked"])}

    def edit(self, task_id, action_id, revision, digest, proposal):
        def edit(db):
            self.authority._task(db, task_id)
            row = self._row(db, task_id, action_id)
            self._match(row, revision, digest)
            if row["status"] != "pending":
                raise AuthorizationError("action_not_pending")
            canonical = self._canonical(proposal)
            target, before, current_digest = self._prepare(canonical)
            db.execute("""UPDATE reviewed_actions SET kind=?,target_id=?,proposal_json=?,target_json=?,before_json=?,
                digest=?,revision=revision+1,updated_at=? WHERE id=?""",
                (canonical["kind"], canonical["target_id"], _json(canonical), _json(target),
                 _json(before) if before is not None else None, current_digest, _now(), action_id))
            current = self._row(db, task_id, action_id)
            self._event(db, task_id, "action_edited", current)
            return self._public(current, content=True)
        return self.authority._request(task_id, "action_edit", edit)

    def cancel(self, task_id, action_id, revision, digest):
        def cancel(db):
            self.authority._task(db, task_id)
            row = self._row(db, task_id, action_id)
            self._match(row, revision, digest)
            if row["status"] != "pending":
                raise AuthorizationError("action_not_pending")
            now = _now()
            db.execute("UPDATE reviewed_actions SET status='cancelled',updated_at=?,finished_at=? WHERE id=?", (now, now, action_id))
            current = self._row(db, task_id, action_id)
            self._event(db, task_id, "action_cancelled", current)
            return self._public(current, content=True)
        return self.authority._request(task_id, "action_cancel", cancel)

    def _begin(self, task_id, action_id, revision, digest, *, automation=None, checked_proposal=None):
        def begin(db):
            self.authority._task(db, task_id, require_active=False)
            row = self._row(db, task_id, action_id)
            self._match(row, revision, digest)
            if row["attempt_id"] is not None:
                return {"started": False, "action": self._public(row, content=True)}
            self.authority._task(db, task_id)
            if row["status"] != "pending":
                raise AuthorizationError("action_not_pending")
            target = self.targets.get(row["target_id"])
            approved = json.loads(row["target_json"])
            if target is None or target.describe(row["target_id"], host=True) != approved:
                raise AuthorizationError("action_target_changed")
            if row["before_json"] is not None and _snapshot(target) != json.loads(row["before_json"]):
                raise AuthorizationError("action_file_changed")
            if self.check_content is not None:
                # Exact stored revision, before budget or a single-use attempt.
                # This callback is pure and must not open another transaction.
                self.check_content(json.loads(row["proposal_json"]))
            now, attempt_id = _now(), uuid.uuid4().hex
            mode, source, scope = "manual", "host_confirmation", None
            if automation is not None:
                if row["revision"] != 1:
                    raise AuthorizationError("automatic_edited_action_requires_review")
                if checked_proposal is None or self._canonical(checked_proposal) != json.loads(row["proposal_json"]):
                    raise AuthorizationError("automatic_checked_candidate_changed")
                if row["kind"] not in _NETWORK:
                    raise AuthorizationError("automatic_kind_requires_review")
                candidate = self._public(row, content=True)
                candidate["attempt_id"] = attempt_id
                body_bytes = len(_network_body(target, candidate)[1])
                permission = automation._authorize_attempt(db, task_id, row, target, attempt_id, body_bytes)
                mode, source, scope = "automatic", permission["source"], permission["policy_digest"]
            db.execute("""UPDATE reviewed_actions SET status='executing',attempt_id=?,approved_at=?,authorized_at=?,
                execution_mode=?,authorization_source=?,authorization_sha256=?,updated_at=? WHERE id=?""",
                (attempt_id, now if mode == "manual" else None, now, mode, source, scope, now, action_id))
            current = self._row(db, task_id, action_id)
            self._event(db, task_id, "action_commit_started", current)
            return {"started": True, "action": self._public(current, content=True)}
        return self.authority._request(task_id, "action_commit_begin", begin)

    def _finish(self, task_id, action_id, attempt_id, result):
        def finish(db):
            self.authority._task(db, task_id, require_active=False)
            row = self._row(db, task_id, action_id)
            if row["attempt_id"] != attempt_id or row["status"] != "executing":
                raise AuthorizationError("action_attempt_finished")
            if result.get("outcome") not in _OUTCOMES:
                raise AuthorizationError("invalid_action_outcome")
            now = _now()
            db.execute("UPDATE reviewed_actions SET status=?,result_json=?,updated_at=?,finished_at=? WHERE id=?",
                       (result["outcome"], _json(result), now, now, action_id))
            current = self._row(db, task_id, action_id)
            self._event(db, task_id, "action_commit_finished", current)
            return self._public(current, content=True)
        return self.authority._request(task_id, "action_commit_finish", finish)

    def commit(self, task_id, action_id, revision, digest):
        """Host-only: consume the exact reviewed version before one side effect.

        A replay, including after revocation, only returns the consumed attempt.
        Even a definitely-not-started attempt cannot be retried automatically.
        """
        with self.authority._lock:
            decision = self._begin(task_id, action_id, revision, digest)
            return self._perform_started(task_id, decision)

    def _perform_started(self, task_id, decision):
        """Caller holds Authority's lock across the complete effect interval."""
        action = decision["action"]
        if not decision["started"]:
            return {"started": False, "action": action}
        target = self.targets[action["target_id"]]
        try:
            result = _perform_network(target, action) if action["kind"] in _NETWORK else _perform_file(target, action)
        except BaseException:
            self._finish(task_id, action["id"], action["attempt_id"], {"outcome": "unconfirmed", "reason": "action_interrupted"})
            raise
        return {"started": True, "action": self._finish(task_id, action["id"], action["attempt_id"], result)}

    def commit_automatic(self, task_id, action_id, revision, digest, automation, *, checked_proposal):
        """Host-only automatic entry after reviewing this exact normalized candidate.

        The caller holds its broker lock and runs content checks first. No
        model verdict or worker field can create the host's frozen scope.
        Missing scope/remaining budget keeps a proposal pending; incompatible
        labels, revocation, pause, changed bindings or failed storage reject.
        """
        from .action_automation import ActionAutomation, PENDING_REASONS
        if type(automation) is not ActionAutomation or automation.authority is not self.authority:
            raise ValueError("automatic_action_authority_mismatch")
        with self.authority._lock:
            try:
                decision = self._begin(task_id, action_id, revision, digest,
                                       automation=automation, checked_proposal=checked_proposal)
            except AuthorizationError as exc:
                if exc.reason not in PENDING_REASONS:
                    raise
                return {"started": False, "reason": exc.reason, "action": self.get(task_id, action_id)["action"]}
            return self._perform_started(task_id, decision)

    def request_automatic(self, task_id, request_key, proposal, automation, *, checked_proposal):
        """Host convenience entry; prior requests never trigger another attempt.

        A broker should use prior before its model check, then submit and
        commit_automatic under its own management lock. This helper is useful
        for trusted callers that already completed the candidate review.
        """
        with self.authority._lock:
            previous = self.prior(task_id, request_key, proposal)
            if previous is not None:
                return {"started": False, "reason": previous.get("reason", "action_already_recorded"), "action": previous}
            row = self.submit(task_id, request_key, proposal)
            return self.commit_automatic(task_id, row["id"], row["revision"], row["digest"], automation,
                                         checked_proposal=checked_proposal)

    def recover(self):
        """Host startup only, after exclusive state ownership; never resumes I/O."""
        with self.authority._transaction() as db:
            rows = db.execute("SELECT * FROM reviewed_actions WHERE status='executing' ORDER BY rowid").fetchall()
            now = _now()
            for row in rows:
                db.execute("UPDATE reviewed_actions SET status='unconfirmed',result_json=?,updated_at=?,finished_at=? WHERE id=?",
                    (_json({"outcome": "unconfirmed", "reason": "action_recovered"}), now, now, row["id"]))
                self._event(db, row["task_id"], "action_commit_recovered", self._row(db, row["task_id"], row["id"]))
            return len(rows)
