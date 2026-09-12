"""Operator-owned, persistent OpenClaw profiles (Linux/WSL).

Each profile is born private, including pasted chat and subsequent sessions.
Only its fixed model service is entrusted with conversation data. The Gateway
runs in a network namespace; a host bridge holds its fixed model credential.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import socketserver
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import quote, urlsplit
import uuid

from .authority import AuthorizationError
from .broker import Broker, MAX_CONTENT
from .client import MAX_MESSAGE
from .run import load_policy
from .sandbox import sandbox_available, _system_mount_args, _reject_broad_grant, _overlaps

OPENCLAW_VERSION = "2026.9.4"
TOOLS = ["exec", "yuanxingmu_read", "yuanxingmu_send", "yuanxingmu_status"]
PACKAGE = Path(__file__).resolve().parent
PLUGIN = PACKAGE / "integrations" / "openclaw" / "plugin"


def _linux():
    if not sys.platform.startswith("linux"):
        raise RuntimeError("请在 Linux 或 WSL 中运行；需要真实的 Linux 执行隔离。")


def _save(path: Path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def _bytes(path: Path, value: bytes):
    with path.open("xb") as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def _hash(path: Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _identity(path: Path):
    info = path.stat(follow_symlinks=False)
    if stat.S_ISLNK(info.st_mode):
        raise RuntimeError("profile_path_must_not_be_a_symlink")
    return [info.st_dev, info.st_ino]


def _name(value: str):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value):
        raise ValueError("资料和接收位置的名称须为 1–64 位字母、数字、下划线或连字符。")
    return value


def _model_url(value: str):
    url = urlsplit(value)
    if url.scheme not in ("https", "http") or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError("模型地址须为不含密码、查询参数或片段的 HTTPS 地址，或本机 HTTP 地址。")
    if url.scheme == "http":
        try:
            loopback = ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            loopback = url.hostname == "localhost"
        if not loopback:
            raise ValueError("远程模型服务必须使用 HTTPS。")
    return value.rstrip("/")


def _manifest(profile: Path):
    profile = profile.absolute()
    if profile.is_symlink():
        raise RuntimeError("profile_path_must_not_be_a_symlink")
    profile = profile.resolve(strict=True)
    value = json.loads((profile / "profile.json").read_text(encoding="utf-8"))
    if value.get("version") != 2 or value.get("profile") != str(profile):
        raise RuntimeError("profile_identity_changed")
    if value.get("framework", "openclaw") not in {"openclaw", "hermes"}:
        raise RuntimeError("profile_framework_unknown")
    return profile, value


def _task_state(profile: Path, manifest: dict):
    database = profile / "broker-state" / "authority.sqlite3"
    # mode=ro is deliberate: a missing ledger must never create a new authority.
    with sqlite3.connect("file:" + quote(str(database)) + "?mode=ro", uri=True) as db:
        row = db.execute("SELECT family_id,revoked FROM authority_tasks WHERE id=?", (manifest["task_id"],)).fetchone()
        if row is None or row[0] != manifest["family_id"]:
            raise RuntimeError("profile_authority_identity_changed")
        labels = [r[0] for r in db.execute("SELECT label FROM authority_labels WHERE family_id=? ORDER BY label", (row[0],))]
        if "private" not in labels:
            raise RuntimeError("profile_private_label_missing")
        result = {"task_id": manifest["task_id"], "active": not bool(row[1]), "revoked": bool(row[1]), "labels": labels}
        if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='quarantine_families'").fetchone():
            paused = db.execute("SELECT state,epoch FROM quarantine_families WHERE family_id=?", (row[0],)).fetchone()
            result.update(paused=bool(paused and paused[0] == "paused"), pause_epoch=paused[1] if paused else 0)
        return result


def _public(profile: Path, manifest: dict):
    return {"profile": str(profile), "task_id": manifest["task_id"], "model": manifest["model"],
            "framework": manifest.get("framework", "openclaw"),
            "documents": manifest["documents"], "destinations": manifest["destinations"],
            "url": f"http://127.0.0.1:{manifest['port']}/", "input_privacy": "private",
            "features": manifest.get("features", [])}


def _process_identity(pid: int):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return fields[19] if fields[0] != "Z" else None
    except (OSError, IndexError):
        return None


def _offline_lifecycle(profile: Path):
    path = profile / "lifecycle.json"
    if not path.exists():
        return "stopped"
    previous = json.loads(path.read_text())
    for kind in ("supervisor", "gateway"):
        pid, start = previous.get(kind + "_pid"), previous.get(kind + "_start")
        if pid and start and _process_identity(pid) == start:
            return "unconfirmed"
    # A crash cannot certify descendant cleanup; do not call it a clean stop.
    return "stopped" if previous.get("cleanup_confirmed") is True else "interrupted"


def init_profile(profile: Path, *, node: Path, openclaw_package: Path, bwrap: Path,
                 model_url: str, model_id: str, api_key: str = "local-unused",
                 documents: dict[str, Path] | None = None, destinations: dict | None = None, reviewed_mail=False,
                 defense_policy: dict | None = None, reviewed_actions=False, action_targets: dict | None = None,
                 judge_config: dict | None = None,
                 selected_skills: dict[str, Path] | None = None,
                 port: int = 18911, context_window: int = 32768, max_tokens: int = 2048) -> dict:
    """Create once. Inputs and policy are snapshots; init never overwrites a profile."""
    _linux()
    if judge_config is not None and defense_policy is None:
        raise ValueError("judge_requires_layered_defense")
    model_url = _model_url(model_url)
    if not isinstance(model_id, str) or not model_id.strip() or any(c in model_id for c in "\x00\r\n"):
        raise ValueError("需要有效的模型名称。")
    if not isinstance(api_key, str) or not api_key or any(c in api_key for c in "\x00\r\n"):
        raise ValueError("invalid_model_api_key")
    if not 1024 <= port <= 65535 or port == 18701 or context_window < 4096 or not 128 <= max_tokens < context_window:
        raise ValueError("invalid_port_or_context_window")
    node, openclaw_package, bwrap = (p.resolve(strict=True) for p in (node, openclaw_package, bwrap))
    for executable in (node, bwrap):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise ValueError("runtime_must_be_executable")
    if json.loads((openclaw_package / "package.json").read_text())["version"] != OPENCLAW_VERSION:
        raise ValueError("本版支持 OpenClaw " + OPENCLAW_VERSION)
    (openclaw_package / "openclaw.mjs").resolve(strict=True)
    readiness = sandbox_available(bwrap=bwrap)
    if not readiness["available"]:
        raise RuntimeError(str(readiness["reason"]))
    imported = {}
    for name, source in (documents or {}).items():
        _name(name)
        source = Path(source).resolve(strict=True)
        if not source.is_file() or source.stat().st_size > MAX_CONTENT:
            raise ValueError("资料须为不超过 256 KiB 的 UTF-8 文本文件。")
        data = source.read_bytes()
        data.decode("utf-8")
        imported[name] = data
    destinations = destinations or {}
    if not isinstance(destinations, dict):
        raise ValueError("destinations_must_be_an_object")
    for name, item in destinations.items():
        _name(name)
        if not isinstance(item, dict) or set(item) not in ({"url", "labels"}, {"url", "labels", "headers"}):
            raise ValueError("destination_requires_url_and_labels")
        if item["labels"] not in ([], ["private"]):
            raise ValueError("destination_labels_must_be_private_or_empty")
    profile = profile.absolute()
    # Never accept an existing directory, even an empty one, or a symlink.
    if profile.exists() or profile.is_symlink():
        raise RuntimeError("此位置已有内容，请使用新的目录；已有实例请用 start。")
    for runtime_path in (node, bwrap, openclaw_package.parent):
        _reject_broad_grant(runtime_path, "OpenClaw runtime")
        if _overlaps(runtime_path, profile.resolve()):
            raise ValueError("runtime_mount_overlaps_private_profile")
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.mkdir(mode=0o700)
    profile = profile.resolve()
    from .skills import create_snapshot
    skill_snapshot = create_snapshot(profile / "skill-store", selected_skills or {})
    empty_snapshot = create_snapshot(profile / "skill-store", {})
    for name in ("documents", "workspace", "trusted-core", "plugin", "openclaw-state", "host-home", "node_modules", "gateway-audit", "runtime-etc"):
        (profile / name).mkdir(mode=0o700)
    (profile / "trusted-core" / "yuanxingmu").mkdir(mode=0o700)
    for source in PACKAGE.glob("*.py"):
        _bytes(profile / "trusted-core" / "yuanxingmu" / source.name, source.read_bytes())
    for source in PLUGIN.iterdir():
        if source.is_file():
            _bytes(profile / "plugin" / source.name, source.read_bytes())
    (profile / "node_modules" / "openclaw").symlink_to(openclaw_package, target_is_directory=True)
    resources = {}
    for name, data in imported.items():
        _bytes(profile / "documents" / (name + ".txt"), data)
        resources[name] = {"path": "documents/" + name + ".txt", "labels": ["private"]}
    _save(profile / "policy.json", {"resources": resources, "destinations": destinations})
    loaded_resources, loaded_destinations = load_policy(profile / "policy.json")
    _bytes(profile / "model-key", api_key.encode())
    from .judge_profile import save_judge_profile
    judge_files = save_judge_profile(profile, judge_config)
    guards = None
    if defense_policy is not None:
        _save(profile / "defense-policy.json", defense_policy)
        from .protection import load_guards
        guards = load_guards(profile, {"url": model_url, "id": model_id})
    targets = None
    if reviewed_actions:
        _save(profile / "action-targets.json", action_targets or {})
        from .protection import load_action_targets
        targets = load_action_targets(profile)
    with Broker(profile / "broker-state", loaded_resources, loaded_destinations,
                reviewed_mail=reviewed_mail, guards=guards, action_targets=targets) as broker:
        task = broker.create_task(initial_labels=["private"])
        broker.bind_workspace(task, profile / "workspace")
        family = broker.authority._db.execute("SELECT family_id FROM authority_tasks WHERE id=?", (task,)).fetchone()[0]
    profile_id = uuid.uuid4().hex
    sockets = Path("/tmp") / ("yxm-" + str(os.getuid()) + "-" + profile_id)
    token = secrets.token_urlsafe(32)
    _bytes(profile / "gateway-token", token.encode())
    for name, value in {
        "passwd": f"yuanxingmu:x:{os.getuid()}:{os.getgid()}:Yuanxingmu:{profile / 'host-home'}:/bin/sh\n",
        "group": f"yuanxingmu:x:{os.getgid()}:\n",
        "nsswitch.conf": "passwd: files\ngroup: files\nhosts: files\n",
        "hosts": "127.0.0.1 localhost\n::1 localhost\n",
    }.items():
        _bytes(profile / "runtime-etc" / name, value.encode())
    config = {
        "update": {"checkOnStart": False},
        "logging": {"file": str(profile / "gateway-audit" / "openclaw.log")},
        "gateway": {"mode": "local", "bind": "loopback", "port": port,
                    "auth": {"mode": "token", "token": "${YUANXINGMU_GATEWAY_TOKEN}"},
                    "controlUi": {"enabled": True, "automaticallyFetchFavicons": False}},
        "agents": {"defaults": {"workspace": str(profile / "workspace"), "skipBootstrap": True,
                    "model": {"primary": "yuanxingmu-model/" + model_id},
                    "sandbox": {"mode": "all", "backend": "yuanxingmu", "scope": "session",
                                "workspaceAccess": "rw", "docker": {"workdir": "/workspace"},
                                "browser": {"enabled": False}}}},
        "models": {"mode": "replace", "catalogRefresh": {"enabled": False}, "providers": {
            "yuanxingmu-model": {"baseUrl": "http://127.0.0.1:18701/v1", "apiKey": "local-bridge-no-key",
                "api": "openai-completions", "models": [{"id": model_id, "name": model_id,
                    "input": ["text"], "reasoning": False, "contextWindow": context_window,
                    "maxTokens": max_tokens,
                    "cost": {"input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0}}]}}},
        "skills": {"allowBundled": [], "load": {"extraDirs": [], "watch": False}},
        "tools": {"allow": TOOLS + (["yuanxingmu_prepare_email"] if reviewed_mail else []) + (["yuanxingmu_action_targets", "yuanxingmu_prepare_action"] if reviewed_actions else []),
                  "sandbox": {"tools": {"allow": TOOLS + (["yuanxingmu_prepare_email"] if reviewed_mail else []) + (["yuanxingmu_action_targets", "yuanxingmu_prepare_action"] if reviewed_actions else [])}}, "fs": {"workspaceOnly": True},
                  "elevated": {"enabled": False}, "codeMode": {"enabled": False},
                  "exec": {"host": "sandbox", "timeoutSeconds": 25}},
        "plugins": {"allow": ["yuanxingmu"], "slots": {"memory": "none"},
                    "load": {"paths": [str(profile / "plugin")]}, "entries": {"yuanxingmu": {
                        "enabled": True, "config": {"python": str(Path(sys.executable).resolve()),
                            "corePath": str(profile / "trusted-core"), "workspace": str(profile / "workspace"),
                            "brokerSocket": str(sockets / "broker.sock"), "operatorSocket": str(sockets / "operator.sock"),
                            "bwrap": str(bwrap), "auditPath": str(profile / "gateway-audit" / "adapter-events.jsonl"),
                            "resourceIds": sorted(resources), "destinationIds": sorted(destinations),
                            "defenseEnabled": defense_policy is not None,
                            "reviewedActions": reviewed_actions is True,
                            "reviewedMail": reviewed_mail is True}}}},
    }
    _save(profile / "openclaw.json", config)
    immutable = [profile / "openclaw.json", profile / "policy.json", profile / "model-key", profile / "gateway-token",
                 profile / "broker-state" / "bindings.json", profile / "broker-state" / "workspaces.json"]
    if defense_policy is not None:
        immutable.append(profile / "defense-policy.json")
    immutable.extend(judge_files)
    if reviewed_actions:
        immutable.append(profile / "action-targets.json")
    for directory in ("documents", "trusted-core", "plugin", "runtime-etc"):
        immutable.extend(p for p in (profile / directory).rglob("*") if p.is_file())
    identities = {name: _identity(profile / name) for name in (
        ".", "workspace", "documents", "trusted-core", "plugin", "host-home", "openclaw-state",
        "broker-state", "broker-state/authority.sqlite3", "gateway-audit", "runtime-etc")}
    manifest = {"version": 2, "framework": "openclaw", "profile": str(profile), "profile_id": profile_id, "task_id": task, "family_id": family,
                "features": (["reviewed_email_v1"] if reviewed_mail else []) + (["layered_defense_v1", "quarantine_v1", "buffered_response_v1", "live_settings_v1"] if defense_policy is not None else []) + (["reviewed_actions_v1"] if reviewed_actions else []),
                "node": str(node), "openclaw_package": str(openclaw_package), "bwrap": str(bwrap), "python": str(Path(sys.executable).resolve()),
                "runtime": str(sockets), "port": port, "model": {"url": model_url, "id": model_id},
                "documents": sorted(resources), "destinations": sorted(destinations),
                "skills_snapshot": skill_snapshot.to_dict(), "skills_empty_snapshot": empty_snapshot.to_dict(),
                "files": {str(p.relative_to(profile)): _hash(p) for p in immutable}, "identities": identities,
                "runtime_files": {str(p): _hash(p) for p in (node, bwrap, openclaw_package / "package.json", openclaw_package / "openclaw.mjs")}}
    if judge_config is not None:
        manifest["features"].append("independent_judge_v1")
    _save(profile / "profile.json", manifest)
    return {"status": "created", **_public(profile, manifest)}


def validate_profile(profile: Path) -> dict:
    _linux()
    profile, manifest = _manifest(profile)
    if "skills_snapshot" in manifest:
        from .skills import verify_snapshot
        for key in ("skills_snapshot", "skills_empty_snapshot"):
            snapshot = manifest[key]
            verified = verify_snapshot(Path(snapshot["path"]), snapshot["digest"])
            if verified.to_dict() != snapshot:
                raise RuntimeError("profile_skill_snapshot_changed")
    for name, expected in manifest["identities"].items():
        if _identity(profile / name) != expected:
            raise RuntimeError("profile_directory_or_ledger_replaced: " + name)
    for name, digest in manifest["files"].items():
        candidate = profile / name
        if candidate.is_symlink() or _hash(candidate) != digest:
            raise RuntimeError("profile_file_changed: " + name)
    for directory in ("documents", "trusted-core", "plugin", "runtime-etc"):
        actual = {str(p.relative_to(profile)) for p in (profile / directory).rglob("*") if p.is_file()}
        expected = {name for name in manifest["files"] if name.startswith(directory + "/")}
        if actual != expected:
            raise RuntimeError("profile_snapshot_contents_changed: " + directory)
    for name, digest in manifest["runtime_files"].items():
        if _hash(Path(name)) != digest:
            raise RuntimeError("profile_runtime_changed")
    if manifest.get("framework", "openclaw") == "hermes":
        from .hermes import validate_binding
        validate_binding(profile, manifest)
    elif (profile / "node_modules" / "openclaw").resolve(strict=True) != Path(manifest["openclaw_package"]):
        raise RuntimeError("profile_openclaw_binding_changed")
    _task_state(profile, manifest)
    return manifest


def _rpc(endpoint: Path, action: str):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(20)
        client.connect(str(endpoint))
        client.sendall(json.dumps({"op": action}).encode() + b"\n")
        line = client.makefile("rb").readline(65537)
        if len(line) > 65536 or not line.endswith(b"\n"):
            raise RuntimeError("invalid_operator_response")
        return json.loads(line)


@contextmanager
def _profile_lock(profile: Path):
    import fcntl
    with (profile / "profile.lock").open("a+b") as lock:
        os.fchmod(lock.fileno(), 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("profile_already_running_or_starting") from None
        yield


def control_profile(profile: Path, action: str) -> dict:
    _linux()
    if action not in ("status", "revoke", "stop"):
        raise ValueError("unknown_operator_action")
    profile, manifest = _manifest(profile)
    try:
        result = _rpc(Path(manifest["runtime"]) / "operator.sock", action)
    except (FileNotFoundError, ConnectionRefusedError):
        # The offline path still validates, then acquires the same supervisor
        # lock; it must not revive missing state or race a gateway being started.
        with _profile_lock(profile):
            manifest = validate_profile(profile)
            state = _offline_lifecycle(profile)
            if state != "stopped" and action == "stop":
                return {"status": state, "operator_action": action, **_public(profile, manifest),
                        "reason": "supervisor_unreachable_cleanup_not_confirmed", "task": _task_state(profile, manifest)}
            if action == "revoke":
                resources, destinations = load_policy(profile / "policy.json")
                from .protection import profile_services
                with Broker(profile / "broker-state", resources, destinations, **profile_services(profile, manifest)) as broker:
                    broker.revoke(manifest["task_id"])
            return {"status": state, "operator_action": action, **_public(profile, manifest),
                    "task": _task_state(profile, manifest)}
    if action == "stop" and result.get("status") == "stopping":
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            lifecycle = json.loads((profile / "lifecycle.json").read_text())
            if lifecycle.get("status") in ("stopped", "failed"):
                return {**result, "status": lifecycle["status"]}
            time.sleep(.1)
        raise RuntimeError("stop_not_confirmed; inspect lifecycle.json")
    return result


def review_profile(profile: Path, action: str, value: dict | None = None) -> dict:
    """Use only the unmounted host review endpoint; never the agent operator socket."""
    _linux()
    profile, manifest = _manifest(profile)
    is_action = action.startswith("action_")
    is_tool = action.startswith("tool_")
    is_quarantine = action.startswith("quarantine_")
    is_protection = action.startswith("protection_")
    feature = "layered_defense_v1" if is_tool or is_quarantine or is_protection else "reviewed_actions_v1" if is_action else "reviewed_email_v1"
    if feature not in manifest.get("features", []):
        raise AuthorizationError("reviewed_actions_not_enabled" if is_action else "reviewed_mail_not_enabled")
    if action not in {"list", "get", "edit", "cancel", "send", "action_list", "action_get", "action_edit", "action_cancel", "action_commit", "tool_list", "tool_get", "tool_approve", "tool_deny", "quarantine_status", "quarantine_resume", "protection_set"} or (value is not None and (not isinstance(value, dict) or "op" in value)):
        raise AuthorizationError("invalid_mail_review")
    request = {"op": action, **(value or {})}
    payload = json.dumps(request, ensure_ascii=True).encode() + b"\n"
    if len(payload) > MAX_MESSAGE:
        raise AuthorizationError("invalid_mail_review")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(120)
            connection.connect(str(Path(manifest["runtime"]) / "review.sock"))
            connection.sendall(payload)
            with connection.makefile("rb") as stream:
                raw = stream.readline(MAX_MESSAGE + 1)
        if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
            raise RuntimeError("mail_review_response_unconfirmed")
        result = json.loads(raw)
        if not isinstance(result, dict) or result.get("ok") is not True:
            raise AuthorizationError(result.get("reason", "mail_review_failed") if isinstance(result, dict) else "mail_review_failed")
        return result
    except (FileNotFoundError, ConnectionRefusedError):
        # Missing service alone is insufficient. The supervisor lock and original
        # profile validation are also required, and live failures never retry here.
        with _profile_lock(profile):
            manifest = validate_profile(profile)
            if action not in {"list", "get", "action_list", "action_get", "tool_list", "tool_get", "quarantine_status"} and _offline_lifecycle(profile) != "stopped":
                raise AuthorizationError("mail_profile_state_unconfirmed")
            resources, destinations = load_policy(profile / "policy.json")
            from .protection import profile_services
            with Broker(profile / "broker-state", resources, destinations, **profile_services(profile, manifest)) as broker:
                return {"ok": True, **broker.review_mail(manifest["task_id"], request)}


def _environment(profile: Path, manifest: dict):
    if manifest.get("framework", "openclaw") == "hermes":
        from .hermes import environment
        return environment(profile, manifest)
    # Do not inherit provider credentials, HOME, OPENCLAW_* overrides or proxies.
    return {"PATH": str(Path(manifest["node"]).parent) + ":/usr/bin:/bin", "HOME": str(profile / "host-home"),
            "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
            "OPENCLAW_STATE_DIR": str(profile / "openclaw-state"),
            "OPENCLAW_CONFIG_PATH": str(profile / "openclaw.json"),
            "OPENCLAW_SKIP_CHANNELS": "1", "OPENCLAW_SKIP_GMAIL_WATCHER": "1", "OPENCLAW_SKIP_CRON": "1",
            "OPENCLAW_SKIP_BROWSER_CONTROL_SERVER": "1", "OPENCLAW_SKIP_CANVAS_HOST": "1", "OPENCLAW_DISABLE_BONJOUR": "1",
            "YUANXINGMU_GATEWAY_TOKEN": (profile / "gateway-token").read_text()}


def gateway_command(profile: Path, manifest: dict) -> list[str]:
    """A second isolation boundary covers framework actions outside its tools.

    The gateway sees neither model credentials nor the authority database. Its
    network namespace has only loopback bridges. Worker namespaces remain
    available; the inner worker applies --disable-userns itself.
    """
    if manifest.get("framework", "openclaw") == "hermes":
        from .hermes import gateway_command as hermes_command
        return hermes_command(profile, manifest)
    from .gateway_network import INNER_BOOTSTRAP
    runtime = Path(manifest["runtime"])
    args = [manifest["bwrap"], "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc",
            "--unshare-uts", "--hostname", "yuanxingmu-gateway", "--cap-drop", "ALL",
            "--new-session", "--die-with-parent", "--as-pid-1", *_system_mount_args(),
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    # Explicit runtime grants; do not expose a user's home, profile parent or /etc.
    external = [Path(manifest["node"]), Path(manifest["openclaw_package"]).parent, Path(manifest["bwrap"])]
    for path in external:
        _reject_broad_grant(path, "OpenClaw runtime")
        if _overlaps(path, profile):
            raise ValueError("runtime_mount_overlaps_private_profile")
    readonly = [*external,
                profile / "trusted-core", profile / "plugin",
                profile / "node_modules", profile / "openclaw.json"]
    python = Path(manifest["python"])
    if not python.is_relative_to(Path("/usr")):
        raise RuntimeError("Gateway isolation currently requires a system Python under /usr.")
    for path in readonly:
        args += ["--ro-bind", str(path), str(path)]
    for name in ("passwd", "group", "nsswitch.conf", "hosts"):
        args += ["--ro-bind", str(profile / "runtime-etc" / name), "/etc/" + name]
    for name in ("openclaw-state", "host-home", "workspace", "gateway-audit"):
        path = profile / name
        args += ["--bind", str(path), str(path)]
    if "skills_snapshot" in manifest:
        selected = manifest["skills_snapshot"]["tree_path"]
        empty = manifest["skills_empty_snapshot"]["tree_path"]
        args += ["--ro-bind", selected, str(profile / "workspace" / "skills")]
        for target in (profile / "workspace" / ".agents" / "skills", profile / "openclaw-state" / "skills",
                       profile / "host-home" / ".agents" / "skills"):
            args += ["--ro-bind", empty, str(target)]
        for name in ("skills", "custodian-skills"):
            target = Path(manifest["openclaw_package"]) / name
            if target.is_dir():
                args += ["--ro-bind", empty, str(target)]
    for name in ("model.sock", "broker.sock", "operator.sock"):
        path = runtime / name
        args += ["--ro-bind", str(path), str(path)]
    args += ["--bind", str(runtime / "webui"), str(runtime / "webui")]
    args += ["--chdir", str(profile / "host-home"), "--remount-ro", "/", "--",
             str(python), "-I", "-B", "-c", INNER_BOOTSTRAP, str(profile / "trusted-core"),
             "--runtime", str(runtime), "--webui-port", str(manifest["port"]), "--",
             manifest["node"], str(Path(manifest["openclaw_package"]) / "openclaw.mjs"), "gateway", "run"]
    return args


def _descendants():
    """PID + start time guards against reuse while shutting down our own tree."""
    processes = {}
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            raw = path.read_text()
            fields = raw[raw.rfind(")") + 2:].split()
            processes[int(path.parent.name)] = (int(fields[1]), fields[19])
        except (OSError, ValueError, IndexError):
            pass
    parents = {os.getpid()}
    children = {}
    while True:
        added = {pid for pid, (parent, start) in processes.items() if parent in parents and pid not in parents}
        if not added:
            return children
        children.update({pid: processes[pid][1] for pid in added})
        parents.update(added)


def _shutdown_children(gateway):
    # Gateway/worker launchers may create separate process groups. Subreaping
    # and descendant enumeration cover those groups as well as native cleanup.
    for sig, seconds in ((signal.SIGTERM, 5), (signal.SIGKILL, 3)):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            children = _descendants()
            if not children:
                break
            for pid, started in children.items():
                try:
                    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
                    if fields[19] == started and fields[0] != "Z":
                        os.kill(pid, sig)
                except (OSError, IndexError):
                    pass
            if gateway is not None:
                gateway.poll()
            while True:
                try:
                    if os.waitpid(-1, os.WNOHANG)[0] == 0:
                        break
                except ChildProcessError:
                    break
            time.sleep(.05)
    if _descendants():
        raise RuntimeError("worker_shutdown_not_confirmed")


def serve_profile(profile: Path):
    """Internal supervisor; clients use start_profile or the CLI."""
    _linux()
    profile, manifest = _manifest(profile)
    with _profile_lock(profile):
        manifest = validate_profile(profile)
        framework = manifest.get("framework", "openclaw")
        display = "Hermes" if framework == "hermes" else "OpenClaw"
        if not _task_state(profile, manifest)["active"]:
            raise AuthorizationError("task_revoked")
        ready = sandbox_available(bwrap=Path(manifest["bwrap"]))
        if not ready["available"]:
            raise RuntimeError(str(ready["reason"]))
        import ctypes
        # PR_SET_CHILD_SUBREAPER makes orphaned worker launchers ours to stop.
        if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
            raise RuntimeError("cannot_supervise_worker_processes")
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_: stop.set())
        runtime = Path(manifest["runtime"])
        runtime.mkdir(mode=0o700, exist_ok=True)
        mode = runtime.stat(follow_symlinks=False)
        if not stat.S_ISDIR(mode.st_mode) or mode.st_uid != os.getuid() or mode.st_mode & 0o077:
            raise RuntimeError("unsafe_runtime_directory")
        for name in ("broker.sock", "operator.sock", "review.sock"):
            path = runtime / name
            if path.exists() or path.is_symlink():
                if not stat.S_ISSOCK(path.lstat().st_mode):
                    raise RuntimeError("unexpected_runtime_file")
                path.unlink()
        lifecycle = {"status": "starting", "supervisor_pid": os.getpid(),
                     "supervisor_start": _process_identity(os.getpid()), "task_id": manifest["task_id"]}
        _save(profile / "lifecycle.json", lifecycle)
        gateway, server, thread, network = None, None, None, None
        resources, destinations = load_policy(profile / "policy.json")
        try:
            from .protection import profile_services, foundation_config
            with Broker(profile / "broker-state", resources, destinations, **profile_services(profile, manifest)) as broker:
                from .protection import apply_profile_settings
                broker.configure_callback = lambda settings: apply_profile_settings(profile, manifest, broker, settings)
                if broker.guards is not None:
                    snapshot = manifest.get("skills_snapshot")
                    roots = [Path(value) for value in snapshot["scan_paths"]] if snapshot else []
                    if snapshot and not roots:
                        roots = [Path(snapshot["tree_path"])]
                    report = broker.guards.scan_foundation(foundation_config(profile, manifest), roots)
                    _save(profile / "foundation-report.json", {**report.to_dict(), "policy_sha256": manifest["files"]["defense-policy.json"]})
                    if not report.allowed:
                        raise RuntimeError("启动检查未通过；请查看 foundation-report.json。")
                broker.serve(manifest["task_id"], runtime / "broker.sock")
                if {"reviewed_email_v1", "reviewed_actions_v1", "layered_defense_v1"}.intersection(manifest.get("features", [])):
                    # gateway_command mounts three individual sockets, never this
                    # endpoint or its parent. Worker tools cannot approve a draft.
                    broker.serve_reviews(manifest["task_id"], runtime / "review.sock")

                class Handler(socketserver.StreamRequestHandler):
                    def handle(self):
                        self.connection.settimeout(20)
                        try:
                            raw = self.rfile.readline(101)
                            request = json.loads(raw) if len(raw) <= 100 and raw.endswith(b"\n") else None
                            if not isinstance(request, dict) or set(request) != {"op"} or request["op"] not in ("status", "revoke", "stop"):
                                raise ValueError("fixed_operator_action_required")
                            action = request["op"]
                            if action == "revoke":
                                broker.revoke(manifest["task_id"])
                            task = broker.authority.describe(manifest["task_id"])
                            result = {"status": "stopping" if action == "stop" else lifecycle["status"],
                                      "operator_action": action, "task": task, **_public(profile, manifest)}
                            self.wfile.write(json.dumps(result).encode() + b"\n")
                            self.wfile.flush()
                            if action == "stop":
                                stop.set()
                        except (OSError, ValueError, RuntimeError) as exc:
                            self.wfile.write(json.dumps({"status": "error", "reason": type(exc).__name__}).encode() + b"\n")

                server = socketserver.ThreadingUnixStreamServer(str(runtime / "operator.sock"), Handler)
                server.daemon_threads = True
                (runtime / "operator.sock").chmod(0o600)
                thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
                thread.start()
                from .gateway_network import HostNetwork
                from .model_output import ModelOutputGuard
                network = HostNetwork(runtime, model_url=manifest["model"]["url"],
                                      api_key=(profile / "model-key").read_text(), webui_port=manifest["port"],
                                      output_guard=ModelOutputGuard(broker, manifest["task_id"]) if broker.guards is not None else None)
                network.__enter__()
                with (profile / "gateway.stdout.log").open("ab") as out, (profile / "gateway.stderr.log").open("ab") as err:
                    os.fchmod(out.fileno(), 0o600)
                    os.fchmod(err.fileno(), 0o600)
                    parent_guard = ("import ctypes,os,signal,sys; parent=int(sys.argv.pop(1)); "
                                    "sys.exit(1) if os.getppid()!=parent else None; "
                                    "result=ctypes.CDLL(None).prctl(1,signal.SIGTERM,0,0,0); "
                                    "sys.exit(1) if result or os.getppid()!=parent else None; "
                                    "os.execv(sys.argv[1],sys.argv[1:])")
                    gateway = subprocess.Popen([sys.executable, "-I", "-B", "-c", parent_guard, str(os.getpid()),
                                                *gateway_command(profile, manifest)], cwd=profile / "host-home",
                        env=_environment(profile, manifest), stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                        close_fds=True, start_new_session=True)
                lifecycle.update(gateway_pid=gateway.pid, gateway_start=_process_identity(gateway.pid))
                _save(profile / "lifecycle.json", lifecycle)
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline:
                    if gateway.poll() is not None:
                        raise RuntimeError(display + " 启动失败；请查看 gateway.stderr.log。")
                    if stop.wait(.2):
                        raise RuntimeError("stopped_while_starting")
                    if framework == "hermes":
                        from .hermes import check_ready
                        healthy = check_ready(profile, manifest)
                        if healthy.get("ok") is True:
                            break
                        continue
                    connection = http.client.HTTPConnection("127.0.0.1", manifest["port"], timeout=1)
                    try:
                        connection.request("GET", "/")
                        response = connection.getresponse()
                        body = response.read(1024 * 1024)
                        if response.status == 200 and b"openclaw" in body.lower():
                            break
                    except OSError:
                        continue
                    finally:
                        connection.close()
                else:
                    raise RuntimeError(display + " 启动超时；请查看 gateway.stderr.log。")
                if framework == "openclaw":
                    health = subprocess.run([manifest["node"], str(Path(manifest["openclaw_package"]) / "openclaw.mjs"),
                                         "health", "--json", "--timeout", "3000"], env=_environment(profile, manifest),
                                        cwd=profile / "host-home", capture_output=True, text=True, timeout=20)
                    try:
                        healthy = json.loads(health.stdout) if health.returncode == 0 else {}
                    except ValueError:
                        healthy = {}
                if (healthy.get("ok") is not True or gateway.poll() is not None
                        or _process_identity(gateway.pid) != lifecycle["gateway_start"]):
                    raise RuntimeError(display + " 身份与健康检查未通过；请检查端口是否被其他实例占用。")
                # An unrelated OpenClaw page cannot pass a handshake with our
                # randomly generated token. Non-JSON output is not a success.
                _save(profile / "gateway-health.json", {"authenticated": True, "gateway_pid": gateway.pid})
                lifecycle.update(status="ready", gateway_pid=gateway.pid)
                _save(profile / "lifecycle.json", lifecycle)
                while not stop.wait(.2):
                    if gateway.poll() is not None:
                        raise RuntimeError(display + " 意外退出；请查看 gateway.stderr.log。")
                _shutdown_children(gateway)
        except BaseException as exc:
            lifecycle.update(status="failed", reason=str(exc))
            raise
        finally:
            try:
                _shutdown_children(gateway)
                lifecycle["cleanup_confirmed"] = True
            except RuntimeError as exc:
                lifecycle.update(status="failed", reason=str(exc), cleanup_confirmed=False)
            if server is not None:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)
            if network is not None:
                network.__exit__(None, None, None)
            (runtime / "operator.sock").unlink(missing_ok=True)
            if lifecycle["status"] != "failed":
                lifecycle["status"] = "stopped"
            _save(profile / "lifecycle.json", lifecycle)


def _dashboard_url(profile: Path, manifest: dict):
    if manifest.get("framework", "openclaw") == "hermes":
        from .hermes import dashboard_url
        return dashboard_url(profile, manifest)
    return f"http://127.0.0.1:{manifest['port']}/#token=" + (profile / "gateway-token").read_text()


def start_profile(profile: Path) -> dict:
    manifest = validate_profile(profile)
    profile = Path(manifest["profile"])
    if not _task_state(profile, manifest)["active"]:
        raise AuthorizationError("task_revoked")
    try:
        running = _rpc(Path(manifest["runtime"]) / "operator.sock", "status")
        if running.get("status") == "ready":
            return {**running, "dashboard_url": _dashboard_url(profile, manifest)}
        raise RuntimeError("profile_already_running_or_starting")
    except (FileNotFoundError, ConnectionRefusedError):
        pass
    if _offline_lifecycle(profile) != "stopped":
        raise RuntimeError("上一次服务异常中断，尚未确认清理完成；请检查 lifecycle.json 和记录的进程。")
    # Explicit -I bootstrap prevents cwd/PYTHONPATH injection into the supervisor.
    bootstrap = "import sys; sys.path.insert(0, sys.argv.pop(1)); from yuanxingmu.openclaw import serve_profile; from pathlib import Path; serve_profile(Path(sys.argv[1]))"
    with (profile / "supervisor.log").open("ab") as log:
        os.fchmod(log.fileno(), 0o600)
        process = subprocess.Popen([sys.executable, "-I", "-B", "-c", bootstrap, str(profile / "trusted-core"), str(profile)],
            cwd=profile / "host-home", env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            stdin=subprocess.DEVNULL, stdout=log, stderr=log, close_fds=True, start_new_session=True)
    deadline = time.monotonic() + (140 + 35 * manifest.get("skills_snapshot", {}).get("file_count", 0) if "layered_defense_v1" in manifest.get("features", []) else 100)
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("启动失败；请查看实例目录中的 supervisor.log。")
        try:
            ready = _rpc(Path(manifest["runtime"]) / "operator.sock", "status")
            if ready.get("status") == "ready":
                return {**ready, "dashboard_url": _dashboard_url(profile, manifest)}
        except (FileNotFoundError, ConnectionRefusedError):
            pass
        time.sleep(.2)
    # A timeout must not leave a gateway whose existence was not reported.
    process.terminate()
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        raise RuntimeError("启动未确认，清理也未确认；请检查 supervisor.log。") from None
    raise RuntimeError("聊天服务启动超时。")
