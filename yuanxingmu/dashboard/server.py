"""Single-user loopback UI over the existing persistent OpenClaw authority.

The browser cannot supply paths, commands, ports, or policy. Jobs are durable
receipts, not instructions replayed after a restart. Credentials stay on the host.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
import uuid
import webbrowser

from .. import openclaw as core
from ..gateway_network import _upstream
from ..mail_transport import MailAccount, validate_draft

LIMITS = {"documents": 8, "document_bytes": 262144, "total_document_bytes": 1048576}
# JSON may escape every content character as six bytes.
MAX_BODY = 7 * 1048576
MAX_PROFILES = 128
MAX_JOBS = 4096
HEX_ID = re.compile(r"[0-9a-f]{32}\Z")
STATUSES = {"stopped", "starting", "ready", "stopping", "interrupted", "unconfirmed", "failed"}
WEB = Path(__file__).parent / "web"


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class APIError(RuntimeError):
    def __init__(self, status: int, code: str, message: str):
        self.status, self.code, self.message = status, code, message
        super().__init__(message)

    def public(self):
        return {"code": self.code, "message": self.message}


def _fault(exc: Exception):
    if isinstance(exc, APIError):
        return exc.public()
    # Never return exception text: upstream errors can contain keys or documents.
    reason = getattr(exc, "reason", str(exc))
    mail_errors = {
        "mail_draft_changed": "这封草稿已经改变，请重新打开并核对最新内容。",
        "mail_draft_not_pending": "这封草稿已经取消或开始发送，不能再修改或重新发送。",
        "mail_account_changed": "发件邮箱已改变，请重新核对发件地址后再确认。",
        "mail_account_missing": "请先设置这台电脑使用的发件邮箱。",
        "reviewed_mail_not_enabled": "这项旧工作没有邮件核对功能，请保留原工作并建立新工作。",
        "task_paused": "这份工作已暂停，请查看最新防护记录并由你确认恢复。",
        "protected_value_blocked": "发现已登记的敏感字段，内容已扣留。请在防护记录查看暂停原因。",
        "protected_check_failed": "无法完整检查敏感字段，内容已扣留。请在防护记录查看原因。",
        "defense_storage_fault": "防护状态写入失败，后续操作已停止。请保留记录、检查存储并重启服务。",
        "quarantine_incident_changed": "暂停原因已更新，请重新读取并核对，旧确认没有恢复工作。",
        "defense_baseline_unavailable": "这份旧工作没有保存创建时设置，不能恢复。当前设置未改变。",
        "defense_settings_preview_expired": "当前设置已变化，请刷新并重新核对。本次没有修改设置。",
        "defense_settings_preview_required": "请刷新防护记录，再核对并保存最新设置。本次没有修改设置。",
        "defense_baseline_preview_changed": "创建时设置的预览不匹配，请刷新后重新核对。本次没有修改设置。",
        "defense_reset_preview_changed": "恢复全部开启的预览已改动，请按普通修改保存。本次没有修改设置。",
        "profile_requires_skill_rules_support": "这份旧工作不支持独立技能规则开关。请保留原工作并新建工作；本次没有修改设置。",
    }
    if reason in mail_errors:
        return {"code": reason, "message": mail_errors[reason]}
    if "task_revoked" in reason:
        return {"code": "task_revoked", "message": "这项工作的权限已永久收回，不能重新开启。"}
    if "profile_already_running_or_starting" in reason:
        return {"code": "profile_busy", "message": "这项工作正在启动或被其他操作占用，请稍后刷新。"}
    if any(part in reason for part in ("changed", "replaced", "symlink", "missing", "identity")):
        return {"code": "state_changed", "message": "保存的配置或权限记录发生变化。已停止本次操作，请保留目录并检查。"}
    return {"code": "operation_failed", "message": "操作未完成。请查看本机实例日志；不要把此状态当作已经关闭或获得保护。"}


def _identity(path: Path, *, directory: bool):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise APIError(409, "unsafe_storage", "工作台目录必须属于当前用户，且仅当前用户可访问。")
    return [info.st_dev, info.st_ino]


@dataclass(frozen=True)
class Runtime:
    node: Path | None
    openclaw_package: Path | None
    bwrap: Path | None
    hermes_python: Path | None = None
    hermes_source: Path | None = None

    @classmethod
    def discover(cls, install_root: Path, *, node=None, openclaw_package=None, bwrap=None,
                 hermes_python=None, hermes_source=None):
        def choose(explicit, preferred, fallback=None, *, keep_leaf=False):
            value = explicit or (preferred if preferred and preferred.exists() else fallback)
            if not value:
                return None
            path = Path(value).expanduser()
            return path.parent.resolve() / path.name if keep_leaf else path.resolve()
        return cls(
            choose(node, install_root / "tools/node-v24.16.0-linux-x64/bin/node", shutil.which("node")),
            choose(openclaw_package, install_root / "openclaw/node_modules/openclaw"),
            choose(bwrap, None, shutil.which("bwrap")),
            choose(hermes_python, install_root / "hermes/env/bin/python", keep_leaf=True),
            choose(hermes_source, install_root / "hermes/source"),
        )

    def public(self):
        message = "请先按安装说明准备 Node.js、OpenClaw 2026.9.4 和可用的 Linux 隔离环境。"
        try:
            if not sys.platform.startswith("linux"):
                raise ValueError("linux_required")
            if not Path(sys.executable).resolve().is_relative_to("/usr"):
                message = "请使用系统 Python 3.12 或更新版本建立虚拟环境，再打开工作台。"
                raise ValueError("system_python_required")
            for executable in (self.node, self.bwrap):
                if not executable or not executable.is_file() or not os.access(executable, os.X_OK):
                    raise ValueError("missing_runtime")
            if not self.openclaw_package:
                raise ValueError("missing_package")
            package = json.loads((self.openclaw_package / "package.json").read_text())
            if package.get("version") != core.OPENCLAW_VERSION or not (self.openclaw_package / "openclaw.mjs").is_file():
                raise ValueError("wrong_package")
            version = subprocess.run([str(self.node), "--version"], capture_output=True, timeout=10, check=True).stdout.decode().strip()
            if not re.fullmatch(r"v(?:2[4-9]|[3-9][0-9])\.\d+\.\d+", version):
                raise ValueError("node_version")
            if not core.sandbox_available(bwrap=self.bwrap)["available"]:
                raise ValueError("isolation_unavailable")
        except Exception:
            return {"available": False, "openclaw": core.OPENCLAW_VERSION, "reason": message}
        return {"available": True, "openclaw": core.OPENCLAW_VERSION, "reason": None}

    def hermes_public(self):
        if not self.hermes_python or not self.hermes_source:
            return {"available": False, "reason": "本机尚未安装支持的 Hermes 网页运行环境。"}
        from ..hermes import runtime_available
        return runtime_available(node=self.node, hermes_python=self.hermes_python,
                                 hermes_source=self.hermes_source, bwrap=self.bwrap)


def validate_create(value):
    required = {"name", "model_url", "model_id", "api_key", "documents"}
    if not isinstance(value, dict) or not required <= set(value) or set(value) - required - {"framework", "objective", "defense", "skills", "judge", "action_automation", "action_automation_bindings"}:
        raise APIError(400, "invalid_fields", "请填写工作名称、模型连接信息和资料。")
    if not isinstance(value.get("framework", "openclaw"), str) or value.get("framework", "openclaw") not in {"openclaw", "hermes"}:
        raise APIError(400, "invalid_framework", "请选择 OpenClaw 或 Hermes。")
    if "objective" in value and (not isinstance(value["objective"], str) or not value["objective"].strip()
                                  or len(value["objective"].encode("utf-8")) > 8192 or "\x00" in value["objective"]):
        raise APIError(400, "invalid_objective", "请写明这份工作要完成什么，以及不能做什么；最多 8 KB。")
    if "defense" in value:
        from ..guards import validate_defense_settings
        try:
            if not value.get("objective"):
                raise ValueError
            validate_defense_settings(value["defense"])
        except (ValueError, TypeError):
            raise APIError(400, "invalid_defense_settings", "防护设置无效。") from None
    if "judge" in value:
        from ..judge_profile import normalize_judge_config
        try:
            if not value.get("objective"):
                raise ValueError("judge_requires_layered_defense")
            normalize_judge_config(value["judge"])
        except (ValueError, TypeError):
            raise APIError(400, "invalid_judge_config", "请填写独立检查模型的地址、名称及有效密钥；检查等待最多45秒。") from None
    automatic_fields = {"action_automation", "action_automation_bindings"}
    if automatic_fields & set(value):
        scope, bindings = value.get("action_automation"), value.get("action_automation_bindings")
        if (not automatic_fields <= set(value) or not value.get("objective")
                or type(scope) is not dict or type(scope.get("targets")) is not dict
                or type(bindings) is not dict or not 1 <= len(bindings) <= 32
                or set(bindings) != set(scope["targets"])
                or any(type(key) is not str or type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest)
                       for key, digest in bindings.items())):
            raise APIError(400, "invalid_automatic_action_scope", "请重新选择本次工作可自动执行的对象，并填写工作目的。")
    if "skills" in value and (type(value["skills"]) is not list or len(value["skills"]) > 32
            or any(type(item) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", item) for item in value["skills"])
            or len(set(value["skills"])) != len(value["skills"])):
        raise APIError(400, "invalid_skills", "请选择已在本机登记的技能。")
    for field, maximum in (("name", 80), ("model_url", 2048), ("model_id", 256), ("api_key", 8192)):
        item = value[field]
        if not isinstance(item, str) or len(item) > maximum or any(ord(c) < 32 or ord(c) == 127 for c in item):
            raise APIError(400, "invalid_field", "填写内容过长或含有不支持的字符。")
        try:
            item.encode("utf-8")
        except UnicodeError:
            raise APIError(400, "invalid_utf8", "请使用有效的 UTF-8 文本。") from None
        if field != "api_key" and not item.strip():
            raise APIError(400, "missing_field", "请填写工作名称、模型地址和模型名称。")
    try:
        model_url = core._model_url(value["model_url"])
        _upstream(model_url)
        parsed = urlsplit(model_url)
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError()
        if "\\" in model_url or any(c.isspace() for c in model_url):
            raise ValueError()
    except ValueError:
        raise APIError(400, "invalid_model_url", "云端模型请用 HTTPS 地址；本机模型可用 http://127.0.0.1，地址不能含密码或查询参数。") from None
    if parsed.scheme == "https" and not value["api_key"].strip():
        raise APIError(400, "missing_api_key", "请填写云端模型服务提供的 API 密钥。")
    if any(ord(c) < 33 or ord(c) > 126 for c in value["api_key"]):
        raise APIError(400, "invalid_api_key", "模型密钥不能包含空格、换行或中文，请核对后重新填写。")
    documents = value["documents"]
    if not isinstance(documents, list) or len(documents) > LIMITS["documents"]:
        raise APIError(400, "too_many_documents", "每项工作最多导入 8 份文本。")
    names, total = set(), 0
    for document in documents:
        if not isinstance(document, dict) or set(document) != {"name", "filename", "content"}:
            raise APIError(400, "invalid_document", "资料需要名称、文件名和 UTF-8 文本内容。")
        try:
            core._name(document["name"])
        except ValueError:
            raise APIError(400, "invalid_resource_name", "资料名称请用 1–64 位字母、数字、下划线或连字符。") from None
        if document["name"] in names:
            raise APIError(400, "duplicate_resource", "每份资料请使用不同的名称。")
        names.add(document["name"])
        filename = document["filename"]
        if not isinstance(filename, str) or not 1 <= len(filename) <= 200 or any(ord(c) < 32 or c in "/\\" for c in filename):
            raise APIError(400, "invalid_filename", "请使用普通文件名，不要填写文件路径。")
        try:
            filename.encode("utf-8")
            if not isinstance(document["content"], str):
                raise ValueError()
            size = len(document["content"].encode("utf-8"))
        except (ValueError, UnicodeError):
            raise APIError(400, "invalid_utf8", "资料必须是有效的 UTF-8 文本。") from None
        total += size
        if size > LIMITS["document_bytes"] or total > LIMITS["total_document_bytes"]:
            raise APIError(413, "documents_too_large", "每份文本最多 256 KiB，合计最多 1 MiB。")
    return {**copy.deepcopy(value), "name": value["name"].strip(), "model_url": model_url,
            "api_key": value["api_key"] or "local-unused"}


class Workbench:
    def __init__(self, root: Path, runtime: Runtime, *, port: int = 18910, action_targets: dict | None = None, skill_sources: dict | None = None):
        core._linux()
        self.root = root.expanduser().absolute()
        self.runtime = runtime
        self.skill_sources = {core._name(name): Path(path).expanduser().absolute() for name, path in (skill_sources or {}).items()}
        from ..actions import ActionTarget
        if action_targets is not None and (not isinstance(action_targets, dict) or len(action_targets) > 32):
            raise ValueError("invalid_action_targets")
        self.action_targets = {core._name(name): ActionTarget(**value).to_config()
                               for name, value in (action_targets or {}).items()}
        self.port = port
        self.token = secrets.token_urlsafe(32)
        self.mutex = threading.RLock()
        self.pending = {}
        self.core_locks = {}
        self.observations = {}
        self.workers = set()
        self.closing = False
        self.write_failed = False
        self._lock_file = None
        self.alerts = None
        self.runtime_status = runtime.public()
        self.hermes_status = runtime.hermes_public()
        fresh = not self.root.exists() and not self.root.is_symlink()
        if fresh:
            self.root.mkdir(mode=0o700, parents=True)
        root_identity = _identity(self.root, directory=True)
        # Resolve only after rejecting an alias at the chosen storage root.
        self.root = self.root.resolve(strict=True)
        import fcntl
        lock_path = self.root / "manager.lock"
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            self._lock_file = os.fdopen(descriptor, "r+b")
            self._lock_identity = _identity(lock_path, directory=False)
            fcntl.flock(self._lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.catalog_path = self.root / "catalog.json"
            if fresh:
                (self.root / "profiles").mkdir(mode=0o700)
                (self.root / "imports").mkdir(mode=0o700)
                self.catalog = {"version": 1, "root_identity": root_identity,
                    "profiles_identity": _identity(self.root / "profiles", directory=True),
                    "imports_identity": _identity(self.root / "imports", directory=True),
                    "fingerprint_key": secrets.token_hex(32), "profiles": {}, "jobs": {}, "requests": {}}
                self._catalog_identity = None
                self._catalog_digest = None
                self._save()
            else:
                self._catalog_identity = _identity(self.catalog_path, directory=False)
                raw = self.catalog_path.read_bytes()
                self._catalog_digest = hashlib.sha256(raw).hexdigest()
                self.catalog = json.loads(raw)
                self._validate_catalog()
                self._check_storage()
            self.jobs = copy.deepcopy(self.catalog["jobs"])
            if "action_targets" in self.catalog:
                self.action_targets = {core._name(name): ActionTarget(**value).to_config()
                                       for name, value in self.catalog["action_targets"].items()}
            else:
                self.catalog["action_targets"] = copy.deepcopy(self.action_targets)
            if self.port and self.port in {entry["port"] for entry in self.catalog["profiles"].values()}:
                raise APIError(409, "manager_port_conflict", "工作台端口与已有聊天端口重复，请使用其他工作台端口。")
            for job in self.jobs.values():
                if job["status"] == "running":
                    job.update(status="failed", finished_at=_now(), error={"code": "manager_interrupted",
                        "message": "工作台曾中断，未重试这次操作。请刷新查看实际状态。"})
            for entry in self.catalog["profiles"].values():
                if entry["phase"] == "creating":
                    entry["phase"] = "creation_failed"
            self._save_jobs()
            from .alerts import HostAlerts
            self.alerts = HostAlerts(self)
        except Exception:
            if self._lock_file:
                self._lock_file.close()
            raise

    def _validate_catalog(self):
        catalog = self.catalog
        if catalog.get("version") != 1 or not re.fullmatch(r"[0-9a-f]{64}", catalog.get("fingerprint_key", "")):
            raise APIError(409, "catalog_changed", "工作台记录无效，不能继续。请保留原目录。")
        for identity in ("root_identity", "profiles_identity", "imports_identity"):
            if not isinstance(catalog.get(identity), list) or len(catalog[identity]) != 2:
                raise ValueError("catalog_identity_changed")
        for collection in ("profiles", "jobs", "requests"):
            if not isinstance(catalog.get(collection), dict):
                raise ValueError("catalog_changed")
        for identifier, entry in catalog["profiles"].items():
            if not HEX_ID.fullmatch(identifier) or entry.get("id") != identifier or entry.get("phase") not in {"creating", "created", "creation_failed"}:
                raise ValueError("profile_identity_changed")
            if not isinstance(entry.get("port"), int) or not 1024 <= entry["port"] <= 65535:
                raise ValueError("profile_port_changed")
        if "mail_account" in catalog:
            account = catalog["mail_account"]
            if not isinstance(account, dict) or set(account) != {"id", "config"} or not isinstance(account["id"], str) or not HEX_ID.fullmatch(account["id"]):
                raise ValueError("mail_account_changed")
            MailAccount(**account["config"])
        if not isinstance(catalog.get("mail_account_requests", {}), dict):
            raise ValueError("mail_account_changed")
        if not isinstance(catalog.get("action_targets", {}), dict) or len(catalog.get("action_targets", {})) > 32:
            raise ValueError("action_targets_changed")
        if "notifications" in catalog:
            from .alerts import validate_catalog
            validate_catalog(catalog["notifications"])

    def _check_storage(self):
        for path, expected, directory in (
            (self.root, self.catalog["root_identity"], True),
            (self.root / "profiles", self.catalog["profiles_identity"], True),
            (self.root / "imports", self.catalog["imports_identity"], True),
            (self.root / "manager.lock", self._lock_identity, False),
        ):
            if _identity(path, directory=directory) != expected:
                raise APIError(409, "storage_changed", "工作台目录被移动或替换，已停止操作。请保留原目录。")
        if self._catalog_identity is not None:
            if (_identity(self.catalog_path, directory=False) != self._catalog_identity
                    or hashlib.sha256(self.catalog_path.read_bytes()).hexdigest() != self._catalog_digest):
                raise APIError(409, "catalog_changed", "工作台记录被修改或替换，已停止操作。")
        elif self.catalog_path.exists() or self.catalog_path.is_symlink():
            raise APIError(409, "catalog_changed", "工作台记录位置已有内容。")

    def _save(self):
        if self.write_failed:
            raise APIError(503, "storage_unconfirmed", "工作台记录写入未确认，请保留原目录并重新打开工作台。")
        self._check_storage()
        raw = (json.dumps(self.catalog, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
        temporary = self.root / ("catalog-" + uuid.uuid4().hex + ".tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.catalog_path)
        self._catalog_identity = _identity(self.catalog_path, directory=False)
        self._catalog_digest = hashlib.sha256(raw).hexdigest()
        descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _save_jobs(self):
        jobs = copy.deepcopy(self.jobs)
        for job in jobs.values():
            job.get("result", {}).pop("dashboard_url", None)
        self.catalog["jobs"] = jobs
        self._save()

    def _entry(self, identifier):
        entry = self.catalog["profiles"].get(identifier)
        if entry is None:
            raise APIError(404, "profile_not_found", "没有找到这项工作。")
        return entry

    def _profile_path(self, entry):
        self._check_storage()
        path = self.root / "profiles" / entry["id"]
        if entry["phase"] != "created" or not entry.get("identity") or not entry.get("manifest_sha256"):
            raise APIError(409, "creation_failed", "这项工作未完成创建，不能启动。请创建一项新的工作。")
        if _identity(path, directory=True) != entry["identity"]:
            raise APIError(409, "profile_changed", "这项工作的目录已被替换，已停止操作。")
        manifest_path = path / "profile.json"
        _identity(manifest_path, directory=False)
        if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != entry["manifest_sha256"]:
            raise APIError(409, "profile_changed", "这项工作的配置记录已变化，已停止操作。")
        return path

    def info(self):
        return {"application": "元星木", "runtime": copy.deepcopy(self.runtime_status), "limits": dict(LIMITS),
                "skills": [{"id": name, "label": name} for name in sorted(self.skill_sources)],
                "frameworks": {"openclaw": copy.deepcopy(self.runtime_status), "hermes": copy.deepcopy(self.hermes_status)}}

    def mail_account(self):
        with self.mutex:
            self._check_storage()
            account = self.catalog.get("mail_account")
            if not account:
                return {"configured": False, "account_id": None, "from_address": "", "host": "", "port": 465, "username": ""}
            return {"configured": True, "account_id": account["id"],
                    **{name: account["config"][name] for name in ("from_address", "host", "port", "username")}}

    def set_mail_account(self, value, request_key):
        if not isinstance(request_key, str) or not HEX_ID.fullmatch(request_key):
            raise APIError(400, "invalid_request_key", "操作标识无效，请重新提交。")
        try:
            if not isinstance(value, dict) or set(value) != {"host", "port", "username", "password", "from_address"}:
                raise ValueError("invalid_fields")
            account = MailAccount(**value)
        except (TypeError, ValueError):
            raise APIError(400, "invalid_mail_account", "请检查邮箱服务器、端口、账号、授权码和发件地址；这版使用加密的 SMTP 连接。") from None
        config = {name: getattr(account, name) for name in value}
        with self.mutex:
            self._check_storage()
            if self.closing or self.write_failed:
                raise APIError(409, "manager_closing", "工作台正在关闭或保存失败，请重新打开后设置。")
            fingerprint = hmac.new(bytes.fromhex(self.catalog["fingerprint_key"]),
                json.dumps(config, sort_keys=True).encode(), hashlib.sha256).hexdigest()
            requests = self.catalog.setdefault("mail_account_requests", {})
            previous = requests.get(request_key)
            if previous:
                if not hmac.compare_digest(previous["fingerprint"], fingerprint):
                    raise APIError(409, "request_conflict", "这次设置的内容已改变，请重新提交。")
                if self.catalog.get("mail_account", {}).get("id") != previous["account_id"]:
                    raise APIError(409, "mail_account_changed", "邮箱设置后来已经改变，请刷新后核对。")
                return self.mail_account()
            if len(requests) >= 512:
                raise APIError(409, "settings_limit", "这份预览工作台的邮箱设置记录已达到上限，请保留原目录。")
            current = self.catalog.get("mail_account")
            identifier = current["id"] if current and current["config"] == config else uuid.uuid4().hex
            self.catalog["mail_account"] = {"id": identifier, "config": config}
            requests[request_key] = {"fingerprint": fingerprint, "account_id": identifier}
            try:
                self._save()
            except Exception:
                self.write_failed = True
                raise
            return self.mail_account()

    def mail_view(self, identifier, draft_id=None):
        lock = self._core_lock(identifier)
        if not lock.acquire(blocking=False):
            raise APIError(409, "profile_busy", "这项工作有操作正在执行，请稍后查看邮件。")
        try:
            with self.mutex:
                path = self._profile_path(self._entry(identifier))
                features = json.loads((path / "profile.json").read_text()).get("features", [])
            if "reviewed_email_v1" not in features:
                return {"supported": False, "active": False, "drafts": []}
            result = core.review_profile(path, "get" if draft_id else "list", {"draft_id": draft_id} if draft_id else {})
            return {"supported": True, **result}
        finally:
            lock.release()

    def actions_view(self, identifier, action_id=None):
        lock = self._core_lock(identifier)
        if not lock.acquire(blocking=False):
            raise APIError(409, "profile_busy", "这项工作有操作正在执行，请稍后查看。")
        try:
            with self.mutex:
                path = self._profile_path(self._entry(identifier))
                features = json.loads((path / "profile.json").read_text()).get("features", [])
            if "reviewed_actions_v1" not in features:
                return {"supported": False, "active": False, "actions": [], "targets": []}
            result = core.review_profile(path, "action_get" if action_id else "action_list", {"action_id": action_id} if action_id else {})
            return {"supported": True, **result}
        finally:
            lock.release()

    def targets_view(self):
        from ..actions import ActionTarget
        with self.mutex:
            self._check_storage()
            items = []
            for name, value in self.action_targets.items():
                target = ActionTarget(**value)
                items.append({"id": name, **target.describe(name, host=True)})
            return {"targets": items, "applies_to": "new_profiles"}

    def set_target(self, value, request_key, *, remove=False):
        from ..actions import ActionTarget
        from ..sandbox import _overlaps
        if not isinstance(request_key, str) or not HEX_ID.fullmatch(request_key):
            raise APIError(400, "invalid_request_key", "操作标识无效。")
        if type(value) is not dict or set(value) != ({"id"} if remove else {"id", "target"}):
            raise APIError(400, "invalid_target", "请填写操作对象的名称与设置。")
        try:
            identifier = core._name(value["id"])
            if not remove:
                fields = {"kind", "label", "url", "provider", "workspace", "relative_path", "form_fields"}
                if type(value["target"]) is not dict or set(value["target"]) - fields:
                    raise ValueError
                target = ActionTarget(**value["target"])
                if target.workspace is not None and _overlaps(target.workspace, self.root):
                    raise ValueError
                config = target.to_config()
        except (ValueError, TypeError, OSError):
            raise APIError(400, "invalid_target", "请核对对象类型和名称。网络地址须为 HTTPS 或本机地址；文件须位于工作台目录之外的现有 Linux/WSL 文件夹中。") from None
        with self.mutex:
            self._check_storage()
            if self.closing or self.write_failed:
                raise APIError(409, "manager_unavailable", "工作台正在关闭或保存状态未确认。")
            operation = "target_remove" if remove else "target_set"
            fingerprint = hmac.new(bytes.fromhex(self.catalog["fingerprint_key"]),
                json.dumps([operation, value], ensure_ascii=True, sort_keys=True).encode(), hashlib.sha256).hexdigest()
            prior = self.catalog["requests"].get(request_key)
            if prior:
                if prior["fingerprint"] != fingerprint:
                    raise APIError(409, "request_conflict", "这次设置内容已经改变，请重新读取。")
                return {"job": copy.deepcopy(self.jobs[prior["job_id"]])}
            if len(self.jobs) >= MAX_JOBS or (not remove and identifier not in self.action_targets and len(self.action_targets) >= 32):
                raise APIError(409, "target_limit", "预览版的操作对象或记录数量已达到上限。")
            targets = copy.deepcopy(self.action_targets)
            if remove:
                targets.pop(identifier, None)
            else:
                targets[identifier] = config
            job_id = uuid.uuid4().hex
            self.jobs[job_id] = {"id": job_id, "profile_id": None, "action": operation, "status": "succeeded",
                "created_at": _now(), "finished_at": _now(), "result": {"targets_updated": True}}
            self.catalog["requests"][request_key] = {"fingerprint": fingerprint, "job_id": job_id}
            self.catalog["action_targets"] = targets
            try:
                self._save_jobs()
            except Exception:
                self.write_failed = True
                raise APIError(503, "storage_unconfirmed", "对象设置保存未确认，请保留当前页面并重新读取原操作记录。") from None
            self.action_targets = targets
            return {"job": copy.deepcopy(self.jobs[job_id])}

    def tools_view(self, identifier, review_id=None):
        lock = self._core_lock(identifier)
        if not lock.acquire(blocking=False):
            raise APIError(409, "profile_busy", "这项工作有操作正在执行，请稍后查看。")
        try:
            with self.mutex:
                path = self._profile_path(self._entry(identifier))
                features = json.loads((path / "profile.json").read_text()).get("features", [])
            if "layered_defense_v1" not in features:
                return {"supported": False, "active": False, "reviews": []}
            result = core.review_profile(path, "tool_get" if review_id else "tool_list", {"review_id": review_id} if review_id else {})
            return {"supported": True, **result}
        finally:
            lock.release()

    def protection_view(self, identifier):
        from ..protection import public_settings_history, settings_baseline, settings_diff
        with self.mutex:
            path = self._profile_path(self._entry(identifier))
        manifest = core.validate_profile(path)
        protected_fields = {"enabled": "protected_fields_v1" in manifest.get("features", []), "mode": "enforce"}
        if "layered_defense_v1" not in manifest.get("features", []):
            return {"supported": False, "events": [], "protected_fields": protected_fields,
                    "quarantine": core.review_profile(path, "quarantine_status") if protected_fields["enabled"] else None,
                    "message": "这项工作没有启用额外的五层语义与规则检查。"}
        from ..guards import GuardPolicy
        policy = GuardPolicy.from_dict(json.loads((path / "defense-policy.json").read_text()))
        events = []
        event_path = path / "defense-events.jsonl"
        if event_path.exists():
            with event_path.open("rb") as stream:
                stream.seek(0, 2)
                start = max(0, stream.tell() - 1048576)
                stream.seek(start)
                if start:
                    stream.readline()
                lines = stream.read(1048576).splitlines()
            for line in lines[-100:]:
                try:
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        continue
                    event = {key: value.get(key) for key in ("time", "layer", "verdict", "code", "reason", "enforced", "assessed", "would_verdict")}
                    evidence = value.get("evidence", {})
                    if not isinstance(evidence, dict):
                        evidence = {}
                    event["evidence"] = {key: evidence.get(key) for key in ("elapsed_ms", "judge_valid", "raw_verdict_sha256", "input_sha256", "candidate_sha256") if key in evidence}
                    if event.get("code") == "operator_settings_changed":
                        history = public_settings_history(evidence)
                        if history is not None:
                            event["settings_history"] = history
                    events.append(event)
                except (ValueError, TypeError):
                    continue
        report = path / "foundation-report.json"
        foundation = json.loads(report.read_text()) if report.exists() else None
        if foundation is not None:
            foundation["current_policy"] = foundation.get("policy_sha256") == manifest["files"]["defense-policy.json"]
        quarantine = core.review_profile(path, "quarantine_status") if "quarantine_v1" in manifest.get("features", []) else None
        from ..judge_profile import judge_profile_report
        judge = judge_profile_report(path, manifest["model"], pins=manifest["files"])
        stopped = core._offline_lifecycle(path) == "stopped"
        live_settings = "live_settings_v1" in manifest.get("features", [])
        baseline = settings_baseline(path, manifest)
        if baseline["supported"]:
            baseline["changes"] = settings_diff(policy.settings(), baseline["settings"])
        return {"supported": True, "framework": manifest.get("framework", "openclaw"),
                "protected_fields": protected_fields,
                "editable": (stopped or live_settings) and not (quarantine or {}).get("storage_fault", False),
                "live_settings": live_settings and not stopped,
                "judge": judge,
                "skills": {"names": list(manifest.get("skills_snapshot", {}).get("source_paths", {})), "files": manifest.get("skills_snapshot", {}).get("file_count", 0)},
                "objective": policy.objective, "mode": policy.mode,
                "per_layer_settings": "per_layer_settings_v1" in manifest.get("features", []),
                "skill_rules_settings": "skill_rules_v1" in manifest.get("features", []),
                "skill_purpose": "skill_purpose_v1" in manifest.get("features", []),
                "settings_history": "settings_history_v1" in manifest.get("features", []),
                "policy_sha256": manifest["files"]["defense-policy.json"], "baseline": baseline,
                "layers": {name: getattr(policy, name + "_enabled") for name in ("foundation", "input", "memory", "alignment", "command")},
                "layer_modes": {name: getattr(policy, name + "_mode") for name in ("foundation", "input", "memory", "alignment", "command")},
                "effective_modes": {name: policy.effective_mode(name) if getattr(policy, name + "_enabled") else "disabled" for name in ("foundation", "input", "memory", "alignment", "command")},
                "foundation_scans": {"configuration": policy.foundation_config_enabled, "skill_semantic": policy.skill_semantic_enabled,
                                     **({"skill_rules": policy.skill_rules_enabled} if "skill_rules_v1" in manifest.get("features", []) else {})},
                "buffered_response": "buffered_response_v1" in manifest.get("features", []),
                "input_containment": "input_containment_v1" in manifest.get("features", []),
                "quarantine": quarantine, "foundation": foundation, "events": list(reversed(events))}

    def _core_lock(self, identifier):
        with self.mutex:
            return self.core_locks.setdefault(identifier, threading.RLock())

    def _remember(self, identifier, actual):
        # Only retain the last observed public state, never the native login URL.
        if actual.get("status") in STATUSES:
            with self.mutex:
                self.observations[identifier] = {"status": actual["status"], "task": copy.deepcopy(actual.get("task", {}))}
        return actual

    def _observe(self, identifier, path):
        lock = self._core_lock(identifier)
        deadline = time.monotonic() + 20
        while not lock.acquire(blocking=False):
            with self.mutex:
                action = self.pending.get(identifier)
                previous = copy.deepcopy(self.observations.get(identifier))
            if action:
                # An offline status read also takes the core's exclusive profile
                # lock. Do not race it against supervisor startup or revocation.
                # The UI shows pending separately and cannot act on this state.
                if previous is not None:
                    return {**previous, "_pending_observation": action}
                return {"status": "starting" if action in {"create", "start"} else "stopping" if action == "stop" else "unconfirmed",
                        "_pending_observation": action}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise APIError(409, "status_busy", "状态查询尚未完成，请稍后刷新。")
            # A mutation can enter the queue after this reader; recheck pending
            # rather than sitting behind a hundred-second native startup.
            if lock.acquire(timeout=min(.05, remaining)):
                break
        try:
            return self._remember(identifier, core.control_profile(path, "status"))
        finally:
            lock.release()

    def summary(self, identifier, *, observed=None):
        with self.mutex:
            self._check_storage()
            entry = copy.deepcopy(self._entry(identifier))
        result = {key: entry[key] for key in ("id", "name", "created_at", "model_id", "documents")}
        result["framework"] = entry.get("framework", "openclaw")
        result.update(status="failed", revoked=None, pending=None, features=[])
        cached_pending = None
        try:
            if entry["phase"] != "created":
                result["status"] = "starting" if entry["phase"] == "creating" else "creation_failed"
            else:
                with self.mutex:
                    path = self._profile_path(entry)
                    result["features"] = [name for name in json.loads((path / "profile.json").read_text()).get("features", [])
                                          if name in {"reviewed_email_v1", "reviewed_actions_v1", "layered_defense_v1", "quarantine_v1", "buffered_response_v1", "protected_fields_v1"}]
                actual = self._remember(identifier, observed) if observed is not None else self._observe(identifier, path)
                cached_pending = actual.get("_pending_observation")
                if actual.get("status") not in STATUSES:
                    raise RuntimeError("invalid_status")
                result["status"] = actual["status"]
                revoked = actual.get("task", {}).get("revoked")
                result["revoked"] = revoked if isinstance(revoked, bool) else None
                if "quarantine_v1" in result["features"]:
                    result["paused"] = actual.get("task", {}).get("paused")
                    result["pause_epoch"] = actual.get("task", {}).get("pause_epoch")
                if actual["status"] in {"interrupted", "unconfirmed", "failed"}:
                    result["error"] = {"code": "state_unconfirmed", "message": "服务状态异常，尚不能确认已经关闭。请保留记录并检查。"}
        except Exception as exc:
            result["error"] = _fault(exc)
        with self.mutex:
            # If the job completed while this response was built, an older
            # cached observation must still be marked as in progress.
            result["pending"] = self.pending.get(identifier) or cached_pending
        return result

    def profiles(self):
        with self.mutex:
            self._check_storage()
            identifiers = list(self.catalog["profiles"])
        return {"profiles": [self.summary(identifier) for identifier in reversed(identifiers)]}

    def job(self, identifier):
        with self.mutex:
            self._check_storage()
            if identifier not in self.jobs:
                raise APIError(404, "job_not_found", "没有找到这次操作记录。")
            return {"job": copy.deepcopy(self.jobs[identifier])}

    def request_job(self, request_key):
        with self.mutex:
            self._check_storage()
            item = self.catalog["requests"].get(request_key)
            if item is None:
                raise APIError(404, "request_not_found", "尚未找到这次提交记录；请保留当前页面，不要重复执行。")
            return self.job(item["job_id"])

    def _reserve_port(self):
        occupied = {entry["port"] for entry in self.catalog["profiles"].values()} | {self.port, 18701}
        for port in range(18911, 19912):
            if port in occupied:
                continue
            with socket.socket() as probe:
                try:
                    probe.bind(("127.0.0.1", port))
                except OSError:
                    continue
            return port
        raise APIError(409, "no_free_port", "当前没有可用的聊天端口，请先处理占用。")

    def submit(self, action: str, identifier: str | None, value, request_key: str):
        if not HEX_ID.fullmatch(request_key):
            raise APIError(400, "invalid_request_key", "操作标识无效，请刷新工作台后重试。")
        if action == "create":
            payload = validate_create(value)
            if set(payload.get("skills", [])) - set(self.skill_sources):
                raise APIError(400, "unknown_skill", "所选技能不在本机登记列表中。")
        elif action in {"start", "stop", "revoke"}:
            expected = {"confirm": "revoke"} if action == "revoke" else {}
            if not isinstance(value, dict) or value != expected:
                raise APIError(400, "invalid_fields", "操作参数无效；收回权限需要明确确认。")
            payload = None
        elif action == "defense_set":
            from ..guards import validate_defense_settings
            try:
                if (type(value) is not dict or "settings" not in value
                        or set(value) - {"settings", "intent", "baseline_sha256", "expected_policy_sha256"}):
                    raise ValueError
                validate_defense_settings(value["settings"])
                intent = value.get("intent", "set")
                if type(intent) is not str or intent not in {"set", "reset_defaults", "restore_creation"}:
                    raise ValueError
                preview_keys = {"baseline_sha256", "expected_policy_sha256"}
                if intent == "restore_creation":
                    if any(type(value.get(key)) is not str or not re.fullmatch(r"[0-9a-f]{64}", value[key]) for key in preview_keys):
                        raise ValueError
                else:
                    if "baseline_sha256" in value:
                        raise ValueError
                    if "expected_policy_sha256" in value and (type(value["expected_policy_sha256"]) is not str
                            or not re.fullmatch(r"[0-9a-f]{64}", value["expected_policy_sha256"])):
                        raise ValueError
            except (ValueError, TypeError):
                raise APIError(400, "invalid_defense_settings", "防护设置无效。") from None
            payload = copy.deepcopy(value)
        elif action == "quarantine_resume":
            if (type(value) is not dict or set(value) != {"epoch", "incident_id", "confirm"}
                    or type(value["epoch"]) is not int or value["epoch"] < 1
                    or type(value["incident_id"]) is not str or not HEX_ID.fullmatch(value["incident_id"])
                    or value["confirm"] != "resume"):
                raise APIError(400, "invalid_quarantine_resume", "请先查看最新的暂停原因，再确认恢复工作。")
            payload = copy.deepcopy(value)
        elif action in {"tool_approve", "tool_deny"}:
            if (not isinstance(value, dict) or set(value) != {"review_id", "digest", "confirm"}
                    or not isinstance(value.get("review_id"), str) or not HEX_ID.fullmatch(value["review_id"])
                    or not isinstance(value.get("digest"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["digest"])
                    or value["confirm"] != action.removeprefix("tool_")):
                raise APIError(400, "invalid_tool_review", "请重新读取并核对这一次操作的完整内容。")
            payload = copy.deepcopy(value)
        elif action in {"action_edit", "action_commit", "action_cancel"}:
            fields = {"action_id", "revision", "digest"}
            fields |= {"proposal"} if action == "action_edit" else {"confirm"} if action == "action_commit" else set()
            if (not isinstance(value, dict) or set(value) != fields or not isinstance(value.get("action_id"), str)
                    or not HEX_ID.fullmatch(value["action_id"]) or type(value.get("revision")) is not int or value["revision"] < 1
                    or not isinstance(value.get("digest"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["digest"])
                    or (action == "action_commit" and value["confirm"] != "commit")
                    or (action == "action_edit" and not isinstance(value["proposal"], dict))):
                raise APIError(400, "invalid_action_review", "请重新打开操作，核对对象、版本和完整内容后再确认。")
            payload = copy.deepcopy(value)
        elif action in {"mail_edit", "mail_send", "mail_cancel"}:
            fields = {"draft_id", "revision", "digest"}
            fields |= {"draft"} if action == "mail_edit" else {"account_id", "confirm"} if action == "mail_send" else set()
            if (not isinstance(value, dict) or set(value) != fields or not isinstance(value.get("draft_id"), str)
                    or not HEX_ID.fullmatch(value["draft_id"]) or type(value.get("revision")) is not int or value["revision"] < 1
                    or not isinstance(value.get("digest"), str) or not re.fullmatch(r"[0-9a-f]{64}", value["digest"])):
                raise APIError(400, "invalid_mail_review", "邮件核对记录不完整，请重新打开草稿。")
            payload = copy.deepcopy(value)
            if action == "mail_edit":
                try:
                    payload["draft"] = validate_draft(value["draft"])
                except ValueError:
                    raise APIError(400, "invalid_mail_draft", "请填写一个收件邮箱、200 字以内的主题和 64 KB 以内的纯文本正文。") from None
            if action == "mail_send" and (value["confirm"] != "send" or not isinstance(value["account_id"], str) or not HEX_ID.fullmatch(value["account_id"])):
                raise APIError(400, "mail_confirmation_required", "请核对发件人、收件人、主题和全文，再明确确认这封邮件。")
        else:
            raise APIError(404, "not_found", "没有这个操作。")
        fingerprint_input = json.dumps([action, identifier, value], ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
        with self.mutex:
            self._check_storage()
            if self.write_failed:
                raise APIError(503, "storage_unconfirmed", "工作台记录写入未确认，请检查磁盘并重新打开工作台。")
            if self.closing:
                raise APIError(409, "manager_closing", "工作台正在关闭，请重新打开后操作。")
            fingerprint = hmac.new(bytes.fromhex(self.catalog["fingerprint_key"]), fingerprint_input, hashlib.sha256).hexdigest()
            prior = self.catalog["requests"].get(request_key)
            if prior:
                if not hmac.compare_digest(fingerprint, prior["fingerprint"]):
                    raise APIError(409, "request_conflict", "这次操作的内容已改变，请重新提交。")
                return {"job": copy.deepcopy(self.jobs[prior["job_id"]])}
            if len(self.jobs) >= MAX_JOBS:
                raise APIError(409, "job_limit", "此预览版的操作记录已达到上限，请保留原目录。")
            if action == "create":
                self._automatic_scope(payload, self.action_targets)
                payload["_action_targets_snapshot"] = copy.deepcopy(self.action_targets)
                runtime_status = self.hermes_status if payload.get("framework") == "hermes" else self.runtime_status
                if not runtime_status["available"]:
                    raise APIError(409, "runtime_unavailable", runtime_status["reason"])
                if len(self.catalog["profiles"]) >= MAX_PROFILES:
                    raise APIError(409, "profile_limit", "此预览版最多保存 128 项工作。")
                identifier = uuid.uuid4().hex
                entry = {"id": identifier, "name": payload["name"], "created_at": _now(), "model_id": payload["model_id"],
                    "framework": payload.get("framework", "openclaw"),
                    "documents": [{"name": d["name"], "filename": d["filename"], "bytes": len(d["content"].encode())} for d in payload["documents"]],
                    "port": self._reserve_port(), "phase": "creating", "identity": None, "manifest_sha256": None}
                self.catalog["profiles"][identifier] = entry
            else:
                entry = self._entry(identifier)
                if identifier in self.pending:
                    raise APIError(409, "profile_busy", "这项工作有操作尚未完成，请稍候。")
                self._profile_path(entry)
                if action == "mail_send":
                    account = self.catalog.get("mail_account")
                    if account is None:
                        raise APIError(409, "mail_account_missing", "请先设置发件邮箱。")
                    if account["id"] != payload["account_id"]:
                        raise APIError(409, "mail_account_changed", "发件邮箱已改变，请重新核对发件地址。")
            job_id = uuid.uuid4().hex
            job = {"id": job_id, "profile_id": identifier, "action": action, "status": "running", "created_at": _now()}
            self.jobs[job_id] = job
            self.catalog["requests"][request_key] = {"fingerprint": fingerprint, "job_id": job_id}
            self.pending[identifier] = action
            try:
                self._save_jobs()
            except Exception:
                self.write_failed = True
                self.pending.pop(identifier, None)
                if entry["phase"] == "creating":
                    entry["phase"] = "creation_failed"
                error = APIError(503, "storage_unconfirmed", "操作尚未开始，工作台记录写入失败。请检查磁盘并重新打开工作台。")
                job.update(status="failed", finished_at=_now(), error=error.public())
                raise error from None
            worker = threading.Thread(target=self._execute, args=(job_id, payload), name="yxm-operation-" + job_id[:8])
            self.workers.add(worker)
            try:
                worker.start()
            except Exception:
                self.workers.discard(worker)
                self.pending.pop(identifier, None)
                if entry["phase"] == "creating":
                    entry["phase"] = "creation_failed"
                error = APIError(503, "worker_unavailable", "本机未能开始这次操作，请稍后重试。")
                job.update(status="failed", finished_at=_now(), error=error.public())
                try:
                    self._save_jobs()
                except Exception:
                    self.write_failed = True
                raise error from None
            return {"job": copy.deepcopy(job)}

    def _automatic_scope(self, payload, targets):
        """Validate fresh user consent against host targets while holding mutex."""
        if "action_automation" not in payload:
            return None
        from ..action_automation import AutomaticActionPolicy
        from ..actions import ActionTarget
        try:
            registered = {key: ActionTarget(**item) for key, item in targets.items()}
            for key, expected in payload["action_automation_bindings"].items():
                if key not in registered or not hmac.compare_digest(
                        expected, registered[key].describe(key, host=True)["binding_digest"]):
                    raise APIError(409, "automatic_action_target_changed", "所选对象已改变，请刷新对象列表后重新设置授权范围。")
            return AutomaticActionPolicy.from_config(payload["action_automation"], registered).to_config()
        except (ValueError, TypeError, KeyError):
            raise APIError(400, "invalid_automatic_action_scope", "自动执行范围无效；请选择已登记的消息、上传或表单对象。") from None

    def _create(self, entry, payload):
        with self.mutex:
            self._check_storage()
            # Compare consent again at execution time; never read new target
            # addresses after this snapshot has been approved and captured.
            automatic = self._automatic_scope(payload, self.action_targets)
            targets = copy.deepcopy(payload.get("_action_targets_snapshot", self.action_targets))
            self._automatic_scope(payload, targets)
        path = self.root / "profiles" / entry["id"]
        temporary = self.root / "imports" / uuid.uuid4().hex
        temporary.mkdir(mode=0o700)
        imported = {}
        try:
            for document in payload["documents"]:
                source = temporary / (uuid.uuid4().hex + ".txt")
                descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(document["content"].encode("utf-8"))
                imported[document["name"]] = source
            if payload.get("framework") == "hermes":
                from ..hermes import init_profile
                framework_args = {"hermes_python": self.runtime.hermes_python, "hermes_source": self.runtime.hermes_source}
            else:
                init_profile = core.init_profile
                framework_args = {"openclaw_package": self.runtime.openclaw_package}
            if payload.get("objective"):
                framework_args["defense_policy"] = {"objective": payload["objective"].strip(), **payload.get("defense", {})}
            framework_args["selected_skills"] = {name: self.skill_sources[name] for name in payload.get("skills", [])}
            if "judge" in payload:
                framework_args["judge_config"] = payload["judge"]
            framework_args.update(reviewed_actions=True, action_targets=targets)
            if automatic is not None:
                framework_args["action_automation"] = automatic
            init_profile(path, node=self.runtime.node, **framework_args,
                bwrap=self.runtime.bwrap, model_url=payload["model_url"], model_id=payload["model_id"], api_key=payload["api_key"],
                documents=imported, destinations={}, port=entry["port"], reviewed_mail=True)
            with self.mutex:
                self._check_storage()
                entry["identity"] = _identity(path, directory=True)
                _identity(path / "profile.json", directory=False)
                entry["manifest_sha256"] = hashlib.sha256((path / "profile.json").read_bytes()).hexdigest()
                entry["phase"] = "created"
                self._save_jobs()
        finally:
            # Only generated upload files are removed; a partial profile is retained.
            for source in imported.values():
                source.unlink(missing_ok=True)
            temporary.rmdir()

    def _execute(self, job_id, payload):
        with self.mutex:
            job = self.jobs[job_id]
            entry = self.catalog["profiles"][job["profile_id"]]
        core_lock = self._core_lock(entry["id"])
        core_lock.acquire()
        outcome = {}
        extra = {}
        try:
            if job["action"] == "create":
                self._create(entry, payload)
                observed = None
            else:
                with self.mutex:
                    path = self._profile_path(entry)
                if job["action"] == "defense_set":
                    from ..protection import configure_profile
                    extra = configure_profile(path, payload["settings"], _workbench=True,
                                              intent=payload.get("intent", "set"), baseline_sha256=payload.get("baseline_sha256"),
                                              expected_policy_sha256=payload.get("expected_policy_sha256"))
                    with self.mutex:
                        entry["manifest_sha256"] = hashlib.sha256((path / "profile.json").read_bytes()).hexdigest()
                        self._save_jobs()
                    observed = core.control_profile(path, "status")
                elif job["action"].startswith(("action_", "tool_", "quarantine_")):
                    extra = core.review_profile(path, job["action"], payload)
                    extra.pop("ok", None)
                    observed = core.control_profile(path, "status")
                elif job["action"].startswith("mail_"):
                    if job["action"] == "mail_send":
                        with self.mutex:
                            self._check_storage()
                            account = self.catalog.get("mail_account")
                            if not account or account["id"] != payload["account_id"]:
                                raise RuntimeError("mail_account_changed")
                            payload["account"] = copy.deepcopy(account["config"])
                    extra = core.review_profile(path, job["action"].removeprefix("mail_"), payload)
                    extra.pop("ok", None)
                    observed = core.control_profile(path, "status")
                else:
                    observed = core.start_profile(path) if job["action"] == "start" else core.control_profile(path, job["action"])
                if job["action"] == "start" and observed.get("status") != "ready":
                    raise RuntimeError("start_unconfirmed")
                if job["action"] == "revoke" and observed.get("task", {}).get("revoked") is not True:
                    raise RuntimeError("revoke_unconfirmed")
                if job["action"] == "stop":
                    if observed.get("status") != "stopped":
                        raise RuntimeError("stop_unconfirmed")
                    lifecycle_path = path / "lifecycle.json"
                    if lifecycle_path.exists() and json.loads(lifecycle_path.read_text()).get("cleanup_confirmed") is not True:
                        raise RuntimeError("stop_cleanup_unconfirmed")
            summary = self.summary(entry["id"], observed=observed)
            if summary.get("error") and job["action"] in {"create", "start"}:
                raise RuntimeError("state_unconfirmed")
            outcome = {"status": "succeeded", "result": {"profile": summary, **extra}}
            if job["action"] == "start":
                url = observed.get("dashboard_url", "")
                expected = r"http://127\.0\.0\.1:" + str(entry["port"]) + r"/"
                if entry.get("framework", "openclaw") == "openclaw":
                    expected += r"#token=[A-Za-z0-9_-]{16,128}"
                if not isinstance(url, str) or not re.fullmatch(expected, url):
                    raise RuntimeError("invalid_native_url")
                outcome["result"]["dashboard_url"] = url
        except Exception as exc:
            outcome = {"status": "failed", "error": _fault(exc)}
            with self.mutex:
                if entry["phase"] == "creating":
                    entry["phase"] = "creation_failed"
        finally:
            payload = None
            with self.mutex:
                self.pending.pop(entry["id"], None)
                if "result" in outcome:
                    outcome["result"]["profile"]["pending"] = None
                job.update(outcome, finished_at=_now())
                try:
                    self._save_jobs()
                except Exception as exc:
                    self.write_failed = True
                    job.pop("result", None)
                    job.update(status="failed", error=_fault(exc))
                self.workers.discard(threading.current_thread())
            core_lock.release()

    def close(self):
        with self.mutex:
            self.closing = True
            workers = list(self.workers)
        # Let accepted operations finish; never pretend closing this manager stops agents.
        for worker in workers:
            worker.join()
        if self.alerts is not None:
            self.alerts.close()
        if self._lock_file:
            self._lock_file.close()
            self._lock_file = None


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 16

    def __init__(self, manager: Workbench):
        self.manager = manager
        super().__init__(("127.0.0.1", manager.port), Handler)
        manager.port = self.server_port
        self.origin = f"http://127.0.0.1:{self.server_port}"

    def handle_error(self, request, client_address):
        # Base class tracebacks can contain request/body details.
        pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "Yuanxingmu"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(12)

    def log_message(self, *args):
        pass

    def send_error(self, code, message=None, explain=None):
        self._send(code, {"error": {"code": "invalid_request", "message": "请求格式无效。"}})

    def _send(self, status, value, content_type="application/json; charset=utf-8"):
        data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD":
            self.wfile.write(data)

    def _one(self, name, *, required=False):
        values = self.headers.get_all(name, [])
        if len(values) > 1 or (required and len(values) != 1):
            raise APIError(400, "invalid_headers", "请求头格式无效。")
        return values[0] if values else None

    def _dispatch(self):
        if self._one("Host", required=True) != self.server.origin.removeprefix("http://"):
            raise APIError(403, "invalid_host", "请使用启动时给出的本机工作台链接。")
        origin = self._one("Origin")
        if origin is not None and origin != self.server.origin:
            raise APIError(403, "invalid_origin", "只能从本机工作台执行操作。")
        # Do not normalize encoded paths or absolute-form proxy requests into routes.
        raw_target = self.requestline.split()[1]
        if raw_target != self.path or not self.path.startswith("/") or self.path.startswith("//") or "?" in self.path or "%" in self.path:
            raise APIError(404, "not_found", "没有这个页面。")
        if self._one("Transfer-Encoding") is not None or self._one("Expect") is not None:
            raise APIError(400, "invalid_framing", "不支持此请求传输方式。")
        length = self._one("Content-Length")
        if self.command != "POST" and length not in (None, "0"):
            raise APIError(400, "unexpected_body", "此操作不接收请求内容。")
        static = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                  "/automation.js": ("automation.js", "text/javascript; charset=utf-8"),
                  "/actions.js": ("actions.js", "text/javascript; charset=utf-8"),
                  "/protection.js": ("protection.js", "text/javascript; charset=utf-8"),
                  "/mail.js": ("mail.js", "text/javascript; charset=utf-8"),
                  "/targets.js": ("targets.js", "text/javascript; charset=utf-8"),
                  "/alerts.js": ("alerts.js", "text/javascript; charset=utf-8"),
                  "/styles.css": ("styles.css", "text/css; charset=utf-8"), "/mark.svg": ("mark.svg", "image/svg+xml")}
        if self.path in static and self.command == "GET":
            filename, content_type = static[self.path]
            return self._send(200, (WEB / filename).read_bytes(), content_type)
        authorization = self._one("Authorization") or ""
        if not hmac.compare_digest(authorization.encode(), ("Bearer " + self.server.manager.token).encode()):
            raise APIError(401, "unauthorized", "工作台访问凭证已失效，请重新打开终端中的启动链接。")
        manager = self.server.manager
        if self.command == "GET":
            if self.path == "/api/info":
                return self._send(200, manager.info())
            if self.path == "/api/profiles":
                return self._send(200, manager.profiles())
            if self.path == "/api/mail-account":
                return self._send(200, manager.mail_account())
            if self.path == "/api/action-targets":
                return self._send(200, manager.targets_view())
            if self.path == "/api/notifications":
                return self._send(200, manager.alerts.view())
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/tools(?:/([0-9a-f]{32}))?", self.path)
            if match:
                return self._send(200, manager.tools_view(match[1], match[2]))
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/actions(?:/([0-9a-f]{32}))?", self.path)
            if match:
                return self._send(200, manager.actions_view(match[1], match[2]))
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/protection", self.path)
            if match:
                return self._send(200, manager.protection_view(match[1]))
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/mail(?:/([0-9a-f]{32}))?", self.path)
            if match:
                return self._send(200, manager.mail_view(match[1], match[2]))
            match = re.fullmatch(r"/api/jobs/([0-9a-f]{32})", self.path)
            if match:
                return self._send(200, manager.job(match[1]))
            match = re.fullmatch(r"/api/requests/([0-9a-f]{32})", self.path)
            if match:
                return self._send(200, manager.request_job(match[1]))
        elif self.command == "POST":
            if origin != self.server.origin:
                raise APIError(403, "invalid_origin", "只能从本机工作台执行操作。")
            if self._one("Content-Type", required=True) not in ("application/json", "application/json; charset=utf-8"):
                raise APIError(400, "invalid_content_type", "操作需要 JSON 内容。")
            if length is None or not re.fullmatch(r"[0-9]+", length):
                raise APIError(400, "invalid_length", "请求长度无效。")
            if int(length) > MAX_BODY:
                raise APIError(413, "request_too_large", "本次提交过大，请减少资料。")
            request_key = self._one("Idempotency-Key", required=True)
            raw = self.rfile.read(int(length))
            if len(raw) != int(length):
                raise APIError(400, "incomplete_request", "提交未完成，请重试。")
            def object_pairs(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise ValueError("duplicate_key")
                    value[key] = item
                return value
            try:
                value = json.loads(raw.decode("utf-8"), object_pairs_hook=object_pairs,
                                   parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_number")))
            except (ValueError, UnicodeError, RecursionError):
                raise APIError(400, "invalid_json", "提交内容格式无效。") from None
            if self.path == "/api/profiles":
                return self._send(202, manager.submit("create", None, value, request_key))
            if self.path == "/api/mail-account":
                return self._send(200, manager.set_mail_account(value, request_key))
            if self.path in {"/api/action-targets", "/api/action-targets/remove"}:
                return self._send(200, manager.set_target(value, request_key, remove=self.path.endswith("/remove")))
            if self.path == "/api/notifications":
                return self._send(200, manager.alerts.configure(value, request_key))
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/tools/([0-9a-f]{32})/(approve|deny)", self.path)
            if match:
                if not isinstance(value, dict) or "review_id" in value:
                    raise APIError(400, "invalid_tool_review", "操作参数无效。")
                return self._send(202, manager.submit("tool_" + match[3], match[1], {**value, "review_id": match[2]}, request_key))
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/protection", self.path)
            if match:
                return self._send(202, manager.submit("defense_set", match[1], value, request_key))
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/quarantine/resume", self.path)
            if match:
                return self._send(202, manager.submit("quarantine_resume", match[1], value, request_key))
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/actions/([0-9a-f]{32})/(edit|cancel|commit)", self.path)
            if match:
                if not isinstance(value, dict) or "action_id" in value:
                    raise APIError(400, "invalid_action_review", "操作参数无效。")
                return self._send(202, manager.submit("action_" + match[3], match[1], {**value, "action_id": match[2]}, request_key))
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/mail/(edit|send|cancel)", self.path)
            if match:
                return self._send(202, manager.submit("mail_" + match[2], match[1], value, request_key))
            match = re.fullmatch(r"/api/profiles/([0-9a-f]{32})/(start|stop|revoke)", self.path)
            if match:
                return self._send(202, manager.submit(match[2], match[1], value, request_key))
        else:
            raise APIError(405, "method_not_allowed", "不支持此操作。")
        raise APIError(404, "not_found", "没有这个页面或操作。")

    def _handle(self):
        try:
            self._dispatch()
        except APIError as exc:
            self._send(exc.status, {"error": exc.public()})
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception as exc:
            self._send(500, {"error": _fault(exc)})

    def handle_expect_100(self):
        self._send(400, {"error": {"code": "invalid_framing", "message": "不支持此请求传输方式。"}})
        return False

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _handle


def make_server(manager: Workbench):
    return Server(manager)


def serve(root: Path, runtime: Runtime, *, port=18910, open_browser=True, action_targets=None, skill_sources=None):
    if not 1024 <= port <= 65535 or port == 18701:
        raise ValueError("工作台端口须在 1024–65535 之间，且不能使用 18701。")
    manager = Workbench(root, runtime, port=port, action_targets=action_targets, skill_sources=skill_sources)
    server = None
    try:
        server = make_server(manager)
        launch_url = server.origin + "/#access=" + manager.token
        print("元星木工作台已打开。请只供自己使用以下链接：", flush=True)
        print(launch_url, flush=True)
        print("关闭工作台不会关闭运行中的 AI。请先在页面点击“关闭服务”，再退出。", flush=True)
        if open_browser:
            webbrowser.open(launch_url, new=2)
        server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:
        print("正在结束工作台，等待已提交的操作完成。", flush=True)
    finally:
        if server:
            server.server_close()
        manager.close()
    return 0
