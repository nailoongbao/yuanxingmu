"""Host-owned event scanner for the durable notification outbox.

Only this Workbench reads the fixed, pinned authority ledgers. It never reads
event details, exposes endpoints/keys to Agents, or changes task permissions.
Queue insertion is durable before the catalog cursor advances. An interrupted
scan is replayed with the same opaque event ID, preserving deduplication.
"""
from __future__ import annotations

import copy
from dataclasses import asdict
import hashlib
import hmac
import json
import os
import sqlite3
import stat
import threading
import uuid

from ..notifications import NotificationConfig, NotificationQueue


def _empty():
    return {"version": 1, "enabled": False, "generation": None, "config": None,
            "cursors": {}, "queue_identities": None, "stopped": []}


def validate_catalog(value):
    from .server import HEX_ID
    if (type(value) is not dict or set(value) != set(_empty()) or value["version"] != 1
            or type(value["enabled"]) is not bool or type(value["cursors"]) is not dict
            or type(value["stopped"]) is not list or len(value["stopped"]) > 20):
        raise ValueError("notification_catalog_invalid")
    if any(type(key) is not str or not HEX_ID.fullmatch(key) or type(cursor) is not int or cursor < 0
           for key, cursor in value["cursors"].items()):
        raise ValueError("notification_cursor_invalid")
    if value["enabled"]:
        if type(value["generation"]) is not str or not HEX_ID.fullmatch(value["generation"]):
            raise ValueError("notification_generation_invalid")
        NotificationConfig.from_dict(value["config"])
        identities = value["queue_identities"]
        if (type(identities) is not dict or set(identities) != {"directory", "database"}
                or any(type(item) is not list or len(item) != 2 or any(type(n) is not int or n < 0 for n in item)
                       for item in identities.values())):
            raise ValueError("notification_identity_invalid")
    elif any(value[key] is not None for key in ("generation", "config", "queue_identities")) or value["cursors"]:
        raise ValueError("notification_disabled_configuration_invalid")
    for item in value["stopped"]:
        if (type(item) is not dict or set(item) != {"generation", "counts", "storage_fault", "stopped_at"}
                or type(item["generation"]) is not str or not HEX_ID.fullmatch(item["generation"])
                or type(item["storage_fault"]) is not bool or type(item["stopped_at"]) is not str):
            raise ValueError("notification_history_invalid")
        counts = item["counts"]
        if counts is not None and (type(counts) is not dict or set(counts) != {"pending", "in_flight", "delivered", "failed"}
                or any(type(n) is not int or n < 0 for n in counts.values())):
            raise ValueError("notification_history_invalid")


def _private(info, directory=False, *, allow_read_bits=False):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & (0o033 if allow_read_bits else 0o077)
            or (not directory and info.st_nlink != 1)):
        raise ValueError("notification_source_unsafe")
    return [info.st_dev, info.st_ino]


def _ledger(manager, entry, after=None):
    """Read a bounded batch, without creating a ledger or reading event details."""
    path = manager._profile_path(entry)
    manifest = json.loads((path / "profile.json").read_bytes())
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    profile_fd = os.open(path, flags)
    state_fd = database_fd = None
    database = None
    try:
        if _private(os.fstat(profile_fd), True) != entry["identity"]:
            raise ValueError("notification_source_replaced")
        state_fd = os.open("broker-state", flags, dir_fd=profile_fd)
        identities = manifest["identities"]
        if _private(os.fstat(state_fd), True) != identities["broker-state"]:
            raise ValueError("notification_source_replaced")
        database_fd = os.open("authority.sqlite3", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state_fd)
        # Existing Authority SQLite files inherit normal read bits, beneath the
        # owner-only broker directory. Reject writes/execute bits and hardlinks.
        expected = _private(os.fstat(database_fd), allow_read_bits=True)
        if expected != identities["broker-state/authority.sqlite3"]:
            raise ValueError("notification_source_replaced")
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                _private(os.stat("authority.sqlite3" + suffix, dir_fd=state_fd, follow_symlinks=False), allow_read_bits=True)
            except FileNotFoundError:
                pass
        database = sqlite3.connect(f"file:/proc/self/fd/{state_fd}/authority.sqlite3?mode=ro", uri=True, timeout=.2)
        database.execute("PRAGMA query_only=ON")
        database.execute("PRAGMA trusted_schema=OFF")
        database.execute("BEGIN")
        task = database.execute("SELECT family_id FROM authority_tasks WHERE id=?", (manifest["task_id"],)).fetchone()
        if task is None or task[0] != manifest["family_id"]:
            raise ValueError("notification_source_task_changed")
        maximum = database.execute("SELECT COALESCE(MAX(event_id),0) FROM authority_events").fetchone()[0]
        if after is not None and maximum < after:
            raise ValueError("notification_source_rewound")
        rows = [] if after is None else database.execute("""SELECT e.event_id,e.action,e.allowed,e.reason,t.family_id
            FROM authority_events e LEFT JOIN authority_tasks t ON t.id=e.task_id
            WHERE e.event_id>? ORDER BY e.event_id LIMIT 128""", (after,)).fetchall()
        if (_private(os.stat("authority.sqlite3", dir_fd=state_fd, follow_symlinks=False), allow_read_bits=True) != expected
                or _private((path / "broker-state").lstat(), True) != identities["broker-state"]):
            raise ValueError("notification_source_replaced")
        return maximum, rows, manifest["family_id"]
    finally:
        if database is not None:
            database.close()
        for descriptor in (database_fd, state_fd, profile_fd):
            if descriptor is not None:
                os.close(descriptor)


def _state(row, family_id):
    _, action, allowed, reason, family = row
    if family != family_id:
        return None
    if action == "quarantine_pause" and allowed == 0:
        return "paused"
    if action == "quarantine_resume" and allowed == 1:
        return "resumed"
    if action == "revoke" and allowed == 1:
        return "revoked"
    if ((action == "tool_review_request" and allowed == 0 and reason == "human_confirmation_required")
            or (action in {"mail_draft_submitted", "action_proposed"} and allowed == 1)):
        return "approval_required"
    return None


class HostAlerts:
    def __init__(self, manager):
        self.manager = manager
        self._queue = None
        self._fault = None
        self._source_errors = {}
        self._last_scan_at = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        settings = manager.catalog.get("notifications", _empty())
        validate_catalog(settings)
        if settings["enabled"]:
            try:
                path = self._path(settings["generation"])
                pins = settings["queue_identities"]
                if (_private(path.lstat(), True) != pins["directory"]
                        or _private((path / "notifications.sqlite3").lstat()) != pins["database"]):
                    raise ValueError("notification_queue_replaced")
                self._queue = NotificationQueue(path, NotificationConfig.from_dict(settings["config"]))
                self._queue.start()
            except Exception:
                self._fault = "notification_queue_unavailable"
                try:
                    self._halt()
                except Exception:
                    pass
        self._worker = threading.Thread(target=self._run, name="yuanxingmu-notification-scanner", daemon=True)
        self._worker.start()

    def _path(self, generation):
        return self.manager.root / ("notifications-" + generation)

    def _halt(self):
        if self._queue is not None:
            self._queue.close()
            self._queue = None

    def _run(self):
        while not self._stop.is_set():
            self._wake.clear()
            try:
                self.scan_once()
            except Exception:
                with self.manager.mutex:
                    self._fault = "notification_scanner_failed"
                    try:
                        self._halt()
                    except Exception:
                        pass
            self._wake.wait(.3)

    def scan_once(self):
        from .server import _now
        manager = self.manager
        with manager.mutex:
            if manager.closing or self._stop.is_set() or self._fault:
                return
            manager._check_storage()
            if manager.write_failed:
                raise RuntimeError("notification_catalog_unconfirmed")
            settings = manager.catalog.get("notifications", _empty())
            if not settings["enabled"] or self._queue is None:
                return
            cursors = dict(settings["cursors"])
            errors = {}
            for identifier, entry in manager.catalog["profiles"].items():
                if self._stop.is_set():
                    break
                if entry["phase"] != "created":
                    continue
                lock = manager._core_lock(identifier)
                if not lock.acquire(blocking=False):
                    continue
                try:
                    _, rows, family = _ledger(manager, entry, cursors.get(identifier, 0))
                    for row in rows:
                        state = _state(row, family)
                        if state is not None:
                            event_id = hashlib.sha256((identifier + ":" + str(row[0])).encode("ascii")).hexdigest()
                            self._queue.enqueue(event_id, state)
                        cursors[identifier] = row[0]
                except Exception as error:
                    errors[identifier] = "notification_queue_full" if str(error) == "notification_queue_full" else "notification_source_unavailable"
                    if self._queue.status(limit=0)["storage_fault"]:
                        self._fault = "notification_queue_unavailable"
                        self._halt()
                        break
                finally:
                    lock.release()
            self._source_errors = errors
            self._last_scan_at = _now()
            if cursors != settings["cursors"]:
                settings["cursors"] = cursors
                try:
                    manager._save()
                except Exception:
                    manager.write_failed = True
                    raise

    def view(self):
        manager = self.manager
        with manager.mutex:
            try:
                manager._check_storage()
            except Exception:
                self._fault = "notification_catalog_unavailable"
                try:
                    self._halt()
                except Exception:
                    pass
            settings = manager.catalog.get("notifications", _empty())
            public = NotificationConfig.from_dict(settings["config"]).public() if settings["enabled"] else None
            report = self._queue.status() if self._queue is not None else None
            fault = bool(self._fault or manager.write_failed or (report and report["storage_fault"]))
            counts = None if fault else report["counts"] if report else {name: 0 for name in ("pending", "in_flight", "delivered", "failed")}
            full = counts is not None and public is not None and sum(counts.values()) >= public["queue_capacity"]
            return {"enabled": settings["enabled"], "generation": settings["generation"], "configuration": public,
                    "has_credential": bool(settings["enabled"] and settings["config"].get("api_key")),
                    "counts": counts, "events": [] if fault or not report else report["events"],
                    "full": full, "storage_fault": fault, "scanner_error": self._fault,
                    "source_errors": [{"profile_id": identifier, "code": code} for identifier, code in self._source_errors.items()],
                    "worker_running": bool(report and report["worker_running"]),
                    "worker_error": report["worker_error"] if report else None,
                    "scanner_running": bool(settings["enabled"] and not fault and self._worker.is_alive() and not self._stop.is_set()),
                    "last_scan_at": self._last_scan_at, "stopped": copy.deepcopy(settings["stopped"]),
                    "delivery_semantics": "at_least_once", "starts_with": "new_events", "requires_workbench_process": True}

    def configure(self, value, request_key):
        from .server import APIError, HEX_ID, MAX_JOBS, _now
        if type(request_key) is not str or not HEX_ID.fullmatch(request_key):
            raise APIError(400, "invalid_request_key", "操作标识无效。")
        if (type(value) is not dict or type(value.get("enabled")) is not bool
                or set(value) != ({"enabled", "config"} if value.get("enabled") else {"enabled"})):
            raise APIError(400, "invalid_notification_settings", "请填写提醒接收设置，或选择关闭后台提醒。")
        try:
            config = NotificationConfig.from_dict(value["config"]) if value["enabled"] else None
        except (ValueError, TypeError):
            raise APIError(400, "invalid_notification_settings", "接收地址须为 HTTPS 或明确的本机 HTTP 地址，不能带账号、查询参数或页面锚点；请核对凭证和重试设置。") from None
        manager = self.manager
        with manager.mutex:
            manager._check_storage()
            if manager.closing or manager.write_failed or self._stop.is_set():
                raise APIError(409, "manager_unavailable", "工作台正在关闭或保存状态未确认。")
            fingerprint = hmac.new(bytes.fromhex(manager.catalog["fingerprint_key"]),
                json.dumps(["notifications_set", value], sort_keys=True, ensure_ascii=True).encode(), hashlib.sha256).hexdigest()
            prior = manager.catalog["requests"].get(request_key)
            if prior:
                if prior["fingerprint"] != fingerprint:
                    raise APIError(409, "request_conflict", "这次设置内容已经改变，请重新读取。")
                return {"job": copy.deepcopy(manager.jobs[prior["job_id"]])}
            if len(manager.jobs) >= MAX_JOBS:
                raise APIError(409, "job_limit", "本机操作记录已达到上限，请保留原记录。")
            old = manager.catalog.get("notifications", _empty())
            same = old["enabled"] == value["enabled"] and old["config"] == (asdict(config) if config else None)
            candidate = None
            if not same:
                desired = _empty()
                desired["stopped"] = copy.deepcopy(old["stopped"])
                if config is not None:
                    cursors = {}
                    try:
                        for identifier, entry in manager.catalog["profiles"].items():
                            if entry["phase"] != "created":
                                continue
                            lock = manager._core_lock(identifier)
                            if not lock.acquire(blocking=False):
                                raise RuntimeError("profile_busy")
                            try:
                                cursors[identifier] = _ledger(manager, entry)[0]
                            finally:
                                lock.release()
                        generation = uuid.uuid4().hex
                        path = self._path(generation)
                        candidate = NotificationQueue(path, config)
                        desired.update(enabled=True, generation=generation, config=asdict(config), cursors=cursors,
                            queue_identities={"directory": _private(path.lstat(), True),
                                              "database": _private((path / "notifications.sqlite3").lstat())})
                    except Exception:
                        if candidate is not None:
                            candidate.close()
                        raise APIError(409, "notification_source_unavailable", "工作记录正在变更或无法核对，提醒设置没有更换；请稍后重新读取。") from None
                if old["enabled"]:
                    report = self._queue.status(limit=0) if self._queue is not None else None
                    desired["stopped"].append({"generation": old["generation"], "counts": report["counts"] if report else None,
                        "storage_fault": bool(self._fault or not report or report["storage_fault"]), "stopped_at": _now()})
                    desired["stopped"] = desired["stopped"][-20:]
                try:
                    self._halt()
                except Exception:
                    if candidate is not None:
                        candidate.close()
                    self._fault = "notification_shutdown_unconfirmed"
                    raise APIError(503, "notification_shutdown_unconfirmed", "旧提醒服务的停止尚未确认，新设置没有启用，请查询原操作记录。") from None
                manager.catalog["notifications"] = desired
            job_id = uuid.uuid4().hex
            manager.jobs[job_id] = {"id": job_id, "profile_id": None, "action": "notifications_set", "status": "succeeded",
                "created_at": _now(), "finished_at": _now(), "result": {"notifications_updated": True, "enabled": value["enabled"]}}
            manager.catalog["requests"][request_key] = {"fingerprint": fingerprint, "job_id": job_id}
            try:
                manager._save_jobs()
            except Exception:
                manager.write_failed = True
                if candidate is not None:
                    candidate.close()
                self._fault = "notification_catalog_unconfirmed"
                raise APIError(503, "storage_unconfirmed", "提醒设置保存未确认，请保留页面并查询这一次保存；不要将它当作已启用提醒。") from None
            if not same:
                self._queue = candidate
                self._fault = None
                self._source_errors = {}
                if candidate is not None:
                    try:
                        candidate.start()
                    except Exception:
                        self._fault = "notification_worker_failed"
                self._wake.set()
            return {"job": copy.deepcopy(manager.jobs[job_id])}

    def close(self):
        self._stop.set()
        self._wake.set()
        self._worker.join(timeout=3)
        if self._worker.is_alive():
            raise RuntimeError("notification_scanner_shutdown_pending")
        with self.manager.mutex:
            self._halt()
