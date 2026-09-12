"""Host-only persistent notification outbox, independent of any browser page.

The host supplies a fixed endpoint/credential on every open. Their digest and
all delivery settings bind the queue; configuration is never taken from an
Agent or an event. Only opaque event IDs and four generic states are accepted.

Delivery is at least once. A stable Idempotency-Key lets cooperating receivers
deduplicate retries after uncertain responses. Default webhooks acknowledge
with any 2xx status; strict mode requires {"accepted": true, "event_id": ID}.
Successful delivery says nothing about a person reading the notification.

Rows, including delivered rows, count toward capacity so deduplication remains
durable. A full queue raises rather than discarding an alert or its tombstone.
The host must surface full/failed/faulted status and manage retention explicitly.
No notification result changes task permission, approvals or quarantine state.
close() requests cancellation and stops further claims. A request already sent
may reach its receiver; without an acknowledgement it stays eligible for retry.
Retry and lease deadlines use the Linux boot's shared monotonic clock. Wall
timestamps are only records, so correcting the system clock cannot delay a
retry or expire a live lease. A new boot preserves IDs/attempts and starts at
most one fresh backoff; an old boot's in-flight request cannot still be running.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, fields
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import sys
import threading
import time
from urllib.parse import urlsplit
import uuid

from .guards import JudgeConfig


_MESSAGES = {"paused": "工作已暂停，请在元星木工作台查看。",
             "resumed": "工作已由本人恢复，请在元星木工作台查看。",
             "revoked": "工作权限已收回，请在元星木工作台查看。",
             "approval_required": "有操作等待本人核对，请在元星木工作台查看。"}
_EVENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_DB_NAME = "notifications.sqlite3"
_SCHEMA_VERSION = 2


@dataclass(frozen=True, slots=True)
class NotificationConfig:
    url: str
    api_key: str = field(default="", repr=False)
    timeout_seconds: float = 5
    max_attempts: int = 5
    backoff_seconds: float = 2
    max_backoff_seconds: float = 60
    max_response_bytes: int = 8192
    queue_capacity: int = 10000
    strict_receipt: bool = False

    def __post_init__(self):
        JudgeConfig(self.url, "notification-endpoint", api_key=self.api_key)
        if "\\" in self.url or any(not 33 <= ord(c) <= 126 for c in self.api_key):
            raise ValueError("invalid_notification_configuration")
        bounds = {"timeout_seconds": (.01, 30), "backoff_seconds": (.01, 3600), "max_backoff_seconds": (.01, 86400)}
        if any(type(getattr(self, name)) not in {int, float} or not low <= getattr(self, name) <= high
               for name, (low, high) in bounds.items()):
            raise ValueError("invalid_notification_configuration")
        if (self.max_backoff_seconds < self.backoff_seconds or type(self.max_attempts) is not int
                or not 1 <= self.max_attempts <= 20 or type(self.max_response_bytes) is not int
                or not 256 <= self.max_response_bytes <= 65536 or type(self.queue_capacity) is not int
                or not 1 <= self.queue_capacity <= 100000 or type(self.strict_receipt) is not bool):
            raise ValueError("invalid_notification_configuration")

    @classmethod
    def from_dict(cls, value: dict):
        if type(value) is not dict or set(value) - {f.name for f in fields(cls)}:
            raise ValueError("invalid_notification_configuration")
        try:
            return cls(**value)
        except TypeError:
            raise ValueError("invalid_notification_configuration") from None

    def public(self) -> dict:
        parsed = urlsplit(self.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if self.api_key:
            origin = origin.replace(self.api_key, "[已隐藏]")
        return {"destination_origin": origin,
                "strict_receipt": self.strict_receipt, "timeout_seconds": self.timeout_seconds,
                "max_attempts": self.max_attempts, "backoff_seconds": self.backoff_seconds,
                "max_backoff_seconds": self.max_backoff_seconds, "queue_capacity": self.queue_capacity}


def _json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _boot_identifier() -> str:
    try:
        return str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()))
    except (OSError, ValueError, UnicodeError):
        raise RuntimeError("notification_clock_unavailable") from None


def _open_directory(path: Path) -> int:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("notifications_require_linux_host")
    if not path.is_absolute() or ".." in path.parts or path == Path("/") or "\x00" in str(path):
        raise ValueError("invalid_notification_state_path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for index, part in enumerate(path.parts[1:]):
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if index != len(path.parts) - 2:
                    raise
                os.mkdir(part, 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError("notification_state_not_private")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _private_file(directory, name):
    info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("invalid_notification_state_file")
    return info


class NotificationQueue:
    """A bounded durable outbox; start() explicitly enables background delivery.

    enqueue() and status() never send. dispatch_once() is useful to host service
    loops/tests; otherwise start() drains due rows in one background worker.
    Root integration must keep this state/config and all methods host-only.
    """
    def __init__(self, state_dir: Path, config: NotificationConfig):
        if type(config) is not NotificationConfig:
            raise ValueError("invalid_notification_configuration")
        self._config = config
        self.state_dir = Path(state_dir)
        self._lock = threading.RLock()
        self._dispatch_lock = threading.Lock()
        self._transport_lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._worker = None
        self._closed = False
        self._fault = False
        self._worker_error = None
        self._active_cancel = None
        self._active_transport = None
        self._directory = _open_directory(self.state_dir)
        directory_info = os.fstat(self._directory)
        self._directory_identity = (directory_info.st_dev, directory_info.st_ino)
        self._db = None
        try:
            self._boot_id = _boot_identifier()
            try:
                fd = os.open(_DB_NAME, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=self._directory)
            except FileExistsError:
                _private_file(self._directory, _DB_NAME)
                new_database = False
            else:
                new_database = True
                os.close(fd)
                os.fsync(self._directory)
            for suffix in ("-journal", "-wal", "-shm"):
                try:
                    _private_file(self._directory, _DB_NAME + suffix)
                except FileNotFoundError:
                    pass
            info = _private_file(self._directory, _DB_NAME)
            self._database_identity = (info.st_dev, info.st_ino)
            self._db = sqlite3.connect(f"file:/proc/self/fd/{self._directory}/{_DB_NAME}?mode=rw", uri=True,
                                       timeout=3, isolation_level=None, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA journal_mode=DELETE")
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.execute("PRAGMA trusted_schema=OFF")
            with self._transaction() as db:
                db.execute("CREATE TABLE IF NOT EXISTS notification_binding(version INTEGER NOT NULL, digest TEXT NOT NULL)")
                db.execute("""CREATE TABLE IF NOT EXISTS notification_events(
                    event_id TEXT PRIMARY KEY, status TEXT NOT NULL,
                    delivery TEXT NOT NULL CHECK(delivery IN ('pending','in_flight','delivered','failed')),
                    attempts INTEGER NOT NULL DEFAULT 0, created_at REAL NOT NULL, updated_at REAL NOT NULL,
                    available_at REAL NOT NULL, lease_token TEXT, lease_until REAL,
                    last_error TEXT, delivered_at REAL,
                    schedule_boot TEXT, available_mono REAL, lease_mono REAL)""")
                digest = hashlib.sha256(_json(asdict(config))).hexdigest()
                rows = db.execute("SELECT version,digest FROM notification_binding").fetchall()
                if not rows and new_database:
                    db.execute("INSERT INTO notification_binding(version,digest) VALUES(?,?)", (_SCHEMA_VERSION, digest))
                elif len(rows) != 1 or rows[0]["version"] not in {1, _SCHEMA_VERSION} or rows[0]["digest"] != digest:
                    raise ValueError("notification_configuration_changed")
                if rows and rows[0]["version"] == 1:
                    columns = {row["name"] for row in db.execute("PRAGMA table_info(notification_events)")}
                    for name, kind in (("schedule_boot", "TEXT"), ("available_mono", "REAL"), ("lease_mono", "REAL")):
                        if name not in columns:
                            db.execute(f"ALTER TABLE notification_events ADD COLUMN {name} {kind}")
                    db.execute("UPDATE notification_binding SET version=?", (_SCHEMA_VERSION,))
                self._restore_schedule(db)
        except BaseException:
            if self._db is not None:
                self._db.close()
            os.close(self._directory)
            raise

    @property
    def config(self):
        return self._config

    def _retry_delay(self, attempts):
        if attempts == 0:
            return 0
        return min(self.config.max_backoff_seconds, self.config.backoff_seconds * 2 ** (attempts - 1))

    def _restore_schedule(self, db):
        # Monotonic values survive process restarts, but cannot cross an OS boot.
        # Never rebase another instance's current-boot lease. Legacy rows have
        # no boot identity, so wait a full lease before recovering an old claim.
        now, elapsed = time.time(), time.monotonic()
        rows = db.execute("""SELECT * FROM notification_events WHERE delivery IN ('pending','in_flight')
                             AND (schedule_boot IS NULL OR schedule_boot!=?)""", (self._boot_id,)).fetchall()
        for row in rows:
            delay = self._retry_delay(row["attempts"]) if row["delivery"] == "pending" else 0
            lease_delay = self.config.timeout_seconds + 5 if row["schedule_boot"] is None else 0
            in_flight = row["delivery"] == "in_flight"
            db.execute("""UPDATE notification_events SET schedule_boot=?,available_mono=?,available_at=?,
                          lease_mono=?,lease_until=? WHERE event_id=?""",
                       (self._boot_id, elapsed + delay, now + delay,
                        elapsed + lease_delay if in_flight else None,
                        now + lease_delay if in_flight else None, row["event_id"]))

    def _healthy(self):
        if self._closed:
            raise RuntimeError("notification_queue_closed")
        if self._fault:
            raise RuntimeError("notification_storage_fault")
        self._verify_storage()

    def _verify_storage(self):
        try:
            directory = self.state_dir.stat(follow_symlinks=False)
            if (not stat.S_ISDIR(directory.st_mode) or stat.S_IMODE(directory.st_mode) & 0o077
                    or (directory.st_dev, directory.st_ino) != self._directory_identity):
                raise ValueError
            file = _private_file(self._directory, _DB_NAME)
            if (file.st_dev, file.st_ino) != self._database_identity:
                raise ValueError
        except (OSError, ValueError):
            self._fault = True
            raise RuntimeError("notification_storage_fault") from None

    @contextmanager
    def _transaction(self):
        with self._lock:
            self._healthy()
            try:
                self._db.execute("BEGIN IMMEDIATE")
                yield self._db
                self._db.execute("COMMIT")
            except BaseException as error:
                if isinstance(error, (sqlite3.Error, OSError)):
                    self._fault = True
                if self._db.in_transaction:
                    try:
                        self._db.execute("ROLLBACK")
                    except sqlite3.Error:
                        self._fault = True
                        raise
                raise

    @staticmethod
    def _record(row) -> dict:
        return {key: row[key] for key in ("event_id", "status", "delivery", "attempts", "created_at", "updated_at",
                                          "available_at", "last_error", "delivered_at")}

    def enqueue(self, event_id: str, status: str) -> dict:
        if (type(event_id) is not str or not _EVENT_ID.fullmatch(event_id)
                or type(status) is not str or status not in _MESSAGES):
            raise ValueError("invalid_notification_event")
        with self._transaction() as db:
            now, elapsed = time.time(), time.monotonic()
            row = db.execute("SELECT * FROM notification_events WHERE event_id=?", (event_id,)).fetchone()
            if row is not None:
                if row["status"] != status:
                    raise ValueError("notification_event_conflict")
                result = {"created": False, **self._record(row)}
            else:
                count = db.execute("SELECT COUNT(*) FROM notification_events").fetchone()[0]
                if count >= self.config.queue_capacity:
                    raise ValueError("notification_queue_full")
                db.execute("""INSERT INTO notification_events(event_id,status,delivery,created_at,updated_at,available_at,
                              schedule_boot,available_mono) VALUES(?,?,'pending',?,?,?,?,?)""",
                           (event_id, status, now, now, now, self._boot_id, elapsed))
                result = {"created": True, **self._record(db.execute("SELECT * FROM notification_events WHERE event_id=?", (event_id,)).fetchone())}
        self._wake.set()
        return result

    def status(self, *, limit: int = 20) -> dict:
        if type(limit) is not int or not 0 <= limit <= 100:
            raise ValueError("invalid_notification_status_limit")
        with self._lock:
            if self._closed:
                raise RuntimeError("notification_queue_closed")
            try:
                self._verify_storage()
                counts = dict(self._db.execute("SELECT delivery,COUNT(*) FROM notification_events GROUP BY delivery"))
                counts = {name: counts.get(name, 0) for name in ("pending", "in_flight", "delivered", "failed")}
                rows = self._db.execute("SELECT * FROM notification_events ORDER BY created_at DESC,event_id LIMIT ?", (limit,)).fetchall()
            except (RuntimeError, sqlite3.Error):
                self._fault = True
                counts, rows = None, []
            return {"counts": counts,
                    "events": [self._record(row) for row in rows], "storage_fault": self._fault,
                    "worker_running": bool(self._worker and self._worker.is_alive()),
                    "transport_busy": self._transport_lock.locked(),
                    "worker_error": self._worker_error, "capacity": self.config.queue_capacity,
                    "delivery_semantics": "at_least_once", "configuration": self.config.public()}

    def _claim(self):
        with self._transaction() as db:
            now, elapsed = time.time(), time.monotonic()
            db.execute("""UPDATE notification_events SET delivery='failed',last_error='delivery_unconfirmed',updated_at=?,
                          lease_token=NULL,lease_until=NULL,lease_mono=NULL
                          WHERE delivery='in_flight' AND schedule_boot=? AND lease_mono<=? AND attempts>=?""",
                       (now, self._boot_id, elapsed, self.config.max_attempts))
            row = db.execute("""SELECT * FROM notification_events WHERE attempts<? AND schedule_boot=? AND
                         ((delivery='pending' AND available_mono<=?) OR (delivery='in_flight' AND lease_mono<=?))
                         ORDER BY CASE delivery WHEN 'pending' THEN available_mono ELSE lease_mono END,rowid LIMIT 1""",
                         (self.config.max_attempts, self._boot_id, elapsed, elapsed)).fetchone()
            if row is None:
                return None
            token = uuid.uuid4().hex
            db.execute("""UPDATE notification_events SET delivery='in_flight',attempts=attempts+1,
                          lease_token=?,lease_until=?,lease_mono=?,updated_at=? WHERE event_id=?""",
                       (token, now + self.config.timeout_seconds + 5, elapsed + self.config.timeout_seconds + 5,
                        now, row["event_id"]))
            return {"event_id": row["event_id"], "status": row["status"], "attempts": row["attempts"] + 1, "token": token}

    def _complete(self, claim, outcome):
        accepted, retryable, error = outcome
        terminal = accepted or not retryable or claim["attempts"] >= self.config.max_attempts
        delivery = "delivered" if accepted else "failed" if terminal else "pending"
        delay = self._retry_delay(claim["attempts"])
        with self._transaction() as db:
            now, elapsed = time.time(), time.monotonic()
            db.execute("""UPDATE notification_events SET delivery=?,updated_at=?,available_at=?,available_mono=?,last_error=?,
                          delivered_at=?,lease_token=NULL,lease_until=NULL,lease_mono=NULL
                          WHERE event_id=? AND delivery='in_flight' AND lease_token=? AND schedule_boot=?""",
                       (delivery, now, now if terminal else now + delay, elapsed if terminal else elapsed + delay, error, now if accepted else None,
                        claim["event_id"], claim["token"], self._boot_id))

    def _send(self, claim, cancelled, holder):
        connection = None
        try:
            if cancelled.is_set():
                return False, True, "delivery_cancelled"
            endpoint = urlsplit(self.config.url)
            factory = http.client.HTTPSConnection if endpoint.scheme == "https" else http.client.HTTPConnection
            connection = factory(endpoint.hostname, endpoint.port, timeout=self.config.timeout_seconds)
            holder["connection"] = connection
            connection.connect()
            holder["socket"] = connection.sock
            if cancelled.is_set():
                return False, True, "delivery_cancelled"
            payload = _json({"version": 1, "event_id": claim["event_id"], "status": claim["status"],
                             "message": _MESSAGES[claim["status"]]})
            headers = {"Content-Type": "application/json", "Accept": "application/json",
                       "Idempotency-Key": "yuanxingmu-notification:" + claim["event_id"]}
            if self.config.api_key:
                headers["Authorization"] = "Bearer " + self.config.api_key
            connection.request("POST", endpoint.path or "/", body=payload, headers=headers)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                retry = response.status in {408,425,429} or 500 <= response.status < 600
                return False, retry, "redirect_rejected" if 300 <= response.status < 400 else "http_" + str(response.status)
            if not self.config.strict_receipt:
                # 2xx is the default receipt. Ignore and close the optional body;
                # untrusted webhook bodies are never stored or shown to users.
                return True, False, None
            raw = response.read(self.config.max_response_bytes + 1)
            if len(raw) > self.config.max_response_bytes:
                return False, False, "receipt_too_large"
            def unique(items):
                value = {}
                for key, item in items:
                    if key in value:
                        raise ValueError
                    value[key] = item
                return value
            try:
                receipt = json.loads(raw, object_pairs_hook=unique)
            except (ValueError, UnicodeError, RecursionError):
                return False, False, "receipt_invalid"
            if (type(receipt) is not dict or set(receipt) != {"accepted", "event_id"}
                    or receipt["accepted"] is not True or receipt["event_id"] != claim["event_id"]):
                return False, False, "receipt_mismatch"
            return True, False, None
        except (OSError, http.client.HTTPException, UnicodeError, ValueError):
            return False, True, "transport_error"
        finally:
            if connection is not None:
                connection.close()

    def dispatch_once(self) -> bool:
        """Attempt at most one due event. No delivery or approval is invented."""
        if not self._dispatch_lock.acquire(blocking=False):
            return False
        transport_reserved = False
        try:
            self._healthy()
            if self._stop.is_set() or not self._transport_lock.acquire(blocking=False):
                return False
            transport_reserved = True
            claim = self._claim()
            if claim is None:
                return False
            finished, cancelled, holder = threading.Event(), threading.Event(), {}
            with self._lock:
                self._active_cancel, self._active_transport = cancelled, holder
                if self._stop.is_set():
                    cancelled.set()
            def send():
                try:
                    holder["outcome"] = self._send(claim, cancelled, holder)
                except Exception:
                    holder["outcome"] = (False, True, "transport_error")
                finally:
                    self._transport_lock.release()
                    finished.set()
            worker = threading.Thread(target=send, name="yuanxingmu-notification-transport", daemon=True)
            worker.start()
            transport_reserved = False
            if not finished.wait(self.config.timeout_seconds):
                cancelled.set()
                self._abort_transport(holder)
                outcome = (False, True, "delivery_timeout")
            else:
                outcome = holder.get("outcome", (False, True, "transport_error"))
            self._complete(claim, outcome)
            return True
        finally:
            with self._lock:
                self._active_cancel = self._active_transport = None
            if transport_reserved:
                self._transport_lock.release()
            self._dispatch_lock.release()

    @staticmethod
    def _abort_transport(holder):
        transport_socket = holder.get("socket") if holder is not None else None
        if transport_socket is not None:
            try:
                transport_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def start(self):
        with self._lock:
            self._healthy()
            if self._stop.is_set():
                raise RuntimeError("notification_queue_stopping")
            if self._worker is not None and self._worker.is_alive():
                return
            def run():
                try:
                    while not self._stop.is_set():
                        self._wake.clear()
                        if not self.dispatch_once():
                            self._wake.wait(.2)
                except Exception:
                    self._worker_error = "notification_worker_failed"
                    self._stop.set()
            self._worker = threading.Thread(target=run, name="yuanxingmu-notification-outbox", daemon=True)
            self._worker.start()

    def close(self):
        with self._lock:
            self._stop.set()
            self._wake.set()
            if self._active_cancel is not None:
                self._active_cancel.set()
            self._abort_transport(self._active_transport)
        if self._worker is not None:
            self._worker.join(timeout=self.config.timeout_seconds + 2)
            if self._worker.is_alive():
                raise RuntimeError("notification_worker_shutdown_pending")
        if not self._dispatch_lock.acquire(timeout=self.config.timeout_seconds + 2):
            raise RuntimeError("notification_dispatch_shutdown_pending")
        try:
            with self._lock:
                if self._closed:
                    return
                self._closed = True
                try:
                    self._db.close()
                finally:
                    os.close(self._directory)
        finally:
            self._dispatch_lock.release()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
