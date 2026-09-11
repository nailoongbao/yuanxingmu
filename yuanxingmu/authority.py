"""Persistent authorization state owned by a trusted broker, outside the model.

Labels accumulate across an entire root task family. Reading through any child
constrains every existing and future family member. Connections are not identities.

This module does not authenticate callers, read resource contents, or send data.
The broker must bind each request to its task and coordinate the interval between
an authorization decision and the external effect. An ``allowed`` result is a
snapshot, not a reusable capability or an atomic network-send operation.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
import sqlite3
import threading
from typing import Callable
import uuid


class AuthorizationError(RuntimeError):
    """A request could not be authorized; ``reason`` is a stable machine code."""

    def __init__(self, reason: str, message: str | None = None):
        self.reason = reason
        super().__init__(message or reason)


_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS authority_meta (version INTEGER NOT NULL)",
    """CREATE TABLE IF NOT EXISTS authority_families (
        id TEXT PRIMARY KEY, revision INTEGER NOT NULL DEFAULT 0)""",
    """CREATE TABLE IF NOT EXISTS authority_tasks (
        id TEXT PRIMARY KEY, family_id TEXT NOT NULL REFERENCES authority_families(id),
        parent_id TEXT REFERENCES authority_tasks(id), revoked INTEGER NOT NULL DEFAULT 0
        CHECK (revoked IN (0, 1)))""",
    """CREATE INDEX IF NOT EXISTS authority_task_parent ON authority_tasks(parent_id)""",
    """CREATE TABLE IF NOT EXISTS authority_resources (
        family_id TEXT NOT NULL REFERENCES authority_families(id), resource_id TEXT NOT NULL,
        labels TEXT NOT NULL, PRIMARY KEY (family_id, resource_id))""",
    """CREATE TABLE IF NOT EXISTS authority_destinations (
        family_id TEXT NOT NULL REFERENCES authority_families(id), destination_id TEXT NOT NULL,
        labels TEXT NOT NULL, PRIMARY KEY (family_id, destination_id))""",
    """CREATE TABLE IF NOT EXISTS authority_resource_grants (
        task_id TEXT NOT NULL REFERENCES authority_tasks(id), resource_id TEXT NOT NULL,
        PRIMARY KEY (task_id, resource_id))""",
    """CREATE TABLE IF NOT EXISTS authority_destination_grants (
        task_id TEXT NOT NULL REFERENCES authority_tasks(id), destination_id TEXT NOT NULL,
        PRIMARY KEY (task_id, destination_id))""",
    """CREATE TABLE IF NOT EXISTS authority_labels (
        family_id TEXT NOT NULL REFERENCES authority_families(id), label TEXT NOT NULL,
        PRIMARY KEY (family_id, label))""",
    """CREATE TABLE IF NOT EXISTS authority_events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT NOT NULL,
        action TEXT NOT NULL, allowed INTEGER NOT NULL, reason TEXT NOT NULL,
        details TEXT NOT NULL, created_at TEXT NOT NULL)""",
    """CREATE INDEX IF NOT EXISTS authority_event_task ON authority_events(task_id, event_id)""",
)


def _identifier(value, kind: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise AuthorizationError("invalid_" + kind, kind + " must be a nonempty string")
    return value


def _identifiers(value, kind: str) -> list[str]:
    if not isinstance(value, list):
        raise AuthorizationError("invalid_" + kind, kind + " must be a list of strings")
    return sorted({_identifier(item, kind) for item in value})


def _policy(value, kind: str) -> dict[str, list[str]]:
    if not isinstance(value, dict):
        raise AuthorizationError("invalid_" + kind, kind + " must map identifiers to label lists")
    return {_identifier(key, kind): _identifiers(labels, "label") for key, labels in value.items()}


class Authority:
    """A SQLite task ledger; safe to share across threads and reopen on the same DB.

    All decisions and updates use ``BEGIN IMMEDIATE``, including across separate
    Authority instances. Label checks, revocation checks, and their audit events
    therefore have one committed order. Keep the DB and this object trusted.
    """

    def __init__(self, db_path: str | os.PathLike[str]):
        self._lock = threading.RLock()
        self._closed = False
        self._db = sqlite3.connect(os.fspath(db_path), timeout=30, isolation_level=None,
                                   check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        try:
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.execute("PRAGMA synchronous = FULL")
            with self._transaction() as db:
                for statement in _SCHEMA:
                    db.execute(statement)
                versions = db.execute("SELECT version FROM authority_meta").fetchall()
                if not versions:
                    db.execute("INSERT INTO authority_meta(version) VALUES (1)")
                elif len(versions) != 1 or versions[0]["version"] != 1:
                    raise AuthorizationError("unsupported_schema")
        except BaseException:
            self._db.close()
            self._closed = True
            raise

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._db.close()
                self._closed = True

    def __enter__(self) -> Authority:
        with self._lock:
            if self._closed:
                raise AuthorizationError("authority_closed")
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    @contextmanager
    def _transaction(self):
        with self._lock:
            if self._closed:
                raise AuthorizationError("authority_closed")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    @staticmethod
    def _event(db, task_id: str, action: str, allowed: bool, reason: str, details: dict) -> int:
        cursor = db.execute(
            "INSERT INTO authority_events(task_id,action,allowed,reason,details,created_at) VALUES (?,?,?,?,?,?)",
            (task_id, action, int(allowed), reason, json.dumps(details, sort_keys=True),
             datetime.now(timezone.utc).isoformat()),
        )
        return cursor.lastrowid

    def _request(self, task_id: str, action: str, operation: Callable):
        task_id = _identifier(task_id, "task_id")
        denied = None
        with self._transaction() as db:
            # A denial has its own committed event, but cannot commit any partial
            # grant/label mutation made by the rejected operation.
            db.execute("SAVEPOINT authority_request")
            try:
                result = operation(db)
            except AuthorizationError as exc:
                db.execute("ROLLBACK TO authority_request")
                denied = exc
                self._event(db, task_id, action, False, exc.reason, {})
            finally:
                db.execute("RELEASE authority_request")
        if denied is not None:
            raise denied
        return result

    @staticmethod
    def _task(db, task_id: str, *, require_active: bool = True):
        task = db.execute("SELECT * FROM authority_tasks WHERE id = ?", (task_id,)).fetchone()
        if task is None:
            raise AuthorizationError("unknown_task")
        if require_active and task["revoked"]:
            raise AuthorizationError("task_revoked")
        return task

    @staticmethod
    def _labels(db, family_id: str) -> list[str]:
        return [row[0] for row in db.execute(
            "SELECT label FROM authority_labels WHERE family_id = ? ORDER BY label", (family_id,))]

    @staticmethod
    def _revision(db, family_id: str, *, advance: bool = False) -> int:
        if advance:
            db.execute("UPDATE authority_families SET revision = revision + 1 WHERE id = ?", (family_id,))
        return db.execute("SELECT revision FROM authority_families WHERE id = ?", (family_id,)).fetchone()[0]

    @staticmethod
    def _grants(db, task_id: str, kind: str) -> list[str]:
        # kind is a module-owned constant, never request text.
        return [row[0] for row in db.execute(
            f"SELECT {kind}_id FROM authority_{kind}_grants WHERE task_id = ? ORDER BY {kind}_id", (task_id,))]

    def create_root(self, resources: dict[str, list[str]], destinations: dict[str, list[str]],
                    *, task_id: str | None = None) -> str:
        """Trusted configuration only. Labels are exact sets, with no wildcard semantics."""
        resources = _policy(resources, "resource_id")
        destinations = _policy(destinations, "destination_id")
        task_id = _identifier(task_id, "task_id") if task_id is not None else "task_" + uuid.uuid4().hex

        def create(db):
            if db.execute("SELECT 1 FROM authority_tasks WHERE id = ?", (task_id,)).fetchone():
                raise AuthorizationError("task_already_exists")
            # Internal family identity is separate from every callable task ID.
            family_id = uuid.uuid4().hex
            db.execute("INSERT INTO authority_families(id) VALUES (?)", (family_id,))
            db.execute("INSERT INTO authority_tasks(id,family_id) VALUES (?,?)", (task_id, family_id))
            for kind, mapping in (("resource", resources), ("destination", destinations)):
                db.executemany(f"INSERT INTO authority_{kind}s(family_id,{kind}_id,labels) VALUES (?,?,?)",
                               [(family_id, name, json.dumps(labels)) for name, labels in mapping.items()])
                db.executemany(f"INSERT INTO authority_{kind}_grants(task_id,{kind}_id) VALUES (?,?)",
                               [(task_id, name) for name in mapping])
            self._event(db, task_id, "create_root", True, "root_created",
                        {"resources": resources, "destinations": destinations, "revision": 0})
            return task_id

        return self._request(task_id, "create_root", create)

    def delegate(self, task_id: str, *, resources: list[str] | None = None,
                 destinations: list[str] | None = None) -> str:
        """Create a child with a subset of its parent's grants; None inherits all."""
        def create(db):
            parent = self._task(db, task_id)
            grants = {}
            for kind, requested in (("resource", resources), ("destination", destinations)):
                available = self._grants(db, task_id, kind)
                selected = available if requested is None else _identifiers(requested, kind + "_id")
                if not set(selected).issubset(available):
                    raise AuthorizationError("delegation_would_expand_" + kind + "s")
                grants[kind] = selected
            child_id = "task_" + uuid.uuid4().hex
            db.execute("INSERT INTO authority_tasks(id,family_id,parent_id) VALUES (?,?,?)",
                       (child_id, parent["family_id"], task_id))
            for kind, names in grants.items():
                db.executemany(f"INSERT INTO authority_{kind}_grants(task_id,{kind}_id) VALUES (?,?)",
                               [(child_id, name) for name in names])
            revision = self._revision(db, parent["family_id"], advance=True)
            self._event(db, task_id, "delegate", True, "child_created",
                        {"child_task_id": child_id, "resources": grants["resource"],
                         "destinations": grants["destination"], "revision": revision})
            return child_id

        return self._request(task_id, "delegate", create)

    def record_read(self, task_id: str, resource_id: str) -> dict:
        """Commit family labels before the broker returns any resource contents.

        If a subsequent resource fetch fails, these conservative labels remain.
        Model-controlled inputs cannot supply, replace, or clear labels.
        """
        def record(db):
            task = self._task(db, task_id)
            _identifier(resource_id, "resource_id")
            resource = db.execute("SELECT labels FROM authority_resources WHERE family_id=? AND resource_id=?",
                                  (task["family_id"], resource_id)).fetchone()
            if resource is None:
                raise AuthorizationError("unknown_resource")
            if resource_id not in self._grants(db, task_id, "resource"):
                raise AuthorizationError("resource_not_granted")
            resource_labels = json.loads(resource["labels"])
            db.executemany("INSERT OR IGNORE INTO authority_labels(family_id,label) VALUES (?,?)",
                           [(task["family_id"], label) for label in resource_labels])
            result = {"allowed": True, "reason": "read_authorized", "task_id": task_id,
                      "resource_id": resource_id, "resource_labels": resource_labels,
                      "labels": self._labels(db, task["family_id"]),
                      "revision": self._revision(db, task["family_id"], advance=True)}
            result["event_id"] = self._event(db, task_id, "record_read", True, result["reason"], result)
            return result

        return self._request(task_id, "record_read", record)

    def authorize_send(self, task_id: str, destination_id: str) -> dict:
        """Check current family labels against a granted destination's accepted labels."""
        def authorize(db):
            task = self._task(db, task_id)
            _identifier(destination_id, "destination_id")
            destination = db.execute(
                "SELECT labels FROM authority_destinations WHERE family_id=? AND destination_id=?",
                (task["family_id"], destination_id)).fetchone()
            if destination is None:
                raise AuthorizationError("unknown_destination")
            if destination_id not in self._grants(db, task_id, "destination"):
                raise AuthorizationError("destination_not_granted")
            labels = self._labels(db, task["family_id"])
            blocked = sorted(set(labels) - set(json.loads(destination["labels"])))
            result = {"allowed": not blocked,
                      "reason": "destination_cannot_receive_labels" if blocked else "send_authorized",
                      "task_id": task_id, "destination_id": destination_id, "labels": labels,
                      "blocked_labels": blocked, "revision": self._revision(db, task["family_id"])}
            result["event_id"] = self._event(db, task_id, "authorize_send", result["allowed"], result["reason"], result)
            return result

        return self._request(task_id, "authorize_send", authorize)

    def describe(self, task_id: str) -> dict:
        """Inspect a task, including revoked tasks; no ancestor callable IDs are exposed."""
        task_id = _identifier(task_id, "task_id")
        with self._transaction() as db:
            task = self._task(db, task_id, require_active=False)
            result = {"task_id": task_id, "active": not bool(task["revoked"]), "revoked": bool(task["revoked"]),
                      "labels": self._labels(db, task["family_id"]),
                      "revision": self._revision(db, task["family_id"])}
            for kind in ("resource", "destination"):
                result[kind + "s"] = {row[0]: json.loads(row[1]) for row in db.execute(
                    f"SELECT p.{kind}_id,p.labels FROM authority_{kind}s p "
                    f"JOIN authority_{kind}_grants g ON g.{kind}_id=p.{kind}_id "
                    "WHERE p.family_id=? AND g.task_id=? ORDER BY 1", (task["family_id"], task_id))}
            return result

    def revoke(self, task_id: str) -> None:
        """Revoke this task and its entire existing subtree atomically; idempotent."""
        def revoke_subtree(db):
            task = self._task(db, task_id, require_active=False)
            db.execute("""WITH RECURSIVE descendants(id) AS (
                SELECT id FROM authority_tasks WHERE id=? UNION ALL
                SELECT t.id FROM authority_tasks t JOIN descendants d ON t.parent_id=d.id)
                UPDATE authority_tasks SET revoked=1 WHERE id IN (SELECT id FROM descendants)""", (task_id,))
            revision = self._revision(db, task["family_id"], advance=True)
            self._event(db, task_id, "revoke", True, "subtree_revoked", {"revision": revision})

        self._request(task_id, "revoke", revoke_subtree)

    def events(self, task_id: str) -> list[dict]:
        """Ordered audit for this task and its descendants, including after revocation."""
        task_id = _identifier(task_id, "task_id")
        with self._transaction() as db:
            self._task(db, task_id, require_active=False)
            rows = db.execute("""WITH RECURSIVE descendants(id) AS (
                SELECT id FROM authority_tasks WHERE id=? UNION ALL
                SELECT t.id FROM authority_tasks t JOIN descendants d ON t.parent_id=d.id)
                SELECT e.* FROM authority_events e JOIN descendants d ON e.task_id=d.id ORDER BY e.event_id""",
                              (task_id,)).fetchall()
            return [{**dict(row), "allowed": bool(row["allowed"]), "details": json.loads(row["details"])}
                    for row in rows]
