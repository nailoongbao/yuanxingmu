"""Durable task-family pauses in the host's existing Authority database.

The caller authenticates the operator and keeps ``resume`` off every worker
socket. A string such as ``operator='workbench'`` is audit metadata, not proof
of identity. ``assert_admission`` belongs in Authority's active-task check so
the pause and each new permission are ordered by the same SQLite transaction.

Pausing invalidates unused reviews and drafts. It cannot recall a consumed
permit, undo an external effect, or stop a native tool which already passed
its check. Those facts remain in their original ledgers. No chat message,
timer, process restart, or notification delivery clears a pause.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import re
import uuid

from .authority import Authority, AuthorizationError, _identifier


_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,96}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_INCIDENT = re.compile(r"[0-9a-f]{32}\Z")
MAX_LIST = 100
_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS quarantine_families (
        family_id TEXT PRIMARY KEY REFERENCES authority_families(id),
        state TEXT NOT NULL CHECK (state IN ('active','paused')),
        epoch INTEGER NOT NULL CHECK (epoch >= 1),
        last_incident_id TEXT NOT NULL,
        updated_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS quarantine_incidents (
        id TEXT PRIMARY KEY,
        family_id TEXT NOT NULL REFERENCES authority_families(id),
        task_id TEXT NOT NULL REFERENCES authority_tasks(id),
        epoch INTEGER NOT NULL CHECK (epoch >= 1),
        fingerprint TEXT NOT NULL,
        layer TEXT NOT NULL, code TEXT NOT NULL, reason TEXT NOT NULL,
        evidence_sha256 TEXT,
        invalidated_json TEXT NOT NULL, admitted_json TEXT NOT NULL,
        created_at TEXT NOT NULL, resolved_at TEXT, resolved_by TEXT,
        UNIQUE(family_id,epoch),
        CHECK ((resolved_at IS NULL AND resolved_by IS NULL)
            OR (resolved_at IS NOT NULL AND resolved_by IS NOT NULL)))""",
    """CREATE INDEX IF NOT EXISTS quarantine_incidents_family_epoch
        ON quarantine_incidents(family_id,epoch DESC)""",
    """CREATE UNIQUE INDEX IF NOT EXISTS quarantine_incidents_open_fingerprint
        ON quarantine_incidents(family_id,fingerprint) WHERE resolved_at IS NULL""",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table_exists(db, table: str) -> bool:
    return db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None


def assert_admission(db, task_row) -> None:
    """Check within the caller's transaction; do not cache this decision.

Legacy Authority databases without this optional feature have no pause table.
The host must construct Quarantine before exposing a protected worker socket.
Malformed state and database failures propagate; they never imply permission.
    """
    if task_row["revoked"]:
        raise AuthorizationError("task_revoked")
    if not _table_exists(db, "quarantine_families"):
        return
    row = db.execute("SELECT state FROM quarantine_families WHERE family_id=?", (task_row["family_id"],)).fetchone()
    if row is None:
        return
    if row["state"] == "paused":
        raise AuthorizationError("task_paused", "发现可疑内容，任务已暂停。请在元星木工作台核对后恢复。")
    if row["state"] != "active":
        raise AuthorizationError("invalid_quarantine_state")


def _token(value, code: str) -> str:
    if type(value) is not str or not _TOKEN.fullmatch(value):
        raise AuthorizationError(code)
    return value


def _reason(value) -> str:
    if type(value) is not str or not value.strip():
        raise AuthorizationError("invalid_quarantine_reason")
    # This is a bounded explanation, never raw candidate content or a command.
    cleaned = "".join(c for c in value.strip() if ord(c) >= 32 or c in "\n\t")[:1000]
    if not cleaned.strip():
        raise AuthorizationError("invalid_quarantine_reason")
    return cleaned


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Quarantine:
    """Pause an entire task family; only a host review may resume it."""

    def __init__(self, authority: Authority):
        self.authority = authority
        with authority._transaction() as db:
            for statement in _SCHEMA:
                db.execute(statement)

    def _task(self, db, task_id):
        # require_active=False avoids a recursive quarantine check and allows
        # the host to inspect a pause after permanent revocation.
        return self.authority._task(db, task_id, require_active=False)

    @staticmethod
    def _admitted(db, family_id) -> dict:
        counts = {"consumed_tool_permits": 0, "sending_mail": 0, "executing_actions": 0}
        for table, status, key in (
            ("tool_reviews", "consumed", "consumed_tool_permits"),
            ("mail_drafts", "sending", "sending_mail"),
            ("reviewed_actions", "executing", "executing_actions"),
        ):
            if _table_exists(db, table):
                counts[key] = db.execute(
                    f"SELECT count(*) FROM {table} WHERE status=? AND task_id IN "
                    "(SELECT id FROM authority_tasks WHERE family_id=?)", (status, family_id)).fetchone()[0]
        return counts

    @staticmethod
    def _invalidate(db, family_id, now) -> dict:
        invalidated = {"tool_reviews": 0, "mail_drafts": 0, "reviewed_actions": 0}
        if _table_exists(db, "tool_reviews"):
            invalidated["tool_reviews"] = db.execute(
                "UPDATE tool_reviews SET status='interrupted' WHERE status IN ('pending','approved') "
                "AND task_id IN (SELECT id FROM authority_tasks WHERE family_id=?)", (family_id,)).rowcount
        for table in ("mail_drafts", "reviewed_actions"):
            if _table_exists(db, table):
                invalidated[table] = db.execute(
                    f"UPDATE {table} SET status='cancelled',updated_at=?,finished_at=? WHERE status='pending' "
                    "AND task_id IN (SELECT id FROM authority_tasks WHERE family_id=?)", (now, now, family_id)).rowcount
        return invalidated

    @staticmethod
    def _incident(row) -> dict:
        # Callable task/family IDs and raw candidate contents stay host-private.
        value = {key: row[key] for key in (
            "id", "epoch", "layer", "code", "reason", "evidence_sha256", "created_at", "resolved_at", "resolved_by")}
        value["invalidated"] = json.loads(row["invalidated_json"])
        value["admitted_effects"] = json.loads(row["admitted_json"])
        return value

    def _status(self, db, task) -> dict:
        state = db.execute("SELECT * FROM quarantine_families WHERE family_id=?", (task["family_id"],)).fetchone()
        if state is None:
            return {"scope": "task_family", "state": "active", "paused": False,
                    "revoked": bool(task["revoked"]), "can_resume": False, "epoch": 0,
                    "incident_id": None, "updated_at": None, "incident": None,
                    "unresolved_count": 0, "incidents": [], "has_more": False,
                    "admitted_effects": self._admitted(db, task["family_id"])}
        row = db.execute("SELECT * FROM quarantine_incidents WHERE id=? AND family_id=?",
                         (state["last_incident_id"], task["family_id"])).fetchone()
        if row is None or state["state"] not in {"active", "paused"}:
            raise AuthorizationError("invalid_quarantine_state")
        rows = db.execute("SELECT * FROM quarantine_incidents WHERE family_id=? ORDER BY epoch DESC LIMIT ?",
                          (task["family_id"], MAX_LIST + 1)).fetchall()
        unresolved = db.execute("SELECT count(*) FROM quarantine_incidents WHERE family_id=? AND resolved_at IS NULL",
                                (task["family_id"],)).fetchone()[0]
        paused = state["state"] == "paused"
        if paused != bool(unresolved) or (paused and row["resolved_at"] is not None):
            raise AuthorizationError("invalid_quarantine_state")
        return {"scope": "task_family", "state": state["state"], "paused": paused,
                "revoked": bool(task["revoked"]),
                "can_resume": paused and not task["revoked"] and task["parent_id"] is None,
                "epoch": state["epoch"], "incident_id": state["last_incident_id"],
                "updated_at": state["updated_at"], "incident": self._incident(row),
                "unresolved_count": unresolved, "incidents": [self._incident(r) for r in rows[:MAX_LIST]],
                "has_more": len(rows) > MAX_LIST, "admitted_effects": self._admitted(db, task["family_id"])}

    def status(self, task_id: str) -> dict:
        """Return a bounded host view, including while paused or revoked."""
        task_id = _identifier(task_id, "task_id")
        with self.authority._transaction() as db:
            return self._status(db, self._task(db, task_id))

    def pause(self, task_id: str, *, layer: str, code: str, reason: str,
              evidence_sha256: str | None = None) -> dict:
        """Commit the pause, invalidate unused approvals, and audit atomically.

An identical unresolved observation is deduplicated within the current pause
cycle. New evidence or a new reason advances the epoch, so a stale review page
cannot release the new incident. After resume, the same evidence pauses anew.
        """
        task_id = _identifier(task_id, "task_id")
        layer = _token(layer, "invalid_quarantine_layer")
        code = _token(code, "invalid_quarantine_code")
        reason = _reason(reason)
        if evidence_sha256 is not None and (type(evidence_sha256) is not str or not _DIGEST.fullmatch(evidence_sha256)):
            raise AuthorizationError("invalid_quarantine_evidence")
        fingerprint = hashlib.sha256(_json([task_id, layer, code, reason, evidence_sha256]).encode("utf-8")).hexdigest()
        with self.authority._transaction() as db:
            task = self._task(db, task_id)
            if task["revoked"]:
                raise AuthorizationError("task_revoked")
            current = db.execute("SELECT * FROM quarantine_families WHERE family_id=?", (task["family_id"],)).fetchone()
            existing = db.execute("SELECT id FROM quarantine_incidents WHERE family_id=? AND fingerprint=? AND resolved_at IS NULL",
                                  (task["family_id"], fingerprint)).fetchone()
            if existing is not None:
                if current is None or current["state"] != "paused":
                    raise AuthorizationError("invalid_quarantine_state")
                return {**self._status(db, task), "deduplicated": True, "observed_incident_id": existing["id"]}
            if current is not None:
                # Check state consistency before any mutation could mask it.
                self._status(db, task)
            epoch = (current["epoch"] if current is not None else 0) + 1
            incident_id, now = uuid.uuid4().hex, _now()
            invalidated = self._invalidate(db, task["family_id"], now)
            admitted = self._admitted(db, task["family_id"])
            db.execute("""INSERT INTO quarantine_incidents
                (id,family_id,task_id,epoch,fingerprint,layer,code,reason,evidence_sha256,
                 invalidated_json,admitted_json,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (incident_id, task["family_id"], task_id, epoch, fingerprint, layer, code, reason,
                 evidence_sha256, _json(invalidated), _json(admitted), now))
            db.execute("""INSERT INTO quarantine_families(family_id,state,epoch,last_incident_id,updated_at)
                VALUES (?,'paused',?,?,?) ON CONFLICT(family_id) DO UPDATE SET
                state='paused',epoch=excluded.epoch,last_incident_id=excluded.last_incident_id,updated_at=excluded.updated_at""",
                (task["family_id"], epoch, incident_id, now))
            revision = self.authority._revision(db, task["family_id"], advance=True)
            self.authority._event(db, task_id, "quarantine_pause", False, code,
                {"epoch": epoch, "incident_id": incident_id, "layer": layer, "revision": revision,
                 "evidence_sha256": evidence_sha256, "invalidated": invalidated, "admitted_effects": admitted})
            return {**self._status(db, task), "deduplicated": False, "observed_incident_id": incident_id}

    def resume(self, task_id: str, *, epoch: int, incident_id: str, confirm: str,
               operator: str = "workbench") -> dict:
        """Host-only exact review. Existing drafts/approvals never reactivate.

The operator must review the current host snapshot. ``epoch`` and incident ID
bind that snapshot, not operator identity; the caller must authenticate the
human separately. A child task cannot authorize family-wide recovery.
        """
        task_id = _identifier(task_id, "task_id")
        if type(epoch) is not int or epoch < 1 or type(incident_id) is not str or not _INCIDENT.fullmatch(incident_id):
            raise AuthorizationError("invalid_quarantine_review")
        if confirm != "resume":
            raise AuthorizationError("quarantine_confirmation_required")
        operator = _token(operator, "invalid_quarantine_operator")
        with self.authority._transaction() as db:
            task = self._task(db, task_id)
            if task["revoked"]:
                raise AuthorizationError("task_revoked")
            if task["parent_id"] is not None:
                raise AuthorizationError("quarantine_root_review_required")
            current = self._status(db, task)
            if not current["paused"]:
                raise AuthorizationError("task_not_paused")
            if current["epoch"] != epoch or not hmac.compare_digest(current["incident_id"], incident_id):
                raise AuthorizationError("quarantine_review_changed")
            now = _now()
            db.execute("UPDATE quarantine_incidents SET resolved_at=?,resolved_by=? WHERE family_id=? AND resolved_at IS NULL",
                       (now, operator, task["family_id"]))
            db.execute("UPDATE quarantine_families SET state='active',epoch=epoch+1,updated_at=? WHERE family_id=?",
                       (now, task["family_id"]))
            revision = self.authority._revision(db, task["family_id"], advance=True)
            self.authority._event(db, task_id, "quarantine_resume", True, "host_reviewed_current_incidents",
                {"epoch": epoch + 1, "reviewed_epoch": epoch, "incident_id": incident_id,
                 "operator": operator, "resolved_count": current["unresolved_count"], "revision": revision})
            return self._status(db, task)
