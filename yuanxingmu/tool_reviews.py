"""Host-owned, expiring approvals for one exact native tool invocation.

The agent-facing API can request and consume, never approve. Consumption is
committed before execution; a lost reply or failed command is not replayable.
This approves one invocation inside the existing isolation boundary, not code
referenced by mutable paths or any additional network or document permission.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid

from .authority import AuthorizationError

_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


def candidate(tool, arguments):
    if type(tool) is not str or not _KEY.fullmatch(tool) or type(arguments) is not dict:
        raise AuthorizationError("invalid_tool_review_candidate")
    try:
        raw = json.dumps({"tool": tool, "arguments": arguments}, sort_keys=True,
                         ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        if len(raw.encode("utf-8")) > 262144:
            raise ValueError
        return raw
    except (ValueError, TypeError, UnicodeError):
        raise AuthorizationError("invalid_tool_review_candidate") from None


class ToolReviews:
    def __init__(self, authority, *, clock=time.time):
        self.authority, self.clock = authority, clock
        with authority._transaction() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS tool_reviews (
                id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES authority_tasks(id),
                request_key TEXT NOT NULL, candidate TEXT NOT NULL, digest TEXT NOT NULL,
                reason TEXT NOT NULL, status TEXT NOT NULL, created_at REAL NOT NULL,
                expires_at REAL NOT NULL, decided_at REAL, consumed_at REAL,
                UNIQUE(task_id,request_key))""")

    def recover(self):
        # The exclusive broker lock prevents competing approval services. It
        # does not prove an executor stopped; a consumed permit stays consumed.
        # A new service lifecycle cannot inherit an outstanding approval.
        with self.authority._transaction() as db:
            db.execute("UPDATE tool_reviews SET status='interrupted' WHERE status IN ('pending','approved')")

    def _expire(self, db, task_id):
        db.execute("UPDATE tool_reviews SET status='expired' WHERE task_id=? AND expires_at<=? AND status IN ('pending','approved')",
                   (task_id, self.clock()))

    def _row(self, db, task_id, review_id, digest=None):
        if type(review_id) is not str or not _ID.fullmatch(review_id):
            raise AuthorizationError("invalid_tool_review_id")
        row = db.execute("SELECT * FROM tool_reviews WHERE id=? AND task_id=?", (review_id, task_id)).fetchone()
        if row is None:
            raise AuthorizationError("tool_review_not_found")
        if digest is not None and (type(digest) is not str or not _DIGEST.fullmatch(digest) or digest != row["digest"]):
            raise AuthorizationError("tool_review_changed")
        return row

    @staticmethod
    def _public(row, *, full=False):
        result = {key: row[key] for key in ("id", "digest", "status", "reason", "created_at", "expires_at", "decided_at", "consumed_at")}
        if full:
            result.update(json.loads(row["candidate"]))
        else:
            result["tool"] = json.loads(row["candidate"])["tool"]
        return result

    def request(self, task_id, request_key, tool, arguments, *, reason, blocked=False):
        if type(request_key) is not str or not _KEY.fullmatch(request_key):
            raise AuthorizationError("invalid_tool_review_request")
        raw = candidate(tool, arguments)
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id)
            self._expire(db, task_id)
            prior = db.execute("SELECT * FROM tool_reviews WHERE task_id=? AND request_key=?", (task_id, request_key)).fetchone()
            if prior is not None:
                if prior["candidate"] != raw:
                    raise AuthorizationError("tool_review_request_conflict")
                return {"allowed": False, "review_id": prior["id"], "digest": prior["digest"], "status": prior["status"]}
            if db.execute("SELECT count(*) FROM tool_reviews WHERE task_id=?", (task_id,)).fetchone()[0] >= 2048:
                raise AuthorizationError("tool_review_limit")
            review_id, now = uuid.uuid4().hex, self.clock()
            status = "blocked" if blocked else "pending"
            digest = hashlib.sha256(json.dumps(["yxm-tool-review-v1", task["family_id"], task_id, review_id, raw],
                                              ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
            db.execute("INSERT INTO tool_reviews(id,task_id,request_key,candidate,digest,reason,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       (review_id, task_id, request_key, raw, digest, str(reason)[:1000], status, now, now + 300))
            self.authority._event(db, task_id, "tool_review_request", False, "guard_blocked" if blocked else "human_confirmation_required", {"review_id": review_id, "digest": digest})
            return {"allowed": False, "review_id": review_id, "digest": digest, "status": status}

    def prior(self, task_id, request_key, tool, arguments):
        if type(request_key) is not str or not _KEY.fullmatch(request_key):
            raise AuthorizationError("invalid_tool_review_request")
        raw = candidate(tool, arguments)
        with self.authority._transaction() as db:
            self.authority._task(db, task_id, require_active=False)
            self._expire(db, task_id)
            row = db.execute("SELECT * FROM tool_reviews WHERE task_id=? AND request_key=?", (task_id, request_key)).fetchone()
            if row is None:
                return None
            if row["candidate"] != raw:
                raise AuthorizationError("tool_review_request_conflict")
            return {"allowed": False, "review_id": row["id"], "digest": row["digest"], "status": row["status"]}

    def list(self, task_id):
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id, require_active=False)
            self._expire(db, task_id)
            rows = db.execute("SELECT * FROM tool_reviews WHERE task_id=? ORDER BY rowid DESC LIMIT 100", (task_id,)).fetchall()
            return {"reviews": [self._public(row) for row in rows], "active": not bool(task["revoked"])}

    def get(self, task_id, review_id):
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id, require_active=False)
            self._expire(db, task_id)
            return {"review": self._public(self._row(db, task_id, review_id), full=True), "active": not bool(task["revoked"])}

    def decide(self, task_id, review_id, digest, decision):
        if decision not in {"approve", "deny"}:
            raise AuthorizationError("invalid_tool_review_decision")
        with self.authority._transaction() as db:
            self.authority._task(db, task_id)
            self._expire(db, task_id)
            row = self._row(db, task_id, review_id, digest)
            if row["status"] == "pending":
                status = "approved" if decision == "approve" else "denied"
                db.execute("UPDATE tool_reviews SET status=?,decided_at=? WHERE id=?", (status, self.clock(), review_id))
                self.authority._event(db, task_id, "tool_review_decision", decision == "approve", status,
                                      {"review_id": review_id, "digest": digest})
            return {"review": self._public(self._row(db, task_id, review_id), full=True)}

    def consume(self, task_id, review_id, digest, tool, arguments):
        raw = candidate(tool, arguments)
        with self.authority._transaction() as db:
            self.authority._task(db, task_id)
            self._expire(db, task_id)
            row = self._row(db, task_id, review_id, digest)
            if row["candidate"] != raw:
                raise AuthorizationError("tool_review_candidate_changed")
            allowed = row["status"] == "approved"
            status = "consumed" if allowed else row["status"]
            if allowed:
                db.execute("UPDATE tool_reviews SET status='consumed',consumed_at=? WHERE id=?", (self.clock(), review_id))
                self.authority._event(db, task_id, "tool_review_consume", True, "single_invocation_consumed", {"review_id": review_id, "digest": digest})
            return {"allowed": allowed, "review_id": review_id, "digest": digest, "status": status}
