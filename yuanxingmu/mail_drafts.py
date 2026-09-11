"""Private, durable mail drafts in the broker's existing authority database.

This module neither authenticates a human nor sends mail. The broker must expose
submission separately from its host-only review API and hold its own lock across
``begin_send``, one transport attempt, and ``finish_send``. A committed attempt
can never be replaced, even if its result is unknown or mail was not started.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hmac
import re
import uuid

from .authority import Authority, AuthorizationError, _identifier
from .mail_transport import draft_digest, validate_draft


MAX_DRAFTS = 128
MAX_PENDING = 16
MAX_LIST = 50
_KEY = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_OUTCOMES = frozenset({"acknowledged", "unconfirmed", "not_started"})
_PUBLIC_FIELDS = (
    "id", "recipient", "subject", "body", "digest", "revision", "status",
    "created_at", "updated_at", "attempt_id", "account_id", "from_address",
    "approved_at", "finished_at",
)
_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS mail_drafts (
        id TEXT PRIMARY KEY,
        task_id TEXT NOT NULL REFERENCES authority_tasks(id),
        family_id TEXT NOT NULL REFERENCES authority_families(id),
        request_key TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        recipient TEXT NOT NULL,
        subject TEXT NOT NULL,
        body TEXT NOT NULL,
        digest TEXT NOT NULL,
        revision INTEGER NOT NULL CHECK (revision >= 1),
        status TEXT NOT NULL CHECK (status IN
            ('pending','cancelled','sending','acknowledged','unconfirmed','not_started')),
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        attempt_id TEXT UNIQUE,
        account_id TEXT,
        from_address TEXT,
        approved_at TEXT,
        finished_at TEXT,
        UNIQUE (task_id, request_key),
        CHECK (
            (status IN ('pending','cancelled') AND attempt_id IS NULL
                AND account_id IS NULL AND from_address IS NULL AND approved_at IS NULL)
            OR
            (status IN ('sending','acknowledged','unconfirmed','not_started')
                AND attempt_id IS NOT NULL AND account_id IS NOT NULL
                AND from_address IS NOT NULL AND approved_at IS NOT NULL)
        ))""",
    """CREATE INDEX IF NOT EXISTS mail_drafts_task_created
        ON mail_drafts(task_id, created_at DESC)""",
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _key(value, reason: str) -> str:
    if type(value) is not str or not _KEY.fullmatch(value):
        raise AuthorizationError(reason)
    return value


def _canonical(value) -> dict[str, str]:
    try:
        return validate_draft(value)
    except ValueError as exc:
        raise AuthorizationError(str(exc)) from None


def _fingerprint(value) -> str:
    try:
        return draft_digest(value)
    except ValueError as exc:
        raise AuthorizationError(str(exc)) from None


class MailDrafts:
    """A ledger sharing Authority's connection, transactions, and audit ordering.

    Do not call ``recover`` merely because a new wrapper is constructed. Recovery
    is safe only after the broker has acquired exclusive ownership of its state
    directory and knows that no previous transport attempt is still running.
    """

    def __init__(self, authority: Authority):
        self.authority = authority
        with authority._transaction() as db:
            for statement in _SCHEMA:
                db.execute(statement)

    @staticmethod
    def _row(db, task_id: str, draft_id: str):
        if type(draft_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", draft_id):
            raise AuthorizationError("mail_draft_not_found")
        row = db.execute("SELECT * FROM mail_drafts WHERE task_id=? AND id=?",
                         (task_id, draft_id)).fetchone()
        if row is None:
            raise AuthorizationError("mail_draft_not_found")
        return row

    @staticmethod
    def _public(row, *, include_body: bool = True) -> dict:
        return {name: row[name] for name in _PUBLIC_FIELDS if include_body or name != "body"}

    @staticmethod
    def _match(row, revision: int, digest: str) -> None:
        if type(revision) is not int or revision < 1:
            raise AuthorizationError("invalid_mail_revision")
        if type(digest) is not str or not _DIGEST.fullmatch(digest):
            raise AuthorizationError("invalid_mail_digest")
        if row["revision"] != revision or not hmac.compare_digest(row["digest"], digest):
            raise AuthorizationError("mail_draft_changed")

    def _event(self, db, task_id: str, action: str, row) -> None:
        # Content and envelope fields belong only in the private draft table.
        details = {name: row[name] for name in ("id", "digest", "revision", "status")}
        self.authority._event(db, task_id, action, True, action, details)

    def recover(self) -> int:
        """Mark abandoned attempts unconfirmed, preserving their consumed identity."""
        with self.authority._transaction() as db:
            rows = db.execute("SELECT * FROM mail_drafts WHERE status='sending' ORDER BY rowid").fetchall()
            now = _now()
            for row in rows:
                db.execute("UPDATE mail_drafts SET status='unconfirmed',updated_at=?,finished_at=? WHERE id=?",
                           (now, now, row["id"]))
                current = self._row(db, row["task_id"], row["id"])
                self._event(db, row["task_id"], "mail_send_recovered", current)
            return len(rows)

    def submit(self, task_id: str, request_key: str, draft: dict) -> dict:
        def submit(db):
            task = self.authority._task(db, task_id)
            key = _key(request_key, "invalid_mail_request_key")
            canonical = _canonical(draft)
            digest = _fingerprint(canonical)
            previous = db.execute("SELECT * FROM mail_drafts WHERE task_id=? AND request_key=?",
                                  (task_id, key)).fetchone()
            if previous is not None:
                # Editing changes the current digest, never this original request binding.
                if not hmac.compare_digest(previous["request_digest"], digest):
                    raise AuthorizationError("mail_request_conflict")
                return self._public(previous)
            counts = db.execute("SELECT COUNT(*), COALESCE(SUM(status='pending'),0) FROM mail_drafts WHERE task_id=?",
                                (task_id,)).fetchone()
            if counts[0] >= MAX_DRAFTS:
                raise AuthorizationError("mail_draft_limit")
            if counts[1] >= MAX_PENDING:
                raise AuthorizationError("mail_pending_limit")
            identifier, now = uuid.uuid4().hex, _now()
            db.execute("""INSERT INTO mail_drafts
                (id,task_id,family_id,request_key,request_digest,recipient,subject,body,digest,
                 revision,status,created_at,updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,1,'pending',?,?)""",
                (identifier, task_id, task["family_id"], key, digest,
                 canonical["recipient"], canonical["subject"], canonical["body"], digest, now, now))
            row = self._row(db, task_id, identifier)
            self._event(db, task_id, "mail_draft_submitted", row)
            return self._public(row)

        return self.authority._request(task_id, "mail_draft_submit", submit)

    def list(self, task_id: str) -> dict:
        task_id = _identifier(task_id, "task_id")
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id, require_active=False)
            columns = ",".join(name for name in _PUBLIC_FIELDS if name != "body")
            rows = db.execute(f"SELECT {columns} FROM mail_drafts WHERE task_id=? ORDER BY created_at DESC,rowid DESC LIMIT ?",
                              (task_id, MAX_LIST)).fetchall()
            return {"drafts": [self._public(row, include_body=False) for row in rows],
                    "active": not bool(task["revoked"])}

    def get(self, task_id: str, draft_id: str) -> dict:
        task_id = _identifier(task_id, "task_id")
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id, require_active=False)
            row = self._row(db, task_id, draft_id)
            return {"draft": self._public(row), "active": not bool(task["revoked"])}

    def edit(self, task_id: str, draft_id: str, revision: int, digest: str, draft: dict) -> dict:
        def edit(db):
            self.authority._task(db, task_id)
            row = self._row(db, task_id, draft_id)
            self._match(row, revision, digest)
            if row["status"] != "pending":
                raise AuthorizationError("mail_draft_not_pending")
            canonical = _canonical(draft)
            current_digest = _fingerprint(canonical)
            db.execute("""UPDATE mail_drafts SET recipient=?,subject=?,body=?,digest=?,revision=revision+1,updated_at=?
                WHERE id=?""", (canonical["recipient"], canonical["subject"], canonical["body"],
                                current_digest, _now(), draft_id))
            current = self._row(db, task_id, draft_id)
            self._event(db, task_id, "mail_draft_edited", current)
            return self._public(current)

        return self.authority._request(task_id, "mail_draft_edit", edit)

    def cancel(self, task_id: str, draft_id: str, revision: int, digest: str) -> dict:
        def cancel(db):
            self.authority._task(db, task_id)
            row = self._row(db, task_id, draft_id)
            self._match(row, revision, digest)
            if row["status"] != "pending":
                raise AuthorizationError("mail_draft_not_pending")
            now = _now()
            db.execute("UPDATE mail_drafts SET status='cancelled',updated_at=?,finished_at=? WHERE id=?",
                       (now, now, draft_id))
            current = self._row(db, task_id, draft_id)
            self._event(db, task_id, "mail_draft_cancelled", current)
            return self._public(current)

        return self.authority._request(task_id, "mail_draft_cancel", cancel)

    def begin_send(self, task_id: str, draft_id: str, revision: int, digest: str,
                   account_id: str, from_address: str) -> dict:
        """Commit the sole attempt before the caller can invoke its transport.

        Repeating a confirmation only reads an existing attempt. Its account and
        sender remain fixed, including after task revocation or account changes.
        """
        def begin(db):
            self.authority._task(db, task_id, require_active=False)
            row = self._row(db, task_id, draft_id)
            self._match(row, revision, digest)
            if row["attempt_id"] is not None:
                return {"started": False, "draft": self._public(row)}
            self.authority._task(db, task_id)
            if row["status"] != "pending":
                raise AuthorizationError("mail_draft_not_pending")
            account = _key(account_id, "invalid_mail_account_id")
            sender = _canonical({"recipient": from_address, "subject": "", "body": ""})["recipient"]
            now, attempt_id = _now(), uuid.uuid4().hex
            db.execute("""UPDATE mail_drafts SET status='sending',attempt_id=?,account_id=?,from_address=?,
                approved_at=?,updated_at=? WHERE id=?""",
                (attempt_id, account, sender, now, now, draft_id))
            current = self._row(db, task_id, draft_id)
            self._event(db, task_id, "mail_send_started", current)
            return {"started": True, "draft": self._public(current)}

        return self.authority._request(task_id, "mail_send_begin", begin)

    def finish_send(self, task_id: str, draft_id: str, attempt_id: str, outcome: str) -> dict:
        """Record an observation without granting permission for any later attempt."""
        def finish(db):
            self.authority._task(db, task_id, require_active=False)
            row = self._row(db, task_id, draft_id)
            if type(attempt_id) is not str or row["attempt_id"] is None or row["attempt_id"] != attempt_id:
                raise AuthorizationError("mail_attempt_mismatch")
            if type(outcome) is not str or outcome not in _OUTCOMES:
                raise AuthorizationError("invalid_mail_outcome")
            if row["status"] != "sending":
                if row["status"] == outcome:
                    return self._public(row)
                raise AuthorizationError("mail_attempt_finished")
            now = _now()
            db.execute("UPDATE mail_drafts SET status=?,updated_at=?,finished_at=? WHERE id=?",
                       (outcome, now, now, draft_id))
            current = self._row(db, task_id, draft_id)
            self._event(db, task_id, "mail_send_finished", current)
            return self._public(current)

        return self.authority._request(task_id, "mail_send_finish", finish)
