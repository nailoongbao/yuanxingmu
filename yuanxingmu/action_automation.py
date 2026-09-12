"""Host-frozen automatic action scope and durable task-family attempt budgets.

This is authorization, not a model verdict. The host binds the policy when it
creates a root task and grants the reserved destinations through Authority.
An agent cannot install policies, reset budgets, declassify labels, or call the
transaction helper. A broker must hold its management lock through the one I/O
attempt. Reopening a ledger never retries an attempt or refunds its budget.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import json
from types import MappingProxyType

from .actions import ActionTarget, MAX_ACTIONS, _digest, _has_prior_unconfirmed_action, _json, _KEY
from .authority import Authority, AuthorizationError, _identifier, _identifiers


AUTOMATIC_KINDS = frozenset({"message", "upload", "form"})
MAX_BODY_BYTES = 1024 * 1024
DESTINATION_PREFIX = "action:"
PENDING_REASONS = frozenset({
    "automatic_family_not_bound", "automatic_target_not_granted", "automatic_kind_requires_review",
    "automatic_edited_action_requires_review", "automatic_action_too_large",
    "automatic_attempt_budget_exhausted", "automatic_body_budget_exhausted", "destination_not_granted",
    "automatic_prior_outcome_unconfirmed",
})


def _integer(value, minimum, maximum, reason):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(reason)
    return value


@dataclass(frozen=True, slots=True)
class AutomaticActionGrant:
    target_id: str
    kind: str
    binding_digest: str
    destination_id: str
    accepted_labels: tuple[str, ...]
    max_body_bytes: int

    def binding(self):
        return {"target_id": self.target_id, "kind": self.kind, "binding_digest": self.binding_digest,
                "destination_id": self.destination_id, "accepted_labels": list(self.accepted_labels),
                "max_body_bytes": self.max_body_bytes}


@dataclass(frozen=True, slots=True, init=False)
class AutomaticActionPolicy:
    max_attempts: int
    max_total_body_bytes: int
    grants: object

    @classmethod
    def from_config(cls, value, targets):
        """Construct only from trusted host settings and registered ActionTargets."""
        if type(value) is not dict or set(value) != {"version", "max_attempts", "max_total_body_bytes", "targets"}:
            raise ValueError("invalid_automatic_action_policy")
        if type(value["version"]) is not int or value["version"] != 1:
            raise ValueError("invalid_automatic_action_policy_version")
        attempts = _integer(value["max_attempts"], 1, MAX_ACTIONS, "invalid_automatic_attempt_budget")
        total = _integer(value["max_total_body_bytes"], 1, MAX_BODY_BYTES * MAX_ACTIONS, "invalid_automatic_body_budget")
        if type(targets) is not dict or type(value["targets"]) is not dict or not 1 <= len(value["targets"]) <= 128:
            raise ValueError("invalid_automatic_action_targets")
        grants = {}
        for target_id, scope in value["targets"].items():
            if type(target_id) is not str or not _KEY.fullmatch(target_id):
                raise ValueError("invalid_automatic_target_id")
            target = targets.get(target_id)
            if not isinstance(target, ActionTarget) or target.kind not in AUTOMATIC_KINDS:
                raise ValueError("automatic_target_must_be_registered_network_action")
            if type(scope) is not dict or set(scope) != {"accepted_labels", "max_body_bytes"}:
                raise ValueError("invalid_automatic_target_scope")
            try:
                labels = _identifiers(scope["accepted_labels"], "label")
            except AuthorizationError:
                raise ValueError("invalid_automatic_target_labels") from None
            if len(labels) > 32 or any(len(label.encode("utf-8")) > 128 for label in labels):
                raise ValueError("invalid_automatic_target_labels")
            maximum = _integer(scope["max_body_bytes"], 1, MAX_BODY_BYTES, "invalid_automatic_action_byte_limit")
            grants[target_id] = AutomaticActionGrant(target_id, target.kind, _digest(target.binding()),
                DESTINATION_PREFIX + target_id, tuple(labels), maximum)
        result = object.__new__(cls)
        object.__setattr__(result, "max_attempts", attempts)
        object.__setattr__(result, "max_total_body_bytes", total)
        object.__setattr__(result, "grants", MappingProxyType(grants))
        return result

    def destination_labels(self):
        """Reserved Authority destinations; never add a second transport for them."""
        return {grant.destination_id: list(grant.accepted_labels) for grant in self.grants.values()}

    def to_config(self):
        return {"version": 1, "max_attempts": self.max_attempts, "max_total_body_bytes": self.max_total_body_bytes,
                "targets": {key: {"accepted_labels": list(grant.accepted_labels), "max_body_bytes": grant.max_body_bytes}
                            for key, grant in sorted(self.grants.items())}}

    def binding(self):
        return {"version": 1, "max_attempts": self.max_attempts, "max_total_body_bytes": self.max_total_body_bytes,
                "targets": {key: grant.binding() for key, grant in sorted(self.grants.items())}}

    @property
    def digest(self):
        return _digest(self.binding())


_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS action_auto_policies (
        family_id TEXT PRIMARY KEY REFERENCES authority_families(id),
        root_task_id TEXT NOT NULL REFERENCES authority_tasks(id),
        policy_digest TEXT NOT NULL, policy_json TEXT NOT NULL,
        max_attempts INTEGER NOT NULL CHECK(max_attempts > 0),
        max_total_body_bytes INTEGER NOT NULL CHECK(max_total_body_bytes > 0),
        created_at TEXT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS action_auto_attempts (
        action_id TEXT PRIMARY KEY REFERENCES reviewed_actions(id),
        attempt_id TEXT NOT NULL UNIQUE,
        family_id TEXT NOT NULL REFERENCES action_auto_policies(family_id),
        task_id TEXT NOT NULL REFERENCES authority_tasks(id),
        policy_digest TEXT NOT NULL, target_id TEXT NOT NULL, binding_digest TEXT NOT NULL,
        destination_id TEXT NOT NULL, authority_revision INTEGER NOT NULL,
        labels_json TEXT NOT NULL, body_bytes INTEGER NOT NULL CHECK(body_bytes >= 0),
        created_at TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS action_auto_attempts_family ON action_auto_attempts(family_id)",
)


class ActionAutomation:
    def __init__(self, authority: Authority, targets: dict, policy: AutomaticActionPolicy):
        if not isinstance(authority, Authority) or type(policy) is not AutomaticActionPolicy or type(targets) is not dict:
            raise ValueError("invalid_action_automation_configuration")
        for key, grant in policy.grants.items():
            target = targets.get(key)
            if not isinstance(target, ActionTarget) or not hmac.compare_digest(_digest(target.binding()), grant.binding_digest):
                raise ValueError("automatic_action_target_binding_changed")
        self.authority, self.policy = authority, policy
        self.targets = MappingProxyType(dict(targets))
        with authority._transaction() as db:
            for statement in _SCHEMA:
                db.execute(statement)

    def _policy(self, db, family_id):
        row = db.execute("SELECT * FROM action_auto_policies WHERE family_id=?", (family_id,)).fetchone()
        if row is None:
            raise AuthorizationError("automatic_family_not_bound")
        if (not hmac.compare_digest(row["policy_digest"], self.policy.digest)
                or row["policy_json"] != _json(self.policy.binding())
                or row["max_attempts"] != self.policy.max_attempts
                or row["max_total_body_bytes"] != self.policy.max_total_body_bytes):
            raise AuthorizationError("automatic_task_scope_changed")
        return row

    def _destination_binding(self, db, family_id, grant):
        destination = db.execute("SELECT labels FROM authority_destinations WHERE family_id=? AND destination_id=?",
                                 (family_id, grant.destination_id)).fetchone()
        if destination is None or sorted(json.loads(destination["labels"])) != list(grant.accepted_labels):
            raise AuthorizationError("automatic_destination_binding_changed")

    def bind_task(self, task_id):
        """Host-only creation step. Existing family scope is immutable, never reset."""
        def bind(db):
            task = self.authority._task(db, task_id)
            prior = db.execute("SELECT 1 FROM action_auto_policies WHERE family_id=?", (task["family_id"],)).fetchone()
            if prior:
                self._policy(db, task["family_id"])
                return {"bound": False, "policy_digest": self.policy.digest}
            if task["parent_id"] is not None:
                raise AuthorizationError("automatic_scope_requires_root_creation")
            for grant in self.policy.grants.values():
                self._destination_binding(db, task["family_id"], grant)
                if grant.destination_id not in self.authority._grants(db, task_id, "destination"):
                    raise AuthorizationError("destination_not_granted")
            db.execute("""INSERT INTO action_auto_policies
                (family_id,root_task_id,policy_digest,policy_json,max_attempts,max_total_body_bytes,created_at)
                VALUES(?,?,?,?,?,?,?)""", (task["family_id"], task_id, self.policy.digest, _json(self.policy.binding()),
                    self.policy.max_attempts, self.policy.max_total_body_bytes, datetime.now(timezone.utc).isoformat()))
            self.authority._event(db, task_id, "automatic_scope_bound", True, "frozen_task_scope",
                                 {"policy_digest": self.policy.digest, "scope": self.policy.binding()})
            return {"bound": True, "policy_digest": self.policy.digest}
        return self.authority._request(task_id, "automatic_scope_bind", bind)

    def _authorize_attempt(self, db, task_id, row, target, attempt_id, body_bytes):
        """Only Actions._begin calls this inside its single attempt transaction."""
        task = self.authority._task(db, task_id)
        self._policy(db, task["family_id"])
        if row["kind"] not in AUTOMATIC_KINDS:
            raise AuthorizationError("automatic_kind_requires_review")
        grant = self.policy.grants.get(row["target_id"])
        if grant is None:
            raise AuthorizationError("automatic_target_not_granted")
        if grant.kind != row["kind"] or not hmac.compare_digest(_digest(target.binding()), grant.binding_digest):
            raise AuthorizationError("automatic_action_target_binding_changed")
        self._destination_binding(db, task["family_id"], grant)
        decision = self.authority._authorize_send(db, task_id, grant.destination_id)
        if not decision["allowed"]:
            raise AuthorizationError(decision["reason"])
        # A new model call/key is not permission to repeat an uncertain effect.
        # Include manual attempts and descendants, and compare the actual
        # current proposal (which a human may have edited), not request_digest.
        if _has_prior_unconfirmed_action(db, task["family_id"], row, grant.binding_digest):
            raise AuthorizationError("automatic_prior_outcome_unconfirmed")
        if type(body_bytes) is not int or body_bytes < 0:
            raise AuthorizationError("invalid_automatic_body_size")
        if body_bytes > grant.max_body_bytes:
            raise AuthorizationError("automatic_action_too_large")
        usage = db.execute("SELECT COUNT(*),COALESCE(SUM(body_bytes),0) FROM action_auto_attempts WHERE family_id=?",
                           (task["family_id"],)).fetchone()
        if usage[0] >= self.policy.max_attempts:
            raise AuthorizationError("automatic_attempt_budget_exhausted")
        if usage[1] + body_bytes > self.policy.max_total_body_bytes:
            raise AuthorizationError("automatic_body_budget_exhausted")
        db.execute("""INSERT INTO action_auto_attempts
            (action_id,attempt_id,family_id,task_id,policy_digest,target_id,binding_digest,destination_id,
             authority_revision,labels_json,body_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (row["id"], attempt_id, task["family_id"], task_id, self.policy.digest, grant.target_id,
             grant.binding_digest, grant.destination_id, decision["revision"], _json(decision["labels"]),
             body_bytes, datetime.now(timezone.utc).isoformat()))
        self.authority._event(db, task_id, "automatic_attempt_reserved", True, "frozen_task_scope",
            {"action_id": row["id"], "attempt_id": attempt_id, "policy_digest": self.policy.digest,
             "destination_id": grant.destination_id, "body_bytes": body_bytes, "authority_revision": decision["revision"]})
        return {"source": "frozen_task_scope", "policy_digest": self.policy.digest}

    def describe(self, task_id):
        """Host-readable family usage; no target URLs, headers, or sibling task IDs."""
        task_id = _identifier(task_id, "task_id")
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id, require_active=False)
            self._policy(db, task["family_id"])
            usage = db.execute("SELECT COUNT(*),COALESCE(SUM(body_bytes),0) FROM action_auto_attempts WHERE family_id=?",
                               (task["family_id"],)).fetchone()
            return {"policy_digest": self.policy.digest, "scope": self.policy.binding(), "attempts_used": usage[0],
                    "body_bytes_used": usage[1], "attempts_remaining": self.policy.max_attempts - usage[0],
                    "body_bytes_remaining": self.policy.max_total_body_bytes - usage[1]}

    def review_facts(self, task_id):
        """Host-only review context, not a reusable permission to execute.

        Read scope, child grants, family labels and usage in one transaction.
        Do not include destinations, credentials, proposal text or sibling IDs.
        Actions._begin still checks the current authority immediately before I/O.
        """
        task_id = _identifier(task_id, "task_id")
        with self.authority._transaction() as db:
            task = self.authority._task(db, task_id)
            self._policy(db, task["family_id"])
            destinations = set(self.authority._grants(db, task_id, "destination"))
            labels = set(self.authority._labels(db, task["family_id"]))
            targets = []
            for key, grant in sorted(self.policy.grants.items()):
                if not hmac.compare_digest(_digest(self.targets[key].binding()), grant.binding_digest):
                    raise AuthorizationError("automatic_action_target_binding_changed")
                self._destination_binding(db, task["family_id"], grant)
                targets.append({"target_id": key, "kind": grant.kind,
                                "task_granted": grant.destination_id in destinations,
                                "current_labels_allowed": labels <= set(grant.accepted_labels),
                                "max_body_bytes": grant.max_body_bytes})
            usage = db.execute("SELECT COUNT(*),COALESCE(SUM(body_bytes),0) FROM action_auto_attempts WHERE family_id=?",
                               (task["family_id"],)).fetchone()
            # These are bounded, host-recorded outcomes, not model assertions.
            # Never include a proposal or a target's human-readable label here.
            rows = db.execute("""SELECT id,kind,target_id,status,execution_mode,authorization_source
                FROM reviewed_actions WHERE task_id=? ORDER BY rowid DESC LIMIT 8""", (task_id,)).fetchall()
            return {"version": 1, "source": "host_ledger", "automatic_scope_sha256": self.policy.digest,
                    "automatic_targets": targets,
                    "attempts_remaining": self.policy.max_attempts - usage[0],
                    "body_bytes_remaining": self.policy.max_total_body_bytes - usage[1],
                    "recent_action_results": [dict(row) for row in rows]}
