"""Trusted, fixed-destination resource broker. Run outside every worker sandbox.

One OS process owns a state directory. Its lock covers the entire read/authorize/
send interval across all endpoints. This is a single-host prototype, not a
distributed authorization service. No approval result is reusable by a worker.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import sys
import threading
from urllib.parse import urlsplit
import uuid

from .authority import Authority, AuthorizationError
from .client import MAX_MESSAGE
from .mail_drafts import MailDrafts
from .mail_transport import MailAccount, send_email
from .protected_boundary import ProtectedContentError, check_candidate

MAX_CONTENT = 256 * 1024


@dataclass(frozen=True)
class Resource:
    path: Path
    labels: tuple[str, ...] = ()


@dataclass(frozen=True)
class Destination:
    url: str
    labels: tuple[str, ...] = ()
    # Loaded by the trusted host, never returned in describe or mounted in workers.
    headers: dict[str, str] = field(default_factory=dict, repr=False)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _send(destination: Destination, body: str, request_id: str) -> dict:
    """No environment proxies, redirects, model-chosen URLs, or response bodies."""
    url = urlsplit(destination.url)
    factory = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    connection = factory(url.hostname, url.port, timeout=8)
    encoded = json.dumps({"request_id": request_id, "body": body}, ensure_ascii=True).encode()
    target = url.path or "/"
    if url.query:
        target += "?" + url.query
    headers = {**destination.headers, "Content-Type": "application/json", "X-Yuanxingmu-Request": request_id}
    try:
        connection.request("POST", target, encoded, headers)
        response = connection.getresponse()
        response.read(MAX_CONTENT + 1)
        # A redirect is never followed. A failing remote can already have consumed
        # the body; neither an error nor a timeout proves that it was not received.
        return {"http_status": response.status, "outcome": "acknowledged" if 200 <= response.status < 300 else "unconfirmed"}
    finally:
        connection.close()


class _Server(socketserver.ThreadingUnixStreamServer if hasattr(socketserver, "ThreadingUnixStreamServer") else object):
    daemon_threads = True
    block_on_close = True


class Broker:
    """Host-only management API; a worker receives only its mounted Unix socket."""

    def __init__(self, state_dir: Path, resources: dict[str, Resource], destinations: dict[str, Destination], *,
                 reviewed_mail=False, guards=None, action_targets=None, input_containment=False,
                 action_automation=None, protected_data=None):
        if protected_data is not None:
            from .protected_data import HostProtectedData
            if type(protected_data) is not HostProtectedData:
                raise ValueError("invalid_host_protected_data")
        if type(input_containment) is not bool or (input_containment and guards is None):
            raise ValueError("input_containment_requires_guards")
        if action_automation is not None and (guards is None or action_targets is None):
            raise ValueError("automatic_actions_require_guards_and_targets")
        automatic_policy = None
        if action_automation is not None:
            from .action_automation import AutomaticActionPolicy
            automatic_policy = AutomaticActionPolicy.from_config(action_automation, action_targets)
            if set(destinations) & set(automatic_policy.destination_labels()):
                raise ValueError("automatic_action_destination_collision")
        if not sys.platform.startswith("linux") or not hasattr(socket, "AF_UNIX"):
            raise RuntimeError("broker_requires_linux")
        import fcntl
        self.state_dir = Path(state_dir).resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state_dir.chmod(0o700)
        self._file_lock = (self.state_dir / "broker.lock").open("a+b")
        try:
            fcntl.flock(self._file_lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._file_lock.close()
            raise RuntimeError("state_already_owned_by_another_broker") from None
        self._lock = threading.RLock()
        self._servers: list[tuple[_Server, threading.Thread, Path]] = []
        self._closed = False
        self._fault = False
        self._guard_marker = self.state_dir / "guard-session.dirty"
        self.configure_callback = None
        self.resources = dict(resources)
        self.destinations = dict(destinations)
        self.reviewed_mail = reviewed_mail is True
        self.guards = guards
        self.protected_data = protected_data
        self.input_containment = input_containment
        self.action_targets = None if action_targets is None else dict(action_targets)
        self.automatic_policy = automatic_policy
        self.automation = None
        self.actions = None
        self.tool_reviews = None
        self.quarantine = None
        self.mail = None
        self.authority = None
        try:
            binding = self._binding()
            saved = self.state_dir / "bindings.json"
            if saved.exists():
                if json.loads(saved.read_text()) != binding:
                    raise RuntimeError("state_policy_or_resource_changed")
            else:
                with saved.open("x", encoding="utf-8") as stream:
                    json.dump(binding, stream, sort_keys=True)
                    stream.flush()
                    os.fsync(stream.fileno())
            self.authority = Authority(self.state_dir / "authority.sqlite3")
            if self.guards is not None:
                from .tool_reviews import ToolReviews
                self.tool_reviews = ToolReviews(self.authority)
                self.tool_reviews.recover()
            if self.guards is not None or self.protected_data is not None:
                from .quarantine import Quarantine
                self.quarantine = Quarantine(self.authority)
            if self.action_targets is not None:
                from .actions import Actions
                self.actions = Actions(self.authority, self.action_targets, check_content=self._check_protected)
                self.actions.recover()
                if self.automatic_policy is not None:
                    from .action_automation import ActionAutomation
                    self.automation = ActionAutomation(self.authority, self.action_targets, self.automatic_policy)
            if self.reviewed_mail:
                self.mail = MailDrafts(self.authority, check_content=self._check_protected)
                # The exclusive broker lock proves no earlier sender is live.
                self.mail.recover()
            if self.quarantine is not None:
                unclean = self._guard_marker.exists() or self._guard_marker.is_symlink()
                fd = os.open(self._guard_marker, os.O_CREAT | os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
                try:
                    os.write(fd, b"Host defense session open. Retain on faults or unconfirmed termination.\n")
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self._sync_state_directory()
                if unclean:
                    with self.authority._transaction() as db:
                        roots = [r[0] for r in db.execute("SELECT id FROM authority_tasks WHERE parent_id IS NULL AND revoked=0")]
                    for task in roots:
                        self.quarantine.pause(task, layer="foundation", code="previous_defense_session_unconfirmed",
                            reason="上一次防护服务未确认正常结束，已暂停后续操作。请先核对记录，再恢复工作。")
        except BaseException:
            if self.authority is not None:
                self.authority.close()
            self._file_lock.close()
            raise

    def _binding(self) -> dict:
        for name in (*self.resources, *self.destinations):
            if not isinstance(name, str) or not name or len(name) > 128:
                raise ValueError("invalid_binding_name")
        resource_binding = {}
        for name, resource in self.resources.items():
            path = Path(resource.path).resolve(strict=True)
            if not path.is_file() or path.stat().st_size > MAX_CONTENT:
                raise ValueError("resource_must_be_a_small_regular_file")
            resource_binding[name] = {"path": str(path), "sha256": _digest(path.read_bytes()), "labels": sorted(resource.labels)}
        destination_binding = {}
        for name, destination in self.destinations.items():
            parsed = urlsplit(destination.url)
            if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
                raise ValueError("invalid_destination_url")
            if parsed.scheme == "http":
                try:
                    loopback = ipaddress.ip_address(parsed.hostname).is_loopback
                except ValueError:
                    loopback = False
                if not loopback:
                    raise ValueError("unencrypted_destination_requires_literal_loopback")
            if any(not isinstance(k, str) or not isinstance(v, str) or "\r" in k + v or "\n" in k + v
                   or k.lower() in ("host", "content-length", "transfer-encoding", "connection", "content-type", "x-yuanxingmu-request")
                   for k, v in destination.headers.items()):
                raise ValueError("invalid_destination_headers")
            destination_binding[name] = {"url": destination.url, "labels": sorted(destination.labels),
                "headers_sha256": _digest(json.dumps(destination.headers, sort_keys=True).encode())}
        binding = {"version": 1, "resources": resource_binding, "destinations": destination_binding}
        if self.protected_data is not None:
            from .protected_data import HostProtectedData, HostResource
            # A caller cannot attach a set compiled from different documents.
            resources = {name: HostResource(Path(self.resources[name].path).read_bytes().decode("utf-8"), item["sha256"])
                         for name, item in resource_binding.items()}
            HostProtectedData.from_private_json(self.protected_data.to_private_json(), resources=resources)
            binding["protected_data"] = self.protected_data.binding_digest()
        if self.reviewed_mail:
            binding["reviewed_mail"] = 1
        if self.guards is not None:
            self.guards.check_content = self._check_protected
            # Settings changes must rewrite this binding under the host lock.
            # Credentials are represented by a digest only. Newly introduced
            # defaults are omitted to preserve old persisted profile bindings.
            judge = asdict(self.guards.judge) if self.guards.judge is not None else None
            binding["guards"] = {"policy": self.guards.policy.to_dict(),
                                 "judge_sha256": _digest(json.dumps(judge, sort_keys=True).encode())}
            if self.input_containment:
                binding["input_containment"] = 1
        if self.action_targets is not None:
            binding["reviewed_actions"] = {name: target.binding() for name, target in sorted(self.action_targets.items())}
            if self.automatic_policy is not None:
                binding["automatic_actions"] = self.automatic_policy.binding()
            existing = self.state_dir / "workspaces.json"
            workspaces = [Path(name) for name in json.loads(existing.read_text())] if existing.exists() else []
            for target in self.action_targets.values():
                if target.workspace is None:
                    continue
                for protected in [self.state_dir, *workspaces, *(Path(r.path).resolve() for r in self.resources.values())]:
                    if target.workspace == protected or target.workspace in protected.parents or protected in target.workspace.parents:
                        raise ValueError("reviewed_file_target_overlaps_agent_or_trusted_state")
        return json.loads(json.dumps(binding))

    def _guard_result(self, task_id, result):
        value = result.to_dict()
        if self._contained_input(value):
            value["intervention"] = "withhold_input_continue_task"
            value["reason"] += " 这一段资料已被扣留，其他已授权工作可以继续，无需恢复工作。"
        try:
            self._event(task_id, "defense_check", {k: v for k, v in value.items() if k != "cleaned_text"})
        except Exception:
            self._fault = True
            raise
        if not result.allowed:
            self._pause_for_check(task_id, value)
            raise AuthorizationError(value["code"], value["reason"])
        return value

    def _contained_input(self, value):
        # Only an entire external input that has not reached the Agent can be
        # discarded locally. Tool, memory, response and preflight failures do
        # not inherit this exception. This host option is pinned per profile.
        return (self.input_containment and value.get("layer") == "input"
                and value.get("verdict") == "block" and value.get("enforced") is True
                and value.get("assessed") is True and value.get("withheld") is True
                and value.get("evidence", {}).get("method") == "rule")

    def _pause_for_check(self, task_id, value):
        """Pause subsequent admissions, not effects already admitted to an executor."""
        if self.quarantine is None or value.get("verdict") != "block" or value.get("enforced") is False:
            return
        if self._contained_input(value):
            return
        evidence = value.get("evidence", {})
        try:
            self.quarantine.pause(task_id, layer=value["layer"], code=value["code"], reason=value["reason"],
                                  evidence_sha256=evidence.get("candidate_sha256") or evidence.get("input_sha256"))
        except Exception:
            self._fault = True
            raise

    def _sync_state_directory(self):
        fd = os.open(self.state_dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _require_healthy(self):
        if self._closed:
            raise AuthorizationError("broker_closed")
        if self._fault:
            raise AuthorizationError("defense_storage_fault", "防护状态写入失败，后续操作已停止。请保留记录并重启防护服务。")

    def _require_admission(self, task_id):
        self._require_healthy()
        with self.authority._transaction() as db:
            self.authority._task(db, task_id)

    def _check_protected(self, candidate):
        # Pure: also safe inside Actions/MailDrafts' admission transaction.
        check_candidate(self.protected_data, candidate)

    def _protected_failure(self, task_id, error):
        # No source text, field value, or low-entropy value hash in the audit.
        try:
            self._event(task_id, "protected_content_withheld", {"allowed": False, "reason": error.reason})
            self.quarantine.pause(task_id, layer="data", code=error.reason, reason=str(error))
        except Exception:
            self._fault = True
            raise

    def _protect(self, task_id, candidate):
        """Model boundary entry; caller holds the broker lock, outside DB work."""
        try:
            self._check_protected(candidate)
        except ProtectedContentError as exc:
            self._protected_failure(task_id, exc)
            raise

    def _guard_tool(self, task_id, tool, arguments, *, action_request=False):
        self._check_protected({"tool": tool, "arguments": arguments})
        if self.guards is None:
            return
        if not self.authority.describe(task_id)["active"]:
            raise AuthorizationError("task_revoked")
        self._guard_result(task_id, self.guards.check_memory(tool, arguments))
        if tool in {"exec", "terminal"}:
            self._guard_result(task_id, self.guards.check_command(arguments.get("command", "")))
        context = self._review_context(task_id)
        if action_request:
            # Only the actual request_action dispatch branch sets this flag.
            # A worker naming a tool/argument "request_action" cannot set it.
            canonical = self.actions._canonical(arguments)
            grant = self.automatic_policy.grants.get(canonical["target_id"])
            context["host_facts"]["action_request"] = {
                "operation": "request_action", "kind": canonical["kind"], "target_id": canonical["target_id"],
                "effect": "pending_only" if grant is None else "automatic_candidate",
            }
        self._guard_result(task_id, self.guards.check_alignment(
            {"tool": tool, "arguments": arguments}, **context))

    def _review_context(self, task_id):
        # There is deliberately no worker RPC field or operation for this.
        return {"host_facts": self.automation.review_facts(task_id)} if self.automation is not None else {}

    def _guard_native_tool(self, task_id, tool, arguments, *, alignment=True):
        """Return review to the native human approval hook; never execute here."""
        self._check_protected({"tool": tool, "arguments": arguments})
        checks = [self.guards.check_memory(tool, arguments)]
        source = arguments.get("source_tool")
        if isinstance(source, dict) and isinstance(source.get("tool"), str) and isinstance(source.get("arguments"), dict):
            checks.append(self.guards.check_memory(source["tool"], source["arguments"]))
        if tool in {"exec", "terminal"}:
            checks.append(self.guards.check_command(arguments.get("command", "")))
        for check in checks:
            value = check.to_dict()
            self._event(task_id, "defense_check", {k: v for k, v in value.items() if k != "cleaned_text"})
        if alignment and not any(check.verdict == "block" for check in checks):
            check = self.guards.check_alignment({"tool": tool, "arguments": arguments}, **self._review_context(task_id))
            checks.append(check)
            self._event(task_id, "defense_check", {k: v for k, v in check.to_dict().items() if k != "cleaned_text"})
        outcome = next((check for check in checks if check.verdict == "block"), None)
        outcome = outcome or next((check for check in checks if check.verdict == "review"), None)
        if outcome is not None:
            return {"allowed": False, "verdict": outcome.verdict, "reason": outcome.code, "message": outcome.reason,
                    "mode": self.guards.policy.effective_mode(outcome.layer), "check": outcome.to_dict()}
        modes = {check.layer: self.guards.policy.effective_mode(check.layer) for check in checks if check.assessed}
        effective = set(modes.values())
        return {"allowed": True, "verdict": "allow", "reason": "candidate_checks_completed",
                "mode": next(iter(effective)) if len(effective) == 1 else "mixed" if effective else "disabled",
                "layer_modes": modes}

    def create_task(self, *, task_id: str | None = None, initial_labels: list[str] | None = None) -> str:
        with self._lock:
            self._require_healthy()
            destinations = {k: list(v.labels) for k, v in self.destinations.items()}
            if self.automatic_policy is not None:
                automatic = self.automatic_policy.destination_labels()
                if set(destinations) & set(automatic):
                    raise ValueError("automatic_action_destination_collision")
                destinations.update(automatic)
            task = self.authority.create_root({k: list(v.labels) for k, v in self.resources.items()},
                destinations, task_id=task_id,
                initial_labels=initial_labels)
            if self.automation is not None:
                self.automation.bind_task(task)
            return task

    def delegate(self, task_id: str, *, resources=None, destinations=None) -> str:
        with self._lock:
            self._require_admission(task_id)
            return self.authority.delegate(task_id, resources=resources, destinations=destinations)

    def revoke(self, task_id: str) -> dict:
        with self._lock:
            return self.authority.revoke(task_id)

    def bind_workspace(self, task_id: str, workspace: Path) -> Path:
        """Persist host-selected workspace ownership; never infer identity from its contents."""
        with self._lock:
            if not self.authority.describe(task_id)["active"]:
                raise AuthorizationError("task_revoked")
            work = Path(workspace).resolve(strict=True)
            if not work.is_dir():
                raise ValueError("workspace_must_be_a_directory")
            for target in (self.action_targets or {}).values():
                if target.workspace is not None and (target.workspace == work or target.workspace in work.parents or work in target.workspace.parents):
                    raise ValueError("reviewed_file_target_overlaps_agent_workspace")
            for protected in [self.state_dir, *(Path(r.path).resolve() for r in self.resources.values())]:
                if protected == work or work in protected.parents or protected in work.parents:
                    raise ValueError("workspace_overlaps_trusted_state_or_resource")
            registry = self.state_dir / "workspaces.json"
            records = json.loads(registry.read_text()) if registry.exists() else {}
            for path, owner in records.items():
                known = Path(path)
                if owner != task_id and (known == work or known in work.parents or work in known.parents):
                    raise AuthorizationError("workspace_already_bound_to_another_task")
            records[str(work)] = task_id
            temporary = registry.with_suffix(".tmp")
            with temporary.open("w", encoding="utf-8") as stream:
                json.dump(records, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(registry)
            return work

    def _event(self, task_id: str, operation: str, result: dict, **extra) -> None:
        event = {"time": datetime.now(timezone.utc).isoformat(), "task_id": task_id, "operation": operation,
                 **{k: v for k, v in result.items() if k not in ("content", "body")}, **extra}
        try:
            with (self.state_dir / "broker-events.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            if self.guards is not None or self.protected_data is not None:
                self._fault = True
            raise

    def dispatch(self, task_id: str, request: dict) -> dict:
        with self._lock:
            operation = request.get("op") if isinstance(request, dict) else None
            try:
                if self._closed:
                    raise AuthorizationError("broker_closed")
                fields = {"read": {"op", "resource"}, "send": {"op", "destination", "body"}, "describe": {"op"},
                          "draft_email": {"op", "request_key", "draft"},
                          "action_targets": {"op"}, "propose_action": {"op", "request_key", "proposal"},
                          "request_action": {"op", "request_key", "proposal"},
                          "guard_tool": {"op", "tool", "arguments"}, "guard_rules": {"op", "tool", "arguments"}, "inspect_input": {"op", "text"},
                          "request_tool_review": {"op", "request_key", "tool", "arguments"},
                          "consume_tool_review": {"op", "review_id", "digest", "tool", "arguments"}}
                if not isinstance(operation, str) or operation not in fields or set(request) != fields[operation]:
                    raise AuthorizationError("invalid_request")
                self._require_healthy()
                if operation != "request_tool_review":
                    self._require_admission(task_id)
                if operation in {"request_tool_review", "consume_tool_review"}:
                    if self.tool_reviews is None:
                        raise AuthorizationError("layered_defense_not_enabled")
                    if not self.authority.describe(task_id)["active"]:
                        raise AuthorizationError("task_revoked")
                    from .tool_reviews import candidate
                    candidate(request["tool"], request["arguments"])
                    self._check_protected({"tool": request["tool"], "arguments": request["arguments"]})
                    if operation == "request_tool_review":
                        result = self.tool_reviews.prior(task_id, request["request_key"], request["tool"], request["arguments"])
                        if result is None:
                            self._require_admission(task_id)
                            result = self._guard_native_tool(task_id, request["tool"], request["arguments"])
                            check = result.pop("check", None)
                            if result.get("verdict") in {"review", "block"}:
                                result = self.tool_reviews.request(task_id, request["request_key"], request["tool"], request["arguments"],
                                    reason=result["message"], blocked=result["verdict"] == "block")
                            if check:
                                self._pause_for_check(task_id, check)
                    else:
                        result = self.tool_reviews.consume(task_id, request["review_id"], request["digest"], request["tool"], request["arguments"])
                elif operation in {"action_targets", "propose_action", "request_action"}:
                    if self.actions is None:
                        raise AuthorizationError("reviewed_actions_not_enabled")
                    if not self.authority.describe(task_id)["active"]:
                        raise AuthorizationError("task_revoked")
                    if operation == "action_targets":
                        result = {"allowed": True, "targets": self.actions.describe_targets()}
                        if self.automatic_policy is not None:
                            result["automatic_scope"] = self.automatic_policy.to_config()
                    elif operation == "request_action":
                        if self.automation is None:
                            raise AuthorizationError("automatic_actions_not_enabled")
                        canonical = self.actions._canonical(request["proposal"])
                        previous = self.actions.prior(task_id, request["request_key"], canonical)
                        if previous is not None:
                            result = {"allowed": True, "started": False, "reason": "action_already_recorded", **previous}
                        else:
                            self._guard_tool(task_id, "yuanxingmu_request_action", canonical, action_request=True)
                            action = self.actions.submit(task_id, request["request_key"], canonical)
                            if not self.guards.policy.alignment_enabled or self.guards.policy.effective_mode("alignment") != "enforce":
                                result = {"allowed": True, "started": False, "reason": "automatic_defense_not_enforcing", **action}
                            else:
                                outcome = self.actions.commit_automatic(task_id, action["id"], action["revision"], action["digest"],
                                                                        self.automation, checked_proposal=canonical)
                                # Host commit records can include file snapshots
                                # and target metadata. Workers receive only the
                                # same public fields used for an inert proposal.
                                public_action = self.actions.prior(task_id, request["request_key"], canonical)
                                result = {"allowed": True, "reason": outcome.get("reason", "action_automatic_attempt_recorded"),
                                          "started": outcome["started"], **public_action}
                    else:
                        self._guard_tool(task_id, "yuanxingmu_prepare_action", request["proposal"])
                        action = self.actions.submit(task_id, request["request_key"], request["proposal"])
                        result = {"allowed": True, "reason": "action_waiting_for_review" if action["status"] == "pending" else "action_already_recorded", **action}
                elif operation in {"guard_tool", "guard_rules", "inspect_input"}:
                    if self.guards is None:
                        raise AuthorizationError("layered_defense_not_enabled")
                    if not self.authority.describe(task_id)["active"]:
                        raise AuthorizationError("task_revoked")
                    if operation in {"guard_tool", "guard_rules"}:
                        if not isinstance(request["tool"], str) or not isinstance(request["arguments"], dict):
                            raise AuthorizationError("invalid_guard_candidate")
                        result = self._guard_native_tool(task_id, request["tool"], request["arguments"], alignment=operation == "guard_tool")
                        if operation == "guard_rules":
                            result["final_execution_check_required"] = True
                        check = result.pop("check", None)
                        if check:
                            self._pause_for_check(task_id, check)
                    else:
                        self._check_protected(request["text"])
                        check = self.guards.check_input(request["text"])
                        self._guard_result(task_id, check)
                        result = {"allowed": True, "reason": "input_check_completed", "mode": self.guards.policy.effective_mode("input")}
                elif operation == "describe":
                    state = self.authority.describe(task_id)
                    if not state["active"]:
                        raise AuthorizationError("task_revoked")
                    result = {"allowed": True, **state}
                elif operation == "read":
                    name = request["resource"]
                    if not isinstance(name, str) or name not in self.resources:
                        raise AuthorizationError("unknown_resource")
                    self._guard_tool(task_id, "yuanxingmu_read", {"resource": name})
                    decision = self.authority.record_read(task_id, name)
                    content = Path(self.resources[name].path).read_bytes()
                    expected = json.loads((self.state_dir / "bindings.json").read_text())["resources"][name]["sha256"]
                    if len(content) > MAX_CONTENT or _digest(content) != expected:
                        raise AuthorizationError("resource_changed")
                    text = content.decode("utf-8")
                    if self.protected_data is not None:
                        text = self.protected_data.redacted(name, expected)
                        self._check_protected(text)
                    if self.guards is not None:
                        self._guard_result(task_id, self.guards.check_input(text))
                    result = {**decision, "content": text}
                elif operation == "draft_email":
                    if self.mail is None:
                        raise AuthorizationError("reviewed_mail_not_enabled")
                    self._guard_tool(task_id, "yuanxingmu_prepare_email", request["draft"])
                    draft = self.mail.submit(task_id, request["request_key"], request["draft"])
                    result = {"allowed": True, "reason": "mail_draft_saved", "draft_id": draft["id"],
                              "digest": draft["digest"], "revision": draft["revision"], "status": draft["status"]}
                else:
                    name, body = request["destination"], request["body"]
                    if not isinstance(name, str) or name not in self.destinations:
                        raise AuthorizationError("unknown_destination")
                    if not isinstance(body, str) or len(body.encode("utf-8")) > MAX_CONTENT:
                        raise AuthorizationError("invalid_body")
                    decision = self.authority.authorize_send(task_id, name)
                    result = dict(decision)
                    if decision["allowed"]:
                        self._guard_tool(task_id, "yuanxingmu_send", {"destination": name, "body": body})
                        request_id = uuid.uuid4().hex
                        # Persist intent first; interrupted/unacknowledged attempts
                        # remain distinguishable from attempts never authorized.
                        self._event(task_id, "send_intent", decision, request_id=request_id, body_sha256=_digest(body.encode()))
                        try:
                            delivered = _send(self.destinations[name], body, request_id)
                        except (OSError, http.client.HTTPException, ValueError):
                            delivered = {"outcome": "unknown"}
                        result.update(request_id=request_id, **delivered)
                self._event(task_id, operation, result)
                return result
            except AuthorizationError as exc:
                if isinstance(exc, ProtectedContentError):
                    self._protected_failure(task_id, exc)
                result = {"allowed": False, "reason": exc.reason}
                if str(exc) != exc.reason:
                    result["message"] = str(exc)
            except (OSError, ValueError, TypeError):
                result = {"allowed": False, "reason": "broker_operation_failed"}
            audit_operation = operation if isinstance(operation, str) and operation in {"read", "send", "describe", "draft_email", "guard_tool", "guard_rules", "inspect_input", "action_targets", "propose_action", "request_action", "request_tool_review", "consume_tool_review"} else "invalid"
            self._event(task_id, audit_operation, result)
            return result

    def review_mail(self, task_id: str, request: dict) -> dict:
        """Host-only approval. Never call this from dispatch or a worker socket."""
        with self._lock:
            if isinstance(request, dict) and str(request.get("op", "")).startswith("quarantine_"):
                return self.review_quarantine(task_id, request)
            if isinstance(request, dict) and str(request.get("op", "")).startswith("protection_"):
                self._require_healthy()
                if (set(request) not in ({"op", "settings"}, {"op", "settings", "metadata"})
                        or request["op"] != "protection_set" or not callable(self.configure_callback)):
                    raise AuthorizationError("live_defense_settings_unavailable")
                metadata = request.get("metadata", {})
                if (type(metadata) is not dict or ("metadata" in request and set(metadata) != {
                        "source", "intent", "baseline_sha256", "expected_policy_sha256"})):
                    raise AuthorizationError("invalid_settings_metadata")
                return self.configure_callback(request["settings"], **metadata)
            if isinstance(request, dict) and str(request.get("op", "")).startswith("tool_"):
                return self.review_tool(task_id, request)
            if isinstance(request, dict) and str(request.get("op", "")).startswith("action_"):
                return self.review_action(task_id, request)
            if self._closed or self.mail is None:
                raise AuthorizationError("reviewed_mail_unavailable")
            fields = {
                "list": {"op"}, "get": {"op", "draft_id"},
                "edit": {"op", "draft_id", "revision", "digest", "draft"},
                "cancel": {"op", "draft_id", "revision", "digest"},
                "send": {"op", "draft_id", "revision", "digest", "account_id", "account", "confirm"},
            }
            op = request.get("op") if isinstance(request, dict) else None
            if not isinstance(op, str) or op not in fields or set(request) != fields[op]:
                raise AuthorizationError("invalid_mail_review")
            if op == "list":
                return self.mail.list(task_id)
            if op == "get":
                return self.mail.get(task_id, request["draft_id"])
            args = (task_id, request["draft_id"], request["revision"], request["digest"])
            self._require_healthy()
            if op == "edit":
                self._protect(task_id, request["draft"])
                return {"draft": self.mail.edit(*args, request["draft"])}
            if op == "cancel":
                return {"draft": self.mail.cancel(*args)}
            if request["confirm"] != "send":
                raise AuthorizationError("mail_confirmation_required")
            try:
                account = MailAccount(**request["account"])
            except (ValueError, TypeError):
                raise AuthorizationError("invalid_mail_account") from None
            try:
                decision = self.mail.begin_send(*args, request["account_id"], account.from_address)
            except ProtectedContentError as exc:
                self._protected_failure(task_id, exc)
                raise
            draft = decision["draft"]
            if not decision["started"]:
                return {"draft": draft}
            # begin_send committed a single-use attempt before any network I/O.
            # This same lock also orders revoke and every other broker endpoint.
            try:
                outcome = send_email(account, {name: draft[name] for name in ("recipient", "subject", "body")},
                                     draft["attempt_id"])["outcome"]
            except BaseException:
                self.mail.finish_send(task_id, draft["id"], draft["attempt_id"], "unconfirmed")
                raise
            return {"draft": self.mail.finish_send(task_id, draft["id"], draft["attempt_id"], outcome)}

    def review_action(self, task_id: str, request: dict) -> dict:
        """Only the unmounted review socket reaches this method."""
        with self._lock:
            if self._closed or self.actions is None:
                raise AuthorizationError("reviewed_actions_not_enabled")
            fields = {"action_list": {"op"}, "action_get": {"op", "action_id"},
                      "action_edit": {"op", "action_id", "revision", "digest", "proposal"},
                      "action_cancel": {"op", "action_id", "revision", "digest"},
                      "action_commit": {"op", "action_id", "revision", "digest", "confirm"}}
            op = request.get("op") if isinstance(request, dict) else None
            if not isinstance(op, str) or op not in fields or set(request) != fields[op]:
                raise AuthorizationError("invalid_action_review")
            if op == "action_list":
                return {**self.actions.list(task_id), "targets": self.actions.describe_targets()}
            if op == "action_get":
                return self.actions.get(task_id, request["action_id"])
            args = (task_id, request["action_id"], request["revision"], request["digest"])
            self._require_healthy()
            if op == "action_edit":
                self._protect(task_id, request["proposal"])
                return {"action": self.actions.edit(*args, request["proposal"])}
            if op == "action_cancel":
                return {"action": self.actions.cancel(*args)}
            if request["confirm"] != "commit":
                raise AuthorizationError("action_confirmation_required")
            try:
                return self.actions.commit(*args)
            except ProtectedContentError as exc:
                self._protected_failure(task_id, exc)
                raise

    def review_tool(self, task_id: str, request: dict) -> dict:
        with self._lock:
            if self._closed or self.tool_reviews is None:
                raise AuthorizationError("layered_defense_not_enabled")
            fields = {"tool_list": {"op"}, "tool_get": {"op", "review_id"},
                      "tool_approve": {"op", "review_id", "digest", "confirm"},
                      "tool_deny": {"op", "review_id", "digest", "confirm"}}
            op = request.get("op") if isinstance(request, dict) else None
            if not isinstance(op, str) or op not in fields or set(request) != fields[op]:
                raise AuthorizationError("invalid_tool_review")
            if op == "tool_list":
                return self.tool_reviews.list(task_id)
            if op == "tool_get":
                return self.tool_reviews.get(task_id, request["review_id"])
            decision = op.removeprefix("tool_")
            self._require_healthy()
            if request["confirm"] != decision:
                raise AuthorizationError("tool_confirmation_required")
            return self.tool_reviews.decide(task_id, request["review_id"], request["digest"], decision)

    def review_quarantine(self, task_id: str, request: dict) -> dict:
        """Host-only recovery; agent-facing dispatch never routes these operations."""
        with self._lock:
            if self._closed or self.quarantine is None:
                raise AuthorizationError("layered_defense_not_enabled")
            fields = {"quarantine_status": {"op"},
                      "quarantine_resume": {"op", "epoch", "incident_id", "confirm"}}
            op = request.get("op") if isinstance(request, dict) else None
            if not isinstance(op, str) or op not in fields or set(request) != fields[op]:
                raise AuthorizationError("invalid_quarantine_request")
            if op == "quarantine_status":
                return {**self.quarantine.status(task_id), "storage_fault": self._fault}
            self._require_healthy()
            return self.quarantine.resume(task_id, epoch=request["epoch"], incident_id=request["incident_id"],
                                          confirm=request["confirm"], operator="workbench")

    def serve_reviews(self, task_id: str, socket_path: Path) -> Path:
        """Bind a host-only socket. Its path must not be mounted into any agent."""
        with self._lock:
            if self._closed or (self.mail is None and self.actions is None and self.tool_reviews is None and self.quarantine is None):
                raise AuthorizationError("reviewed_mail_unavailable")
            socket_path = Path(socket_path).absolute()
            if len(os.fsencode(socket_path)) > 100:
                raise ValueError("unix_socket_path_too_long")
            socket_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            broker = self

            class Handler(socketserver.StreamRequestHandler):
                def handle(self):
                    self.connection.settimeout(120)
                    try:
                        raw = self.rfile.readline(MAX_MESSAGE + 1)
                        if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
                            raise AuthorizationError("invalid_mail_review")
                        result = broker.review_mail(task_id, json.loads(raw))
                        response = {"ok": True, **result}
                    except AuthorizationError as exc:
                        response = {"ok": False, "reason": exc.reason}
                    except (OSError, ValueError, TypeError, RuntimeError):
                        response = {"ok": False, "reason": "mail_review_failed"}
                    try:
                        self.wfile.write(json.dumps(response, ensure_ascii=True).encode() + b"\n")
                    except OSError:
                        pass

            server = _Server(str(socket_path), Handler)
            socket_path.chmod(0o600)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
            self._servers.append((server, thread, socket_path))
            thread.start()
            return socket_path

    def serve(self, task_id: str, socket_path: Path, *, allowed_operations=None) -> Path:
        """Bind identity and an optional host-selected operation subset.

        A narrow SDK socket must reject raw RPC bypasses of its tool list too.
        This filter only removes capabilities; dispatch still checks authority.
        """
        if allowed_operations is not None:
            if (type(allowed_operations) not in {set, frozenset} or not allowed_operations
                    or any(type(item) is not str for item in allowed_operations)):
                raise ValueError("invalid_broker_operation_subset")
            allowed_operations = frozenset(allowed_operations)
        with self._lock:
            if self._closed or not self.authority.describe(task_id)["active"]:
                raise AuthorizationError("task_inactive")
            socket_path = Path(socket_path).absolute()
            if len(os.fsencode(socket_path)) > 100:
                raise ValueError("unix_socket_path_too_long")
            socket_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            broker = self

            class Handler(socketserver.StreamRequestHandler):
                def handle(self):
                    self.connection.settimeout(10)
                    try:
                        raw = self.rfile.readline(MAX_MESSAGE + 1)
                        if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
                            result = {"allowed": False, "reason": "invalid_message"}
                        else:
                            try:
                                request = json.loads(raw)
                            except (ValueError, UnicodeError):
                                request = None
                            if (allowed_operations is not None and (type(request) is not dict
                                    or type(request.get("op")) is not str or request["op"] not in allowed_operations)):
                                result = {"allowed": False, "reason": "operation_not_available_in_session"}
                            else:
                                result = broker.dispatch(task_id, request)
                        self.wfile.write(json.dumps(result, ensure_ascii=True).encode() + b"\n")
                    except (OSError, ValueError):
                        return

            server = _Server(str(socket_path), Handler)
            socket_path.chmod(0o600)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            self._servers.append((server, thread, socket_path))
            thread.start()
            return socket_path

    def close(self) -> None:
        with self._lock:
            if self._file_lock.closed:
                return
            self._closed = True
        errors = []
        for server, thread, path in self._servers:
            for cleanup in (server.shutdown, server.server_close, lambda: thread.join(timeout=2),
                            lambda: path.unlink(missing_ok=True)):
                try:
                    cleanup()
                except BaseException as exc:
                    errors.append(exc)
        self._servers.clear()
        with self._lock:
            try:
                if self.authority is not None:
                    self.authority.close()
            except BaseException as exc:
                errors.append(exc)
            finally:
                self.authority = None
            try:
                if self.quarantine is not None and not self._fault and not errors:
                    try:
                        self._guard_marker.unlink(missing_ok=True)
                        self._sync_state_directory()
                    except BaseException as exc:
                        errors.append(exc)
                if errors:
                    self._fault = True
                if self.quarantine is not None and self._fault and not self._guard_marker.exists():
                    # A failed directory fsync after unlink is not a clean close.
                    # Restore the marker when storage permits; never mask the
                    # original failure or retain the exclusive process lock.
                    fd = os.open(self._guard_marker, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                    try:
                        os.write(fd, b"Defense shutdown was not confirmed. Host review required.\n")
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    self._sync_state_directory()
            except BaseException as exc:
                errors.append(exc)
            finally:
                self._file_lock.close()
        if errors:
            raise errors[0]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
