"""Hermes's native terminal provider and fixed-profile Broker tools.

Imported only by the official Hermes plugin loader, inside the outer boundary.
Every new chat, resume and delegated task retains the same host-owned authority.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

from agent.terminal_env_provider import TerminalEnvironmentProvider
from tools.environments.base import BaseEnvironment, EnvironmentConnectionError
from tools.environments.base_output import _pipe_stdin
from tools.interrupt import is_interrupted, is_thread_interrupted

from .client import request
from .sandbox import sandbox_available
from .worker import start, stop

_LOCAL_TOOLS = frozenset({"terminal", "process_manage", "read_file", "write_file", "patch", "search_files"})
_BLOCKED_INPUT = "这段工具输出尚未通过元星木检查，已暂不交给 AI。请在工作台查看记录。"
_BLOCKED_COMMAND = "此次操作尚未通过元星木检查，没有执行。请在工作台查看记录。"
_INVOCATION = ContextVar("yuanxingmu_hermes_invocation", default=None)
_REVIEW_WAIT_SECONDS = 300
_REVIEW_POLL_SECONDS = 0.5


def _canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


@dataclass
class _Invocation:
    task_id: str
    session_id: str
    tool_call_id: str
    source_json: str
    owner_thread: int = field(default_factory=threading.get_ident)
    counter: int = 0
    closed: bool = False
    lock: object = field(default_factory=threading.RLock)

    @property
    def source_tool(self) -> dict:
        # Every consumer receives a fresh copy of the source fixed at entry.
        return json.loads(self.source_json)

    def active(self) -> bool:
        with self.lock:
            return not self.closed and not is_interrupted() and not is_thread_interrupted(self.owner_thread)

    def close(self) -> None:
        with self.lock:
            self.closed = True

    def request_key(self, arguments: dict) -> str:
        with self.lock:
            if not self.active():
                raise RuntimeError("yuanxingmu_invocation_closed")
            index = self.counter
            self.counter += 1
        return hashlib.sha256(_canonical(["hermes-execute-v1", self.task_id, self.session_id,
                                         self.tool_call_id, index, arguments]).encode()).hexdigest()


@contextmanager
def _invocation_scope(binding: dict, tool_name: str, arguments: dict, context: dict):
    session, call = context.get("session_id"), context.get("tool_call_id")
    if (not isinstance(arguments, dict) or not isinstance(session, str) or not session
            or not isinstance(call, str) or not call):
        raise ValueError("yuanxingmu_invocation_identity_unavailable")
    tool = ("file_write" if tool_name in {"write_file", "patch"} else
            "terminal" if tool_name in {"terminal", "process_manage"} else "file_read")
    # Copy before waiting: no mutable model/plugin argument can change the
    # exact source displayed for a final executable candidate.
    invocation = _Invocation(binding["task_id"], session, call,
                             _canonical({"tool": tool, "name": tool_name, "arguments": arguments}))
    token = _INVOCATION.set(invocation)
    try:
        yield invocation
    finally:
        # A reset alone leaves copied contexts live after a hook/tool timeout.
        invocation.close()
        _INVOCATION.reset(token)


def _current_invocation(binding: dict):
    invocation = _INVOCATION.get()
    if invocation is None or invocation.task_id != binding["task_id"] or not invocation.active():
        return None
    from tools.approval_context import _approval_tool_call_id, _approval_session_id
    if (_approval_tool_call_id.get() != invocation.tool_call_id
            or _approval_session_id.get() != invocation.session_id):
        return None
    return invocation


def _tool_review(binding: dict, invocation: _Invocation, arguments: dict, *, cancelled=lambda: False) -> bool:
    """Wait only on a host decision and consume it once before execution.

    Hermes's YOLO, session approvals, permanent allowlist and approval callback
    are deliberately not consulted. A lost consumption reply never retries.
    """
    if cancelled() or not invocation.active():
        return False
    try:
        request_key = invocation.request_key(arguments)
        result = request("request_tool_review", socket_path=binding["broker_socket"], timeout_seconds=60,
                         request_key=request_key, tool="terminal", arguments=arguments)
        # This is the single semantic decision for this final executable
        # candidate. Pending reviews only poll/consume this stored decision.
        if result.get("allowed") is True:
            return result.get("verdict") == "allow" and not cancelled() and invocation.active()
        review_id, digest = result.get("review_id"), result.get("digest")
        if (result.get("status") not in {"pending", "approved"}
                or not isinstance(review_id, str) or re.fullmatch(r"[0-9a-f]{32}", review_id) is None
                or not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
            return False
        deadline = time.monotonic() + _REVIEW_WAIT_SECONDS
        while not cancelled() and invocation.active() and time.monotonic() < deadline:
            result = request("consume_tool_review", socket_path=binding["broker_socket"],
                             review_id=review_id, digest=digest, tool="terminal", arguments=arguments)
            if result.get("review_id") != review_id or result.get("digest") != digest:
                return False
            if result.get("allowed") is True:
                return result.get("status") == "consumed" and not cancelled() and invocation.active()
            if result.get("status") != "pending":
                return False
            time.sleep(_REVIEW_POLL_SECONDS)
    except (OSError, ValueError, RuntimeError, TypeError):
        return False
    return False


def _guard(binding: dict, operation: str, **fields) -> bool:
    if not binding.get("defense_enabled"):
        return True
    try:
        if operation == "inspect_input" and (not isinstance(fields.get("text"), str)
                or len(fields["text"].encode("utf-8")) > 262144):
            return False
        result = request(operation, socket_path=binding["broker_socket"], timeout_seconds=60, **fields)
        return result.get("allowed") is True
    except (OSError, ValueError, RuntimeError, TypeError):
        return False


class YuanxingmuEnvironment(BaseEnvironment):
    is_local = False

    def __init__(self, *, binding: dict, cwd: str, timeout: int):
        super().__init__(cwd=cwd, timeout=timeout)
        self.binding = binding
        self._prefer_nonlogin = True
        self._closed = False
        self._process_lock = threading.RLock()
        self._processes = []

    def init_session(self):
        self._snapshot_ready = False
        self._prefer_nonlogin = True

    def _prepare_command(self, command: str):
        return command, None  # Host sudo credentials are never part of this provider.

    def _before_execute(self):
        with self._process_lock:
            if self._closed or is_interrupted():
                raise EnvironmentConnectionError("yuanxingmu_environment_closed")
        try:
            state = request("describe", socket_path=self.binding["broker_socket"])
        except (OSError, ValueError, RuntimeError) as exc:
            raise EnvironmentConnectionError("yuanxingmu_broker_unavailable") from exc
        if not state.get("allowed") or not state.get("active"):
            raise EnvironmentConnectionError("yuanxingmu_task_not_active")
        if state.get("task_id") != self.binding["task_id"]:
            raise EnvironmentConnectionError("yuanxingmu_task_binding_mismatch")

    def execute(self, command, cwd="", **kwargs):
        # This check remains in the execution provider, independent of the
        # optional Hermes hook dispatcher and its fail-open output hooks.
        arguments = {"command": command, "cwd": cwd or self.cwd}
        if kwargs.get("stdin_data") is not None:
            arguments["stdin_data"] = kwargs["stdin_data"]
        if self.binding.get("defense_enabled"):
            invocation = _current_invocation(self.binding)
            if invocation is None:
                return {"output": _BLOCKED_COMMAND, "returncode": 126}
            arguments["source_tool"] = invocation.source_tool
            try:
                # Freeze the same bytes sent for checking, display and consume.
                arguments = json.loads(_canonical(arguments))
            except (ValueError, TypeError):
                return {"output": _BLOCKED_COMMAND, "returncode": 126}
            allowed = _tool_review(self.binding, invocation, arguments,
                                   cancelled=lambda: self._closed or not invocation.active())
            if not allowed or self._closed or not invocation.active():
                return {"output": _BLOCKED_COMMAND, "returncode": 126}
        # The approved command is not subsequently rewritten into a different
        # background command by BaseEnvironment. Its fixed cwd wrapper remains.
        kwargs["rewrite_compound_background"] = False
        result = super().execute(command, cwd, **kwargs)
        if not _guard(self.binding, "inspect_input", text=result.get("output", "")):
            return {"output": _BLOCKED_INPUT, "returncode": 126}
        return result

    def _run_bash(self, cmd_string, *, login=False, timeout=120, stdin_data=None):
        with self._process_lock:
            invocation = _current_invocation(self.binding) if self.binding.get("defense_enabled") else None
            if self._closed or (self.binding.get("defense_enabled") and invocation is None):
                raise EnvironmentConnectionError("yuanxingmu_environment_closed")
            with invocation.lock if invocation else self._process_lock:
                if invocation is not None and not invocation.active():
                    raise EnvironmentConnectionError("yuanxingmu_invocation_closed")
                process = start(
                    command=["/bin/bash", "--noprofile", "--norc", "-c", cmd_string],
                    workspace=Path(self.binding["workspace"]), broker_socket=Path(self.binding["broker_socket"]),
                    readonly_paths=[Path(self.binding["core_root"]), *([Path(self.binding["skill_dir"])] if self.binding.get("skill_dir") else [])],
                    env={}, bwrap=Path(self.binding["bwrap"]),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                    text=True, encoding="utf-8", errors="replace",
                )
                self._processes.append(process)
        if stdin_data is not None:
            _pipe_stdin(process, stdin_data)
        return process

    def _kill_process(self, process):
        stop(process)

    def cleanup(self):
        with self._process_lock:
            self._closed = True
            processes = list(self._processes)
        for process in processes:
            stop(process)


class YuanxingmuProvider(TerminalEnvironmentProvider):
    name = "yuanxingmu"
    display_name = "Yuanxingmu"
    is_remote = True
    is_container = True
    skip_container_guards = False
    session_isolated_when_nonpersistent = True

    def __init__(self, binding: dict):
        self.binding = dict(binding)
        self.availability = sandbox_available(bwrap=Path(binding["bwrap"]))
        self.environments = []

    def is_available(self):
        return bool(self.availability["available"])

    @property
    def strip_env_keys(self):
        return frozenset({"YUANXINGMU_HERMES_CONFIG", "YUANXINGMU_CORE_ROOT", "HERMES_DASHBOARD_SESSION_TOKEN"})

    @property
    def cache_path_base(self):
        return "/workspace/.hermes"

    def create_environment(self, *, cwd, timeout, task_id="default", image=None, container_config=None, **kwargs):
        if not self.is_available():
            raise EnvironmentConnectionError(str(self.availability["reason"]))
        # Hermes generates task IDs internally. They are observation IDs, not a
        # request to mint or select host authority: all use this one socket.
        environment = YuanxingmuEnvironment(binding=self.binding, cwd=cwd or "/workspace", timeout=timeout)
        environment._before_execute()
        self.environments.append(environment)
        return environment


def _schema(name: str, description: str, properties: dict, required: list[str]) -> dict:
    return {"name": name, "description": description, "parameters": {
        "type": "object", "properties": properties, "required": required, "additionalProperties": False}}


def _identifier(ids: list[str]) -> dict:
    return {"type": "string", "minLength": 1, "maxLength": 128, **({"enum": ids} if ids else {})}


def _invalid() -> str:
    return json.dumps({"allowed": False, "reason": "invalid_tool_arguments"})


def _tool_handler(binding: dict, operation: str):
    def handler(args, **context):
        if not isinstance(args, dict):
            return _invalid()
        fields = {}
        if operation in {"describe", "action_targets"}:
            if args:
                return _invalid()
        elif operation == "read":
            if set(args) != {"resource"} or args["resource"] not in binding["resource_ids"]:
                return _invalid()
            fields = dict(args)
        elif operation == "send":
            if (set(args) != {"destination", "body"} or args["destination"] not in binding["destination_ids"]
                    or not isinstance(args["body"], str) or len(args["body"].encode("utf-8")) > 256 * 1024):
                return _invalid()
            fields = dict(args)
        elif operation in {"draft_email", "propose_action"}:
            if operation == "draft_email" and (not binding.get("reviewed_mail") or set(args) != {"recipient", "subject", "body"}
                    or not all(isinstance(value, str) for value in args.values())
                    or len(args["recipient"]) > 254 or len(args["subject"]) > 200
                    or len(args["body"].encode("utf-8")) > 64 * 1024):
                return _invalid()
            if operation == "propose_action" and (not binding.get("reviewed_actions") or set(args) != {"kind", "target_id", "payload"}
                    or args["kind"] not in {"message", "upload", "form", "overwrite", "delete"}
                    or not isinstance(args["target_id"], str) or not isinstance(args["payload"], dict)):
                return _invalid()
            # Hermes pins these contextvars around registry handler execution.
            # Lack of correlation blocks drafting; it cannot produce a fresh
            # request key on retry and accidentally duplicate a reviewed send.
            from tools.approval_context import _approval_tool_call_id, _approval_session_id
            call_id, session_id = _approval_tool_call_id.get(), _approval_session_id.get() or context.get("session_id")
            if not isinstance(call_id, str) or not call_id or not isinstance(session_id, str) or not session_id:
                return json.dumps({"allowed": False, "reason": "tool_correlation_unavailable"})
            key = hashlib.sha256((session_id + "\0" + call_id).encode()).hexdigest()
            fields = {"request_key": key, "draft" if operation == "draft_email" else "proposal": dict(args)}
        else:
            return _invalid()
        try:
            result = request(operation, socket_path=binding["broker_socket"], **fields)
        except (OSError, ValueError, RuntimeError):
            return json.dumps({"allowed": None, "reason": "broker_response_unavailable", "outcome": "unknown"})
        if operation == "draft_email" and result.get("status") == "pending":
            result = {**result, "message": "草稿已交给元星木工作台，尚未发送。请用户核对收件人、主题和全文后亲自确认。"}
        return json.dumps(result, ensure_ascii=False)
    return handler


def register(ctx):
    path = Path(ctx.get_config("host_config") or os.environ.get("YUANXINGMU_HERMES_CONFIG", ""))
    if not path.is_absolute():
        raise ValueError("yuanxingmu_requires_absolute_host_config")
    binding = json.loads(path.read_text(encoding="utf-8"))
    if binding.get("version") != 1 or not binding.get("task_id"):
        raise ValueError("yuanxingmu_invalid_profile_binding")
    ctx.register_terminal_environment_provider(YuanxingmuProvider(binding))
    if binding.get("skill_dir"):
        selected = ", ".join(binding.get("skill_names", [])) or "未选择技能"
        ctx.register_system_prompt_section(
            "yuanxingmu.selected-skills",
            "操作者为本配置固定的技能：" + selected + "。需要技能内容时，用原生 read_file 读取 "
            + binding["skill_dir"] + "/<技能目录名>/SKILL.md。此目录是只读快照；新增或改变技能须由操作者在元星木工作台选择。",
        )
    declarations = [
        ("yuanxingmu_read", "read", "读取操作者配置的资料；只能选择资料名称。", {"resource": _identifier(binding["resource_ids"])}, ["resource"]),
        ("yuanxingmu_send", "send", "请求权限服务发送到操作者配置的固定接收位置；不能指定网址或改变权限。",
         {"destination": _identifier(binding["destination_ids"]), "body": {"type": "string", "maxLength": 262144}}, ["destination", "body"]),
        ("yuanxingmu_status", "describe", "查看这个配置的真实权限；新建聊天和重新连接不会清除限制。", {}, []),
    ]
    if binding.get("reviewed_mail"):
        declarations.append(("yuanxingmu_prepare_email", "draft_email", "起草等待用户亲自核对的邮件。此工具不发送邮件，不能批准草稿。",
                             {"recipient": {"type": "string", "maxLength": 254}, "subject": {"type": "string", "maxLength": 200},
                              "body": {"type": "string", "maxLength": 65536}}, ["recipient", "subject", "body"]))
    if binding.get("reviewed_actions"):
        declarations.extend([
            ("yuanxingmu_action_targets", "action_targets", "查看操作者配置的消息、上传、表单及文件操作目标。", {}, []),
            ("yuanxingmu_prepare_action", "propose_action", "起草等待用户核对的操作，不会立即执行。目标必须来自yuanxingmu_action_targets。"
             "message的payload为body；upload为filename和content；form为fields对象；overwrite为content；delete为空对象。",
             {"kind": {"type": "string", "enum": ["message", "upload", "form", "overwrite", "delete"]},
              "target_id": {"type": "string"}, "payload": {
                  "type": "object", "description": "仅填写所选 kind 需要的字段，宿主会核对完整内容。",
                  "properties": {
                      "body": {"type": "string", "maxLength": 65536},
                      "filename": {"type": "string", "maxLength": 255},
                      "content": {"type": "string", "maxLength": 65536},
                      "fields": {"type": "object", "additionalProperties": {"type": "string"}},
                  }, "additionalProperties": False}}, ["kind", "target_id", "payload"]),
        ])
    for name, operation, description, properties, required in declarations:
        ctx.register_tool(name=name, toolset="yuanxingmu", schema=_schema(name, description, properties, required),
                          handler=_tool_handler(binding, operation), description=description)
    allowed = _LOCAL_TOOLS | {item[0] for item in declarations}

    def around_tool(tool_name="", args=None, next_call=None, **kwargs):
        # Execution middleware runs on the actual caller. Bounded pre-tool
        # hooks instead receive a copied Context in a separate worker thread.
        # Middleware exceptions before next_call are skipped by Hermes, so all
        # rejected identities/arguments must produce an explicit blocked result.
        blocked = json.dumps({"error": _BLOCKED_COMMAND, "allowed": False}, ensure_ascii=False)
        if tool_name not in allowed or not isinstance(args, dict):
            return blocked
        if tool_name not in _LOCAL_TOOLS or not binding.get("defense_enabled"):
            return next_call(args)
        entered = False
        try:
            with _invocation_scope(binding, tool_name, args, kwargs) as invocation:
                if not invocation.active():
                    return blocked
                # Process-control handlers can act without execute(). Their
                # direct guard belongs here, outside the optional hook worker.
                if tool_name == "process_manage" and not _guard(
                        binding, "guard_tool", tool="terminal", arguments=invocation.source_tool["arguments"]):
                    return blocked
                if not invocation.active():
                    return blocked
                entered = True
                return next_call(args)
        except Exception:
            if entered:
                raise
            return blocked

    ctx.register_middleware("tool_execution", around_tool)

    def before_tool(tool_name="", args=None, **kwargs):
        if tool_name not in allowed:
            return {"action": "block", "message": "此配置没有开放这个工具；请使用已配置的资料、终端或发送工具。"}
        if tool_name in _LOCAL_TOOLS:
            try:
                if not isinstance(args, dict):
                    raise ValueError("invalid_native_arguments")
                invocation = _INVOCATION.get()
                if invocation is not None and (not invocation.active()
                        or invocation.task_id != binding["task_id"]
                        or invocation.session_id != kwargs.get("session_id")
                        or invocation.tool_call_id != kwargs.get("tool_call_id")
                        or invocation.source_tool["name"] != tool_name
                        or _canonical(invocation.source_tool["arguments"]) != _canonical(args)):
                    raise ValueError("yuanxingmu_invocation_mismatch")
            except (ValueError, TypeError):
                return {"action": "block", "message": _BLOCKED_COMMAND}
            if binding.get("defense_enabled") and tool_name != "process_manage":
                # Native Hermes can reject a sudo/write before reaching its
                # terminal backend. Keep host rule blocks here, then judge the
                # complete executable candidate only at the provider below.
                normalized = "file_write" if tool_name in {"write_file", "patch"} else "terminal" if tool_name == "terminal" else "file_read"
                try:
                    verdict = request("guard_rules", socket_path=binding["broker_socket"], timeout_seconds=60,
                                      tool=normalized, arguments=args)
                except (OSError, ValueError, RuntimeError, TypeError):
                    verdict = {}
                if verdict.get("allowed") is not True and verdict.get("verdict") != "review":
                    return {"action": "block", "message": _BLOCKED_COMMAND}
        return None

    # Convenience gate only. Socket-bound Broker decisions and the process
    # network namespace remain effective even if a hook is skipped or fails.
    ctx.register_hook("pre_tool_call", before_tool)

    def transform_result(tool_name="", result=None, **kwargs):
        if tool_name in _LOCAL_TOOLS and not _guard(binding, "inspect_input", text=result):
            return json.dumps({"error": _BLOCKED_INPUT}, ensure_ascii=False)
        return None

    ctx.register_hook("transform_tool_result", transform_result)
