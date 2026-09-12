"""Bounded OpenAI chat response inspection before any provider bytes are released.

Supports one text/tool choice in JSON or SSE. This buffers the entire response:
it does not claim to preserve live token streaming. Unsupported/malformed output
fails closed. Tool execution still requires the independent native tool checks.
"""
from __future__ import annotations

import json
import sqlite3

MAX_RESPONSE = 2 * 1024 * 1024
WITHHELD = "【元星木防护提醒】这次回答未通过检查，已暂不展示。请在元星木工作台查看原因；若工作已暂停，需要由你核对后恢复。"
_STORAGE_REASONS = {"defense_storage_fault", "storage_fault", "invalid_quarantine_state"}
_ADMISSION_REASONS = {"task_paused", "task_revoked", *_STORAGE_REASONS}


def _host_notice(reason, *, preflight):
    if reason is None and not preflight:
        return WITHHELD
    if reason == "task_paused":
        state = "这份工作已暂停。"
        next_step = "请在元星木工作台核对原因并恢复后，再继续聊天。"
    elif reason == "task_revoked":
        state = "这份工作的权限已撤销。"
        next_step = "请在元星木工作台查看状态；恢复暂停不会重新授予权限。"
    elif type(reason) is str and reason in _STORAGE_REASONS:
        state = "防护状态无法可靠读取或保存，已停止继续处理。"
        next_step = "请在元星木工作台查看并处理防护服务故障。"
    else:
        state = "宿主当前无法确认这份工作的权限，已停止继续处理。"
        next_step = "请在元星木工作台查看工作状态。"
    delivery = "本次请求未发送给模型。" if preflight else "本次返回的内容已暂不展示。"
    return "【元星木防护提醒】" + state + delivery + next_step


class InvalidModelOutput(ValueError):
    pass


def _object(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InvalidModelOutput("duplicate_model_key")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(InvalidModelOutput("invalid_model_number")))
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise InvalidModelOutput("invalid_model_json") from exc


def _message_text(value, *, streaming):
    if type(value) is not dict:
        raise InvalidModelOutput("invalid_model_message")
    known = {"role", "content", "refusal", "reasoning", "reasoning_content", "tool_calls", "function_call"}
    if set(value) - known or value.get("role", "assistant") != "assistant":
        raise InvalidModelOutput("unsupported_model_message")
    parts = []
    for key in ("content", "refusal", "reasoning", "reasoning_content"):
        item = value.get(key)
        if item is not None:
            if type(item) is not str:
                raise InvalidModelOutput("unsupported_model_text")
            parts.append((key, item))
    tools = value.get("tool_calls")
    if tools is not None and (type(tools) is not list or len(tools) > 64 or any(type(t) is not dict for t in tools)):
        raise InvalidModelOutput("invalid_model_tools")
    if value.get("function_call") is not None and type(value["function_call"]) is not dict:
        raise InvalidModelOutput("invalid_model_function")
    if not streaming and value.get("role") != "assistant":
        raise InvalidModelOutput("missing_assistant_role")
    return parts


def inspect_text(raw: bytes, content_type: str) -> str:
    """Parse complete answer/reasoning/refusal text, without a prefix limit.

    Native tool cards may display call arguments too. Those are covered by
    separate execution checks, not by this text-only response review.
    """
    if type(raw) is not bytes or len(raw) > MAX_RESPONSE:
        raise InvalidModelOutput("model_response_too_large")
    kind = content_type.split(";", 1)[0].strip().lower()
    streams = {key: [] for key in ("content", "refusal", "reasoning", "reasoning_content")}
    if kind == "application/json":
        value = _object(raw)
        if type(value) is not dict or type(value.get("choices")) is not list or len(value["choices"]) != 1:
            raise InvalidModelOutput("one_model_choice_required")
        choice = value["choices"][0]
        if (type(choice) is not dict or type(choice.get("index")) is not int or choice["index"] != 0
                or choice.get("finish_reason") not in {"stop", "tool_calls", "function_call"}):
            raise InvalidModelOutput("incomplete_model_output")
        for key, text in _message_text(choice.get("message"), streaming=False):
            streams[key].append(text)
    elif kind == "text/event-stream":
        try:
            text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeError as exc:
            raise InvalidModelOutput("invalid_model_encoding") from exc
        if not text.endswith("\n\n"):
            raise InvalidModelOutput("incomplete_model_event")
        done = finished = seen_choice = False
        for event in text.split("\n\n"):
            data = []
            for line in event.splitlines():
                if not line or line.startswith(":"):
                    continue
                if line.startswith("data:"):
                    data.append(line[5:].removeprefix(" "))
                elif line == "event: message":
                    continue
                else:
                    raise InvalidModelOutput("unsupported_model_event")
            if not data:
                continue
            if done:
                raise InvalidModelOutput("model_data_after_done")
            value = "\n".join(data)
            if value == "[DONE]":
                done = True
                continue
            value = _object(value)
            if type(value) is not dict or type(value.get("choices")) is not list or len(value["choices"]) > 1:
                raise InvalidModelOutput("one_model_choice_required")
            if not value["choices"]:
                if not finished or "usage" not in value:
                    raise InvalidModelOutput("unexpected_empty_model_choice")
                continue
            if finished:
                raise InvalidModelOutput("model_delta_after_finish")
            choice = value["choices"][0]
            if type(choice) is not dict or type(choice.get("index")) is not int or choice["index"] != 0:
                raise InvalidModelOutput("one_model_choice_required")
            seen_choice = True
            for key, item in _message_text(choice.get("delta"), streaming=True):
                streams[key].append(item)
            finish = choice.get("finish_reason")
            if finish is not None:
                if finish not in {"stop", "tool_calls", "function_call"}:
                    raise InvalidModelOutput("incomplete_model_output")
                finished = True
        if not (done and finished and seen_choice):
            raise InvalidModelOutput("incomplete_model_stream")
    else:
        raise InvalidModelOutput("unsupported_model_content_type")
    # Preserve field separation so fragmented tokens cannot hide an instruction.
    return "\n\n".join(key + ":\n" + "".join(values) for key, values in streams.items() if any(values))


def withheld_response(content_type: str, *, reason: str | None = None, preflight=False) -> bytes:
    """A clearly labelled host notice, never represented as a model's verdict."""
    # Only fixed host text is selected. Never interpolate an exception message,
    # provider content or caller-supplied reason into the notice.
    notice = _host_notice(reason, preflight=preflight)
    base = {"id": "yuanxingmu-host-intervention", "model": "yuanxingmu-host", "created": 0}
    if content_type.lower().startswith("text/event-stream"):
        value = {**base, "object": "chat.completion.chunk", "choices": [{"index": 0,
                 "delta": {"role": "assistant", "content": notice}, "finish_reason": "stop"}]}
        return ("data: " + json.dumps(value, ensure_ascii=False) + "\n\ndata: [DONE]\n\n").encode("utf-8")
    return json.dumps({**base, "object": "chat.completion", "choices": [{"index": 0,
                       "message": {"role": "assistant", "content": notice}, "finish_reason": "stop"}]}, ensure_ascii=False).encode("utf-8")


class ModelOutputGuard:
    """Host callback; the native process cannot turn it off or supply its verdict."""
    def __init__(self, broker, task_id):
        self.broker, self.task_id = broker, task_id

    def preflight(self, request_body):
        """Do not spend another upstream request after a committed pause."""
        from .authority import AuthorizationError
        with self.broker._lock:
            try:
                self.broker._require_admission(self.task_id)
            except AuthorizationError as exc:
                reason = exc.reason
            except (OSError, sqlite3.Error):
                reason = "defense_storage_fault"
            else:
                return None
        try:
            request = _object(request_body)
        except InvalidModelOutput:
            request = None
        kind = "text/event-stream" if type(request) is dict and request.get("stream") is True else "application/json"
        return kind, withheld_response(kind, reason=reason, preflight=True)

    def __call__(self, raw, content_type):
        from .authority import AuthorizationError
        with self.broker._lock:
            try:
                self.broker._require_admission(self.task_id)
            except AuthorizationError as exc:
                return withheld_response(content_type, reason=exc.reason)
            except (OSError, sqlite3.Error):
                return withheld_response(content_type, reason="defense_storage_fault")
            if not self.broker.guards.policy.alignment_enabled:
                result = self.broker.guards.check_response("")
            else:
                try:
                    text = inspect_text(raw, content_type)
                    result = self.broker.guards.check_response(text, **self.broker._review_context(self.task_id))
                except InvalidModelOutput as exc:
                    result = self.broker.guards._rule("alignment", "block", str(exc),
                        "模型返回不完整或包含尚不支持的格式，已暂不展示。", raw)
                except AuthorizationError as exc:
                    return withheld_response(content_type, reason=exc.reason)
                except (OSError, sqlite3.Error):
                    return withheld_response(content_type, reason="defense_storage_fault")
            try:
                self.broker._guard_result(self.task_id, result)
            except AuthorizationError as exc:
                if exc.reason in _ADMISSION_REASONS:
                    return withheld_response(content_type, reason=exc.reason)
                return withheld_response(content_type)
            except (OSError, sqlite3.Error):
                return withheld_response(content_type, reason="defense_storage_fault")
            return raw
