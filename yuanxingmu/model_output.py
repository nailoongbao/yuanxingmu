"""Bounded OpenAI chat response inspection before any provider bytes are released.

Supports one text/tool choice in JSON or SSE. This buffers the entire response:
it does not claim to preserve live token streaming. Unsupported/malformed output
fails closed. Tool execution still requires the independent native tool checks.
The legacy inspect_text API remains prose-only. With host protected data enabled,
inspect_visible additionally reassembles tool/function arguments and retains all
provider metadata for an independent deterministic check before byte release.
"""
from __future__ import annotations

import json
import sqlite3

MAX_RESPONSE = 2 * 1024 * 1024
MAX_EVENTS = 4096
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
    elif type(reason) is str and reason in {"protected_value_blocked", "protected_check_failed"}:
        state = ("内容含有受保护字段。" if reason == "protected_value_blocked"
                 else "敏感字段检查无法完成。")
        next_step = "请在元星木工作台查看记录并处理；这次操作没有自动重试。"
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


class _VisibleMessage:
    """One supported choice, including interleaved tool deltas by index."""
    def __init__(self):
        self.streams = {key: [] for key in ("content", "refusal", "reasoning", "reasoning_content")}
        self.tools = {}
        self.function = None

    @staticmethod
    def _parts(function, state):
        if type(function) is not dict or set(function) - {"name", "arguments"}:
            raise InvalidModelOutput("unsupported_model_function")
        for key in ("name", "arguments"):
            fragment = function.get(key)
            if fragment is not None:
                if type(fragment) is not str:
                    raise InvalidModelOutput("invalid_model_function_fragment")
                state[key].append(fragment)

    def add(self, message, *, streaming):
        for key, text in _message_text(message, streaming=streaming):
            self.streams[key].append(text)
        calls = message.get("tool_calls")
        if calls:
            if self.function is not None:
                raise InvalidModelOutput("mixed_model_function_protocols")
            seen_indexes = set()
            for position, call in enumerate(calls):
                if set(call) - {"index", "id", "type", "function"}:
                    raise InvalidModelOutput("unsupported_model_tool")
                index = call.get("index") if streaming else call.get("index", position)
                if type(index) is not int or not 0 <= index < 64 or (not streaming and index != position):
                    raise InvalidModelOutput("invalid_model_tool_index")
                if index in seen_indexes:
                    raise InvalidModelOutput("duplicate_model_tool_index")
                seen_indexes.add(index)
                state = self.tools.setdefault(index, {"id": None, "type": None, "name": [], "arguments": []})
                for key in ("id", "type"):
                    part = call.get(key)
                    if part is not None:
                        if type(part) is not str or not part or len(part) > 256:
                            raise InvalidModelOutput("invalid_model_tool_identity")
                        if state[key] is not None and state[key] != part:
                            raise InvalidModelOutput("changing_model_tool_identity")
                        state[key] = part
                if state["type"] not in {None, "function"}:
                    raise InvalidModelOutput("unsupported_model_tool_type")
                if call.get("function") is not None:
                    self._parts(call["function"], state)
        legacy = message.get("function_call")
        if legacy is not None:
            if self.tools:
                raise InvalidModelOutput("mixed_model_function_protocols")
            if self.function is None:
                self.function = {"name": [], "arguments": []}
            self._parts(legacy, self.function)

    @staticmethod
    def _function(state):
        name = "".join(state["name"])
        if not name or len(name) > 256 or any(ord(char) < 32 for char in name):
            raise InvalidModelOutput("invalid_model_function_name")
        arguments = _object("".join(state["arguments"]))
        if type(arguments) is not dict:
            raise InvalidModelOutput("model_function_object_required")
        return {"name": name, "arguments": arguments}

    def finish(self, reason):
        visible = {key: "".join(parts) for key, parts in self.streams.items() if parts}
        if self.tools:
            if reason != "tool_calls" or sorted(self.tools) != list(range(len(self.tools))):
                raise InvalidModelOutput("incomplete_model_tools")
            identifiers, calls = set(), []
            for index in sorted(self.tools):
                state = self.tools[index]
                if not state["id"] or state["type"] != "function" or state["id"] in identifiers:
                    raise InvalidModelOutput("invalid_model_tool_identity")
                identifiers.add(state["id"])
                calls.append({"index": index, "id": state["id"], "type": "function",
                              "function": self._function(state)})
            visible["tool_calls"] = calls
        elif self.function is not None:
            if reason != "function_call":
                raise InvalidModelOutput("incomplete_model_function")
            visible["function_call"] = self._function(self.function)
        elif reason != "stop":
            raise InvalidModelOutput("missing_model_tool_call")
        return visible


def inspect_visible(raw: bytes, content_type: str) -> dict:
    """Decode the complete supported response for host private-value matching.

    Returns the original provider objects plus assembled visible fields. This
    is private inspection material, NOT an audit record. Tool argument strings
    must form complete JSON objects, with duplicate keys rejected. SSE text and
    function/name/argument fragments are joined in their own stream or call
    index, never across different calls. IDs must stay stable. SSE comments and
    otherwise unused metadata remain in the candidate instead of being dropped.
    """
    if type(raw) is not bytes or len(raw) > MAX_RESPONSE:
        raise InvalidModelOutput("model_response_too_large")
    if type(content_type) is not str:
        raise InvalidModelOutput("unsupported_model_content_type")
    kind = content_type.split(";", 1)[0].strip().lower()
    message = _VisibleMessage()
    envelopes, comments = [], []
    finish = None
    if kind == "application/json":
        envelope = _object(raw)
        if type(envelope) is not dict or type(envelope.get("choices")) is not list or len(envelope["choices"]) != 1:
            raise InvalidModelOutput("one_model_choice_required")
        choice = envelope["choices"][0]
        if type(choice) is not dict or type(choice.get("index")) is not int or choice["index"] != 0:
            raise InvalidModelOutput("one_model_choice_required")
        finish = choice.get("finish_reason")
        if type(finish) is not str or finish not in {"stop", "tool_calls", "function_call"}:
            raise InvalidModelOutput("incomplete_model_output")
        message.add(choice.get("message"), streaming=False)
        envelopes.append(envelope)
    elif kind == "text/event-stream":
        try:
            text = raw.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n")
        except UnicodeError:
            raise InvalidModelOutput("invalid_model_encoding") from None
        if not text.endswith("\n\n"):
            raise InvalidModelOutput("incomplete_model_event")
        events = text.split("\n\n")
        if len(events) > MAX_EVENTS + 1:
            raise InvalidModelOutput("too_many_model_events")
        done = finished = seen = False
        for event in events:
            data = []
            for line in event.splitlines():
                if not line:
                    continue
                if line.startswith(":"):
                    comments.append(line[1:])
                elif line.startswith("data:"):
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
            envelope = _object(value)
            if type(envelope) is not dict or type(envelope.get("choices")) is not list or len(envelope["choices"]) > 1:
                raise InvalidModelOutput("one_model_choice_required")
            envelopes.append(envelope)
            if not envelope["choices"]:
                if not finished or "usage" not in envelope:
                    raise InvalidModelOutput("unexpected_empty_model_choice")
                continue
            if finished:
                raise InvalidModelOutput("model_delta_after_finish")
            choice = envelope["choices"][0]
            if type(choice) is not dict or type(choice.get("index")) is not int or choice["index"] != 0:
                raise InvalidModelOutput("one_model_choice_required")
            seen = True
            message.add(choice.get("delta"), streaming=True)
            finish = choice.get("finish_reason")
            if finish is not None:
                if type(finish) is not str or finish not in {"stop", "tool_calls", "function_call"}:
                    raise InvalidModelOutput("incomplete_model_output")
                finished = True
        if not (done and finished and seen):
            raise InvalidModelOutput("incomplete_model_stream")
    else:
        raise InvalidModelOutput("unsupported_model_content_type")
    return {"provider_envelopes": envelopes, "assembled": message.finish(finish), "sse_comments": comments}


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

    def _invalid_protected(self):
        """Commit a fixed failure without handing parser exceptions to audit."""
        from .protected_boundary import ProtectedContentError
        return self._record_protected(ProtectedContentError(invalid=True))

    def _record_protected(self, error):
        from .authority import AuthorizationError
        try:
            self.broker._protected_failure(self.task_id, error)
        except AuthorizationError as exc:
            return exc.reason
        except Exception:
            # Broker's failure path marks storage unhealthy. Never let a
            # failing audit restore the original provider/request bytes.
            return "defense_storage_fault"
        return error.reason

    def preflight(self, request_body):
        """Check admission and decoded protected request fields before network."""
        from .authority import AuthorizationError
        request = None
        with self.broker._lock:
            try:
                self.broker._require_admission(self.task_id)
                if getattr(self.broker, "protected_data", None) is not None:
                    try:
                        if type(request_body) is not bytes or len(request_body) > MAX_RESPONSE:
                            raise InvalidModelOutput("model_request_too_large")
                        request = _object(request_body)
                        if type(request) is not dict:
                            raise InvalidModelOutput("model_request_object_required")
                    except InvalidModelOutput:
                        reason = self._invalid_protected()
                    else:
                        # Includes all messages, role/content arrays, tool
                        # definitions, nested arguments, and extra metadata.
                        self.broker._protect(self.task_id, request)
                        return None
                else:
                    return None
            except AuthorizationError as exc:
                reason = exc.reason
            except (OSError, sqlite3.Error):
                reason = "defense_storage_fault"
        if request is None:
            try:
                # This only selects a fixed response envelope. It cannot allow
                # the rejected request or expose its parser exception.
                request = _object(request_body) if type(request_body) is bytes and len(request_body) <= MAX_RESPONSE else None
            except InvalidModelOutput:
                request = None
        kind = "text/event-stream" if type(request) is dict and request.get("stream") is True else "application/json"
        return kind, withheld_response(kind, reason=reason, preflight=True)

    def __call__(self, raw, content_type):
        from .authority import AuthorizationError
        from .protected_boundary import ProtectedContentError
        with self.broker._lock:
            try:
                self.broker._require_admission(self.task_id)
            except AuthorizationError as exc:
                return withheld_response(content_type, reason=exc.reason)
            except (OSError, sqlite3.Error):
                return withheld_response(content_type, reason="defense_storage_fault")
            if getattr(self.broker, "protected_data", None) is not None:
                try:
                    candidate = inspect_visible(raw, content_type)
                except (InvalidModelOutput, ValueError, TypeError, UnicodeError, RecursionError):
                    return withheld_response(content_type, reason=self._invalid_protected())
                try:
                    self.broker._protect(self.task_id, candidate)
                except AuthorizationError as exc:
                    return withheld_response(content_type, reason=exc.reason)
                except (OSError, sqlite3.Error):
                    return withheld_response(content_type, reason="defense_storage_fault")
            if self.broker.guards is None:
                return raw
            try:
                try:
                    if not self.broker.guards.policy.alignment_enabled:
                        result = self.broker.guards.check_response("")
                    else:
                        text = inspect_text(raw, content_type)
                        result = self.broker.guards.check_response(text, **self.broker._review_context(self.task_id))
                except InvalidModelOutput as exc:
                    result = self.broker.guards._rule("alignment", "block", str(exc),
                        "模型返回不完整或包含尚不支持的格式，已暂不展示。", raw)
            except ProtectedContentError as exc:
                # Guards checks its input and _finish output using the PURE
                # callback. This branch must commit the pause/audit itself,
                # including an error thrown inside the _rule fallback above.
                return withheld_response(content_type, reason=self._record_protected(exc))
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
