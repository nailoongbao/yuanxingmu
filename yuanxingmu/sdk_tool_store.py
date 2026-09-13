"""Host-owned original tool receipts for the fixed Google ADK runtime.

The worker can name an original model-issued call but cannot supply a result,
choose a task/session, or provide an idempotency key. The journal reuses the
private ModelStore file protocol; synthetic completion envelopes below are
storage serialization only and are never sent to a model. Its independent
limit is 128 tool records. An uncommitted outcome stops further dispatch.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import threading

from .adapters.client import TOOL_NAMES, _arguments
from .authority import AuthorizationError
from .client import MAX_MESSAGE
from .gateway_network import _listen, _private_directory, _Serving
from .sdk_model_store import ModelStore, ModelStoreError, _dump, _json


_OPERATIONS = {"read", "describe", "action_targets", "propose_action", "draft_email"}
_EFFECTS = {"propose_action", "draft_email", "request_action"}
_BY_NAME = {TOOL_NAMES[op]: op for op in _OPERATIONS}
_BY_NAME["yuanxingmu_request_action"] = "request_action"


def _fail():
    raise ValueError("sdk_host_tool_result_unavailable")


def _summary(result):
    return {key: value for key, value in result.items()
            if key in {"allowed", "reason", "status", "outcome", "started"}}


class SdkToolServer:
    def __init__(self, broker, task_id, socket_path, private_directory, session_id,
                 model_store, *, automatic_actions=False, resume=False):
        if (type(automatic_actions) is not bool or type(resume) is not bool
                or not callable(getattr(model_store, "lookup_tool_call", None))):
            _fail()
        self.broker, self.task_id, self.session_id = broker, task_id, session_id
        self.model_store, self.automatic_actions = model_store, automatic_actions
        self.path = Path(socket_path).absolute()
        self.store = ModelStore(private_directory, session_id, create=not resume)
        self._mutex = threading.Lock()
        self._serving = None

    def _call(self, nonce, supplied):
        original = self.model_store.lookup_tool_call(nonce)
        if (type(original) is not dict or original.get("id") != nonce
                or original.get("type") != "function" or type(original.get("function")) is not dict):
            _fail()
        function = original["function"]
        operation = _BY_NAME.get(function.get("name"))
        if operation is None or (operation == "request_action" and not self.automatic_actions):
            _fail()
        arguments = _json(function["arguments"].encode("utf-8"), limit=MAX_MESSAGE)
        normalized = _arguments("propose_action" if operation == "request_action" else operation, arguments)
        if operation == "request_action" and normalized["proposal"]["kind"] not in {"message", "upload", "form"}:
            _fail()
        call = {"op": operation, **normalized}
        if type(supplied) is not dict or _dump(supplied) != _dump(call):
            _fail()
        return call

    def _request(self, nonce, call):
        # The host derives both the storage binding and the business key.
        raw = _dump({"model": "yuanxingmu-host-tool-store-v1", "messages": [{"role": "user", "content":
            _dump(["google_adk", self.session_id, nonce, call]).decode("utf-8")} ]})
        business = dict(call)
        if call["op"] in _EFFECTS:
            namespace = "automatic" if call["op"] == "request_action" else "reviewed"
            binding = ["yuanxingmu-google-adk-" + namespace + "-v1", self.session_id, call["op"], nonce]
            digest = hashlib.sha256(json.dumps(binding, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
            business["request_key"] = "adk_" + namespace + "_v1_" + digest
        return raw, business

    @staticmethod
    def _stored(raw):
        envelope = _json(raw)
        result = _json(envelope["choices"][0]["message"]["content"].encode("utf-8"))
        if type(result) is not dict or type(result.get("allowed")) is not bool:
            _fail()
        return result

    def _current(self, business, original):
        # Called under the Broker lock, after current admission. Definite
        # denials remain denials: no retry can turn them into a new effect.
        if original["allowed"] is False:
            return _summary(original)
        operation = business["op"]
        if operation in {"read", "describe", "action_targets"}:
            return _summary(self.broker.dispatch(self.task_id, business))
        if operation == "draft_email":
            if self.broker.mail is None:
                _fail()
            self.broker._guard_tool(self.task_id, "yuanxingmu_prepare_email", business["draft"])
            draft = self.broker.mail.get(self.task_id, original["draft_id"])["draft"]
            return {"allowed": True, "status": draft["status"]}
        if self.broker.actions is None:
            _fail()
        if operation == "propose_action":
            self.broker._guard_tool(self.task_id, "yuanxingmu_prepare_action", business["proposal"])
        current = self.broker.actions.prior(self.task_id, business["request_key"], business["proposal"])
        if current is None or current["id"] != original["id"]:
            _fail()
        return {"allowed": True, "started": False, **_summary(current)}

    def dispatch(self, request):
        """Internal bounded RPC; no caller-supplied receipt is ever accepted."""
        ticket = None
        if not self._mutex.acquire(blocking=False):
            return {"allowed": False, "reason": "sdk_tool_busy"}
        try:
            if (type(request) is not dict or set(request) != {"op", "nonce", "call"}
                    or type(request["op"]) is not str or request["op"] not in {"sdk_tool", "sdk_tool_result"}):
                _fail()
            call = self._call(request["nonce"], request["call"])
            raw, business = self._request(request["nonce"], call)
            # This is the same lock ordering used by all Broker endpoints:
            # current admission through effect/result persistence is serialized.
            with self.broker._lock:
                self.broker._require_admission(self.task_id)
                if request["op"] == "sdk_tool_result":
                    result = self._stored(self.store.lookup(raw))
                    return {"allowed": True, "result": result}
                ticket = self.store.begin(raw, stop_on_unknown=True)
                if ticket.replay is not None:
                    result = self._stored(ticket.replay)
                    current = self._current(business, result)
                else:
                    result = self.broker.dispatch(self.task_id, business)
                    if type(result) is not dict or type(result.get("allowed")) is not bool:
                        _fail()
                    envelope = _dump({"choices": [{"index": 0, "finish_reason": "stop", "message": {
                        "role": "assistant", "content": _dump(result).decode("utf-8")}}]})
                    result = self._stored(self.store.complete(ticket, envelope, "application/json"))
                    current = _summary(result)
                # A durable result must precede release. Even finish/storage
                # faults refuse success; subsequent calls cannot redispatch.
                self.store.finish(ticket)
                ticket = None
                return {"allowed": True, "result": result, "current": current}
        except AuthorizationError as error:
            return {"allowed": False, "reason": error.reason}
        except (ModelStoreError, OSError, ValueError, TypeError, KeyError, RuntimeError, RecursionError):
            return {"allowed": False, "reason": "sdk_host_tool_result_unavailable"}
        finally:
            if ticket is not None:
                try:
                    self.store.finish(ticket)
                except (OSError, ValueError):
                    pass
            self._mutex.release()

    def __enter__(self):
        if self._serving is not None:
            raise RuntimeError("sdk_tool_server_already_running")
        if len(os.fsencode(self.path)) > 100:
            raise ValueError("unix_socket_path_too_long")
        _private_directory(self.path.parent)
        owner = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.connection.settimeout(120)
                try:
                    raw = self.rfile.readline(MAX_MESSAGE + 1)
                    if not raw.endswith(b"\n"):
                        _fail()
                    request = _json(raw, limit=MAX_MESSAGE)
                    response = owner.dispatch(request)
                    body = json.dumps(response, ensure_ascii=True, allow_nan=False).encode() + b"\n"
                    if len(body) > MAX_MESSAGE:
                        _fail()
                except (OSError, ValueError, TypeError, RecursionError):
                    body = b'{"allowed":false,"reason":"sdk_host_tool_result_unavailable"}\n'
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

        server, path = _listen(socket.AF_UNIX, str(self.path), Handler)
        self._serving = _Serving(server, path)
        return self

    def close(self):
        if self._serving is not None:
            serving, self._serving = self._serving, None
            serving.close()

    def __exit__(self, *exception):
        self.close()
