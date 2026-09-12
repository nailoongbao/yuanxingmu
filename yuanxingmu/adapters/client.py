"""Fixed-endpoint Broker client shared by optional native SDK adapters."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hashlib
import json
import os

from ..client import MAX_MESSAGE, request


OPERATIONS = ("read", "send", "describe", "action_targets", "propose_action", "draft_email")
PROPOSALS = frozenset({"propose_action", "draft_email"})
FRAMEWORKS = frozenset({"langchain", "openai_agents", "pydantic_ai", "google_adk", "crewai", "agno", "autogen", "llama_index", "microsoft_agent_framework", "smolagents"})
TOOL_NAMES = {operation: "yuanxingmu_" + operation for operation in OPERATIONS}
DESCRIPTIONS = {
    "read": "Read one host-registered resource. The Broker retains its data restrictions for this task.",
    "send": "Send text to one host-registered destination if the Broker permits it. This can send immediately. "
            "Do not retry an uncertain result; this operation is not deduplicated.",
    "describe": "Inspect the current Broker task's permissions and data restrictions.",
    "action_targets": "List the host-registered targets available for reviewed action proposals.",
    "propose_action": "Save an action proposal for separate host review. This tool cannot approve or execute it. "
                      "A repeated tool call returns the existing record, which may already be cancelled or completed. "
                      "For a form, supply fields as a list of name/value objects.",
    "draft_email": "Save an email draft for separate host review. This tool cannot approve or send mail. "
                   "A repeated tool call returns the existing draft and its current status.",
}


def _object(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError("invalid_tool_arguments")
    return value


def _text(value):
    if type(value) is not str:
        raise ValueError("invalid_tool_arguments")
    return value


def _arguments(operation, arguments):
    fields = {"read": {"resource"}, "send": {"destination", "body"}, "describe": set(),
              "action_targets": set(), "propose_action": {"proposal"}, "draft_email": {"draft"}}
    _object(arguments, fields[operation])
    if operation in {"read", "send"}:
        return {key: _text(value) for key, value in arguments.items()}
    if operation == "draft_email":
        draft = _object(arguments["draft"], {"recipient", "subject", "body"})
        return {"draft": {key: _text(value) for key, value in draft.items()}}
    if operation == "propose_action":
        proposal = _object(arguments["proposal"], {"kind", "target_id", "payload"})
        kind, target_id = _text(proposal["kind"]), _text(proposal["target_id"])
        payload_fields = {"message": {"body"}, "upload": {"filename", "content"}, "form": {"fields"},
                          "overwrite": {"content"}, "delete": set()}
        if kind not in payload_fields:
            raise ValueError("invalid_tool_arguments")
        payload = _object(proposal["payload"], payload_fields[kind])
        if kind == "form":
            # Explicit pairs keep every model-visible object closed to extra
            # properties, including in SDKs with strict function schemas.
            pairs = payload["fields"]
            if type(pairs) is not list or len(pairs) > 64:
                raise ValueError("invalid_tool_arguments")
            submitted = {}
            for item in pairs:
                _object(item, {"name", "value"})
                name, value = _text(item["name"]), _text(item["value"])
                if name in submitted:
                    raise ValueError("duplicate_form_field")
                submitted[name] = value
            payload = {"fields": submitted}
        else:
            payload = {key: _text(value) for key, value in payload.items()}
        return {"proposal": {"kind": kind, "target_id": target_id, "payload": payload}}
    return {}


def decode_arguments(value: str) -> dict:
    """Read an SDK's JSON arguments without accepting duplicate object keys."""
    if type(value) is not str or len(value.encode("utf-8")) > MAX_MESSAGE:
        raise ValueError("invalid_tool_arguments")

    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate_tool_argument")
            result[key] = item
        return result

    def constant(_):
        raise ValueError("invalid_tool_arguments")

    result = json.loads(value, object_pairs_hook=pairs, parse_constant=constant)
    if type(result) is not dict:
        raise ValueError("invalid_tool_arguments")
    return result


def encode_result(result: dict) -> str:
    # Return the Broker's current status verbatim, including proposal replays.
    return json.dumps(result, ensure_ascii=True, sort_keys=True)


@dataclass(frozen=True, slots=True)
class NativeTools:
    """Bind an explicit worker socket and host-selected persistent session ID.

    A session ID is not a credential. The Broker socket determines the task.
    Keep the same ID when resuming that session, and choose a new ID for a new
    session. Python immutability does not isolate this object from hostile code
    in its own process; a host supervisor must provide that boundary separately.
    """

    socket_path: str = field(repr=False)
    session_id: str = field(repr=False)

    def __post_init__(self):
        path = os.fspath(self.socket_path)
        if type(path) is not str or not os.path.isabs(path) or "\x00" in path:
            raise ValueError("native_tools_require_absolute_socket")
        if type(self.session_id) is not str or not self.session_id or len(self.session_id) > 256:
            raise ValueError("native_tools_require_host_session")
        object.__setattr__(self, "socket_path", path)

    def request_key(self, operation: str, framework: str, tool_call_id: str) -> str:
        if operation not in PROPOSALS or framework not in FRAMEWORKS:
            raise ValueError("invalid_native_proposal_context")
        if type(tool_call_id) is not str or not tool_call_id or len(tool_call_id) > 512:
            raise ValueError("native_tool_call_id_required")
        binding = ["yuanxingmu-native-v1", framework, self.session_id, operation, tool_call_id]
        digest = hashlib.sha256(json.dumps(binding, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
        return "native_v1_" + digest

    def invoke(self, operation: str, arguments: dict, *, framework: str, tool_call_id: str | None = None) -> dict:
        if operation not in OPERATIONS or framework not in FRAMEWORKS:
            raise ValueError("invalid_native_operation")
        fields = _arguments(operation, arguments)
        if operation in PROPOSALS:
            fields["request_key"] = self.request_key(operation, framework, tool_call_id)
        # Always explicit: environment variables and model parameters cannot
        # redirect the endpoint, select a task, or invoke a host review method.
        # There is deliberately no automatic transport retry here.
        return request(operation, socket_path=self.socket_path, **fields)

    async def ainvoke(self, operation: str, arguments: dict, *, framework: str,
                      tool_call_id: str | None = None) -> dict:
        return await asyncio.to_thread(self.invoke, operation, arguments,
                                       framework=framework, tool_call_id=tool_call_id)
