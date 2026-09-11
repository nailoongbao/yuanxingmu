"""A bounded synchronous MCP client for explicit stdio test configurations."""
from __future__ import annotations

import base64
import binascii
import json
import math
import os
from pathlib import Path
import queue
import subprocess
import threading
import time


class ProtocolError(RuntimeError):
    pass


PROTOCOL_VERSION = "2024-11-05"
# Both integration-02 fixture and FastMCP 4.0.3 traces negotiate this version.
# A server may propose another version; this narrow client must not silently
# claim compatibility with a protocol it has not implemented and exercised.
SUPPORTED_PROTOCOL_VERSIONS = frozenset({PROTOCOL_VERSION})
MAX_NOTIFICATIONS = 100
_UNSET = object()


def _object(value, description: str) -> dict:
    if not isinstance(value, dict):
        raise ProtocolError(f"{description} must be an object")
    return value


def _string(value, description: str, *, nonempty: bool = False) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        raise ProtocolError(f"{description} must be a {'nonempty ' if nonempty else ''}string")
    return value


def _optional_strings(value: dict, names: tuple[str, ...], description: str) -> None:
    for name in names:
        if name in value:
            _string(value[name], f"{description}.{name}")


def _meta(value: dict, description: str) -> None:
    if "_meta" in value:
        _object(value["_meta"], f"{description}._meta")


def _number(value) -> bool:
    return type(value) in (int, float) and (type(value) is int or math.isfinite(value))


def _response(value, expected_id=_UNSET) -> dict:
    response = _object(value, "JSON-RPC response")
    if response.get("jsonrpc") != "2.0":
        raise ProtocolError("JSON-RPC version must be exactly '2.0'")
    if "method" in response:
        raise ProtocolError("Unsolicited MCP requests are unsupported")
    if set(response) - {"jsonrpc", "id", "result", "error"}:
        raise ProtocolError("Unexpected JSON-RPC response envelope fields")
    identifier = response.get("id")
    if type(identifier) not in (int, str):
        raise ProtocolError("MCP response ID must be a string or integer, not bool, float or null")
    if expected_id is not _UNSET and (type(identifier) is not type(expected_id) or identifier != expected_id):
        raise ProtocolError("Unexpected MCP response ID")
    if ("result" in response) == ("error" in response):
        raise ProtocolError("JSON-RPC response must contain exactly one of result and error")
    if "error" in response:
        error = _object(response["error"], "JSON-RPC error")
        if set(error) - {"code", "message", "data"} or type(error.get("code")) is not int:
            raise ProtocolError("JSON-RPC error must have an integer code and valid fields")
        _string(error.get("message"), "JSON-RPC error.message")
    return response


def _notification(value: dict) -> None:
    if value.get("jsonrpc") != "2.0":
        raise ProtocolError("JSON-RPC notification version must be exactly '2.0'")
    if set(value) - {"jsonrpc", "method", "params"}:
        raise ProtocolError("Invalid MCP notification envelope")
    method = value.get("method")
    if not isinstance(method, str) or not method.startswith("notifications/") or method == "notifications/":
        raise ProtocolError("Unsupported or invalid MCP notification method")
    params = value.get("params", {})
    _object(params, "MCP notification params")
    _meta(params, "MCP notification params")
    if method == "notifications/message":
        if type(params.get("level")) is not str or params["level"] not in {"debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"}:
            raise ProtocolError("Invalid MCP logging notification level")
        if "data" not in params:
            raise ProtocolError("MCP logging notification is missing data")
        _optional_strings(params, ("logger",), "MCP notification")
    elif method == "notifications/progress":
        if type(params.get("progressToken")) not in (str, int) or not _number(params.get("progress")):
            raise ProtocolError("Invalid MCP progress notification")
        if "total" in params and not _number(params["total"]):
            raise ProtocolError("Invalid MCP progress total")
        _optional_strings(params, ("message",), "MCP progress notification")
    elif method == "notifications/cancelled":
        if type(params.get("requestId")) not in (str, int):
            raise ProtocolError("Invalid MCP cancellation request ID")
        _optional_strings(params, ("reason",), "MCP cancellation notification")
    elif method == "notifications/resources/updated":
        _string(params.get("uri"), "MCP updated resource URI", nonempty=True)


def _base64(value, description: str) -> None:
    _string(value, description)
    try:
        base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ProtocolError(f"{description} is not valid base64") from exc


def _annotations(block: dict) -> None:
    _meta(block, "MCP content")
    if "annotations" not in block:
        return
    annotations = _object(block["annotations"], "MCP content annotations")
    if "audience" in annotations:
        audience = annotations["audience"]
        if not isinstance(audience, list) or any(type(role) is not str or role not in ("user", "assistant") for role in audience):
            raise ProtocolError("Invalid MCP content annotation audience")
    if "priority" in annotations:
        priority = annotations["priority"]
        if not _number(priority) or not 0 <= priority <= 1:
            raise ProtocolError("Invalid MCP content annotation priority")
    _optional_strings(annotations, ("lastModified",), "MCP content annotations")


def _tool_result(value) -> dict:
    result = _object(value, "MCP tools/call result")
    _meta(result, "MCP tools/call result")
    if "isError" in result and type(result["isError"]) is not bool:
        raise ProtocolError("MCP tools/call isError must be a boolean")
    if "structuredContent" in result:
        _object(result["structuredContent"], "MCP structuredContent")
    content = result.get("content")
    if not isinstance(content, list):
        raise ProtocolError("MCP tools/call content must be an array")
    for block in content:
        _object(block, "MCP content block")
        _annotations(block)
        kind = block.get("type")
        if kind == "text":
            _string(block.get("text"), "MCP text content")
        elif kind in ("image", "audio"):
            _base64(block.get("data"), "MCP media data")
            _string(block.get("mimeType"), "MCP media mimeType", nonempty=True)
        elif kind == "resource":
            resource = _object(block.get("resource"), "MCP embedded resource")
            _meta(resource, "MCP embedded resource")
            _string(resource.get("uri"), "MCP embedded resource URI", nonempty=True)
            _optional_strings(resource, ("mimeType",), "MCP embedded resource")
            if ("text" in resource) == ("blob" in resource):
                raise ProtocolError("Embedded resource must contain exactly one of text and blob")
            if "text" in resource:
                _string(resource["text"], "MCP resource text")
            else:
                _base64(resource["blob"], "MCP resource blob")
        elif kind == "resource_link":
            _string(block.get("uri"), "MCP resource link URI", nonempty=True)
            _string(block.get("name"), "MCP resource link name", nonempty=True)
            _optional_strings(block, ("description", "mimeType", "title"), "MCP resource link")
            if "size" in block and (type(block["size"]) is not int or block["size"] < 0):
                raise ProtocolError("Invalid MCP resource link size")
        else:
            raise ProtocolError("Unknown or missing MCP content block type")
    return result


def require_tool_success(response: dict) -> dict:
    """Return a valid successful CallToolResult, or fail without claiming success.

    RPCSession.call deliberately preserves legitimate JSON-RPC policy errors.
    Call this helper on paths where the workflow requires an actual successful
    tool result; then separately check the expected receipt or source content.
    This validates protocol shape, not whether a claimed side effect happened.
    """
    _response(response)
    if "error" in response:
        raise ProtocolError("MCP tool call returned a JSON-RPC error")
    result = _tool_result(response["result"])
    if result.get("isError") is True:
        raise ProtocolError("MCP tool call returned isError=true")
    return result


def _initialize_result(value) -> None:
    result = _object(value, "MCP initialize result")
    version = _string(result.get("protocolVersion"), "MCP protocolVersion", nonempty=True)
    if version not in SUPPORTED_PROTOCOL_VERSIONS:
        raise ProtocolError("Server proposed an unsupported MCP protocol version")
    capabilities = _object(result.get("capabilities"), "MCP server capabilities")
    for name in ("experimental", "logging", "prompts", "resources", "tools", "completions", "tasks"):
        if name in capabilities:
            capability = _object(capabilities[name], f"MCP capability {name}")
            for flag in ("listChanged", "subscribe"):
                if flag in capability and type(capability[flag]) is not bool:
                    raise ProtocolError(f"MCP capability {name}.{flag} must be a boolean")
    server = _object(result.get("serverInfo"), "MCP serverInfo")
    _string(server.get("name"), "MCP serverInfo.name", nonempty=True)
    _string(server.get("version"), "MCP serverInfo.version", nonempty=True)
    _optional_strings(result, ("instructions",), "MCP initialize result")
    _meta(result, "MCP initialize result")


def _tools_result(value) -> list[str]:
    result = _object(value, "MCP tools/list result")
    _meta(result, "MCP tools/list result")
    if "nextCursor" in result:
        _string(result["nextCursor"], "MCP tools/list nextCursor", nonempty=True)
    items = result.get("tools")
    if not isinstance(items, list):
        raise ProtocolError("MCP tools/list tools must be an array")
    names = []
    for tool in items:
        _object(tool, "MCP tool definition")
        name = _string(tool.get("name"), "MCP tool name", nonempty=True)
        if name in names:
            raise ProtocolError("Duplicate tool names in MCP tool directory")
        schema = _object(tool.get("inputSchema"), "MCP tool inputSchema")
        if schema.get("type") != "object":
            raise ProtocolError("MCP tool inputSchema.type must be object")
        if "properties" in schema:
            _object(schema["properties"], "MCP tool inputSchema.properties")
        if "required" in schema:
            required = schema["required"]
            if not isinstance(required, list) or any(not isinstance(field, str) for field in required):
                raise ProtocolError("MCP tool inputSchema.required must be an array of strings")
        _optional_strings(tool, ("title", "description"), "MCP tool")
        _meta(tool, "MCP tool")
        names.append(name)
    return names


def _unique_object(pairs: list[tuple]) -> dict:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ProtocolError("Duplicate JSON field in MCP message")
        value[key] = item
    return value


def _invalid_constant(_value: str):
    raise ProtocolError("Non-finite JSON constant in MCP message")


def child_environment(overrides: dict[str, str] | None = None) -> dict[str, str]:
    # Match the deliberately small environment used in our synthetic experiments.
    # Real configurations must declare everything else they need explicitly.
    essentials = {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "PATH", "USERPROFILE", "USERNAME", "USER", "LOGNAME"}
    result = {key: value for key, value in os.environ.items() if key.upper() in essentials}
    result.update({"PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"})
    result.update(overrides or {})
    return result


class RPCSession:
    def __init__(self, entry: dict, evidence_path: Path, timeout: float = 35):
        self.entry = entry
        self.path = evidence_path
        self.timeout = timeout
        self.trace = []
        self.forced_termination = False
        self.id = 0
        self.queue = queue.Queue()
        self.stderr = evidence_path.with_suffix(".stderr.txt").open("w", encoding="utf-8")
        self.process = subprocess.Popen([entry["command"], *entry.get("args", [])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr,
            cwd=entry.get("cwd"), env=child_environment(entry.get("env")),
            text=True, encoding="utf-8", bufsize=1,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        def drain():
            for line in self.process.stdout:
                self.queue.put(line)
            self.queue.put(None)
        self.reader = threading.Thread(target=drain, daemon=True)
        self.reader.start()

    def __enter__(self):
        try:
            response = self.request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "defensecheck-test-client", "version": "0.1.0a1"}})
            if "error" in response:
                raise ProtocolError("MCP initialization returned an error")
            self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            self.process.stdin.flush()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def request(self, method: str, params: dict) -> dict:
        self.id += 1
        request = {"jsonrpc": "2.0", "id": self.id, "method": method, "params": params}
        self.trace.append({"request": request})
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        deadline = time.monotonic() + self.timeout
        notifications = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ProtocolError("MCP response timed out; test is incomplete")
            try:
                line = self.queue.get(timeout=remaining)
            except queue.Empty as exc:
                raise ProtocolError("MCP response timed out; test is incomplete") from exc
            if time.monotonic() > deadline:
                raise ProtocolError("MCP response timed out; test is incomplete")
            if line is None:
                raise ProtocolError("MCP process closed its output; test is incomplete")
            try:
                response = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
            except json.JSONDecodeError as exc:
                raise ProtocolError("MCP process emitted non-protocol output; test is incomplete") from exc
            if not isinstance(response, dict):
                raise ProtocolError("Invalid MCP response object")
            if "id" not in response and "method" in response:
                _notification(response)
                notifications += 1
                if notifications > MAX_NOTIFICATIONS:
                    raise ProtocolError("Too many notifications before the MCP response")
                self.trace.append({"notification": response})
                continue
            _response(response, self.id)
            if "result" in response:
                if method == "initialize":
                    _initialize_result(response["result"])
                elif method == "tools/list":
                    _tools_result(response["result"])
                elif method == "tools/call":
                    _tool_result(response["result"])
            self.trace.append({"response": response})
            return response

    def tools(self) -> list[str]:
        response = self.request("tools/list", {})
        if "error" in response:
            raise ProtocolError("Could not read the MCP tool directory")
        if "nextCursor" in response["result"]:
            raise ProtocolError("Paginated MCP tool directories are unsupported; test is incomplete")
        return _tools_result(response["result"])

    def call(self, name: str, **arguments) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    def __exit__(self, *_args):
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=12)
        except subprocess.TimeoutExpired:
            self.forced_termination = True
            self.process.terminate()
            self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.process.stdout.close()
        self.stderr.close()
        self.path.write_text(json.dumps({"trace": self.trace, "returncode": self.process.returncode,
            "forced_termination": self.forced_termination}, indent=2) + "\n", encoding="utf-8")
