"""A serial ToolCallingAgent loop for the isolated, host-supervised SDK runner.

This module is a worker, not an isolation or authorization boundary. The host
mounts its fixed configuration, Broker and checked model sockets. Tool IDs come
from the host model journal; checkpoint contents never grant permission.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from dataclasses import replace
import hashlib
import http.client
from importlib.metadata import version
import json
import os
from pathlib import Path
import socket
import stat
import sys
import uuid

from smolagents import Model, Tool, ToolCallingAgent
from smolagents.memory import ActionStep, FinalAnswerStep, TaskStep, ToolCall
from smolagents.models import ChatMessage, ChatMessageToolCall, ChatMessageToolCallFunction
from smolagents.monitoring import LogLevel, Timing

from ._host_invocations import HostInvocations
from ._schemas import SCHEMAS
from ..client import request
from .client import NativeTools, TOOL_NAMES, _arguments, decode_arguments, encode_result
from .smolagents import _inputs, build_tools


SDK_VERSION = "1.26.0"
# A profile judge may use 45 seconds; automatic actions then perform several
# network phases with 8-second socket waits. Keep this worker's complete RPC
# above that chain, within the client's 120-second ceiling. The host separately
# enforces the overall run deadline. No model argument can change this value.
SDK_RPC_TIMEOUT_SECONDS = 120
MAX_JSON = 16 * 1024 * 1024
MAX_CHECKPOINT = 16 * 1024 * 1024
OPERATIONS = ("read", "describe", "action_targets", "propose_action", "draft_email")
BY_NAME = {TOOL_NAMES[name]: name for name in OPERATIONS}
AUTOMATIC_TOOL = "yuanxingmu_request_action"
AUTOMATIC_KINDS = frozenset({"message", "upload", "form"})


def _bytes(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _json(raw: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("sdk_duplicate_json_key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("sdk_invalid_json")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def _text(value, maximum=MAX_JSON):
    if type(value) is not str or len(value.encode()) > maximum or "\x00" in value:
        raise ValueError("sdk_invalid_text")
    return value


def _check_action_outcome(result):
    value = _json(result.encode())
    if type(value) is dict and any(value.get(field) in ("unconfirmed", "executing") for field in ("status", "outcome")):
        # The receiver may already have acted. A model continuation could use
        # another nonce and repeat that effect; only host review can resolve it.
        raise RuntimeError("sdk_action_unconfirmed")


def _config(config):
    fields = {"version", "framework", "session_id", "task_id", "model_id", "max_steps", "max_tokens",
              "prompt", "resume", "checkpoint", "broker_socket", "model_socket"}
    if (type(config) is not dict or not fields <= set(config) or set(config) - fields - {"automatic_actions"}
            or type(config["version"]) is not int or config["version"] != 1):
        raise ValueError("sdk_invalid_config")
    config = dict(config)
    config.setdefault("automatic_actions", False)
    if type(config["automatic_actions"]) is not bool:
        raise ValueError("sdk_invalid_config")
    if config["framework"] != "smolagents" or type(config["resume"]) is not bool:
        raise ValueError("sdk_invalid_config")
    for name in ("session_id", "task_id", "model_id"):
        if not _text(config[name], 256):
            raise ValueError("sdk_invalid_config")
    for name, maximum in (("max_steps", 128), ("max_tokens", 32768)):
        if type(config[name]) is not int or not 1 <= config[name] <= maximum:
            raise ValueError("sdk_invalid_config")
    if not _text(config["prompt"], 256 * 1024).strip():
        raise ValueError("sdk_invalid_prompt")
    for name in ("checkpoint", "broker_socket", "model_socket"):
        if not Path(_text(config[name], 4096)).is_absolute():
            raise ValueError("sdk_requires_absolute_path")
    return dict(config)


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=210)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def _message(response: dict) -> ChatMessage:
    if (type(response) is not dict or type(response.get("choices")) is not list
            or len(response["choices"]) != 1):
        raise ValueError("sdk_invalid_model_response")
    choice = response["choices"][0]
    if type(choice) is not dict or type(choice.get("message")) is not dict:
        raise ValueError("sdk_invalid_model_response")
    message = choice["message"]
    if message.get("role") != "assistant":
        raise ValueError("sdk_invalid_model_role")
    content = message.get("content")
    if content is not None:
        _text(content)
    calls = message.get("tool_calls")
    calls = [] if calls is None else calls
    if type(calls) is not list or len(calls) > 32:
        raise ValueError("sdk_invalid_tool_calls")
    parsed, seen = [], set()
    for call in calls:
        if (type(call) is not dict or set(call) != {"id", "type", "function"}
                or call["type"] != "function" or type(call["function"]) is not dict
                or set(call["function"]) != {"name", "arguments"}):
            raise ValueError("sdk_invalid_tool_call")
        nonce = _text(call["id"], 512)
        if not nonce or nonce in seen:
            raise ValueError("sdk_invalid_host_nonce")
        seen.add(nonce)
        function = call["function"]
        name = _text(function["name"], 128)
        args = function["arguments"]
        args = decode_arguments(args) if type(args) is str else deepcopy(args)
        if type(args) is not dict:
            raise ValueError("sdk_invalid_tool_arguments")
        parsed.append(ChatMessageToolCall(id=nonce, type="function",
            function=ChatMessageToolCallFunction(name=name, arguments=args)))
    if not parsed:
        if content is None:
            raise ValueError("sdk_empty_model_response")
        # Plain text is an answer, never parsed into a new tool invocation.
        parsed = [ChatMessageToolCall(id="plain_text_answer", type="function",
            function=ChatMessageToolCallFunction(name="final_answer", arguments={"answer": content}))]
    return ChatMessage(role="assistant", content=content, tool_calls=parsed)


class _RuntimeTools(NativeTools):
    """Longer bounded RPCs for the defended loop, with unchanged proposal keys."""

    def invoke(self, operation, arguments, *, framework, tool_call_id=None):
        if framework != "smolagents" or operation not in OPERATIONS:
            raise ValueError("invalid_native_operation")
        fields = _arguments(operation, arguments)
        if operation in {"propose_action", "draft_email"}:
            fields["request_key"] = self.request_key(operation, framework, tool_call_id)
        return request(operation, socket_path=self.socket_path,
                       timeout_seconds=SDK_RPC_TIMEOUT_SECONDS, **fields)


class BridgeModel(Model):
    """No provider SDK, credentials, URL override, streaming or transport retry."""

    def __init__(self, config: dict):
        super().__init__(model_id=config["model_id"], flatten_messages_as_text=True)
        self.config = dict(config)
        self.before_request = None
        self.after_response = None

    def request(self, payload: dict) -> tuple[ChatMessage, dict]:
        body = _bytes(payload)
        if len(body) > MAX_JSON:
            raise ValueError("sdk_model_request_too_large")
        if self.before_request is not None:
            self.before_request(payload)
        connection = _UnixHTTP(self.config["model_socket"])
        try:
            connection.request("POST", "/v1/chat/completions", body=body,
                               headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(MAX_JSON + 1)
            if response.status != 200 or len(raw) > MAX_JSON:
                raise RuntimeError("sdk_model_request_failed")
            value = _json(raw)
            message = _message(value)
        except Exception:
            # Provider/transport details may contain request or response text.
            raise RuntimeError("sdk_model_request_failed") from None
        finally:
            connection.close()
        if self.after_response is not None:
            self.after_response(payload, value)
        return message, value

    def generate(self, messages, stop_sequences=None, response_format=None, tools_to_call_from=None, **kwargs):
        if kwargs or response_format is not None:
            raise ValueError("sdk_model_options_not_supported")
        payload = self._prepare_completion_kwargs(messages=messages, stop_sequences=stop_sequences,
            tools_to_call_from=tools_to_call_from, model=self.model_id,
            max_tokens=self.config["max_tokens"], stream=False)
        return self.request(payload)[0]

    def parse_tool_calls(self, message):
        raise RuntimeError("sdk_unregistered_tool_call")


def _automatic_arguments(arguments):
    payload = SCHEMAS["propose_action"].model_validate(arguments).model_dump()
    if payload["proposal"]["kind"] not in AUTOMATIC_KINDS:
        raise ValueError("sdk_automatic_action_kind_not_allowed")
    return payload


class _AutomaticActionTool(Tool):
    """Only this optional runtime operation can request existing host automation."""
    skip_forward_signature_validation = True
    name = AUTOMATIC_TOOL
    description = (
        "Request a message, upload, or form action within the host's existing automatic scope. "
        "This can execute immediately when host checks allow it; outside the scope it stays pending. "
        "A repeated call returns its recorded outcome. Never claim an unconfirmed action succeeded."
    )
    output_type = "string"

    def __init__(self, client, invocations):
        super().__init__()
        self.inputs = _inputs("propose_action")
        proposal = self.inputs["proposal"]
        proposal["oneOf"] = [branch for branch in proposal["oneOf"]
                             if branch["properties"]["kind"]["const"] in AUTOMATIC_KINDS]
        proposal["properties"]["kind"]["enum"] = sorted(AUTOMATIC_KINDS)
        self._client, self._invocations = client, invocations

    def forward(self, **arguments):
        payload = _automatic_arguments(arguments)
        nonce = self._invocations.current()
        if type(nonce) is not str or not nonce or len(nonce) > 512:
            raise ValueError("sdk_host_nonce_required")
        # Deliberately disjoint from NativeTools' reviewed proposal namespace.
        binding = ["yuanxingmu-smolagents-automatic-v1", self._client.session_id, "request_action", nonce]
        key = "smol_auto_v1_" + hashlib.sha256(_bytes(binding)).hexdigest()
        canonical = _arguments("propose_action", payload)["proposal"]
        return encode_result(request("request_action", socket_path=self._client.socket_path,
                                     timeout_seconds=SDK_RPC_TIMEOUT_SECONDS,
                                     request_key=key, proposal=canonical))


class ProtectedToolCallingAgent(ToolCallingAgent):
    """Dispatch each checked host nonce with native singleton SDK semantics."""

    def __init__(self, *, client: NativeTools, model: Model, max_steps: int, automatic_actions=False):
        if type(automatic_actions) is not bool:
            raise ValueError("sdk_invalid_automatic_actions")
        self.invocations = HostInvocations()
        self.automatic_actions = automatic_actions
        self.completed_tools = {}
        self.after_tool = None
        self.aborted = False
        client = _RuntimeTools(client.socket_path, client.session_id)
        tools = [tool for tool in build_tools(client, invocations=self.invocations) if tool.name in BY_NAME]
        if automatic_actions:
            tools.append(_AutomaticActionTool(client, self.invocations))
        super().__init__(tools=tools, model=model, max_steps=max_steps, add_base_tools=False,
                         managed_agents=None, planning_interval=None, stream_outputs=False,
                         max_tool_threads=1, verbosity_level=LogLevel.OFF)

    def _substitute_state_variables(self, arguments):
        # The five content-only tools require no arbitrary Python state values.
        return arguments

    def execute_tool_call(self, tool_name, arguments):
        if (tool_name not in BY_NAME and tool_name != "final_answer"
                and not (self.automatic_actions and tool_name == AUTOMATIC_TOOL)):
            raise RuntimeError("sdk_tool_not_available")
        nonce = self.invocations.current()
        if nonce is None:
            raise RuntimeError("sdk_host_nonce_required")
        if tool_name == "final_answer":
            # Answers have no external effect and may use a synthetic local ID
            # for plain text. Never reuse an earlier turn's answer as a tool.
            return super().execute_tool_call(tool_name, arguments)
        signature = hashlib.sha256(_bytes([tool_name, arguments])).hexdigest()
        previous = self.completed_tools.get(nonce)
        if previous is not None:
            if previous["signature"] != signature:
                raise RuntimeError("sdk_host_nonce_conflict")
            _check_action_outcome(previous["result"])
            return previous["result"]
        try:
            result = super().execute_tool_call(tool_name, arguments)
        except Exception:
            # Native AgentError normally asks the model to try again. Stop this
            # run instead; a failed RPC may already have created a proposal.
            raise RuntimeError("sdk_tool_dispatch_failed") from None
        if not isinstance(result, str):
            raise RuntimeError("sdk_tool_result_not_text")
        result = str(result)
        _check_action_outcome(result)
        self.completed_tools[nonce] = {"signature": signature, "result": result}
        if self.after_tool is not None:
            self.after_tool()
        return result

    def process_tool_calls(self, chat_message, memory_step):
        calls = chat_message.tool_calls
        if not calls or len(calls) > 32:
            raise RuntimeError("sdk_invalid_tool_calls")
        seen = set()
        # Validate the whole batch before any of its calls reaches the Broker.
        for call in calls:
            nonce, name, args = call.id, call.function.name, call.function.arguments
            if not _text(nonce, 512) or nonce in seen:
                raise RuntimeError("sdk_invalid_host_nonce")
            seen.add(nonce)
            if name == "final_answer":
                if len(calls) != 1 or type(args) is not dict or set(args) != {"answer"}:
                    raise RuntimeError("sdk_invalid_final_answer")
                _text(args["answer"])
            elif name in BY_NAME:
                SCHEMAS[BY_NAME[name]].model_validate(args)
            elif self.automatic_actions and name == AUTOMATIC_TOOL:
                _automatic_arguments(args)
            else:
                raise RuntimeError("sdk_tool_not_available")
        combined, observations = [], []
        for call in calls:
            single = replace(chat_message, tool_calls=[call])
            step = ActionStep(step_number=memory_step.step_number, timing=Timing(start_time=0.0))
            native = super().process_tool_calls(single, step)
            while True:
                # The native singleton path never starts a thread. Do not keep
                # a ContextVar bound while yielding control to our caller.
                with self.invocations.bind(call.id):
                    try:
                        event = next(native)
                    except StopIteration:
                        break
                yield event
            combined.extend(step.tool_calls or [])
            if step.observations:
                observations.append(step.observations)
        memory_step.tool_calls = combined
        memory_step.observations = "\n".join(observations)

    def _step_stream(self, memory_step):
        try:
            yield from super()._step_stream(memory_step)
        except BaseException:
            self.aborted = True
            raise

    def _handle_max_steps_reached(self, task):
        # The SDK normally spends an extra model call to invent a final answer.
        raise RuntimeError("sdk_max_steps_reached")


def _history(steps):
    result = []
    for step in steps:
        if isinstance(step, TaskStep):
            result.append({"kind": "task", "task": step.task})
        elif isinstance(step, ActionStep):
            result.append({"kind": "action", "step_number": step.step_number,
                "model_output": step.model_output, "observations": step.observations,
                "is_final_answer": step.is_final_answer,
                "tool_calls": [{"id": call.id, "name": call.name, "arguments": call.arguments}
                               for call in step.tool_calls or []]})
        elif not isinstance(step, FinalAnswerStep):
            raise ValueError("sdk_unsupported_memory_step")
    return result


def _restore_history(history):
    if type(history) is not list or len(history) > 4096:
        raise ValueError("sdk_invalid_checkpoint")
    result = []
    for item in history:
        if type(item) is not dict:
            raise ValueError("sdk_invalid_checkpoint")
        if item.get("kind") == "task" and set(item) == {"kind", "task"}:
            result.append(TaskStep(task=_text(item["task"])))
        elif item.get("kind") == "action" and set(item) == {
                "kind", "step_number", "model_output", "observations", "is_final_answer", "tool_calls"}:
            if (type(item["step_number"]) is not int or item["step_number"] < 1
                    or type(item["is_final_answer"]) is not bool
                    or type(item["tool_calls"]) is not list or len(item["tool_calls"]) > 32):
                raise ValueError("sdk_invalid_checkpoint")
            calls = []
            for call in item["tool_calls"]:
                if type(call) is not dict or set(call) != {"id", "name", "arguments"} or type(call["arguments"]) is not dict:
                    raise ValueError("sdk_invalid_checkpoint")
                calls.append(ToolCall(id=_text(call["id"], 512), name=_text(call["name"], 128),
                                      arguments=call["arguments"]))
            for key in ("model_output", "observations"):
                if item[key] is not None:
                    _text(item[key])
            result.append(ActionStep(step_number=item["step_number"], timing=Timing(start_time=0.0),
                model_output=item["model_output"], observations=item["observations"], tool_calls=calls,
                is_final_answer=item["is_final_answer"]))
        else:
            raise ValueError("sdk_invalid_checkpoint")
    return result


class _Checkpoint:
    def __init__(self, config):
        self.path = Path(config["checkpoint"])
        binding = {key: config[key] for key in ("version", "framework", "session_id", "task_id", "model_id", "automatic_actions")}
        if self.path.is_symlink():
            raise ValueError("sdk_invalid_checkpoint")
        exists = self.path.exists()
        if exists != config["resume"]:
            raise ValueError("sdk_checkpoint_resume_required" if exists else "sdk_checkpoint_missing")
        if exists:
            info = self.path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CHECKPOINT or info.st_nlink != 1:
                raise ValueError("sdk_invalid_checkpoint")
            self.value = _json(self.path.read_bytes())
            if type(self.value) is dict:
                # Checkpoints written before the optional automatic tool had
                # only reviewed operations; they never imply automation.
                self.value.setdefault("automatic_actions", False)
            fields = {*binding, "prompt", "status", "history", "pending", "completed_tools", "turn_steps", "answer"}
            if (type(self.value) is not dict or set(self.value) != fields
                    or any(self.value[key] != value for key, value in binding.items())
                    or self.value["status"] not in {"running", "completed"}
                    or type(self.value["turn_steps"]) is not int or not 0 <= self.value["turn_steps"] <= 128
                    or type(self.value["completed_tools"]) is not dict or len(self.value["completed_tools"]) > 131072):
                raise ValueError("sdk_checkpoint_binding_mismatch")
            _text(self.value["prompt"])
            _restore_history(self.value["history"])
            for nonce, item in self.value["completed_tools"].items():
                if (not _text(nonce, 512) or type(item) is not dict or set(item) != {"signature", "result"}
                        or type(item["signature"]) is not str or len(item["signature"]) != 64):
                    raise ValueError("sdk_invalid_checkpoint")
                _text(item["result"])
                # Older workers may have saved this as a completed tool. Do
                # not resume a batch or return a cached answer past that event.
                _check_action_outcome(item["result"])
            if self.value["status"] == "running" and self.value["prompt"] != config["prompt"]:
                raise ValueError("sdk_unfinished_prompt_changed")
            if self.value["status"] == "completed":
                _text(self.value["answer"])
            pending = self.value["pending"]
            if pending is not None and (type(pending) is not dict or set(pending) != {"request", "response"}
                    or type(pending["request"]) is not dict
                    or (pending["response"] is not None and type(pending["response"]) is not dict)):
                raise ValueError("sdk_invalid_checkpoint")
        else:
            self.value = {**binding, "prompt": config["prompt"], "status": "running", "history": [],
                "pending": None, "completed_tools": {}, "turn_steps": 0, "answer": None}

    def save(self):
        raw = _bytes(self.value)
        if len(raw) > MAX_CHECKPOINT:
            raise RuntimeError("sdk_checkpoint_too_large")
        temporary = self.path.with_name("." + self.path.name + "." + uuid.uuid4().hex)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if sys.platform.startswith("linux"):
                directory = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


def run_session(config: dict) -> dict:
    config = _config(config)
    if version("smolagents") != SDK_VERSION:
        raise RuntimeError("sdk_version_not_supported")
    checkpoint = _Checkpoint(config)
    value = checkpoint.value

    def result(answer):
        return {"status": "completed", "answer": _text(str(answer)), "framework": "smolagents",
                "session_id": config["session_id"], "steps": value["turn_steps"]}

    if value["status"] == "completed" and value["prompt"] == config["prompt"]:
        return result(value["answer"])
    new_turn = value["status"] == "completed"
    if new_turn:
        value.update(prompt=config["prompt"], status="running", pending=None, turn_steps=0, answer=None)
    model = BridgeModel(config)
    agent = ProtectedToolCallingAgent(client=NativeTools(config["broker_socket"], config["session_id"]),
                                     model=model, max_steps=config["max_steps"], automatic_actions=config["automatic_actions"])
    agent.completed_tools = value["completed_tools"]
    agent.memory.steps = _restore_history(value["history"])
    agent.after_tool = checkpoint.save

    def before_request(payload):
        value["history"] = _history(agent.memory.steps)
        value["pending"] = {"request": deepcopy(payload), "response": None}
        checkpoint.save()

    def after_response(payload, response):
        value["pending"] = {"request": deepcopy(payload), "response": deepcopy(response)}
        checkpoint.save()

    def finished_step(step, **_):
        if not isinstance(step, ActionStep) or agent.aborted:
            return
        value["history"] = _history([*agent.memory.steps, step])
        value["pending"] = None
        value["turn_steps"] += 1
        checkpoint.save()

    model.before_request, model.after_response = before_request, after_response
    agent.step_callbacks.register(ActionStep, finished_step)
    checkpoint.save()
    pending = value["pending"]
    if pending is not None:
        if type(pending) is not dict or set(pending) != {"request", "response"} or type(pending["request"]) is not dict:
            raise ValueError("sdk_invalid_checkpoint")
        # Re-fetch exact bytes through the host journal, which checks current
        # authority. Never dispatch a tool from a workspace-cached response.
        original_response = pending["response"]
        model.before_request = model.after_response = None
        try:
            message, checked = model.request(pending["request"])
        finally:
            model.before_request, model.after_response = before_request, after_response
        if original_response is not None and _bytes(checked) != _bytes(original_response):
            raise RuntimeError("sdk_checkpoint_response_changed")
        after_response(pending["request"], checked)
        step = ActionStep(step_number=value["turn_steps"] + 1, timing=Timing(start_time=0.0),
                          model_output=message.content, model_output_message=message)
        final = None
        for event in agent.process_tool_calls(message, step):
            if getattr(event, "is_final_answer", False):
                final = event.output
        step.is_final_answer = final is not None
        finished_step(step)
        agent.memory.steps.append(step)
        if final is not None:
            value.update(status="completed", answer=str(final))
            checkpoint.save()
            return result(final)
    remaining = config["max_steps"] - value["turn_steps"]
    if remaining <= 0:
        raise RuntimeError("sdk_max_steps_reached")
    if not config["resume"] or new_turn:
        answer = agent.run(config["prompt"], reset=not new_turn, max_steps=remaining)
    else:
        # AgentMemory has no loading API. Rebuild its text-only dataclasses and
        # continue the SDK's own loop without appending a duplicate user task.
        agent.task = config["prompt"]
        agent.interrupt_switch = False
        if not agent.memory.steps:
            agent.memory.steps.append(TaskStep(task=agent.task))
        final = None
        for event in agent._run_stream(task=agent.task, max_steps=remaining):
            if isinstance(event, FinalAnswerStep):
                final = event.output
        if final is None:
            raise RuntimeError("sdk_missing_final_answer")
        answer = final
    value.update(status="completed", answer=str(answer), history=_history(agent.memory.steps), pending=None)
    checkpoint.save()
    return result(answer)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the host-supervised smolagents worker")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.config.is_symlink() or args.config.stat().st_size > 1024 * 1024:
            raise ValueError("sdk_invalid_config")
        config = _json(args.config.read_bytes())
        # SDK/provider error rendering must not expose model or document text.
        # Normal CLI output is the one final JSON object, checked by the host.
        with open(os.devnull, "w", encoding="utf-8") as discard, redirect_stdout(discard), redirect_stderr(discard):
            outcome = run_session(config)
    except Exception:
        print('{"status":"failed","reason":"sdk_session_failed"}')
        return 1
    print(json.dumps(outcome, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
