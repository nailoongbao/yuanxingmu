"""A fixed native PydanticAI Agent inside the host's isolated SDK worker.

Native tool approvals are automatic durable scheduling pauses, not user
questions or host authorization. All effects still pass through the Broker.
There is no provider client, credential, remote conversation or model retry.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path

from pydantic_ai import Agent, DeferredToolRequests, DeferredToolResults, RunContext, Tool
from pydantic_ai.messages import ModelMessagesTypeAdapter, ModelResponse, TextPart, ToolCallPart
from pydantic_ai.models import Model
from pydantic_ai.usage import UsageLimits

from ..client import request
from ._openai_agents_schema import inline_model_schema
from ._pydantic_ai_checkpoint import Checkpoint
from ._runtime_support import checked_config, checked_text, json_bytes, load_json, model_request, read_json
from ._schemas import ClosedModel, FormProposal, MessageProposal, SCHEMAS, UploadProposal
from .client import DESCRIPTIONS, NativeTools, PROPOSALS, TOOL_NAMES, _arguments, decode_arguments, encode_result


SDK_VERSION = "2.43.0"
SDK_PACKAGES = {"pydantic-ai-slim": SDK_VERSION, "pydantic-graph": SDK_VERSION, "pydantic": "2.13.5"}
SDK_RPC_TIMEOUT_SECONDS = 120
OPERATIONS = ("read", "describe", "action_targets", "propose_action", "draft_email")
BY_NAME = {TOOL_NAMES[name]: name for name in OPERATIONS}
AUTOMATIC_TOOL = "yuanxingmu_request_action"
INSTRUCTIONS = ("Use only registered resources and tools to complete the user's task. Inspect permissions and "
                "action targets when needed. Reviewed proposals and email drafts require separate host review. "
                "Automatic actions are available only within the host's existing scope. Report outcomes accurately.")


class AutomaticArgs(ClosedModel):
    proposal: MessageProposal | UploadProposal | FormProposal


def _check_action_outcome(result):
    value = load_json(checked_text(result).encode())
    if type(value) is not dict:
        raise RuntimeError("sdk_tool_result_not_object")
    if (any(value.get(field) in ("unconfirmed", "executing") for field in ("status", "outcome"))
            or value.get("reason") == "automatic_prior_outcome_unconfirmed"):
        raise RuntimeError("sdk_action_unconfirmed")
    if value.get("reason") in ("broker_operation_failed", "task_revoked", "task_paused", "broker_closed",
                               "defense_storage_fault", "storage_fault", "invalid_quarantine_state"):
        raise RuntimeError("sdk_host_stopped")


class _RuntimeTools(NativeTools):
    def request_key(self, operation, framework, tool_call_id):
        if operation not in {*PROPOSALS, "request_action"} or framework != "pydantic_ai":
            raise ValueError("sdk_invalid_request_context")
        if not checked_text(tool_call_id, 512):
            raise ValueError("sdk_host_nonce_required")
        namespace = "automatic" if operation == "request_action" else "reviewed"
        binding = ["yuanxingmu-pydantic-ai-" + namespace + "-v1", self.session_id, operation, tool_call_id]
        return "pa_" + namespace + "_v1_" + hashlib.sha256(json_bytes(binding)).hexdigest()

    def invoke(self, operation, arguments, *, framework, tool_call_id=None):
        if operation not in OPERATIONS or framework != "pydantic_ai":
            raise ValueError("sdk_invalid_native_operation")
        fields = _arguments(operation, arguments)
        if operation in PROPOSALS:
            fields["request_key"] = self.request_key(operation, framework, tool_call_id)
        return request(operation, socket_path=self.socket_path, timeout_seconds=SDK_RPC_TIMEOUT_SECONDS, **fields)


class _HostModel(Model):
    def __init__(self, loop):
        # Pinned SDK pricing preload uses bundled data. An explicit context
        # window also avoids model-name pricing lookup; no provider is created.
        super().__init__(profile={"context_window": None, "supports_tools": True})
        self.loop = loop

    @property
    def model_name(self):
        return self.loop.config["model_id"]

    @property
    def system(self):
        return "yuanxingmu-host"

    async def request(self, messages, model_settings, model_request_parameters):
        from ._pydantic_ai_state import native_messages

        parameters = model_request_parameters
        if (model_settings != {"max_tokens": self.loop.config["max_tokens"], "parallel_tool_calls": False}
                or parameters.native_tools or parameters.output_tools or parameters.output_object is not None
                or parameters.output_mode != "text" or not parameters.allow_text_output
                or parameters.allow_image_output or parameters.thinking is not None
                or parameters.prompted_output_template is not None
                or parameters.revealed_tool_names or parameters.deferred_capability_ids
                or not parameters.instruction_parts or len(parameters.instruction_parts) != 1
                or parameters.instruction_parts[0].content != INSTRUCTIONS):
            raise ValueError("sdk_model_configuration_changed")
        definitions = parameters.function_tools
        if len(definitions) != len(self.loop.names):
            raise ValueError("sdk_model_tools_changed")
        for definition, name in zip(definitions, self.loop.names):
            tool = self.loop.function_tools[name]
            if (definition.name != name or definition.parameters_json_schema != tool.function_schema.json_schema
                    or definition.description != tool.description or definition.strict is not True
                    or definition.sequential is not True or definition.kind != "unapproved"
                    or definition.defer_loading or definition.return_schema != {"type": "string"}
                    or definition.include_return_schema is not False):
                raise ValueError("sdk_model_tools_changed")
        native = load_json(ModelMessagesTypeAdapter.dump_json(messages))
        history = native_messages(self.loop, native)
        payload = {"model": self.model_name, "messages": [{"role": "system", "content": INSTRUCTIONS}, *history],
                   "tools": deepcopy(self.loop.schemas), "stream": False,
                   "max_tokens": self.loop.config["max_tokens"], "parallel_tool_calls": False}
        return await self.loop.model(payload)


class _Loop:
    def __init__(self, config, checkpoint):
        self.config, self.checkpoint = config, checkpoint
        self.client = _RuntimeTools(config["broker_socket"], config["session_id"])
        self.failed = False
        self.failure_reason = None
        self.lock = asyncio.Lock()
        self.cursor = checkpoint.value["native_cursor"]
        self.active_row = self.cursor - 1
        self.names = [*BY_NAME, *([AUTOMATIC_TOOL] if config["automatic_actions"] else [])]
        self.function_tools = {name: self.tool(name) for name in self.names}
        self.schemas = [{"type": "function", "function": {
            "name": name, "description": tool.description,
            "parameters": inline_model_schema(tool.function_schema.json_schema), "strict": True}}
            for name, tool in self.function_tools.items()]
        self.agent = Agent(_HostModel(self), name="yuanxingmu_assistant", instructions=INSTRUCTIONS,
                           output_type=[str, DeferredToolRequests], retries=0,
                           model_settings={"max_tokens": config["max_tokens"], "parallel_tool_calls": False},
                           tools=list(self.function_tools.values()), end_strategy="exhaustive")
        self.agent.instrument = False

    def tool(self, name):
        automatic = name == AUTOMATIC_TOOL
        schema = AutomaticArgs if automatic else SCHEMAS[BY_NAME[name]]
        description = ("Request a message, upload, or form within the host's existing automatic scope. "
                       "The host checks current authority and returns its recorded outcome for repeats."
                       if automatic else DESCRIPTIONS[BY_NAME[name]])

        async def invoke(context, arguments):
            async with self.lock:
                try:
                    if self.failed:
                        raise RuntimeError("sdk_round_stopped")
                    payload = schema.model_validate(arguments.model_dump()).model_dump()
                    await self.checked_call(context.tool_call_id, name, payload)
                    if automatic:
                        result = await asyncio.to_thread(request, "request_action", socket_path=self.client.socket_path,
                            timeout_seconds=SDK_RPC_TIMEOUT_SECONDS,
                            request_key=self.client.request_key("request_action", "pydantic_ai", context.tool_call_id),
                            proposal=_arguments("propose_action", payload)["proposal"])
                    else:
                        result = await self.client.ainvoke(BY_NAME[name], payload, framework="pydantic_ai",
                                                          tool_call_id=context.tool_call_id)
                    encoded = encode_result(result)
                    _check_action_outcome(encoded)
                    row = self.checkpoint.value["records"][self.active_row]
                    cached = row["results"].get(context.tool_call_id)
                    if cached is not None:
                        _check_action_outcome(cached)
                        if result.get("allowed") is False and load_json(cached).get("allowed") is not False:
                            raise RuntimeError("sdk_replayed_tool_no_longer_allowed")
                        # Native recovery replays the complete deferred batch.
                        # Keep exact original model history after Broker replay.
                        return cached
                    row["results"][context.tool_call_id] = encoded
                    self.checkpoint.save()
                    return encoded
                except BaseException as error:
                    self.failed = True
                    self.failure_reason = (str(error) if type(error) is RuntimeError and str(error) in {
                        "sdk_action_unconfirmed", "sdk_host_stopped", "sdk_checkpoint_response_changed",
                        "sdk_replayed_tool_no_longer_allowed"} else "sdk_tool_dispatch_failed")
                    raise

        # A single typed BaseModel argument is flattened by the native SDK;
        # its native validator retains ClosedModel's strict and extra rules.
        invoke.__annotations__ = {"context": RunContext, "arguments": schema, "return": str}
        return Tool(invoke, name=name, description=description, takes_ctx=True, strict=True,
                    sequential=True, requires_approval=True, max_retries=0, include_return_schema=False)

    def calls(self, message):
        if type(message) is not dict or message.get("role") != "assistant":
            raise ValueError("sdk_invalid_model_message")
        content = message.get("content")
        if content is not None:
            checked_text(content)
        calls = message.get("tool_calls")
        calls = [] if calls is None else calls
        if type(calls) is not list or len(calls) > 32:
            raise ValueError("sdk_invalid_tool_calls")
        result, seen = [], set()
        for call in calls:
            if (type(call) is not dict or set(call) != {"id", "type", "function"} or call["type"] != "function"
                    or type(call["function"]) is not dict or set(call["function"]) != {"name", "arguments"}):
                raise ValueError("sdk_invalid_tool_call")
            nonce, name = checked_text(call["id"], 512), checked_text(call["function"]["name"], 128)
            if not nonce or nonce in seen or name not in self.names:
                raise ValueError("sdk_tool_not_available")
            seen.add(nonce)
            arguments = decode_arguments(call["function"]["arguments"])
            schema = AutomaticArgs if name == AUTOMATIC_TOOL else SCHEMAS[BY_NAME[name]]
            payload = schema.model_validate(arguments).model_dump()
            _arguments("propose_action" if name == AUTOMATIC_TOOL else BY_NAME[name], payload)
            result.append({"id": nonce, "name": name, "arguments": payload})
        if not result and not content:
            raise ValueError("sdk_empty_model_response")
        return result

    def response(self, value):
        if (type(value) is not dict or type(value.get("choices")) is not list or len(value["choices"]) != 1
                or type(value["choices"][0]) is not dict or type(value["choices"][0].get("message")) is not dict):
            raise ValueError("sdk_invalid_model_response")
        message = value["choices"][0]["message"]
        return message, self.calls(message)

    def native_response(self, value):
        message, calls = self.response(value)
        parts = [TextPart(message["content"])] if message.get("content") is not None else []
        parts.extend(ToolCallPart(call["name"], args=call["arguments"], tool_call_id=call["id"]) for call in calls)
        return ModelResponse(parts=parts, model_name=self.config["model_id"], provider_name="yuanxingmu-host",
                             finish_reason="tool_call" if calls else "stop")

    def messages(self, messages):
        if type(messages) is not list or not messages or len(messages) > 512:
            raise ValueError("sdk_invalid_messages")
        for index, item in enumerate(messages):
            if type(item) is not dict:
                raise ValueError("sdk_invalid_message")
            fields, role = {"role", "content"}, item.get("role")
            if index == 0 and role == "system":
                if item.get("content") != INSTRUCTIONS:
                    raise ValueError("sdk_checkpoint_instructions_changed")
            elif role == "assistant":
                if "tool_calls" in item:
                    fields.add("tool_calls")
                self.calls(item)
            elif role == "tool":
                fields.add("tool_call_id")
                checked_text(item.get("tool_call_id"), 512)
                _check_action_outcome(item.get("content"))
            elif role == "user":
                checked_text(item.get("content"))
            else:
                raise ValueError("sdk_invalid_message_role")
            if set(item) != fields:
                raise ValueError("sdk_invalid_message")
        if messages[0] != {"role": "system", "content": INSTRUCTIONS}:
            raise ValueError("sdk_checkpoint_instructions_changed")

    def check_record(self, row):
        body = row["request"]
        if (set(body) != {"model", "messages", "tools", "stream", "max_tokens", "parallel_tool_calls"}
                or body["model"] != self.config["model_id"] or body["stream"] is not False
                or body["parallel_tool_calls"] is not False or type(body["max_tokens"]) is not int
                or not 1 <= body["max_tokens"] <= 32768 or body["tools"] != self.schemas):
            raise ValueError("sdk_checkpoint_request_changed")
        self.messages(body["messages"])
        if row["response"] is not None:
            _, calls = self.response(row["response"])
            if set(row["results"]) - {call["id"] for call in calls}:
                raise ValueError("sdk_checkpoint_tool_result_changed")
            for result in row["results"].values():
                _check_action_outcome(result)
        elif row["results"]:
            raise ValueError("sdk_checkpoint_tool_result_changed")

    async def model(self, payload):
        if self.failed:
            raise RuntimeError("sdk_round_stopped")
        records = self.checkpoint.value["records"]
        if self.cursor - self.checkpoint.value["round_start"] >= self.config["max_steps"]:
            raise RuntimeError("sdk_max_steps_reached")
        if self.cursor < len(records):
            row = records[self.cursor]
            if json_bytes(row["request"]) != json_bytes(payload):
                raise ValueError("sdk_checkpoint_replay_changed")
        else:
            row = {"request": payload, "response": None, "results": {}}
            records.append(row)
            self.checkpoint.save()
        response = await asyncio.to_thread(model_request, self.config, row["request"])
        _, calls = self.response(response)  # Validate the whole batch before native dispatch.
        previous = {call["id"] for old in records[:self.cursor] if old["response"] is not None
                    for call in self.response(old["response"])[1]}
        if previous & {call["id"] for call in calls}:
            raise ValueError("sdk_repeated_host_nonce")
        if row["response"] is not None and json_bytes(row["response"]) != json_bytes(response):
            raise RuntimeError("sdk_checkpoint_response_changed")
        row["response"] = response
        self.checkpoint.save()
        self.active_row = self.cursor
        self.cursor += 1
        return self.native_response(response)

    async def checked_call(self, nonce, name, arguments):
        if self.failed or self.active_row < 0:
            raise RuntimeError("sdk_round_stopped")
        row = self.checkpoint.value["records"][self.active_row]
        response = await asyncio.to_thread(model_request, self.config, row["request"])
        if row["response"] is None or json_bytes(response) != json_bytes(row["response"]):
            raise RuntimeError("sdk_checkpoint_response_changed")
        _, calls = self.response(response)
        if {"id": nonce, "name": name, "arguments": arguments} not in calls:
            raise ValueError("sdk_invocation_not_in_host_response")


async def _run(config):
    from ._pydantic_ai_state import validate_saved

    checkpoint = Checkpoint(config)
    loop = _Loop(config, checkpoint)
    value = checkpoint.value
    validate_saved(loop)
    if config["resume"] and value["status"] == "running" and value["prompt"] != config["prompt"]:
        raise ValueError("sdk_unfinished_prompt_changed")
    if value["status"] == "completed" and value["prompt"] == config["prompt"]:
        return {"status": "completed", "answer": value["answer"], "framework": "pydantic_ai",
                "session_id": config["session_id"], "steps": loop.cursor - value["round_start"]}
    prompt = config["prompt"] if loop.cursor == value["round_start"] or value["status"] == "completed" else None
    if value["status"] == "completed":
        value.update(prompt=config["prompt"], round_start=loop.cursor, status="running", answer=None)
        checkpoint.save()
    if not config["resume"]:
        checkpoint.save()
    history = ModelMessagesTypeAdapter.validate_json(json_bytes(value["native"]))
    while True:
        approvals = None
        if history and history[-1].kind == "response" and history[-1].tool_calls:
            calls = loop.response(value["records"][loop.active_row]["response"])[1]
            for call in calls:
                await loop.checked_call(call["id"], call["name"], call["arguments"])
            approvals = DeferredToolResults(approvals={call["id"]: True for call in calls})
        try:
            result = await loop.agent.run(prompt, message_history=history, deferred_tool_results=approvals,
                                          usage_limits=UsageLimits(request_limit=config["max_steps"]), infer_name=False)
        except Exception:
            if loop.failure_reason is not None:
                raise RuntimeError(loop.failure_reason) from None
            raise
        native = load_json(result.all_messages_json())
        if isinstance(result.output, DeferredToolRequests):
            output = result.output
            calls = loop.response(value["records"][loop.active_row]["response"])[1]
            if (output.calls or output.metadata or
                    [{"id": call.tool_call_id, "name": call.tool_name, "arguments": call.args_as_dict()}
                     for call in output.approvals] != calls):
                raise ValueError("sdk_native_approval_changed")
            checkpoint.snapshot(native, loop.cursor)
            validate_saved(loop)
            checkpoint.save()
            history = ModelMessagesTypeAdapter.validate_json(json_bytes(native))
            prompt = None
            continue
        answer = checked_text(result.output)
        checkpoint.snapshot(native, loop.cursor, status="completed", answer=answer)
        validate_saved(loop)
        checkpoint.save()
        return {"status": "completed", "answer": answer, "framework": "pydantic_ai",
                "session_id": config["session_id"], "steps": loop.cursor - value["round_start"]}


def run_session(config):
    config = checked_config(config, "pydantic_ai")
    if any(version(package) != expected for package, expected in SDK_PACKAGES.items()):
        raise RuntimeError("sdk_version_not_supported")
    try:
        return asyncio.run(_run(config))
    except (ValueError, RuntimeError, OSError):
        raise
    except Exception:
        raise RuntimeError("sdk_native_run_failed") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the host-supervised PydanticAI worker")
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = read_json(args.config, 1024 * 1024)
        with open(os.devnull, "w", encoding="utf-8") as discard, redirect_stdout(discard), redirect_stderr(discard):
            outcome = run_session(config)
    except Exception:
        print('{"status":"failed","reason":"sdk_session_failed"}')
        return 1
    print(json.dumps(outcome, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
