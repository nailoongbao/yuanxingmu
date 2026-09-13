"""Fixed native Google ADK Runner with durable sessions and host-owned effects.

The pinned SDK can omit unfinished tools when resuming a failed parallel batch.
We therefore replay interrupted invocations through the real Runner, checking
its native events against retained attempts. Original host responses/nonces
are rechecked; Broker receipts deduplicate effects and original results rebuild
the exact native conversation. Native agent transfer changes workflow only.
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import aclosing, redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
from typing import Any, Literal

from google.adk.agents import LlmAgent
from google.adk.agents.run_config import RunConfig
from google.adk.apps.app import App, ResumabilityConfig
from google.adk.models.base_llm import BaseLlm
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import Runner
from google.adk.sessions.in_memory_session_service import InMemorySessionService
from google.adk.sessions.session import Session
from google.adk.telemetry.context import ContentCapturingMode, TelemetryConfig
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.adk.tools.transfer_to_agent_tool import TransferToAgentTool
from google.genai import types
from pydantic import Field

from ..client import request
from ._google_adk_checkpoint import Checkpoint
from ._openai_agents_schema import inline_model_schema
from ._runtime_support import checked_config, checked_text, json_bytes, load_json, model_request, read_json
from ._schemas import ClosedModel, FormProposal, MessageProposal, SCHEMAS, UploadProposal
from .client import DESCRIPTIONS, NativeTools, PROPOSALS, TOOL_NAMES, _arguments, decode_arguments, encode_result


SDK_VERSION = "2.9.0"
SDK_PACKAGES = {"google-adk": SDK_VERSION, "google-genai": "2.23.0", "pydantic": "2.13.5"}
SDK_RPC_TIMEOUT_SECONDS = 120
APP_NAME = "yuanxingmu"
USER_ID = "host"
COORDINATOR, EXECUTOR = "yuanxingmu_coordinator", "yuanxingmu_executor"
TRANSFER_TOOL = "transfer_to_agent"
AUTOMATIC_TOOL = "yuanxingmu_request_action"
OPERATIONS = ("read", "describe", "action_targets", "propose_action", "draft_email")
BY_NAME = {TOOL_NAMES[name]: name for name in OPERATIONS}
INSTRUCTIONS = {
    COORDINATOR: "Use registered resources to understand the user's task. Inspect permissions and action targets "
                 "when needed. Transfer action preparation or execution to the execution assistant. Both assistants "
                 "share the same host task, permissions, data restrictions and action budget.",
    EXECUTOR: "Complete the user's task using the registered action tools and supplied conversation. Reviewed "
              "proposals and email drafts require separate host review. Automatic actions are available only "
              "within the host's existing scope. Report returned outcomes accurately."}
EXECUTOR_DESCRIPTION = "Prepare reviewed actions or perform actions within the existing host scope; retain the same authority and budget."
STOP_REASONS = {"sdk_action_unconfirmed", "sdk_host_stopped", "sdk_checkpoint_response_changed",
                "sdk_replayed_tool_no_longer_allowed", "sdk_tool_dispatch_failed", "sdk_model_dispatch_failed",
                "sdk_native_event_changed", "sdk_checkpoint_write_failed", "sdk_max_steps_reached"}


class AutomaticArgs(ClosedModel):
    proposal: MessageProposal | UploadProposal | FormProposal


class TransferArgs(ClosedModel):
    agent_name: Literal["yuanxingmu_executor"]


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
        if operation not in {*PROPOSALS, "request_action"} or framework != "google_adk":
            raise ValueError("sdk_invalid_request_context")
        if not checked_text(tool_call_id, 512):
            raise ValueError("sdk_host_nonce_required")
        namespace = "automatic" if operation == "request_action" else "reviewed"
        binding = ["yuanxingmu-google-adk-" + namespace + "-v1", self.session_id, operation, tool_call_id]
        return "adk_" + namespace + "_v1_" + hashlib.sha256(json_bytes(binding)).hexdigest()

    def invoke(self, operation, arguments, *, framework, tool_call_id=None):
        if operation not in OPERATIONS or framework != "google_adk":
            raise ValueError("sdk_invalid_native_operation")
        fields = _arguments(operation, arguments)
        if operation in PROPOSALS:
            fields["request_key"] = self.request_key(operation, framework, tool_call_id)
        return request(operation, socket_path=self.socket_path, timeout_seconds=SDK_RPC_TIMEOUT_SECONDS, **fields)


class _BrokerTool(BaseTool):
    def __init__(self, loop, name):
        self.loop = loop
        self.schema = AutomaticArgs if name == AUTOMATIC_TOOL else SCHEMAS[BY_NAME[name]]
        description = ("Request a message, upload, or form within the host's existing automatic scope. "
                       "The host checks current authority and returns its recorded outcome for repeats."
                       if name == AUTOMATIC_TOOL else DESCRIPTIONS[BY_NAME[name]])
        super().__init__(name=name, description=description)

    def _get_declaration(self):
        return types.FunctionDeclaration(name=self.name, description=self.description,
                                         parameters_json_schema=self.schema.model_json_schema())

    async def run_async(self, *, args, tool_context):
        if not isinstance(tool_context, ToolContext):
            raise ValueError("sdk_native_tool_context_required")
        return await self.loop.invoke(self.name, args, tool_context.function_call_id)


class _HostModel(BaseLlm):
    loop: Any = Field(exclude=True, repr=False)
    agent_name: str

    async def generate_content_async(self, llm_request, stream=False):
        try:
            if stream:
                raise ValueError("sdk_streaming_not_supported")
            native = llm_request.model_dump(mode="json", exclude_none=True)
            self.loop.check_native_request(native, self.agent_name)
            if set(llm_request.tools_dict) != set(self.loop.names[self.agent_name]):
                raise ValueError("sdk_model_tools_changed")
            for name, tool in llm_request.tools_dict.items():
                if name == TRANSFER_TOOL:
                    if (type(tool) is not TransferToAgentTool or tool._agent_names != [EXECUTOR]
                            or tool._include_transfer_reason is not False):
                        raise ValueError("sdk_native_transfer_changed")
                elif tool is not self.loop.function_tools[name]:
                    raise ValueError("sdk_native_tool_changed")
            response = await self.loop.model(self.agent_name, native)
        except BaseException as error:
            self.loop.fail(error, "sdk_model_dispatch_failed")
            raise RuntimeError(self.loop.failure_reason) from None
        # Native transfer deliberately closes this generator after its one
        # response. GeneratorExit at this yield is normal SDK control flow.
        yield response


class _SessionService(InMemorySessionService):
    """Single-worker native service with an atomic durable snapshot per event."""
    def __init__(self, loop):
        super().__init__()
        self.loop = loop
        native = loop.checkpoint.value["native"]
        if native is not None:
            # The raw JSON subset and its journal bindings were checked first.
            session = Session.model_validate(native)
            self.sessions = {APP_NAME: {USER_ID: {session.id: session}}}

    def export(self):
        session = self.sessions[APP_NAME][USER_ID][self.loop.config["session_id"]]
        return session.model_dump(mode="json", exclude_none=True)

    async def append_event(self, session, event):
        from ._google_adk_state import validate_event, validate_saved
        try:
            raw = event.model_dump(mode="json", exclude_none=True)
            validate_event(raw)
            if raw["invocation_id"] != self.loop.checkpoint.value["invocation_id"]:
                raise ValueError("sdk_native_invocation_changed")
            if self.loop.failed and "error_code" not in raw:
                raise RuntimeError(self.loop.failure_reason)
            result = await super().append_event(session=session, event=event)
            self.loop.checkpoint.value["native"] = self.export()
            validate_saved(self.loop)
            self.loop.checkpoint.save()
            if "error_code" in raw:
                self.loop.fail(RuntimeError(raw["error_message"]), "sdk_native_event_changed")
            return result
        except BaseException as error:
            self.loop.fail(error, "sdk_native_event_changed")
            raise


class _Loop:
    def __init__(self, config, checkpoint):
        self.config, self.checkpoint = config, checkpoint
        self.client = _RuntimeTools(config["broker_socket"], config["session_id"])
        self.failed, self.failure_reason = False, None
        self.condition = asyncio.Condition()
        self.dispatch_index = 0
        self.cursor = checkpoint.value["round_start"]
        self.active_row = -1
        self.names = {
            COORDINATOR: [TOOL_NAMES[key] for key in ("read", "describe", "action_targets")] + [TRANSFER_TOOL],
            EXECUTOR: [TOOL_NAMES[key] for key in ("describe", "action_targets", "propose_action", "draft_email")]
                      + ([AUTOMATIC_TOOL] if config["automatic_actions"] else [])}
        self.function_tools = {name: _BrokerTool(self, name)
                               for name in [*BY_NAME, *([AUTOMATIC_TOOL] if config["automatic_actions"] else [])]}
        generation = types.GenerateContentConfig(max_output_tokens=config["max_tokens"], response_modalities=["TEXT"])
        self.executor = LlmAgent(name=EXECUTOR, description=EXECUTOR_DESCRIPTION, mode="chat",
            model=_HostModel(model=config["model_id"], loop=self, agent_name=EXECUTOR), instruction=INSTRUCTIONS[EXECUTOR],
            tools=[self.function_tools[name] for name in self.names[EXECUTOR]], generate_content_config=generation,
            disallow_transfer_to_parent=True, disallow_transfer_to_peers=True,
            before_tool_callback=self.before_tool, after_tool_callback=self.after_tool)
        self.coordinator = LlmAgent(name=COORDINATOR, mode="chat",
            model=_HostModel(model=config["model_id"], loop=self, agent_name=COORDINATOR), instruction=INSTRUCTIONS[COORDINATOR],
            tools=[self.function_tools[name] for name in self.names[COORDINATOR][:-1]], sub_agents=[self.executor],
            generate_content_config=generation, disallow_transfer_to_parent=True, disallow_transfer_to_peers=True,
            before_tool_callback=self.before_tool, after_tool_callback=self.after_tool)
        transfer = TransferToAgentTool([EXECUTOR])
        declarations = {name: tool._get_declaration().model_dump(mode="json", exclude_none=True)
                        for name, tool in self.function_tools.items()}
        declarations[TRANSFER_TOOL] = transfer._get_declaration().model_dump(mode="json", exclude_none=True)
        self.declarations = declarations
        self.schemas = {agent: [{"type": "function", "function": {
            "name": name, "description": declarations[name]["description"],
            "parameters": inline_model_schema(TransferArgs.model_json_schema() if name == TRANSFER_TOOL
                                               else self.function_tools[name].schema.model_json_schema()), "strict": True}}
            for name in names] for agent, names in self.names.items()}
        from google.adk.flows.llm_flows.agent_transfer import _build_transfer_instructions
        self.instructions = {agent: text + f'\n\nYou are an agent. Your internal name is "{agent}".'
                             for agent, text in INSTRUCTIONS.items()}
        self.instructions[EXECUTOR] += f' The description about you is "{EXECUTOR_DESCRIPTION}".'
        self.instructions[COORDINATOR] += "\n\n" + _build_transfer_instructions(TRANSFER_TOOL, self.coordinator, [self.executor])

    def fail(self, error, fallback):
        self.failed = True
        if self.failure_reason is None:
            self.failure_reason = str(error) if type(error) is RuntimeError and str(error) in STOP_REASONS else fallback

    def calls(self, message, agent):
        if type(message) is not dict or message.get("role") != "assistant":
            raise ValueError("sdk_invalid_model_message")
        # Provider reasoning text is not part of this worker's output subset.
        if set(message) - {"role", "content", "tool_calls", "reasoning_content", "refusal"}:
            raise ValueError("sdk_model_content_not_supported")
        for key in ("reasoning_content", "refusal"):
            if message.get(key) is not None:
                raise ValueError("sdk_model_content_not_supported")
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
            if not nonce or nonce in seen or agent not in self.names or name not in self.names[agent]:
                raise ValueError("sdk_tool_not_available")
            seen.add(nonce)
            arguments = decode_arguments(call["function"]["arguments"])
            schema = TransferArgs if name == TRANSFER_TOOL else AutomaticArgs if name == AUTOMATIC_TOOL else SCHEMAS[BY_NAME[name]]
            payload = schema.model_validate(arguments).model_dump()
            if name != TRANSFER_TOOL:
                _arguments("propose_action" if name == AUTOMATIC_TOOL else BY_NAME[name], payload)
            result.append({"id": nonce, "name": name, "arguments": payload})
        if any(call["name"] == TRANSFER_TOOL for call in result) and (len(result) != 1 or content):
            raise ValueError("sdk_transfer_mixed_batch")
        if not result and not content:
            raise ValueError("sdk_empty_model_response")
        return result

    def response(self, value, agent):
        if (type(value) is not dict or type(value.get("choices")) is not list or len(value["choices"]) != 1
                or type(value["choices"][0]) is not dict or type(value["choices"][0].get("message")) is not dict):
            raise ValueError("sdk_invalid_model_response")
        message = value["choices"][0]["message"]
        return message, self.calls(message, agent)

    def native_response(self, value, agent):
        message, calls = self.response(value, agent)
        parts = [types.Part(text=message["content"])] if message.get("content") else []
        parts.extend(types.Part(function_call=types.FunctionCall(id=call["id"], name=call["name"],
                      args=load_json(json_bytes(call["arguments"])))) for call in calls)
        return LlmResponse(content=types.Content(role="model", parts=parts))

    def check_native_request(self, value, agent):
        from ._google_adk_state import translate_contents
        if (agent not in self.names or type(value) is not dict
                or set(value) != {"model", "contents", "config", "live_connect_config"}
                or value["model"] != self.config["model_id"]
                or value["live_connect_config"] != {"max_output_tokens": self.config["max_tokens"],
                                                    "input_audio_transcription": {}, "output_audio_transcription": {}}):
            raise ValueError("sdk_model_configuration_changed")
        expected = {"system_instruction": self.instructions[agent], "max_output_tokens": self.config["max_tokens"],
                    "response_modalities": ["TEXT"], "labels": {"adk_agent_name": agent}}
        config = value["config"]
        if type(config) is not dict or set(config) != {*expected, "tools"} or any(config[k] != v for k, v in expected.items()):
            raise ValueError("sdk_model_configuration_changed")
        tools = config["tools"]
        if (type(tools) is not list or len(tools) != 1 or type(tools[0]) is not dict
                or set(tools[0]) != {"function_declarations"} or type(tools[0]["function_declarations"]) is not list):
            raise ValueError("sdk_model_tools_changed")
        declarations = tools[0]["function_declarations"]
        if (len(declarations) != len(self.names[agent]) or any(type(item) is not dict for item in declarations)
                or {item.get("name") for item in declarations} != set(self.names[agent])
                or any(item != self.declarations[item["name"]] for item in declarations)):
            raise ValueError("sdk_model_tools_changed")
        translate_contents(value["contents"])

    def payload(self, native, agent):
        from ._google_adk_state import translate_contents
        return {"model": self.config["model_id"], "messages": [
                    {"role": "system", "content": self.instructions[agent]}, *translate_contents(native["contents"])],
                "tools": deepcopy(self.schemas[agent]), "stream": False, "max_tokens": self.config["max_tokens"],
                "parallel_tool_calls": False}

    async def model(self, agent, native):
        from ._google_adk_state import validate_saved
        if self.failed:
            raise RuntimeError(self.failure_reason)
        records = self.checkpoint.value["records"]
        if self.cursor - self.checkpoint.value["round_start"] >= self.config["max_steps"]:
            raise RuntimeError("sdk_max_steps_reached")
        body = self.payload(native, agent)
        event_count = len(self.checkpoint.value["native"]["events"])
        if self.cursor < len(records):
            row = records[self.cursor]
            if (row["agent"] != agent or row["event_count"] != event_count or row["native_request"] != native
                    or json_bytes(row["request"]) != json_bytes(body)):
                raise ValueError("sdk_checkpoint_replay_changed")
        else:
            row = {"agent": agent, "event_count": event_count, "native_request": native,
                   "request": body, "response": None, "results": {}}
            records.append(row)
            validate_saved(self)
            self.checkpoint.save()
        response = await asyncio.to_thread(model_request, self.config, row["request"])
        _, calls = self.response(response, agent)  # Validate the complete batch before native dispatch.
        previous = {call["id"] for old in records[:self.cursor] if old["response"] is not None
                    for call in self.response(old["response"], old["agent"])[1]}
        if previous & {call["id"] for call in calls}:
            raise ValueError("sdk_repeated_host_nonce")
        if row["response"] is not None and json_bytes(row["response"]) != json_bytes(response):
            raise RuntimeError("sdk_checkpoint_response_changed")
        row["response"] = response
        self.checkpoint.save()
        self.active_row, self.dispatch_index = self.cursor, 0
        self.cursor += 1
        return self.native_response(response, agent)

    async def checked_call(self, nonce, name, arguments):
        if self.failed or self.active_row < 0:
            raise RuntimeError(self.failure_reason or "sdk_tool_dispatch_failed")
        row = self.checkpoint.value["records"][self.active_row]
        response = await asyncio.to_thread(model_request, self.config, row["request"])
        if row["response"] is None or json_bytes(response) != json_bytes(row["response"]):
            raise RuntimeError("sdk_checkpoint_response_changed")
        _, calls = self.response(response, row["agent"])
        call = {"id": nonce, "name": name, "arguments": arguments}
        if call not in calls:
            raise ValueError("sdk_invocation_not_in_host_response")
        return calls.index(call)

    async def invoke(self, name, arguments, nonce):
        async with self.condition:
            try:
                schema = AutomaticArgs if name == AUTOMATIC_TOOL else SCHEMAS[BY_NAME[name]]
                payload = schema.model_validate(arguments).model_dump()
                row = self.checkpoint.value["records"][self.active_row]
                calls = self.response(row["response"], row["agent"])[1]
                index = calls.index({"id": nonce, "name": name, "arguments": payload})
                while not self.failed and index != self.dispatch_index:
                    await self.condition.wait()
                if self.failed:
                    raise RuntimeError(self.failure_reason)
                await self.checked_call(nonce, name, payload)
                if name == AUTOMATIC_TOOL:
                    result = await asyncio.to_thread(request, "request_action", socket_path=self.client.socket_path,
                        timeout_seconds=SDK_RPC_TIMEOUT_SECONDS,
                        request_key=self.client.request_key("request_action", "google_adk", nonce),
                        proposal=_arguments("propose_action", payload)["proposal"])
                else:
                    result = await self.client.ainvoke(BY_NAME[name], payload, framework="google_adk", tool_call_id=nonce)
                encoded = encode_result(result)
                _check_action_outcome(encoded)
                cached = row["results"].get(nonce)
                if cached is not None:
                    _check_action_outcome(cached)
                    if result.get("allowed") is False and load_json(cached).get("allowed") is not False:
                        raise RuntimeError("sdk_replayed_tool_no_longer_allowed")
                    encoded = cached
                else:
                    row["results"][nonce] = encoded
                    self.checkpoint.save()
                self.dispatch_index += 1
                self.condition.notify_all()
                return encoded
            except BaseException as error:
                self.fail(error, "sdk_tool_dispatch_failed")
                self.condition.notify_all()
                raise RuntimeError(self.failure_reason) from None

    async def before_tool(self, tool, args, tool_context):
        if self.failed:
            raise RuntimeError(self.failure_reason)
        if tool.name == TRANSFER_TOOL:
            try:
                payload = TransferArgs.model_validate(args).model_dump()
                if type(tool) is not TransferToAgentTool or await self.checked_call(tool_context.function_call_id, tool.name, payload) != 0:
                    raise ValueError("sdk_native_transfer_changed")
            except BaseException as error:
                self.fail(error, "sdk_tool_dispatch_failed")
                raise RuntimeError(self.failure_reason) from None
        elif tool is not self.function_tools.get(tool.name):
            self.fail(ValueError(), "sdk_tool_dispatch_failed")
            raise RuntimeError(self.failure_reason)

    async def after_tool(self, tool, args, tool_context, tool_response):
        if tool.name == TRANSFER_TOOL:
            try:
                from ._google_adk_state import EMPTY_ACTIONS
                if (tool_response is not None or tool_context.actions.model_dump(mode="json", exclude_none=True)
                        != {**EMPTY_ACTIONS, "transfer_to_agent": EXECUTOR}):
                    raise ValueError("sdk_native_transfer_changed")
                row = self.checkpoint.value["records"][self.active_row]
                nonce = tool_context.function_call_id
                if nonce in row["results"] and row["results"][nonce] != "null":
                    raise ValueError("sdk_native_transfer_changed")
                row["results"][nonce] = "null"
                self.checkpoint.save()
            except BaseException as error:
                self.fail(error, "sdk_tool_dispatch_failed")
                raise RuntimeError(self.failure_reason) from None


async def _run(config):
    from ._google_adk_state import validate_saved
    checkpoint = Checkpoint(config)
    loop = _Loop(config, checkpoint)
    validate_saved(loop)
    value = checkpoint.value
    if config["resume"] and value["status"] == "running" and value["prompt"] != config["prompt"]:
        raise ValueError("sdk_unfinished_prompt_changed")
    if value["status"] == "completed" and value["prompt"] == config["prompt"]:
        return {"status": "completed", "answer": value["answer"], "framework": "google_adk",
                "session_id": config["session_id"], "steps": len(value["records"]) - value["round_start"]}
    if value["status"] == "completed":
        checkpoint.start_turn(config["prompt"])
    elif config["resume"]:
        checkpoint.restart_invocation()
    loop.cursor = value["round_start"]
    service = _SessionService(loop)
    if value["native"] is None:
        await service.create_session(app_name=APP_NAME, user_id=USER_ID, session_id=config["session_id"])
        value["native"] = service.export()
        checkpoint.save()
    app = App(name=APP_NAME, root_agent=loop.coordinator, resumability_config=ResumabilityConfig(is_resumable=True))
    runner = Runner(app=app, session_service=service, auto_create_session=False)
    try:
        async with aclosing(runner.run_async(user_id=USER_ID, session_id=config["session_id"],
                invocation_id=value["invocation_id"], new_message=types.Content(role="user", parts=[types.Part(text=value["prompt"]) ]),
                run_config=RunConfig(max_llm_calls=config["max_steps"] + 1,
                    telemetry=TelemetryConfig(genai_semconv_stability_opt_in="stable",
                        capture_message_content=ContentCapturingMode.NO_CONTENT,
                        adk_experimental_telemetry_opt_in=False)))) as events:
            async for _event in events:
                pass
    except Exception:
        if loop.failure_reason is not None:
            raise RuntimeError(loop.failure_reason) from None
        raise
    if loop.failed:
        raise RuntimeError(loop.failure_reason)
    if not value["records"] or loop.cursor != len(value["records"]):
        raise RuntimeError("sdk_native_completion_missing")
    last = value["records"][-1]
    message, calls = loop.response(last["response"], last["agent"])
    if calls:
        raise RuntimeError("sdk_native_completion_missing")
    value.update(status="completed", answer=checked_text(message["content"]))
    validate_saved(loop)
    checkpoint.save()
    return {"status": "completed", "answer": value["answer"], "framework": "google_adk",
            "session_id": config["session_id"], "steps": loop.cursor - value["round_start"]}


def run_session(config):
    config = checked_config(config, "google_adk")
    if any(version(package) != expected for package, expected in SDK_PACKAGES.items()):
        raise RuntimeError("sdk_version_not_supported")
    try:
        return asyncio.run(_run(config))
    except (ValueError, RuntimeError, OSError):
        raise
    except Exception:
        raise RuntimeError("sdk_native_run_failed") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the host-supervised Google ADK worker")
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
