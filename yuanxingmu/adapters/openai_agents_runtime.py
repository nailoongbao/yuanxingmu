"""A fixed native Runner and handoff inside the host's isolated SDK worker.

Function approvals are internal scheduling pauses. Every actual invocation is
checked against the host's original model response and still goes through the
same Broker. Only stable native checkpoints are saved, never exception state.
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

from agents import Agent, FunctionTool, Model, ModelSettings, RunConfig, Runner, RunState, handoff
from agents.items import ModelResponse
from agents.exceptions import MaxTurnsExceeded
from agents.models.chatcmpl_converter import Converter
from agents.retry import ModelRetrySettings
from agents.run import ToolExecutionConfig
from agents.run_context import RunContextWrapper
from agents.usage import Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from ..client import request
from ._openai_agents_checkpoint import Checkpoint
from ._openai_agents_schema import inline_model_schema
from ._runtime_support import checked_config, checked_text, json_bytes, load_json, model_request, read_json
from ._schemas import ClosedModel, EmptyArgs, FormProposal, MessageProposal, SCHEMAS, UploadProposal
from .client import DESCRIPTIONS, NativeTools, PROPOSALS, TOOL_NAMES, _arguments, decode_arguments, encode_result


SDK_VERSION = "0.22.2"
SDK_PACKAGES = {"openai-agents": SDK_VERSION, "openai": "3.13.0", "pydantic": "2.13.5"}
SDK_RPC_TIMEOUT_SECONDS = 120
OPERATIONS = ("read", "describe", "action_targets", "propose_action", "draft_email")
BY_NAME = {TOOL_NAMES[name]: name for name in OPERATIONS}
AUTOMATIC_TOOL = "yuanxingmu_request_action"
HANDOFF_TOOL = "yuanxingmu_handoff_to_executor"
RESEARCHER = "yuanxingmu_researcher"
EXECUTOR = "yuanxingmu_executor"
INSTRUCTIONS = {
    RESEARCHER: "Use only registered resources to answer the user's task. Inspect permissions and targets when needed. "
                "For an action proposal, email draft, or permitted automatic action, hand off once to the execution "
                "assistant with the available handoff tool. Handoff retains the same host permissions and budget.",
    EXECUTOR: "Complete the user's task using the registered action tools and the supplied conversation. "
              "Reviewed proposals and email drafts require separate host review. Automatic actions are available "
              "only within the host's existing scope. Report the returned outcomes accurately."}
HANDOFF_DESCRIPTION = "Transfer the current task and conversation to the fixed execution assistant. " \
                      "The host task, permissions, data restrictions, and action budget stay the same."


class AutomaticArgs(ClosedModel):
    proposal: MessageProposal | UploadProposal | FormProposal


def _check_action_outcome(result):
    value = load_json(checked_text(result).encode())
    if type(value) is not dict:
        raise RuntimeError("sdk_tool_result_not_object")
    if any(value.get(field) in ("unconfirmed", "executing") for field in ("status", "outcome")):
        raise RuntimeError("sdk_action_unconfirmed")
    if value.get("reason") == "automatic_prior_outcome_unconfirmed":
        raise RuntimeError("sdk_action_unconfirmed")
    if value.get("reason") in ("broker_operation_failed", "task_revoked", "task_paused", "broker_closed",
                               "defense_storage_fault", "storage_fault", "invalid_quarantine_state"):
        raise RuntimeError("sdk_host_stopped")


class _RuntimeTools(NativeTools):
    def request_key(self, operation, framework, tool_call_id):
        if operation not in {*PROPOSALS, "request_action"} or framework != "openai_agents":
            raise ValueError("sdk_invalid_request_context")
        if not checked_text(tool_call_id, 512):
            raise ValueError("sdk_host_nonce_required")
        namespace = "automatic" if operation == "request_action" else "reviewed"
        binding = ["yuanxingmu-openai-agents-" + namespace + "-v1", self.session_id, operation, tool_call_id]
        return "oa_" + namespace + "_v1_" + hashlib.sha256(json_bytes(binding)).hexdigest()

    def invoke(self, operation, arguments, *, framework, tool_call_id=None):
        if operation not in OPERATIONS or framework != "openai_agents":
            raise ValueError("sdk_invalid_native_operation")
        fields = _arguments(operation, arguments)
        if operation in PROPOSALS:
            fields["request_key"] = self.request_key(operation, framework, tool_call_id)
        return request(operation, socket_path=self.socket_path, timeout_seconds=SDK_RPC_TIMEOUT_SECONDS, **fields)


class _HostModel(Model):
    def __init__(self, loop, agent_name):
        self.loop, self.agent_name = loop, agent_name

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema,
                           handoffs, tracing, *, previous_response_id, conversation_id, prompt):
        if (system_instructions != INSTRUCTIONS[self.agent_name] or output_schema is not None
                or previous_response_id is not None or conversation_id is not None or prompt is not None
                or not tracing.is_disabled()):
            raise ValueError("sdk_model_configuration_changed")
        names = [tool.name for tool in tools] + [tool.tool_name for tool in handoffs]
        if names != self.loop.names[self.agent_name]:
            raise ValueError("sdk_model_tools_changed")
        messages = Converter.items_to_messages(input, strict_feature_validation=True)
        self.loop.messages(messages)
        payload = {"model": self.loop.config["model_id"],
                   "messages": [{"role": "system", "content": system_instructions}, *messages],
                   "tools": deepcopy(self.loop.schemas[self.agent_name]), "stream": False,
                   "max_tokens": self.loop.config["max_tokens"], "parallel_tool_calls": False}
        return await self.loop.model(self.agent_name, payload)

    async def stream_response(self, *args, **kwargs):
        raise RuntimeError("sdk_streaming_not_supported")
        yield  # The native abstract interface requires an async iterator.


class _Loop:
    def __init__(self, config, checkpoint):
        self.config, self.checkpoint = config, checkpoint
        self.client = _RuntimeTools(config["broker_socket"], config["session_id"])
        self.failed = False
        self.failure_reason = None
        self.lock = asyncio.Lock()
        self.cursor = checkpoint.value["native_cursor"]
        self.active_row = self.cursor - 1
        self.names = {
            RESEARCHER: [TOOL_NAMES[key] for key in ("read", "describe", "action_targets")] + [HANDOFF_TOOL],
            EXECUTOR: [TOOL_NAMES[key] for key in ("describe", "action_targets", "propose_action", "draft_email")]
                      + ([AUTOMATIC_TOOL] if config["automatic_actions"] else [])}
        self.function_tools = {name: self.tool(name) for name in [*BY_NAME, *([AUTOMATIC_TOOL] if config["automatic_actions"] else [])]}
        settings = ModelSettings(parallel_tool_calls=False, max_tokens=config["max_tokens"],
                                 retry=ModelRetrySettings(max_retries=0))
        self.executor = Agent(name=EXECUTOR, instructions=INSTRUCTIONS[EXECUTOR], model=_HostModel(self, EXECUTOR),
                              model_settings=settings, tools=[self.function_tools[name] for name in self.names[EXECUTOR]])
        transfer = handoff(self.executor, tool_name_override=HANDOFF_TOOL,
                           tool_description_override=HANDOFF_DESCRIPTION, input_type=EmptyArgs,
                           on_handoff=self.transfer, nest_handoff_history=False)
        self.researcher = Agent(name=RESEARCHER, instructions=INSTRUCTIONS[RESEARCHER], model=_HostModel(self, RESEARCHER),
                                model_settings=settings, tools=[self.function_tools[name] for name in self.names[RESEARCHER][:-1]],
                                handoffs=[transfer])
        self.schemas = {}
        for agent, names in self.names.items():
            self.schemas[agent] = [{"type": "function", "function": {
                "name": name, "description": HANDOFF_DESCRIPTION if name == HANDOFF_TOOL else self.function_tools[name].description,
                "parameters": inline_model_schema(transfer.input_json_schema if name == HANDOFF_TOOL else self.function_tools[name].params_json_schema),
                "strict": True}} for name in names]
        self.run_config = RunConfig(tracing_disabled=True, trace_include_sensitive_data=False,
                                    tool_execution=ToolExecutionConfig(max_function_tool_concurrency=1),
                                    tool_not_found_behavior="raise_error", tool_name_collision_policy="error")

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
                    payload = schema.model_validate(decode_arguments(arguments)).model_dump()
                    await self.checked_call(context.tool_call_id, name, payload)
                    if automatic:
                        result = await asyncio.to_thread(request, "request_action", socket_path=self.client.socket_path,
                            timeout_seconds=SDK_RPC_TIMEOUT_SECONDS,
                            request_key=self.client.request_key("request_action", "openai_agents", context.tool_call_id),
                            proposal=_arguments("propose_action", payload)["proposal"])
                    else:
                        result = await self.client.ainvoke(BY_NAME[name], payload, framework="openai_agents",
                                                          tool_call_id=context.tool_call_id)
                    encoded = encode_result(result)
                    _check_action_outcome(encoded)
                    row = self.checkpoint.value["records"][self.active_row]
                    cached = row["results"].get(context.tool_call_id)
                    if cached is not None:
                        _check_action_outcome(cached)
                        if result.get("allowed") is False and load_json(cached).get("allowed") is not False:
                            raise RuntimeError("sdk_replayed_tool_no_longer_allowed")
                        # Reconstruct the exact history the model originally saw.
                        # Host replay decorations (started/reason) can change.
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

        # The decorator's default error handler converts exceptions into model
        # text. Disable that native path so a lost receipt ends the whole run.
        return FunctionTool(name=name, description=description, params_json_schema=schema.model_json_schema(),
                            on_invoke_tool=invoke, strict_json_schema=True, needs_approval=True,
                            timeout_behavior="raise_exception", _failure_error_function=None,
                            _use_default_failure_error_function=False)

    def calls(self, message, agent=None):
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
            nonce = checked_text(call["id"], 512)
            name = checked_text(call["function"]["name"], 128)
            if not nonce or nonce in seen or agent is not None and name not in self.names[agent]:
                raise ValueError("sdk_tool_not_available")
            seen.add(nonce)
            arguments = decode_arguments(call["function"]["arguments"])
            if name in BY_NAME:
                payload = SCHEMAS[BY_NAME[name]].model_validate(arguments).model_dump()
                _arguments(BY_NAME[name], payload)
            elif name == AUTOMATIC_TOOL and self.config["automatic_actions"]:
                payload = AutomaticArgs.model_validate(arguments).model_dump()
                _arguments("propose_action", payload)
            elif name == HANDOFF_TOOL:
                payload = EmptyArgs.model_validate(arguments).model_dump()
            else:
                raise ValueError("sdk_tool_not_available")
            result.append({"id": nonce, "name": name, "arguments": payload})
        if any(call["name"] == HANDOFF_TOOL for call in result) and len(result) != 1:
            raise ValueError("sdk_handoff_mixed_batch")
        if not result and content is None:
            raise ValueError("sdk_empty_model_response")
        return result

    def response(self, value, agent):
        if (type(value) is not dict or type(value.get("choices")) is not list or len(value["choices"]) != 1
                or type(value["choices"][0]) is not dict or type(value["choices"][0].get("message")) is not dict):
            raise ValueError("sdk_invalid_model_response")
        message = value["choices"][0]["message"]
        return message, self.calls(message, agent)

    def native_response(self, value, agent, record_index):
        message, calls = self.response(value, agent)
        output = []
        if message.get("content") is not None:
            output.append(ResponseOutputMessage(id="msg_" + hashlib.sha256(json_bytes([record_index, value])).hexdigest(),
                role="assistant", type="message", status="completed",
                content=[ResponseOutputText(text=message["content"], type="output_text", annotations=[])]))
        output.extend(ResponseFunctionToolCall(id="fc_" + call["id"], call_id=call["id"], name=call["name"],
            arguments=json_bytes(call["arguments"]).decode(), type="function_call", status="completed") for call in calls)
        return ModelResponse(output=output, usage=Usage(requests=1), response_id=None)

    def messages(self, messages, *, system=False):
        if type(messages) is not list or not messages or len(messages) > 512:
            raise ValueError("sdk_invalid_messages")
        for index, item in enumerate(messages):
            if type(item) is not dict:
                raise ValueError("sdk_invalid_message")
            fields = {"role", "content"}
            role = item.get("role")
            if role == "assistant":
                if "tool_calls" in item:
                    fields.add("tool_calls")
                self.calls(item)
            elif role == "tool":
                fields.add("tool_call_id")
                checked_text(item.get("tool_call_id"), 512)
                text = checked_text(item.get("content"))
                if text != '{"assistant": "yuanxingmu_executor"}':
                    _check_action_outcome(text)
            elif role == "user" or system and index == 0 and role == "system":
                checked_text(item.get("content"))
            else:
                raise ValueError("sdk_invalid_message_role")
            if set(item) != fields:
                raise ValueError("sdk_invalid_message")

    def check_record(self, row):
        if row["agent"] not in self.names:
            raise ValueError("sdk_checkpoint_agent_changed")
        body = row["request"]
        if (set(body) != {"model", "messages", "tools", "stream", "max_tokens", "parallel_tool_calls"}
                or body["model"] != self.config["model_id"] or body["stream"] is not False
                or body["parallel_tool_calls"] is not False or type(body["max_tokens"]) is not int
                or not 1 <= body["max_tokens"] <= 32768 or body["tools"] != self.schemas[row["agent"]]):
            raise ValueError("sdk_checkpoint_request_changed")
        self.messages(body["messages"], system=True)
        if body["messages"][0] != {"role": "system", "content": INSTRUCTIONS[row["agent"]]}:
            raise ValueError("sdk_checkpoint_instructions_changed")
        if row["response"] is not None:
            _, calls = self.response(row["response"], row["agent"])
            available = {call["id"] for call in calls if call["name"] != HANDOFF_TOOL}
            if set(row["results"]) - available:
                raise ValueError("sdk_checkpoint_tool_result_changed")
            for result in row["results"].values():
                _check_action_outcome(result)
        elif row["results"]:
            raise ValueError("sdk_checkpoint_tool_result_changed")

    async def model(self, agent, payload):
        if self.failed:
            raise RuntimeError("sdk_round_stopped")
        records = self.checkpoint.value["records"]
        if self.cursor - self.checkpoint.value["round_start"] >= self.config["max_steps"]:
            raise RuntimeError("sdk_max_steps_reached")
        if self.cursor < len(records):
            row = records[self.cursor]
            if row["agent"] != agent or json_bytes(row["request"]) != json_bytes(payload):
                raise ValueError("sdk_checkpoint_replay_changed")
        else:
            row = {"agent": agent, "request": payload, "response": None, "results": {}}
            records.append(row)
            self.checkpoint.save()  # Keep the last stable native state, not live Runner internals.
        response = await asyncio.to_thread(model_request, self.config, row["request"])
        self.response(response, agent)  # Validate every call before exposing the batch to Runner.
        if row["response"] is not None and json_bytes(row["response"]) != json_bytes(response):
            raise RuntimeError("sdk_checkpoint_response_changed")
        row["response"] = response
        self.checkpoint.save()
        self.active_row = self.cursor
        self.cursor += 1
        return self.native_response(response, agent, self.active_row)

    async def checked_call(self, nonce, name, arguments):
        if self.failed or self.active_row < 0:
            raise RuntimeError("sdk_round_stopped")
        row = self.checkpoint.value["records"][self.active_row]
        response = await asyncio.to_thread(model_request, self.config, row["request"])
        if row["response"] is None or json_bytes(response) != json_bytes(row["response"]):
            raise RuntimeError("sdk_checkpoint_response_changed")
        _, calls = self.response(response, row["agent"])
        if {"id": nonce, "name": name, "arguments": arguments} not in calls:
            raise ValueError("sdk_invocation_not_in_host_response")

    async def transfer(self, _context, _arguments):
        try:
            row = self.checkpoint.value["records"][self.active_row]
            _, calls = self.response(row["response"], row["agent"])
            if row["agent"] != RESEARCHER or len(calls) != 1 or calls[0]["name"] != HANDOFF_TOOL:
                raise ValueError("sdk_invalid_handoff")
            await self.checked_call(calls[0]["id"], HANDOFF_TOOL, {})
        except BaseException:
            self.failed = True
            raise


async def _run(config):
    from ._openai_agents_state import validate_saved

    checkpoint = Checkpoint(config)
    loop = _Loop(config, checkpoint)
    value = checkpoint.value
    if config["resume"]:
        validate_saved(loop)
        if value["status"] == "running" and value["prompt"] != config["prompt"]:
            raise ValueError("sdk_unfinished_prompt_changed")
        if value["status"] == "completed" and value["prompt"] == config["prompt"]:
            return {"status": "completed", "answer": value["answer"], "framework": "openai_agents",
                    "session_id": config["session_id"], "steps": value["native"]["current_turn"]}
        if value["status"] == "running" and value["native"]["current_turn"] >= config["max_steps"]:
            raise RuntimeError("sdk_max_steps_reached")
        state = await RunState.from_json(loop.researcher, deepcopy(value["native"]),
                                         context_override={}, strict_context=True)
    else:
        state = RunState(RunContextWrapper(context={}), config["prompt"], loop.researcher, config["max_steps"])
    if value["status"] == "completed":
        # A new user turn uses the native prior history but starts the fixed
        # researcher role. The host session and action budget are unchanged.
        history = [*state._original_input] if type(state._original_input) is list else [{"role": "user", "content": state._original_input}]
        history += [item.to_input_item() for item in state._generated_items]
        history.append({"role": "user", "content": config["prompt"]})
        loop.cursor = len(value["records"])
        loop.active_row = loop.cursor - 1
        value.update(prompt=config["prompt"], round_start=loop.cursor)
        state = RunState(RunContextWrapper(context={}), history, loop.researcher, config["max_steps"])
    if not config["resume"] or value["status"] == "completed":
        checkpoint.snapshot(state, loop.cursor)
        validate_saved(loop)
        checkpoint.save()
    while True:
        interruptions = state.get_interruptions()
        if interruptions:
            item = interruptions[0]
            raw = item.raw_item
            await loop.checked_call(raw.call_id, raw.name, decode_arguments(raw.arguments))
            state.approve(item, always_approve=False)
        try:
            result = await Runner.run(loop.researcher, state, run_config=loop.run_config)
        except Exception:
            if loop.failure_reason is not None:
                raise RuntimeError(loop.failure_reason) from None
            raise
        state = result.to_state()
        if result.interruptions:
            checkpoint.snapshot(state, loop.cursor)
            validate_saved(loop)
            checkpoint.save()
            continue
        answer = checked_text(result.final_output)
        checkpoint.snapshot(state, loop.cursor, status="completed", answer=answer)
        validate_saved(loop)
        checkpoint.save()
        return {"status": "completed", "answer": answer, "framework": "openai_agents",
                "session_id": config["session_id"], "steps": state._current_turn}


def run_session(config):
    config = checked_config(config, "openai_agents")
    if any(version(package) != expected for package, expected in SDK_PACKAGES.items()):
        raise RuntimeError("sdk_version_not_supported")
    try:
        return asyncio.run(_run(config))
    except MaxTurnsExceeded:
        raise RuntimeError("sdk_max_steps_reached") from None
    except (ValueError, RuntimeError, OSError):
        raise
    except Exception:
        raise RuntimeError("sdk_native_run_failed") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the host-supervised OpenAI Agents worker")
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
