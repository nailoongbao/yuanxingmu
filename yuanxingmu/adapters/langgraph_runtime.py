"""One fixed, serial StateGraph loop inside the host's SDK process boundary.

The native graph owns scheduling and checkpoint recovery. Checked host model
responses are re-fetched before every singleton ToolNode dispatch; JSON working
state cannot introduce a new tool instruction or grant an action permission.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import hashlib
from importlib.metadata import version
import json
import os
from pathlib import Path
from typing import Annotated, TypedDict

from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import InjectedToolCallId
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import ToolNode
from pydantic import create_model

from ..client import request
from ._langgraph_checkpoint import CheckpointSaver, STATE_FIELDS
from ._runtime_support import checked_config, checked_text, json_bytes, load_json, model_request, read_json
from ._schemas import ClosedModel, FormProposal, MessageProposal, SCHEMAS, UploadProposal
from .client import NativeTools, PROPOSALS, TOOL_NAMES, _arguments, decode_arguments, encode_result
from .langchain import _ClosedStructuredTool, build_tools


SDK_VERSION = "1.2.11"
SDK_PACKAGES = {"langgraph": SDK_VERSION, "langchain-core": "1.6.2", "langgraph-prebuilt": "1.1.0",
                "langgraph-checkpoint": "4.2.0", "pydantic": "2.13.5"}
SDK_RPC_TIMEOUT_SECONDS = 120
OPERATIONS = ("read", "describe", "action_targets", "propose_action", "draft_email")
BY_NAME = {TOOL_NAMES[name]: name for name in OPERATIONS}
AUTOMATIC_TOOL = "yuanxingmu_request_action"


class AutomaticArgs(ClosedModel):
    proposal: MessageProposal | UploadProposal | FormProposal


class GraphState(TypedDict):
    prompt: str
    messages: list[dict]
    pending: dict | None
    cursor: int
    turn_steps: int
    answer: str | None
    status: str


def _check_action_outcome(result):
    value = load_json(result.encode())
    if type(value) is not dict:
        raise RuntimeError("sdk_tool_result_not_object")
    if any(value.get(field) in ("unconfirmed", "executing") for field in ("status", "outcome")):
        raise RuntimeError("sdk_action_unconfirmed")


class _RuntimeTools(NativeTools):
    def request_key(self, operation, framework, tool_call_id):
        if operation not in {*PROPOSALS, "request_action"} or framework != "langchain":
            raise ValueError("sdk_invalid_request_context")
        if not checked_text(tool_call_id, 512):
            raise ValueError("sdk_host_nonce_required")
        namespace = "automatic" if operation == "request_action" else "reviewed"
        binding = ["yuanxingmu-langgraph-" + namespace + "-v1", self.session_id, operation, tool_call_id]
        return "lg_" + namespace + "_v1_" + hashlib.sha256(json_bytes(binding)).hexdigest()

    def invoke(self, operation, arguments, *, framework, tool_call_id=None):
        if operation not in OPERATIONS or framework != "langchain":
            raise ValueError("sdk_invalid_native_operation")
        fields = _arguments(operation, arguments)
        if operation in PROPOSALS:
            fields["request_key"] = self.request_key(operation, framework, tool_call_id)
        return request(operation, socket_path=self.socket_path, timeout_seconds=SDK_RPC_TIMEOUT_SECONDS, **fields)


def _automatic_tool(client):
    schema = create_model("LangGraphAutomaticWithCallId", __base__=AutomaticArgs,
                          tool_call_id=(Annotated[str, InjectedToolCallId], ...))

    def run(*, tool_call_id: Annotated[str, InjectedToolCallId], **arguments):
        payload = AutomaticArgs.model_validate(arguments).model_dump()
        return encode_result(request("request_action", socket_path=client.socket_path,
            timeout_seconds=SDK_RPC_TIMEOUT_SECONDS,
            request_key=client.request_key("request_action", "langchain", tool_call_id),
            proposal=_arguments("propose_action", payload)["proposal"]))

    return _ClosedStructuredTool.from_function(func=run, name=AUTOMATIC_TOOL, infer_schema=False,
        description="Request a message, upload, or form within the host's existing automatic scope. "
                    "The host checks current authority and returns its recorded outcome for repeats.",
        args_schema=schema, visible_args_schema=AutomaticArgs)


class _Loop:
    def __init__(self, config):
        self.config = config
        client = _RuntimeTools(config["broker_socket"], config["session_id"])
        self.tools = [tool for tool in build_tools(client) if tool.name in BY_NAME]
        if config["automatic_actions"]:
            self.tools.append(_automatic_tool(client))
        self.schemas = [convert_to_openai_tool(tool) for tool in self.tools]
        self.tool_node = ToolNode(self.tools, handle_tool_errors=False)

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
            nonce = checked_text(call["id"], 512)
            if not nonce or nonce in seen:
                raise ValueError("sdk_invalid_host_nonce")
            seen.add(nonce)
            name, arguments = call["function"]["name"], call["function"]["arguments"]
            checked_text(name, 128)
            arguments = decode_arguments(arguments) if type(arguments) is str else arguments
            if name in BY_NAME:
                payload = SCHEMAS[BY_NAME[name]].model_validate(arguments).model_dump()
            elif self.config["automatic_actions"] and name == AUTOMATIC_TOOL:
                payload = AutomaticArgs.model_validate(arguments).model_dump()
            else:
                raise ValueError("sdk_tool_not_available")
            # This also rejects duplicate form fields before any batch effect.
            _arguments("propose_action" if name == AUTOMATIC_TOOL else BY_NAME[name], payload)
            result.append({"name": name, "args": payload, "id": nonce, "type": "tool_call"})
        if not result and content is None:
            raise ValueError("sdk_empty_model_response")
        return result

    def response(self, value):
        if (type(value) is not dict or type(value.get("choices")) is not list or len(value["choices"]) != 1
                or type(value["choices"][0]) is not dict or type(value["choices"][0].get("message")) is not dict):
            raise ValueError("sdk_invalid_model_response")
        message = value["choices"][0]["message"]
        calls = self.calls(message)
        normalized = {"role": "assistant", "content": message.get("content")}
        if calls:
            normalized["tool_calls"] = [{"id": call["id"], "type": "function", "function": {
                "name": call["name"], "arguments": json_bytes(call["args"]).decode()}} for call in calls]
        return normalized, calls

    def messages(self, values):
        if type(values) is not list or not values or len(values) > 8192:
            raise ValueError("sdk_invalid_messages")
        for message in values:
            if type(message) is not dict:
                raise ValueError("sdk_invalid_message")
            role = message.get("role")
            fields = {"role", "content"}
            if role == "tool":
                fields.add("tool_call_id")
                if not checked_text(message.get("tool_call_id"), 512):
                    raise ValueError("sdk_invalid_message")
                _check_action_outcome(checked_text(message.get("content")))
            elif role == "assistant":
                if "tool_calls" in message:
                    fields.add("tool_calls")
                self.calls(message)
            elif role == "user":
                checked_text(message.get("content"))
            else:
                raise ValueError("sdk_invalid_message_role")
            if set(message) != fields:
                raise ValueError("sdk_invalid_message")

    def payload(self, messages):
        return {"model": self.config["model_id"], "messages": deepcopy(messages), "tools": deepcopy(self.schemas),
                "max_tokens": self.config["max_tokens"], "stream": False}

    def field(self, name, value):
        if name == "messages":
            self.messages(value)
        elif name == "prompt":
            if not checked_text(value, 256 * 1024).strip():
                raise ValueError("sdk_invalid_checkpoint_prompt")
        elif name in {"cursor", "turn_steps"}:
            if type(value) is not int or not 0 <= value <= (32 if name == "cursor" else 128):
                raise ValueError("sdk_invalid_checkpoint_counter")
        elif name == "answer":
            if value is not None:
                checked_text(value)
        elif name == "status":
            if value not in ("running", "completed"):
                raise ValueError("sdk_invalid_checkpoint_status")
        elif name == "pending" and value is not None:
            if (type(value) is not dict or set(value) != {"request", "response"} or type(value["request"]) is not dict):
                raise ValueError("sdk_invalid_checkpoint_pending")
            body = value["request"]
            if (set(body) != {"model", "messages", "tools", "max_tokens", "stream"}
                    or body["model"] != self.config["model_id"] or body["stream"] is not False
                    or type(body["max_tokens"]) is not int or not 1 <= body["max_tokens"] <= 32768
                    or body["tools"] != self.schemas):
                raise ValueError("sdk_checkpoint_request_changed")
            self.messages(body["messages"])
            if value["response"] is not None:
                self.response(value["response"])

    def state(self, value):
        if type(value) is not dict or set(value) != STATE_FIELDS:
            raise ValueError("sdk_invalid_graph_state")
        for name, item in value.items():
            self.field(name, item)
        users = [item["content"] for item in value["messages"] if item["role"] == "user"]
        if not users or users[-1] != value["prompt"]:
            raise ValueError("sdk_checkpoint_prompt_changed")
        pending = value["pending"]
        if value["status"] == "completed":
            if pending is not None or value["answer"] is None or value["cursor"] != 0:
                raise ValueError("sdk_invalid_completed_state")
        elif value["answer"] is not None:
            raise ValueError("sdk_invalid_running_state")
        if pending is None:
            if value["cursor"] != 0:
                raise ValueError("sdk_invalid_tool_cursor")
        elif pending["response"] is None:
            if value["cursor"] != 0 or value["messages"] != pending["request"]["messages"]:
                raise ValueError("sdk_checkpoint_request_changed")
        else:
            message, calls = self.response(pending["response"])
            prefix = [*pending["request"]["messages"], message]
            cursor = value["cursor"]
            if (not calls or not 0 <= cursor < len(calls) or value["messages"][:len(prefix)] != prefix
                    or len(value["messages"]) != len(prefix) + cursor):
                raise ValueError("sdk_checkpoint_response_changed")
            for index, item in enumerate(value["messages"][len(prefix):]):
                if item["role"] != "tool" or item["tool_call_id"] != calls[index]["id"]:
                    raise ValueError("sdk_invalid_completed_tool")

    def validate_saved(self, saver):
        # Native resume consumes pending writes as well as channel_values.
        for row in saver.value["records"]:
            values = list(row["checkpoint"]["channel_values"].items())
            values.extend((item["channel"], item["value"]) for item in row["writes"])
            for name, value in values:
                if name in STATE_FIELDS:
                    self.field(name, value)
                elif name == "__start__":
                    self.state(value)
                elif name.startswith("branch:to:"):
                    if value is not None:
                        raise ValueError("sdk_invalid_graph_branch")
                elif name == "__error__":
                    checked_text(value, 128)
                elif value not in (None, []):
                    raise ValueError("sdk_graph_control_not_allowed")

    def prepare(self, state):
        self.state(state)
        if state["status"] != "running" or state["pending"] is not None:
            raise RuntimeError("sdk_invalid_prepare_state")
        if state["turn_steps"] >= self.config["max_steps"]:
            raise RuntimeError("sdk_max_steps_reached")
        return {"pending": {"request": self.payload(state["messages"]), "response": None}, "cursor": 0}

    def model(self, state):
        self.state(state)
        pending = state["pending"]
        if pending is None or pending["response"] is not None or state["status"] != "running":
            raise RuntimeError("sdk_invalid_model_state")
        if state["turn_steps"] >= self.config["max_steps"]:
            raise RuntimeError("sdk_max_steps_reached")
        response = model_request(self.config, pending["request"])
        message, calls = self.response(response)
        update = {"messages": [*state["messages"], message], "turn_steps": state["turn_steps"] + 1}
        if calls:
            update["pending"] = {"request": pending["request"], "response": response}
        else:
            update.update(pending=None, answer=message["content"], status="completed")
        return update

    def tools_one(self, state, config: RunnableConfig):
        self.state(state)
        pending = state["pending"]
        if pending is None or pending["response"] is None or state["status"] != "running":
            raise RuntimeError("sdk_invalid_tools_state")
        response = model_request(self.config, pending["request"])
        if json_bytes(response) != json_bytes(pending["response"]):
            raise RuntimeError("sdk_checkpoint_response_changed")
        _, calls = self.response(response)  # Validate the entire checked batch.
        call = calls[state["cursor"]]
        try:
            # ToolNode submits its whole input list to an executor even with
            # one worker. A singleton prevents queued effects after a failure.
            outputs = self.tool_node.invoke([call], config={**config, "max_concurrency": 1})
        except Exception:
            raise RuntimeError("sdk_tool_dispatch_failed") from None
        if type(outputs) is not dict or set(outputs) != {"messages"}:
            raise RuntimeError("sdk_invalid_tool_result")
        messages = outputs["messages"]
        if (type(messages) is not list or len(messages) != 1 or type(messages[0]) is not ToolMessage
                or messages[0].tool_call_id != call["id"] or messages[0].name != call["name"]
                or messages[0].status != "success" or type(messages[0].content) is not str):
            raise RuntimeError("sdk_invalid_tool_result")
        content = checked_text(messages[0].content)
        _check_action_outcome(content)
        update = {"messages": [*state["messages"], {"role": "tool", "tool_call_id": call["id"], "content": content}],
                  "cursor": state["cursor"] + 1}
        if update["cursor"] == len(calls):
            update.update(cursor=0, pending=None)
        return update

    def compile(self, saver):
        graph = StateGraph(GraphState)
        graph.add_node("prepare", self.prepare)
        graph.add_node("model", self.model)
        graph.add_node("tools", self.tools_one)
        graph.add_edge(START, "prepare")
        graph.add_edge("prepare", "model")
        graph.add_conditional_edges("model", lambda state: END if state["status"] == "completed" else "tools")
        graph.add_conditional_edges("tools", lambda state: "prepare" if state["pending"] is None else "tools")
        return graph.compile(checkpointer=saver)


def run_session(config):
    config = checked_config(config, "langgraph")
    if any(version(package) != expected for package, expected in SDK_PACKAGES.items()):
        raise RuntimeError("sdk_version_not_supported")
    saver = CheckpointSaver(config)
    loop = _Loop(config)
    loop.validate_saved(saver)
    graph = loop.compile(saver)
    options = {"configurable": {"thread_id": config["session_id"]},
               "recursion_limit": 36 * (config["max_steps"] + 1), "max_concurrency": 1}
    state = None
    if config["resume"]:
        if not saver.value["records"]:
            raise ValueError("sdk_checkpoint_incomplete")
        snapshot = graph.get_state(options)
        state = snapshot.values
        if not state:
            latest = saver.value["records"][-1]["checkpoint"]["channel_values"]
            state = latest.get("__start__")
        loop.state(state)
        if state["status"] == "running" and state["prompt"] != config["prompt"]:
            raise ValueError("sdk_unfinished_prompt_changed")
        if not snapshot.next and state["status"] != "completed":
            raise ValueError("sdk_checkpoint_incomplete")
        if state["status"] == "completed" and snapshot.next:
            raise ValueError("sdk_invalid_completed_state")
    if state is not None and state["status"] == "completed" and state["prompt"] == config["prompt"]:
        result = state
    else:
        initial = None
        if state is None or state["status"] == "completed":
            initial = {"prompt": config["prompt"], "messages": [*(state["messages"] if state else []),
                       {"role": "user", "content": config["prompt"]}], "pending": None, "cursor": 0,
                       "turn_steps": 0, "answer": None, "status": "running"}
        result = graph.invoke(initial, options, durability="sync")
    loop.state(result)
    if result["status"] != "completed":
        raise RuntimeError("sdk_missing_final_answer")
    return {"status": "completed", "answer": checked_text(result["answer"]), "framework": "langgraph",
            "session_id": config["session_id"], "steps": result["turn_steps"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run the host-supervised LangGraph worker")
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
