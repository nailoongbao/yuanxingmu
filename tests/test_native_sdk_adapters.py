"""Installed native SDK tools + real Broker socket + local receipt assertions.

No model loop is run. These tests do not claim a sandboxed agent process. The
network allowlist below is a test-only guard against accidental external calls.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from yuanxingmu.actions import ActionTarget
from yuanxingmu.adapters import NativeTools
from yuanxingmu.adapters.client import OPERATIONS, TOOL_NAMES
from yuanxingmu.broker import Broker, Destination, Resource


OBSERVATIONS = []


class NativeRejected(ValueError):
    pass


class Driver:
    def __init__(self, client, transcript):
        self.client, self.transcript = client, transcript

    async def call(self, operation, arguments, call_id="native-call-1"):
        entry = {"operation": operation, "native_call_id": call_id, "arguments": deepcopy(arguments)}
        self.transcript.append(entry)
        try:
            result = await self.invoke(operation, deepcopy(arguments), call_id)
        except Exception as exc:
            entry["rejected_by_adapter_or_sdk"] = type(exc).__name__
            raise
        result = json.loads(result)
        entry["result"] = deepcopy(result)
        return result


class LangChainDriver(Driver):
    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from langchain_core.tools import StructuredTool
        from langgraph.graph import END, START, MessagesState, StateGraph
        from langgraph.prebuilt import ToolNode
        from yuanxingmu.adapters.langchain import build_tools
        self.tools = build_tools(client)
        assert all(isinstance(tool, StructuredTool) for tool in self.tools)
        self.by_name = {tool.name: tool for tool in self.tools}
        self.schemas = {tool.name: tool.tool_call_schema.model_json_schema() for tool in self.tools}
        builder = StateGraph(MessagesState)
        builder.add_node("tools", ToolNode(self.tools))
        builder.add_edge(START, "tools")
        builder.add_edge("tools", END)
        self.graph = builder.compile()

    async def invoke(self, operation, arguments, call_id):
        from langchain_core.messages import AIMessage
        name = TOOL_NAMES[operation]
        if call_id is None:
            return await self.by_name[name].ainvoke(arguments)
        result = await self.graph.ainvoke({"messages": [AIMessage(content="", tool_calls=[{
            "name": name, "args": arguments, "id": call_id, "type": "tool_call"}])]})
        message = result["messages"][-1]
        if message.status == "error":
            raise NativeRejected("native_tool_rejected")
        return message.content


class OpenAIDriver(Driver):
    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from agents import Agent, FunctionTool, set_tracing_disabled
        from yuanxingmu.adapters.openai_agents import build_tools
        set_tracing_disabled(True)
        self.tools = build_tools(client)
        assert all(isinstance(tool, FunctionTool) for tool in self.tools)
        self.agent = Agent(name="native-tool-contract-test", tools=self.tools)
        self.by_name = {tool.name: tool for tool in self.agent.tools}
        self.schemas = {tool.name: tool.params_json_schema for tool in self.tools}

    async def invoke(self, operation, arguments, call_id):
        from agents.tool_context import ToolContext
        tool = self.by_name[TOOL_NAMES[operation]]
        raw = json.dumps(arguments)
        context = ToolContext(context=None, tool_name=tool.name, tool_call_id=call_id,
                              tool_arguments=raw, agent=self.agent)
        return await tool.on_invoke_tool(context, raw)


class PydanticDriver(Driver):
    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from pydantic_ai import Agent, RunContext, Tool
        from pydantic_ai.models.test import TestModel
        from pydantic_ai.toolsets.function import FunctionToolset
        from pydantic_ai.usage import RunUsage
        from yuanxingmu.adapters.pydantic_ai import build_tools
        self.tools = build_tools(client)
        assert all(isinstance(tool, Tool) for tool in self.tools)
        self.agent = Agent(TestModel(), tools=self.tools)
        self.context = RunContext(deps=None, model=TestModel(), usage=RunUsage(), messages=[], agent=self.agent)
        self.toolset = FunctionToolset(self.tools)
        self.schemas = {tool.name: tool.function_schema.json_schema for tool in self.tools}

    async def invoke(self, operation, arguments, call_id):
        name = TOOL_NAMES[operation]
        context = replace(self.context, tool_name=name, tool_call_id=call_id)
        native = (await self.toolset.get_tools(context))[name]
        parsed = native.args_validator.validate_python(arguments)
        return await self.toolset.call_tool(name, parsed, context, native)


class NativeAdapterCases:
    framework = None
    driver_class = None
    modules = ()

    def setUp(self):
        if not sys.platform.startswith("linux"):
            self.skipTest("Real Broker native adapter checks require Linux")
        if any(importlib.util.find_spec(module) is None for module in self.modules):
            self.skipTest("Install docs/native-adapters-requirements.txt for actual SDK checks")
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"LANGCHAIN_TRACING_V2": "false", "LANGSMITH_TRACING": "false",
                                "OPENAI_AGENTS_DISABLE_TRACING": "1", "OTEL_SDK_DISABLED": "true"}).start()
        temporary = tempfile.TemporaryDirectory(prefix="yxm-native-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.receipts, self.transcript, self.connections = [], [], []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                data = self.rfile.read(int(self.headers["Content-Length"]))
                owner.receipts.append({"path": self.path, "body": data.decode("utf-8")})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        self.receiver = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.receiver.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_receiver)
        self.url = f"http://127.0.0.1:{self.receiver.server_port}"
        private = self.root / "private.txt"
        private.write_text("SYNTHETIC-PRIVATE-CONTENT", encoding="utf-8")
        self.host_files = self.root / "host-files"
        self.host_files.mkdir(mode=0o700)
        (self.host_files / "report.txt").write_text("synthetic old report", encoding="utf-8")
        (self.host_files / "delete.txt").write_text("synthetic selected file", encoding="utf-8")
        targets = {
            "chat": ActionTarget("message", "Fixture chat", url=self.url + "/message",
                                 headers={"Authorization": "Bearer SYNTHETIC-HOST-ONLY-TOKEN"}),
            "upload": ActionTarget("upload", "Fixture upload", url=self.url + "/upload"),
            "form": ActionTarget("form", "Fixture form", url=self.url + "/form", form_fields=("name", "note")),
            "replace": ActionTarget("overwrite", "Fixture report", workspace=self.host_files, relative_path="report.txt"),
            "remove": ActionTarget("delete", "Fixture deletion", workspace=self.host_files, relative_path="delete.txt"),
        }
        self.broker = Broker(self.root / "state", {"private": Resource(private, ("internal",))},
                             {"public": Destination(self.url + "/public"),
                              "internal": Destination(self.url + "/internal", ("internal",))},
                             reviewed_mail=True, action_targets=targets)
        self.addCleanup(self.broker.close)
        self.task = self.broker.create_task()
        self.endpoint = self.broker.serve(self.task, self.root / "worker.sock")
        self.client = NativeTools(str(self.endpoint), "fixture-persistent-session")
        original_connect = socket.socket.connect

        def guarded_connect(connection, address):
            if connection.family == socket.AF_UNIX and address == str(self.endpoint):
                self.connections.append("broker_unix_socket")
            elif connection.family == socket.AF_INET and address == ("127.0.0.1", self.receiver.server_port):
                self.connections.append("fixture_http_receiver")
            else:
                raise AssertionError("Native tool tests must not contact a model or external endpoint")
            return original_connect(connection, address)

        patch.object(socket.socket, "connect", guarded_connect).start()
        self.driver = self.driver_class(self.client, self.transcript)

    def close_receiver(self):
        self.receiver.shutdown()
        self.receiver.server_close()
        self.thread.join(2)

    def tearDown(self):
        if not hasattr(self, "driver"):
            return
        OBSERVATIONS.append({"framework": self.framework, "test": self._testMethodName,
                             "native_tools": [{"name": tool.name, "class": type(tool).__module__ + "." + type(tool).__name__}
                                              for tool in self.driver.tools],
                             "schema_sha256": hashlib.sha256(json.dumps(self.driver.schemas, sort_keys=True).encode()).hexdigest(),
                             "calls": self.transcript, "receipts": self.receipts,
                             "connections": self.connections, "broker_events": self.events()})

    def events(self):
        path = self.root / "state/broker-events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def proposal(self, kind="message", target="chat", payload=None):
        return {"proposal": {"kind": kind, "target_id": target,
                             "payload": {"body": "SYNTHETIC-PRIVATE-PROPOSAL"} if payload is None else payload}}

    def commit(self, row):
        return self.broker.review_action(self.task, {"op": "action_commit", "action_id": row["id"],
                                                    "revision": row["revision"], "digest": row["digest"], "confirm": "commit"})

    async def rejected_before_broker(self, operation, arguments, call_id="bad-call"):
        before = len(self.events())
        with self.assertRaises((ValueError, TypeError)):
            await self.driver.call(operation, arguments, call_id)
        self.assertEqual(len(self.events()), before)

    async def test_native_schema_exposes_only_content_fields(self):
        self.assertEqual(set(self.driver.schemas), set(TOOL_NAMES.values()))
        expected = {"read": {"resource"}, "send": {"destination", "body"}, "describe": set(),
                    "action_targets": set(), "propose_action": {"proposal"}, "draft_email": {"draft"}}

        def closed(node):
            if isinstance(node, dict):
                if node.get("type") == "object":
                    self.assertIs(node.get("additionalProperties"), False)
                for value in node.values():
                    closed(value)
            elif isinstance(node, list):
                for value in node:
                    closed(value)

        for operation in OPERATIONS:
            schema = self.driver.schemas[TOOL_NAMES[operation]]
            self.assertEqual(set(schema.get("properties", {})), expected[operation])
            closed(schema)
        self.assertEqual(len(self.events()), 0)

    async def test_native_read_send_and_persistent_data_restrictions(self):
        public = await self.driver.call("send", {"destination": "public", "body": "synthetic public output"}, "public-call")
        self.assertEqual(public["outcome"], "acknowledged")
        read = await self.driver.call("read", {"resource": "private"}, "read-call")
        self.assertEqual(read["content"], "SYNTHETIC-PRIVATE-CONTENT")
        denied = await self.driver.call("send", {"destination": "public", "body": "encoded or paraphrased output"}, "denied-call")
        self.assertFalse(denied["allowed"])
        self.assertEqual(denied["reason"], "destination_cannot_receive_labels")
        internal = await self.driver.call("send", {"destination": "internal", "body": "synthetic internal output"}, "internal-call")
        self.assertEqual(internal["outcome"], "acknowledged")
        state = await self.driver.call("describe", {})
        self.assertEqual(state["labels"], ["internal"])
        targets = await self.driver.call("action_targets", {})
        self.assertTrue(targets["allowed"])
        serialized = json.dumps(targets)
        self.assertNotIn(self.url, serialized)
        self.assertNotIn("SYNTHETIC-HOST-ONLY-TOKEN", serialized)
        self.assertEqual([item["path"] for item in self.receipts], ["/public", "/internal"])

    async def test_forged_host_fields_are_rejected_before_broker(self):
        for key in ("socket_path", "session_id", "task_id", "url", "headers", "credentials", "confirm", "approved", "request_key"):
            with self.subTest(key=key):
                await self.rejected_before_broker("send", {"destination": "public", "body": "synthetic", key: "forged"})
        malformed = self.proposal()
        malformed["proposal"]["payload"]["url"] = self.url + "/wrong"
        await self.rejected_before_broker("propose_action", malformed)
        await self.rejected_before_broker("draft_email", {"draft": {"recipient": "x@example.test", "subject": "s",
                                                                      "body": "b", "account_id": "forged"}})
        await self.rejected_before_broker("read", {"resource": 123})
        self.assertEqual(self.receipts, [])

    async def test_native_call_ids_deduplicate_after_rebuilding_adapter(self):
        first = await self.driver.call("propose_action", self.proposal(), "stable-native-id")
        self.assertEqual(first["status"], "pending")
        self.driver = self.driver_class(NativeTools(str(self.endpoint), "fixture-persistent-session"), self.transcript)
        replay = await self.driver.call("propose_action", self.proposal(), "stable-native-id")
        self.assertEqual(first["id"], replay["id"])
        conflict = await self.driver.call("propose_action", self.proposal(payload={"body": "different content"}), "stable-native-id")
        self.assertEqual(conflict["reason"], "action_request_conflict")
        other_call = await self.driver.call("propose_action", self.proposal(), "another-native-id")
        self.assertNotEqual(first["id"], other_call["id"])
        other_session = self.driver_class(NativeTools(str(self.endpoint), "another-host-session"), self.transcript)
        distinct = await other_session.call("propose_action", self.proposal(), "stable-native-id")
        self.assertNotEqual(first["id"], distinct["id"])
        self.assertEqual(self.receipts, [])

    async def test_missing_native_call_id_cannot_submit_proposals(self):
        await self.rejected_before_broker("propose_action", self.proposal(), None)
        await self.rejected_before_broker("draft_email", {"draft": {"recipient": "x@example.test", "subject": "s", "body": "b"}}, None)
        self.assertEqual(self.receipts, [])

    async def test_completed_and_cancelled_replays_report_existing_status(self):
        first = await self.driver.call("propose_action", self.proposal(), "committed-call")
        self.assertEqual(self.receipts, [])
        committed = self.commit(first)
        self.assertTrue(committed["started"])
        self.assertEqual(committed["action"]["status"], "acknowledged")
        replay = await self.driver.call("propose_action", self.proposal(), "committed-call")
        self.assertEqual(replay["status"], "acknowledged")
        self.assertEqual(replay["id"], first["id"])
        cancelled = await self.driver.call("propose_action", self.proposal(), "cancelled-call")
        self.broker.review_action(self.task, {"op": "action_cancel", "action_id": cancelled["id"],
                                             "revision": cancelled["revision"], "digest": cancelled["digest"]})
        replay = await self.driver.call("propose_action", self.proposal(), "cancelled-call")
        self.assertEqual(replay["status"], "cancelled")
        self.assertEqual(len(self.receipts), 1)

    async def test_email_drafts_never_send_and_reuse_native_identity(self):
        arguments = {"draft": {"recipient": "receiver@example.test", "subject": "Synthetic draft", "body": "Synthetic body"}}
        first = await self.driver.call("draft_email", arguments, "mail-native-id")
        replay = await self.driver.call("draft_email", arguments, "mail-native-id")
        self.assertEqual(first["draft_id"], replay["draft_id"])
        self.assertEqual(first["status"], "pending")
        changed = deepcopy(arguments)
        changed["draft"]["body"] = "different content"
        conflict = await self.driver.call("draft_email", changed, "mail-native-id")
        self.assertEqual(conflict["reason"], "mail_request_conflict")
        self.broker.review_mail(self.task, {"op": "cancel", "draft_id": first["draft_id"],
                                           "revision": first["revision"], "digest": first["digest"]})
        replay = await self.driver.call("draft_email", arguments, "mail-native-id")
        self.assertEqual(replay["status"], "cancelled")
        self.assertEqual(self.receipts, [])

    async def test_five_action_kinds_have_no_effect_until_host_commit(self):
        cases = [self.proposal(), self.proposal("upload", "upload", {"filename": "fixture.txt", "content": "synthetic upload"}),
                 self.proposal("form", "form", {"fields": [{"name": "name", "value": "Fixture"}, {"name": "note", "value": "synthetic form"}]}),
                 self.proposal("overwrite", "replace", {"content": "synthetic replacement"}), self.proposal("delete", "remove", {})]
        rows = [await self.driver.call("propose_action", arguments, f"action-kind-{index}") for index, arguments in enumerate(cases)]
        self.assertTrue(all(row["allowed"] and row["status"] == "pending" for row in rows))
        self.assertEqual(self.receipts, [])
        self.assertEqual((self.host_files / "report.txt").read_text(), "synthetic old report")
        self.assertTrue((self.host_files / "delete.txt").exists())
        for row in rows:
            self.assertEqual(self.commit(row)["action"]["status"], "acknowledged")
        self.assertEqual([receipt["path"] for receipt in self.receipts], ["/message", "/upload", "/form"])
        self.assertIn("synthetic upload", self.receipts[1]["body"])
        self.assertEqual(parse_qs(self.receipts[2]["body"]), {"name": ["Fixture"], "note": ["synthetic form"]})
        self.assertEqual((self.host_files / "report.txt").read_text(), "synthetic replacement")
        self.assertFalse((self.host_files / "delete.txt").exists())

    async def test_unknown_targets_and_duplicate_form_fields_do_not_send(self):
        denied = await self.driver.call("send", {"destination": self.url + "/arbitrary", "body": "synthetic"})
        self.assertEqual(denied["reason"], "unknown_destination")
        denied = await self.driver.call("propose_action", self.proposal(target="not-registered"))
        self.assertEqual(denied["reason"], "action_target_not_allowed")
        duplicate = self.proposal("form", "form", {"fields": [{"name": "name", "value": "one"}, {"name": "name", "value": "two"}]})
        await self.rejected_before_broker("propose_action", duplicate)
        self.assertEqual(self.receipts, [])

    async def test_revocation_blocks_all_bound_tools(self):
        self.broker.revoke(self.task)
        arguments = {"read": {"resource": "private"}, "send": {"destination": "public", "body": "synthetic"},
                     "describe": {}, "action_targets": {}, "propose_action": self.proposal(),
                     "draft_email": {"draft": {"recipient": "x@example.test", "subject": "s", "body": "b"}}}
        for operation in OPERATIONS:
            with self.subTest(operation=operation):
                result = await self.driver.call(operation, arguments[operation], "revoked-" + operation)
                self.assertFalse(result["allowed"])
                self.assertEqual(result["reason"], "task_revoked")
        self.assertEqual(self.receipts, [])


class LangChainNativeTests(NativeAdapterCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "langchain", LangChainDriver, ("langchain_core", "langgraph")

    async def test_model_supplied_call_id_cannot_override_native_call_id(self):
        arguments = self.proposal()
        arguments["tool_call_id"] = "forged-model-value"
        first = await self.driver.call("propose_action", arguments, "actual-native-id")
        replay = await self.driver.call("propose_action", self.proposal(), "actual-native-id")
        self.assertEqual(first["id"], replay["id"])
        other = await self.driver.call("propose_action", self.proposal(), "forged-model-value")
        self.assertNotEqual(first["id"], other["id"])


class OpenAINativeTests(NativeAdapterCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "openai_agents", OpenAIDriver, ("agents",)

    async def test_raw_function_tool_duplicate_keys_rejected_before_broker(self):
        from agents.tool_context import ToolContext
        tool = self.driver.by_name[TOOL_NAMES["send"]]
        raw = '{"destination":"public","body":"first","body":"second"}'
        context = ToolContext(context=None, tool_name=tool.name, tool_call_id="duplicate-json",
                              tool_arguments=raw, agent=self.driver.agent)
        before = len(self.events())
        with self.assertRaisesRegex(ValueError, "duplicate_tool_argument"):
            await tool.on_invoke_tool(context, raw)
        self.assertEqual(len(self.events()), before)
        self.assertEqual(self.receipts, [])


class PydanticNativeTests(NativeAdapterCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "pydantic_ai", PydanticDriver, ("pydantic_ai",)


if __name__ == "__main__":
    unittest.main()
