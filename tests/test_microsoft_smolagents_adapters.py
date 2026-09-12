"""Actual Microsoft Agent Framework / smolagents tool dispatch with Broker.

No model loop, CodeAgent executor, or external destination is run. smolagents
uses per-dispatch host nonces and exposes a documented native-schema limitation.
"""
import asyncio
from copy import deepcopy
import json
import os
import unittest
from unittest.mock import patch

from yuanxingmu.adapters.client import OPERATIONS, TOOL_NAMES
from test_additional_sdk_adapters import AdditionalDriver
from test_autogen_llama_adapters import AutoGenLlamaCases
from test_native_sdk_adapters import NativeAdapterCases, NativeRejected, OBSERVATIONS


class MicrosoftDriver(AdditionalDriver):
    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from agent_framework import Agent, BaseChatClient, FunctionTool
        from agent_framework._tools import FunctionInvocationLayer
        from yuanxingmu.adapters.microsoft_agent_framework import build_tools
        self.model_attempts = []
        attempts = self.model_attempts

        class NeverRunClient(FunctionInvocationLayer, BaseChatClient):
            def _inner_get_response(self, *args, **kwargs):
                attempts.append("get_response")
                raise AssertionError("Registration-only model must never be called")

        self.tools = build_tools(client)
        assert all(isinstance(tool, FunctionTool) for tool in self.tools)
        self.agent = Agent(client=NeverRunClient(), name="native_tool_registration_only", tools=self.tools)
        self.by_name = {tool.name: tool for tool in self.agent.default_options["tools"]}
        self.schemas = {name: tool.to_json_schema_spec()["function"]["parameters"]
                        for name, tool in self.by_name.items()}

    async def invoke(self, operation, arguments, call_id, middleware=None):
        from agent_framework import Content
        from agent_framework._tools import _auto_invoke_function
        name = TOOL_NAMES[operation]
        if call_id is None:
            contents = await self.by_name[name].invoke(arguments=arguments)
            return "".join(content.text for content in contents if content.type == "text")
        result = await _auto_invoke_function(
            Content.from_function_call(call_id, name, arguments=arguments), config={},
            tool_map=self.by_name, middleware_pipeline=middleware, live_tools=self.tools)
        if result.exception:
            raise NativeRejected("native_function_dispatch_rejected")
        return result.result


class SmolagentsDriver(AdditionalDriver):
    identity_source = "host_invocation_nonce"

    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from smolagents import Model, Tool, ToolCallingAgent
        from smolagents.models import get_tool_json_schema
        from smolagents.monitoring import LogLevel
        from yuanxingmu.adapters.smolagents import HostInvocations, build_tools
        self.model_attempts = []
        attempts = self.model_attempts

        class NeverRunModel(Model):
            def generate(self, *args, **kwargs):
                attempts.append("generate")
                raise AssertionError("Registration-only model must never be called")

            def generate_stream(self, *args, **kwargs):
                attempts.append("generate_stream")
                raise AssertionError("Registration-only model must never be called")

        self.identities = HostInvocations()
        self.tools = build_tools(client, invocations=self.identities)
        assert all(isinstance(tool, Tool) for tool in self.tools)
        self.agent = ToolCallingAgent(tools=self.tools, model=NeverRunModel(model_id="never-run"),
                                      add_base_tools=False, verbosity_level=LogLevel.OFF)
        self.by_name = {tool.name: self.agent.tools[tool.name] for tool in self.tools}
        self.schemas = {name: get_tool_json_schema(tool)["function"]["parameters"]
                        for name, tool in self.by_name.items()}

    async def invoke(self, operation, arguments, call_id):
        from smolagents.utils import AgentError

        def execute():
            if call_id is None:
                return self.agent.execute_tool_call(TOOL_NAMES[operation], arguments)
            with self.identities.bind(call_id):
                return self.agent.execute_tool_call(TOOL_NAMES[operation], arguments)

        try:
            return await asyncio.to_thread(execute)
        except AgentError as exc:
            raise NativeRejected("native_smolagents_dispatch_rejected") from exc


class MicrosoftSmolCases(AutoGenLlamaCases):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"HF_HUB_DISABLE_TELEMETRY": "1", "HF_HUB_OFFLINE": "1"}).start()
        super().setUp()


class MicrosoftAgentFrameworkNativeTests(MicrosoftSmolCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "microsoft_agent_framework", MicrosoftDriver, ("agent_framework",)

    async def test_model_cannot_supply_runtime_context_or_native_id(self):
        for name in ("ctx", "context", "tool_call_id", "skip_parsing"):
            await self.rejected_before_broker("propose_action", {**self.proposal(), name: "forged"})

    async def test_middleware_route_preserves_native_id_despite_metadata_changes(self):
        from agent_framework import FunctionMiddleware
        from agent_framework._middleware import FunctionMiddlewarePipeline
        observed = []

        class MetadataProbe(FunctionMiddleware):
            async def process(self, context, call_next):
                observed.append(context.metadata.get("call_id"))
                context.metadata["call_id"] = "arbitrary-metadata-is-not-identity"
                await call_next()

        pipeline = FunctionMiddlewarePipeline(MetadataProbe())
        first = json.loads(await self.driver.invoke("propose_action", self.proposal(), "native-middleware-id", pipeline))
        self.transcript.append({"operation": "propose_action", "route": "native FunctionMiddlewarePipeline",
                                "identity_source": "native_tool_call_id", "native_tool_call_id": "native-middleware-id",
                                "arguments": self.proposal(), "result": deepcopy(first)})
        replay = await self.driver.call("propose_action", self.proposal(), "native-middleware-id")
        self.assertEqual(first["id"], replay["id"])
        self.assertEqual(observed, ["native-middleware-id"])
        self.assertEqual(self.receipts, [])

    async def test_session_and_metadata_cannot_replace_missing_native_id(self):
        from agent_framework import AgentSession, FunctionInvocationContext
        tool = self.driver.by_name[TOOL_NAMES["propose_action"]]
        context = FunctionInvocationContext(tool, self.proposal(), session=AgentSession(),
                                             metadata={"call_id": "fake-context-call"},
                                             kwargs={"tool_call_id": "fake-runtime-call"})
        before = len(self.events())
        with self.assertRaisesRegex(ValueError, "native_tool_call_id_required"):
            await tool.invoke(arguments=self.proposal(), context=context)
        self.assertEqual(len(self.events()), before)
        self.assertEqual(self.receipts, [])

    async def test_direct_function_cannot_reuse_previous_identity_and_raw_result_can_replay(self):
        first = await self.driver.call("propose_action", self.proposal(), "finished-native-id")
        tool = self.driver.by_name[TOOL_NAMES["propose_action"]]
        before = len(self.events())
        with self.assertRaisesRegex(ValueError, "native_tool_call_id_required"):
            await tool(**self.proposal())
        self.assertEqual(len(self.events()), before)
        replay = json.loads(await tool.invoke(arguments=self.proposal(), tool_call_id="finished-native-id", skip_parsing=True))
        self.assertEqual(first["id"], replay["id"])
        self.assertEqual(self.receipts, [])


class SmolagentsNativeTests(MicrosoftSmolCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "smolagents", SmolagentsDriver, ("smolagents",)
    test_native_call_ids_deduplicate_after_rebuilding_adapter = None
    test_missing_native_call_id_cannot_submit_proposals = None
    test_email_drafts_never_send_and_reuse_native_identity = None
    test_native_schema_exposes_only_content_fields = None

    async def test_host_nonces_deduplicate_after_rebuilding_adapter(self):
        await NativeAdapterCases.test_native_call_ids_deduplicate_after_rebuilding_adapter(self)

    async def test_missing_host_nonce_cannot_submit_proposals(self):
        await NativeAdapterCases.test_missing_native_call_id_cannot_submit_proposals(self)

    async def test_email_drafts_never_send_and_reuse_host_nonce(self):
        await NativeAdapterCases.test_email_drafts_never_send_and_reuse_native_identity(self)

    async def test_native_declaration_preserves_nested_schemas_but_omits_root_extra_flag(self):
        expected = {"read": {"resource"}, "send": {"destination", "body"}, "describe": set(),
                    "action_targets": set(), "propose_action": {"proposal"}, "draft_email": {"draft"}}

        def nested_closed(node):
            if isinstance(node, dict):
                if node.get("type") == "object":
                    self.assertIs(node.get("additionalProperties"), False)
                for value in node.values():
                    nested_closed(value)
            elif isinstance(node, list):
                for value in node:
                    nested_closed(value)

        self.assertEqual(set(self.driver.schemas), set(TOOL_NAMES.values()))
        for operation in OPERATIONS:
            schema = self.driver.schemas[TOOL_NAMES[operation]]
            self.assertEqual(set(schema["properties"]), expected[operation])
            self.assertNotIn("additionalProperties", schema)
            nested_closed(schema["properties"])
            await self.rejected_before_broker(operation, {"unregistered_field": "forged"})
        proposal_schema = self.driver.schemas[TOOL_NAMES["propose_action"]]["properties"]["proposal"]
        self.assertEqual(len(proposal_schema["oneOf"]), 5)
        self.assertNotIn("anyOf", proposal_schema)
        self.assertEqual(self.receipts, [])

    async def test_nonce_scope_restores_after_exception_and_model_values_are_rejected(self):
        with self.driver.identities.bind("outer"):
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                with self.driver.identities.bind("inner"):
                    self.assertEqual(self.driver.identities.current(), "inner")
                    raise RuntimeError("fixture")
            self.assertEqual(self.driver.identities.current(), "outer")
        self.assertIsNone(self.driver.identities.current())
        for field in ("tool_call_id", "call_id", "context", "invocation_nonce", "sanitize_inputs_outputs"):
            await self.rejected_before_broker("propose_action", {**self.proposal(), field: "forged"})

    async def test_direct_tool_call_enforces_nested_schema_and_host_nonce(self):
        tool = self.driver.by_name[TOOL_NAMES["propose_action"]]

        def direct():
            with self.driver.identities.bind("direct-host-nonce"):
                return tool(self.proposal())

        first = json.loads(await asyncio.to_thread(direct))
        replay = await self.driver.call("propose_action", self.proposal(), "direct-host-nonce")
        self.assertEqual(first["id"], replay["id"])
        malformed = self.proposal()
        malformed["proposal"]["payload"]["approved"] = True
        before = len(self.events())
        with self.driver.identities.bind("bad-direct-call"):
            with self.assertRaises(ValueError):
                await asyncio.to_thread(tool, **malformed)
        with self.assertRaisesRegex(ValueError, "native_tool_call_id_required"):
            await asyncio.to_thread(tool, **self.proposal())
        self.assertEqual(len(self.events()), before)
        self.assertEqual(self.receipts, [])

    async def test_state_substitution_cannot_set_host_endpoint_or_approval(self):
        self.driver.agent.state["valid-proposal"] = self.proposal()["proposal"]
        valid = await self.driver.call("propose_action", {"proposal": "valid-proposal"}, "valid-state-call")
        self.assertEqual(valid["status"], "pending")
        self.driver.agent.state["hostile-proposal"] = {**self.proposal()["proposal"],
                                                       "socket_path": "/tmp/forged.sock", "approved": True}
        before = len(self.events())
        with self.assertRaises(NativeRejected):
            await self.driver.call("propose_action", {"proposal": "hostile-proposal"}, "state-call")
        self.assertEqual(len(self.events()), before)
        self.assertEqual(self.receipts, [])

    async def test_chat_tool_call_id_is_not_injected_into_registered_tool(self):
        from smolagents.memory import ActionStep
        from smolagents.models import ChatMessage, ChatMessageToolCall, ChatMessageToolCallFunction
        from smolagents.monitoring import Timing
        from smolagents.utils import AgentError
        message = ChatMessage(role="assistant", tool_calls=[ChatMessageToolCall(
            id="actual-chat-message-call-id", type="function", function=ChatMessageToolCallFunction(
                name=TOOL_NAMES["propose_action"], arguments=self.proposal()))])
        step = ActionStep(step_number=0, timing=Timing(start_time=0.0))
        before = len(self.events())
        with self.assertRaisesRegex(AgentError, "native_tool_call_id_required"):
            await asyncio.to_thread(lambda: list(self.driver.agent.process_tool_calls(message, step)))
        self.transcript.append({"operation": "propose_action", "route": "ToolCallingAgent.process_tool_calls",
                                "chat_message_call_id": "actual-chat-message-call-id", "host_invocation_nonce": None,
                                "arguments": self.proposal(), "rejected": "missing_host_nonce"})
        self.assertEqual(len(self.events()), before)
        self.assertEqual(self.receipts, [])


if __name__ == "__main__":
    unittest.main()
