"""Installed AutoGen / LlamaIndex tools, genuine Broker and local receipts.

Only tool registration and dispatch run. Every model entry point is a sentinel
that fails if called. LlamaIndex proposals use explicitly labelled host nonces.
"""
import asyncio
from copy import deepcopy
import hashlib
import json
import unittest

from yuanxingmu.adapters.client import TOOL_NAMES
from test_additional_sdk_adapters import AdditionalCases, AdditionalDriver
from test_native_sdk_adapters import NativeAdapterCases, NativeRejected, OBSERVATIONS


class AutoGenDriver(AdditionalDriver):
    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from autogen_agentchat.agents import AssistantAgent
        from autogen_core.models import ChatCompletionClient
        from autogen_core.tools import BaseTool
        from yuanxingmu.adapters.autogen import build_tools
        self.model_attempts = []
        attempts = self.model_attempts

        class NeverRunClient(ChatCompletionClient):
            async def create(self, *args, **kwargs):
                attempts.append("create")
                raise AssertionError("Registration-only model must never be called")

            def _never(self, *args, **kwargs):
                attempts.append("model_method")
                raise AssertionError("Registration-only model must never be called")

            create_stream = actual_usage = total_usage = count_tokens = remaining_tokens = _never

            async def close(self):
                pass

            @property
            def capabilities(self):
                return {"vision": False, "function_calling": True, "json_output": True}

            @property
            def model_info(self):
                return {**self.capabilities, "family": "unknown", "structured_output": True}

        self.tools = build_tools(client)
        assert all(isinstance(tool, BaseTool) for tool in self.tools)
        self.agent = AssistantAgent("native_tool_registration_only", NeverRunClient(), tools=self.tools)
        self.by_name = {tool.name: tool for tool in self.tools}
        self.schemas = {tool.name: tool.schema["parameters"] for tool in self.tools}

    async def invoke(self, operation, arguments, call_id):
        from autogen_core import CancellationToken, FunctionCall
        name = TOOL_NAMES[operation]
        if call_id is None:
            result = await self.agent._workbench[0].call_tool(name, arguments, CancellationToken())
            if result.is_error:
                raise NativeRejected("native_workbench_rejected")
            return result.to_text()
        # Exercise the actual AgentChat single-call dispatcher. This versioned
        # private SDK method runs only tool execution, never the model loop.
        _, result = await self.agent._execute_tool_call(
            FunctionCall(id=call_id, name=name, arguments=json.dumps(arguments)),
            self.agent._workbench, [], self.agent.name, CancellationToken(), asyncio.Queue())
        if result.is_error:
            raise NativeRejected("native_assistant_dispatch_rejected")
        return result.content


class LlamaIndexDriver(AdditionalDriver):
    identity_source = "host_invocation_nonce"

    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from llama_index.core.agent.workflow import FunctionAgent
        from llama_index.core.llms.mock import MockFunctionCallingLLM
        from llama_index.core.tools import FunctionTool
        from yuanxingmu.adapters.llama_index import HostInvocations, build_tools
        self.model_attempts = []
        attempts = self.model_attempts

        class NeverRunLLM(MockFunctionCallingLLM):
            def _never(self, *args, **kwargs):
                attempts.append("model_method")
                raise AssertionError("Registration-only model must never be called")

            async def _never_async(self, *args, **kwargs):
                attempts.append("async_model_method")
                raise AssertionError("Registration-only model must never be called")

            complete = stream_complete = chat = stream_chat = _never
            acomplete = astream_complete = achat = astream_chat = _never_async

        self.identities = HostInvocations()
        self.tools = build_tools(client, invocations=self.identities)
        assert all(isinstance(tool, FunctionTool) for tool in self.tools)
        self.agent = FunctionAgent(name="native_tool_registration_only", tools=self.tools, llm=NeverRunLLM())
        self.by_name = {tool.metadata.get_name(): tool for tool in self.agent.tools}
        self.schemas = {name: tool.metadata.to_openai_tool()["function"]["parameters"]
                        for name, tool in self.by_name.items()}

    async def invoke(self, operation, arguments, call_id):
        tool = self.by_name[TOOL_NAMES[operation]]
        if call_id is None:
            result = await tool.acall(**arguments)
        else:
            with self.identities.bind(call_id):
                result = await tool.acall(**arguments)
        if result.is_error:
            raise NativeRejected("native_function_tool_rejected")
        return result.content


class AutoGenLlamaCases(AdditionalCases):
    def tearDown(self):
        # LlamaIndex native FunctionTools expose metadata.name, not tool.name.
        # Record the actual objects without adding a test-only wrapper to them.
        if not hasattr(self, "driver"):
            return
        OBSERVATIONS.append({
            "framework": self.framework, "test": self._testMethodName,
            "native_tools": [{"name": getattr(tool, "name", None) or tool.metadata.get_name(),
                              "class": type(tool).__module__ + "." + type(tool).__name__}
                             for tool in self.driver.tools],
            "schema_sha256": hashlib.sha256(json.dumps(self.driver.schemas, sort_keys=True).encode()).hexdigest(),
            "identity_source": self.driver.identity_source,
            "native_registration": type(self.driver.agent).__module__ + "." + type(self.driver.agent).__name__,
            "calls": self.transcript, "receipts": self.receipts, "connections": self.connections,
            "broker_events": self.events(), "prohibited_network_attempts": self.prohibited_network_attempts,
            "model_entry_point_attempts": self.driver.model_attempts,
        })
        self.assertEqual(self.prohibited_network_attempts, [])
        self.assertEqual(self.driver.model_attempts, [])


class AutoGenNativeTests(AutoGenLlamaCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "autogen", AutoGenDriver, ("autogen_core", "autogen_agentchat")

    async def test_model_cannot_supply_hidden_call_id_or_cancellation_token(self):
        for field in ("call_id", "tool_call_id", "cancellation_token"):
            await self.rejected_before_broker("propose_action", {**self.proposal(), field: "forged"})

    async def test_core_tool_agent_message_uses_same_native_identity(self):
        from autogen_core import AgentId, FunctionCall, SingleThreadedAgentRuntime
        from autogen_core.tool_agent import ToolAgent
        runtime = SingleThreadedAgentRuntime()
        await ToolAgent.register(runtime, "fixture_tools", lambda: ToolAgent("Local fixture tools", self.driver.tools))
        runtime.start()
        try:
            result = await runtime.send_message(
                FunctionCall(id="core-native-id", name=TOOL_NAMES["propose_action"], arguments=json.dumps(self.proposal())),
                AgentId("fixture_tools", "default"))
        finally:
            await runtime.stop_when_idle()
            await runtime.close()
        self.assertFalse(result.is_error)
        first = json.loads(result.content)
        self.transcript.append({"operation": "propose_action", "route": "autogen_core.ToolAgent runtime message",
                                "identity_source": "native_tool_call_id", "native_tool_call_id": "core-native-id",
                                "arguments": self.proposal(), "result": deepcopy(first)})
        replay = await self.driver.call("propose_action", self.proposal(), "core-native-id")
        self.assertEqual(first["id"], replay["id"])
        self.assertEqual(self.receipts, [])

    async def test_direct_run_cannot_reuse_previous_call_identity(self):
        from autogen_core import CancellationToken
        first = await self.driver.call("propose_action", self.proposal(), "finished-native-id")
        tool = self.driver.by_name[TOOL_NAMES["propose_action"]]
        before = len(self.events())
        with self.assertRaisesRegex(ValueError, "native_tool_call_id_required"):
            await tool.run(tool.args_type().model_validate(self.proposal()), CancellationToken())
        self.assertEqual(len(self.events()), before)
        replay = await self.driver.call("propose_action", self.proposal(), "finished-native-id")
        self.assertEqual(first["id"], replay["id"])

    async def test_already_cancelled_dispatch_does_not_reach_broker(self):
        from autogen_core import CancellationToken
        token = CancellationToken()
        token.cancel()
        before = len(self.events())
        with self.assertRaises(asyncio.CancelledError):
            await self.driver.by_name[TOOL_NAMES["send"]].run_json(
                {"destination": "public", "body": "never delivered"}, token, call_id="cancelled-call")
        self.assertEqual(len(self.events()), before)
        self.assertEqual(self.receipts, [])


class LlamaIndexNativeTests(AutoGenLlamaCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "llama_index", LlamaIndexDriver, ("llama_index",)
    test_native_call_ids_deduplicate_after_rebuilding_adapter = None
    test_missing_native_call_id_cannot_submit_proposals = None
    test_email_drafts_never_send_and_reuse_native_identity = None

    async def test_host_nonces_deduplicate_after_rebuilding_adapter(self):
        await NativeAdapterCases.test_native_call_ids_deduplicate_after_rebuilding_adapter(self)

    async def test_missing_host_nonce_cannot_submit_proposals(self):
        await NativeAdapterCases.test_missing_native_call_id_cannot_submit_proposals(self)

    async def test_email_drafts_never_send_and_reuse_host_nonce(self):
        await NativeAdapterCases.test_email_drafts_never_send_and_reuse_native_identity(self)

    async def test_scope_restores_after_exceptions_and_model_context_cannot_override_it(self):
        with self.driver.identities.bind("outer"):
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                with self.driver.identities.bind("inner"):
                    self.assertEqual(self.driver.identities.current(), "inner")
                    raise RuntimeError("fixture")
            self.assertEqual(self.driver.identities.current(), "outer")
        self.assertIsNone(self.driver.identities.current())
        for field in ("ctx", "context", "tool_id", "call_id", "invocation_nonce"):
            await self.rejected_before_broker("propose_action", {**self.proposal(), field: "forged"})
        for invalid in (None, "", 123, "x" * 513):
            with self.assertRaisesRegex(ValueError, "host_invocation_nonce_required"):
                with self.driver.identities.bind(invalid):
                    self.fail("Invalid nonce must never be bound")

    async def test_sync_tool_call_preserves_host_nonce_and_rejects_missing_binding(self):
        tool = self.driver.by_name[TOOL_NAMES["propose_action"]]

        def sync_call():
            with self.driver.identities.bind("sync-host-nonce"):
                return tool.call(**self.proposal())

        first = json.loads((await asyncio.to_thread(sync_call)).content)
        replay = await self.driver.call("propose_action", self.proposal(), "sync-host-nonce")
        self.assertEqual(first["id"], replay["id"])
        before = len(self.events())
        with self.assertRaisesRegex(ValueError, "native_tool_call_id_required"):
            await asyncio.to_thread(tool.call, **self.proposal())
        self.assertEqual(len(self.events()), before)
        self.assertEqual(self.receipts, [])

    async def test_native_agent_dispatch_requires_host_binding_despite_workflow_context(self):
        from llama_index.core.workflow import Context
        tool = self.driver.by_name[TOOL_NAMES["propose_action"]]
        context = Context(self.driver.agent)
        before = len(self.events())
        rejected = await self.driver.agent._call_tool(context, tool, self.proposal())
        self.assertTrue(rejected.is_error)
        self.assertIn("native_tool_call_id_required", rejected.content)
        self.assertEqual(len(self.events()), before)
        with self.driver.identities.bind("workflow-host-nonce"):
            accepted = await self.driver.agent._call_tool(context, tool, self.proposal())
        self.assertFalse(accepted.is_error)
        first = json.loads(accepted.content)
        self.transcript.append({"operation": "propose_action", "route": "FunctionAgent._call_tool",
                                "identity_source": "host_invocation_nonce", "host_invocation_nonce": "workflow-host-nonce",
                                "arguments": self.proposal(), "result": deepcopy(first)})
        replay = await self.driver.call("propose_action", self.proposal(), "workflow-host-nonce")
        self.assertEqual(first["id"], replay["id"])
        self.assertEqual(self.receipts, [])


if __name__ == "__main__":
    unittest.main()
