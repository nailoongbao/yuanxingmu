"""Actual Google ADK, CrewAI and Agno tool objects + Broker + local effects.

No model runner or inference is executed. CrewAI uses an explicitly labelled
host nonce per dispatch because its tested tool API has no call-ID injection.
"""
import asyncio
from copy import deepcopy
import importlib.util
import json
import logging
import os
import socket
import unittest
from unittest.mock import patch

from yuanxingmu.adapters.client import TOOL_NAMES
from test_native_sdk_adapters import NativeAdapterCases, NativeRejected, OBSERVATIONS


class AdditionalDriver:
    identity_source = "native_tool_call_id"

    def __init__(self, client, transcript):
        self.client, self.transcript = client, transcript

    async def call(self, operation, arguments, call_id="sdk-call-1"):
        entry = {"operation": operation, "identity_source": self.identity_source,
                 self.identity_source: call_id, "arguments": deepcopy(arguments)}
        self.transcript.append(entry)
        try:
            result = json.loads(await self.invoke(operation, deepcopy(arguments), call_id))
        except Exception as exc:
            entry["rejected_by_adapter_or_sdk"] = type(exc).__name__
            raise
        entry["result"] = deepcopy(result)
        return result


class GoogleADKDriver(AdditionalDriver):
    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from google.adk.agents import LlmAgent
        from google.adk.agents.invocation_context import InvocationContext
        from google.adk.sessions import InMemorySessionService, Session
        from google.adk.tools.base_tool import BaseTool
        from yuanxingmu.adapters.google_adk import build_tools
        self.tools = build_tools(client)
        assert all(isinstance(tool, BaseTool) for tool in self.tools)
        self.agent = LlmAgent(name="native_tool_registration_only", model="not-run", tools=self.tools)
        self.by_name = {tool.name: tool for tool in self.agent.tools}
        self.schemas = {tool.name: tool._get_declaration().parameters_json_schema for tool in self.tools}
        self.context = InvocationContext(invocation_id="host-run-not-a-call-id", agent=self.agent,
            session_service=InMemorySessionService(),
            session=Session(id="fixture-session", app_name="fixture-app", user_id="fixture-user"))

    async def invoke(self, operation, arguments, call_id):
        from google.adk.tools.tool_context import ToolContext
        context = ToolContext(self.context, function_call_id=call_id)
        return await self.by_name[TOOL_NAMES[operation]].run_async(args=arguments, tool_context=context)


class CrewAIDriver(AdditionalDriver):
    identity_source = "host_invocation_nonce"

    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from crewai import Agent
        from crewai.llms.base_llm import BaseLLM
        from crewai.tools import BaseTool
        from crewai.tools.structured_tool import CrewStructuredTool
        from yuanxingmu.adapters.crewai import HostInvocations, build_tools

        class NeverRunLLM(BaseLLM):
            def call(self, *args, **kwargs):
                raise AssertionError("Registration-only LLM must never be invoked")

        self.identities = HostInvocations()
        self.tools = build_tools(client, invocations=self.identities)
        assert all(isinstance(tool, BaseTool) for tool in self.tools)
        self.agent = Agent(role="native-tool-registration-only", goal="register tools without running a model",
                           backstory="Local test fixture", llm=NeverRunLLM(model="never-run"),
                           tools=self.tools, cache=False, verbose=False, allow_delegation=False)
        self.by_name = {tool.name: tool.to_structured_tool() for tool in self.agent.tools}
        assert all(isinstance(tool, CrewStructuredTool) for tool in self.by_name.values())
        self.schemas = {name: tool.args_schema.model_json_schema() for name, tool in self.by_name.items()}

    async def invoke(self, operation, arguments, call_id):
        tool = self.by_name[TOOL_NAMES[operation]]
        if call_id is None:
            return await tool.ainvoke(arguments)
        with self.identities.bind(call_id):
            return await tool.ainvoke(arguments)


class AgnoDriver(AdditionalDriver):
    def __init__(self, client, transcript):
        super().__init__(client, transcript)
        from agno.agent import Agent
        from agno.tools.function import Function
        from yuanxingmu.adapters.agno import build_tools
        self.tools = build_tools(client)
        assert all(isinstance(tool, Function) for tool in self.tools)
        self.agent = Agent(name="native-tool-registration-only", tools=self.tools, telemetry=False)
        self.by_name = {tool.name: tool for tool in self.agent.tools}
        self.schemas = {tool.name: tool.to_dict()["parameters"] for tool in self.tools}

    async def invoke(self, operation, arguments, call_id):
        from agno.tools.function import FunctionCall
        call = FunctionCall(function=self.by_name[TOOL_NAMES[operation]], arguments=arguments, call_id=call_id)
        result = await call.aexecute()
        if result.status != "success":
            raise NativeRejected("native_function_rejected")
        return result.result


class AdditionalCases(NativeAdapterCases):
    def setUp(self):
        if any(importlib.util.find_spec(module) is None for module in self.modules):
            self.skipTest("Install docs/additional-native-adapters-requirements.txt for these SDK checks")
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"CREWAI_TELEMETRY_DISABLED": "true", "OTEL_SDK_DISABLED": "true",
                                "AGNO_TELEMETRY": "false", "ANONYMIZED_TELEMETRY": "false"}).start()
        self.prohibited_network_attempts = []
        original_getaddrinfo = socket.getaddrinfo
        original_connect = socket.socket.connect

        def guarded_connect(connection, address):
            if connection.family == socket.AF_UNIX and address == str(getattr(self, "endpoint", "")):
                return original_connect(connection, address)
            if connection.family == socket.AF_INET and hasattr(self, "receiver") and address == ("127.0.0.1", self.receiver.server_port):
                return original_connect(connection, address)
            self.prohibited_network_attempts.append("connect")
            raise AssertionError("SDK tool tests prohibit model or external connections")

        def guarded_resolve(host, *args, **kwargs):
            if host != "127.0.0.1":
                self.prohibited_network_attempts.append("getaddrinfo")
                raise AssertionError("SDK tool tests prohibit external DNS resolution")
            return original_getaddrinfo(host, *args, **kwargs)

        def guarded_connect_ex(connection, address):
            # None of the exercised native tools needs connect_ex; reject it
            # so an SDK cannot use it to bypass the shared connect guard.
            self.prohibited_network_attempts.append("connect_ex")
            raise AssertionError("SDK tool tests prohibit connect_ex")

        patch.object(socket.socket, "connect", guarded_connect).start()
        patch.object(socket, "getaddrinfo", guarded_resolve).start()
        patch.object(socket.socket, "connect_ex", guarded_connect_ex).start()
        # Negative argument checks would otherwise print their contents to the
        # SDK logger. They remain recorded in the explicit synthetic transcript.
        patch.object(logging.Logger, "isEnabledFor", lambda *_args: False).start()
        super().setUp()

    def tearDown(self):
        super().tearDown()
        if hasattr(self, "driver"):
            OBSERVATIONS[-1]["identity_source"] = self.driver.identity_source
            OBSERVATIONS[-1]["native_registration"] = type(self.driver.agent).__module__ + "." + type(self.driver.agent).__name__
            OBSERVATIONS[-1]["prohibited_network_attempts"] = self.prohibited_network_attempts
            self.assertEqual(self.prohibited_network_attempts, [], "An SDK attempted a prohibited network operation")

    async def test_parallel_proposals_keep_separate_call_identities(self):
        rows = await asyncio.gather(*(self.driver.call("propose_action", self.proposal(), f"parallel-{i}") for i in range(4)))
        self.assertEqual(len({row["id"] for row in rows}), 4)
        for index, row in enumerate(rows):
            replay = await self.driver.call("propose_action", self.proposal(), f"parallel-{index}")
            self.assertEqual(replay["id"], row["id"])
        self.assertEqual(self.receipts, [])


class GoogleADKNativeTests(AdditionalCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "google_adk", GoogleADKDriver, ("google", "google.adk")

    async def test_model_cannot_supply_native_tool_context(self):
        arguments = self.proposal()
        arguments["tool_context"] = {"function_call_id": "forged"}
        await self.rejected_before_broker("propose_action", arguments)


class CrewAINativeTests(AdditionalCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "crewai", CrewAIDriver, ("crewai",)
    test_native_call_ids_deduplicate_after_rebuilding_adapter = None
    test_missing_native_call_id_cannot_submit_proposals = None

    async def test_host_nonces_deduplicate_after_rebuilding_adapter(self):
        await NativeAdapterCases.test_native_call_ids_deduplicate_after_rebuilding_adapter(self)

    async def test_missing_host_nonce_cannot_submit_proposals(self):
        await NativeAdapterCases.test_missing_native_call_id_cannot_submit_proposals(self)

    async def test_nonce_scope_exits_and_model_nonce_is_rejected(self):
        with self.driver.identities.bind("outer"):
            with self.assertRaisesRegex(RuntimeError, "fixture"):
                with self.driver.identities.bind("inner"):
                    self.assertEqual(self.driver.identities.current(), "inner")
                    raise RuntimeError("fixture")
            self.assertEqual(self.driver.identities.current(), "outer")
        self.assertIsNone(self.driver.identities.current())
        arguments = self.proposal()
        arguments["invocation_nonce"] = "forged"
        await self.rejected_before_broker("propose_action", arguments)
        await self.rejected_before_broker("propose_action", self.proposal(), None)

    async def test_sync_structured_tool_and_base_tool_preserve_host_nonce(self):
        def sync_call(tool, nonce, structured):
            with self.driver.identities.bind(nonce):
                return json.loads(tool.invoke(self.proposal()) if structured else tool.run(**self.proposal()))
        native = self.driver.by_name[TOOL_NAMES["propose_action"]]
        first = await asyncio.to_thread(sync_call, native, "sync-host-nonce", True)
        original = next(tool for tool in self.driver.tools if tool.name == native.name)
        replay = await asyncio.to_thread(sync_call, original, "sync-host-nonce", False)
        self.assertEqual(first["id"], replay["id"])
        with self.driver.identities.bind("sync-host-nonce"):
            async_replay = json.loads(await original.arun(**self.proposal()))
        self.assertEqual(first["id"], async_replay["id"])
        self.assertEqual(self.receipts, [])


class AgnoNativeTests(AdditionalCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class, modules = "agno", AgnoDriver, ("agno",)

    async def test_model_fc_cannot_override_native_function_call(self):
        arguments = self.proposal()
        arguments["fc"] = {"call_id": "forged-call-id"}
        first = await self.driver.call("propose_action", arguments, "actual-call-id")
        replay = await self.driver.call("propose_action", self.proposal(), "actual-call-id")
        self.assertEqual(first["id"], replay["id"])
        other = await self.driver.call("propose_action", self.proposal(), "forged-call-id")
        self.assertNotEqual(first["id"], other["id"])

    async def test_sync_function_execute_uses_the_same_native_identity(self):
        from agno.tools.function import FunctionCall
        from yuanxingmu.adapters.agno import build_tools
        tool = next(tool for tool in build_tools(self.client, asynchronous=False) if tool.name == TOOL_NAMES["propose_action"])
        call = FunctionCall(function=tool, arguments=self.proposal(), call_id="sync-native-id")
        execution = await asyncio.to_thread(call.execute)
        self.assertEqual(execution.status, "success")
        replay = await self.driver.call("propose_action", self.proposal(), "sync-native-id")
        self.assertEqual(json.loads(execution.result)["id"], replay["id"])
        self.assertEqual(self.receipts, [])


if __name__ == "__main__":
    unittest.main()
