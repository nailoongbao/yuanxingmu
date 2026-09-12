"""Real Node Mastra tools -> Unix Broker; no generated model loop or isolation claim."""
import asyncio
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import queue
import subprocess
import threading
import unittest

from test_additional_sdk_adapters import AdditionalCases
from test_native_sdk_adapters import NativeAdapterCases, NativeRejected


OBSERVATIONS = []
DRIVERS = []


class MastraDriver:
    mode = "agent"

    def __init__(self, client, transcript):
        self.client, self.transcript = client, transcript
        self.identity_source = "agent_tool_call_id" if self.mode == "agent" else "host_invocation_nonce"
        self.lock, self.next_id, self.pending = threading.Lock(), 1, {}
        self.attempts, self.connections, self.model_attempts = [], [], []
        self.closed = False
        ready = queue.Queue()
        self.pending[0] = ready
        self.process = subprocess.Popen([os.environ["YXM_MASTRA_NODE"], str(Path(__file__).with_name("mastra_native_driver.mjs")),
            os.environ["YXM_MASTRA_ADAPTER"], client.socket_path, client.session_id],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        self.reader = threading.Thread(target=self.read_results, daemon=True)
        self.reader.start()
        try:
            result = ready.get(timeout=30)
            if not result.get("ready"):
                raise RuntimeError("Native Mastra registration failed: " + str(result))
            self.schemas, self.native_tools = result["schemas"], result["native_tools"]
            self.registration = result["native_registration"]
        except Exception:
            self.process.kill()
            self.process.wait(5)
            self.reader.join(5)
            error = self.process.stderr.read()
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                stream.close()
            raise RuntimeError("Native Mastra startup failed: " + error)
        DRIVERS.append(self)

    def read_results(self):
        try:
            for line in self.process.stdout:
                result = json.loads(line)
                with self.lock:
                    target = self.pending.pop(result["id"], None)
                if target is not None:
                    target.put(result)
        finally:
            with self.lock:
                waiting = list(self.pending.values())
                self.pending.clear()
            for target in waiting:
                target.put({"error": {"message": "native_driver_closed"}})

    def rpc(self, **request):
        waiting = queue.Queue()
        with self.lock:
            request_id = self.next_id
            self.next_id += 1
            self.pending[request_id] = waiting
            self.process.stdin.write(json.dumps({"id": request_id, **request}) + "\n")
            self.process.stdin.flush()
        result = waiting.get(timeout=25)
        self.attempts.extend(result.get("attempts", []))
        self.model_attempts.extend(result.get("model_attempts", []))
        self.connections = result.get("connections", self.connections)
        if "error" in result:
            raise NativeRejected(result["error"]["message"])
        return result["result"]

    async def call(self, operation, arguments, call_id="native-call-1", **options):
        entry = {"operation": operation, "identity_source": self.identity_source,
                 self.identity_source: call_id, "context_supplied_by_fixture": True,
                 "arguments": deepcopy(arguments), **options}
        self.transcript.append(entry)
        try:
            result = await asyncio.to_thread(self.rpc, command="call", mode=self.mode, operation=operation,
                                            arguments=arguments, call_id=call_id, **options)
        except Exception as exc:
            entry["rejected_by_adapter_or_sdk"] = type(exc).__name__
            raise
        entry["result"] = deepcopy(result)
        return result

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self.rpc(command="shutdown")
            self.process.stdin.close()
            self.process.wait(5)
        finally:
            if self.process.poll() is None:
                self.process.kill()
                self.process.wait(5)
            self.reader.join(5)
            self.process.stdout.close()
            self.stderr = self.process.stderr.read()
            self.process.stderr.close()


class WorkflowDriver(MastraDriver):
    mode = "workflow"


class MastraCases(AdditionalCases):
    modules = ()

    def setUp(self):
        if not all(os.environ.get(key) and Path(os.environ[key]).is_file()
                   for key in ("YXM_MASTRA_NODE", "YXM_MASTRA_ADAPTER")):
            self.skipTest("Use run_mastra_native_adapter.py with an independent Node SDK environment")
        self.driver_start = len(DRIVERS)
        self.addCleanup(self.close_drivers)
        super().setUp()

    def close_drivers(self):
        for driver in DRIVERS[self.driver_start:]:
            driver.close()

    def tearDown(self):
        if not hasattr(self, "driver"):
            return
        self.close_drivers()
        drivers = DRIVERS[self.driver_start:]
        attempts = [item for driver in drivers for item in driver.attempts]
        model_attempts = [item for driver in drivers for item in driver.model_attempts]
        OBSERVATIONS.append({"framework": "mastra", "mode": self.driver.mode, "test": self._testMethodName,
            "native_tools": self.driver.native_tools, "native_registration": self.driver.registration,
            "schema_sha256": hashlib.sha256(json.dumps(self.driver.schemas, sort_keys=True).encode()).hexdigest(),
            "calls": self.transcript, "receipts": self.receipts, "broker_events": self.events(),
            "node_connections": [item for driver in drivers for item in driver.connections],
            "python_connections": self.connections, "contexts_supplied_by_fixture": True,
            "node_network_attempts": attempts, "model_attempts": model_attempts,
            "python_network_attempts": self.prohibited_network_attempts})
        self.assertEqual(attempts, [])
        self.assertEqual(model_attempts, [])
        self.assertEqual(self.prohibited_network_attempts, [])
        for driver in drivers:
            self.assertEqual(driver.process.returncode, 0, driver.stderr)

    async def test_resume_input_is_revalidated_before_broker(self):
        await self.driver.call("propose_action", self.proposal(), "valid-resumed", resume=True)
        malformed = self.proposal()
        malformed["proposal"]["payload"]["approved"] = True
        before = len(self.events())
        with self.assertRaises(NativeRejected):
            await self.driver.call("propose_action", malformed, "bad-resumed", resume=True)
        self.assertEqual(len(self.events()), before)
        self.assertEqual(self.receipts, [])

    async def test_already_aborted_call_never_reaches_broker(self):
        before = len(self.events())
        with self.assertRaisesRegex(NativeRejected, "already_aborted"):
            await self.driver.call("send", {"destination": "public", "body": "never sent"}, aborted=True)
        self.assertEqual(len(self.events()), before)
        self.assertEqual(self.receipts, [])


class MastraAgentContextTests(MastraCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class = "mastra", MastraDriver

    async def test_agent_execution_tool_wrapper_forwards_call_id(self):
        first = await asyncio.to_thread(self.driver.rpc, command="native_agent_dispatch", operation="propose_action",
                                         arguments=self.proposal(), call_id="native-wrapper-call")
        self.transcript.append({"operation": "propose_action", "route": "Agent.getToolsForExecution Tool.execute",
                                "agent_tool_call_id": "native-wrapper-call", "context_supplied_by_fixture": True,
                                "arguments": self.proposal(), "result": first})
        replay = await self.driver.call("propose_action", self.proposal(), "native-wrapper-call")
        self.assertEqual(first["id"], replay["id"])
        self.assertEqual(self.receipts, [])

    async def test_unicode_identity_has_stable_documented_key(self):
        value = "\u8c03\u7528\U0001f600\u007f"
        actual = await asyncio.to_thread(self.driver.rpc, command="request_key", operation="propose_action",
                                         identity={"source": "agent_tool_call_id", "value": value})
        binding = ["yuanxingmu-mastra-v1", self.client.session_id, "propose_action", "agent_tool_call_id", value]
        expected = "mastra_v1_" + hashlib.sha256(json.dumps(binding, ensure_ascii=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(actual, expected)
        self.assertEqual(self.events(), [])

    async def test_native_and_host_identities_with_same_text_are_separate(self):
        native = await self.driver.call("propose_action", self.proposal(), "same-id-text")
        host = WorkflowDriver(self.client, self.transcript)
        hosted = await host.call("propose_action", self.proposal(), "same-id-text")
        self.assertNotEqual(native["id"], hosted["id"])
        self.assertEqual(self.receipts, [])


class MastraWorkflowHostNonceTests(MastraCases, unittest.IsolatedAsyncioTestCase):
    framework, driver_class = "mastra", WorkflowDriver
    test_native_call_ids_deduplicate_after_rebuilding_adapter = None
    test_missing_native_call_id_cannot_submit_proposals = None
    test_email_drafts_never_send_and_reuse_native_identity = None

    async def test_host_nonces_deduplicate_after_rebuilding_adapter(self):
        await NativeAdapterCases.test_native_call_ids_deduplicate_after_rebuilding_adapter(self)

    async def test_workflow_run_id_cannot_replace_missing_host_nonce(self):
        await NativeAdapterCases.test_missing_native_call_id_cannot_submit_proposals(self)

    async def test_email_drafts_never_send_and_reuse_host_nonce(self):
        await NativeAdapterCases.test_email_drafts_never_send_and_reuse_native_identity(self)

    async def test_async_host_scope_restores_after_exception(self):
        rows = await asyncio.to_thread(self.driver.rpc, command="scope_check")
        self.assertEqual(rows, ["inner", "outer", None])
        await self.rejected_before_broker("propose_action", self.proposal(), None)


if __name__ == "__main__":
    unittest.main()
