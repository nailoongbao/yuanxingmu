"""Scaled socket deadlines against a real delayed judge and Unix Broker.

The 15:120 deadline ratio is preserved while the local judge waits 0.35 seconds.
Only the socket deadline is scaled; SDK dispatch, Broker policy, persistence and
automatic HTTP effects are real. There is no external model or network service.
"""
from contextlib import contextmanager
from copy import deepcopy
import inspect
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

import yuanxingmu.client as transport
import yuanxingmu.adapters.client as shared_client
import test_smolagents_runtime as fixtures
import test_smolagents_automatic_runtime as automatic_fixtures


@unittest.skipUnless(sys.platform.startswith("linux") and fixtures.HAS_SDK,
                     "Requires Linux and the pinned smolagents SDK environment")
class SmolagentsRuntimeTimeoutTests(unittest.TestCase):
    start_server = fixtures.SmolagentsRuntimeTests.start_server
    actions = fixtures.SmolagentsRuntimeTests.actions
    sdk_message = staticmethod(fixtures.SmolagentsRuntimeTests.sdk_message)
    sdk_step = staticmethod(fixtures.SmolagentsRuntimeTests.sdk_step)
    dispatch = fixtures.SmolagentsRuntimeTests.dispatch
    proposal = staticmethod(automatic_fixtures.SmolagentsAutomaticRuntimeTests.proposal)
    events = automatic_fixtures.SmolagentsAutomaticRuntimeTests.events
    agent = automatic_fixtures.SmolagentsAutomaticRuntimeTests.agent

    def setUp(self):
        automatic_fixtures.SmolagentsAutomaticRuntimeTests.setUp(self)
        self.judge.delay = .35
        self.rpc_calls = []

    @contextmanager
    def scaled_deadlines(self):
        real_request = transport.request
        public_default = inspect.signature(real_request).parameters["timeout_seconds"].default
        self.assertEqual(public_default, 15)
        self.assertEqual(self.runtime.SDK_RPC_TIMEOUT_SECONDS, 120)

        def scaled_request(operation, **fields):
            budget = fields.pop("timeout_seconds", public_default)
            self.rpc_calls.append({"operation": operation, "budget": budget, "fields": deepcopy(fields)})
            return real_request(operation, timeout_seconds=budget / 100, **fields)

        with patch.object(shared_client, "request", scaled_request), patch.object(self.runtime, "request", scaled_request):
            yield

    def test_runtime_read_waits_for_judge_after_public_default_times_out(self):
        response = fixtures.completion(fixtures.tool_call("host-slow-read", "yuanxingmu_read", {"resource": "note"}))
        self.responses.extend([response, fixtures.final_response()])
        with self.scaled_deadlines():
            with self.assertRaises(TimeoutError):
                self.client.invoke("read", {"resource": "note"}, framework="smolagents")
            result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertIn("LOCAL-REGISTERED-RESOURCE", json.dumps(self.requests[-1]["body"]["messages"]))
        self.assertEqual([(row["operation"], row["budget"]) for row in self.rpc_calls], [("read", 15), ("read", 120)])
        self.assertEqual(len(self.judge.requests), 2)
        self.assertEqual(self.receipts, [])

    def test_runtime_proposal_keeps_public_request_key_after_a_short_budget_timeout(self):
        nonce = "host-slow-proposal"
        expected_key = self.client.request_key("propose_action", "smolagents", nonce)
        self.responses.extend([fixtures.completion(fixtures.tool_call(nonce, "yuanxingmu_propose_action", self.proposal())),
                               fixtures.final_response()])
        with self.scaled_deadlines():
            with self.assertRaises(TimeoutError):
                self.client.invoke("propose_action", self.proposal(), framework="smolagents", tool_call_id=nonce)
            result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["status"], "completed")
        self.assertEqual([(row["operation"], row["budget"]) for row in self.rpc_calls],
                         [("propose_action", 15), ("propose_action", 120)])
        self.assertEqual([row["fields"]["request_key"] for row in self.rpc_calls], [expected_key, expected_key])
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.actions()[0]["status"], "pending")
        self.assertEqual(self.receipts, [])

    def test_automatic_action_recovers_from_old_budget_without_repeating_delivery(self):
        response = fixtures.completion(fixtures.tool_call("host-slow-automatic", "yuanxingmu_request_action", self.proposal()))
        self.responses.append(response)
        with self.scaled_deadlines():
            # Reproduce the former runtime budget without waiting 15 seconds.
            with patch.object(self.runtime, "SDK_RPC_TIMEOUT_SECONDS", 15):
                with self.assertRaises(RuntimeError):
                    self.runtime.run_session(deepcopy(self.config))
            checkpoint = json.loads(Path(self.config["checkpoint"]).read_bytes())
            self.assertEqual(checkpoint["completed_tools"], {})
            self.assertIsNotNone(checkpoint["pending"]["response"])
            self.responses.extend([response, fixtures.final_response()])
            result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual([(row["operation"], row["budget"]) for row in self.rpc_calls],
                         [("request_action", 15), ("request_action", 120)])
        self.assertEqual(self.rpc_calls[0]["fields"]["request_key"], self.rpc_calls[1]["fields"]["request_key"])
        self.assertEqual(self.requests[0]["raw"], self.requests[1]["raw"])
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.actions()[0]["status"], "acknowledged")
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(self.receipts[0]["path"], "/message")
        self.assertEqual(len(self.judge.requests), 1)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_model_arguments_cannot_override_deadline_socket_or_request_identity(self):
        from smolagents.utils import AgentError
        with self.scaled_deadlines():
            for name, original in (("yuanxingmu_read", {"resource": "note"}),
                                   ("yuanxingmu_propose_action", self.proposal()),
                                   ("yuanxingmu_request_action", self.proposal())):
                for field, value in (("timeout_seconds", 120), ("socket_path", str(self.root / "forged.sock")),
                                     ("request_key", "model-selected")):
                    with self.subTest(tool=name, field=field):
                        arguments = {**deepcopy(original), field: value}
                        call = fixtures.tool_call("host-invalid-" + field, name, arguments)
                        with self.assertRaises((ValueError, RuntimeError, AgentError)):
                            self.dispatch(self.agent(), call)
        self.assertEqual(self.rpc_calls, [])
        self.assertEqual(self.events(), b"")
        self.assertEqual(self.judge.requests, [])
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])


if __name__ == "__main__":
    unittest.main()
