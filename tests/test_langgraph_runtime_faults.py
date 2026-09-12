"""Native graph recovery across tool and checkpoint faults, using local RPC."""
from copy import deepcopy
from functools import wraps
import inspect
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import yuanxingmu.client as transport
import test_langgraph_runtime as fixtures


@fixtures.REQUIRES_SDK
class LanggraphRuntimeFaultTests(fixtures.LanggraphFixture, unittest.TestCase):
    enable_automation = True

    def interrupt_before_dispatch(self, response):
        from langgraph.prebuilt import ToolNode
        self.responses.extend([response, fixtures.final_response()])
        with patch.object(ToolNode, "_func", side_effect=RuntimeError("simulated_worker_loss_before_dispatch")):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.upstream_requests), 1)
        checkpoint = Path(self.config["checkpoint"])
        self.assertIn(response["choices"][0]["message"]["tool_calls"][0]["id"], checkpoint.read_text())
        return checkpoint

    def test_unfinished_graph_resumes_with_none_and_rechecks_original_request(self):
        from langgraph.pregel import Pregel
        response = fixtures.completion(fixtures.tool_call(
            "host-before-dispatch", "yuanxingmu_propose_action", self.proposal()))
        self.interrupt_before_dispatch(response)
        original_invoke, inputs = Pregel.invoke, []

        @wraps(original_invoke)
        def observed_invoke(graph, value, *args, **kwargs):
            inputs.append(value)
            return original_invoke(graph, value, *args, **kwargs)

        before = len(self.requests)
        with patch.object(Pregel, "invoke", observed_invoke):
            result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertTrue(inputs)
        self.assertIsNone(inputs[0])
        self.assertEqual(self.requests[0]["raw"], self.requests[before]["raw"])
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.actions()[0]["status"], "pending")
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.upstream_requests), 2)

    def test_crash_after_broker_acceptance_replays_nonce_without_duplicate_effect(self):
        from langgraph.prebuilt import ToolNode
        response = fixtures.completion(
            fixtures.tool_call("host-accepted-first", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-accepted-second", "yuanxingmu_request_action", self.proposal("second")))
        self.responses.extend([response, fixtures.final_response()])
        original, interrupted = ToolNode._func, []

        @wraps(original)
        def crash_after_tool(node, *args, **kwargs):
            result = original(node, *args, **kwargs)
            if not interrupted:
                interrupted.append(True)
                raise RuntimeError("simulated_worker_loss_after_broker_acceptance")
            return result

        with patch.object(ToolNode, "_func", crash_after_tool):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(interrupted, [True])
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 1)
        first_id = self.actions()[0]["id"]
        self.assertEqual(self.actions()[0]["status"], "acknowledged")
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.receipts), 2)
        self.assertIn("first", self.receipts[0]["body"])
        self.assertIn("second", self.receipts[1]["body"])
        self.assertEqual(len(self.actions()), 2)
        self.assertIn(first_id, {row["id"] for row in self.actions()})
        self.assertEqual(len(self.judge.requests), 2)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 2)

    def test_checkpointed_first_call_is_not_dispatched_when_second_call_resumes(self):
        from langgraph.prebuilt import ToolNode
        response = fixtures.completion(
            fixtures.tool_call("host-partial-first", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-partial-second", "yuanxingmu_request_action", self.proposal("second")))
        self.responses.extend([response, fixtures.final_response()])
        original = ToolNode._func

        @wraps(original)
        def stop_second(node, input, config, runtime):
            calls, _ = node._parse_input(input)
            if calls[0]["id"] == "host-partial-second":
                raise RuntimeError("simulated_worker_loss_before_second_call")
            return original(node, input, config, runtime)

        with patch.object(ToolNode, "_func", stop_second):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(len(self.receipts), 1)
        dispatched = []

        @wraps(original)
        def track(node, input, config, runtime):
            calls, _ = node._parse_input(input)
            dispatched.extend(call["id"] for call in calls)
            return original(node, input, config, runtime)

        with patch.object(ToolNode, "_func", track):
            result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(dispatched, ["host-partial-second"])
        self.assertEqual(len(self.receipts), 2)
        self.assertEqual(len(self.actions()), 2)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 2)

    def test_changed_host_response_blocks_recovery_and_retains_original_pending_response(self):
        response = fixtures.completion(fixtures.tool_call(
            "host-original-pending", "yuanxingmu_request_action", self.proposal()))
        checkpoint = self.interrupt_before_dispatch(response)
        changed = fixtures.completion(fixtures.tool_call(
            "host-changed-pending", "yuanxingmu_request_action", self.proposal("changed")))
        self.bridge_hook = lambda _row: changed
        with self.assertRaisesRegex(RuntimeError, "response_changed"):
            self.runtime.run_session({**self.config, "resume": True})
        saved = json.dumps(json.loads(checkpoint.read_bytes()))
        self.assertIn("host-original-pending", saved)
        self.assertNotIn("host-changed-pending", saved)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.upstream_requests), 1)
        self.assertEqual(len(self.responses), 1)

    def test_host_recheck_failure_prevents_tool_dispatch_then_allows_safe_resume(self):
        response = fixtures.completion(fixtures.tool_call(
            "host-recheck-rejected", "yuanxingmu_request_action", self.proposal()))
        self.responses.extend([response, fixtures.final_response()])

        def deny_recheck(row):
            if row["raw"] in self.journal:
                return (403, {"error": {"message": "host request no longer authorized"}})
            return None

        self.bridge_hook = deny_recheck
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.judge.requests, [])
        self.bridge_hook = None
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_extended_rpc_deadline_waits_for_real_judge_for_all_tool_paths(self):
        # Preserve the public/runtime 15:120 ratio with shorter real socket waits.
        self.judge.delay = .35
        real_request = transport.request
        public_default = inspect.signature(real_request).parameters["timeout_seconds"].default
        self.assertEqual(public_default, 15)
        self.assertEqual(self.runtime.SDK_RPC_TIMEOUT_SECONDS, 120)
        rpc_calls = []

        def scaled_request(operation, **fields):
            budget = fields.pop("timeout_seconds", public_default)
            rpc_calls.append((operation, budget))
            return real_request(operation, timeout_seconds=budget / 100, **fields)

        with patch.object(self.runtime, "request", scaled_request):
            result = self.run_calls(
                fixtures.tool_call("host-slow-read", "yuanxingmu_read", {"resource": "note"}),
                fixtures.tool_call("host-slow-proposal", "yuanxingmu_propose_action", self.proposal("review")),
                fixtures.tool_call("host-slow-automatic", "yuanxingmu_request_action", self.proposal("automatic")))
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(rpc_calls, [("read", 120), ("propose_action", 120), ("request_action", 120)])
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 2)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_native_tool_rpc_error_stops_without_model_retry_or_later_call(self):
        self.responses.extend([fixtures.completion(
            fixtures.tool_call("host-rpc-error", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-rpc-later", "yuanxingmu_request_action", self.proposal("later"))),
            fixtures.final_response()])
        with patch.object(self.runtime, "request", side_effect=OSError("synthetic_transport_failure")) as invoke:
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(len(self.upstream_requests), 1)
        self.assertEqual(len(self.responses), 1)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.judge.requests, [])

    def test_forged_native_pending_writes_cannot_dispatch_a_changed_host_response(self):
        response = fixtures.completion(fixtures.tool_call(
            "host-original-write", "yuanxingmu_request_action", self.proposal()))
        checkpoint = self.interrupt_before_dispatch(response)
        saved = json.loads(checkpoint.read_bytes())
        row = next(row for row in saved["records"] if row["checkpoint"]["id"] == saved["latest"])
        failed_task = next(write for write in row["writes"] if write["channel"] == "__error__")
        pending = deepcopy(row["checkpoint"]["channel_values"]["pending"])
        pending["response"] = fixtures.completion(fixtures.tool_call(
            "host-forged-write", "yuanxingmu_request_action", self.proposal("MUST-NOT-SEND")))
        # These writes use the real failed native task identity. LangGraph may
        # replay them as a completed node; the next tool still needs host data.
        row["writes"] = [
            {"task_id": failed_task["task_id"], "index": index, "channel": channel,
             "value": value, "task_path": failed_task["task_path"]}
            for index, (channel, value) in enumerate((("pending", pending), ("cursor", 0), ("branch:to:tools", None)))
        ]
        checkpoint.write_text(json.dumps(saved), encoding="utf-8")
        with self.assertRaises((ValueError, RuntimeError)):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.judge.requests, [])
        self.assertEqual(len(self.upstream_requests), 1)
        self.assertEqual(len(self.responses), 1)

    def test_old_uncertain_tool_messages_in_checkpoints_or_writes_block_reopening(self):
        nonce = "host-old-uncertain"
        self.run_calls(fixtures.tool_call(nonce, "yuanxingmu_request_action", self.proposal()))
        checkpoint = Path(self.config["checkpoint"])
        original = json.loads(checkpoint.read_bytes())
        count = len(self.requests)

        def change_outcome(messages, field, outcome):
            message = next(item for item in messages if item.get("tool_call_id") == nonce)
            result = json.loads(message["content"])
            self.assertEqual(result["status"], "acknowledged")
            result.pop("status", None)
            result.pop("outcome", None)
            result[field] = outcome
            message["content"] = json.dumps(result)

        for source in ("checkpoint", "pending_writes"):
            for field in ("status", "outcome"):
                for outcome in ("unconfirmed", "executing"):
                    with self.subTest(source=source, field=field, outcome=outcome):
                        saved = deepcopy(original)
                        if source == "checkpoint":
                            row = next(row for row in saved["records"] if row["checkpoint"]["id"] == saved["latest"])
                            messages = row["checkpoint"]["channel_values"]["messages"]
                        else:
                            write = next(write for row in saved["records"] for write in row["writes"]
                                         if write["channel"] == "messages"
                                         and any(item.get("tool_call_id") == nonce for item in write["value"]))
                            messages = write["value"]
                        change_outcome(messages, field, outcome)
                        raw = json.dumps(saved).encode("utf-8")
                        checkpoint.write_bytes(raw)
                        with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                            self.runtime.run_session({**self.config, "resume": True})
                        self.assertEqual(checkpoint.read_bytes(), raw)
                        self.assertEqual(len(self.requests), count)
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.actions()[0]["status"], "acknowledged")
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)


if __name__ == "__main__":
    unittest.main()
