"""Real ADK transfer and serial automatic effects through the actual Broker."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from test_google_adk_runtime import COMPLETE, GoogleAdkFixture, REQUIRES_SDK, completion, final_response, tool_call


@REQUIRES_SDK
class GoogleAdkAutomaticTests(GoogleAdkFixture, unittest.TestCase):
    enable_automation = True

    def test_message_upload_form_execute_in_order(self):
        calls = [tool_call("message", "yuanxingmu_request_action", self.proposal()),
                 tool_call("upload", "yuanxingmu_request_action", {"proposal": {"kind": "upload", "target_id": "upload", "payload": {"filename": "report.txt", "content": "PUBLIC REPORT"}}}),
                 tool_call("form", "yuanxingmu_request_action", {"proposal": {"kind": "form", "target_id": "form", "payload": {"fields": [{"name": "note", "value": "PUBLIC FORM"}]}}})]
        result = self.run_executor(*calls)
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual([receipt["path"] for receipt in self.receipts], ["/message", "/upload", "/form"])
        self.assertEqual(len(self.actions()), 3)
        for row in self.actions():
            self.assertEqual(row["status"], "acknowledged")
            self.assertEqual(row["execution_mode"], "automatic")
            self.assertEqual(row["authorization_source"], "frozen_task_scope")
            self.assertIsNone(row["approved_at"])

    def test_scope_denial_reaches_model_without_a_receipt(self):
        result = self.run_executor(tool_call("outside", "yuanxingmu_request_action", self.proposal(target="outside")))
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(self.receipts, [])
        self.assertIn("automatic_target_not_granted", json.dumps(self.upstream_requests[-1]["body"]["messages"]))

    def test_new_turn_keeps_existing_automatic_budget(self):
        self.run_executor(*(tool_call(f"call-{i}", "yuanxingmu_request_action", self.proposal(str(i))) for i in range(3)))
        self.responses.extend([completion(self.transfer("second-transfer")), completion(tool_call("fourth", "yuanxingmu_request_action", self.proposal("fourth"))), final_response()])
        self.runtime.run_session({**self.config, "resume": True, "prompt": "Send one more progress update."})
        self.assertEqual(len(self.receipts), 3)
        self.assertIn("automatic_attempt_budget_exhausted", json.dumps(self.upstream_requests[-1]["body"]["messages"]))
        self.assertNotIn("transfer_to_agent", {item["function"]["name"] for item in self.upstream_requests[-1]["body"]["tools"]})

    def test_lost_receiver_receipt_stops_following_batch_tools(self):
        self.drop_receipts = True
        self.responses.extend([completion(self.transfer()), completion(
            tool_call("one", "yuanxingmu_request_action", self.proposal("first")),
            tool_call("two", "yuanxingmu_request_action", self.proposal("must not execute"))), final_response()])
        with self.assertRaisesRegex(RuntimeError, "sdk_action_unconfirmed"):
            self.runtime.run_session(self.config)
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.upstream_requests), 2)
        with self.assertRaisesRegex(RuntimeError, "sdk_action_unconfirmed"):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(len(self.receipts), 1)

    def test_bad_second_argument_blocks_good_first_action(self):
        self.responses.extend([completion(self.transfer()), completion(
            tool_call("one", "yuanxingmu_request_action", self.proposal()),
            tool_call("two", "yuanxingmu_request_action", {"proposal": {"kind": "delete", "target_id": "remove"}}))])
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])

    def test_partial_batch_host_reply_loss_recovers_original_result_without_repeat(self):
        original = self.runtime.request
        dropped = False

        def request(operation, *args, **kwargs):
            nonlocal dropped
            result = original(operation, *args, **kwargs)
            if operation == "request_action" and not dropped:
                dropped = True
                raise OSError("fixture_lost_host_reply")
            return result

        self.responses.extend([completion(self.transfer()), completion(
            tool_call("one", "yuanxingmu_request_action", self.proposal("first")),
            tool_call("two", "yuanxingmu_request_action", self.proposal("second"))), final_response()])
        with patch.object(self.runtime, "request", request), self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        first = self.saved()
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(first["records"][1]["results"], {})
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(len(self.receipts), 2)
        self.assertEqual(len(self.upstream_requests), 3)
        self.assertEqual(self.saved()["attempts"][0], first["native"])

    def test_cached_original_tool_result_survives_partial_batch(self):
        original = self.runtime.request
        failed = False

        def request(operation, *args, **kwargs):
            nonlocal failed
            if operation == "request_action" and kwargs["proposal"]["payload"]["body"] == "second" and not failed:
                failed = True
                raise OSError("fixture_interrupted_second_call")
            return original(operation, *args, **kwargs)

        self.responses.extend([completion(self.transfer()), completion(
            tool_call("one", "yuanxingmu_request_action", self.proposal("first")),
            tool_call("two", "yuanxingmu_request_action", self.proposal("second"))), final_response()])
        with patch.object(self.runtime, "request", request), self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        cached = self.saved()["records"][1]["results"]["one"]
        self.assertEqual(len(self.receipts), 1)
        self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(len(self.receipts), 2)
        self.assertEqual(self.saved()["records"][1]["results"]["one"], cached)
        tools = [row for row in self.upstream_requests[-1]["body"]["messages"] if row["role"] == "tool"]
        self.assertEqual(tools[0]["content"], cached)

    def test_native_dispatch_is_serial_even_when_sdk_schedules_reverse_order(self):
        import asyncio
        from google.adk.flows.llm_flows import _batch_tool_executor
        original = _batch_tool_executor._start_execute_task
        original_request = self.runtime.request
        entered, running = [], 0

        def request(operation, *args, **kwargs):
            nonlocal running
            if operation != "request_action":
                return original_request(operation, *args, **kwargs)
            running += 1
            self.assertEqual(running, 1)
            entered.append(kwargs["proposal"]["payload"]["body"])
            try:
                return original_request(operation, *args, **kwargs)
            finally:
                running -= 1

        async def delayed(coro, name):
            if name == "one":
                await asyncio.sleep(0.01)
            return await coro

        def schedule(prepared, coro):
            return original(prepared, delayed(coro, prepared.function_call.id))

        with patch.object(self.runtime, "request", request), patch.object(_batch_tool_executor, "_start_execute_task", schedule):
            self.run_executor(tool_call("one", "yuanxingmu_request_action", self.proposal("first")),
                              tool_call("two", "yuanxingmu_request_action", self.proposal("second")))
        self.assertEqual(entered, ["first", "second"])

    def test_actual_revoke_after_first_effect_stops_later_and_replayed_effects(self):
        original = self.runtime.request
        revoked = False

        def request(operation, *args, **kwargs):
            nonlocal revoked
            result = original(operation, *args, **kwargs)
            if operation == "request_action" and not revoked:
                revoked = True
                self.broker.authority.revoke(self.task)
            return result

        self.responses.extend([completion(self.transfer()), completion(
            tool_call("one", "yuanxingmu_request_action", self.proposal("first")),
            tool_call("two", "yuanxingmu_request_action", self.proposal("second"))), final_response()])
        with patch.object(self.runtime, "request", request), self.assertRaisesRegex(RuntimeError, "sdk_host_stopped"):
            self.runtime.run_session(self.config)
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.upstream_requests), 2)
        with self.assertRaisesRegex(RuntimeError, "sdk_host_stopped"):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(len(self.receipts), 1)

    def test_changed_resource_on_replay_stops_before_pending_transfer_and_action(self):
        self.responses.extend([completion(tool_call("read", "yuanxingmu_read", {"resource": "note"})),
                               completion(self.transfer()), completion(tool_call("auto", "yuanxingmu_request_action", self.proposal())), final_response()])
        self.interrupt_after(lambda event: bool(event.get_function_responses()))
        (self.root / "note.txt").write_text("CHANGED RESOURCE")
        with self.assertRaisesRegex(RuntimeError, "sdk_replayed_tool_no_longer_allowed"):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(len(self.upstream_requests), 1)
        self.assertEqual(self.receipts, [])

    def test_storage_failure_after_receipt_stops_then_deduplicates_on_resume(self):
        from yuanxingmu.adapters import _google_adk_checkpoint
        original = _google_adk_checkpoint.atomic_json

        def write(path, value):
            if len(value["records"]) > 1 and value["records"][1]["results"]:
                raise OSError("fixture_disk_failure_after_receipt")
            return original(path, value)

        self.responses.extend([completion(self.transfer()), completion(
            tool_call("one", "yuanxingmu_request_action", self.proposal("first")),
            tool_call("two", "yuanxingmu_request_action", self.proposal("second"))), final_response()])
        with patch.object(_google_adk_checkpoint, "atomic_json", write), self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(self.saved()["records"][1]["results"], {})
        self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(len(self.receipts), 2)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 2)

    def test_host_stop_outcomes_prevent_later_tools_and_model(self):
        outcomes = [{"allowed": False, "reason": reason} for reason in (
            "automatic_prior_outcome_unconfirmed", "task_revoked", "task_paused", "broker_operation_failed",
            "defense_storage_fault", "storage_fault", "invalid_quarantine_state", "broker_closed")]
        outcomes.extend({field: value} for field in ("status", "outcome") for value in ("unconfirmed", "executing"))
        for index, outcome in enumerate(outcomes):
            with self.subTest(outcome=outcome):
                self.responses.extend([completion(self.transfer("transfer-" + str(index))), completion(
                    tool_call("first", "yuanxingmu_request_action", self.proposal("first")),
                    tool_call("later", "yuanxingmu_request_action", self.proposal("later"))), final_response()])
                with patch.object(self.runtime, "request", return_value=outcome) as invoke, self.assertRaises(RuntimeError):
                    self.runtime.run_session({**self.config, "prompt": f"stop {index}", "checkpoint": str(self.root / f"stop-{index}.json")})
                self.assertEqual(invoke.call_count, 1)
                self.assertEqual(len(self.responses), 1)
                self.responses.clear()
        self.assertEqual(self.receipts, [])

    def test_extended_timeout_applies_to_all_broker_paths(self):
        original, calls = self.runtime.request, []

        def request(operation, *args, **kwargs):
            calls.append((operation, kwargs["timeout_seconds"]))
            return original(operation, *args, **kwargs)

        self.responses.extend([completion(tool_call("read", "yuanxingmu_read", {"resource": "note"})),
                               completion(self.transfer()), completion(
                                   tool_call("review", "yuanxingmu_propose_action", self.proposal("reviewed")),
                                   tool_call("automatic", "yuanxingmu_request_action", self.proposal("automatic"))), final_response()])
        with patch.object(self.runtime, "request", request):
            self.runtime.run_session(self.config)
        self.assertEqual(calls, [("read", 120), ("propose_action", 120), ("request_action", 120)])
