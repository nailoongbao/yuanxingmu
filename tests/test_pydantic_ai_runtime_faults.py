"""Native PydanticAI recovery with real Broker effects and injected faults."""
from copy import deepcopy
import inspect
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import yuanxingmu.client as transport
import test_pydantic_ai_runtime as fixtures


@fixtures.REQUIRES_SDK
class PydanticAiRuntimeFaultTests(fixtures.PydanticAiFixture, unittest.TestCase):
    enable_automation = True

    def interrupt_before_dispatch(self, response):
        from pydantic_ai._function_schema import FunctionSchema
        self.responses.extend([response, fixtures.final_response()])
        with patch.object(FunctionSchema, "call", side_effect=RuntimeError("simulated_worker_loss_before_dispatch")):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.upstream_requests), 1)
        return Path(self.config["checkpoint"])

    def test_native_pending_history_restores_original_ids_and_rechecks_host(self):
        from pydantic_ai import Agent, DeferredToolResults
        response = fixtures.completion(fixtures.tool_call("host-pending", "yuanxingmu_propose_action", self.proposal()))
        checkpoint = self.interrupt_before_dispatch(response)
        saved = json.loads(checkpoint.read_bytes())
        self.assertEqual(saved["native"][-1]["parts"][0]["tool_call_id"], "host-pending")
        original, observed = Agent.run, []

        async def run(agent, *args, **kwargs):
            observed.append(kwargs)
            return await original(agent, *args, **kwargs)

        count = len(self.requests)
        with patch.object(Agent, "run", run):
            result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertIsInstance(observed[0]["deferred_tool_results"], DeferredToolResults)
        self.assertEqual(observed[0]["deferred_tool_results"].approvals, {"host-pending": True})
        self.assertEqual(observed[0]["deferred_tool_results"].calls, {})
        self.assertEqual(observed[0]["message_history"][-1].tool_calls[0].tool_call_id, "host-pending")
        self.assertIn(self.upstream_requests[0]["raw"], [row["raw"] for row in self.requests[count:]])
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.actions()[0]["status"], "pending")
        self.assertEqual(self.receipts, [])

    def test_batch_crash_after_first_effect_replays_exact_result_without_duplicate_effect(self):
        from pydantic_ai._function_schema import FunctionSchema
        response = fixtures.completion(
            fixtures.tool_call("host-first", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-second", "yuanxingmu_request_action", self.proposal("second")))
        self.responses.extend([response, fixtures.final_response()])
        original, interrupted = FunctionSchema.call, []

        async def crash_after_tool(schema, arguments, context):
            result = await original(schema, arguments, context)
            if not interrupted:
                interrupted.append(result)
                raise RuntimeError("simulated_worker_loss_after_broker_acceptance")
            return result

        with patch.object(FunctionSchema, "call", crash_after_tool):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(len(self.receipts), 1)
        first_id = self.actions()[0]["id"]
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.receipts), 2)
        self.assertEqual(len(self.actions()), 2)
        self.assertIn(first_id, {row["id"] for row in self.actions()})
        model_result = next(item["content"] for item in self.upstream_requests[-1]["body"]["messages"]
                            if item.get("tool_call_id") == "host-first")
        self.assertEqual(model_result, interrupted[0])
        self.assertEqual(len(self.judge.requests), 2)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 2)

    def test_second_call_failure_recovery_keeps_first_result_and_serial_order(self):
        from pydantic_ai._function_schema import FunctionSchema
        self.responses.extend([fixtures.completion(
            fixtures.tool_call("host-first", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-second", "yuanxingmu_request_action", self.proposal("second")),
            fixtures.tool_call("host-third", "yuanxingmu_request_action", self.proposal("third"))), fixtures.final_response()])
        original, dispatches = FunctionSchema.call, []

        async def stop_second(schema, arguments, context):
            dispatches.append(context.tool_call_id)
            if context.tool_call_id == "host-second":
                raise RuntimeError("simulated_worker_loss_before_second")
            return await original(schema, arguments, context)

        with patch.object(FunctionSchema, "call", stop_second):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(dispatches, ["host-first", "host-second"])
        self.assertEqual(len(self.receipts), 1)
        saved = json.loads(Path(self.config["checkpoint"]).read_bytes())
        self.assertEqual(list(saved["records"][0]["results"]), ["host-first"])
        self.assertEqual(saved["native"][-1]["kind"], "response")
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.receipts), 3)
        self.assertEqual(len(self.actions()), 3)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 3)

    def test_changed_host_response_blocks_recovery_and_preserves_original_pause(self):
        response = fixtures.completion(fixtures.tool_call("host-original", "yuanxingmu_request_action", self.proposal()))
        path = self.interrupt_before_dispatch(response)
        original = path.read_bytes()
        changed = fixtures.completion(fixtures.tool_call("host-forged", "yuanxingmu_request_action", self.proposal("changed")))
        self.bridge_hook = lambda row: changed if row["raw"] == self.upstream_requests[0]["raw"] else None
        with self.assertRaisesRegex(RuntimeError, "response_changed"):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.responses), 1)

    def test_host_recheck_failure_stops_before_dispatch_then_can_resume(self):
        response = fixtures.completion(fixtures.tool_call("host-recheck", "yuanxingmu_request_action", self.proposal()))
        self.responses.extend([response, fixtures.final_response()])
        self.bridge_hook = lambda row: (403, {"error": "revoked"}) if row["raw"] in self.journal else None
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])
        self.bridge_hook = None
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_extended_rpc_timeout_applies_to_read_reviewed_and_automatic_paths(self):
        self.judge.delay = .35
        original = transport.request
        default = inspect.signature(original).parameters["timeout_seconds"].default
        calls = []

        def scaled(operation, **fields):
            timeout = fields.pop("timeout_seconds", default)
            calls.append((operation, timeout))
            return original(operation, timeout_seconds=timeout / 100, **fields)

        self.responses.extend([fixtures.completion(fixtures.tool_call("host-read", "yuanxingmu_read", {"resource": "note"})),
            fixtures.completion(fixtures.tool_call("host-review", "yuanxingmu_propose_action", self.proposal("review")),
                                fixtures.tool_call("host-auto", "yuanxingmu_request_action", self.proposal("auto"))),
            fixtures.final_response()])
        with patch.object(self.runtime, "request", scaled):
            result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(default, 15)
        self.assertEqual(calls, [("read", 120), ("propose_action", 120), ("request_action", 120)])
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 2)

    def test_rpc_error_stops_later_tools_and_model_without_retry(self):
        self.responses.extend([fixtures.completion(
            fixtures.tool_call("host-error", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-later", "yuanxingmu_request_action", self.proposal("later"))), fixtures.final_response()])
        with patch.object(self.runtime, "request", side_effect=OSError("synthetic_rpc_loss")) as invoke:
            with self.assertRaisesRegex(RuntimeError, "tool_dispatch_failed"):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(len(self.upstream_requests), 1)
        self.assertEqual(len(self.responses), 1)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_lost_initial_model_response_recovers_host_response_without_new_generation(self):
        response = fixtures.completion(fixtures.tool_call("host-model-loss", "yuanxingmu_request_action", self.proposal()))
        self.responses.extend([response, fixtures.final_response()])
        dropped = []

        def drop_once(row):
            if not dropped:
                dropped.append(row["raw"])
                return True
            return False

        self.drop_model_response = drop_once
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(deepcopy(self.config))
        saved = json.loads(Path(self.config["checkpoint"]).read_bytes())
        self.assertIsNone(saved["records"][0]["response"])
        self.assertEqual(saved["native"], [])
        self.drop_model_response = None
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(len(self.receipts), 1)

    def test_lost_model_reply_after_read_reuses_exact_tool_history(self):
        next_response = fixtures.completion(fixtures.tool_call("host-action", "yuanxingmu_request_action", self.proposal()))
        self.responses.extend([fixtures.completion(fixtures.tool_call("host-read", "yuanxingmu_read", {"resource": "note"})),
                               next_response, fixtures.final_response()])
        dropped = []

        def drop_once(row):
            if not dropped and self.journal.get(row["raw"]) == next_response:
                dropped.append(row["raw"])
                return True
            return False

        self.drop_model_response = drop_once
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(deepcopy(self.config))
        self.drop_model_response = None
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.upstream_requests), 3)
        self.assertEqual(len(self.receipts), 1)
        self.assertIn(dropped[0], [row["raw"] for row in self.requests[3:]])

    def test_changed_resource_after_read_stops_replay_before_later_action(self):
        next_response = fixtures.completion(fixtures.tool_call("host-action", "yuanxingmu_request_action", self.proposal()))
        self.responses.extend([fixtures.completion(fixtures.tool_call("host-read", "yuanxingmu_read", {"resource": "note"})),
                               next_response, fixtures.final_response()])
        self.drop_model_response = lambda row: self.journal.get(row["raw"]) == next_response
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(deepcopy(self.config))
        (self.root / "note.txt").write_text("CHANGED-AFTER-ORIGINAL-READ", encoding="utf-8")
        self.drop_model_response = None
        with self.assertRaisesRegex(RuntimeError, "replayed_tool_no_longer_allowed"):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_consistently_forged_native_call_and_saved_response_cannot_override_host(self):
        path = self.interrupt_before_dispatch(fixtures.completion(fixtures.tool_call(
            "host-original-call", "yuanxingmu_request_action", self.proposal("ORIGINAL-ACTION"))))
        forged = path.read_text().replace("host-original-call", "host-forged-call").replace("ORIGINAL-ACTION", "FORGED-ACTION")
        path.write_text(forged)
        with self.assertRaises((ValueError, RuntimeError)):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.judge.requests, [])

    def test_checkpoint_storage_failure_after_receipt_stops_then_replays_host_nonce(self):
        self.responses.extend([fixtures.completion(
            fixtures.tool_call("host-first", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-second", "yuanxingmu_request_action", self.proposal("second"))), fixtures.final_response()])
        original = self.runtime.Checkpoint.save

        def fail_after_effect(checkpoint):
            if checkpoint.value["records"] and checkpoint.value["records"][0]["results"]:
                raise OSError("simulated_disk_failure")
            return original(checkpoint)

        with patch.object(self.runtime.Checkpoint, "save", fail_after_effect):
            with self.assertRaisesRegex(RuntimeError, "tool_dispatch_failed"):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(len(self.receipts), 1)
        saved = json.loads(Path(self.config["checkpoint"]).read_bytes())
        self.assertEqual(saved["records"][0]["results"], {})
        self.assertEqual(saved["native"][-1]["kind"], "response")
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.receipts), 2)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 2)

    def test_lost_model_reply_on_new_user_turn_restores_that_prompt_exactly(self):
        self.responses.append(fixtures.final_response("First turn complete"))
        self.runtime.run_session(deepcopy(self.config))
        self.responses.append(fixtures.final_response("Second turn complete"))
        config = {**self.config, "resume": True, "prompt": "New user request after completion"}
        self.drop_model_response = lambda row: row["body"]["messages"][-1]["content"] == config["prompt"]
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(config)
        self.assertEqual(len(self.upstream_requests), 2)
        self.drop_model_response = None
        result = self.runtime.run_session(config)
        self.assertEqual(result["answer"], "Second turn complete")
        self.assertEqual(result["steps"], 1)
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(self.requests[-1]["raw"], self.upstream_requests[-1]["raw"])

    def test_host_stop_outcomes_prevent_later_call_and_model_continuation(self):
        outcomes = [{"allowed": False, "reason": reason} for reason in (
            "automatic_prior_outcome_unconfirmed", "task_revoked", "task_paused", "broker_operation_failed",
            "defense_storage_fault", "storage_fault", "invalid_quarantine_state", "broker_closed")]
        outcomes.extend({field: value} for field in ("status", "outcome") for value in ("unconfirmed", "executing"))
        for index, outcome in enumerate(outcomes):
            with self.subTest(outcome=outcome):
                self.responses.extend([fixtures.completion(
                    fixtures.tool_call(f"host-stop-first-{index}", "yuanxingmu_request_action", self.proposal("first")),
                    fixtures.tool_call(f"host-stop-later-{index}", "yuanxingmu_request_action", self.proposal("later"))),
                    fixtures.final_response()])
                with patch.object(self.runtime, "request", return_value=outcome) as invoke:
                    with self.assertRaises(RuntimeError):
                        self.runtime.run_session({**self.config, "prompt": f"Host stop {index}",
                                                  "checkpoint": str(self.root / f"stopped-{index}.json")})
                self.assertEqual(invoke.call_count, 1)
                self.assertEqual(len(self.responses), 1)
                self.responses.clear()
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])

    def test_uncertain_native_or_journal_result_blocks_completed_resume(self):
        nonce = "host-uncertain-history"
        self.run_calls(fixtures.tool_call(nonce, "yuanxingmu_request_action", self.proposal()))
        path = Path(self.config["checkpoint"])
        original, count = json.loads(path.read_bytes()), len(self.requests)
        for source in ("native", "request_history"):
            for field in ("status", "outcome"):
                for outcome in ("unconfirmed", "executing"):
                    with self.subTest(source=source, field=field, outcome=outcome):
                        saved = deepcopy(original)
                        if source == "native":
                            message = next(part for item in saved["native"] for part in item["parts"]
                                           if part.get("part_kind") == "tool-return" and part["tool_call_id"] == nonce)
                        else:
                            message = next(item for row in saved["records"] for item in row["request"]["messages"]
                                           if item.get("tool_call_id") == nonce)
                        result = json.loads(message["content"])
                        result.pop("status", None)
                        result.pop("outcome", None)
                        result[field] = outcome
                        message["content"] = json.dumps(result)
                        raw = json.dumps(saved).encode()
                        path.write_bytes(raw)
                        with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                            self.runtime.run_session({**self.config, "resume": True})
                        self.assertEqual(path.read_bytes(), raw)
                        self.assertEqual(len(self.requests), count)
        self.assertEqual(len(self.receipts), 1)

    def test_prior_uncertain_action_new_nonce_stops_repeated_worker_resume(self):
        self.drop_receipts = True
        original = transport.request("request_action", socket_path=self.client.socket_path, request_key="host-prior-unknown",
                                     proposal=self.proposal()["proposal"])
        self.assertEqual(original["status"], "unconfirmed")
        self.responses.extend([fixtures.completion(
            fixtures.tool_call("host-new-same-action", "yuanxingmu_request_action", self.proposal()),
            fixtures.tool_call("host-later-different-action", "yuanxingmu_request_action", self.proposal("later"))),
            fixtures.final_response()])
        for resume in (False, True, True):
            with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                self.runtime.run_session({**self.config, "resume": resume})
            self.assertEqual(len(self.receipts), 1)
            self.assertEqual(len(self.upstream_requests), 1)
            self.assertEqual(len(self.responses), 1)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)
        self.assertEqual(len(self.actions()), 2)
        self.assertEqual({action["status"] for action in self.actions()}, {"unconfirmed", "pending"})


if __name__ == "__main__":
    unittest.main()
