"""Native Runner recovery across local tool, journal and worker-state faults."""
import asyncio
from copy import deepcopy
import inspect
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import yuanxingmu.client as transport
import test_openai_agents_runtime as fixtures


@fixtures.REQUIRES_SDK
class OpenaiAgentsRuntimeFaultTests(fixtures.OpenaiAgentsFixture, unittest.TestCase):
    enable_automation = True

    def interrupt_before_dispatch(self, response):
        from agents.run_internal import tool_execution
        self.responses.extend([fixtures.handoff_response(), response, fixtures.final_response()])
        with patch.object(tool_execution, "_invoke_function_tool_with_metadata",
                          side_effect=RuntimeError("simulated_worker_loss_before_dispatch")):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.upstream_requests), 2)
        checkpoint = Path(self.config["checkpoint"])
        self.assertIn(response["choices"][0]["message"]["tool_calls"][0]["id"], checkpoint.read_text())
        return checkpoint

    def test_pending_native_state_restores_executor_and_rechecks_original_request(self):
        from agents import Runner, RunState
        response = fixtures.completion(fixtures.tool_call(
            "host-before-dispatch", "yuanxingmu_propose_action", self.proposal()))
        self.interrupt_before_dispatch(response)
        original_runner, original_restore = Runner.run, RunState.from_json
        inputs, restored = [], []

        async def runner(starting_agent, value, *args, **kwargs):
            inputs.append(value)
            return await original_runner(starting_agent, value, *args, **kwargs)

        async def restore(*args, **kwargs):
            value = await original_restore(*args, **kwargs)
            restored.append(value.to_json(strict_context=True))
            return value

        before = len(self.requests)
        with patch.object(Runner, "run", staticmethod(runner)), \
                patch.object(RunState, "from_json", staticmethod(restore)):
            result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertTrue(inputs)
        self.assertTrue(all(isinstance(value, RunState) for value in inputs))
        self.assertTrue(restored)
        self.assertEqual(restored[0]["current_agent"]["name"], fixtures.EXECUTOR)
        self.assertEqual(restored[0]["context"]["approvals"], {})
        original_action = self.upstream_requests[1]["raw"]
        self.assertIn(original_action, [row["raw"] for row in self.requests[before:]])
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.actions()[0]["status"], "pending")
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.upstream_requests), 3)

    def test_crash_after_broker_acceptance_replays_nonce_without_duplicate_effect(self):
        from agents.run_internal import tool_execution
        response = fixtures.completion(
            fixtures.tool_call("host-accepted-first", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-accepted-second", "yuanxingmu_request_action", self.proposal("second")))
        self.responses.extend([fixtures.handoff_response(), response, fixtures.final_response()])
        original = tool_execution._invoke_function_tool_with_metadata
        interrupted = []

        async def crash_after_tool(**kwargs):
            result = await original(**kwargs)
            if not interrupted:
                interrupted.append(True)
                raise RuntimeError("simulated_worker_loss_after_broker_acceptance")
            return result

        with patch.object(tool_execution, "_invoke_function_tool_with_metadata", crash_after_tool):
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

    def test_partial_native_checkpoint_does_not_dispatch_completed_first_call(self):
        from agents.run_internal import tool_execution
        response = fixtures.completion(
            fixtures.tool_call("host-partial-first", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-partial-second", "yuanxingmu_request_action", self.proposal("second")))
        self.responses.extend([fixtures.handoff_response(), response, fixtures.final_response()])
        original = tool_execution._invoke_function_tool_with_metadata

        async def stop_second(**kwargs):
            if kwargs["context"].tool_call_id == "host-partial-second":
                raise RuntimeError("simulated_worker_loss_before_second_call")
            return await original(**kwargs)

        with patch.object(tool_execution, "_invoke_function_tool_with_metadata", stop_second):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(len(self.receipts), 1)
        dispatched = []

        async def track(**kwargs):
            dispatched.append(kwargs["context"].tool_call_id)
            return await original(**kwargs)

        with patch.object(tool_execution, "_invoke_function_tool_with_metadata", track):
            result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(dispatched, ["host-partial-second"])
        self.assertEqual(len(self.receipts), 2)
        self.assertEqual(len(self.actions()), 2)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 2)

    def test_changed_host_response_blocks_recovery_and_keeps_original_pending_response(self):
        response = fixtures.completion(fixtures.tool_call(
            "host-original-pending", "yuanxingmu_request_action", self.proposal()))
        checkpoint = self.interrupt_before_dispatch(response)
        changed = fixtures.completion(fixtures.tool_call(
            "host-changed-pending", "yuanxingmu_request_action", self.proposal("changed")))
        action_raw = self.upstream_requests[1]["raw"]
        self.bridge_hook = lambda row: changed if row["raw"] == action_raw else None
        with self.assertRaisesRegex(RuntimeError, "response_changed"):
            self.runtime.run_session({**self.config, "resume": True})
        saved = json.dumps(json.loads(checkpoint.read_bytes()))
        self.assertIn("host-original-pending", saved)
        self.assertNotIn("host-changed-pending", saved)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(len(self.responses), 1)

    def test_host_recheck_failure_prevents_dispatch_then_allows_safe_resume(self):
        response = fixtures.completion(fixtures.tool_call(
            "host-recheck-rejected", "yuanxingmu_request_action", self.proposal()))
        self.responses.extend([fixtures.handoff_response(), response, fixtures.final_response()])

        def deny_action_recheck(row):
            if row["raw"] in self.journal and self.journal[row["raw"]] == response:
                return (403, {"error": {"message": "host request no longer authorized"}})
            return None

        self.bridge_hook = deny_action_recheck
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

        self.responses.extend([
            fixtures.completion(fixtures.tool_call("host-slow-read", "yuanxingmu_read", {"resource": "note"})),
            fixtures.handoff_response(),
            fixtures.completion(
                fixtures.tool_call("host-slow-proposal", "yuanxingmu_propose_action", self.proposal("review")),
                fixtures.tool_call("host-slow-automatic", "yuanxingmu_request_action", self.proposal("automatic"))),
            fixtures.final_response()])
        with patch.object(self.runtime, "request", scaled_request):
            result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(rpc_calls, [("read", 120), ("propose_action", 120), ("request_action", 120)])
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 2)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_native_tool_rpc_error_stops_without_model_retry_or_later_call(self):
        self.responses.extend([fixtures.handoff_response(), fixtures.completion(
            fixtures.tool_call("host-rpc-error", "yuanxingmu_request_action", self.proposal("first")),
            fixtures.tool_call("host-rpc-later", "yuanxingmu_request_action", self.proposal("later"))),
            fixtures.final_response()])
        with patch.object(self.runtime, "request", side_effect=OSError("synthetic_transport_failure")) as invoke:
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(invoke.call_count, 1)
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(len(self.responses), 1)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.judge.requests, [])

    def test_lost_executor_response_after_handoff_recovers_the_committed_host_response(self):
        response = fixtures.completion(fixtures.tool_call(
            "host-after-model-recovery", "yuanxingmu_request_action", self.proposal()))
        self.responses.extend([fixtures.handoff_response(), response, fixtures.final_response()])
        dropped = []

        def drop_first_executor_response(row):
            if not dropped and self.journal.get(row["raw"]) == response:
                dropped.append(row["raw"])
                return True
            return False

        self.drop_model_response = drop_first_executor_response
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(len(dropped), 1)
        self.assertEqual(self.journal[dropped[0]], response)
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(self.actions(), [])
        self.drop_model_response = None
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.upstream_requests), 3)
        self.assertEqual(sum(row["raw"] == dropped[0] for row in self.upstream_requests), 1)
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_forged_native_approvals_and_agent_identity_fail_before_dispatch(self):
        from agents import RunState
        response = fixtures.completion(fixtures.tool_call(
            "host-pending-native", "yuanxingmu_request_action", self.proposal()))
        checkpoint = self.interrupt_before_dispatch(response)
        original = json.loads(checkpoint.read_bytes())
        count, before = len(self.requests), self.events()
        saved_checkpoint = self.runtime.Checkpoint({**self.config, "resume": True})
        loop = self.runtime._Loop(self.config, saved_checkpoint)

        async def native_approval():
            state = await RunState.from_json(loop.researcher, deepcopy(original["native"]),
                                             context_override={}, strict_context=True)
            state.approve(state.get_interruptions()[0])
            return state.to_json(strict_context=True)

        approved_native = asyncio.run(native_approval())
        self.assertTrue(approved_native["context"]["approvals"])
        for variant in ("approvals", "foreign_agent", "wrong_local_agent", "missing_native"):
            with self.subTest(variant=variant):
                saved = deepcopy(original)
                if variant == "approvals":
                    # This is a syntactically valid SDK approval, made by the
                    # real public API. It still cannot authorize a Broker call.
                    saved["native"] = deepcopy(approved_native)
                elif variant == "foreign_agent":
                    saved["native"]["current_agent"] = {"name": "foreign_executor"}
                elif variant == "wrong_local_agent":
                    saved["native"]["current_agent"] = {"name": fixtures.RESEARCHER}
                else:
                    saved["native"] = None
                raw = json.dumps(saved).encode("utf-8")
                checkpoint.write_bytes(raw)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session({**self.config, "resume": True})
                self.assertEqual(checkpoint.read_bytes(), raw)
                self.assertEqual(len(self.requests), count)
                self.assertEqual(self.events(), before)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_action_replay_retains_original_result_and_committed_model_request(self):
        final = fixtures.final_response()
        self.responses.extend([fixtures.handoff_response(), fixtures.completion(fixtures.tool_call(
            "host-replay-action", "yuanxingmu_request_action", self.proposal())), final])
        dropped, broker_results = [], []

        def drop_final_response(row):
            if not dropped and self.journal.get(row["raw"]) == final:
                dropped.append(row["raw"])
                return True
            return False

        real_request = self.runtime.request

        def record_broker_result(operation, **kwargs):
            result = real_request(operation, **kwargs)
            if operation == "request_action":
                broker_results.append(deepcopy(result))
            return result

        self.drop_model_response = drop_final_response
        with patch.object(self.runtime, "request", record_broker_result):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
            self.assertEqual(len(dropped), 1)
            self.assertEqual(len(self.receipts), 1)
            self.assertEqual(len(self.upstream_requests), 3)
            self.drop_model_response = None
            before = len(self.requests)
            result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(broker_results), 2)
        self.assertNotEqual(broker_results[0], broker_results[1])
        self.assertIn("action_already_recorded", json.dumps(broker_results[1]))
        self.assertIn(dropped[0], [row["raw"] for row in self.requests[before:]])
        self.assertEqual(len(self.upstream_requests), 3)
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.judge.requests), 1)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_changed_resource_after_read_cannot_reuse_earlier_allowed_result(self):
        handoff = fixtures.handoff_response("host-after-read-handoff")
        self.responses.extend([
            fixtures.completion(fixtures.tool_call("host-original-read", "yuanxingmu_read", {"resource": "note"})),
            handoff, fixtures.completion(fixtures.tool_call(
                "host-after-read-action", "yuanxingmu_request_action", self.proposal())), fixtures.final_response()])
        dropped = []

        def drop_handoff_response(row):
            if not dropped and self.journal.get(row["raw"]) == handoff:
                dropped.append(row["raw"])
                return True
            return False

        self.drop_model_response = drop_handoff_response
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(len(dropped), 1)
        self.assertIn(b"LOCAL-REGISTERED-RESOURCE", dropped[0])
        self.assertEqual(len(self.upstream_requests), 2)
        (self.root / "note.txt").write_text("CHANGED-AFTER-ORIGINAL-READ", encoding="utf-8")
        self.drop_model_response = None
        with self.assertRaisesRegex(RuntimeError, "replayed_tool_no_longer_allowed"):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_forged_native_calls_and_saved_response_cannot_override_host_journal(self):
        response = fixtures.completion(fixtures.tool_call(
            "host-original-call", "yuanxingmu_request_action", self.proposal("ORIGINAL-ACTION-BODY")))
        checkpoint = self.interrupt_before_dispatch(response)
        original = checkpoint.read_text()
        # Change every worker copy consistently: RunState's pending call,
        # generated items and raw responses, plus the saved host response row.
        forged = original.replace("host-original-call", "host-forged-call").replace(
            "ORIGINAL-ACTION-BODY", "FORGED-ACTION-BODY")
        checkpoint.write_text(forged)
        with self.assertRaises((ValueError, RuntimeError)):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.judge.requests, [])
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(len(self.responses), 1)

    def test_uncertain_native_outputs_or_request_history_block_completed_resume(self):
        nonce = "host-old-uncertain"
        self.run_calls(fixtures.tool_call(nonce, "yuanxingmu_request_action", self.proposal()))
        checkpoint = Path(self.config["checkpoint"])
        original = json.loads(checkpoint.read_bytes())
        count = len(self.requests)
        for source in ("native", "request_history"):
            for field in ("status", "outcome"):
                for outcome in ("unconfirmed", "executing"):
                    with self.subTest(source=source, field=field, outcome=outcome):
                        saved = deepcopy(original)
                        if source == "native":
                            message = next(item["raw_item"] for item in saved["native"]["generated_items"]
                                           if item.get("type") == "tool_call_output_item"
                                           and item["raw_item"].get("call_id") == nonce)
                            key = "output"
                        else:
                            message = next(item for row in saved["records"] for item in row["request"]["messages"]
                                           if item.get("tool_call_id") == nonce)
                            key = "content"
                        result = json.loads(message[key])
                        self.assertEqual(result["status"], "acknowledged")
                        result.pop("status", None)
                        result.pop("outcome", None)
                        result[field] = outcome
                        message[key] = json.dumps(result)
                        if source == "native":
                            # Keep redundant SDK output copies and the saved
                            # tool result consistent, so the uncertain-status
                            # check itself has to block the completed answer.
                            for row in saved["records"]:
                                if nonce in row["results"]:
                                    row["results"][nonce] = message[key]
                            for item in saved["native"]["session_items"]:
                                if item.get("type") == "tool_call_output_item" and item["raw_item"].get("call_id") == nonce:
                                    item["raw_item"]["output"] = message[key]
                        raw = json.dumps(saved).encode("utf-8")
                        checkpoint.write_bytes(raw)
                        with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                            self.runtime.run_session({**self.config, "resume": True})
                        self.assertEqual(checkpoint.read_bytes(), raw)
                        self.assertEqual(len(self.requests), count)
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_host_stop_outcomes_prevent_later_call_and_model_continuation(self):
        outcomes = [{"allowed": False, "reason": reason} for reason in (
            "automatic_prior_outcome_unconfirmed", "task_revoked", "task_paused", "broker_operation_failed",
            "defense_storage_fault", "storage_fault", "invalid_quarantine_state", "broker_closed")]
        outcomes.extend({field: value} for field in ("status", "outcome") for value in ("unconfirmed", "executing"))
        for index, outcome in enumerate(outcomes):
            with self.subTest(outcome=outcome):
                self.responses.extend([fixtures.handoff_response(f"host-stop-handoff-{index}"), fixtures.completion(
                    fixtures.tool_call(f"host-stop-first-{index}", "yuanxingmu_request_action", self.proposal("first")),
                    fixtures.tool_call(f"host-stop-later-{index}", "yuanxingmu_request_action", self.proposal("later"))),
                    fixtures.final_response()])
                with patch.object(self.runtime, "request", return_value=outcome) as invoke:
                    with self.assertRaises(RuntimeError):
                        self.runtime.run_session({**self.config, "prompt": f"Host stop outcome {index}.",
                                                  "checkpoint": str(self.root / f"stopped-{index}.json")})
                self.assertEqual(invoke.call_count, 1)
                self.assertEqual(len(self.responses), 1)
                self.responses.clear()
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])


if __name__ == "__main__":
    unittest.main()
