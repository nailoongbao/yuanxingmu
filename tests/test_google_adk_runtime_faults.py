"""Closed native checkpoint validation and fault-stopped ADK execution."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from test_google_adk_runtime import COMPLETE, GoogleAdkFixture, REQUIRES_SDK, completion, final_response, tool_call


@REQUIRES_SDK
class GoogleAdkFaultTests(GoogleAdkFixture, unittest.TestCase):
    def test_dropped_model_response_reuses_original_host_journal(self):
        self.responses.extend([completion(tool_call("read", "yuanxingmu_read", {"resource": "note"})), final_response()])
        dropped = False

        def drop(row):
            nonlocal dropped
            if not dropped:
                dropped = True
                return True
            return False

        self.drop_model_response = drop
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertEqual(len(self.upstream_requests), 1)
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertTrue(self.saved()["attempts"][0]["events"][-1].get("error_code"))

    def test_original_nonce_checked_before_each_dispatch(self):
        calls = [tool_call("first", "yuanxingmu_read", {"resource": "note"}),
                 tool_call("second", "yuanxingmu_describe", {})]
        self.responses.append(completion(*calls))
        seen = 0

        def hook(row):
            nonlocal seen
            seen += 1
            return (403, {"error": "revoked"}) if seen == 3 else None

        self.bridge_hook = hook
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertEqual(set(self.saved()["records"][0]["results"]), {"first"})
        self.assertEqual(len(self.upstream_requests), 1)

    def test_changed_host_response_is_rejected_on_replay(self):
        self.responses.extend([completion(tool_call("read", "yuanxingmu_read", {"resource": "note"})), (500, {"error": "stop"})])
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.bridge_hook = lambda row: completion(tool_call("changed", "yuanxingmu_read", {"resource": "note"}))
        with self.assertRaisesRegex(RuntimeError, "sdk_checkpoint_response_changed"):
            self.runtime.run_session({**self.config, "resume": True})

    def test_resume_wrong_prompt_and_binding_rejected(self):
        self.responses.append((500, {"error": "stop"}))
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        before = len(self.requests)
        for changes in ({"prompt": "other"}, {"task_id": "other"}, {"session_id": "other"}, {"automatic_actions": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.runtime.run_session({**self.config, "resume": True, **changes})
        self.assertEqual(len(self.requests), before)

    def test_unknown_media_remote_auth_and_state_flags_rejected_before_parse(self):
        self.run_calls(tool_call("read", "yuanxingmu_read", {"resource": "note"}))
        saved = self.saved()
        from google.adk.sessions.session import Session
        mutations = [lambda v: v["native"]["events"][1].update(unknown_field="silently ignored by native SDK"),
                     lambda v: v["native"]["events"][1]["content"]["parts"][0].update(inline_data={"data": "secret"}),
                     lambda v: v["native"]["events"][1]["content"]["parts"][0].update(executable_code={"code": "x"}),
                     lambda v: v["native"]["events"][1]["actions"]["requested_auth_configs"].update(x={"auth_scheme": "external"}),
                     lambda v: v["native"]["state"].update(authority="admin"),
                     lambda v: v["native"]["events"][1]["actions"]["state_delta"].update(authority="admin"),
                     lambda v: v["native"]["events"][1]["node_info"].update(output_for=["outside"])]
        for mutate in mutations:
            value = deepcopy(saved)
            mutate(value)
            Path(self.config["checkpoint"]).write_text(json.dumps(value))
            with patch.object(Session, "model_validate", side_effect=AssertionError("must reject before native parse")), self.assertRaises(ValueError):
                self.runtime.run_session({**self.config, "resume": True})

    def test_modified_call_result_agent_and_terminal_are_rejected(self):
        self.run_calls(tool_call("read", "yuanxingmu_read", {"resource": "note"}))
        saved = self.saved()
        mutations = [lambda v: v["native"]["events"][1]["content"]["parts"][0]["function_call"].update(id="forged"),
                     lambda v: v["native"]["events"][2]["content"]["parts"][0]["function_response"].update(name="other"),
                     lambda v: v["native"]["events"][2]["content"]["parts"][0]["function_response"]["response"].update(result='{"allowed":true}'),
                     lambda v: v["native"]["events"][1].update(author="yuanxingmu_executor"),
                     lambda v: v["native"]["events"][1]["node_info"].update(path="yuanxingmu_coordinator@2"),
                     lambda v: v["native"]["events"][2]["actions"].update(end_of_agent=True)]
        for mutate in mutations:
            value = deepcopy(saved)
            mutate(value)
            Path(self.config["checkpoint"]).write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                self.runtime.run_session({**self.config, "resume": True})

    def test_storage_failure_prevents_tool_dispatch(self):
        from yuanxingmu.adapters import _google_adk_checkpoint
        original = _google_adk_checkpoint.atomic_json

        def write(path, value):
            if value["records"] and value["records"][-1]["response"] is not None:
                raise OSError("fixture_disk_failure")
            return original(path, value)

        self.responses.append(completion(tool_call("read", "yuanxingmu_read", {"resource": "note"})))
        before = self.events()
        with patch.object(_google_adk_checkpoint, "atomic_json", write), self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertEqual(before, self.events())

    def test_repeated_host_nonce_rejected_across_model_calls(self):
        self.responses.extend([completion(tool_call("same", "yuanxingmu_describe", {})),
                               completion(tool_call("same", "yuanxingmu_describe", {}))])
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertIsNone(self.saved()["records"][-1]["response"])

    def test_model_error_does_not_become_a_successful_native_end_event(self):
        self.responses.append((500, {"error": "fixture unavailable"}))
        with self.assertRaisesRegex(RuntimeError, "sdk_model_dispatch_failed"):
            self.runtime.run_session(self.config)
        self.assertEqual(self.saved()["status"], "running")
        self.assertTrue(self.saved()["native"]["events"][-1].get("error_code"))

    def test_interrupt_after_native_call_before_any_dispatch(self):
        self.responses.extend([completion(tool_call("read", "yuanxingmu_read", {"resource": "note"})), final_response()])
        before = self.events()
        prior = self.interrupt_after(lambda event: bool(event.get_function_calls()))
        self.assertEqual(before, self.events())
        self.assertEqual(prior["records"][0]["results"], {})
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(self.saved()["attempts"][0], prior["native"])
        self.assertEqual(len(self.upstream_requests), 2)

    def test_interrupt_after_native_batch_result_keeps_original_history(self):
        self.responses.extend([completion(tool_call("read", "yuanxingmu_read", {"resource": "note"}),
                                          tool_call("describe", "yuanxingmu_describe", {})), final_response()])
        prior = self.interrupt_after(lambda event: bool(event.get_function_responses()))
        self.assertEqual(len(prior["records"][0]["results"]), 2)
        self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(self.saved()["records"][0]["results"], prior["records"][0]["results"])
        self.assertEqual(len(self.upstream_requests), 2)

    def test_transfer_call_and_result_interruptions_keep_actual_child_path(self):
        for phase in ("call", "result"):
            with self.subTest(phase=phase):
                self.config.update(checkpoint=str(self.root / (phase + ".json")), prompt="Transfer interruption " + phase)
                self.responses.extend([completion(self.transfer("transfer-" + phase)), final_response()])
                before = len(self.upstream_requests)
                prior = self.interrupt_after(lambda event: bool(event.get_function_calls() if phase == "call" else event.get_function_responses()))
                self.assertEqual(len(self.upstream_requests), before + 1)
                result = self.runtime.run_session({**self.config, "resume": True})
                self.assertEqual(result["answer"], COMPLETE)
                self.assertEqual(len(self.upstream_requests), before + 2)
                self.assertEqual(self.saved()["attempts"][0], prior["native"])
                self.assertEqual(self.saved()["native"]["events"][-1]["node_info"]["path"],
                                 "yuanxingmu_coordinator@1/yuanxingmu_executor@1")

    def test_first_child_model_reply_loss_is_recovered_without_regeneration(self):
        self.responses.extend([completion(self.transfer()), completion(tool_call("describe", "yuanxingmu_describe", {})), final_response()])
        dropped = False

        def drop(row):
            nonlocal dropped
            if "yuanxingmu_draft_email" in {tool["function"]["name"] for tool in row["body"]["tools"]} and not dropped:
                dropped = True
                return True
            return False

        self.drop_model_response = drop
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertEqual(len(self.upstream_requests), 2)
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(len(self.upstream_requests), 3)

    def test_final_text_before_terminal_replay_has_no_new_generation(self):
        self.responses.append(final_response())
        self.interrupt_after(lambda event: bool(event.content and event.content.role == "model"))
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(len(self.upstream_requests), 1)

    def test_new_turn_interrupted_model_recovers_exact_prompt(self):
        self.responses.append(final_response("FIRST"))
        self.runtime.run_session(self.config)
        prompt = "A distinct new user turn"
        self.responses.append(final_response("SECOND"))
        self.drop_model_response = lambda row: row["body"]["messages"][-1] == {"role": "user", "content": prompt}
        with self.assertRaises(RuntimeError):
            self.runtime.run_session({**self.config, "resume": True, "prompt": prompt})
        self.drop_model_response = None
        result = self.runtime.run_session({**self.config, "resume": True, "prompt": prompt})
        self.assertEqual(result["answer"], "SECOND")
        self.assertEqual(result["steps"], 1)
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(self.requests[-1]["raw"], self.upstream_requests[-1]["raw"])

    def test_step_limit_can_resume_with_larger_limit_without_repeat_generation(self):
        self.responses.extend([completion(tool_call("describe", "yuanxingmu_describe", {})), final_response()])
        with self.assertRaisesRegex(RuntimeError, "sdk_max_steps_reached"):
            self.runtime.run_session({**self.config, "max_steps": 1})
        self.assertEqual(len(self.upstream_requests), 1)
        result = self.runtime.run_session({**self.config, "resume": True, "max_steps": 2})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(len(self.upstream_requests), 2)

    def test_forging_both_native_call_and_journal_cannot_replace_host_response(self):
        self.responses.extend([completion(tool_call("original-nonce", "yuanxingmu_read", {"resource": "note"})), final_response()])
        self.interrupt_after(lambda event: bool(event.get_function_calls()))
        path = Path(self.config["checkpoint"])
        path.write_text(path.read_text().replace("original-nonce", "forged-nonce"))
        before = self.events()
        with self.assertRaisesRegex(RuntimeError, "sdk_checkpoint_response_changed"):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(before, self.events())

    def test_duplicate_missing_ids_and_empty_nonlist_calls_rejected(self):
        messages = [completion(tool_call("same", "yuanxingmu_describe", {}), tool_call("same", "yuanxingmu_describe", {})),
                    completion(tool_call("", "yuanxingmu_describe", {})), final_response()]
        messages[-1]["choices"][0]["message"]["tool_calls"] = {}
        for index, response in enumerate(messages):
            with self.subTest(index=index):
                self.responses.append(response)
                before = self.events()
                with self.assertRaises(RuntimeError):
                    self.runtime.run_session({**self.config, "prompt": f"invalid {index}", "checkpoint": str(self.root / f"invalid-{index}.json")})
                self.assertEqual(before, self.events())

    def test_no_google_provider_client_created(self):
        from google import genai
        self.responses.append(final_response())
        with patch.object(genai, "Client", side_effect=AssertionError("must use approved host bridge")):
            result = self.runtime.run_session(self.config)
        self.assertEqual(result["answer"], COMPLETE)
