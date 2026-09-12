"""Automatic action scopes and fail-stop behavior in the native OpenAI Agents loop."""
from copy import deepcopy
import json
from pathlib import Path
import unittest
from urllib.parse import parse_qs

from yuanxingmu.guards import JudgeConfig
import test_openai_agents_runtime as fixtures
from test_yuanxingmu_guards import _JudgeFixture, _answer


@fixtures.REQUIRES_SDK
class OpenaiAgentsAutomaticRuntimeTests(fixtures.OpenaiAgentsFixture, unittest.TestCase):
    enable_automation = True

    def test_automatic_tool_is_absent_when_omitted_or_explicitly_disabled(self):
        for explicit in (False, True):
            with self.subTest(explicit=explicit):
                config = {**self.config, "prompt": f"Disabled automation {explicit}.",
                          "checkpoint": str(self.root / f"disabled-{explicit}.json")}
                if explicit:
                    config["automatic_actions"] = False
                else:
                    del config["automatic_actions"]
                self.responses.extend([fixtures.handoff_response(f"host-disabled-handoff-{explicit}"),
                                       fixtures.completion(fixtures.tool_call(
                                           "host-disabled", "yuanxingmu_request_action", self.proposal()))])
                before = self.events()
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session(config)
                self.assertEqual(self.events(), before)
                names = {item["function"]["name"] for item in self.upstream_requests[-1]["body"]["tools"]}
                self.assertNotIn("yuanxingmu_request_action", names)
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.judge.requests, [])
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 0)

    def test_three_native_approved_calls_use_real_receipts_and_frozen_scope(self):
        upload = {"proposal": {"kind": "upload", "target_id": "upload",
                               "payload": {"filename": "progress.txt", "content": "LOCAL-UPLOAD-CONTENT"}}}
        form = {"proposal": {"kind": "form", "target_id": "form",
                             "payload": {"fields": [{"name": "note", "value": "LOCAL-FORM-CONTENT"}]}}}
        self.run_calls(fixtures.tool_call("host-auto-message", "yuanxingmu_request_action", self.proposal()),
                       fixtures.tool_call("host-auto-upload", "yuanxingmu_request_action", upload),
                       fixtures.tool_call("host-auto-form", "yuanxingmu_request_action", form))
        self.assertEqual([row["path"] for row in self.receipts], ["/message", "/upload", "/form"])
        self.assertIn("LOCAL-OPENAI-AGENTS-PROGRESS", self.receipts[0]["body"])
        self.assertIn("LOCAL-UPLOAD-CONTENT", self.receipts[1]["body"])
        self.assertEqual(parse_qs(self.receipts[2]["body"]), {"note": ["LOCAL-FORM-CONTENT"]})
        self.assertEqual(len(self.judge.requests), 3)
        self.assertEqual(len(self.upstream_requests), 3)
        self.assertEqual(len(self.actions()), 3)
        for action in self.actions():
            self.assertEqual(action["status"], "acknowledged")
            self.assertEqual(action["execution_mode"], "automatic")
            self.assertEqual(action["authorization_source"], "frozen_task_scope")
            self.assertIsNone(action["approved_at"])
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 3)

    def test_outside_scope_remains_pending_without_receipt_or_budget_use(self):
        self.run_calls(fixtures.tool_call("host-outside", "yuanxingmu_request_action", self.proposal(target="outside")))
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.actions()[0]["status"], "pending")
        self.assertIn("automatic_target_not_granted", json.dumps(self.upstream_requests[-1]["body"]["messages"]))
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 0)

    def test_three_budget_denials_return_to_model_and_allow_final_answer(self):
        self.responses.extend([
            fixtures.handoff_response(),
            fixtures.completion(*(fixtures.tool_call(f"host-budget-used-{index}", "yuanxingmu_request_action",
                                                    self.proposal(f"allowed-{index}")) for index in range(3))),
            *(fixtures.completion(fixtures.tool_call(f"host-budget-denied-{index}", "yuanxingmu_request_action",
                                                    self.proposal(f"denied-{index}"))) for index in range(3)),
            fixtures.final_response()])
        result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(len(self.receipts), 3)
        # Guards inspect all six requests before the automatic budget decision.
        self.assertEqual(len(self.judge.requests), 6)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 3)
        denials = [json.loads(item["content"]) for item in self.upstream_requests[-1]["body"]["messages"]
                   if item.get("role") == "tool" and item.get("tool_call_id", "").startswith("host-budget-denied-")]
        self.assertEqual(len(denials), 3)
        self.assertTrue(all(item["reason"] == "automatic_attempt_budget_exhausted" for item in denials))

    def test_files_and_forged_host_arguments_are_rejected_before_broker(self):
        overwrite = {"proposal": {"kind": "overwrite", "target_id": "replace", "payload": {"content": "changed"}}}
        delete = {"proposal": {"kind": "delete", "target_id": "remove", "payload": {}}}
        forged = {**self.proposal(), "approved": True, "request_key": "model-selected",
                  "action_automation": self.scope, "timeout_seconds": 120}
        nested = self.proposal()
        nested["proposal"]["payload"]["url"] = "http://127.0.0.1:1/unregistered"
        for index, arguments in enumerate((overwrite, delete, forged, nested)):
            with self.subTest(case=index):
                self.responses.extend([fixtures.handoff_response(f"host-invalid-handoff-{index}"),
                                       fixtures.completion(fixtures.tool_call(
                                           f"host-invalid-{index}", "yuanxingmu_request_action", arguments))])
                before = self.events()
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session({**self.config, "prompt": f"Invalid automatic request {index}.",
                                              "checkpoint": str(self.root / f"invalid-{index}.json")})
                self.assertEqual(self.events(), before)
        self.assertEqual((self.host_files / "report.txt").read_text(), "ORIGINAL-REPORT")
        self.assertEqual((self.host_files / "delete.txt").read_text(), "ORIGINAL-KEEP")
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.judge.requests, [])

    def test_guard_block_and_revocation_override_automatic_runtime(self):
        blocked_judge = _JudgeFixture([_answer("block")])
        self.addCleanup(blocked_judge.close)
        self.guards.judge = JudgeConfig(blocked_judge.url, "synthetic-judge")
        self.run_calls(fixtures.tool_call("host-guard-block", "yuanxingmu_request_action", self.proposal()),
                       checkpoint=str(self.root / "guard-block.json"))
        self.assertEqual(len(blocked_judge.requests), 1)
        self.assertEqual(self.receipts, [])
        self.broker.revoke(self.task)
        self.responses.extend([fixtures.handoff_response("host-revoked-handoff"), fixtures.completion(
            fixtures.tool_call("host-after-revoke", "yuanxingmu_request_action", self.proposal())),
            fixtures.final_response()])
        with self.assertRaisesRegex(RuntimeError, "host_stopped"):
            self.runtime.run_session({**self.config, "prompt": "Try after task revocation.",
                                      "checkpoint": str(self.root / "revoked.json")})
        self.assertEqual(len(self.responses), 1)
        self.assertEqual(len(blocked_judge.requests), 1)
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])

    def test_review_and_automatic_request_have_separate_nonce_namespaces(self):
        nonce = "host-same-correlation-nonce"
        self.run_calls(fixtures.tool_call(nonce, "yuanxingmu_propose_action", self.proposal()),
                       checkpoint=str(self.root / "review.json"))
        first_id = self.actions()[0]["id"]
        self.assertEqual(self.actions()[0]["status"], "pending")
        self.assertEqual(self.receipts, [])
        self.run_calls(fixtures.tool_call(nonce, "yuanxingmu_request_action", self.proposal()),
                       prompt="Request the authorized automatic action.", checkpoint=str(self.root / "automatic.json"))
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 2)
        states = {row["id"]: row["status"] for row in self.actions()}
        self.assertEqual(states[first_id], "pending")
        self.assertEqual(set(states.values()), {"pending", "acknowledged"})

    def test_lost_receipt_stops_batch_resume_and_worker_checkpoint_rebuild(self):
        self.drop_receipts = True
        later = {"proposal": {"kind": "upload", "target_id": "upload",
                              "payload": {"filename": "later.txt", "content": "MUST-NOT-SEND"}}}
        response = fixtures.completion(
            fixtures.tool_call("host-unconfirmed-first", "yuanxingmu_request_action", self.proposal()),
            fixtures.tool_call("host-unconfirmed-later", "yuanxingmu_request_action", later))
        self.responses.extend([fixtures.handoff_response(), response, fixtures.final_response()])
        first_id = None
        for phase, resume in (("initial", False), ("resume", True), ("worker-state-loss", False)):
            with self.subTest(phase=phase):
                if phase == "worker-state-loss":
                    # Only worker state is removed. Host journal/session/nonces remain.
                    Path(self.config["checkpoint"]).unlink()
                with self.assertRaisesRegex(RuntimeError, "unconfirmed"):
                    self.runtime.run_session({**self.config, "resume": resume})
                self.assertEqual(len(self.upstream_requests), 2)
                self.assertEqual(len(self.responses), 1)
                self.assertEqual(len(self.receipts), 1)
                self.assertEqual(self.receipts[0]["path"], "/message")
                self.assertIn("LOCAL-OPENAI-AGENTS-PROGRESS", self.receipts[0]["body"])
                self.assertEqual(len(self.actions()), 1)
                self.assertEqual(self.actions()[0]["status"], "unconfirmed")
                first_id = first_id or self.actions()[0]["id"]
                self.assertEqual(self.actions()[0]["id"], first_id)
                self.assertEqual(len(self.judge.requests), 1)
                self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)
                self.assertIsInstance(json.loads(Path(self.config["checkpoint"]).read_bytes()), dict)
        originals = {row["raw"] for row in self.upstream_requests}
        self.assertEqual(len(originals), 2)
        self.assertTrue(all(row["raw"] in originals for row in self.requests))


if __name__ == "__main__":
    unittest.main()
