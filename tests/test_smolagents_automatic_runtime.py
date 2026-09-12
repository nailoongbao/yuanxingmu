"""Automatic scopes in real smolagents loops, with Unix RPC and local receipts.

Both model and judge replies are deterministic local fixtures. This file tests
the SDK/Broker execution boundary, not external inference or process isolation.
"""
from copy import deepcopy
from http.server import ThreadingHTTPServer
import hashlib
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from yuanxingmu.actions import ActionTarget
from yuanxingmu.adapters import NativeTools
from yuanxingmu.broker import Broker, Resource
from yuanxingmu.guards import GuardPolicy, Guards, JudgeConfig
import test_smolagents_runtime as fixtures
from test_yuanxingmu_guards import _JudgeFixture, _answer


@unittest.skipUnless(sys.platform.startswith("linux") and fixtures.HAS_SDK,
                     "Requires Linux and the pinned smolagents SDK environment")
class SmolagentsAutomaticRuntimeTests(unittest.TestCase):
    # Reuse setup helpers, without inheriting or importing another TestCase's
    # test methods into this module's discovery result.
    actions = fixtures.SmolagentsRuntimeTests.actions
    sdk_message = staticmethod(fixtures.SmolagentsRuntimeTests.sdk_message)
    sdk_step = staticmethod(fixtures.SmolagentsRuntimeTests.sdk_step)
    dispatch = fixtures.SmolagentsRuntimeTests.dispatch

    def start_server(self, server):
        if isinstance(server, ThreadingHTTPServer):
            self.effect_receiver = server
        fixtures.SmolagentsRuntimeTests.start_server(self, server)

    def setUp(self):
        fixtures.SmolagentsRuntimeTests.setUp(self)
        receiver_url = self.broker.action_targets["chat"].url.rsplit("/", 1)[0]
        self.broker.close()
        self.judge = _JudgeFixture()
        self.addCleanup(self.judge.close)
        self.guard_events = []
        self.guards = Guards(GuardPolicy("Send progress to the authorized internal team; keep other actions for review."),
                             JudgeConfig(self.judge.url, "synthetic-judge"), audit=self.guard_events.append)
        self.host_files = self.root / "host-files"
        self.host_files.mkdir()
        (self.host_files / "report.txt").write_text("ORIGINAL-REPORT", encoding="utf-8")
        (self.host_files / "delete.txt").write_text("ORIGINAL-KEEP", encoding="utf-8")
        targets = {
            "chat": ActionTarget("message", "Authorized team", url=receiver_url + "/message"),
            "outside": ActionTarget("message", "Outside scope", url=receiver_url + "/outside"),
            "upload": ActionTarget("upload", "Authorized upload", url=receiver_url + "/upload"),
            "form": ActionTarget("form", "Authorized form", url=receiver_url + "/form", form_fields=("note",)),
            "replace": ActionTarget("overwrite", "Host report", workspace=self.host_files, relative_path="report.txt"),
            "remove": ActionTarget("delete", "Host file", workspace=self.host_files, relative_path="delete.txt"),
        }
        self.scope = {"version": 1, "max_attempts": 3, "max_total_body_bytes": 65536,
                      "targets": {name: {"accepted_labels": ["private"], "max_body_bytes": 8192}
                                  for name in ("chat", "upload", "form")}}
        self.broker = Broker(self.root / "automatic-state", {"note": Resource(self.root / "note.txt", ("private",))}, {},
                             guards=self.guards, action_targets=targets, action_automation=self.scope,
                             input_containment=True, reviewed_mail=True)
        self.addCleanup(self.broker.close)
        self.task = self.broker.create_task(initial_labels=["private"])
        endpoint = self.broker.serve(self.task, self.root / "automatic.sock")
        self.client = NativeTools(str(endpoint), "host-automatic-session")
        self.config.update(session_id=self.client.session_id, task_id=self.task,
                           broker_socket=str(endpoint), automatic_actions=True)

    @staticmethod
    def proposal(body="LOCAL-AUTOMATIC-PROGRESS", *, target="chat"):
        return {"proposal": {"kind": "message", "target_id": target, "payload": {"body": body}}}

    def events(self):
        path = self.root / "automatic-state/broker-events.jsonl"
        return path.read_bytes() if path.exists() else b""

    def agent(self, *, automatic_actions=True):
        return self.runtime.ProtectedToolCallingAgent(client=self.client,
                model=self.runtime.BridgeModel(deepcopy(self.config)), max_steps=8,
                automatic_actions=automatic_actions)

    def run_calls(self, *calls, checkpoint="checkpoint.json", **changes):
        self.responses.extend([fixtures.completion(*calls), fixtures.final_response()])
        result = self.runtime.run_session({**self.config, "checkpoint": str(self.root / checkpoint), **changes})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        return result

    def drop_receipt_after_body(self):
        def receive_without_ack(handler):
            body = handler.rfile.read(int(handler.headers["Content-Length"]))
            self.receipts.append({"path": handler.path, "body": body.decode("utf-8")})
            handler.close_connection = True
            handler.connection.shutdown(socket.SHUT_RDWR)

        receiver = patch.object(self.effect_receiver.RequestHandlerClass, "do_POST", receive_without_ack)
        receiver.start()
        self.addCleanup(receiver.stop)

    def unconfirmed_calls(self):
        return (
            fixtures.tool_call("host-unconfirmed-first", "yuanxingmu_request_action", self.proposal()),
            fixtures.tool_call("host-unconfirmed-later", "yuanxingmu_request_action",
                               {"proposal": {"kind": "upload", "target_id": "upload",
                                             "payload": {"filename": "later.txt", "content": "MUST-NOT-SEND"}}}),
        )

    def assert_one_unconfirmed_effect(self):
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(self.receipts[0]["path"], "/message")
        self.assertIn("LOCAL-AUTOMATIC-PROGRESS", self.receipts[0]["body"])
        actions = self.actions()
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["status"], "unconfirmed")
        self.assertEqual(len(self.judge.requests), 1)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)
        return actions[0]["id"]

    def run_unconfirmed(self, response, *, resume=False):
        next_response = fixtures.final_response()
        self.responses.extend([deepcopy(response), next_response])
        model_calls = len(self.requests)
        with self.assertRaisesRegex(RuntimeError, "^sdk_action_unconfirmed$"):
            self.runtime.run_session({**self.config, "resume": resume})
        self.assertEqual(len(self.requests), model_calls + 1)
        self.assertEqual(list(self.responses), [next_response])
        self.responses.clear()
        self.assert_one_unconfirmed_effect()
        saved = json.loads(Path(self.config["checkpoint"]).read_bytes())
        self.assertEqual(saved["status"], "running")
        self.assertIsNone(saved["answer"])
        self.assertEqual(saved["turn_steps"], 0)
        self.assertEqual(saved["completed_tools"], {})
        self.assertEqual(saved["pending"]["request"], self.requests[-1]["body"])
        self.assertEqual(saved["pending"]["response"], response)
        return saved

    def test_automatic_tool_is_absent_by_default_and_when_explicitly_disabled(self):
        from smolagents.utils import AgentError
        for explicit in (False, True):
            with self.subTest(explicit=explicit):
                config = {**self.config, "checkpoint": str(self.root / f"disabled-{explicit}.json")}
                if explicit:
                    config["automatic_actions"] = False
                else:
                    del config["automatic_actions"]
                self.responses.append(fixtures.completion(fixtures.tool_call(
                    "host-disabled", "yuanxingmu_request_action", self.proposal())))
                before = self.events()
                with self.assertRaises((ValueError, RuntimeError, AgentError)):
                    self.runtime.run_session(config)
                self.assertEqual(self.events(), before)
                names = {item["function"]["name"] for item in self.requests[-1]["body"]["tools"]}
                self.assertNotIn("yuanxingmu_request_action", names)
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 0)

    def test_enabled_agent_run_sends_once_under_frozen_scope_and_real_guard(self):
        self.run_calls(fixtures.tool_call("host-auto-message", "yuanxingmu_request_action", self.proposal()))
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(self.receipts[0]["path"], "/message")
        self.assertIn("LOCAL-AUTOMATIC-PROGRESS", self.receipts[0]["body"])
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(len(self.judge.requests), 1)
        candidate = json.loads(self.judge.requests[0]["body"]["messages"][1]["content"])["candidate"]
        self.assertEqual(candidate["tool"], "yuanxingmu_request_action")
        action = self.actions()[0]
        self.assertEqual(action["status"], "acknowledged")
        self.assertEqual(action["execution_mode"], "automatic")
        self.assertEqual(action["authorization_source"], "frozen_task_scope")
        self.assertIsNone(action["approved_at"])
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_upload_and_form_use_registered_targets_and_real_local_receipts(self):
        upload = {"proposal": {"kind": "upload", "target_id": "upload",
                               "payload": {"filename": "progress.txt", "content": "LOCAL-UPLOAD-CONTENT"}}}
        form = {"proposal": {"kind": "form", "target_id": "form",
                             "payload": {"fields": [{"name": "note", "value": "LOCAL-FORM-CONTENT"}]}}}
        self.run_calls(fixtures.tool_call("host-auto-upload", "yuanxingmu_request_action", upload),
                       fixtures.tool_call("host-auto-form", "yuanxingmu_request_action", form))
        self.assertEqual([row["path"] for row in self.receipts], ["/upload", "/form"])
        self.assertIn("LOCAL-UPLOAD-CONTENT", self.receipts[0]["body"])
        self.assertEqual(parse_qs(self.receipts[1]["body"]), {"note": ["LOCAL-FORM-CONTENT"]})
        self.assertEqual(len(self.actions()), 2)
        self.assertTrue(all(row["status"] == "acknowledged" for row in self.actions()))
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 2)

    def test_outside_scope_stays_pending_without_a_receipt_or_budget_use(self):
        self.run_calls(fixtures.tool_call("host-outside-scope", "yuanxingmu_request_action",
                                        self.proposal(target="outside")))
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.actions()[0]["status"], "pending")
        self.assertIn("automatic_target_not_granted", json.dumps(self.requests[-1]["body"]["messages"]))
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 0)

    def test_file_actions_and_forged_host_fields_are_rejected_before_broker(self):
        from smolagents.utils import AgentError
        overwrite = {"proposal": {"kind": "overwrite", "target_id": "replace", "payload": {"content": "changed"}}}
        delete = {"proposal": {"kind": "delete", "target_id": "remove", "payload": {}}}
        forged = {**self.proposal(), "approved": True, "request_key": "model-selected",
                  "action_automation": self.scope}
        nested = self.proposal()
        nested["proposal"]["payload"]["url"] = "http://127.0.0.1:1/unregistered"
        for index, arguments in enumerate((overwrite, delete, forged, nested)):
            with self.subTest(case=index):
                self.responses.append(fixtures.completion(fixtures.tool_call(
                    f"host-invalid-{index}", "yuanxingmu_request_action", arguments)))
                before, model_calls = self.events(), len(self.requests)
                with self.assertRaises((ValueError, RuntimeError, AgentError)):
                    self.runtime.run_session({**self.config, "checkpoint": str(self.root / f"invalid-{index}.json")})
                self.assertEqual(len(self.requests), model_calls + 1)
                self.assertEqual(self.events(), before)
        self.assertEqual((self.host_files / "report.txt").read_text(), "ORIGINAL-REPORT")
        self.assertEqual((self.host_files / "delete.txt").read_text(), "ORIGINAL-KEEP")
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.judge.requests, [])

    def test_guard_block_and_revocation_override_enabled_runtime(self):
        blocked_judge = _JudgeFixture([_answer("block")])
        self.addCleanup(blocked_judge.close)
        self.guards.judge = JudgeConfig(blocked_judge.url, "synthetic-judge")
        self.run_calls(fixtures.tool_call("host-guard-block", "yuanxingmu_request_action", self.proposal()),
                       checkpoint="guard-block.json")
        self.assertEqual(len(blocked_judge.requests), 1)
        self.assertEqual(self.receipts, [])
        self.broker.revoke(self.task)
        self.run_calls(fixtures.tool_call("host-after-revoke", "yuanxingmu_request_action", self.proposal()),
                       checkpoint="revoked.json")
        self.assertEqual(len(blocked_judge.requests), 1)
        self.assertEqual(self.receipts, [])
        self.assertEqual(self.actions(), [])

    def test_review_only_proposal_and_automatic_request_have_separate_nonce_namespaces(self):
        nonce = "host-same-correlation-nonce"
        self.run_calls(fixtures.tool_call(nonce, "yuanxingmu_propose_action", self.proposal()),
                       checkpoint="review-only.json")
        first_id = self.actions()[0]["id"]
        self.assertEqual(self.actions()[0]["status"], "pending")
        self.assertEqual(self.receipts, [])
        self.run_calls(fixtures.tool_call(nonce, "yuanxingmu_request_action", self.proposal()),
                       checkpoint="automatic.json")
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 2)
        states = {row["id"]: row["status"] for row in self.actions()}
        self.assertEqual(states[first_id], "pending")
        self.assertEqual(set(states.values()), {"pending", "acknowledged"})

    def test_resume_after_host_execution_before_checkpoint_does_not_repeat_effect(self):
        response = fixtures.completion(fixtures.tool_call(
            "host-auto-recover", "yuanxingmu_request_action", self.proposal()))
        self.responses.append(response)
        save = self.runtime._Checkpoint.save
        interrupted = []

        def crash_before_save(checkpoint):
            if checkpoint.value["completed_tools"] and not interrupted:
                interrupted.append(True)
                raise RuntimeError("simulated_worker_loss_after_host_execution")
            return save(checkpoint)

        with patch.object(self.runtime._Checkpoint, "save", crash_before_save):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(len(self.receipts), 1)
        first_id = self.actions()[0]["id"]
        self.assertEqual(self.actions()[0]["status"], "acknowledged")
        saved = json.loads(Path(self.config["checkpoint"]).read_bytes())
        self.assertEqual(saved["completed_tools"], {})
        self.assertIsNotNone(saved["pending"]["response"])
        judge_calls = len(self.judge.requests)
        self.responses.extend([response, fixtures.final_response()])
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["answer"], fixtures.COMPLETE)
        self.assertEqual(self.requests[0]["raw"], self.requests[1]["raw"])
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.actions()[0]["id"], first_id)
        self.assertEqual(len(self.judge.requests), judge_calls)
        self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)

    def test_unconfirmed_action_stops_batch_and_normal_resume(self):
        self.drop_receipt_after_body()
        response = fixtures.completion(*self.unconfirmed_calls())
        saved = self.run_unconfirmed(response)
        first_id = self.actions()[0]["id"]
        resumed = self.run_unconfirmed(response, resume=True)
        self.assertEqual(resumed, saved)
        self.assertEqual(self.requests[0]["raw"], self.requests[1]["raw"])
        self.assertEqual(self.assert_one_unconfirmed_effect(), first_id)

    def test_prior_unknown_with_new_nonce_stops_remaining_batch_on_each_resume(self):
        self.drop_receipt_after_body()
        initial = self.runtime.request("request_action", socket_path=self.config["broker_socket"],
            request_key="earlier-unknown-effect", proposal=self.proposal()["proposal"])
        self.assertEqual(initial["status"], "unconfirmed")
        response = fixtures.completion(*self.unconfirmed_calls())
        results, original_request = [], self.runtime.request

        def record_request(operation, **kwargs):
            result = original_request(operation, **kwargs)
            if operation == "request_action":
                results.append(result)
            return result

        for resume in (False, True, True):
            self.responses.append(response)
            with patch.object(self.runtime, "request", record_request):
                with self.assertRaisesRegex(RuntimeError, "sdk_action_unconfirmed"):
                    self.runtime.run_session({**self.config, "resume": resume})
            self.assertEqual(results[-1]["reason"], "automatic_prior_outcome_unconfirmed")
            self.assertEqual(results[-1]["status"], "pending")
            self.assertEqual(len(self.actions()), 2)
            self.assertEqual(len(self.receipts), 1)
            self.assertEqual(self.broker.automation.describe(self.task)["attempts_used"], 1)
            self.assertEqual(len(self.judge.requests), 2)
        self.assertEqual(len(results), 3)

    def test_unconfirmed_action_stops_after_worker_checkpoint_loss(self):
        self.drop_receipt_after_body()
        response = fixtures.completion(*self.unconfirmed_calls())
        self.run_unconfirmed(response)
        first_id = self.actions()[0]["id"]
        # Rebuild only worker state. The host session and original call nonces
        # remain intact; this does not model losing the host dispatch journal.
        Path(self.config["checkpoint"]).unlink()
        self.run_unconfirmed(response)
        self.assertEqual(self.requests[0]["raw"], self.requests[1]["raw"])
        self.assertEqual(self.assert_one_unconfirmed_effect(), first_id)

    def test_old_uncertain_tool_cache_cannot_resume_or_return_a_saved_answer(self):
        self.drop_receipt_after_body()
        calls = self.unconfirmed_calls()
        saved = self.run_unconfirmed(fixtures.completion(*calls))
        first_id = self.actions()[0]["id"]
        nonce, name = calls[0]["id"], calls[0]["function"]["name"]
        arguments = json.loads(calls[0]["function"]["arguments"])
        agent = self.agent()
        # Obtain the actual deduplicated Broker reply without the runtime's
        # outcome gate, then model a cache saved by an older worker.
        with agent.invocations.bind(nonce):
            broker_result = json.loads(agent.tools[name](**arguments))
        self.assertEqual(broker_result["status"], "unconfirmed")
        signature = hashlib.sha256(self.runtime._bytes([name, arguments])).hexdigest()
        checkpoint = Path(self.config["checkpoint"])
        for field in ("status", "outcome"):
            for outcome in ("unconfirmed", "executing"):
                cached_result = {key: value for key, value in broker_result.items()
                                 if key not in {"status", "outcome"}}
                cached_result[field] = outcome
                completed = {nonce: {"signature": signature, "result": json.dumps(cached_result)}}
                with self.subTest(field=field, outcome=outcome, recovery="agent_cache"):
                    agent.completed_tools = deepcopy(completed)
                    with self.assertRaisesRegex(RuntimeError, "^sdk_action_unconfirmed$"):
                        self.dispatch(agent, *calls)
                for status in ("running", "completed"):
                    with self.subTest(field=field, outcome=outcome, recovery=status):
                        old = {**deepcopy(saved), "completed_tools": deepcopy(completed), "status": status}
                        if status == "completed":
                            old.update(pending=None, answer=fixtures.COMPLETE, turn_steps=1)
                        raw = json.dumps(old).encode("utf-8")
                        checkpoint.write_bytes(raw)
                        with self.assertRaisesRegex(RuntimeError, "^sdk_action_unconfirmed$"):
                            self.runtime.run_session({**self.config, "resume": True})
                        self.assertEqual(checkpoint.read_bytes(), raw)
                        self.assertEqual(len(self.requests), 1)
                        self.assertEqual(self.assert_one_unconfirmed_effect(), first_id)


if __name__ == "__main__":
    unittest.main()
