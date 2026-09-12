"""Real host ledgers/local receivers, synthetic source fields and judge replies.

No native Agent or external model is run. These exercise the independent data
boundary, not semantic detection accuracy. Mail transport is mocked throughout.
"""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from yuanxingmu.actions import ActionTarget
from yuanxingmu.authority import AuthorizationError
from yuanxingmu.broker import Broker, Destination, Resource
from yuanxingmu.guards import GuardPolicy, Guards, JudgeConfig
from yuanxingmu.protected_boundary import ProtectedContentError, check_candidate
from yuanxingmu.protected_data import HostProtectedData, HostResource
from tests.test_yuanxingmu_actions import Receiver
from tests.test_yuanxingmu_guards import _JudgeFixture, _answer


SOURCE = "项目AUTO19，公开报价218000元，内部底价162000元。\napi_key: SYNTHETIC-PRIVATE-KEY-ABC\n"


def protection():
    return HostProtectedData.compile({"quote": HostResource(SOURCE, hashlib.sha256(SOURCE.encode()).hexdigest())})


class ProtectedCandidateTests(unittest.TestCase):
    def test_decoded_nested_json_keys_values_and_amounts_are_checked(self):
        data = protection()
        for value in ("底价16.2万元", {"content": "162,000.00"}, {"arguments": r'{"body":"\u0031\u0036\u0032\u0030\u0030\u0030"}'},
                      {"arguments": r'{"body":"\u0031\u0036\u0032\u0030\u0030\u0030","body":"public"}'},
                      {"SYNTHETIC-PRIVATE-KEY-ABC": "value"}, {"fields": {"quote": 162000}}):
            with self.subTest(kind=type(value).__name__), self.assertRaises(ProtectedContentError) as caught:
                check_candidate(data, value)
            self.assertEqual(caught.exception.reason, "protected_value_blocked")
            self.assertNotIn("162000", str(caught.exception))
        check_candidate(data, {"public": "218000元", "order": "ORDER162000", "date": "2026-09-12"})

    def test_invalid_or_oversized_candidates_never_get_a_prefix_only_check(self):
        for candidate in (b"bytes", "A" * 262145 + "162000", {"number": float("inf")}, {1: "value"}):
            with self.assertRaises(ProtectedContentError) as caught:
                check_candidate(protection(), candidate)
            self.assertEqual(caught.exception.reason, "protected_check_failed")


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux broker and durable admission boundaries")
class ProtectedBrokerTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="yxm-fields-")))
        self.source = self.root / "source.txt"
        self.source.write_bytes(SOURCE.encode())
        self.resources = {"quote": Resource(self.source, ("private",))}
        self.data = protection()
        self.receiver = Receiver()
        self.addCleanup(self.receiver.close)
        self.targets = {"team": ActionTarget("message", "Team", port=self.receiver.port),
                        "docs": ActionTarget("upload", "Docs", port=self.receiver.port),
                        "form": ActionTarget("form", "Form", port=self.receiver.port, form_fields=("quote",))}
        self.destinations = {"internal": Destination(self.receiver.url("/send"), ("private",)),
                             "external": Destination(self.receiver.url("/external"))}
        self.policy = GuardPolicy("使用公开报价完成任务，不展示或发送底价。", alignment_enabled=False)
        self.audit = []
        self.broker = None
        self.addCleanup(lambda: self.broker.close() if self.broker is not None else None)

    def start(self, *, guards=None, automation=False):
        config = None
        if automation:
            config = {"version": 1, "max_attempts": 8, "max_total_body_bytes": 65536,
                      "targets": {key: {"accepted_labels": ["private"], "max_body_bytes": 8192} for key in self.targets}}
        self.options = {"reviewed_mail": True, "guards": guards, "action_targets": self.targets,
                        "protected_data": self.data, "action_automation": config}
        self.broker = Broker(self.root / "state", self.resources, self.destinations, **self.options)
        self.task = self.broker.create_task(initial_labels=["private"])
        return self.broker

    @staticmethod
    def proposal(body="公开报价218000元"):
        return {"kind": "message", "target_id": "team", "payload": {"body": body}}

    def guards(self, *, policy=None, answer=None):
        judge = _JudgeFixture([answer or _answer()])
        self.addCleanup(judge.close)
        return Guards(policy or self.policy, JudgeConfig(judge.url, "synthetic"), audit=self.audit.append), judge

    def assert_private_audits(self):
        raw = (self.root / "state" / "broker-events.jsonl").read_bytes()
        raw += json.dumps(self.audit).encode()
        with self.broker.authority._transaction() as db:
            raw += json.dumps([tuple(row) for row in db.execute("SELECT * FROM authority_events")]).encode()
        self.assertNotIn(b"162000", raw)
        self.assertNotIn(b"SYNTHETIC-PRIVATE-KEY-ABC", raw)

    def test_read_masks_before_input_check_and_preserves_private_label_without_pause(self):
        guard, _ = self.guards()
        broker = self.start(guards=guard)
        with patch.object(guard, "check_input", wraps=guard.check_input) as inspect:
            result = broker.dispatch(self.task, {"op": "read", "resource": "quote"})
        self.assertTrue(result["allowed"])
        self.assertIn("218000元", result["content"])
        self.assertNotIn("162000", result["content"])
        self.assertNotIn("SYNTHETIC-PRIVATE-KEY-ABC", result["content"])
        self.assertEqual(inspect.call_args.args[0], result["content"])
        self.assertFalse(broker.quarantine.status(self.task)["paused"])
        denied = broker.dispatch(self.task, {"op": "send", "destination": "external", "body": "公开报价218000元"})
        self.assertFalse(denied["allowed"])
        self.assertEqual([], self.receiver.received)
        self.assert_private_audits()

    def test_absent_disabled_and_observing_semantic_guards_do_not_allow_secret_send(self):
        for index, guard in enumerate((None, Guards(self.policy), Guards(replace(self.policy, mode="observe")))):
            with self.subTest(mode=index):
                with Broker(self.root / str(index), self.resources, self.destinations, guards=guard, protected_data=self.data) as broker:
                    task = broker.create_task(initial_labels=["private"])
                    result = broker.dispatch(task, {"op": "send", "destination": "internal", "body": "内部底价16.2万元"})
                    self.assertEqual("protected_value_blocked", result["reason"])
                    self.assertTrue(broker.quarantine.status(task)["paused"])
        self.assertEqual([], self.receiver.received)

    def test_sibling_and_restart_cannot_forget_known_values_or_pause(self):
        broker = self.start()
        child = broker.delegate(self.task)
        sibling = broker.delegate(self.task)
        self.assertTrue(broker.dispatch(child, {"op": "read", "resource": "quote"})["allowed"])
        result = broker.dispatch(sibling, {"op": "send", "destination": "internal", "body": "162000元"})
        self.assertEqual("protected_value_blocked", result["reason"])
        self.assertTrue(broker.quarantine.status(self.task)["paused"])
        broker.close()
        self.broker = Broker(self.root / "state", self.resources, self.destinations, **self.options)
        self.assertEqual("task_paused", self.broker.dispatch(child, {"op": "read", "resource": "quote"})["reason"])
        # A separate root is active, but cannot disclose the same host source.
        other = self.broker.create_task(initial_labels=["private"])
        self.assertEqual("protected_value_blocked", self.broker.dispatch(other,
            {"op": "send", "destination": "internal", "body": "162000"})["reason"])
        self.assert_private_audits()

    def test_changed_source_is_not_returned_and_empty_protection_cannot_replace_binding(self):
        broker = self.start()
        self.source.write_bytes(b"changed source")
        result = broker.dispatch(self.task, {"op": "read", "resource": "quote"})
        self.assertEqual("resource_changed", result["reason"])
        self.assertNotIn("content", result)
        self.source.write_bytes(SOURCE.encode())
        broker.close()
        with self.assertRaises(RuntimeError):
            Broker(self.root / "state", self.resources, self.destinations, **{**self.options, "protected_data": None})

    def test_automatic_public_message_upload_and_form_need_no_per_action_approval(self):
        guard, judge = self.guards(policy=replace(self.policy, alignment_enabled=True))
        broker = self.start(guards=guard, automation=True)
        proposals = [self.proposal(), {"kind": "upload", "target_id": "docs",
            "payload": {"filename": "quote.txt", "content": "公开报价218000元"}},
            {"kind": "form", "target_id": "form", "payload": {"fields": {"quote": "218000"}}}]
        for index, proposal in enumerate(proposals):
            result = broker.dispatch(self.task, {"op": "request_action", "request_key": str(index), "proposal": proposal})
            self.assertTrue(result.get("started"), result)
        self.assertEqual(3, len(self.receiver.received))
        self.assertEqual(3, broker.automation.describe(self.task)["attempts_used"])
        self.assertFalse(broker.quarantine.status(self.task)["paused"])
        self.assertNotIn("162000", json.dumps(judge.requests))
        self.assert_private_audits()

    def test_worker_secret_candidate_never_reaches_judge_or_action_ledger(self):
        guard, judge = self.guards(policy=replace(self.policy, alignment_enabled=True))
        broker = self.start(guards=guard, automation=True)
        result = broker.dispatch(self.task, {"op": "request_action", "request_key": "secret", "proposal": self.proposal("162000元")})
        self.assertEqual("protected_value_blocked", result["reason"])
        self.assertEqual([], judge.requests)
        self.assertEqual(0, broker.automation.describe(self.task)["attempts_used"])
        self.assertEqual([], self.receiver.received)
        self.assert_private_audits()

    def test_final_automatic_check_precedes_budget_and_receiver_even_if_proposal_was_prepared(self):
        guard, _ = self.guards(policy=replace(self.policy, alignment_enabled=True))
        broker = self.start(guards=guard, automation=True)
        proposal = self.proposal("162000元")
        # Host-level insertion deliberately bypasses the broker's earlier check.
        row = broker.actions.submit(self.task, "prepared", proposal)
        with self.assertRaises(ProtectedContentError):
            broker.actions.commit_automatic(self.task, row["id"], row["revision"], row["digest"],
                                            broker.automation, checked_proposal=proposal)
        self.assertEqual([], self.receiver.received)
        self.assertEqual(0, broker.automation.describe(self.task)["attempts_used"])
        current = broker.actions.get(self.task, row["id"])["action"]
        self.assertIsNone(current["attempt_id"])
        self.assertEqual("pending", current["status"])

    def test_final_manual_action_checks_edited_stored_revision_and_pauses_outside_transaction(self):
        broker = self.start()
        row = broker.actions.submit(self.task, "edit", self.proposal())
        row = broker.actions.edit(self.task, row["id"], row["revision"], row["digest"], self.proposal("162,000元"))
        with self.assertRaises(ProtectedContentError):
            broker.review_action(self.task, {"op": "action_commit", "action_id": row["id"],
                "revision": row["revision"], "digest": row["digest"], "confirm": "commit"})
        self.assertEqual([], self.receiver.received)
        self.assertTrue(broker.quarantine.status(self.task)["paused"])
        self.assertIsNone(broker.actions.get(self.task, row["id"])["action"]["attempt_id"])

    def test_mail_final_check_rejects_sensitive_subject_recipient_or_body_without_transport(self):
        broker = self.start()
        row = broker.mail.submit(self.task, "mail", {"recipient": "reader@example.test", "subject": "Quote", "body": "218000元"})
        row = broker.mail.edit(self.task, row["id"], row["revision"], row["digest"],
                              {"recipient": "reader@example.test", "subject": "162000元", "body": "Safe text"})
        with patch("yuanxingmu.broker.send_email") as transport, self.assertRaises(ProtectedContentError):
            broker.review_mail(self.task, {"op": "send", "draft_id": row["id"], "revision": row["revision"],
                "digest": row["digest"], "confirm": "send", "account_id": "fixture", "account": {
                    "host": "smtp.example.test", "port": 465, "username": "fixture", "password": "fixture",
                    "from_address": "sender@example.test"}})
        transport.assert_not_called()
        self.assertTrue(broker.quarantine.status(self.task)["paused"])
        self.assertIsNone(broker.mail.get(self.task, row["id"])["draft"]["attempt_id"])

    def test_judge_cannot_leak_a_known_value_in_its_reason_or_audit(self):
        guard, _ = self.guards(policy=replace(self.policy, alignment_enabled=True, mode="observe"),
                               answer=_answer(reason="允许，内部底价162000元。"))
        broker = self.start(guards=guard)
        result = broker.dispatch(self.task, {"op": "send", "destination": "internal", "body": "218000元"})
        self.assertEqual("protected_value_blocked", result["reason"])
        self.assertEqual([], self.receiver.received)
        self.assert_private_audits()

    def test_known_value_in_objective_is_rejected_before_judge_request(self):
        guard, judge = self.guards(policy=replace(self.policy, alignment_enabled=True, objective="不要披露162000元"))
        broker = self.start(guards=guard)
        result = broker.dispatch(self.task, {"op": "read", "resource": "quote"})
        self.assertEqual("protected_value_blocked", result["reason"])
        self.assertEqual([], judge.requests)
        self.assert_private_audits()

    def test_audit_failure_faults_protected_broker_even_without_semantic_guards(self):
        broker = self.start()
        (broker.state_dir / "broker-events.jsonl").mkdir()
        with self.assertRaises(OSError):
            broker.dispatch(self.task, {"op": "send", "destination": "internal", "body": "162000元"})
        self.assertTrue(broker._fault)
        with self.assertRaises(AuthorizationError) as caught:
            broker._require_admission(self.task)
        self.assertEqual("defense_storage_fault", caught.exception.reason)
        self.assertEqual([], self.receiver.received)
