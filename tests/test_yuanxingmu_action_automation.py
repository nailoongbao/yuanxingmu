"""Automatic scope invariants with real localhost effects, no model calls."""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from email import policy as email_policy
from email.parser import BytesParser
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

from yuanxingmu.action_automation import ActionAutomation, AutomaticActionPolicy
from yuanxingmu.actions import Actions, ActionTarget
from yuanxingmu.authority import Authority, AuthorizationError
from yuanxingmu.quarantine import Quarantine
from tests.test_yuanxingmu_actions import Receiver


class AutomaticActionsTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.authority = Authority(self.directory / "authority.sqlite3")
        self.addCleanup(self.authority.close)
        self.receiver = Receiver()
        self.addCleanup(self.receiver.close)
        self.targets = {
            "team": ActionTarget("message", "固定内部群", port=self.receiver.port),
            "docs": ActionTarget("upload", "固定资料库", port=self.receiver.port),
            "form": ActionTarget("form", "固定表单", port=self.receiver.port, form_fields=("name", "note")),
            "other": ActionTarget("message", "只允许人工确认的目标", port=self.receiver.port),
        }
        self.store = Actions(self.authority, self.targets)
        self.config = {"version": 1, "max_attempts": 8, "max_total_body_bytes": 8192,
                       "targets": {key: {"accepted_labels": ["private"], "max_body_bytes": 2048}
                                   for key in ("team", "docs", "form")}}
        self.make_family()

    def make_family(self, *, config=None, initial_labels=None, bind=True, targets=None):
        self.policy = AutomaticActionPolicy.from_config(config or self.config, targets or self.targets)
        self.task = self.authority.create_root({"sensitive": ["restricted"]}, self.policy.destination_labels(),
            initial_labels=["private"] if initial_labels is None else initial_labels)
        self.automation = ActionAutomation(self.authority, targets or self.targets, self.policy)
        if bind:
            self.automation.bind_task(self.task)

    @staticmethod
    def proposal(kind="message", target="team", payload=None):
        return {"kind": kind, "target_id": target, "payload": {"body": "范围内的信息"} if payload is None else payload}

    def request(self, key="one", proposal=None, task=None):
        proposal = proposal or self.proposal()
        return self.store.request_automatic(task or self.task, key, proposal, self.automation, checked_proposal=proposal)

    def denied(self, reason, function, *args, **kwargs):
        with self.assertRaises(AuthorizationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(reason, caught.exception.reason)

    def test_three_real_network_kinds_execute_once_with_truthful_automatic_record(self):
        proposals = [self.proposal(payload={"body": "中文消息\n第二行"}),
                     self.proposal("upload", "docs", {"filename": "report.txt", "content": "原样上传\n<&>"}),
                     self.proposal("form", "form", {"fields": {"name": "李同学", "note": "A&B=123"}})]
        for index, proposal in enumerate(proposals):
            result = self.request(str(index), proposal)
            self.assertTrue(result["started"])
            action = result["action"]
            self.assertEqual("acknowledged", action["status"])
            self.assertEqual("automatic", action["execution_mode"])
            self.assertEqual("frozen_task_scope", action["authorization_source"])
            self.assertEqual(self.policy.digest, action["authorization_sha256"])
            self.assertIsNone(action["approved_at"])
            self.assertIsNotNone(action["authorized_at"])
            self.assertFalse(self.request(str(index), proposal)["started"])
        self.assertEqual(3, len(self.receiver.received))
        message, upload, form = self.receiver.received
        self.assertEqual({"body": "中文消息\n第二行"}, json.loads(message["data"]))
        mime = BytesParser(policy=email_policy.default).parsebytes(
            b"Content-Type: " + upload["headers"]["Content-Type"].encode() + b"\r\n\r\n" + upload["data"])
        part = list(mime.iter_parts())[0]
        self.assertEqual("report.txt", part.get_filename())
        self.assertEqual("原样上传\n<&>".encode(), part.get_payload(decode=True))
        self.assertEqual({"name": ["李同学"], "note": ["A&B=123"]}, parse_qs(form["data"].decode()))
        usage = self.automation.describe(self.task)
        self.assertEqual(3, usage["attempts_used"])
        self.assertEqual(sum(len(item["data"]) for item in self.receiver.received), usage["body_bytes_used"])
        with self.authority._transaction() as db:
            attempts = db.execute("SELECT * FROM action_auto_attempts ORDER BY rowid").fetchall()
        self.assertEqual([item["headers"]["X-Yuanxingmu-Request"] for item in self.receiver.received],
                         [row["attempt_id"] for row in attempts])

    def test_old_submit_stays_inert_and_manual_confirmation_is_not_automatic_scope(self):
        task = self.authority.create_root({}, {}, initial_labels=["private"])
        row = self.store.submit(task, "old", self.proposal())
        self.assertEqual([], self.receiver.received)
        result = self.store.commit(task, row["id"], row["revision"], row["digest"])
        self.assertEqual("manual", result["action"]["execution_mode"])
        self.assertEqual("host_confirmation", result["action"]["authorization_source"])
        self.assertIsNotNone(result["action"]["approved_at"])
        self.assertIsNone(result["action"]["authorization_sha256"])
        self.assertEqual(0, self.automation.describe(self.task)["attempts_used"])

    def test_private_family_cannot_send_to_public_scope_even_if_candidate_was_checked(self):
        config = deepcopy(self.config)
        for target in config["targets"].values():
            target["accepted_labels"] = []
        self.make_family(config=config)
        self.denied("destination_cannot_receive_labels", self.request)
        self.assertEqual([], self.receiver.received)
        self.assertEqual(0, self.automation.describe(self.task)["attempts_used"])
        self.assertEqual("pending", self.store.prior(self.task, "one", self.proposal())["status"])

    def test_child_read_taints_existing_siblings_and_root_before_any_new_send(self):
        child = self.authority.delegate(self.task)
        sibling = self.authority.delegate(self.task)
        self.authority.record_read(child, "sensitive")
        self.denied("destination_cannot_receive_labels", self.request, task=sibling)
        self.denied("destination_cannot_receive_labels", self.request, task=self.task)
        self.assertEqual([], self.receiver.received)

    def test_family_budget_is_shared_and_child_binding_cannot_reset_it(self):
        config = deepcopy(self.config)
        config["max_attempts"] = 1
        self.make_family(config=config)
        child = self.authority.delegate(self.task)
        self.assertTrue(self.request()["started"])
        self.assertFalse(self.automation.bind_task(child)["bound"])
        result = self.request("child", task=child)
        self.assertEqual("automatic_attempt_budget_exhausted", result["reason"])
        self.assertEqual("pending", result["action"]["status"])
        self.assertEqual(1, self.automation.describe(child)["attempts_used"])
        self.assertEqual(1, len(self.receiver.received))

    def test_child_still_needs_its_own_destination_grant(self):
        child = self.authority.delegate(self.task, destinations=[])
        result = self.request(task=child)
        self.assertEqual("destination_not_granted", result["reason"])
        self.assertEqual(0, self.automation.describe(child)["attempts_used"])
        self.assertEqual([], self.receiver.received)

    def test_child_cannot_initialize_an_unbound_family_policy(self):
        self.make_family(bind=False)
        child = self.authority.delegate(self.task)
        self.denied("automatic_scope_requires_root_creation", self.automation.bind_task, child)
        self.assertEqual("automatic_family_not_bound", self.request(task=child)["reason"])
        self.assertEqual([], self.receiver.received)

    def test_registered_but_ungranted_target_stays_pending(self):
        result = self.request(proposal=self.proposal(target="other"))
        self.assertEqual("automatic_target_not_granted", result["reason"])
        self.assertEqual("pending", result["action"]["status"])
        self.assertEqual([], self.receiver.received)

    @unittest.skipUnless(os.name == "posix", "Safe file targets require POSIX")
    def test_delete_and_overwrite_never_use_automatic_network_scope(self):
        directory = self.directory / "host-files"
        directory.mkdir(mode=0o700)
        (directory / "keep.txt").write_text("must remain", encoding="utf-8")
        for kind in ("delete", "overwrite"):
            target = ActionTarget(kind, "人工文件操作", workspace=directory, relative_path="keep.txt")
            targets = {**self.targets, "file": target}
            store = Actions(self.authority, targets)
            proposal = self.proposal(kind, "file", {} if kind == "delete" else {"content": "new"})
            result = store.request_automatic(self.task, kind, proposal, self.automation, checked_proposal=proposal)
            self.assertEqual("automatic_kind_requires_review", result["reason"])
        self.assertEqual("must remain", (directory / "keep.txt").read_text(encoding="utf-8"))
        self.assertEqual([], self.receiver.received)

    def test_limits_measure_encoded_body_not_character_count(self):
        config = deepcopy(self.config)
        config["targets"]["team"]["max_body_bytes"] = 3
        config["targets"]["form"]["max_body_bytes"] = 20
        self.make_family(config=config)
        message = self.request("text", self.proposal(payload={"body": "汉"}))
        form = self.request("form", self.proposal("form", "form", {"fields": {"name": "测试", "note": "A&B"}}))
        self.assertEqual("automatic_action_too_large", message["reason"])
        self.assertEqual("automatic_action_too_large", form["reason"])
        self.assertEqual(0, self.automation.describe(self.task)["body_bytes_used"])
        self.assertEqual([], self.receiver.received)

    def test_total_byte_limit_persists_across_different_request_keys(self):
        expected = b'{"body":"abc"}'
        config = deepcopy(self.config)
        config["max_total_body_bytes"] = len(expected)
        self.make_family(config=config)
        proposal = self.proposal(payload={"body": "abc"})
        self.assertTrue(self.request("first", proposal)["started"])
        self.assertEqual(expected, self.receiver.received[0]["data"])
        self.assertEqual("automatic_body_budget_exhausted", self.request("second", proposal)["reason"])
        self.assertEqual(1, len(self.receiver.received))

    def test_concurrent_last_budget_slot_allows_exactly_one_effect(self):
        config = deepcopy(self.config)
        config["max_attempts"] = 1
        self.make_family(config=config)
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda index: self.request(str(index)), range(10)))
        self.assertEqual(1, sum(result["started"] for result in results))
        self.assertEqual(1, len(self.receiver.received))
        self.assertEqual(1, self.automation.describe(self.task)["attempts_used"])

    def test_prior_is_read_only_and_different_content_conflicts(self):
        original = self.proposal()
        self.assertIsNone(self.store.prior(self.task, "one", original))
        row = self.store.submit(self.task, "one", original)
        before = len(self.authority.events(self.task))
        self.assertEqual(row, self.store.prior(self.task, "one", original))
        self.assertEqual(before, len(self.authority.events(self.task)))
        self.denied("action_request_conflict", self.store.prior, self.task, "one", self.proposal(payload={"body": "different"}))
        # The request helper must not turn an earlier inert prepare into an automatic send.
        self.assertFalse(self.request()["started"])
        self.assertEqual([], self.receiver.received)

    def test_two_authority_connections_share_the_last_budget_atomically(self):
        config = deepcopy(self.config)
        config["max_attempts"] = 1
        self.make_family(config=config)
        with Authority(self.directory / "authority.sqlite3") as second:
            other_store = Actions(second, self.targets)
            other_automation = ActionAutomation(second, self.targets, self.policy)
            self.assertFalse(other_automation.bind_task(self.task)["bound"])
            proposal = self.proposal()
            def run(index):
                store, manager = (self.store, self.automation) if index % 2 == 0 else (other_store, other_automation)
                return store.request_automatic(self.task, "connection-" + str(index), proposal,
                    manager, checked_proposal=proposal)
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(run, range(10)))
        self.assertEqual(1, sum(result["started"] for result in results))
        self.assertEqual(1, len(self.receiver.received))
        self.assertEqual(1, self.automation.describe(self.task)["attempts_used"])

    def test_checked_candidate_cannot_be_swapped_and_worker_cannot_supply_scope(self):
        proposal = self.proposal()
        row = self.store.submit(self.task, "one", proposal)
        self.denied("automatic_checked_candidate_changed", self.store.commit_automatic,
            self.task, row["id"], row["revision"], row["digest"], self.automation,
            checked_proposal=self.proposal(payload={"body": "different"}))
        self.denied("invalid_action_proposal", self.store.submit, self.task, "forged",
                    {**proposal, "authorized": True})
        self.assertEqual(0, self.automation.describe(self.task)["attempts_used"])
        self.assertEqual([], self.receiver.received)

    def test_manually_edited_version_cannot_reuse_prior_model_check(self):
        proposal = self.proposal()
        row = self.store.submit(self.task, "one", proposal)
        edited = self.proposal(payload={"body": "人工改过的内容"})
        row = self.store.edit(self.task, row["id"], row["revision"], row["digest"], edited)
        result = self.store.commit_automatic(self.task, row["id"], row["revision"], row["digest"],
                                              self.automation, checked_proposal=edited)
        self.assertEqual("automatic_edited_action_requires_review", result["reason"])
        self.assertEqual(2, self.store.prior(self.task, "one", proposal)["revision"])
        self.assertEqual([], self.receiver.received)

    def test_changed_scope_or_target_cannot_expand_existing_task(self):
        config = deepcopy(self.config)
        config["max_attempts"] += 1
        changed = AutomaticActionPolicy.from_config(config, self.targets)
        changed_automation = ActionAutomation(self.authority, self.targets, changed)
        self.denied("automatic_task_scope_changed", changed_automation.bind_task, self.task)
        targets = {**self.targets, "team": ActionTarget("message", "更换目标", url=self.receiver.url("/new"))}
        with self.assertRaisesRegex(ValueError, "automatic_action_target_binding_changed"):
            ActionAutomation(self.authority, targets, self.policy)
        changed_store = Actions(self.authority, targets)
        row = changed_store.submit(self.task, "changed", self.proposal())
        self.denied("automatic_action_target_binding_changed", changed_store.commit_automatic,
            self.task, row["id"], row["revision"], row["digest"], self.automation, checked_proposal=self.proposal())
        self.assertEqual([], self.receiver.received)

    def test_destination_label_registry_must_match_frozen_policy(self):
        with self.authority._transaction() as db:
            db.execute("UPDATE authority_destinations SET labels=? WHERE destination_id='action:team'", ('["private","restricted"]',))
        self.denied("automatic_destination_binding_changed", self.request)
        self.assertEqual([], self.receiver.received)

    def test_pause_and_revocation_reject_pending_and_consumed_replay_never_resends(self):
        proposal = self.proposal()
        consumed = self.request()["action"]
        self.authority.revoke(self.task)
        result = self.store.commit_automatic(self.task, consumed["id"], consumed["revision"], consumed["digest"],
                                               self.automation, checked_proposal=proposal)
        self.assertFalse(result["started"])
        self.denied("task_revoked", self.request, "new")
        self.make_family()
        row = self.store.submit(self.task, "paused", proposal)
        Quarantine(self.authority).pause(self.task, layer="input", code="fixture_pause", reason="Synthetic pause")
        self.denied("task_paused", self.store.commit_automatic, self.task, row["id"], row["revision"], row["digest"],
                    self.automation, checked_proposal=proposal)
        self.assertEqual(1, len(self.receiver.received))

    def test_unconfirmed_transport_is_counted_and_never_retried(self):
        targets = {**self.targets, "team": ActionTarget("message", "响应丢失的固定端点", url=self.receiver.url("/lost"))}
        self.store = Actions(self.authority, targets)
        config = deepcopy(self.config)
        config["max_attempts"] = 8
        self.make_family(config=config, targets=targets)
        first = self.request()
        self.assertEqual("unconfirmed", first["action"]["status"])
        self.assertFalse(self.request()["started"])
        self.assertEqual("automatic_prior_outcome_unconfirmed", self.request("second")["reason"])
        child = self.authority.delegate(self.task)
        self.assertEqual("automatic_prior_outcome_unconfirmed", self.request("child-retry", task=child)["reason"])
        self.assertEqual(1, self.automation.describe(child)["attempts_used"])
        self.assertEqual(7, self.automation.describe(child)["attempts_remaining"])
        self.assertEqual(1, len(self.receiver.received))

    def test_unknown_effect_remains_pending_for_new_key_after_restart(self):
        targets = {**self.targets, "team": ActionTarget("message", "响应丢失的固定端点", url=self.receiver.url("/lost"))}
        self.store = Actions(self.authority, targets)
        self.make_family(targets=targets)
        self.assertEqual("unconfirmed", self.request()["action"]["status"])
        self.authority.close()
        self.authority = Authority(self.directory / "authority.sqlite3")
        self.addCleanup(self.authority.close)
        self.store = Actions(self.authority, targets)
        self.store.recover()
        self.automation = ActionAutomation(self.authority, targets, self.policy)
        child = self.authority.delegate(self.task)
        result = self.request("after-restart", task=child)
        self.assertEqual("automatic_prior_outcome_unconfirmed", result["reason"])
        self.assertEqual("pending", result["action"]["status"])
        self.assertIsNone(result["action"]["attempt_id"])
        self.assertEqual(1, self.automation.describe(child)["attempts_used"])
        self.assertEqual(1, len(self.receiver.received))

    def test_manual_unknown_uses_edited_current_proposal_not_original_request_digest(self):
        targets = {**self.targets, "team": ActionTarget("message", "响应丢失的固定端点", url=self.receiver.url("/lost"))}
        self.store = Actions(self.authority, targets)
        self.make_family(targets=targets)
        original = self.proposal(payload={"body": "original content never sent"})
        # CRLF is normalized before review and execution. The later LF request
        # is the same candidate despite having different original input bytes.
        edited = self.proposal(payload={"body": "approved first line\r\nsecond line"})
        row = self.store.submit(self.task, "manual", original)
        row = self.store.edit(self.task, row["id"], row["revision"], row["digest"], edited)
        outcome = self.store.commit(self.task, row["id"], row["revision"], row["digest"])
        self.assertEqual("manual", outcome["action"]["execution_mode"])
        self.assertEqual("unconfirmed", outcome["action"]["status"])
        normalized = self.proposal(payload={"body": "approved first line\nsecond line"})
        child = self.authority.delegate(self.task)
        result = self.request("auto-retry-of-manual", normalized, task=child)
        self.assertEqual("automatic_prior_outcome_unconfirmed", result["reason"])
        self.assertEqual(0, self.automation.describe(self.task)["attempts_used"])
        self.assertEqual(1, len(self.receiver.received))
        # Original pre-edit content was never sent and is a distinct action.
        self.assertTrue(self.request("distinct-original", original)["started"])
        self.assertEqual(2, len(self.receiver.received))

    def test_executing_manual_attempt_blocks_automatic_duplicate_without_budget_use(self):
        proposal = self.proposal()
        row = self.store.submit(self.task, "manual-started", proposal)
        with self.authority._lock:
            self.assertTrue(self.store._begin(self.task, row["id"], row["revision"], row["digest"])["started"])
        result = self.request("new-key", proposal)
        self.assertEqual("automatic_prior_outcome_unconfirmed", result["reason"])
        self.assertEqual(0, self.automation.describe(self.task)["attempts_used"])
        self.assertEqual([], self.receiver.received)

    def test_acknowledged_equal_content_with_new_key_remains_a_new_authorized_action(self):
        first = self.request("first")
        second = self.request("second")
        self.assertEqual("acknowledged", first["action"]["status"])
        self.assertTrue(second["started"])
        self.assertNotEqual(first["action"]["attempt_id"], second["action"]["attempt_id"])
        self.assertEqual(2, len(self.receiver.received))

    def test_crash_after_reservation_survives_restart_without_io_or_budget_refund(self):
        proposal = self.proposal()
        row = self.store.submit(self.task, "crash", proposal)
        with self.authority._lock:
            begun = self.store._begin(self.task, row["id"], row["revision"], row["digest"],
                automation=self.automation, checked_proposal=proposal)
        self.assertTrue(begun["started"])
        self.assertEqual([], self.receiver.received)
        self.authority.close()
        self.authority = Authority(self.directory / "authority.sqlite3")
        self.addCleanup(self.authority.close)
        self.store = Actions(self.authority, self.targets)
        self.assertEqual(1, self.store.recover())
        self.automation = ActionAutomation(self.authority, self.targets, self.policy)
        self.assertFalse(self.automation.bind_task(self.task)["bound"])
        result = self.store.commit_automatic(self.task, row["id"], row["revision"], row["digest"], self.automation,
                                            checked_proposal=proposal)
        self.assertFalse(result["started"])
        self.assertEqual("unconfirmed", result["action"]["status"])
        self.assertEqual(1, self.automation.describe(self.task)["attempts_used"])
        self.assertEqual([], self.receiver.received)

    def test_audit_failure_rolls_back_both_attempt_and_budget_before_io(self):
        event = self.authority._event
        def fail(db, task, operation, *args):
            if operation == "action_commit_started":
                raise OSError("Synthetic disk failure after budget reservation")
            return event(db, task, operation, *args)
        with patch.object(self.authority, "_event", side_effect=fail):
            with self.assertRaises(OSError):
                self.request()
        self.assertEqual(0, self.automation.describe(self.task)["attempts_used"])
        row = self.store.prior(self.task, "one", self.proposal())
        self.assertEqual("pending", row["status"])
        self.assertIsNone(row["attempt_id"])
        self.assertEqual([], self.receiver.received)

    def test_policy_parser_rejects_implicit_or_unbounded_authority(self):
        invalid = []
        for field, value in (("version", True), ("max_attempts", True), ("max_attempts", 0),
                             ("max_attempts", 129), ("max_total_body_bytes", -1)):
            item = deepcopy(self.config)
            item[field] = value
            invalid.append(item)
        item = deepcopy(self.config)
        item["targets"]["team"]["max_body_bytes"] = True
        invalid.append(item)
        item = deepcopy(self.config)
        item["targets"]["team"]["url"] = self.receiver.url("/model-chosen")
        invalid.append(item)
        item = deepcopy(self.config)
        item["targets"]["unknown"] = {"accepted_labels": [], "max_body_bytes": 100}
        invalid.append(item)
        for config in invalid:
            with self.subTest(config=config), self.assertRaises(ValueError):
                AutomaticActionPolicy.from_config(config, self.targets)
        mutable = self.policy.to_config()
        mutable["targets"]["team"]["accepted_labels"].append("restricted")
        self.assertEqual(["private"], self.policy.destination_labels()["action:team"])


class LegacyActionMigrationTests(unittest.TestCase):
    def test_legacy_manual_and_pending_records_migrate_without_invented_approval(self):
        with tempfile.TemporaryDirectory() as temporary, Authority(Path(temporary) / "legacy.sqlite3") as authority:
            task = authority.create_root({}, {})
            names = ("id", "task_id", "request_key", "request_digest", "kind", "target_id", "proposal_json", "target_json",
                     "before_json", "digest", "revision", "status", "attempt_id", "created_at", "updated_at", "approved_at", "finished_at", "result_json")
            expected = []
            with authority._transaction() as db:
                db.execute("CREATE TABLE reviewed_actions (" + ",".join(name + (" INTEGER" if name == "revision" else " TEXT") for name in names) + ")")
                for index, status in enumerate(("pending", "acknowledged")):
                    row = dict(zip(names, [None] * len(names)))
                    row.update(id=str(index) * 32, task_id=task, request_key=str(index), request_digest="a" * 64,
                               kind="message", target_id="team", proposal_json='{"kind":"message","target_id":"team","payload":{"body":"historical fixture"}}',
                               target_json='{"label":"historical"}', digest="b" * 64, revision=1, status=status,
                               created_at="2026-09-12T00:00:00Z", updated_at="2026-09-12T00:00:00Z")
                    if status == "acknowledged":
                        row.update(attempt_id="c" * 32, approved_at="2026-09-12T00:01:00Z", finished_at="2026-09-12T00:01:01Z",
                                   result_json='{"outcome":"acknowledged"}')
                    db.execute("INSERT INTO reviewed_actions VALUES(" + ",".join("?" for _ in names) + ")", [row[name] for name in names])
                    expected.append(row)
            Actions(authority, {})
            with authority._transaction() as db:
                migrated = db.execute("SELECT * FROM reviewed_actions ORDER BY rowid").fetchall()
            for old, row in zip(expected, migrated):
                self.assertEqual(old, {name: row[name] for name in names})
            self.assertIsNone(migrated[0]["execution_mode"])
            self.assertIsNone(migrated[0]["authorized_at"])
            self.assertEqual("manual", migrated[1]["execution_mode"])
            self.assertEqual("host_confirmation", migrated[1]["authorization_source"])
            self.assertEqual(migrated[1]["approved_at"], migrated[1]["authorized_at"])


if __name__ == "__main__":
    unittest.main()
