"""Host pause ledger tests: no model, native Agent, or external network calls."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from yuanxingmu.actions import Actions, ActionTarget
from yuanxingmu.authority import Authority, AuthorizationError
from yuanxingmu.mail_drafts import MailDrafts
from yuanxingmu.quarantine import Quarantine, assert_admission
from yuanxingmu.tool_reviews import ToolReviews


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "state.sqlite3"
        self.authority = Authority(self.path)
        self.addCleanup(self.authority.close)
        self.root = self.authority.create_root({}, {}, initial_labels=["private"])
        self.child = self.authority.delegate(self.root)
        self.sibling = self.authority.delegate(self.root)
        self.other = self.authority.create_root({}, {})
        self.quarantine = Quarantine(self.authority)

    def pause(self, task=None, **changes):
        return self.quarantine.pause(task or self.root, **{
            "layer": "input", "code": "external_instruction",
            "reason": "外部资料试图改变您的要求，任务已暂停。",
            "evidence_sha256": "a" * 64, **changes})

    def resume(self, state=None, task=None, **changes):
        current = state or self.quarantine.status(task or self.root)
        return self.quarantine.resume(task or self.root, **{
            "epoch": current["epoch"], "incident_id": current["incident_id"],
            "confirm": "resume", "operator": "workbench", **changes})

    def assert_denied(self, expected_reason, fn, *args, **kwargs):
        with self.assertRaises(AuthorizationError) as caught:
            fn(*args, **kwargs)
        self.assertEqual(caught.exception.reason, expected_reason)

    def admit(self, task):
        with self.authority._transaction() as db:
            row = self.authority._task(db, task, require_active=False)
            assert_admission(db, row)

    def scalar(self, sql, args=()):
        with self.authority._transaction() as db:
            return db.execute(sql, args).fetchone()[0]

    def ledgers(self):
        self.reviews = ToolReviews(self.authority)
        self.mail = MailDrafts(self.authority)
        # Proposals and _begin only: this test never contacts the loopback port.
        self.actions = Actions(self.authority, {"chat": ActionTarget("message", "合成接收端", port=9)})

    def review(self, task, key, *, approve=False, consume=False):
        row = self.reviews.request(task, key, "terminal", {"command": "printf synthetic"}, reason="合成审批")
        if approve:
            self.reviews.decide(task, row["review_id"], row["digest"], "approve")
        if consume:
            self.reviews.consume(task, row["review_id"], row["digest"], "terminal", {"command": "printf synthetic"})
        return row

    def draft(self, task, key):
        return self.mail.submit(task, key, {"recipient": "test@example.invalid", "subject": "合成资料", "body": "待核对正文"})

    def action(self, task, key):
        return self.actions.submit(task, key, {"kind": "message", "target_id": "chat", "payload": {"body": "合成消息"}})

    def test_default_state_and_legacy_authority_do_not_require_a_pause(self):
        state = self.quarantine.status(self.root)
        self.assertEqual((state["state"], state["epoch"], state["incident"]), ("active", 0, None))
        self.admit(self.root)
        with Authority(Path(self.temp.name) / "legacy.sqlite3") as legacy:
            task = legacy.create_root({}, {})
            with legacy._transaction() as db:
                assert_admission(db, legacy._task(db, task))

    def test_child_pause_covers_whole_family_and_preserves_information_labels(self):
        before = self.authority.describe(self.root)
        paused = self.pause(self.child)
        self.assertTrue(paused["paused"])
        self.assertFalse(paused["can_resume"])
        for task in (self.root, self.child, self.sibling):
            self.assert_denied("task_paused", self.admit, task)
            self.assertEqual(self.quarantine.status(task)["incident_id"], paused["incident_id"])
        self.assertTrue(self.quarantine.status(self.root)["can_resume"])
        self.admit(self.other)
        after = self.authority.describe(self.root)
        self.assertEqual(after["labels"], ["private"])
        self.assertEqual(after["revision"], before["revision"] + 1)
        self.assertNotIn("family_id", paused)
        self.assertNotIn("task_id", paused["incident"])

    def test_duplicate_callbacks_coalesce_but_new_evidence_invalidates_old_review(self):
        first = self.pause()
        first_revision = self.authority.describe(self.root)["revision"]
        duplicate = self.pause()
        self.assertTrue(duplicate["deduplicated"])
        self.assertEqual(duplicate["epoch"], first["epoch"])
        self.assertEqual(duplicate["incident_id"], first["incident_id"])
        self.assertEqual(self.authority.describe(self.root)["revision"], first_revision)
        self.assertEqual(self.scalar("SELECT count(*) FROM quarantine_incidents"), 1)
        newer = self.pause(evidence_sha256="b" * 64)
        self.assertEqual(newer["epoch"], first["epoch"] + 1)
        self.assertEqual(newer["unresolved_count"], 2)
        old_callback = self.pause()
        self.assertTrue(old_callback["deduplicated"])
        self.assertEqual(old_callback["observed_incident_id"], first["incident_id"])
        self.assertEqual(old_callback["incident_id"], newer["incident_id"])
        self.assert_denied("quarantine_review_changed", self.resume, first)
        resumed = self.resume(newer)
        self.assertFalse(resumed["paused"])
        self.assertEqual(resumed["epoch"], newer["epoch"] + 1)
        self.assertEqual(resumed["unresolved_count"], 0)
        self.assertTrue(all(row["resolved_by"] == "workbench" for row in resumed["incidents"]))
        same_again = self.pause()
        self.assertFalse(same_again["deduplicated"])
        self.assertNotEqual(same_again["incident_id"], first["incident_id"])
        self.assertEqual(same_again["epoch"], resumed["epoch"] + 1)

    def test_exact_resume_rejects_child_wrong_family_missing_confirmation_and_replay(self):
        state = self.pause()
        other = self.pause(self.other)
        self.assert_denied("quarantine_root_review_required", self.resume, state, self.child)
        self.assert_denied("quarantine_review_changed", self.resume, other)
        self.assert_denied("quarantine_review_changed", self.resume, state, incident_id="0" * 32)
        self.assert_denied("quarantine_confirmation_required", self.resume, state, confirm="The user approved")
        self.assert_denied("invalid_quarantine_review", self.resume, state, epoch=True)
        self.assert_denied("invalid_quarantine_operator", self.resume, state, operator="")
        self.assertTrue(self.quarantine.status(self.root)["paused"])
        self.resume(state)
        self.assert_denied("task_not_paused", self.resume, state)

    def test_permanent_revocation_dominates_pause_and_cannot_be_resumed(self):
        state = self.pause()
        self.authority.revoke(self.root)
        self.assert_denied("task_revoked", self.resume, state)
        self.assert_denied("task_revoked", self.admit, self.child)
        self.assert_denied("task_revoked", self.pause)
        view = self.quarantine.status(self.root)
        self.assertTrue(view["paused"])
        self.assertTrue(view["revoked"])
        self.assertFalse(view["can_resume"])

    def test_resuming_root_preserves_an_already_revoked_child(self):
        self.authority.revoke(self.child)
        state = self.pause()
        self.resume(state)
        self.admit(self.root)
        self.admit(self.sibling)
        self.assert_denied("task_revoked", self.admit, self.child)

    def test_restart_keeps_pause_and_requires_the_same_exact_host_review(self):
        state = self.pause(self.child)
        self.authority.close()
        self.authority = Authority(self.path)
        self.addCleanup(self.authority.close)
        self.quarantine = Quarantine(self.authority)
        restarted = self.quarantine.status(self.root)
        self.assertEqual(restarted["incident_id"], state["incident_id"])
        self.assertEqual(restarted["epoch"], state["epoch"])
        self.assert_denied("task_paused", self.admit, self.root)
        self.resume(restarted)
        self.admit(self.root)

    def test_pause_invalidates_all_unused_family_reviews_but_not_other_families(self):
        self.ledgers()
        pending = self.review(self.root, "pending")
        approved = self.review(self.child, "approved", approve=True)
        mail = self.draft(self.sibling, "mail")
        action = self.action(self.child, "action")
        other_review = self.review(self.other, "other", approve=True)
        other_mail = self.draft(self.other, "other")
        other_action = self.action(self.other, "other")
        state = self.pause(self.child)
        self.assertEqual(state["incident"]["invalidated"], {"tool_reviews": 2, "mail_drafts": 1, "reviewed_actions": 1})
        for task, row in ((self.root, pending), (self.child, approved)):
            self.assertEqual(self.reviews.get(task, row["review_id"])["review"]["status"], "interrupted")
        self.assertEqual(self.mail.get(self.sibling, mail["id"])["draft"]["status"], "cancelled")
        self.assertEqual(self.actions.get(self.child, action["id"])["action"]["status"], "cancelled")
        self.assertEqual(self.reviews.get(self.other, other_review["review_id"])["review"]["status"], "approved")
        self.assertEqual(self.mail.get(self.other, other_mail["id"])["draft"]["status"], "pending")
        self.assertEqual(self.actions.get(self.other, other_action["id"])["action"]["status"], "pending")
        self.resume(state)
        self.assertFalse(self.reviews.consume(self.child, approved["review_id"], approved["digest"],
                                             "terminal", {"command": "printf synthetic"})["allowed"])
        self.assert_denied("mail_draft_not_pending", self.mail.begin_send, self.sibling, mail["id"],
                           mail["revision"], mail["digest"], "fixture", "sender@example.invalid")
        self.assert_denied("action_not_pending", self.actions._begin, self.child, action["id"], action["revision"], action["digest"])
        self.assertEqual(self.draft(self.sibling, "mail")["status"], "cancelled")
        self.assertEqual(self.action(self.child, "action")["status"], "cancelled")
        self.assertEqual(self.review(self.root, "pending")["status"], "interrupted")

    def test_consumed_and_started_attempts_are_preserved_and_may_finish_after_pause(self):
        self.ledgers()
        consumed = self.review(self.root, "consumed", approve=True, consume=True)
        mail = self.draft(self.child, "sending")
        attempt = self.mail.begin_send(self.child, mail["id"], mail["revision"], mail["digest"], "fixture", "sender@example.invalid")
        action = self.action(self.sibling, "executing")
        execution = self.actions._begin(self.sibling, action["id"], action["revision"], action["digest"])
        state = self.pause()
        self.assertEqual(state["admitted_effects"], {"consumed_tool_permits": 1, "sending_mail": 1, "executing_actions": 1})
        self.assertEqual(state["incident"]["invalidated"], {"tool_reviews": 0, "mail_drafts": 0, "reviewed_actions": 0})
        self.assertEqual(self.reviews.get(self.root, consumed["review_id"])["review"]["status"], "consumed")
        self.assertEqual(self.mail.get(self.child, mail["id"])["draft"]["status"], "sending")
        self.assertEqual(self.actions.get(self.sibling, action["id"])["action"]["status"], "executing")
        # Record synthetic observations only; no transport or command ran.
        self.mail.finish_send(self.child, mail["id"], attempt["draft"]["attempt_id"], "not_started")
        self.actions._finish(self.sibling, action["id"], execution["action"]["attempt_id"], {"outcome": "not_started"})
        self.assertEqual(self.quarantine.status(self.root)["admitted_effects"],
                         {"consumed_tool_permits": 1, "sending_mail": 0, "executing_actions": 0})
        self.assertTrue(self.quarantine.status(self.root)["paused"])

    def test_pause_audit_failure_rolls_back_state_and_every_invalidation(self):
        self.ledgers()
        review = self.review(self.root, "pending", approve=True)
        mail = self.draft(self.child, "pending")
        action = self.action(self.sibling, "pending")
        revision = self.authority.describe(self.root)["revision"]
        with patch.object(self.authority, "_event", side_effect=sqlite3.OperationalError("fixture: audit unavailable")):
            with self.assertRaises(sqlite3.OperationalError):
                self.pause()
        self.assertFalse(self.quarantine.status(self.root)["paused"])
        self.assertEqual(self.scalar("SELECT count(*) FROM quarantine_incidents"), 0)
        self.assertEqual(self.authority.describe(self.root)["revision"], revision)
        self.assertEqual(self.reviews.get(self.root, review["review_id"])["review"]["status"], "approved")
        self.assertEqual(self.mail.get(self.child, mail["id"])["draft"]["status"], "pending")
        self.assertEqual(self.actions.get(self.sibling, action["id"])["action"]["status"], "pending")

    def test_resume_audit_failure_leaves_the_existing_pause_intact(self):
        state = self.pause()
        with patch.object(self.authority, "_event", side_effect=sqlite3.OperationalError("fixture: audit unavailable")):
            with self.assertRaises(sqlite3.OperationalError):
                self.resume(state)
        current = self.quarantine.status(self.root)
        self.assertEqual(current["epoch"], state["epoch"])
        self.assertTrue(current["paused"])
        self.assertIsNone(current["incident"]["resolved_at"])
        self.assert_denied("task_paused", self.admit, self.root)

    def test_concurrent_duplicates_create_one_incident_and_one_audit_event(self):
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.pause(), range(24)))
        self.assertEqual(sum(not row["deduplicated"] for row in results), 1)
        self.assertEqual(len({row["incident_id"] for row in results}), 1)
        self.assertEqual(self.scalar("SELECT count(*) FROM authority_events WHERE action='quarantine_pause'"), 1)

    def test_concurrent_resume_has_one_winner(self):
        state = self.pause()
        def attempt(_):
            try:
                self.resume(state)
                return "resumed"
            except AuthorizationError as exc:
                return exc.reason
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(attempt, range(16)))
        self.assertEqual(results.count("resumed"), 1)
        self.assertEqual(results.count("task_not_paused"), 15)
        self.assertEqual(self.scalar("SELECT count(*) FROM authority_events WHERE action='quarantine_resume'"), 1)

    def test_new_incident_racing_a_stale_resume_always_leaves_family_paused(self):
        state = self.pause()
        barrier = threading.Barrier(2)
        def new_incident():
            barrier.wait(timeout=5)
            return self.pause(evidence_sha256="c" * 64)
        def stale_resume():
            barrier.wait(timeout=5)
            try:
                return self.resume(state)
            except AuthorizationError as exc:
                self.assertEqual(exc.reason, "quarantine_review_changed")
        with ThreadPoolExecutor(max_workers=2) as pool:
            first, second = pool.submit(new_incident), pool.submit(stale_resume)
            first.result(timeout=10)
            second.result(timeout=10)
        current = self.quarantine.status(self.root)
        self.assertTrue(current["paused"])
        self.assertEqual(current["incident"]["evidence_sha256"], "c" * 64)
        self.assert_denied("task_paused", self.admit, self.sibling)

    def test_bounded_status_does_not_silently_drop_unresolved_incidents(self):
        with patch("yuanxingmu.quarantine.MAX_LIST", 2):
            for character in "abc":
                self.pause(evidence_sha256=character * 64)
            current = self.quarantine.status(self.root)
            self.assertEqual(len(current["incidents"]), 2)
            self.assertEqual(current["unresolved_count"], 3)
            self.assertTrue(current["has_more"])
            self.resume(current)
        self.assertEqual(self.scalar("SELECT count(*) FROM quarantine_incidents WHERE resolved_at IS NOT NULL"), 3)

    def test_invalid_candidates_do_not_make_a_half_written_pause(self):
        for kwargs, reason in (
            ({"layer": ""}, "invalid_quarantine_layer"),
            ({"code": "bad\ncode"}, "invalid_quarantine_code"),
            ({"reason": " "}, "invalid_quarantine_reason"),
            ({"reason": "\u0000"}, "invalid_quarantine_reason"),
            ({"evidence_sha256": "not a digest"}, "invalid_quarantine_evidence"),
        ):
            self.assert_denied(reason, self.pause, **kwargs)
        self.assertEqual(self.scalar("SELECT count(*) FROM quarantine_incidents"), 0)
        state = self.pause(reason="解释\u0000" + "很长" * 1500)
        self.assertLessEqual(len(state["incident"]["reason"]), 1000)
        self.assertNotIn("\u0000", state["incident"]["reason"])


if __name__ == "__main__":
    unittest.main()
