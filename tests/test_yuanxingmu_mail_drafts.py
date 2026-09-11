from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from yuanxingmu.authority import Authority, AuthorizationError
from yuanxingmu.mail_drafts import MailDrafts
from yuanxingmu.mail_transport import draft_digest


class MailDraftTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "authority.sqlite3"
        self.authority = self.open_authority()
        self.task = self.authority.create_root({"quote": ["quotes"]}, {"outside": []},
                                                initial_labels=["private"])
        self.store = MailDrafts(self.authority)
        self.original = {"recipient": "private-recipient@EXAMPLE.TEST", "subject": "PRIVATE-SUBJECT",
                         "body": "PRIVATE-BODY: internal quote 3200\r\nPlease review.\t"}

    def open_authority(self):
        authority = Authority(self.path)
        self.addCleanup(authority.close)
        return authority

    def new(self, key="request-1", *, task=None, store=None, draft=None):
        return (store or self.store).submit(task or self.task, key,
                                            self.original if draft is None else draft)

    def begin(self, row, *, task=None, store=None, account="office", sender="sender@EXAMPLE.TEST"):
        return (store or self.store).begin_send(task or self.task, row["id"], row["revision"],
                                                row["digest"], account, sender)

    def assert_denied(self, reason, function, *args, **kwargs):
        with self.assertRaises(AuthorizationError) as caught:
            function(*args, **kwargs)
        self.assertEqual(reason, caught.exception.reason)

    def test_canonical_content_and_metadata_survive_reopen(self):
        row = self.new()
        self.assertRegex(row["id"], r"\A[0-9a-f]{32}\Z")
        self.assertEqual("pending", row["status"])
        self.assertEqual(1, row["revision"])
        self.assertEqual("private-recipient@example.test", row["recipient"])
        self.assertEqual(self.original["body"].replace("\r\n", "\n"), row["body"])
        self.assertEqual(draft_digest(self.original), row["digest"])
        self.assertIsNone(row["attempt_id"])
        self.assertIsNone(row["account_id"])
        self.assertIsNone(row["approved_at"])
        listing = self.store.list(self.task)
        self.assertTrue(listing["active"])
        self.assertEqual([{key: value for key, value in row.items() if key != "body"}], listing["drafts"])
        for internal in ("task_id", "family_id", "request_key", "request_digest"):
            self.assertNotIn(internal, row)
        self.authority.close()
        reopened = MailDrafts(self.open_authority())
        self.assertEqual({"draft": row, "active": True}, reopened.get(self.task, row["id"]))

    def test_original_request_replays_current_draft_after_edit(self):
        row = self.new()
        changed = {"recipient": "approved@example.test", "subject": "Reviewed subject", "body": "Reviewed body\n"}
        edited = self.store.edit(self.task, row["id"], row["revision"], row["digest"], changed)
        self.assertEqual(row["id"], edited["id"])
        self.assertEqual(2, edited["revision"])
        self.assertEqual(row["created_at"], edited["created_at"])
        self.assertEqual(draft_digest(changed), edited["digest"])
        self.assertEqual(edited, self.new())
        canonical_replay = {**self.original, "recipient": "private-recipient@example.test",
                            "body": self.original["body"].replace("\r\n", "\n")}
        self.assertEqual(edited, self.new(draft=canonical_replay))
        self.assert_denied("mail_request_conflict", self.new, draft=changed)
        self.assertEqual(1, len(self.store.list(self.task)["drafts"]))
        self.authority.close()
        reopened = MailDrafts(self.open_authority())
        self.assertEqual(edited, reopened.submit(self.task, "request-1", self.original))

    def test_stale_review_cannot_send_edited_content(self):
        original = self.new()
        replacement = {"recipient": "reviewed@example.test", "subject": "New subject", "body": "Changed body"}
        edited = self.store.edit(self.task, original["id"], original["revision"], original["digest"], replacement)
        self.assert_denied("mail_draft_changed", self.begin, original)
        self.assert_denied("mail_draft_changed", self.store.begin_send, self.task, edited["id"],
                           edited["revision"], original["digest"], "office", "sender@example.test")
        self.assert_denied("mail_draft_changed", self.store.edit, self.task, original["id"],
                           original["revision"], original["digest"], self.original)
        self.assert_denied("mail_draft_changed", self.store.cancel, self.task, original["id"],
                           original["revision"], original["digest"])
        observed = self.store.get(self.task, edited["id"])["draft"]
        self.assertEqual(edited, observed)
        result = self.begin(edited)
        self.assertTrue(result["started"])
        for key, value in replacement.items():
            self.assertEqual(value, result["draft"][key])

    def test_bad_inputs_are_authorization_errors_without_draft_mutations(self):
        for key in (None, [], "", "contains spaces", "x" * 129):
            with self.subTest(key=key):
                self.assert_denied("invalid_mail_request_key", self.new, key)
        for draft, reason in (
            ({**self.original, "approved": True}, "invalid_mail_draft_keys"),
            ({**self.original, "recipient": "bad\r\nBcc: hidden@example.test"}, "invalid_mail_address"),
            ({**self.original, "subject": "bad\nheader"}, "invalid_mail_subject"),
            ({**self.original, "body": "bad\x00body"}, "invalid_mail_body"),
        ):
            with self.subTest(reason=reason):
                self.assert_denied(reason, self.new, draft=draft)
        self.assertEqual([], self.store.list(self.task)["drafts"])
        row = self.new()
        for revision, digest, reason in (
            (True, row["digest"], "invalid_mail_revision"),
            (0, row["digest"], "invalid_mail_revision"),
            (1, "bad", "invalid_mail_digest"),
            (1, "0" * 64, "mail_draft_changed"),
        ):
            self.assert_denied(reason, self.store.begin_send, self.task, row["id"], revision, digest,
                               "office", "sender@example.test")
        self.assert_denied("invalid_mail_account_id", self.begin, row, account="")
        self.assert_denied("invalid_mail_address", self.begin, row, sender="bad\n@example.test")
        self.assertEqual(row, self.store.get(self.task, row["id"])["draft"])

    def test_other_tasks_cannot_read_change_or_finish_a_draft(self):
        row = self.new()
        sibling = self.authority.delegate(self.task)
        independent = self.authority.create_root({}, {})
        for task in (sibling, independent):
            self.assertEqual([], self.store.list(task)["drafts"])
            for function, arguments in (
                (self.store.get, (task, row["id"])),
                (self.store.edit, (task, row["id"], row["revision"], row["digest"], self.original)),
                (self.store.cancel, (task, row["id"], row["revision"], row["digest"])),
                (self.store.begin_send, (task, row["id"], row["revision"], row["digest"], "office", "sender@example.test")),
                (self.store.finish_send, (task, row["id"], "0" * 32, "acknowledged")),
            ):
                self.assert_denied("mail_draft_not_found", function, *arguments)
        begun = self.begin(row)["draft"]
        self.assert_denied("mail_draft_not_found", self.store.finish_send, sibling, row["id"],
                           begun["attempt_id"], "acknowledged")
        self.assertEqual(begun, self.store.get(self.task, row["id"])["draft"])
        # A request key is local to its task, never an authority to another task's row.
        other = self.new(task=sibling)
        self.assertNotEqual(row["id"], other["id"])

    def test_revoked_tasks_can_inspect_but_not_change_pending_drafts(self):
        child = self.authority.delegate(self.task)
        rows = [(self.task, self.new()), (child, self.new(task=child))]
        self.authority.revoke(self.task)
        for task, row in rows:
            self.assertFalse(self.store.list(task)["active"])
            self.assertEqual({"active": False, "draft": row}, self.store.get(task, row["id"]))
            self.assert_denied("task_revoked", self.new, task=task)
            self.assert_denied("task_revoked", self.store.edit, task, row["id"], row["revision"], row["digest"], self.original)
            self.assert_denied("task_revoked", self.store.cancel, task, row["id"], row["revision"], row["digest"])
            self.assert_denied("task_revoked", self.begin, row, task=task)
        for function, arguments in ((self.store.list, ("missing",)), (self.store.get, ("missing", rows[0][1]["id"])),
                                    (self.store.submit, ("missing", "request", self.original))):
            self.assert_denied("unknown_task", function, *arguments)
        self.authority.close()
        reopened = MailDrafts(self.open_authority())
        self.assertFalse(reopened.get(child, rows[1][1]["id"])["active"])
        self.assert_denied("task_revoked", reopened.begin_send, child, rows[1][1]["id"], 1,
                           rows[1][1]["digest"], "office", "sender@example.test")

    def test_attempt_is_committed_before_return_and_never_replaced(self):
        row = self.new()
        begun = self.begin(row)
        self.assertTrue(begun["started"])
        attempt = begun["draft"]
        self.assertEqual("sending", attempt["status"])
        self.assertRegex(attempt["attempt_id"], r"\A[0-9a-f]{32}\Z")
        self.assertEqual("office", attempt["account_id"])
        self.assertEqual("sender@example.test", attempt["from_address"])
        self.assertIsNotNone(attempt["approved_at"])
        separate = MailDrafts(self.open_authority())
        self.assertEqual(attempt, separate.get(self.task, row["id"])["draft"])
        repeated = self.begin(row, store=separate, account="changed-account", sender="other@example.test")
        self.assertEqual({"started": False, "draft": attempt}, repeated)
        self.authority.revoke(self.task)
        self.assertEqual(repeated, self.begin(row))
        finished = self.store.finish_send(self.task, row["id"], attempt["attempt_id"], "acknowledged")
        self.assertEqual("acknowledged", finished["status"])
        self.assertFalse(self.begin(row)["started"])

    def test_all_outcomes_are_terminal_including_not_started(self):
        for outcome in ("acknowledged", "unconfirmed", "not_started"):
            with self.subTest(outcome=outcome):
                row = self.new(outcome)
                attempt = self.begin(row)["draft"]
                completed = self.store.finish_send(self.task, row["id"], attempt["attempt_id"], outcome)
                self.assertEqual(outcome, completed["status"])
                self.assertIsNotNone(completed["finished_at"])
                self.assertEqual(completed, self.store.finish_send(self.task, row["id"], attempt["attempt_id"], outcome))
                self.assertEqual({"started": False, "draft": completed}, self.begin(row))
                other_outcome = "unconfirmed" if outcome != "unconfirmed" else "acknowledged"
                self.assert_denied("mail_attempt_finished", self.store.finish_send, self.task, row["id"],
                                   attempt["attempt_id"], other_outcome)
                self.assert_denied("mail_draft_not_pending", self.store.edit, self.task, row["id"],
                                   row["revision"], row["digest"], self.original)
                self.assert_denied("mail_draft_not_pending", self.store.cancel, self.task, row["id"],
                                   row["revision"], row["digest"])
                self.assertEqual(completed, self.new(outcome))

    def test_cancelled_draft_cannot_be_sent_or_reopened(self):
        row = self.new()
        cancelled = self.store.cancel(self.task, row["id"], row["revision"], row["digest"])
        self.assertEqual("cancelled", cancelled["status"])
        self.assertIsNone(cancelled["attempt_id"])
        self.assertEqual(cancelled, self.new())
        self.assert_denied("mail_draft_not_pending", self.begin, row)
        self.assert_denied("mail_draft_not_pending", self.store.edit, self.task, row["id"],
                           row["revision"], row["digest"], self.original)
        self.assert_denied("mail_attempt_mismatch", self.store.finish_send, self.task, row["id"],
                           "0" * 32, "acknowledged")

    def test_wrong_attempt_and_invalid_outcome_do_not_finish_a_send(self):
        row = self.new()
        attempt = self.begin(row)["draft"]
        self.assert_denied("mail_attempt_mismatch", self.store.finish_send, self.task, row["id"],
                           "0" * 32, "acknowledged")
        self.assert_denied("invalid_mail_outcome", self.store.finish_send, self.task, row["id"],
                           attempt["attempt_id"], {"outcome": "acknowledged"})
        self.assert_denied("invalid_mail_outcome", self.store.finish_send, self.task, row["id"],
                           attempt["attempt_id"], "pending")
        self.assertEqual(attempt, self.store.get(self.task, row["id"])["draft"])

    def test_explicit_recovery_consumes_abandoned_attempts_across_reopen(self):
        child = self.authority.delegate(self.task)
        first = self.begin(self.new("first"))["draft"]
        second = self.begin(self.new("second", task=child), task=child)["draft"]
        pending = self.new("pending")
        self.authority.revoke(child)
        self.authority.close()
        authority = self.open_authority()
        reopened = MailDrafts(authority)
        # Constructing a wrapper is not evidence that an in-flight sender has died.
        self.assertEqual("sending", reopened.get(self.task, first["id"])["draft"]["status"])
        self.assertEqual(2, reopened.recover())
        self.assertEqual(0, reopened.recover())
        for task, original in ((self.task, first), (child, second)):
            current = reopened.get(task, original["id"])["draft"]
            self.assertEqual("unconfirmed", current["status"])
            for name in ("attempt_id", "digest", "revision", "from_address", "account_id", "approved_at"):
                self.assertEqual(original[name], current[name])
            self.assertEqual({"started": False, "draft": current}, self.begin(original, task=task, store=reopened))
            self.assert_denied("mail_attempt_finished", reopened.finish_send, task, current["id"],
                               current["attempt_id"], "acknowledged")
        self.assertEqual(pending, reopened.get(self.task, pending["id"])["draft"])
        recovered = [event for event in authority.events(self.task) if event["action"] == "mail_send_recovered"]
        self.assertEqual(2, len(recovered))

    def test_pending_limit_and_submission_replay(self):
        rows = [self.new(f"pending-{index}") for index in range(16)]
        self.assertEqual(rows[0], self.new("pending-0"))
        self.assert_denied("mail_pending_limit", self.new, "too-many")
        self.store.cancel(self.task, rows[0]["id"], rows[0]["revision"], rows[0]["digest"])
        self.assertEqual("pending", self.new("released-slot")["status"])
        self.assert_denied("mail_pending_limit", self.new, "too-many")

    def test_total_limit_preserves_history_and_lists_latest_fifty(self):
        rows = []
        for index in range(128):
            row = self.new(f"history-{index}")
            rows.append(self.store.cancel(self.task, row["id"], row["revision"], row["digest"]))
        listing = self.store.list(self.task)["drafts"]
        self.assertEqual([row["id"] for row in reversed(rows[-50:])], [row["id"] for row in listing])
        self.assertTrue(all("body" not in row for row in listing))
        self.assert_denied("mail_draft_limit", self.new, "too-many-ever")
        self.assertEqual(rows[0], self.new("history-0"))
        self.assertEqual(rows[0], self.store.get(self.task, rows[0]["id"])["draft"])

    def test_concurrent_submissions_and_confirmations_share_sqlite_order(self):
        stores = [self.store, MailDrafts(self.open_authority())]
        barrier = threading.Barrier(2)

        def submit(index):
            barrier.wait(timeout=10)
            return self.new(store=stores[index])

        with ThreadPoolExecutor(max_workers=2) as executor:
            rows = list(executor.map(submit, range(2)))
        self.assertEqual(rows[0], rows[1])
        self.assertEqual(1, len(self.store.list(self.task)["drafts"]))
        barrier = threading.Barrier(2)

        def confirm(index):
            barrier.wait(timeout=10)
            return self.begin(rows[0], store=stores[index])

        with ThreadPoolExecutor(max_workers=2) as executor:
            attempts = list(executor.map(confirm, range(2)))
        self.assertEqual(1, sum(result["started"] for result in attempts))
        self.assertEqual(attempts[0]["draft"], attempts[1]["draft"])
        starts = [event for event in self.authority.events(self.task) if event["action"] == "mail_send_started"]
        self.assertEqual(1, len(starts))

    def test_concurrent_revocation_and_confirmation_have_one_committed_order(self):
        row = self.new()
        other = self.open_authority()
        other_store = MailDrafts(other)
        barrier = threading.Barrier(2)

        def confirm():
            barrier.wait(timeout=10)
            try:
                return self.begin(row, store=other_store)
            except AuthorizationError as exc:
                self.assertEqual("task_revoked", exc.reason)
                return None

        def revoke():
            barrier.wait(timeout=10)
            self.authority.revoke(self.task)

        with ThreadPoolExecutor(max_workers=2) as executor:
            confirming = executor.submit(confirm)
            executor.submit(revoke).result(timeout=15)
            result = confirming.result(timeout=15)
        current = self.store.get(self.task, row["id"])
        self.assertFalse(current["active"])
        if result is None:
            self.assertEqual("pending", current["draft"]["status"])
            self.assertIsNone(current["draft"]["attempt_id"])
        else:
            self.assertTrue(result["started"])
            events = self.authority.events(self.task)
            started = next(event["event_id"] for event in events if event["action"] == "mail_send_started")
            revoked = next(event["event_id"] for event in events if event["action"] == "revoke")
            self.assertLess(started, revoked)
            self.assertEqual(result["draft"], current["draft"])

    def test_failed_intent_transaction_does_not_consume_or_authorize_a_draft(self):
        row = self.new()
        before = self.authority.events(self.task)
        with patch.object(self.authority, "_event", side_effect=OSError("simulated audit storage failure")):
            with self.assertRaises(OSError):
                self.begin(row)
        self.assertEqual(row, self.store.get(self.task, row["id"])["draft"])
        self.assertEqual(before, self.authority.events(self.task))
        self.assertTrue(self.begin(row)["started"])

    def test_mail_audit_contains_no_content_and_does_not_change_private_authority(self):
        self.authority.record_read(self.task, "quote")
        before = self.authority.describe(self.task)
        row = self.new()
        revised = {"recipient": "changed-private-recipient@example.test", "subject": "CHANGED-PRIVATE-SUBJECT",
                   "body": "CHANGED-PRIVATE-BODY"}
        row = self.store.edit(self.task, row["id"], row["revision"], row["digest"], revised)
        attempted = self.begin(row, account="audit-account-sentinel", sender="private-sender@example.test")["draft"]
        self.store.finish_send(self.task, row["id"], attempted["attempt_id"], "acknowledged")
        self.assert_denied("mail_request_conflict", self.new, draft=revised)
        after = self.authority.describe(self.task)
        self.assertEqual(before, after)
        self.assertEqual(["private", "quotes"], after["labels"])
        self.assertFalse(self.authority.authorize_send(self.task, "outside")["allowed"])
        events = self.authority.events(self.task)
        encoded = json.dumps(events)
        for secret in ("private-recipient", "PRIVATE-SUBJECT", "PRIVATE-BODY", "changed-private-recipient",
                       "CHANGED-PRIVATE-SUBJECT", "CHANGED-PRIVATE-BODY", "audit-account-sentinel", "private-sender"):
            self.assertNotIn(secret, encoded)
        mail_events = [event for event in events if event["action"].startswith("mail_")]
        self.assertGreater(len(mail_events), 0)
        for event in mail_events:
            self.assertLessEqual(set(event["details"]), {"id", "digest", "revision", "status"})


if __name__ == "__main__":
    unittest.main()
