from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest

from yuanxingmu.authority import Authority, AuthorizationError


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "task-ledger.sqlite3"
        self.authority = self.open_authority()
        self.resources = {"public": [], "customer": ["customer"], "payroll": ["payroll"]}
        self.destinations = {"outside": [], "customer_team": ["customer"],
                             "internal": ["customer", "payroll"]}
        self.root = self.authority.create_root(self.resources, self.destinations)

    def open_authority(self):
        authority = Authority(self.path)
        self.addCleanup(authority.close)
        return authority

    def assert_denied(self, reason, function, *args, **kwargs):
        with self.assertRaises(AuthorizationError) as error:
            function(*args, **kwargs)
        self.assertEqual(reason, error.exception.reason)

    def test_public_work_and_internal_correction_remain_possible(self):
        authority = self.authority
        self.assertTrue(authority.authorize_send(self.root, "outside")["allowed"])
        authority.record_read(self.root, "public")
        self.assertTrue(authority.authorize_send(self.root, "outside")["allowed"])
        read = authority.record_read(self.root, "customer")
        self.assertEqual(["customer"], read["resource_labels"])
        denial = authority.authorize_send(self.root, "outside")
        self.assertFalse(denial["allowed"])
        self.assertEqual(["customer"], denial["blocked_labels"])
        self.assertTrue(authority.authorize_send(self.root, "customer_team")["allowed"])
        self.assertFalse(authority.authorize_send(self.root, "outside")["allowed"])
        authority.record_read(self.root, "payroll")
        self.assertFalse(authority.authorize_send(self.root, "customer_team")["allowed"])
        self.assertTrue(authority.authorize_send(self.root, "internal")["allowed"])

    def test_child_created_before_parent_read_inherits_later_family_labels(self):
        child = self.authority.delegate(self.root, resources=[], destinations=["outside", "internal"])
        self.assertTrue(self.authority.authorize_send(child, "outside")["allowed"])
        self.authority.record_read(self.root, "customer")
        self.assertFalse(self.authority.authorize_send(child, "outside")["allowed"])
        self.assertTrue(self.authority.authorize_send(child, "internal")["allowed"])
        later_child = self.authority.delegate(self.root)
        self.assertEqual(["customer"], self.authority.describe(later_child)["labels"])

    def test_child_read_constrains_parent_siblings_and_grandchildren(self):
        reader = self.authority.delegate(self.root, resources=["customer"])
        sibling = self.authority.delegate(self.root, resources=[])
        grandchild = self.authority.delegate(sibling)
        self.authority.record_read(reader, "customer")
        for task in (self.root, reader, sibling, grandchild):
            with self.subTest(task=task):
                self.assertFalse(self.authority.authorize_send(task, "outside")["allowed"])
                self.assertEqual(["customer"], self.authority.describe(task)["labels"])

    def test_delegation_cannot_expand_permissions_at_any_depth(self):
        child = self.authority.delegate(self.root, resources=["public"], destinations=["internal"])
        grandchild = self.authority.delegate(child)
        for task in (child, grandchild):
            self.assert_denied("delegation_would_expand_resources", self.authority.delegate,
                               task, resources=["customer"])
            self.assert_denied("delegation_would_expand_destinations", self.authority.delegate,
                               task, destinations=["outside"])
            self.assert_denied("resource_not_granted", self.authority.record_read, task, "customer")
            self.assert_denied("destination_not_granted", self.authority.authorize_send, task, "outside")
        empty = self.authority.delegate(child, resources=[], destinations=[])
        self.assertEqual({}, self.authority.describe(empty)["resources"])
        self.assertEqual({}, self.authority.describe(empty)["destinations"])
        self.assertEqual([], self.authority.describe(self.root)["labels"])

    def test_independent_root_does_not_inherit_another_familys_labels(self):
        second_root = self.authority.create_root(self.resources, self.destinations)
        self.authority.record_read(self.root, "customer")
        self.assertTrue(self.authority.authorize_send(second_root, "outside")["allowed"])
        self.assertFalse(self.authority.authorize_send(self.root, "outside")["allowed"])

    def test_unknown_ids_fail_closed_without_tainting_or_widening(self):
        for action, arguments in (
            (self.authority.record_read, ("nonexistent", "public")),
            (self.authority.authorize_send, ("nonexistent", "outside")),
            (self.authority.delegate, ("nonexistent",)),
            (self.authority.revoke, ("nonexistent",)),
            (self.authority.describe, ("nonexistent",)),
            (self.authority.events, ("nonexistent",)),
        ):
            self.assert_denied("unknown_task", action, *arguments)
        self.assert_denied("unknown_resource", self.authority.record_read, self.root, "absent")
        self.assert_denied("unknown_destination", self.authority.authorize_send, self.root, "absent")
        self.assertEqual([], self.authority.describe(self.root)["labels"])
        self.assert_denied("task_already_exists", self.authority.create_root, {}, {}, task_id=self.root)
        self.assertEqual(self.resources, self.authority.describe(self.root)["resources"])

    def test_revoke_child_covers_subtree_but_preserves_sibling_permissions_and_labels(self):
        child = self.authority.delegate(self.root)
        grandchild = self.authority.delegate(child)
        sibling = self.authority.delegate(self.root)
        self.authority.record_read(grandchild, "customer")
        self.authority.revoke(child)
        self.authority.revoke(child)
        for task in (child, grandchild):
            self.assertTrue(self.authority.describe(task)["revoked"])
            self.assert_denied("task_revoked", self.authority.record_read, task, "public")
            self.assert_denied("task_revoked", self.authority.authorize_send, task, "internal")
            self.assert_denied("task_revoked", self.authority.delegate, task)
        for task in (self.root, sibling):
            self.assertTrue(self.authority.authorize_send(task, "internal")["allowed"])
            self.assertFalse(self.authority.authorize_send(task, "outside")["allowed"])
        self.authority.revoke(self.root)
        self.assert_denied("task_revoked", self.authority.authorize_send, sibling, "internal")

    def test_state_and_revocation_survive_close_and_a_separate_process(self):
        child = self.authority.delegate(self.root)
        revoked_child = self.authority.delegate(self.root)
        self.authority.record_read(child, "customer")
        self.authority.revoke(revoked_child)
        old_events = self.authority.events(self.root)
        self.authority.close()
        code = (
            "import json,sys; from yuanxingmu.authority import Authority; "
            "a=Authority(sys.argv[1]); "
            "print(json.dumps({'send':a.authorize_send(sys.argv[2],'outside'),"
            "'revoked':a.describe(sys.argv[3])['revoked']})); a.close()"
        )
        result = subprocess.run([sys.executable, "-c", code, str(self.path), child, revoked_child],
                                cwd=Path(__file__).resolve().parents[1], text=True,
                                capture_output=True, check=True, timeout=30)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["send"]["allowed"])
        self.assertEqual(["customer"], payload["send"]["labels"])
        self.assertTrue(payload["revoked"])
        reopened = self.open_authority()
        self.assertEqual(old_events, reopened.events(self.root)[:len(old_events)])

    def test_read_labels_are_committed_before_record_read_returns(self):
        other_connection = self.open_authority()
        result = self.authority.record_read(self.root, "customer")
        observed = other_connection.authorize_send(self.root, "outside")
        self.assertFalse(observed["allowed"])
        self.assertEqual(result["revision"], observed["revision"])
        self.assertGreater(observed["event_id"], result["event_id"])

    def test_audit_is_ordered_and_child_audit_does_not_expose_ancestor_task_ids(self):
        child = self.authority.delegate(self.root)
        sibling = self.authority.delegate(self.root)
        self.authority.record_read(child, "customer")
        self.authority.authorize_send(sibling, "outside")
        self.assert_denied("unknown_resource", self.authority.record_read, child, "absent")
        root_events = self.authority.events(self.root)
        self.assertEqual(sorted(event["event_id"] for event in root_events),
                         [event["event_id"] for event in root_events])
        child_events = self.authority.events(child)
        self.assertEqual({child}, {event["task_id"] for event in child_events})
        self.assertNotIn(self.root, json.dumps(child_events))
        self.assertNotIn(self.root, json.dumps(self.authority.describe(child)))
        self.assertEqual("unknown_resource", child_events[-1]["reason"])

    def test_configuration_is_copied_and_labels_have_no_wildcards(self):
        resources = {"secret": ["classified", "classified"]}
        destinations = {"literal_star": ["*"], "internal": ["classified"]}
        task = self.authority.create_root(resources, destinations)
        resources["secret"].clear()
        destinations["literal_star"].append("classified")
        self.authority.record_read(task, "secret")
        self.assertEqual(["classified"], self.authority.describe(task)["labels"])
        self.assertFalse(self.authority.authorize_send(task, "literal_star")["allowed"])

    def test_model_inputs_cannot_supply_labels_or_clearance(self):
        with self.assertRaises(TypeError):
            self.authority.record_read(self.root, "customer", labels=[])
        with self.assertRaises(TypeError):
            self.authority.authorize_send(self.root, "outside", clearance=["customer"])
        with self.assertRaises(TypeError):
            self.authority.delegate(self.root, family_id="another-family")
        self.assert_denied("invalid_label", self.authority.create_root, {"secret": "customer"}, {})
        self.assert_denied("invalid_resource_id", self.authority.delegate, self.root, resources="customer")

    def test_concurrent_reads_and_sends_match_one_committed_family_history(self):
        resources = {f"r{index}": [f"label{index}"] for index in range(4)}
        task = self.authority.create_root(resources, {"outside": [], "internal": [f"label{i}" for i in range(4)]})
        child = self.authority.delegate(task)
        # Exercise both a shared connection across threads and independent
        # connections against the same persistent DB. No sleeps or mock locks.
        handles = [self.authority if i % 2 else self.open_authority() for i in range(8)]
        barrier = threading.Barrier(8)

        def worker(index):
            barrier.wait(timeout=15)
            authority = handles[index]
            if index < 4:
                return authority.record_read(task if index % 2 else child, f"r{index}")
            return [authority.authorize_send(child if index % 2 else task,
                                             "outside" if attempt % 2 else "internal")
                    for attempt in range(12)]

        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(worker, range(8)))
        self.assertEqual(8, len(results))
        committed_labels = set()
        read_count = send_count = 0
        for event in self.authority.events(task):
            details = event["details"]
            if event["action"] == "record_read":
                committed_labels.update(details["resource_labels"])
                read_count += 1
                self.assertEqual(sorted(committed_labels), details["labels"])
            elif event["action"] == "authorize_send":
                send_count += 1
                self.assertEqual(sorted(committed_labels), details["labels"])
                expected = details["destination_id"] == "internal" or not committed_labels
                self.assertEqual(expected, event["allowed"])
        self.assertEqual((4, 48), (read_count, send_count))
        self.assertEqual(sorted(committed_labels), self.authority.describe(child)["labels"])
        self.assertFalse(self.authority.authorize_send(child, "outside")["allowed"])

    def test_concurrent_revoke_and_delegate_cannot_leave_an_active_child(self):
        separate = self.open_authority()
        barrier = threading.Barrier(2)

        def delegate():
            barrier.wait(timeout=15)
            try:
                return separate.delegate(self.root)
            except AuthorizationError as exc:
                self.assertEqual("task_revoked", exc.reason)
                return None

        def revoke():
            barrier.wait(timeout=15)
            self.authority.revoke(self.root)

        with ThreadPoolExecutor(max_workers=2) as executor:
            future = executor.submit(delegate)
            executor.submit(revoke).result(timeout=20)
            child = future.result(timeout=20)
        if child is not None:
            self.assert_denied("task_revoked", separate.authorize_send, child, "internal")

    def test_closed_authority_never_issues_a_decision(self):
        self.authority.close()
        self.assert_denied("authority_closed", self.authority.authorize_send, self.root, "outside")
        with Authority(self.path) as reopened:
            self.assertTrue(reopened.authorize_send(self.root, "outside")["allowed"])


if __name__ == "__main__":
    unittest.main()
