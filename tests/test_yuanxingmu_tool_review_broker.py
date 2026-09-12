"""Tool approvals through real worker/review sockets, without running a model.

The guard verdict is a controllable local fixture. These tests check permission
and durable status transitions; no native command is executed and no claim is
made that a consumed permission proves the command succeeded.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import json
from pathlib import Path
import socket
import stat
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from yuanxingmu.broker import Broker
from yuanxingmu.guards import GuardPolicy, GuardResult


def exchange(path, value):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        connection.sendall(json.dumps(value, ensure_ascii=True).encode() + b"\n")
        with connection.makefile("rb") as stream:
            raw = stream.readline(1024 * 1024)
    if not raw.endswith(b"\n"):
        raise AssertionError("Broker returned no complete response")
    return json.loads(raw)


class SwitchingGuardFixture:
    """A declared fixture, never an actual model or network judge."""

    def __init__(self):
        self.policy = GuardPolicy("Verify one exact synthetic native invocation", allowed_tools=("terminal",))
        self.judge = None
        self.verdict = "review"
        self.calls = []

    @staticmethod
    def check_memory(tool, arguments):
        return GuardResult("allow", "fixture_memory_allow", "Synthetic memory check", "memory")

    @staticmethod
    def check_command(command):
        return GuardResult("allow", "fixture_command_allow", "Synthetic command check", "command")

    def check_alignment(self, candidate):
        self.calls.append(deepcopy(candidate))
        return GuardResult(self.verdict, "fixture_judge_" + self.verdict, "Synthetic verdict: " + self.verdict, "alignment")


@unittest.skipUnless(sys.platform.startswith("linux"), "Real Broker Unix sockets require Linux")
class ToolReviewBrokerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="yxm-tool-review-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.guards = SwitchingGuardFixture()
        self.now = [1000.0]
        self.broker = self.new_broker()
        self.addCleanup(lambda: self.broker.close())
        self.task = self.broker.create_task()
        self.worker, self.host = self.bind(self.task, "primary")
        self.arguments = {"command": "printf synthetic-fixture", "cwd": "/workspace", "stdin_data": "12",
                          "source_tool": {"tool": "terminal", "arguments": {"command": "printf synthetic-fixture"}}}

    def new_broker(self):
        broker = Broker(self.root / "state", {}, {}, guards=self.guards)
        broker.tool_reviews.clock = lambda: self.now[0]
        return broker

    def bind(self, task_id, prefix):
        return (self.broker.serve(task_id, self.root / (prefix + "-worker.sock")),
                self.broker.serve_reviews(task_id, self.root / (prefix + "-host.sock")))

    def ask(self, key="native-call", *, arguments=None, endpoint=None):
        return exchange(endpoint or self.worker, {"op": "request_tool_review", "request_key": key,
                        "tool": "terminal", "arguments": deepcopy(self.arguments if arguments is None else arguments)})

    def consume(self, row, *, arguments=None, endpoint=None, digest=None, tool="terminal"):
        return exchange(endpoint or self.worker, {"op": "consume_tool_review", "review_id": row["review_id"],
                        "digest": row["digest"] if digest is None else digest, "tool": tool,
                        "arguments": deepcopy(self.arguments if arguments is None else arguments)})

    def decide(self, row, action="approve", *, endpoint=None, digest=None, confirm=None):
        return exchange(endpoint or self.host, {"op": "tool_" + action, "review_id": row["review_id"],
                        "digest": row["digest"] if digest is None else digest,
                        "confirm": action if confirm is None else confirm})

    def detail(self, row, *, endpoint=None):
        return exchange(endpoint or self.host, {"op": "tool_get", "review_id": row["review_id"]})

    def restart(self):
        self.broker.close()
        self.broker = self.new_broker()
        self.worker, self.host = self.bind(self.task, "primary")

    def test_worker_socket_never_reaches_host_approval_or_listing(self):
        row = self.ask()
        self.assertFalse(row["allowed"])
        self.assertEqual(row["status"], "pending")
        self.assertEqual(stat.S_IMODE(self.host.stat().st_mode), 0o600)
        for value in ({"op": "tool_list"}, {"op": "tool_get", "review_id": row["review_id"]},
                      {"op": "tool_approve", "review_id": row["review_id"], "digest": row["digest"], "confirm": "approve"},
                      {"op": "tool_deny", "review_id": row["review_id"], "digest": row["digest"], "confirm": "deny"}):
            with self.subTest(operation=value["op"]):
                self.assertEqual(exchange(self.worker, value), {"allowed": False, "reason": "invalid_request"})
        for field, value in (("approved", True), ("decision", "approve"), ("task_id", self.task), ("blocked", False)):
            response = exchange(self.worker, {"op": "request_tool_review", "request_key": "forged",
                                "tool": "terminal", "arguments": self.arguments, field: value})
            self.assertEqual(response, {"allowed": False, "reason": "invalid_request"})
        self.assertEqual(self.detail(row)["review"]["arguments"], self.arguments)
        self.assertFalse(self.consume(row)["allowed"])

    def test_host_must_confirm_exact_digest_and_pending_consumption_does_not_spend_it(self):
        row = self.ask()
        self.assertFalse(self.consume(row)["allowed"])
        self.assertFalse(self.decide(row, digest="0" * 64)["ok"])
        self.assertEqual(self.decide(row, confirm="yes")["reason"], "tool_confirmation_required")
        self.assertEqual(self.detail(row)["review"]["status"], "pending")
        self.assertEqual(self.decide(row)["review"]["status"], "approved")
        consumed = self.consume(row)
        self.assertTrue(consumed["allowed"])
        self.assertEqual(consumed["status"], "consumed")
        self.assertFalse(self.consume(row)["allowed"])

    def test_real_socket_concurrent_consumers_receive_exactly_one_permission(self):
        row = self.ask()
        self.decide(row)
        # Keep connection fanout below the server's default listen backlog so
        # this checks concurrent consumption rather than queue saturation.
        gate = threading.Barrier(4)

        def consume(index):
            if index < 4:
                gate.wait(timeout=3)
            return self.consume(row)

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(consume, range(32)))
        self.assertEqual(sum(item["allowed"] for item in results), 1)
        self.assertTrue(all(item["status"] == "consumed" for item in results))
        with self.broker.authority._transaction() as db:
            events = db.execute("SELECT count(*) FROM authority_events WHERE action='tool_review_consume'").fetchone()[0]
        self.assertEqual(events, 1)

    def test_lost_consumption_reply_does_not_make_permission_replayable(self):
        row = self.ask()
        self.decide(row)
        persisted = threading.Event()
        original = self.broker.tool_reviews.consume

        def observe(*args, **kwargs):
            result = original(*args, **kwargs)
            persisted.set()
            return result

        with patch.object(self.broker.tool_reviews, "consume", observe):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(str(self.worker))
                value = {"op": "consume_tool_review", "review_id": row["review_id"], "digest": row["digest"],
                         "tool": "terminal", "arguments": self.arguments}
                connection.sendall(json.dumps(value).encode() + b"\n")
                connection.shutdown(socket.SHUT_WR)
                self.assertTrue(persisted.wait(3))
                # Deliberately discard the first reply rather than treating it
                # as proof that an executor ever used the issued permission.
        replay = self.consume(row)
        self.assertEqual(replay["status"], "consumed")
        self.assertFalse(replay["allowed"])

    def test_approval_cannot_be_transferred_to_changed_candidate_or_task(self):
        row = self.ask()
        self.decide(row)
        variants = [{**self.arguments, "command": "printf changed"}, {**self.arguments, "cwd": "/tmp"},
                    {**self.arguments, "stdin_data": "13"}, {**self.arguments, "source_tool": {"tool": "different", "arguments": {}}},
                    {**self.arguments, "extra": "unreviewed"}]
        for arguments in variants:
            with self.subTest(arguments=arguments):
                self.assertEqual(self.consume(row, arguments=arguments)["reason"], "tool_review_candidate_changed")
        self.assertEqual(self.consume(row, tool="exec")["reason"], "tool_review_candidate_changed")
        self.assertEqual(self.consume(row, digest="0" * 64)["reason"], "tool_review_changed")
        other_task = self.broker.create_task()
        other_worker, other_host = self.bind(other_task, "other")
        self.assertEqual(self.consume(row, endpoint=other_worker)["reason"], "tool_review_not_found")
        self.assertEqual(self.decide(row, endpoint=other_host)["reason"], "tool_review_not_found")
        self.assertTrue(self.consume(row)["allowed"])

    def test_same_call_with_changed_parameters_remains_a_conflict(self):
        row = self.ask()
        self.guards.verdict = "allow"
        count = len(self.guards.calls)
        result = self.ask(arguments={**self.arguments, "command": "printf changed"})
        self.assertEqual(result["reason"], "tool_review_request_conflict")
        self.assertEqual(len(self.guards.calls), count)
        self.assertEqual(self.detail(row)["review"]["status"], "pending")

    def test_recorded_status_never_reenters_a_later_allowing_judge(self):
        for status in ("pending", "approved", "denied", "consumed", "expired"):
            with self.subTest(status=status):
                self.guards.verdict = "review"
                row = self.ask(key=status)
                if status in {"approved", "consumed", "expired"}:
                    self.decide(row)
                if status == "denied":
                    self.decide(row, "deny")
                if status == "consumed":
                    self.assertTrue(self.consume(row)["allowed"])
                if status == "expired":
                    self.now[0] += 301
                self.guards.verdict = "allow"
                count = len(self.guards.calls)
                replay = self.ask(key=status)
                self.assertFalse(replay["allowed"])
                self.assertEqual(replay["status"], status)
                self.assertEqual(replay["review_id"], row["review_id"])
                self.assertEqual(len(self.guards.calls), count)

    def test_initial_model_block_is_terminal_for_that_native_call(self):
        self.guards.verdict = "block"
        first = self.ask("initial-block")
        self.assertFalse(first["allowed"])
        count = len(self.guards.calls)
        self.guards.verdict = "allow"
        replay = self.ask("initial-block")
        self.assertFalse(replay["allowed"], "A previously blocked native invocation must not ask a changing judge again")
        self.assertEqual(replay["status"], "blocked")
        self.assertEqual(len(self.guards.calls), count)
        self.assertFalse(self.consume(replay)["allowed"])
        self.assertEqual(self.decide(replay)["reason"], "task_paused")

    def test_expiry_is_checked_at_decision_and_consumption(self):
        pending = self.ask("pending-expiry")
        approved = self.ask("approved-expiry")
        self.decide(approved)
        self.now[0] += 300
        self.assertEqual(self.decide(pending)["review"]["status"], "expired")
        for row in (pending, approved):
            consumed = self.consume(row)
            self.assertEqual(consumed["status"], "expired")
            self.assertFalse(consumed["allowed"])

    def test_restarting_the_broker_invalidates_pending_and_approved_permissions(self):
        pending = self.ask("pending-restart")
        approved = self.ask("approved-restart")
        self.decide(approved)
        self.restart()
        self.guards.verdict = "allow"
        count = len(self.guards.calls)
        for key, row in (("pending-restart", pending), ("approved-restart", approved)):
            with self.subTest(key=key):
                self.assertEqual(self.ask(key)["status"], "interrupted")
                self.assertEqual(self.decide(row)["review"]["status"], "interrupted")
                self.assertEqual(self.consume(row)["status"], "interrupted")
                self.assertFalse(self.consume(row)["allowed"])
        self.assertEqual(len(self.guards.calls), count)

    def test_parent_revocation_prevents_approval_and_consumption_on_descendant_socket(self):
        child = self.broker.delegate(self.task)
        worker, host = self.bind(child, "child")
        row = self.ask(endpoint=worker)
        self.decide(row, endpoint=host)
        self.broker.revoke(self.task)
        self.guards.verdict = "allow"
        count = len(self.guards.calls)
        self.assertEqual(self.consume(row, endpoint=worker)["reason"], "task_revoked")
        self.assertEqual(self.decide(row, endpoint=host)["reason"], "task_revoked")
        self.assertEqual(self.ask(endpoint=worker)["reason"], "task_revoked")
        self.assertFalse(self.detail(row, endpoint=host)["active"])
        self.assertEqual(len(self.guards.calls), count)


if __name__ == "__main__":
    unittest.main()
