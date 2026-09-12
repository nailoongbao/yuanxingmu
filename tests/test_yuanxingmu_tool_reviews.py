import concurrent.futures
from pathlib import Path
import tempfile
import unittest

from yuanxingmu.authority import Authority, AuthorizationError
from yuanxingmu.tool_reviews import ToolReviews


class ToolReviewTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.authority = Authority(Path(self.temporary.name) / "state.sqlite3")
        self.task = self.authority.create_root({}, {})
        self.now = [1000.0]
        self.reviews = ToolReviews(self.authority, clock=lambda: self.now[0])
        self.arguments = {"command": "python3 calculate.py", "cwd": "/workspace", "stdin_data": "12"}

    def tearDown(self):
        self.authority.close()
        self.temporary.cleanup()

    def create(self, key="one"):
        return self.reviews.request(self.task, key, "terminal", self.arguments, reason="请核对将运行的代码。")

    def consume(self, item, **changes):
        return self.reviews.consume(self.task, item["review_id"], item["digest"], "terminal", {**self.arguments, **changes})

    def test_only_host_approval_then_one_concurrent_consumer(self):
        item = self.create()
        self.assertFalse(self.consume(item)["allowed"])
        view = self.reviews.get(self.task, item["review_id"])
        self.assertEqual(view["review"]["arguments"], self.arguments)
        self.reviews.decide(self.task, item["review_id"], item["digest"], "approve")
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.consume(item), range(16)))
        self.assertEqual(sum(r["allowed"] for r in results), 1)
        self.assertTrue(all(r["status"] == "consumed" for r in results))

    def test_candidate_and_idempotency_cannot_change(self):
        item = self.create()
        self.assertEqual(item, self.create())
        with self.assertRaises(AuthorizationError):
            self.reviews.request(self.task, "one", "terminal", {**self.arguments, "command": "changed"}, reason="")
        self.reviews.decide(self.task, item["review_id"], item["digest"], "approve")
        for changes in ({"command": "changed"}, {"cwd": "/tmp"}, {"stdin_data": "13"}, {"source_tool": {}}):
            with self.assertRaises(AuthorizationError):
                self.consume(item, **changes)
        self.assertTrue(self.consume(item)["allowed"])

    def test_denial_expiry_revocation_and_restart_never_allow(self):
        denied = self.create("denied")
        self.reviews.decide(self.task, denied["review_id"], denied["digest"], "deny")
        self.assertFalse(self.consume(denied)["allowed"])
        expired = self.create("expired")
        self.reviews.decide(self.task, expired["review_id"], expired["digest"], "approve")
        self.now[0] += 301
        self.assertEqual(self.consume(expired)["status"], "expired")
        restarted = self.create("restarted")
        self.reviews.decide(self.task, restarted["review_id"], restarted["digest"], "approve")
        self.reviews.recover()
        self.assertEqual(self.consume(restarted)["status"], "interrupted")
        revoked = self.create("revoked")
        self.reviews.decide(self.task, revoked["review_id"], revoked["digest"], "approve")
        self.authority.revoke(self.task)
        with self.assertRaisesRegex(AuthorizationError, "task_revoked"):
            self.consume(revoked)

    def test_cross_task_and_stale_digest_are_rejected(self):
        item = self.create()
        other = self.authority.create_root({}, {})
        with self.assertRaises(AuthorizationError):
            self.reviews.get(other, item["review_id"])
        with self.assertRaises(AuthorizationError):
            self.reviews.decide(self.task, item["review_id"], "0" * 64, "approve")
        self.assertFalse(self.consume(item)["allowed"])


if __name__ == "__main__":
    unittest.main()
