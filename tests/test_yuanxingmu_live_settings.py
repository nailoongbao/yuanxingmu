"""Actual host HTTP/Unix sockets and profile files, without running an Agent.

Runtime executables and ready status are management fixtures. No model or
candidate command is executed. Rules, Authority, Broker, and settings writes
are real; failures are injected to verify fail-stop behavior.
"""
import json
import os
import sys
import unittest
from unittest.mock import patch

from yuanxingmu import openclaw as core
from yuanxingmu.broker import Broker
from yuanxingmu.protection import apply_profile_settings, profile_services
from yuanxingmu.run import load_policy
import test_yuanxingmu_dashboard as dashboard_fixture
from test_yuanxingmu_tool_review_broker import exchange


@unittest.skipUnless(sys.platform.startswith("linux"), "Live host settings require Linux")
class LiveSettingsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = dashboard_fixture.DashboardTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        payload = {**self.fixture.payload, "objective": "仅在本地整理资料，外发必须本人确认。"}
        self.identifier, self.profile, _ = self.fixture.create(payload)
        self.manifest = core.validate_profile(self.profile)
        self.assertIn("live_settings_v1", self.manifest["features"])
        lock = core._profile_lock(self.profile)
        lock.__enter__()
        self.addCleanup(lock.__exit__, None, None, None)
        resources, destinations = load_policy(self.profile / "policy.json")
        self.broker = Broker(self.profile / "broker-state", resources, destinations,
                             **profile_services(self.profile, self.manifest))
        self.addCleanup(self.broker.close)
        self.task = self.manifest["task_id"]
        self.broker.configure_callback = lambda changes: apply_profile_settings(self.profile, self.manifest, self.broker, changes)
        runtime = self.fixture.base / "live-sockets"
        runtime.mkdir()
        # The profile's genuine review endpoint is fixed when it is created.
        from pathlib import Path
        native_runtime = Path(self.manifest["runtime"])
        native_runtime.mkdir(parents=True, exist_ok=True)
        self.broker.serve_reviews(self.task, native_runtime / "review.sock")
        self.worker = self.broker.serve(self.task, runtime / "worker.sock")
        core._save(self.profile / "lifecycle.json", {"status": "ready", "supervisor_pid": os.getpid(),
            "supervisor_start": core._process_identity(os.getpid())})
        def status(profile, action):
            self.assertEqual(profile, self.profile)
            self.assertEqual(action, "status")
            return {"status": "ready", "task": self.broker.authority.describe(self.task), **core._public(profile, self.manifest)}
        self.patcher = patch.object(core, "control_profile", side_effect=status)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def update(self, changes, *, expected="succeeded"):
        status, _, accepted = self.fixture.request("POST", f"/api/profiles/{self.identifier}/protection", {"settings": changes})
        self.assertEqual(status, 202, accepted)
        return self.fixture.wait_job(accepted, expected=expected)

    def candidate(self):
        return exchange(self.worker, {"op": "guard_tool", "tool": "exec", "arguments": {"command": "sudo true"}})

    def test_live_update_changes_next_check_without_restarting_or_rebinding(self):
        before = self.broker.authority.describe(self.task)
        pending = self.broker.tool_reviews.request(self.task, "old-policy", "exec", {"command": "fixture"}, reason="fixture")
        self.update({"command_enabled": False, "alignment_enabled": False})
        self.assertTrue(self.candidate()["allowed"])
        self.assertEqual(self.broker.tool_reviews.get(self.task, pending["review_id"])["review"]["status"], "interrupted")
        self.assertEqual(self.broker.authority.describe(self.task)["labels"], before["labels"])
        core.validate_profile(self.profile)
        self.assertFalse(json.loads((self.profile / "defense-policy.json").read_text())["command_enabled"])
        self.update({"command_enabled": True})
        self.assertFalse(self.candidate()["allowed"])
        self.assertTrue(self.broker.quarantine.status(self.task)["paused"])

    def test_settings_do_not_resume_a_paused_task_or_revive_pending_drafts(self):
        draft = self.broker.mail.submit(self.task, "pending-before-pause", {"recipient": "test@example.test", "subject": "fixture", "body": "Synthetic"})
        self.assertFalse(self.candidate()["allowed"])
        self.update({"command_enabled": False, "alignment_enabled": False})
        self.assertEqual(self.candidate()["reason"], "task_paused")
        self.assertEqual(self.broker.mail.get(self.task, draft["id"])["draft"]["status"], "cancelled")

    def test_worker_cannot_change_settings_and_objective_cannot_be_replaced(self):
        result = exchange(self.worker, {"op": "protection_set", "settings": {"command_enabled": False}})
        self.assertFalse(result["allowed"])
        status, _, _ = self.fixture.request("POST", f"/api/profiles/{self.identifier}/protection", {"settings": {"objective": "anything"}})
        self.assertEqual(status, 400)
        self.assertFalse(self.broker._fault)
        self.assertTrue(self.broker.guards.policy.command_enabled)

    def test_partial_live_file_update_latches_fault_and_keeps_dirty_marker(self):
        original = core._save
        def fail_binding(path, value):
            if path.name == "bindings.json":
                raise OSError("synthetic storage failure")
            return original(path, value)
        with patch.object(core, "_save", side_effect=fail_binding):
            self.update({"command_enabled": False}, expected="failed")
        self.assertTrue(self.broker._fault)
        self.assertEqual(self.candidate()["reason"], "defense_storage_fault")
        self.broker.close()
        self.assertTrue((self.profile / "broker-state" / "guard-session.dirty").exists())
        with self.assertRaisesRegex(RuntimeError, "changed"):
            core.validate_profile(self.profile)


if __name__ == "__main__":
    unittest.main()
