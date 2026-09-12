"""Authenticated chat status views over real policies and ledgers; no model calls."""
import json
import sys
import unittest
from unittest import mock

import test_yuanxingmu_openclaw as profile_fixture
from yuanxingmu.broker import Broker
from yuanxingmu.guards import Guards
from yuanxingmu.protection import apply_profile_settings, profile_services
from yuanxingmu.run import load_policy


@unittest.skipUnless(sys.platform.startswith("linux"), "OpenClaw live status requires Linux")
class OpenClawStatusTests(unittest.TestCase):
    def setUp(self):
        self.fixture = profile_fixture.OpenClawProfileTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.api = self.fixture.api
        self.profile = self.fixture.profile

    def initialize(self, *, layered=True, **settings):
        self.objective = "PRIVATE-OBJECTIVE-MUST-NOT-ENTER-CHAT-STATUS"
        self.fixture.initialize(defense_policy={"objective": self.objective, **settings} if layered else None)
        self.manifest = self.api.validate_profile(self.profile)
        resources, destinations = load_policy(self.profile / "policy.json")
        self.broker = Broker(self.profile / "broker-state", resources, destinations,
                             **profile_services(self.profile, self.manifest))
        self.addCleanup(self.broker.close)
        self.task = self.manifest["task_id"]

    def status(self):
        with mock.patch.object(Guards, "_judge", side_effect=AssertionError("status called a model")), \
             mock.patch.object(Guards, "scan_foundation", side_effect=AssertionError("status started a scan")):
            return self.api._operator_protection_status(self.profile, self.manifest, self.broker)

    def report(self, **changes):
        value = {"layer": "foundation", "complete": True, "assessed": True,
                 "verdict": "allow", "would_verdict": None,
                 "policy_sha256": self.manifest["files"]["defense-policy.json"],
                 "files": [{"path": "/host/PRIVATE-SKILL-PATH"}], "reason": "PRIVATE-REPORT-REASON"}
        self.api._save(self.profile / "foundation-report.json", {**value, **changes})

    def test_live_modes_and_scan_summary_are_readonly_and_sanitized(self):
        self.initialize(mode="observe", command_mode="enforce", memory_enabled=False,
                        skill_semantic_enabled=False)
        self.report(complete=False)
        before = self.broker.authority.describe(self.task)
        events = self.broker.authority.events(self.task)
        result = self.status()
        self.assertEqual(result["state"], "available")
        self.assertEqual(result["layers"]["input"], {"enabled": True, "mode": "observe"})
        self.assertEqual(result["layers"]["command"], {"enabled": True, "mode": "enforce"})
        self.assertEqual(result["layers"]["memory"], {"enabled": False, "mode": "observe"})
        self.assertTrue(result["foundation_config_enabled"])
        self.assertFalse(result["skill_semantic_enabled"])
        self.assertEqual(result["foundation_scan"], {"state": "current", "complete": False,
                          "assessed": True, "verdict": "allow", "would_verdict": None})
        self.assertFalse(result["paused"])
        self.assertFalse(result["revoked"])
        self.assertEqual(before, self.broker.authority.describe(self.task))
        self.assertEqual(events, self.broker.authority.events(self.task))
        serialized = json.dumps(result)
        for private in (self.objective, str(self.profile), self.fixture.secret,
                        self.task, "PRIVATE-SKILL-PATH", "PRIVATE-REPORT-REASON"):
            self.assertNotIn(private, serialized)

    def test_running_settings_are_reflected_and_old_foundation_report_is_stale(self):
        self.initialize()
        self.report()
        self.assertEqual(self.status()["foundation_scan"]["state"], "current")
        changed = apply_profile_settings(self.profile, self.manifest, self.broker,
                                         {"alignment_mode": "observe", "memory_enabled": False}, running=True)
        self.assertTrue(changed["live"])
        result = self.status()
        self.assertEqual(result["layers"]["alignment"], {"enabled": True, "mode": "observe"})
        self.assertFalse(result["layers"]["memory"]["enabled"])
        self.assertEqual(result["layers"]["command"], {"enabled": True, "mode": "enforce"})
        self.assertEqual(result["foundation_scan"], {"state": "stale"})
        self.api.validate_profile(self.profile)

    def test_paused_and_revoked_are_separate_persisted_facts(self):
        self.initialize()
        self.broker.quarantine.pause(self.task, layer="input", code="fixture_block", reason="PRIVATE-INCIDENT")
        result = self.status()
        self.assertTrue(result["paused"])
        self.assertFalse(result["revoked"])
        self.assertNotIn("PRIVATE-INCIDENT", json.dumps(result))
        self.broker.revoke(self.task)
        result = self.status()
        self.assertTrue(result["paused"])
        self.assertTrue(result["revoked"])

    def test_absent_layered_defense_and_unhealthy_service_are_not_active_protection(self):
        self.initialize(layered=False)
        self.assertEqual(self.status(), {"schema_version": 1, "state": "not_configured"})
        self.broker._fault = True
        self.assertEqual(self.status(), {"schema_version": 1, "state": "unavailable"})

    def test_missing_invalid_and_disabled_scans_are_not_completed_checks(self):
        self.initialize()
        self.assertEqual(self.status()["foundation_scan"], {"state": "missing"})
        for malformed in ([], {"complete": True}, {"policy_sha256": None},
                          {"layer": "foundation", "complete": True,
                           "policy_sha256": self.manifest["files"]["defense-policy.json"], "verdict": "allow"}):
            with self.subTest(report=malformed):
                self.api._save(self.profile / "foundation-report.json", malformed)
                self.assertEqual(self.status()["foundation_scan"], {"state": "unavailable"})
        self.report()
        apply_profile_settings(self.profile, self.manifest, self.broker, {"foundation_enabled": False}, running=True)
        self.assertEqual(self.status()["foundation_scan"], {"state": "disabled"})


if __name__ == "__main__":
    unittest.main()
