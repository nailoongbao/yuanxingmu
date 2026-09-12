"""Independent quarantine integration tests with real Broker and HTTP sockets.

Guard verdicts and runtime readiness are declared local fixtures. No model,
native Agent, email, message receiver, or pending command is ever executed.
"""
import hashlib
import json
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

from yuanxingmu.actions import ActionTarget
from yuanxingmu.authority import AuthorizationError
from yuanxingmu.broker import Broker, Destination, Resource
from yuanxingmu.guards import GuardPolicy, GuardResult
from yuanxingmu.protection import profile_services
from yuanxingmu.run import load_policy
from test_yuanxingmu_tool_review_broker import exchange
import test_yuanxingmu_dashboard as workbench_fixture


class QuarantineGuardFixture:
    def __init__(self):
        self.policy = GuardPolicy("Local quarantine integration fixture", allowed_tools=("terminal",))
        self.judge = None
        self.alignment = "allow"
        self.enforced = True

    @staticmethod
    def check_memory(tool, arguments):
        return GuardResult("allow", "fixture_memory", "Synthetic memory check", "memory")

    @staticmethod
    def check_command(command):
        return GuardResult("allow", "fixture_command", "Synthetic command check", "command")

    def check_alignment(self, candidate):
        return GuardResult(self.alignment, "fixture_alignment_" + self.alignment, "Synthetic alignment decision", "alignment")

    def check_input(self, text):
        return GuardResult("block" if text.startswith("SYNTHETIC-BLOCK") else "allow", "fixture_external_instruction",
                           "合成外部资料要求改变任务", "input", {"input_sha256": hashlib.sha256(text.encode()).hexdigest()},
                           enforced=self.enforced)


@unittest.skipUnless(sys.platform.startswith("linux"), "Quarantine Broker integration requires Linux")
class QuarantineBrokerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="yxm-quarantine-broker-")
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name)
        resource = self.path / "private.txt"
        resource.write_text("SYNTHETIC-PRIVATE", encoding="utf-8")
        self.guards = QuarantineGuardFixture()
        self.resources = {"private": Resource(resource, ("private",))}
        self.destinations = {"internal": Destination("http://127.0.0.1:9/never-called", ("private",))}
        self.targets = {"chat": ActionTarget("message", "Never-sent fixture", url="http://127.0.0.1:9/never-called")}
        self.broker = self.new_broker()
        self.addCleanup(lambda: self.broker.close())
        self.task = self.broker.create_task(initial_labels=["private"])
        self.child = self.broker.delegate(self.task)
        self.other = self.broker.create_task()
        self.bind()
        original = socket.socket.connect

        def only_local_broker(connection, address):
            if connection.family != socket.AF_UNIX or not str(address).startswith(str(self.path) + "/"):
                raise AssertionError("Quarantine tests must not execute network or model effects")
            return original(connection, address)

        self.addCleanup(patch.stopall)
        patch.object(socket.socket, "connect", only_local_broker).start()

    def new_broker(self):
        return Broker(self.path / "state", self.resources, self.destinations, guards=self.guards,
                      reviewed_mail=True, action_targets=self.targets)

    def bind(self):
        self.worker = self.broker.serve(self.task, self.path / "worker.sock")
        self.child_worker = self.broker.serve(self.child, self.path / "child.sock")
        self.host = self.broker.serve_reviews(self.task, self.path / "host.sock")
        self.child_host = self.broker.serve_reviews(self.child, self.path / "child-host.sock")
        self.other_worker = self.broker.serve(self.other, self.path / "other.sock")

    def status(self, endpoint=None):
        return exchange(endpoint or self.host, {"op": "quarantine_status"})

    def pause(self, text="SYNTHETIC-BLOCK-1", endpoint=None):
        return exchange(endpoint or self.worker, {"op": "inspect_input", "text": text})

    def resume(self, state=None, endpoint=None, **changes):
        state = state or self.status()
        return exchange(endpoint or self.host, {"op": "quarantine_resume", "epoch": state["epoch"],
                        "incident_id": state["incident_id"], "confirm": "resume", **changes})

    def restart(self):
        self.broker.close()
        self.broker = self.new_broker()
        self.bind()

    def test_blocked_input_pauses_family_and_root_host_alone_can_resume(self):
        self.assertEqual(self.pause(endpoint=self.child_worker)["reason"], "fixture_external_instruction")
        state = self.status()
        self.assertTrue(state["paused"])
        self.assertTrue(state["can_resume"])
        self.assertEqual(self.status(self.child_host)["incident_id"], state["incident_id"])
        self.assertFalse(self.status(self.child_host)["can_resume"])
        for worker in (self.worker, self.child_worker):
            self.assertEqual(exchange(worker, {"op": "describe"})["reason"], "task_paused")
            self.assertEqual(exchange(worker, {"op": "send", "destination": "internal", "body": "synthetic"})["reason"], "task_paused")
            self.assertEqual(self.resume(state, worker)["reason"], "invalid_request")
            self.assertEqual(exchange(worker, {"op": "quarantine_status"})["reason"], "invalid_request")
        self.assertEqual(self.resume(state, self.child_host)["reason"], "quarantine_root_review_required")
        self.assertTrue(exchange(self.other_worker, {"op": "describe"})["allowed"])
        self.assertFalse(self.resume(state)["paused"])
        for worker in (self.worker, self.child_worker):
            resumed = exchange(worker, {"op": "describe"})
            self.assertTrue(resumed["allowed"])
            self.assertEqual(resumed["labels"], ["private"])

    def test_exact_resume_rejects_forged_identity_stale_epoch_and_replay(self):
        self.pause()
        first = self.status()
        self.assertEqual(self.resume(first, confirm="yes")["reason"], "quarantine_confirmation_required")
        self.assertEqual(self.resume(first, epoch=True)["reason"], "invalid_quarantine_review")
        self.assertEqual(self.resume(first, task_id=self.other)["reason"], "invalid_quarantine_request")
        self.broker.quarantine.pause(self.child, layer="memory", code="fixture_new_incident", reason="新的合成记忆问题")
        current = self.status()
        self.assertGreater(current["epoch"], first["epoch"])
        self.assertEqual(self.resume(first)["reason"], "quarantine_review_changed")
        self.assertTrue(self.status()["paused"])
        self.assertFalse(self.resume(current)["paused"])
        self.assertEqual(self.resume(current)["reason"], "task_not_paused")

    def test_pause_permanently_invalidates_unused_reviews_mail_and_actions(self):
        arguments = {"command": "printf synthetic"}
        self.guards.alignment = "review"
        review = exchange(self.child_worker, {"op": "request_tool_review", "request_key": "approved-before-pause",
                          "tool": "terminal", "arguments": arguments})
        self.assertEqual(exchange(self.child_host, {"op": "tool_approve", "review_id": review["review_id"],
                         "digest": review["digest"], "confirm": "approve"})["review"]["status"], "approved")
        self.guards.alignment = "allow"
        draft = exchange(self.worker, {"op": "draft_email", "request_key": "mail-before-pause",
                         "draft": {"recipient": "synthetic@example.test", "subject": "Synthetic", "body": "Pending only"}})
        action = exchange(self.child_worker, {"op": "propose_action", "request_key": "action-before-pause",
                          "proposal": {"kind": "message", "target_id": "chat", "payload": {"body": "Pending only"}}})
        self.pause()
        self.assertEqual(self.status()["incident"]["invalidated"], {"tool_reviews": 1, "mail_drafts": 1, "reviewed_actions": 1})
        self.resume()
        replay = exchange(self.child_worker, {"op": "consume_tool_review", "review_id": review["review_id"],
                          "digest": review["digest"], "tool": "terminal", "arguments": arguments})
        self.assertFalse(replay["allowed"])
        self.assertEqual(replay["status"], "interrupted")
        self.assertEqual(exchange(self.host, {"op": "get", "draft_id": draft["draft_id"]})["draft"]["status"], "cancelled")
        self.assertEqual(exchange(self.child_host, {"op": "action_get", "action_id": action["id"]})["action"]["status"], "cancelled")
        self.assertEqual(exchange(self.child_host, {"op": "action_commit", "action_id": action["id"],
                         "revision": action["revision"], "digest": action["digest"], "confirm": "commit"})["reason"], "action_not_pending")

    def test_pause_storage_failure_faults_closed_and_restart_creates_durable_pause(self):
        with patch.object(self.broker.quarantine, "pause", side_effect=OSError("synthetic disk unavailable")):
            self.assertFalse(self.pause()["allowed"])
        state = self.status()
        self.assertTrue(state["storage_fault"])
        self.assertFalse(state["paused"], "The injected failed transaction did not persist an incident")
        for worker in (self.worker, self.child_worker, self.other_worker):
            self.assertEqual(exchange(worker, {"op": "describe"})["reason"], "defense_storage_fault")
        self.assertEqual(self.resume({"epoch": 1, "incident_id": "a" * 32})["reason"], "defense_storage_fault")
        with self.assertRaisesRegex(AuthorizationError, "防护状态写入失败"):
            self.broker.create_task()
        self.broker.close()
        self.assertTrue((self.path / "state/guard-session.dirty").exists())
        self.broker = self.new_broker()
        self.bind()
        restarted = self.status()
        self.assertFalse(restarted["storage_fault"])
        self.assertTrue(restarted["paused"])
        self.assertEqual(restarted["incident"]["code"], "previous_defense_session_unconfirmed")
        self.assertEqual(exchange(self.child_worker, {"op": "describe"})["reason"], "task_paused")
        self.assertEqual(exchange(self.other_worker, {"op": "describe"})["reason"], "task_paused")
        self.assertFalse(self.resume(restarted)["paused"])
        self.assertTrue(exchange(self.child_worker, {"op": "describe"})["allowed"])
        self.assertEqual(exchange(self.other_worker, {"op": "describe"})["reason"], "task_paused")

    def test_clean_restart_keeps_an_existing_pause_and_does_not_reset_labels(self):
        self.pause()
        first = self.status()
        self.restart()
        current = self.status()
        self.assertTrue(current["paused"])
        self.assertEqual(current["incident_id"], first["incident_id"])
        self.assertEqual(current["epoch"], first["epoch"])
        self.resume(current)
        self.assertEqual(exchange(self.worker, {"op": "describe"})["labels"], ["private"])

    def test_observe_only_candidate_does_not_pause_and_review_remains_individual(self):
        self.guards.enforced = False
        self.pause()
        self.assertFalse(self.status()["paused"])
        self.guards.alignment = "review"
        review = exchange(self.worker, {"op": "request_tool_review", "request_key": "individual-review",
                          "tool": "terminal", "arguments": {"command": "printf synthetic"}})
        self.assertEqual(review["status"], "pending")
        self.assertFalse(self.status()["paused"])

    def test_revoked_family_cannot_be_recovered(self):
        self.pause()
        state = self.status()
        self.broker.revoke(self.task)
        self.assertFalse(self.status()["can_resume"])
        self.assertEqual(self.resume(state)["reason"], "task_revoked")
        self.assertEqual(exchange(self.child_worker, {"op": "describe"})["reason"], "task_revoked")

    def test_failed_close_directory_sync_releases_lock_and_restart_keeps_pause(self):
        first_broker = self.broker
        with patch.object(first_broker, "_sync_state_directory", side_effect=OSError("synthetic directory fsync failed")):
            with self.assertRaises(OSError):
                first_broker.close()
        self.assertTrue(first_broker._file_lock.closed)
        self.assertTrue((self.path / "state/guard-session.dirty").exists())
        self.broker = self.new_broker()
        self.bind()
        state = self.status()
        self.assertTrue(state["paused"])
        self.assertEqual(state["incident"]["code"], "previous_defense_session_unconfirmed")
        self.assertEqual(exchange(self.child_worker, {"op": "describe"})["reason"], "task_paused")
        first_broker.close()
        self.assertTrue((self.path / "state/guard-session.dirty").exists(), "Closing an old object again must not delete the new instance's marker")
        self.assertFalse(self.resume(state)["paused"])


class _WorkbenchFixture:
    # Reuse only the declared HTTP fixture setup/helpers, not its test cases.
    setUp = workbench_fixture.DashboardTests.setUp
    _open = workbench_fixture.DashboardTests._open
    _shutdown = workbench_fixture.DashboardTests._shutdown
    _restart = workbench_fixture.DashboardTests._restart
    request = workbench_fixture.DashboardTests.request
    wait_job = workbench_fixture.DashboardTests.wait_job
    create = workbench_fixture.DashboardTests.create


@unittest.skipUnless(sys.platform.startswith("linux"), "Real Workbench HTTP quarantine tests require Linux")
class QuarantineWorkbenchTests(_WorkbenchFixture, unittest.TestCase):
    def setUp(self):
        _WorkbenchFixture.setUp(self)
        self.prohibited_network_attempts = []
        original_connect = socket.socket.connect
        original_resolve = socket.getaddrinfo

        def guarded_connect(connection, address):
            if connection.family == socket.AF_INET and address == ("127.0.0.1", self.server.server_port):
                return original_connect(connection, address)
            allowed_unix = set()
            for manifest_path in self.root.glob("profiles/*/profile.json"):
                runtime = Path(json.loads(manifest_path.read_text())["runtime"])
                allowed_unix.update(str(runtime / name) for name in ("review.sock", "operator.sock"))
            if connection.family == socket.AF_UNIX and str(address) in allowed_unix:
                return original_connect(connection, address)
            self.prohibited_network_attempts.append("connect")
            raise AssertionError("HTTP quarantine test forbids model or external connections")

        def guarded_resolve(host, *args, **kwargs):
            if host != "127.0.0.1":
                self.prohibited_network_attempts.append("resolve")
                raise AssertionError("HTTP quarantine test forbids external name resolution")
            return original_resolve(host, *args, **kwargs)

        self.addCleanup(patch.stopall)
        patch.object(socket.socket, "connect", guarded_connect).start()
        patch.object(socket, "getaddrinfo", guarded_resolve).start()

    def tearDown(self):
        self.assertEqual(self.prohibited_network_attempts, [])

    def paused_profile(self, *, storage_failure=False):
        identifier, path, _ = self.create({**self.payload, "objective": "只在本机核对合成资料"})
        manifest = workbench_fixture.core.validate_profile(path)
        resources, destinations = load_policy(path / "policy.json")
        with Broker(path / "broker-state", resources, destinations, **profile_services(path, manifest)) as broker:
            if storage_failure:
                blocked = GuardResult("block", "fixture_failure", "合成写入失败", "input")
                with patch.object(broker.quarantine, "pause", side_effect=OSError("synthetic disk error")):
                    with self.assertRaises(OSError):
                        broker._guard_result(manifest["task_id"], blocked)
            else:
                broker.quarantine.pause(manifest["task_id"], layer="input", code="fixture_http_incident", reason="待核对的合成资料")
        code, _, result = self.request("GET", f"/api/profiles/{identifier}/protection")
        self.assertEqual(code, 200, result)
        self.assertTrue(result["quarantine"]["paused"])
        return identifier, path, result["quarantine"]

    def test_actual_http_resume_requires_auth_origin_and_exact_current_snapshot(self):
        identifier, path, state = self.paused_profile()
        route = f"/api/profiles/{identifier}/quarantine/resume"
        value = {"epoch": state["epoch"], "incident_id": state["incident_id"], "confirm": "resume"}
        self.assertEqual(self.request("POST", route, value, authenticated=False)[0], 401)
        self.assertEqual(self.request("POST", route, value, origin=False)[0], 403)
        self.assertEqual(self.request("POST", route, {**value, "epoch": True})[0], 400)
        status, _, rejected = self.request("POST", route, {**value, "incident_id": "f" * 32})
        self.assertEqual(status, 202)
        self.wait_job(rejected, expected="failed")
        self.assertTrue(self.request("GET", f"/api/profiles/{identifier}/protection")[2]["quarantine"]["paused"])
        key = uuid.uuid4().hex
        status, _, accepted = self.request("POST", route, value, key=key)
        self.assertEqual(status, 202)
        job = self.wait_job(accepted)
        self.assertFalse(job["result"]["paused"])
        original = self.request("GET", "/api/requests/" + key)[2]
        self.assertEqual(original["job"]["id"], accepted["job"]["id"])
        self.assertEqual(self.request("POST", route, value, key=key)[2]["job"]["id"], accepted["job"]["id"])
        current = self.request("GET", f"/api/profiles/{identifier}/protection")[2]["quarantine"]
        self.assertFalse(current["paused"])
        with sqlite3.connect(path / "broker-state/authority.sqlite3") as db:
            self.assertEqual(db.execute("SELECT count(*) FROM authority_events WHERE action='quarantine_resume'").fetchone()[0], 1)

    def test_actual_http_observes_fault_restart_pause_and_can_resume_it(self):
        identifier, _, state = self.paused_profile(storage_failure=True)
        self.assertEqual(state["incident"]["code"], "previous_defense_session_unconfirmed")
        self.assertFalse(state["storage_fault"])
        code, _, accepted = self.request("POST", f"/api/profiles/{identifier}/quarantine/resume",
            {"epoch": state["epoch"], "incident_id": state["incident_id"], "confirm": "resume"})
        self.assertEqual(code, 202)
        self.wait_job(accepted)
        self.assertFalse(self.request("GET", f"/api/profiles/{identifier}/protection")[2]["quarantine"]["paused"])


if __name__ == "__main__":
    unittest.main()
