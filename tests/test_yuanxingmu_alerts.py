"""Real Workbench HTTP + authority ledger + local webhook; no model execution.

Runtime fixtures permit profile creation without launching a native framework.
Notification tests exercise real host threads, catalog saves, ledger events and
HTTP delivery, rather than treating browser polling as background delivery.
"""
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sqlite3
import sys
import threading
import time
import unittest
from unittest import mock
import uuid

import test_yuanxingmu_dashboard as fixture
from yuanxingmu.broker import Broker
from yuanxingmu.dashboard import alerts
from yuanxingmu.protection import profile_services
from yuanxingmu.run import load_policy


@unittest.skipUnless(sys.platform.startswith("linux"), "Host scanner requires Linux private profiles")
class AlertsTests(unittest.TestCase):
    _open = fixture.DashboardTests._open
    _shutdown = fixture.DashboardTests._shutdown
    _restart = fixture.DashboardTests._restart
    request = fixture.DashboardTests.request
    create = fixture.DashboardTests.create
    wait_job = fixture.DashboardTests.wait_job

    def setUp(self):
        fixture.DashboardTests.setUp(self)
        self.received = []
        self.http_status = 204
        self.receivers = []
        self.receiver = self.new_receiver()
        self.notify_key = "SYNTHETIC-NOTIFICATION-KEY"
        self.config = {"url": f"http://127.0.0.1:{self.receiver.server_port}/PRIVATE-HOOK-PATH",
                       "api_key": self.notify_key, "timeout_seconds": .25,
                       "backoff_seconds": .03, "max_backoff_seconds": .06, "max_attempts": 3}
        self.addCleanup(self.close_receivers)
        connect = socket.socket.connect
        def local_only(connection, address):
            if connection.family == socket.AF_UNIX:
                permitted = {str(Path(json.loads(path.read_text())["runtime"]) / "operator.sock")
                             for path in (self.root / "profiles").glob("*/profile.json")}
                if address in permitted:
                    return connect(connection, address)
            allowed = {receiver.server_port for receiver, _ in self.receivers}
            if self.server:
                allowed.add(self.server.server_port)
            if connection.family not in (socket.AF_INET, socket.AF_INET6) or address[0] != "127.0.0.1" or address[1] not in allowed:
                raise AssertionError("Alerts test attempted a non-fixture network connection")
            return connect(connection, address)
        self.patches.enter_context(mock.patch.object(socket.socket, "connect", new=local_only))

    def new_receiver(self):
        case = self
        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                case.received.append({"port": self.server.server_port, "path": self.path,
                    "authorization": self.headers.get("Authorization"), "key": self.headers.get("Idempotency-Key"), "body": value})
                self.send_response(case.http_status)
                self.send_header("Content-Length", "0")
                self.end_headers()
            def log_message(self, *_):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()
        self.receivers.append((server, thread))
        return server

    def close_receivers(self):
        for receiver, thread in self.receivers:
            receiver.shutdown()
            receiver.server_close()
            thread.join(timeout=2)

    def enabled(self, **overrides):
        return {"enabled": True, "config": {**self.config, **overrides}}

    def configure(self, value=None, key=None):
        status, _, result = self.request("POST", "/api/notifications", self.enabled() if value is None else value, key=key)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["job"]["status"], "succeeded")
        return result

    def wait(self, condition, timeout=4):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(.01)
        self.fail("background notification condition not reached: " + str(self.manager.alerts.view()))

    def report(self):
        status, _, result = self.request("GET", "/api/notifications")
        self.assertEqual(status, 200, result)
        return result

    def event(self, profile, action, allowed=True, reason="synthetic", *, task_id=None):
        manifest = json.loads((profile / "profile.json").read_text())
        with sqlite3.connect(profile / "broker-state" / "authority.sqlite3") as db:
            result = db.execute("INSERT INTO authority_events(task_id,action,allowed,reason,details,created_at) VALUES (?,?,?,?,?,?)",
                (task_id or manifest["task_id"], action, int(allowed), reason,
                 json.dumps({"do_not_send": self.content, "url": "https://untrusted.example.test/", "command": "DO-NOT-SEND-COMMAND"}), "2026-09-12T00:00:00Z"))
            return result.lastrowid

    @contextmanager
    def broker(self, profile):
        manifest = json.loads((profile / "profile.json").read_text())
        resources, destinations = load_policy(profile / "policy.json")
        with Broker(profile / "broker-state", resources, destinations, **profile_services(profile, manifest)) as broker:
            yield broker, manifest["task_id"]

    def test_authenticated_configuration_is_durable_idempotent_and_secret_free(self):
        self.assertEqual(self.request("GET", "/api/notifications", authenticated=False)[0], 401)
        self.assertEqual(self.request("POST", "/api/notifications", self.enabled(), origin=False)[0], 403)
        key = uuid.uuid4().hex
        result = self.configure(key=key)
        first = self.report()
        self.assertEqual(self.configure(key=key), result)
        self.assertEqual(self.request("GET", "/api/requests/" + key)[2], result)
        self.assertEqual(self.report()["generation"], first["generation"])
        self.assertEqual(self.received, [])
        self.assertEqual(self.request("POST", "/api/notifications", {"enabled": False}, key=key)[0], 409)
        self._restart()
        after = self.report()
        self.assertEqual(after["generation"], first["generation"])
        self.assertEqual(self.configure(key=key), result)
        for public in (first, after, result):
            raw = json.dumps(public)
            for private in (self.notify_key, "PRIVATE-HOOK-PATH", self.secret, self.content):
                self.assertNotIn(private, raw)
        self.assertEqual((self.root / "catalog.json").stat().st_mode & 0o777, 0o600)

    def test_settings_reject_event_fields_bad_urls_and_duplicate_json_keys(self):
        for value in ({**self.enabled(), "task_id": "x"}, {"enabled": False, "config": self.config},
                      self.enabled(url="http://external.example.test/hook"), self.enabled(url="https://example.test/hook?key=secret"),
                      self.enabled(headers={"Authorization": "not allowed"}), self.enabled(queue_capacity=True), {"enabled": 1}):
            self.assertEqual(self.request("POST", "/api/notifications", value)[0], 400, value)
        self.assertEqual(self.request("POST", "/api/notifications", body=b'{"enabled":false,"enabled":true}')[0], 400)
        self.assertFalse(self.report()["enabled"])
        self.assertEqual(self.received, [])

    def test_first_configuration_skips_history_and_background_delivers_all_states_without_browser(self):
        identifier, profile, _ = self.create()
        self.event(profile, "quarantine_pause", False)
        self.configure()
        events = [("quarantine_pause", False, "blocked", "paused"), ("quarantine_resume", True, "host_reviewed_current_incidents", "resumed"),
                  ("revoke", True, "subtree_revoked", "revoked"), ("tool_review_request", False, "human_confirmation_required", "approval_required"),
                  ("mail_draft_submitted", True, "mail_draft_submitted", "approval_required"), ("action_proposed", True, "action_proposed", "approval_required")]
        expected = {}
        for action, allowed, reason, state in events:
            event_id = self.event(profile, action, allowed, reason)
            expected[hashlib.sha256((identifier + ":" + str(event_id)).encode()).hexdigest()] = state
        # No browser and no GET/status/scanner calls are needed to cause delivery.
        self.wait(lambda: len(self.received) == 6)
        self.wait(lambda: self.manager.alerts.view()["counts"]["delivered"] == 6)
        self.assertEqual({item["body"]["event_id"]: item["body"]["status"] for item in self.received}, expected)
        for item in self.received:
            self.assertEqual(set(item["body"]), {"version", "event_id", "status", "message"})
            self.assertEqual(item["authorization"], "Bearer " + self.notify_key)
            self.assertEqual(item["key"], "yuanxingmu-notification:" + item["body"]["event_id"])
            self.assertNotIn(self.content, json.dumps(item["body"]))
            self.assertNotIn("DO-NOT-SEND-COMMAND", json.dumps(item["body"]))

    def test_only_successful_state_events_and_real_confirmation_requests_notify(self):
        _, profile, _ = self.create()
        self.configure()
        for action, allowed, reason in (("revoke", False, "unknown_task"), ("quarantine_resume", False, "task_revoked"),
                ("tool_review_request", False, "guard_blocked"), ("tool_review_request", True, "human_confirmation_required"),
                ("action_proposed", False, "invalid"), ("read", True, "ok")):
            self.event(profile, action, allowed, reason)
        last = self.event(profile, "quarantine_pause", False, task_id="unrelated-task")
        self.wait(lambda: self.manager.catalog["notifications"]["cursors"].get(profile.name) == last)
        self.assertEqual(self.received, [])
        self.assertEqual(sum(self.report()["counts"].values()), 0)

    def test_actual_broker_pause_resume_and_revoke_are_not_changed_by_failed_notifications(self):
        _, profile, _ = self.create({**self.payload, "objective": "仅整理资料，不得外发。"})
        self.http_status = 403
        self.configure()
        with self.broker(profile) as (broker, task):
            incident = broker.quarantine.pause(task, layer="command", code="synthetic_block", reason="Synthetic test")
            self.wait(lambda: len(self.received) == 1)
            self.assertTrue(broker.quarantine.status(task)["paused"])
            broker.quarantine.resume(task, epoch=incident["epoch"], incident_id=incident["incident_id"], confirm="resume")
            self.wait(lambda: len(self.received) == 2)
            self.assertFalse(broker.quarantine.status(task)["paused"])
            broker.revoke(task)
            self.wait(lambda: len(self.received) == 3)
            self.assertTrue(broker.authority.describe(task)["revoked"])
        self.wait(lambda: self.manager.alerts.view()["counts"]["failed"] == 3)

    def test_events_created_while_workbench_is_offline_are_delivered_after_restart(self):
        _, profile, _ = self.create()
        self.configure()
        generation = self.report()["generation"]
        self._shutdown()
        self.event(profile, "quarantine_pause", False)
        self.assertEqual(self.received, [])
        self._open()
        self.wait(lambda: len(self.received) == 1)
        self.assertEqual(self.report()["generation"], generation)
        self.wait(lambda: self.report()["counts"]["delivered"] == 1)
        self._restart()
        self.manager.alerts.scan_once()
        self.assertEqual(self.report()["counts"]["delivered"], 1)
        self.assertEqual(len(self.received), 1)

    def test_newly_created_profiles_join_the_existing_background_scanner(self):
        self.configure()
        identifier, profile, _ = self.create()
        event_id = self.event(profile, "action_proposed", True)
        self.wait(lambda: len(self.received) == 1)
        self.assertEqual(self.received[0]["body"]["event_id"], hashlib.sha256((identifier + ":" + str(event_id)).encode()).hexdigest())

    def test_saved_queue_entry_is_deduplicated_if_cursor_was_not_committed_before_restart(self):
        identifier, profile, _ = self.create()
        self.configure()
        event_id = self.event(profile, "quarantine_pause", False)
        self.wait(lambda: self.manager.alerts.view()["counts"]["delivered"] == 1)
        # Emulate durable enqueue followed by a crash before the cursor save.
        with self.manager.mutex:
            self.manager.catalog["notifications"]["cursors"][identifier] = event_id - 1
            self.manager._save()
        self._restart()
        self.wait(lambda: self.manager.catalog["notifications"]["cursors"][identifier] == event_id)
        self.assertEqual(self.report()["counts"]["delivered"], 1)
        self.assertEqual(len(self.received), 1)

    def test_full_queue_retains_cursor_before_unsaved_event_and_is_visible(self):
        identifier, profile, _ = self.create()
        self.configure(self.enabled(queue_capacity=1))
        first = self.event(profile, "quarantine_pause", False)
        second = self.event(profile, "quarantine_resume", True)
        self.wait(lambda: bool(self.manager.alerts.view()["source_errors"]))
        report = self.report()
        self.assertTrue(report["full"])
        self.assertEqual(self.manager.catalog["notifications"]["cursors"][identifier], first)
        self.assertGreater(second, first)
        self._restart()
        self.wait(lambda: bool(self.manager.alerts.view()["source_errors"]))
        self.assertEqual(self.manager.catalog["notifications"]["cursors"][identifier], first)

    def test_changing_target_stops_old_queue_and_only_new_events_use_new_target(self):
        _, profile, _ = self.create()
        self.http_status = 503
        self.configure(self.enabled(backoff_seconds=10, max_backoff_seconds=10))
        first_queue = self.manager.alerts._queue
        self.event(profile, "quarantine_pause", False)
        self.wait(lambda: len(self.received) == 1)
        self.wait(lambda: self.manager.alerts.view()["counts"]["pending"] == 1)
        replacement = self.new_receiver()
        self.http_status = 204
        self.configure(self.enabled(url=f"http://127.0.0.1:{replacement.server_port}/NEW-PRIVATE-HOOK"))
        self.assertTrue(first_queue._closed)
        self.assertEqual(self.report()["stopped"][-1]["counts"]["pending"], 1)
        self.event(profile, "quarantine_resume", True)
        self.wait(lambda: len(self.received) == 2)
        self.assertEqual([item["port"] for item in self.received], [self.receiver.server_port, replacement.server_port])
        self.assertEqual(self.received[-1]["body"]["status"], "resumed")

    def test_disable_does_not_queue_and_reenable_starts_from_new_events(self):
        _, profile, _ = self.create()
        self.configure()
        self.configure({"enabled": False})
        self.event(profile, "quarantine_pause", False)
        self.assertFalse(self.report()["enabled"])
        self.configure()
        self.event(profile, "quarantine_resume", True)
        self.wait(lambda: len(self.received) == 1)
        self.assertEqual(self.received[0]["body"]["status"], "resumed")

    def test_same_settings_with_new_key_do_not_reset_cursor_or_generation(self):
        identifier, profile, _ = self.create()
        self.configure()
        first = self.report()["generation"]
        self.event(profile, "quarantine_pause", False)
        self.wait(lambda: self.manager.alerts.view()["counts"]["delivered"] == 1)
        cursor = self.manager.catalog["notifications"]["cursors"][identifier]
        self.configure()
        self.assertEqual(self.report()["generation"], first)
        self.assertEqual(self.manager.catalog["notifications"]["cursors"][identifier], cursor)

    def test_missing_queue_on_restart_is_fault_not_new_queue(self):
        self.configure()
        path = self.manager.alerts._queue.state_dir / "notifications.sqlite3"
        self._shutdown()
        backup = path.with_suffix(".saved")
        path.rename(backup)
        self._open()
        report = self.report()
        self.assertTrue(report["storage_fault"])
        self.assertIsNone(report["counts"])
        self.assertFalse(path.exists())
        self.assertEqual(self.received, [])

    def test_source_ledger_replacement_and_rewind_are_not_silently_accepted(self):
        _, profile, _ = self.create()
        self.configure()
        database = profile / "broker-state" / "authority.sqlite3"
        backup = database.with_suffix(".backup")
        with self.manager.mutex:
            database.rename(backup)
            database.symlink_to(backup)
        self.wait(lambda: bool(self.manager.alerts.view()["source_errors"]))
        self.assertEqual(self.received, [])
        with self.manager.mutex:
            database.unlink()
            backup.rename(database)
            self.manager.catalog["notifications"]["cursors"][profile.name] = 999999
            self.manager._save()
        self.manager.alerts.scan_once()
        self.assertTrue(self.report()["source_errors"])
        self.assertEqual(self.received, [])

    def test_failed_cursor_save_keeps_queue_durable_and_latches_visible_fault(self):
        _, profile, _ = self.create()
        self.configure()
        with self.manager.mutex:
            self.event(profile, "quarantine_pause", False)
            with mock.patch.object(self.manager, "_save", side_effect=OSError("synthetic disk full")):
                with self.assertRaises(OSError):
                    self.manager.alerts.scan_once()
        self.assertTrue(self.report()["storage_fault"])
        self.assertTrue(self.manager.write_failed)
        self._restart()
        self.wait(lambda: self.manager.alerts.view()["counts"]["delivered"] == 1)
        self.assertEqual(len(self.received), 1)


if __name__ == "__main__":
    unittest.main()
