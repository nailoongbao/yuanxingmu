"""Local workbench request boundaries and durable authority behavior.

HTTP requests use a real loopback server, including raw framing tests. Profile
creation, offline status, and revocation use the real core and SQLite ledger.
Fake runtime files and patched readiness checks permit those fixtures to be
created without starting OpenClaw. Mocked start/stop outcomes and interrupted
jobs test the management interface, not native model or framework execution.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
import copy
import http.client
import json
import multiprocessing
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import uuid

from yuanxingmu import openclaw as core
from yuanxingmu.broker import Broker
from yuanxingmu.dashboard import server as dashboard
from yuanxingmu.run import load_policy


AVAILABLE = {"available": True, "openclaw": "2026.9.4", "reason": None}


def _accept_and_wait_for_interruption(root, paths, payload, key, receipt):
    """A killed manager leaves a real accepted receipt, without starting a model."""
    runtime = dashboard.Runtime(*(Path(path) for path in paths))
    blocked = threading.Event()
    with mock.patch.object(dashboard.Runtime, "public", return_value=AVAILABLE), \
         mock.patch.object(core, "init_profile", side_effect=lambda *a, **k: blocked.wait()):
        manager = dashboard.Workbench(Path(root), runtime, port=0)
        accepted = manager.submit("create", None, payload, key)
        Path(receipt).write_text(json.dumps(accepted), encoding="utf-8")
        blocked.wait()


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux workbench storage and authority only")
class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="yxm-dashboard-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.root = self.base / "workbench"
        runtime_root = self.base / "runtime"
        self.node = runtime_root / "node" / "bin" / "node"
        self.bwrap = runtime_root / "bwrap" / "bin" / "bwrap"
        for executable in (self.node, self.bwrap):
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 64\n", encoding="utf-8")
            executable.chmod(0o755)
        self.package = runtime_root / "node_modules" / "openclaw"
        self.package.mkdir(parents=True)
        (self.package / "package.json").write_text('{"version":"2026.9.4"}', encoding="utf-8")
        (self.package / "openclaw.mjs").write_text("throw new Error('management fixture must not execute');\n", encoding="utf-8")
        self.runtime = dashboard.Runtime(self.node, self.package, self.bwrap)
        self.secret = "MODEL-KEY-ONLY-FOR-SYNTHETIC-DASHBOARD-TEST"
        self.content = "合成报价：仅供权限测试；底价 186000 元。DOCUMENT-CONTENT-MUST-STAY-PRIVATE"
        self.payload = {
            "name": "测试报价任务", "model_url": "http://127.0.0.1:18181/v1",
            "model_id": "fixture-model", "api_key": self.secret,
            "documents": [{"name": "quote", "filename": "测试报价.txt", "content": self.content}],
        }
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(mock.patch.object(dashboard.Runtime, "public", return_value=AVAILABLE))
        self.patches.enter_context(mock.patch.object(core, "sandbox_available", return_value={"available": True, "reason": "fixture only"}))
        # Keep fixture runtime paths separate from the interpreter that spawns tests.
        # Mutating the shared sys module mixes CI's Python binary and standard library.
        fixture_sys = SimpleNamespace(platform=sys.platform, executable=str(Path("/usr/bin/python3").resolve()))
        self.patches.enter_context(mock.patch.object(core, "sys", fixture_sys))
        self.manager = self.server = self.server_thread = None
        self.addCleanup(self._shutdown)
        self._open()

    def _open(self):
        self.manager = dashboard.Workbench(self.root, self.runtime, port=0)
        self.server = dashboard.make_server(self.manager)
        self.server_thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.server_thread.start()
        self.origin = self.server.origin
        self.host = self.origin.removeprefix("http://")

    def _shutdown(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server_thread.join(timeout=3)
            self.server = None
        if self.manager is not None:
            self.manager.close()
            self.manager = None

    def _restart(self):
        self._shutdown()
        self._open()

    def request(self, method, path, value=None, *, headers=None, authenticated=True, origin=True, key=None, body=None):
        supplied = {}
        if authenticated:
            supplied["Authorization"] = "Bearer " + self.manager.token
        if origin:
            supplied["Origin"] = self.origin
        if method == "POST":
            supplied["Content-Type"] = "application/json"
            supplied["Idempotency-Key"] = key or uuid.uuid4().hex
            if body is None:
                body = json.dumps(value, ensure_ascii=True).encode("utf-8")
        supplied.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=supplied)
            response = connection.getresponse()
            raw = response.read()
            result = json.loads(raw) if raw and "application/json" in response.getheader("Content-Type", "") else raw
            return response.status, dict(response.getheaders()), result
        finally:
            connection.close()

    def raw_request(self, method, target, headers, body=b""):
        lines = [f"{method} {target} HTTP/1.1", *(f"{key}: {value}" for key, value in headers), "", ""]
        with socket.create_connection(("127.0.0.1", self.server.server_port), timeout=5) as connection:
            connection.sendall("\r\n".join(lines).encode("ascii") + body)
            connection.shutdown(socket.SHUT_WR)
            response = http.client.HTTPResponse(connection, method=method)
            response.begin()
            raw = response.read()
            return response.status, dict(response.getheaders()), json.loads(raw) if raw else None

    def raw_headers(self, body=b"{}"):
        return [("Host", self.host), ("Origin", self.origin), ("Authorization", "Bearer " + self.manager.token),
                ("Content-Type", "application/json"), ("Content-Length", str(len(body))),
                ("Idempotency-Key", uuid.uuid4().hex)]

    def wait_job(self, accepted, *, expected="succeeded"):
        identifier = accepted["job"]["id"]
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            job = self.manager.job(identifier)["job"]
            if job["status"] != "running":
                self.assertEqual(job["status"], expected, job)
                return job
            time.sleep(.005)
        self.fail("accepted management job did not finish")

    def create(self, payload=None, *, key=None):
        status, _, accepted = self.request("POST", "/api/profiles", payload or self.payload, key=key)
        self.assertEqual(status, 202, accepted)
        job = self.wait_job(accepted)
        identifier = job["profile_id"]
        self.assertRegex(identifier, r"^[0-9a-f]{32}$")
        return identifier, self.root / "profiles" / identifier, job

    def task_ids(self, path):
        database = path / "broker-state" / "authority.sqlite3"
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
            return [row[0] for row in connection.execute("SELECT id FROM authority_tasks ORDER BY id")]

    def assert_private_response(self, value, *additional):
        text = json.dumps(value, ensure_ascii=False)
        for forbidden in (self.secret, self.content, *additional):
            self.assertNotIn(forbidden, text)

    def automatic_payload(self):
        self.manager.set_target({"id": "team", "target": {"kind": "message", "label": "内部团队",
                                "url": "http://127.0.0.1:18338/original"}}, uuid.uuid4().hex)
        digest = self.manager.targets_view()["targets"][0]["binding_digest"]
        return {**copy.deepcopy(self.payload), "objective": "把进度发到用户预先授权的内部团队。",
                "action_automation": {"version": 1, "max_attempts": 8, "max_total_body_bytes": 65536,
                    "targets": {"team": {"accepted_labels": ["private"], "max_body_bytes": 8192}}},
                "action_automation_bindings": {"team": digest}}

    def test_create_freezes_automatic_scope_without_exposing_target_or_credentials(self):
        payload = self.automatic_payload()
        _, profile, job = self.create(payload)
        manifest = core.validate_profile(profile)
        self.assertIn("automatic_actions_v1", manifest["features"])
        self.assertEqual(json.loads((profile / "action-automation.json").read_text()), payload["action_automation"])
        self.assertNotIn("original", json.dumps(job))
        self.assert_private_response(job)
        self.manager.set_target({"id": "team", "target": {"kind": "message", "label": "changed",
                                "url": "http://127.0.0.1:18338/changed"}}, uuid.uuid4().hex)
        self.assertTrue(json.loads((profile / "action-targets.json").read_text())["team"]["url"].endswith("/original"))
        core.validate_profile(profile)

    def test_automatic_creation_requires_complete_matching_fresh_scope(self):
        payload = self.automatic_payload()
        bad = [dict(payload), copy.deepcopy(payload), copy.deepcopy(payload), copy.deepcopy(payload)]
        bad[0].pop("action_automation_bindings")
        bad[1]["action_automation_bindings"]["team"] = "0" * 64
        bad[2]["action_automation"]["max_attempts"] = True
        bad[3].pop("objective")
        before = len(self.manager.catalog["profiles"])
        with mock.patch.object(core, "init_profile") as initialize:
            for value in bad:
                status, _, _ = self.request("POST", "/api/profiles", value)
                self.assertIn(status, (400, 409))
            initialize.assert_not_called()
        self.assertEqual(len(self.manager.catalog["profiles"]), before)

    def test_target_changed_while_creation_is_queued_cannot_reuse_consent(self):
        payload = self.automatic_payload()
        entered, release = threading.Event(), threading.Event()
        execute = self.manager._execute
        def delayed(*args):
            entered.set()
            release.wait(5)
            execute(*args)
        with mock.patch.object(self.manager, "_execute", side_effect=delayed), mock.patch.object(core, "init_profile") as initialize:
            accepted = self.manager.submit("create", None, payload, uuid.uuid4().hex)
            try:
                self.assertTrue(entered.wait(2))
                self.manager.set_target({"id": "team", "target": {"kind": "message", "label": "内部团队",
                                        "url": "http://127.0.0.1:18338/replaced"}}, uuid.uuid4().hex)
            finally:
                release.set()
            job = self.wait_job(accepted, expected="failed")
            initialize.assert_not_called()
        self.assertEqual(job["error"]["code"], "automatic_action_target_changed")
        self.assertFalse((self.root / "profiles" / job["profile_id"]).exists())

    def test_target_settings_do_not_send_expose_secrets_or_rebind_old_profiles(self):
        key = uuid.uuid4().hex
        target = {"id": "team", "target": {"kind": "message", "label": "团队通知", "url": "https://example.test/private-hook/WEBHOOK-SECRET"}}
        with mock.patch("http.client.HTTPSConnection") as connection:
            status, _, first = self.request("POST", "/api/action-targets", target, key=key)
            self.assertEqual(status, 200, first)
            self.assertEqual(first, self.request("POST", "/api/action-targets", target, key=key)[2])
            connection.assert_not_called()
        self.assertEqual(self.request("GET", "/api/requests/" + key)[2], first)
        public = self.request("GET", "/api/action-targets")[2]
        self.assertEqual(public["targets"][0]["destination"], "https://example.test")
        self.assert_private_response(public, "WEBHOOK-SECRET")
        _, profile, _ = self.create()
        self._restart()
        self.assertEqual(self.request("GET", "/api/action-targets")[2], public)
        self.assertEqual(self.request("POST", "/api/action-targets/remove", {"id": "team"})[0], 200)
        self.assertEqual(self.request("GET", "/api/action-targets")[2]["targets"], [])
        self.assertIn("team", json.loads((profile / "action-targets.json").read_text()))
        self.assertEqual(self.request("POST", "/api/action-targets", {**target, "id": "different"}, key=key)[0], 409)

    def test_target_settings_require_host_auth_and_reject_private_overlap(self):
        value = {"id": "file", "target": {"kind": "delete", "label": "不可选择内部记录", "workspace": str(self.root), "relative_path": "catalog.json"}}
        self.assertEqual(self.request("POST", "/api/action-targets", value)[0], 400)
        self.assertEqual(self.request("GET", "/api/action-targets", authenticated=False)[0], 401)
        self.assertEqual(self.request("POST", "/api/action-targets/remove", {"id": "x"}, origin=False)[0], 403)

    def test_defense_setting_change_keeps_task_labels_and_validates_new_binding(self):
        payload = {**self.payload, "objective": "读取报价，生成摘要，不得外发。"}
        identifier, profile, _ = self.create(payload)
        before = self.task_ids(profile)
        read_version = self.request("GET", f"/api/profiles/{identifier}/protection")[2]["policy_sha256"]
        status, _, accepted = self.request("POST", f"/api/profiles/{identifier}/protection", {"settings": {"command_enabled": False}, "expected_policy_sha256": read_version})
        self.assertEqual(status, 202)
        self.wait_job(accepted)
        manifest = core.validate_profile(profile)
        self.assertEqual(self.task_ids(profile), before)
        self.assertFalse(json.loads((profile / "defense-policy.json").read_text())["command_enabled"])
        from yuanxingmu.protection import profile_services
        resources, destinations = load_policy(profile / "policy.json")
        with Broker(profile / "broker-state", resources, destinations, **profile_services(profile, manifest)) as broker:
            self.assertEqual(broker.authority.describe(manifest["task_id"])["labels"], ["private"])
        self.assertEqual(self.request("GET", f"/api/profiles/{identifier}/protection")[0], 200)
        self.assertEqual(self.request("POST", f"/api/profiles/{identifier}/protection", {"settings": {"objective": "changed"}})[0], 400)

    def test_protection_history_skips_corrupt_lines_and_handles_wrong_evidence_type(self):
        identifier, profile, _ = self.create({**self.payload, "objective": "整理报价"})
        (profile / "defense-events.jsonl").write_text('[]\nnull\nnot-json\n' + json.dumps({"layer": "input", "verdict": "allow", "evidence": []}) + '\n')
        status, _, value = self.request("GET", f"/api/profiles/{identifier}/protection")
        self.assertEqual(status, 200, value)
        self.assertEqual(len(value["events"]), 1)
        self.assertEqual(value["events"][0]["evidence"], {})

    def test_protection_history_projects_only_valid_setting_values(self):
        identifier, profile, _ = self.create({**self.payload, "objective": "整理报价"})
        event = {"code": "operator_settings_changed", "layer": "foundation", "reason": "合成设置记录", "evidence": {
            "source": "workbench", "intent": "set", "changes": {
                "command_enabled": {"before": True, "after": False},
                "objective": {"before": "PRIVATE-OBJECTIVE", "after": "PRIVATE-NEW-OBJECTIVE"},
                "alignment_mode": {"before": "inherit", "after": "PRIVATE-INVALID-VALUE"},
                "api_key": {"before": "PRIVATE-KEY", "after": "PRIVATE-NEW-KEY"}}}}
        (profile / "defense-events.jsonl").write_text(json.dumps(event) + "\n")
        status, _, value = self.request("GET", f"/api/profiles/{identifier}/protection")
        self.assertEqual(status, 200, value)
        self.assertEqual(value["events"][0]["settings_history"]["changes"], {"command_enabled": {"before": True, "after": False}})
        self.assertNotIn("PRIVATE-", json.dumps(value))

    def test_creation_and_reset_preserve_mode_semantics_and_restore_recommended_scans(self):
        from yuanxingmu.protection import configure_profile
        identifier, profile, _ = self.create({**self.payload, "objective": "整理报价", "defense": {
            "mode": "observe", "command_mode": "enforce", "skill_semantic_enabled": False}})
        view = self.request("GET", f"/api/profiles/{identifier}/protection")[2]
        self.assertEqual(view["effective_modes"]["command"], "enforce")
        self.assertEqual(view["effective_modes"]["input"], "observe")
        self.assertFalse(view["foundation_scans"]["skill_semantic"])
        from yuanxingmu.guards import GuardPolicy
        status, _, accepted = self.request("POST", f"/api/profiles/{identifier}/protection", {"settings": GuardPolicy("recommended").settings(), "expected_policy_sha256": view["policy_sha256"]})
        self.assertEqual(status, 202, accepted)
        reset = self.wait_job(accepted)["result"]
        self.assertEqual(reset["policy"]["mode"], "enforce")
        self.assertEqual(reset["policy"]["command_mode"], "inherit")
        current = configure_profile(profile)["policy"]
        self.assertEqual(current["mode"], "enforce")
        self.assertTrue(current["foundation_config_enabled"])
        self.assertTrue(current["skill_semantic_enabled"])
        self.assertTrue(all(current[name + "_enabled"] for name in ("input", "memory", "command", "alignment", "foundation")))
        view = self.request("GET", f"/api/profiles/{identifier}/protection")[2]
        self.assertEqual(set(view["effective_modes"].values()), {"enforce"})
        core.validate_profile(profile)
        for bad in ({"input_mode": "off"}, {"skill_semantic_enabled": 1}, {"foundation_config_enabled": "off"}):
            self.assertEqual(self.request("POST", f"/api/profiles/{identifier}/protection", {"settings": bad})[0], 400)
            self.assertEqual(self.request("POST", "/api/profiles", {**self.payload, "objective": "整理报价", "defense": bad})[0], 400)

    def test_cli_cannot_desynchronize_a_workbench_managed_profile(self):
        from yuanxingmu.protection import configure_profile
        identifier, profile, _ = self.create({**self.payload, "objective": "整理报价"})
        files = ("profile.json", "defense-policy.json", "broker-state/bindings.json", "broker-state/authority.sqlite3")
        before = {name: (profile / name).read_bytes() for name in files}
        for changes in ({"command_mode": "observe"}, {"mode": "observe"}, None):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, "workbench_managed_profile"):
                configure_profile(profile, changes, reset=changes is None)
        for name, original in before.items():
            self.assertEqual((profile / name).read_bytes(), original)
        self.assertFalse((profile / "broker-state" / "guard-session.dirty").exists())
        self.assertEqual(configure_profile(profile)["policy"]["mode"], "enforce")
        self.assertEqual(self.request("GET", f"/api/profiles/{identifier}/protection")[0], 200)

    def test_selected_skill_uses_fixed_copy_and_rejects_unregistered_directory(self):
        skill = self.base / "selected-skill"
        skill.mkdir()
        (skill / "SKILL.md").write_text("---\nname: quote-helper\ndescription: Summarize a quote.\n---\nRead the quotation and state its date.\n")
        self.manager.skill_sources = {"quote-helper": skill}
        _, profile, _ = self.create({**self.payload, "skills": ["quote-helper"]})
        manifest = core.validate_profile(profile)
        snapshot = Path(manifest["skills_snapshot"]["tree_path"])
        (skill / "SKILL.md").write_text("changed source")
        self.assertNotEqual((snapshot / "quote-helper" / "SKILL.md").read_text(), "changed source")
        core.validate_profile(profile)
        self.assertEqual(self.request("POST", "/api/profiles", {**self.payload, "skills": ["unregistered"]})[0], 400)

    def mail_fixture(self):
        identifier, path, _ = self.create()
        resources, destinations = load_policy(path / "policy.json")
        from yuanxingmu.protection import profile_services
        with Broker(path / "broker-state", resources, destinations, **profile_services(path, core.validate_profile(path))) as broker:
            task_id = self.task_ids(path)[0]
            masked = broker.dispatch(task_id, {"op": "read", "resource": "quote"})["content"]
            row = broker.mail.submit(task_id, uuid.uuid4().hex, {
                "recipient": "buyer@example.test", "subject": "报价待确认", "body": masked})
        return identifier, path, row

    def mail_settings(self, **changes):
        return {"host": "smtp.example.test", "port": 465, "username": "synthetic-user",
                "password": "MAIL-SECRET-NEVER-IN-API", "from_address": "sender@example.test", **changes}

    @staticmethod
    def mail_reference(row):
        return {"draft_id": row["id"], "revision": row["revision"], "digest": row["digest"]}

    def test_mail_account_is_private_durable_and_changes_invalidate_old_confirmation(self):
        self.assertFalse(self.request("GET", "/api/mail-account")[2]["configured"])
        settings, key = self.mail_settings(), uuid.uuid4().hex
        status, _, account = self.request("POST", "/api/mail-account", settings, key=key)
        self.assertEqual(status, 200)
        self.assertNotIn("password", account)
        self.assertNotIn(settings["password"], json.dumps(account))
        self.assertEqual(self.request("POST", "/api/mail-account", settings, key=key)[2], account)
        self.assertEqual(self.request("POST", "/api/mail-account", self.mail_settings(password="changed"), key=key)[0], 409)
        self._restart()
        self.assertEqual(self.request("GET", "/api/mail-account")[2], account)
        self.assertEqual((self.root / "catalog.json").stat().st_mode & 0o077, 0)
        identifier, _, row = self.mail_fixture()
        changed = self.request("POST", "/api/mail-account", self.mail_settings(from_address="new@example.test"))[2]
        self.assertNotEqual(account["account_id"], changed["account_id"])
        self.assertEqual(self.request("POST", "/api/mail-account", settings, key=key)[0], 409)
        with mock.patch("yuanxingmu.broker.send_email") as send:
            status, _, rejected = self.request("POST", f"/api/profiles/{identifier}/mail/send",
                {**self.mail_reference(row), "account_id": account["account_id"], "confirm": "send"})
            self.assertEqual(status, 409)
            self.assertEqual(rejected["error"]["code"], "mail_account_changed")
            send.assert_not_called()

    def test_mail_routes_require_same_origin_token_and_exact_confirmation_fields(self):
        identifier, _, row = self.mail_fixture()
        reference = self.mail_reference(row)
        settings = self.mail_settings()
        account = self.request("POST", "/api/mail-account", settings)[2]
        send_payload = {**reference, "account_id": account["account_id"], "confirm": "send"}
        routes = [("GET", "/api/mail-account", None), ("POST", "/api/mail-account", settings),
                  ("GET", f"/api/profiles/{identifier}/mail", None),
                  ("GET", f"/api/profiles/{identifier}/mail/{row['id']}", None),
                  ("POST", f"/api/profiles/{identifier}/mail/send", send_payload),
                  ("POST", f"/api/profiles/{identifier}/mail/cancel", reference),
                  ("POST", f"/api/profiles/{identifier}/mail/edit", {**reference, "draft": {
                      "recipient": "buyer@example.test", "subject": "edited", "body": "edited"}})]
        with mock.patch("yuanxingmu.broker.send_email") as send:
            for method, route, value in routes:
                with self.subTest(route=route, method=method):
                    self.assertEqual(self.request(method, route, value, authenticated=False)[0], 401)
                    self.assertEqual(self.request(method, route, value, headers={"Origin": "https://evil.example"})[0], 403)
                    self.assertEqual(self.request(method, route, value, headers={"Host": "evil.example"})[0], 403)
            for field in ("draft", "body", "password", "account", "from_address", "approved"):
                self.assertEqual(self.request("POST", f"/api/profiles/{identifier}/mail/send", {**send_payload, field: "injected"})[0], 400)
            self.assertEqual(self.request("POST", f"/api/profiles/{identifier}/mail/send", {**send_payload, "confirm": True})[0], 400)
            send.assert_not_called()

    def test_mail_edit_requires_fresh_content_and_send_attempt_is_never_repeated(self):
        identifier, path, row = self.mail_fixture()
        prefix = f"/api/profiles/{identifier}/mail"
        listing = self.request("GET", prefix)[2]
        self.assertTrue(listing["supported"])
        self.assertNotIn("body", listing["drafts"][0])
        self.assertEqual(self.request("GET", prefix + "/" + row["id"])[2]["draft"]["body"], row["body"])
        changed = {"recipient": "confirmed@example.test", "subject": "确认后的报价", "body": "只发确认的金额 200000 元。"}
        edited = self.wait_job(self.request("POST", prefix + "/edit", {**self.mail_reference(row), "draft": changed})[2])["result"]["draft"]
        self.assertEqual(edited["revision"], 2)
        account = self.request("POST", "/api/mail-account", self.mail_settings())[2]
        payload = {**self.mail_reference(edited), "account_id": account["account_id"], "confirm": "send"}
        with mock.patch("yuanxingmu.broker.send_email", return_value={"outcome": "acknowledged"}) as send:
            stale = self.wait_job(self.request("POST", prefix + "/send", {**payload, **self.mail_reference(row)})[2], expected="failed")
            self.assertEqual(stale["error"]["code"], "mail_draft_changed")
            send.assert_not_called()
            key = uuid.uuid4().hex
            accepted = self.request("POST", prefix + "/send", payload, key=key)[2]
            sent = self.wait_job(accepted)
            self.assertEqual(sent["result"]["draft"]["status"], "acknowledged")
            self.assertEqual(send.call_args.args[1], changed)
            self.assertNotIn(self.mail_settings()["password"], json.dumps(sent))
            replay = self.request("POST", prefix + "/send", payload, key=key)[2]
            self.assertEqual(replay["job"]["id"], accepted["job"]["id"])
            self.wait_job(self.request("POST", prefix + "/send", payload)[2])
            self._restart()
            self.wait_job(self.request("POST", prefix + "/send", payload)[2])
            send.assert_called_once()
        self.assertEqual(core.control_profile(path, "status")["task"]["labels"], ["private"])
        self.assertEqual(load_policy(path / "policy.json")[1], {})

    def test_mail_unknown_result_is_durable_and_revocation_blocks_pending_draft(self):
        identifier, path, row = self.mail_fixture()
        prefix = f"/api/profiles/{identifier}/mail"
        account = self.request("POST", "/api/mail-account", self.mail_settings())[2]
        payload = {**self.mail_reference(row), "account_id": account["account_id"], "confirm": "send"}
        with mock.patch("yuanxingmu.broker.send_email", return_value={"outcome": "unconfirmed"}) as send:
            sent = self.wait_job(self.request("POST", prefix + "/send", payload)[2])
            self.assertEqual(sent["result"]["draft"]["status"], "unconfirmed")
            self._restart()
            self.wait_job(self.request("POST", prefix + "/send", payload)[2])
            send.assert_called_once()
        resources, destinations = load_policy(path / "policy.json")
        from yuanxingmu.protection import profile_services
        with Broker(path / "broker-state", resources, destinations, **profile_services(path, core.validate_profile(path))) as broker:
            other = broker.mail.submit(self.task_ids(path)[0], uuid.uuid4().hex, {
                "recipient": "other@example.test", "subject": "不能发送", "body": "撤权检查"})
        self.wait_job(self.request("POST", f"/api/profiles/{identifier}/revoke", {"confirm": "revoke"})[2])
        with mock.patch("yuanxingmu.broker.send_email") as send:
            failed = self.wait_job(self.request("POST", prefix + "/send", {
                **payload, **self.mail_reference(other)})[2], expected="failed")
            self.assertEqual(failed["error"]["code"], "task_revoked")
            send.assert_not_called()
        self.assertFalse(self.request("GET", prefix)[2]["active"])

    def test_mail_cancellation_and_cross_work_draft_identity_are_enforced(self):
        identifier, _, row = self.mail_fixture()
        other_id, _, _ = self.create()
        prefix = f"/api/profiles/{identifier}/mail"
        reference = self.mail_reference(row)
        failure = self.wait_job(self.request("POST", f"/api/profiles/{other_id}/mail/cancel", reference)[2], expected="failed")
        self.assertEqual(failure["status"], "failed")
        cancelled = self.wait_job(self.request("POST", prefix + "/cancel", reference)[2])["result"]["draft"]
        self.assertEqual(cancelled["status"], "cancelled")
        account = self.request("POST", "/api/mail-account", self.mail_settings())[2]
        with mock.patch("yuanxingmu.broker.send_email") as send:
            failure = self.wait_job(self.request("POST", prefix + "/send", {**reference, "account_id": account["account_id"], "confirm": "send"})[2], expected="failed")
            self.assertEqual(failure["error"]["code"], "mail_draft_not_pending")
            send.assert_not_called()

    def test_real_http_requires_token_and_returns_defensive_headers(self):
        with mock.patch.object(core, "init_profile") as initialize, mock.patch.object(core, "start_profile") as start, \
             mock.patch.object(core, "control_profile") as control:
            for method, path, value in (("GET", "/api/info", None), ("GET", "/api/profiles", None),
                                        ("POST", "/api/profiles", self.payload)):
                with self.subTest(method=method, path=path):
                    status, headers, result = self.request(method, path, value, authenticated=False)
                    self.assertEqual(status, 401)
                    self.assertEqual(result["error"]["code"], "unauthorized")
                    self.assertEqual(headers["Cache-Control"], "no-store")
                    self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                    self.assertEqual(headers["Referrer-Policy"], "no-referrer")
                    self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
                    self.assertNotIn("Access-Control-Allow-Origin", headers)
            status, _, result = self.request("GET", "/api/info", origin=False)
            self.assertEqual(status, 200)
            self.assertEqual(result["application"], "元星木")
            self.assertEqual(result["limits"], {"documents": 8, "document_bytes": 262144, "total_document_bytes": 1048576})
            self.assertEqual(self.server.server_address[0], "127.0.0.1")
            self.assertEqual(self.request("GET", "/api/info", headers={"Authorization": "Bearer wrong"})[0], 401)
            initialize.assert_not_called()
            start.assert_not_called()
            control.assert_not_called()

    def test_host_origin_and_duplicate_sensitive_headers_never_invoke_core(self):
        body = json.dumps(self.payload).encode()
        cases = []
        for name, value, expected in (("Host", "evil.example", 403), ("Origin", "https://evil.example", 403),
                                      ("Origin", "null", 403), ("Authorization", "Bearer wrong", 401)):
            headers = [(k, value if k == name else v) for k, v in self.raw_headers(body)]
            cases.append((name + " mismatch", headers, expected))
        for name in ("Host", "Origin", "Authorization", "Content-Length", "Content-Type", "Idempotency-Key"):
            headers = self.raw_headers(body)
            value = next(v for k, v in headers if k == name)
            cases.append(("duplicate " + name, headers + [(name.lower(), value)], 400))
        cases.append(("missing Origin", [(k, v) for k, v in self.raw_headers(body) if k != "Origin"], 403))
        cases.append(("missing Host", [(k, v) for k, v in self.raw_headers(body) if k != "Host"], 400))
        with mock.patch.object(core, "init_profile") as initialize, mock.patch.object(core, "start_profile") as start, \
             mock.patch.object(core, "control_profile") as control:
            for label, headers, expected in cases:
                with self.subTest(label=label):
                    self.assertEqual(self.raw_request("POST", "/api/profiles", headers, body)[0], expected)
            self.assertEqual(self.request("GET", "/api/profiles", headers={"Origin": "https://evil.example"})[0], 403)
            initialize.assert_not_called()
            start.assert_not_called()
            control.assert_not_called()
        self.assertEqual(self.manager.profiles(), {"profiles": []})

    def test_gets_unsupported_methods_and_noncanonical_paths_cannot_mutate(self):
        identifier = "a" * 32
        paths = [f"/api/profiles/{identifier}/{action}" for action in ("start", "stop", "revoke")]
        paths += ["/api/../api/profiles", "/%61pi/profiles", "/api/profiles?access=" + self.manager.token,
                  "//api/profiles", self.origin + "/api/profiles", "/../catalog.json", "/profiles/../catalog.json",
                  "/api/profiles/%2e%2e/start", "/api/profiles/../../outside/start"]
        with mock.patch.object(core, "init_profile") as initialize, mock.patch.object(core, "start_profile") as start, \
             mock.patch.object(core, "control_profile") as control:
            for target in paths:
                with self.subTest(target=target):
                    headers = [("Host", self.host), ("Authorization", "Bearer " + self.manager.token)]
                    self.assertEqual(self.raw_request("GET", target, headers)[0], 404)
            for method in ("HEAD", "PUT", "DELETE", "PATCH", "OPTIONS"):
                with self.subTest(method=method):
                    self.assertEqual(self.request(method, "/api/profiles")[0], 405)
            initialize.assert_not_called()
            start.assert_not_called()
            control.assert_not_called()

    def test_invalid_framing_and_json_never_invoke_initializer(self):
        cases = []
        for length in (None, "-1", "+2", "2, 2", str(dashboard.MAX_BODY + 1)):
            headers = [(k, v) for k, v in self.raw_headers() if k != "Content-Length"]
            if length is not None:
                headers.append(("Content-Length", length))
            cases.append(("length " + str(length), headers, b"{}", 413 if length == str(dashboard.MAX_BODY + 1) else 400))
        for name, value in (("Transfer-Encoding", "chunked"), ("Expect", "100-continue")):
            cases.append((name, self.raw_headers() + [(name, value)], b"{}", 400))
        cases.append(("truncated body", self.raw_headers(b"123456"), b"{}", 400))
        for raw in (b"\xff", b"{", b'{"name":"a","name":"b"}', b'{"documents":[{"name":"a","name":"b"}]}',
                    b'{"x":NaN}', b'{"x":Infinity}'):
            cases.append(("JSON " + repr(raw), self.raw_headers(raw), raw, 400))
        with mock.patch.object(core, "init_profile") as initialize:
            for label, headers, body, expected in cases:
                with self.subTest(label=label):
                    status, _, result = self.raw_request("POST", "/api/profiles", headers, body)
                    self.assertEqual(status, expected, result)
            self.assertEqual(self.raw_request("GET", "/api/profiles", self.raw_headers(), b"{}")[0], 400)
            initialize.assert_not_called()
        self.assertEqual(list((self.root / "profiles").iterdir()), [])

    def test_browser_payload_cannot_select_paths_policy_runtime_or_commands(self):
        with mock.patch.object(core, "init_profile") as initialize:
            for field in ("profile", "path", "node", "bwrap", "openclaw_package", "port", "destinations", "policy", "command"):
                with self.subTest(field=field):
                    value = {**self.payload, field: "/tmp/not-authorized"}
                    self.assertEqual(self.request("POST", "/api/profiles", value)[0], 400)
            for patch in ({"name": "../escape"}, {"filename": "../../outside.txt"}, {"filename": "C:\\secrets.txt"},
                          {"path": "/etc/passwd"}):
                with self.subTest(document=patch):
                    value = copy.deepcopy(self.payload)
                    value["documents"][0].update(patch)
                    self.assertEqual(self.request("POST", "/api/profiles", value)[0], 400)
            initialize.assert_not_called()
        self.assertEqual(list((self.root / "profiles").iterdir()), [])

    def test_utf8_and_document_limits_are_measured_in_bytes(self):
        cases = []
        for patch in ({"content": "\ud800"}, {"filename": "\udfff"}, {"content": ["not text"]}):
            value = copy.deepcopy(self.payload)
            value["documents"][0].update(patch)
            cases.append((value, 400))
        value = copy.deepcopy(self.payload)
        value["documents"][0]["content"] = "价" * 87382  # 262146 UTF-8 bytes.
        cases.append((value, 413))
        value = copy.deepcopy(self.payload)
        value["documents"] *= 2
        cases.append((value, 400))
        value = copy.deepcopy(self.payload)
        value["documents"] = [{"name": "d" + str(i), "filename": "f.txt", "content": "x"} for i in range(9)]
        cases.append((value, 400))
        value = copy.deepcopy(self.payload)
        value["documents"] = [{"name": "d" + str(i), "filename": "f.txt", "content": "x" * 210000} for i in range(5)]
        cases.append((value, 413))
        with mock.patch.object(core, "init_profile") as initialize:
            for value, expected in cases:
                with self.subTest(expected=expected, document_count=len(value["documents"])):
                    self.assertEqual(self.request("POST", "/api/profiles", value)[0], expected)
            initialize.assert_not_called()
        boundary = copy.deepcopy(self.payload)
        boundary["documents"] = [{"name": "d" + str(i), "filename": "f.txt", "content": "x" * 262144} for i in range(4)]
        _, path, job = self.create(boundary)
        self.assertEqual(sum(item["bytes"] for item in job["result"]["profile"]["documents"]), 1048576)
        self.assertEqual(sorted(file.stat().st_size for file in (path / "documents").iterdir()), [262144] * 4)

    def test_model_connection_and_request_key_validation_precede_runtime(self):
        values = []
        for url in ("http://remote.example/v1", "file:///etc/passwd", "https://u:p@example.com/v1", "https://@example.com/v1",
                    "https://example.com/v1?key=secret", "https://example.com/v1#x", "https://example.com:99999/v1",
                    "https://example.com:bad/v1", "https://example.com/has space", "https://example.com\\v1"):
            values.append({**self.payload, "model_url": url})
        values += [{**self.payload, "name": ""}, {**self.payload, "api_key": "key\nheader"},
                   {**self.payload, "api_key": "key with space"}, {**self.payload, "api_key": "中文密钥"},
                   {**self.payload, "model_id": "\ud800"}, {**self.payload, "model_url": "https://example.com/v1", "api_key": ""}]
        with mock.patch.object(core, "init_profile") as initialize:
            for value in values:
                with self.subTest(value=value["model_url"]):
                    self.assertEqual(self.request("POST", "/api/profiles", value)[0], 400)
            for key in ("short", "A" * 32, "g" * 32):
                self.assertEqual(self.request("POST", "/api/profiles", self.payload, key=key)[0], 400)
            initialize.assert_not_called()

    def test_real_profile_defaults_private_and_revoke_survives_workbench_restart(self):
        identifier, path, _ = self.create()
        task_ids = self.task_ids(path)
        initial = core.control_profile(path, "status")
        self.assertEqual(initial["status"], "stopped")
        self.assertEqual(initial["task"]["labels"], ["private"])
        resources, destinations = load_policy(path / "policy.json")
        self.assertEqual(destinations, {})
        self.assertEqual(resources["quote"].labels, ("private",))
        from yuanxingmu.protection import profile_services
        with Broker(path / "broker-state", resources, destinations, **profile_services(path, core.validate_profile(path))) as broker:
            read = broker.dispatch(task_ids[0], {"op": "read", "resource": "quote"})
            self.assertTrue(read["allowed"])
            self.assertNotIn("186000", read["content"])
            self.assertIn("DOCUMENT-CONTENT-MUST-STAY-PRIVATE", read["content"])
            denied = broker.dispatch(task_ids[0], {"op": "send", "destination": "public", "body": self.content})
            self.assertEqual(denied["reason"], "unknown_destination")
        with mock.patch.object(core, "control_profile", wraps=core.control_profile) as control:
            self.assertEqual(self.request("POST", f"/api/profiles/{identifier}/revoke", {})[0], 400)
            control.assert_not_called()
        status, _, accepted = self.request("POST", f"/api/profiles/{identifier}/revoke", {"confirm": "revoke"})
        self.assertEqual(status, 202)
        revoked = self.wait_job(accepted)
        self.assertTrue(revoked["result"]["profile"]["revoked"])
        self._restart()
        self.assertTrue(self.manager.profiles()["profiles"][0]["revoked"])
        with mock.patch.object(core, "init_profile", side_effect=AssertionError("must not replace authority")) as initialize, \
             mock.patch.object(core.subprocess, "Popen", side_effect=AssertionError("revoked fixture must not launch")) as launch:
            accepted = self.manager.submit("start", identifier, {}, uuid.uuid4().hex)
            failed = self.wait_job(accepted, expected="failed")
            self.assertEqual(failed["error"]["code"], "task_revoked")
            initialize.assert_not_called()
            launch.assert_not_called()
        self.assertEqual(self.task_ids(path), task_ids)
        with Broker(path / "broker-state", resources, destinations, **profile_services(path, core.validate_profile(path))) as broker:
            self.assertEqual(broker.dispatch(task_ids[0], {"op": "read", "resource": "quote"})["reason"], "task_revoked")

    def test_uploads_are_private_snapshots_and_status_receipts_do_not_contain_secrets(self):
        identifier, path, job = self.create()
        self.assertEqual(list((self.root / "imports").iterdir()), [])
        self.assertEqual((path / "documents" / "quote.txt").read_text(), self.content)
        for response in (job, self.manager.profiles(), self.manager.job(job["id"]), self.manager.info()):
            self.assert_private_response(response)
        raw_catalog = (self.root / "catalog.json").read_text()
        self.assertNotIn(self.secret, raw_catalog)
        self.assertNotIn(self.content, raw_catalog)
        for name in ("catalog.json", "manager.lock"):
            self.assertEqual((self.root / name).stat().st_mode & 0o077, 0)
        with mock.patch.object(core, "start_profile", side_effect=RuntimeError(self.secret + " " + self.content)):
            failed = self.wait_job(self.manager.submit("start", identifier, {}, uuid.uuid4().hex), expected="failed")
            self.assert_private_response(failed)
        with mock.patch.object(core, "control_profile", side_effect=RuntimeError(self.secret + " " + self.content)):
            status, _, result = self.request("GET", "/api/profiles")
            self.assertEqual(status, 200)
            self.assertEqual(result["profiles"][0]["status"], "failed")
            self.assert_private_response(result)

    def test_extra_mutation_fields_unknown_ids_and_paths_do_not_call_runtime(self):
        identifier, _, _ = self.create()
        with mock.patch.object(core, "start_profile") as start, mock.patch.object(core, "control_profile") as control, \
             mock.patch.object(core, "init_profile") as initialize:
            for action, value in (("start", {"command": "anything"}), ("stop", {"force": True}),
                                  ("revoke", {}), ("revoke", {"confirm": "revoke", "restore": True})):
                self.assertEqual(self.request("POST", f"/api/profiles/{identifier}/{action}", value)[0], 400)
            for path in ("/api/profiles/" + "f" * 32 + "/start", "/api/profiles/../../escape/start",
                         "/api/profiles/A" + identifier[1:] + "/start"):
                self.assertEqual(self.request("POST", path, {})[0], 404)
            start.assert_not_called()
            control.assert_not_called()
            initialize.assert_not_called()

    def test_per_profile_mutator_is_serialized_and_retries_keep_one_job(self):
        identifier, path, _ = self.create()
        entered, release = threading.Event(), threading.Event()
        key = uuid.uuid4().hex
        token = "NATIVE-DASHBOARD-TOKEN-ONLY-IN-START-JOB"

        def delayed_start(profile):
            self.assertEqual(profile, path)
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test release timed out")
            actual = core.control_profile(profile, "status")
            return {**actual, "status": "ready", "dashboard_url": actual["url"] + "#token=" + token}

        with mock.patch.object(core, "start_profile", side_effect=delayed_start) as start:
            try:
                status, _, accepted = self.request("POST", f"/api/profiles/{identifier}/start", {}, key=key)
                self.assertEqual(status, 202)
                self.assertTrue(entered.wait(2))
                retry = self.request("POST", f"/api/profiles/{identifier}/start", {}, key=key)
                self.assertEqual(retry[0], 202)
                self.assertEqual(retry[2]["job"]["id"], accepted["job"]["id"])
                for action, value in (("start", {}), ("stop", {}), ("revoke", {"confirm": "revoke"})):
                    response = self.request("POST", f"/api/profiles/{identifier}/{action}", value)
                    self.assertEqual(response[0], 409)
                    self.assertEqual(response[2]["error"]["code"], "profile_busy")
                summary = self.manager.profiles()["profiles"][0]
                self.assertEqual(summary["pending"], "start")
                self.assertEqual(summary["status"], "stopped")  # Real status, not an invented ready state.
                start.assert_called_once()
            finally:
                release.set()
            job = self.wait_job(accepted)
            self.assertIsNone(job["result"]["profile"]["pending"])
            self.assertEqual(job["result"]["dashboard_url"].split("#token=")[1], token)
            repeated = self.manager.submit("start", identifier, {}, key)
            self.assertEqual(repeated["job"]["id"], job["id"])
            start.assert_called_once()
        self.assert_private_response(self.manager.profiles(), token)
        self.assertNotIn(token, (self.root / "catalog.json").read_text())

    def test_concurrent_offline_status_queries_serialize_the_real_profile_lock(self):
        identifier, path, _ = self.create()
        first_locked, release, second_admitted = threading.Event(), threading.Event(), threading.Event()
        admission_lock = threading.Lock()
        admissions = 0
        real_profile_lock = core._profile_lock
        real_summary = self.manager.summary

        @contextmanager
        def held_first_status(profile):
            # Keep the real nonblocking flock held while the other HTTP request arrives.
            with real_profile_lock(profile):
                if not first_locked.is_set():
                    first_locked.set()
                    if not release.wait(5):
                        raise RuntimeError("test did not release the first offline status")
                yield

        def admitted_summary(*args, **kwargs):
            nonlocal admissions
            with admission_lock:
                admissions += 1
                if admissions == 2:
                    second_admitted.set()
            return real_summary(*args, **kwargs)

        with mock.patch.object(core, "_profile_lock", side_effect=held_first_status), \
             mock.patch.object(core, "control_profile", wraps=core.control_profile) as control, \
             mock.patch.object(self.manager, "summary", side_effect=admitted_summary), \
             ThreadPoolExecutor(max_workers=2) as queries:
            first = queries.submit(self.request, "GET", "/api/profiles")
            second = None
            try:
                self.assertTrue(first_locked.wait(2), "first query did not obtain the real core flock")
                second = queries.submit(self.request, "GET", "/api/profiles")
                self.assertTrue(second_admitted.wait(2), "second query did not reach the manager")
                with self.assertRaises(TimeoutError):
                    second.result(timeout=.2)
                self.assertEqual(control.call_count, 1, "the second query raced the core's exclusive flock")
            finally:
                release.set()
            for future in (first, second):
                status, _, result = future.result(timeout=3)
                self.assertEqual(status, 200, result)
                summary, = result["profiles"]
                self.assertEqual((summary["id"], summary["status"]), (identifier, "stopped"))
                self.assertIsNone(summary["pending"])
                self.assertNotIn("error", summary)
            self.assertEqual(control.call_count, 2)
        self.assertEqual(core.control_profile(path, "status")["status"], "stopped")

    def test_polling_during_real_start_lock_uses_pending_then_refreshes_after_completion(self):
        identifier, path, _ = self.create()
        actual = core.control_profile(path, "status")
        token = "SYNTHETIC-START-LOCK-TOKEN-ONLY-IN-RECEIPT"
        for restart, expected_job, expected_pending_status in ((False, "succeeded", "stopped"), (True, "failed", "starting")):
            with self.subTest(restart=restart, expected_job=expected_job):
                if restart:
                    self._restart()  # No previous observation is available in this manager.
                entered, release = threading.Event(), threading.Event()

                def locked_start(profile):
                    self.assertEqual(profile, path)
                    with core._profile_lock(profile):
                        entered.set()
                        if not release.wait(5):
                            raise RuntimeError("test did not release the start flock")
                        if expected_job == "failed":
                            raise RuntimeError("synthetic start failed after holding the real profile lock")
                        return {**actual, "status": "ready", "dashboard_url": actual["url"] + "#token=" + token}

                with mock.patch.object(core, "start_profile", side_effect=locked_start) as start, \
                     mock.patch.object(core, "control_profile", wraps=core.control_profile) as control:
                    status, _, accepted = self.request("POST", f"/api/profiles/{identifier}/start", {})
                    self.assertEqual(status, 202, accepted)
                    try:
                        self.assertTrue(entered.wait(2), "start did not obtain the real core flock")
                        for _ in range(3):
                            status, _, result = self.request("GET", "/api/profiles")
                            self.assertEqual(status, 200, result)
                            summary, = result["profiles"]
                            self.assertEqual((summary["status"], summary["pending"]), (expected_pending_status, "start"))
                            self.assertNotIn("error", summary)
                        control.assert_not_called()
                        status, _, pending = self.request("GET", "/api/jobs/" + accepted["job"]["id"])
                        self.assertEqual(status, 200)
                        self.assertEqual(pending["job"]["status"], "running")
                    finally:
                        release.set()
                    job = self.wait_job(accepted, expected=expected_job)
                    start.assert_called_once()
                    control.assert_not_called()
                    if expected_job == "succeeded":
                        self.assertEqual(job["result"]["profile"]["status"], "ready")
                        self.assertIsNone(job["result"]["profile"]["pending"])
                    else:
                        self.assertNotIn("result", job)
                    # This mock never launches OpenClaw. A fresh real query must
                    # now report stopped, rather than retain the mock's ready state.
                    status, _, refreshed = self.request("GET", "/api/profiles")
                    self.assertEqual(status, 200, refreshed)
                    summary, = refreshed["profiles"]
                    self.assertEqual(summary["status"], "stopped")
                    self.assertIsNone(summary["pending"])
                    self.assertNotIn("error", summary)
                    control.assert_called_once_with(path, "status")
                    self.assert_private_response(refreshed, token)

    def test_status_already_waiting_before_start_rechecks_pending_instead_of_waiting_for_start(self):
        identifier, path, _ = self.create()
        actual = core.control_profile(path, "status")
        reader_waiting, start_entered, release_start = threading.Event(), threading.Event(), threading.Event()
        original_lock = self.manager._core_lock(identifier)

        class ScheduledLock:
            """A real RLock with a deterministic pause before a reader waits.

            The reader reaches its timed wait before start is submitted. The
            scheduler then lets start own the lock before resuming that wait.
            """
            def acquire(self, blocking=True, timeout=-1):
                if timeout >= 0:
                    reader_waiting.set()
                    if not start_entered.wait(3):
                        raise RuntimeError("start did not run before the queued reader resumed")
                    return original_lock.acquire(blocking, timeout)
                return original_lock.acquire(blocking)

            def release(self):
                original_lock.release()

        scheduled = ScheduledLock()

        def locked_start(profile):
            with core._profile_lock(profile):
                start_entered.set()
                if not release_start.wait(5):
                    raise RuntimeError("test did not release the queued start")
                return {**actual, "status": "ready", "dashboard_url": actual["url"] + "#token=SYNTHETIC-QUEUED-START-TOKEN"}

        with mock.patch.dict(self.manager.core_locks, {identifier: scheduled}), \
             mock.patch.object(core, "start_profile", side_effect=locked_start), \
             mock.patch.object(core, "control_profile", wraps=core.control_profile) as control, \
             ThreadPoolExecutor(max_workers=1) as queries:
            scheduled.acquire()
            initially_held = True
            queued = queries.submit(self.request, "GET", "/api/profiles")
            try:
                self.assertTrue(reader_waiting.wait(2), "GET did not start waiting before the mutation")
                accepted = self.manager.submit("start", identifier, {}, uuid.uuid4().hex)
                scheduled.release()
                initially_held = False
                self.assertTrue(start_entered.wait(2), "start did not obtain both runtime and core locks")
                status, _, result = queued.result(timeout=2)
                self.assertEqual(status, 200, result)
                summary, = result["profiles"]
                self.assertEqual((summary["status"], summary["pending"]), ("stopped", "start"))
                self.assertNotIn("error", summary)
                control.assert_not_called()
                self.assertEqual(self.manager.job(accepted["job"]["id"])["job"]["status"], "running")
            finally:
                if initially_held:
                    scheduled.release()
                release_start.set()
            completed = self.wait_job(accepted)
            self.assertEqual(completed["result"]["profile"]["status"], "ready")
            self.assertIsNone(completed["result"]["profile"]["pending"])
            self.assertEqual(self.manager.profiles()["profiles"][0]["status"], "stopped")
            control.assert_called_once_with(path, "status")

    def test_cached_observation_keeps_pending_when_job_finishes_before_response(self):
        identifier, path, _ = self.create()
        actual = core.control_profile(path, "status")
        start_entered, release_start = threading.Event(), threading.Event()
        cache_taken, job_finished = threading.Event(), threading.Event()
        real_observe = self.manager._observe

        def locked_start(profile):
            with core._profile_lock(profile):
                start_entered.set()
                if not release_start.wait(5):
                    raise RuntimeError("test did not release the cached-observation start")
                return {**actual, "status": "ready", "dashboard_url": actual["url"] + "#token=SYNTHETIC-CACHED-OBSERVATION-TOKEN"}

        def finish_job_before_response(*args, **kwargs):
            observed = real_observe(*args, **kwargs)
            if not cache_taken.is_set():
                cache_taken.set()
                if not job_finished.wait(3):
                    raise RuntimeError("job did not finish before the cached response resumed")
            return observed

        with mock.patch.object(core, "start_profile", side_effect=locked_start), \
             mock.patch.object(core, "control_profile", wraps=core.control_profile) as control, \
             mock.patch.object(self.manager, "_observe", side_effect=finish_job_before_response), \
             ThreadPoolExecutor(max_workers=1) as queries:
            accepted = self.manager.submit("start", identifier, {}, uuid.uuid4().hex)
            try:
                self.assertTrue(start_entered.wait(2))
                delayed = queries.submit(self.request, "GET", "/api/profiles")
                self.assertTrue(cache_taken.wait(2), "query did not capture the pre-start observation")
                control.assert_not_called()
                release_start.set()
                completed = self.wait_job(accepted)
                self.assertEqual(completed["result"]["profile"]["status"], "ready")
                self.assertNotIn(identifier, self.manager.pending)
                job_finished.set()
                status, _, result = delayed.result(timeout=2)
                self.assertEqual(status, 200, result)
                summary, = result["profiles"]
                self.assertEqual((summary["status"], summary["pending"]), ("stopped", "start"))
                self.assertNotIn("error", summary)
                control.assert_not_called()
                status, _, refreshed = self.request("GET", "/api/profiles")
                self.assertEqual(status, 200, refreshed)
                summary, = refreshed["profiles"]
                self.assertEqual(summary["status"], "stopped")
                self.assertIsNone(summary["pending"])
                self.assertNotIn("error", summary)
                control.assert_called_once_with(path, "status")
            finally:
                release_start.set()
                job_finished.set()

    def test_create_idempotency_conflict_and_restart_never_allocate_another_task(self):
        key = uuid.uuid4().hex
        with mock.patch.object(core, "init_profile", wraps=core.init_profile) as initialize:
            identifier, path, first = self.create(key=key)
            retry = self.manager.submit("create", None, self.payload, key)
            self.assertEqual(retry["job"]["id"], first["id"])
            status, _, result = self.request("POST", "/api/profiles", {**self.payload, "name": "different"}, key=key)
            self.assertEqual(status, 409)
            self.assertEqual(result["error"]["code"], "request_conflict")
            initialize.assert_called_once()
        before = self.task_ids(path)
        old_access = self.manager.token
        self._restart()
        self.assertNotEqual(self.manager.token, old_access)
        self.assertEqual(self.request("GET", "/api/profiles", headers={"Authorization": "Bearer " + old_access})[0], 401)
        with mock.patch.object(core, "init_profile", side_effect=AssertionError("accepted create was replayed")) as initialize:
            retry = self.manager.submit("create", None, self.payload, key)
            self.assertEqual(retry["job"]["id"], first["id"])
            initialize.assert_not_called()
        self.assertEqual(self.task_ids(path), before)
        self.assertEqual([p["id"] for p in self.manager.profiles()["profiles"]], [identifier])

    def test_successful_start_url_is_not_persisted_or_recreated_after_restart(self):
        identifier, path, _ = self.create()
        observed = core.control_profile(path, "status")
        token = "SYNTHETIC-NATIVE-START-TOKEN-NEVER-DURABLE"
        key = uuid.uuid4().hex
        with mock.patch.object(core, "start_profile", return_value={**observed, "status": "ready", "dashboard_url": observed["url"] + "#token=" + token}):
            first = self.wait_job(self.manager.submit("start", identifier, {}, key))
        self.assertIn(token, first["result"]["dashboard_url"])
        self.assertNotIn(token, (self.root / "catalog.json").read_text())
        self._restart()
        with mock.patch.object(core, "start_profile", side_effect=AssertionError("start receipt replayed")) as start:
            stored = self.manager.job(first["id"])["job"]
            self.assertNotIn("dashboard_url", stored["result"])
            retried = self.manager.submit("start", identifier, {}, key)["job"]
            self.assertEqual(retried["id"], first["id"])
            self.assertNotIn("dashboard_url", retried["result"])
            start.assert_not_called()

    def test_partial_initialization_is_retained_and_exact_retry_is_not_reexecuted(self):
        key = uuid.uuid4().hex

        def partial(profile, **kwargs):
            profile.mkdir(mode=0o700)
            (profile / "partial-marker").write_text("keep this failed initialization", encoding="utf-8")
            raise RuntimeError(self.secret + " " + self.content)

        with mock.patch.object(core, "init_profile", side_effect=partial) as initialize:
            accepted = self.manager.submit("create", None, self.payload, key)
            failed = self.wait_job(accepted, expected="failed")
            identifier = failed["profile_id"]
            path = self.root / "profiles" / identifier
            self.assertTrue((path / "partial-marker").is_file())
            self.assertEqual(list((self.root / "imports").iterdir()), [])
            self.assertEqual(self.manager.profiles()["profiles"][0]["status"], "creation_failed")
            self.assert_private_response(failed)
            self.assertEqual(self.manager.submit("create", None, self.payload, key)["job"]["id"], failed["id"])
            initialize.assert_called_once()
        self._restart()
        with mock.patch.object(core, "init_profile", side_effect=AssertionError("partial initialization was replayed")) as initialize, \
             mock.patch.object(core, "start_profile") as start:
            self.assertEqual(self.manager.submit("create", None, self.payload, key)["job"]["id"], failed["id"])
            self.assertEqual(self.request("POST", f"/api/profiles/{identifier}/start", {})[0], 409)
            initialize.assert_not_called()
            start.assert_not_called()
        self.assertEqual((path / "partial-marker").read_text(), "keep this failed initialization")

    def test_killed_manager_recovers_accepted_job_as_failed_without_replay(self):
        child_root = self.base / "interrupted-manager"
        receipt = self.base / "accepted-receipt.json"
        key = uuid.uuid4().hex
        process = multiprocessing.get_context("spawn").Process(target=_accept_and_wait_for_interruption,
            args=(str(child_root), [str(self.node), str(self.package), str(self.bwrap)], self.payload, key, str(receipt)))
        process.start()
        accepted = None
        try:
            deadline = time.monotonic() + 5
            while process.is_alive() and time.monotonic() < deadline:
                try:
                    accepted = json.loads(receipt.read_text())
                    if accepted.get("job", {}).get("id"):
                        break
                except (FileNotFoundError, ValueError):
                    pass
                time.sleep(.01)
            self.assertIsNotNone(accepted, "child did not persist an accepted operation")
        finally:
            if process.is_alive():
                process.terminate()
            process.join(timeout=5)
            if process.is_alive():
                process.kill()
                process.join(timeout=3)
        self.assertIsNotNone(process.exitcode)
        with mock.patch.object(core, "init_profile", side_effect=AssertionError("interrupted create was replayed")) as initialize:
            recovered = dashboard.Workbench(child_root, self.runtime, port=0)
            try:
                job = recovered.job(accepted["job"]["id"])["job"]
                self.assertEqual(job["status"], "failed")
                self.assertEqual(job["error"]["code"], "manager_interrupted")
                self.assertEqual(recovered.profiles()["profiles"][0]["status"], "creation_failed")
                self.assertEqual(recovered.submit("create", None, self.payload, key)["job"]["id"], job["id"])
                initialize.assert_not_called()
            finally:
                recovered.close()

    def test_missing_ledger_is_not_recreated_or_reported_as_stopped(self):
        identifier, path, _ = self.create()
        ledger = path / "broker-state" / "authority.sqlite3"
        ledger.unlink()
        with mock.patch.object(core, "init_profile", side_effect=AssertionError("must not replace missing ledger")) as initialize, \
             mock.patch.object(core.subprocess, "Popen", side_effect=AssertionError("invalid profile launched")) as launch:
            summaries = self.manager.profiles()["profiles"]
            self.assertEqual(summaries[0]["status"], "failed")
            self.assertIn("error", summaries[0])
            self.wait_job(self.manager.submit("start", identifier, {}, uuid.uuid4().hex), expected="failed")
            initialize.assert_not_called()
            launch.assert_not_called()
        self.assertFalse(ledger.exists())

    def test_receipt_write_failure_starts_no_worker_and_refuses_further_mutations(self):
        key = uuid.uuid4().hex
        before = set(self.manager.jobs)
        with mock.patch.object(self.manager, "_save_jobs", side_effect=OSError("disk full " + self.secret)), \
             mock.patch.object(core, "init_profile") as initialize:
            with self.assertRaises(dashboard.APIError) as raised:
                self.manager.submit("create", None, self.payload, key)
            self.assertEqual((raised.exception.status, raised.exception.code), (503, "storage_unconfirmed"))
            initialize.assert_not_called()
        new_ids = set(self.manager.jobs) - before
        self.assertEqual(len(new_ids), 1)
        failed = self.manager.job(new_ids.pop())["job"]
        self.assertEqual(failed["status"], "failed")
        self.assert_private_response(failed)
        self.assertFalse(self.manager.workers)
        self.assertFalse(self.manager.pending)
        self.assertEqual(self.manager.profiles()["profiles"][0]["status"], "creation_failed")
        with mock.patch.object(core, "init_profile") as initialize:
            for request_key in (key, uuid.uuid4().hex):
                with self.assertRaises(dashboard.APIError) as raised:
                    self.manager.submit("create", None, self.payload, request_key)
                self.assertEqual(raised.exception.status, 503)
            initialize.assert_not_called()
        self.assertEqual(list((self.root / "profiles").iterdir()), [])

    def test_worker_start_failure_is_a_durable_failed_receipt_not_permanent_busy(self):
        key = uuid.uuid4().hex
        before = set(self.manager.jobs)
        with mock.patch.object(threading.Thread, "start", side_effect=RuntimeError("cannot start " + self.secret)), \
             mock.patch.object(core, "init_profile") as initialize:
            with self.assertRaises(dashboard.APIError) as raised:
                self.manager.submit("create", None, self.payload, key)
            self.assertEqual((raised.exception.status, raised.exception.code), (503, "worker_unavailable"))
            initialize.assert_not_called()
        failed_id, = set(self.manager.jobs) - before
        failed = self.manager.job(failed_id)["job"]
        self.assertEqual(failed["status"], "failed")
        self.assert_private_response(failed)
        self.assertFalse(self.manager.workers)
        self.assertFalse(self.manager.pending)
        stored = json.loads((self.root / "catalog.json").read_text())
        self.assertEqual(stored["jobs"][failed_id]["status"], "failed")
        self._restart()
        with mock.patch.object(core, "init_profile") as initialize:
            retried = self.manager.submit("create", None, self.payload, key)["job"]
            self.assertEqual((retried["id"], retried["status"]), (failed_id, "failed"))
            initialize.assert_not_called()
        _, _, created = self.create(key=uuid.uuid4().hex)
        self.assertEqual(created["status"], "succeeded")

    def test_unavailable_isolation_has_no_direct_execution_fallback(self):
        with mock.patch.object(dashboard.Runtime, "public", return_value={"available": False, "openclaw": "2026.9.4", "reason": "fixture unavailable"}), \
             mock.patch.object(core, "init_profile") as initialize:
            unavailable = dashboard.Workbench(self.base / "unavailable", self.runtime, port=0)
            try:
                self.assertFalse(unavailable.info()["runtime"]["available"])
                with self.assertRaises(dashboard.APIError) as raised:
                    unavailable.submit("create", None, self.payload, uuid.uuid4().hex)
                self.assertEqual((raised.exception.status, raised.exception.code), (409, "runtime_unavailable"))
                self.assertEqual(unavailable.profiles(), {"profiles": []})
                initialize.assert_not_called()
            finally:
                unavailable.close()

    def test_snapshot_drift_fails_existing_task_without_reinitializing(self):
        identifier, path, _ = self.create()
        before = self.task_ids(path)
        (path / "documents" / "quote.txt").write_text("changed bytes", encoding="utf-8")
        with mock.patch.object(core, "init_profile", side_effect=AssertionError("drift cannot create a new task")) as initialize, \
             mock.patch.object(core.subprocess, "Popen", side_effect=AssertionError("drifted profile launched")) as launch:
            summary = self.manager.profiles()["profiles"][0]
            self.assertEqual(summary["status"], "failed")
            self.wait_job(self.manager.submit("start", identifier, {}, uuid.uuid4().hex), expected="failed")
            initialize.assert_not_called()
            launch.assert_not_called()
        self.assertEqual(self.task_ids(path), before)

    def test_directory_replacement_and_unknown_catalog_identity_do_not_recover_by_init(self):
        identifier, path, _ = self.create()
        backup = path.with_name(identifier + "-original")
        path.rename(backup)
        path.mkdir(mode=0o700)
        with mock.patch.object(core, "init_profile") as initialize, mock.patch.object(core, "start_profile") as start:
            self.assertEqual(self.manager.profiles()["profiles"][0]["status"], "failed")
            self.assertEqual(self.request("POST", f"/api/profiles/{identifier}/start", {})[0], 409)
            self.assertEqual(self.request("POST", "/api/profiles/" + "f" * 32 + "/start", {})[0], 404)
            initialize.assert_not_called()
            start.assert_not_called()
        self.assertTrue((backup / "broker-state" / "authority.sqlite3").is_file())
        self.assertEqual(list(path.iterdir()), [])

    def test_catalog_identity_tampering_blocks_reopen_instead_of_creating_authority(self):
        identifier, path, _ = self.create()
        before = self.task_ids(path)
        self._shutdown()
        catalog_path = self.root / "catalog.json"
        saved = json.loads(catalog_path.read_text())
        changed = copy.deepcopy(saved)
        changed["profiles"][identifier]["id"] = "../../outside"
        catalog_path.write_text(json.dumps(changed), encoding="utf-8")
        with mock.patch.object(core, "init_profile") as initialize:
            with self.assertRaises((dashboard.APIError, ValueError, OSError)):
                dashboard.Workbench(self.root, self.runtime, port=0)
            initialize.assert_not_called()
        self.assertEqual(self.task_ids(path), before)
        self.assertEqual(json.loads(catalog_path.read_text())["profiles"][identifier]["id"], "../../outside")

    def test_symlink_or_missing_catalog_is_not_silently_replaced(self):
        self._shutdown()
        catalog = self.root / "catalog.json"
        backup = self.base / "catalog-original.json"
        catalog.rename(backup)
        with mock.patch.object(core, "init_profile") as initialize:
            with self.assertRaises((dashboard.APIError, ValueError, OSError)):
                dashboard.Workbench(self.root, self.runtime, port=0)
            self.assertFalse(catalog.exists())
            catalog.symlink_to(backup)
            with self.assertRaises((dashboard.APIError, ValueError, OSError)):
                dashboard.Workbench(self.root, self.runtime, port=0)
            self.assertTrue(catalog.is_symlink())
            initialize.assert_not_called()
        self.assertTrue(backup.is_file())

    def test_storage_exclusive_owner_and_private_permissions_are_required(self):
        with self.assertRaises((dashboard.APIError, OSError)):
            dashboard.Workbench(self.root, self.runtime, port=0)
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises((dashboard.APIError, OSError)):
            dashboard.Workbench(alias, self.runtime, port=0)
        unsafe = self.base / "public-storage"
        unsafe.mkdir(mode=0o755)
        unsafe.chmod(0o755)
        with self.assertRaises(dashboard.APIError):
            dashboard.Workbench(unsafe, self.runtime, port=0)
        self.assertFalse((unsafe / "catalog.json").exists())

    def test_unconfirmed_runtime_states_and_stop_failures_are_not_success(self):
        identifier, path, _ = self.create()
        actual = core.control_profile(path, "status")
        for state in ("interrupted", "unconfirmed", "failed", "invented-status"):
            with self.subTest(state=state), mock.patch.object(core, "control_profile", return_value={**actual, "status": state}):
                summary = self.manager.profiles()["profiles"][0]
                self.assertNotEqual(summary["status"], "stopped")
                self.assertIn("error", summary)
                failed = self.wait_job(self.manager.submit("stop", identifier, {}, uuid.uuid4().hex), expected="failed")
                self.assertNotIn("result", failed)
        for cleanup in (False, None, "true", 1):
            with self.subTest(cleanup=cleanup):
                (path / "lifecycle.json").write_text(json.dumps({"status": "stopped", "cleanup_confirmed": cleanup}))
                with mock.patch.object(core, "control_profile", return_value=actual):
                    self.wait_job(self.manager.submit("stop", identifier, {}, uuid.uuid4().hex), expected="failed")

    def test_refreshed_status_keeps_revocation_separate_and_close_does_not_stop_core(self):
        identifier, path, _ = self.create()
        actual = core.control_profile(path, "status")
        states = [{**actual, "status": "ready", "task": {"revoked": True}},
                  {**actual, "status": "stopped", "task": {"revoked": True}}]
        with mock.patch.object(core, "control_profile", side_effect=states) as control:
            first = self.manager.profiles()["profiles"][0]
            second = self.manager.profiles()["profiles"][0]
            self.assertEqual((first["status"], first["revoked"]), ("ready", True))
            self.assertEqual((second["status"], second["revoked"]), ("stopped", True))
            self.assertEqual(control.call_count, 2)
        with mock.patch.object(core, "control_profile") as control:
            self._shutdown()
            control.assert_not_called()


if __name__ == "__main__":
    unittest.main()
