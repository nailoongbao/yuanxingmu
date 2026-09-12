"""Independent-judge management integration, with no native model execution.

HTTP creation/status/settings use the real Workbench, profile files and ledger.
Runtime binaries/readiness reuse DashboardTests' explicit management fixtures.
The only outbound TCP connections allowed are this test's Workbench and judge
receiver; the judge receiver supplies a synthetic JSON verdict, not inference.
"""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import socket
import sys
import threading
import unittest
from unittest import mock

import test_yuanxingmu_dashboard as dashboard_fixture
from yuanxingmu import cli
from yuanxingmu import judge_profile
from yuanxingmu import openclaw as core
from yuanxingmu.protection import profile_services


@unittest.skipUnless(sys.platform.startswith("linux"), "Real protected profile management requires Linux")
class JudgeIntegrationTests(unittest.TestCase):
    # Reuse setup/helpers explicitly; do not inherit or rerun all DashboardTests.
    _open = dashboard_fixture.DashboardTests._open
    _shutdown = dashboard_fixture.DashboardTests._shutdown
    _restart = dashboard_fixture.DashboardTests._restart
    request = dashboard_fixture.DashboardTests.request
    create = dashboard_fixture.DashboardTests.create
    wait_job = dashboard_fixture.DashboardTests.wait_job
    task_ids = dashboard_fixture.DashboardTests.task_ids

    def setUp(self):
        dashboard_fixture.DashboardTests.setUp(self)
        self.judge_secret = "INDEPENDENT-JUDGE-KEY-SYNTHETIC-ONLY"
        self.received = []
        self.tcp_connections = []
        received = self.received

        class Receiver(BaseHTTPRequestHandler):
            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                received.append({"path": self.path, "authorization": self.headers.get("Authorization"),
                                 "body": json.loads(raw)})
                answer = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant",
                           "content": json.dumps({"verdict": "allow", "reason": "合成测试裁判"})}}]}
                body = json.dumps(answer).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        self.receiver = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        self.receiver_thread = threading.Thread(target=self.receiver.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.receiver_thread.start()
        self.addCleanup(self._close_receiver)
        self.judge_config = {"url": f"http://127.0.0.1:{self.receiver.server_port}/v1", "id": "independent-fixture-judge",
                             "api_key": self.judge_secret, "timeout_seconds": 41}
        self.layered_payload = {**self.payload, "objective": "读取报价并整理摘要，允许保存在 /workspace；不得外发。",
                                "judge": self.judge_config}
        original_connect = socket.socket.connect

        def local_only(connection, address):
            if connection.family in (socket.AF_INET, socket.AF_INET6):
                allowed = {("127.0.0.1", self.server.server_port), ("127.0.0.1", self.receiver.server_port)}
                if tuple(address[:2]) not in allowed:
                    raise AssertionError("unexpected non-fixture TCP destination")
                self.tcp_connections.append(tuple(address[:2]))
            return original_connect(connection, address)

        self.patches.enter_context(mock.patch.object(socket.socket, "connect", new=local_only))

    def _close_receiver(self):
        self.receiver.shutdown()
        self.receiver.server_close()
        self.receiver_thread.join(timeout=3)

    def assert_public(self, value):
        text = json.dumps(value, ensure_ascii=False)
        for secret in (self.secret, self.judge_secret):
            self.assertNotIn(secret, text)

    def protection(self, identifier):
        status, _, value = self.request("GET", f"/api/profiles/{identifier}/protection")
        self.assertEqual(status, 200, value)
        self.assert_public(value)
        return value

    def assert_independent(self, profile, manifest):
        self.assertIn("independent_judge_v1", manifest["features"])
        for name in (judge_profile.CONFIG_NAME, judge_profile.KEY_NAME):
            self.assertEqual(manifest["files"][name], hashlib.sha256((profile / name).read_bytes()).hexdigest())
        self.assertEqual((profile / "model-key").read_text(), self.secret)
        self.assertEqual((profile / "judge-key").read_text(), self.judge_secret)
        guard = profile_services(profile, manifest)["guards"]
        self.assertEqual((guard.judge.model_url, guard.judge.model_id, guard.judge.api_key, guard.judge.timeout_seconds),
                         (self.judge_config["url"], self.judge_config["id"], self.judge_secret, 41))
        return guard

    def test_http_create_and_read_pin_distinct_model_and_keep_keys_out_of_public_state(self):
        identifier, profile, job = self.create(self.layered_payload)
        manifest = core.validate_profile(profile)
        self.assert_independent(profile, manifest)
        self.assertEqual(manifest["model"]["id"], self.payload["model_id"])
        for value in (job, self.request("GET", "/api/profiles")[2],
                      self.request("GET", f"/api/jobs/{job['id']}")[2],
                      json.loads((self.root / "catalog.json").read_text()),
                      json.loads((profile / "judge-config.json").read_text())):
            self.assert_public(value)
        report = self.protection(identifier)["judge"]
        self.assertEqual(report, {"independent": True, "source": "independent", "url": self.judge_config["url"],
                                  "id": self.judge_config["id"], "timeout_seconds": 41})
        self.assertEqual(self.received, [], "Creating or inspecting a profile must not call a model")

    def test_real_judge_transport_uses_independent_endpoint_model_and_host_key(self):
        _, profile, _ = self.create(self.layered_payload)
        guard = self.assert_independent(profile, core.validate_profile(profile))
        verdict = guard.check_alignment({"tool": "yuanxingmu_read", "arguments": {"resource": "quote"}})
        self.assertTrue(verdict.allowed, verdict.to_dict())
        self.assertEqual(len(self.received), 1)
        call = self.received[0]
        self.assertEqual(call["path"], "/v1/chat/completions")
        self.assertEqual(call["authorization"], "Bearer " + self.judge_secret)
        self.assertEqual(call["body"]["model"], self.judge_config["id"])
        self.assertNotIn(self.secret, json.dumps(call))
        prompt = json.loads(call["body"]["messages"][1]["content"])
        self.assertEqual(prompt["frozen_user_objective"], self.layered_payload["objective"])
        self.assertEqual(prompt["candidate"], {"tool": "yuanxingmu_read", "arguments": {"resource": "quote"}})

    def test_http_policy_changes_and_manager_restart_keep_judge_key_pins_and_task(self):
        identifier, profile, _ = self.create(self.layered_payload)
        before = core.validate_profile(profile)
        before_tasks = self.task_ids(profile)
        before_files = {name: (profile / name).read_bytes() for name in ("judge-config.json", "judge-key")}
        status, _, accepted = self.request("POST", f"/api/profiles/{identifier}/protection",
                                           {"settings": {"command_enabled": False}})
        self.assertEqual(status, 202, accepted)
        self.assert_public(accepted)
        self.assert_public(self.wait_job(accepted))
        after = core.validate_profile(profile)
        guard = self.assert_independent(profile, after)
        self.assertFalse(guard.policy.command_enabled)
        self.assertEqual(guard.policy.objective, self.layered_payload["objective"])
        self.assertEqual(self.task_ids(profile), before_tasks)
        self.assertEqual(after["task_id"], before["task_id"])
        for name, content in before_files.items():
            self.assertEqual((profile / name).read_bytes(), content)
            self.assertEqual(after["files"][name], before["files"][name])
        self._restart()
        self.assertTrue(self.protection(identifier)["judge"]["independent"])
        self.assertEqual(self.received, [])

    def test_http_rejects_judge_changes_inside_layer_settings(self):
        identifier, profile, _ = self.create(self.layered_payload)
        before = (profile / "judge-config.json").read_bytes()
        for settings in ({"judge": self.judge_config}, {"judge_url": "https://other.example.test/v1"},
                         {"api_key": "replacement"}, {"timeout_seconds": 10}):
            status, _, value = self.request("POST", f"/api/profiles/{identifier}/protection", {"settings": settings})
            with self.subTest(settings=list(settings)):
                self.assertEqual(status, 400, value)
                self.assert_public(value)
        self.assertEqual((profile / "judge-config.json").read_bytes(), before)

    def test_http_rejects_unpinned_independent_files_in_an_existing_profile(self):
        payload = {key: value for key, value in self.layered_payload.items() if key != "judge"}
        identifier, profile, _ = self.create(payload)
        original = json.loads((profile / "profile.json").read_text())
        judge_profile.save_judge_profile(profile, self.judge_config)
        with self.assertRaisesRegex(ValueError, "not_pinned"):
            profile_services(profile, original)
        status, _, value = self.request("GET", f"/api/profiles/{identifier}/protection")
        self.assertGreaterEqual(status, 400, value)
        self.assert_public(value)
        self.assertEqual(self.received, [])

    def test_http_detects_tampered_judge_key_without_echoing_it(self):
        identifier, profile, _ = self.create(self.layered_payload)
        replacement = "TAMPERED-KEY-MUST-NOT-RENDER"
        (profile / "judge-key").write_text(replacement)
        status, _, value = self.request("GET", f"/api/profiles/{identifier}/protection")
        self.assertGreaterEqual(status, 400, value)
        self.assert_public(value)
        self.assertNotIn(replacement, json.dumps(value))
        self.assertEqual(self.received, [])

    def test_http_configuration_validation_does_not_create_profiles_or_call_endpoints(self):
        cases = [None, {}, {**self.judge_config, "url": "http://example.test/v1"},
                 {**self.judge_config, "timeout_seconds": 46}, {**self.judge_config, "key_file": "../../model-key"},
                 {**self.judge_config, "api_key": "SECRET\nHEADER"}]
        for judge in cases:
            status, _, value = self.request("POST", "/api/profiles", {**self.layered_payload, "judge": judge})
            with self.subTest(judge_type=type(judge).__name__):
                self.assertEqual(status, 400, value)
                self.assert_public(value)
        no_objective = {key: value for key, value in self.layered_payload.items() if key != "objective"}
        self.assertEqual(self.request("POST", "/api/profiles", no_objective)[0], 400)
        self.assertEqual(self.request("GET", "/api/profiles")[2]["profiles"], [])
        self.assertEqual(self.received, [])

    def cli_args(self, name="cli-profile"):
        return ["yuanxingmu", "openclaw", "init", "--profile", str(self.base / name),
                "--node", str(self.node), "--bwrap", str(self.bwrap), "--openclaw-package", str(self.package),
                "--model-url", self.payload["model_url"], "--model-id", self.payload["model_id"],
                "--api-key-env", "YXM_TEST_AGENT_KEY", "--objective", self.layered_payload["objective"]]

    def call_cli(self, arguments, *, environment=None):
        output, errors = io.StringIO(), io.StringIO()
        env = {"YXM_TEST_AGENT_KEY": self.secret, "YXM_TEST_JUDGE_KEY": self.judge_secret, **(environment or {})}
        with mock.patch.object(sys, "argv", arguments), mock.patch.dict(os.environ, env), \
                redirect_stdout(output), redirect_stderr(errors):
            result = cli.main()
        self.assertNotIn(self.secret, output.getvalue() + errors.getvalue())
        self.assertNotIn(self.judge_secret, output.getvalue() + errors.getvalue())
        return result, output.getvalue(), errors.getvalue()

    def test_cli_creates_independent_judge_from_env_without_printing_credentials(self):
        arguments = self.cli_args() + ["--judge-url", self.judge_config["url"], "--judge-model-id", self.judge_config["id"],
                                       "--judge-api-key-env", "YXM_TEST_JUDGE_KEY", "--judge-timeout", "41"]
        result, output, _ = self.call_cli(arguments)
        self.assertEqual(result, 0, output)
        self.assert_public(json.loads(output))
        profile = self.base / "cli-profile"
        self.assert_independent(profile, core.validate_profile(profile))
        self.assertEqual(self.received, [])

    def test_cli_requires_paired_judge_url_and_model_and_nonempty_requested_env(self):
        cases = [["--judge-url", self.judge_config["url"]], ["--judge-model-id", "judge"],
                 ["--judge-api-key-env", "YXM_TEST_JUDGE_KEY"],
                 ["--judge-url", self.judge_config["url"], "--judge-model-id", "judge", "--judge-api-key-env", "YXM_TEST_EMPTY_KEY"]]
        for extra in cases:
            with self.subTest(extra=extra), mock.patch.object(core, "init_profile") as initialize:
                result, output, _ = self.call_cli(self.cli_args() + extra, environment={"YXM_TEST_EMPTY_KEY": ""})
                self.assertEqual(result, 1, output)
                initialize.assert_not_called()

    def test_cli_timeout_option_cannot_silently_disappear_without_judge_selection(self):
        with mock.patch.object(core, "init_profile", return_value={"status": "fixture"}) as initialize:
            result, output, _ = self.call_cli(self.cli_args() + ["--judge-timeout", "41"])
            self.assertEqual(result, 1, output)
            initialize.assert_not_called()

    def test_cli_default_stays_with_working_model_and_independent_timeout_is_bounded(self):
        result, output, _ = self.call_cli(self.cli_args("cli-inherited"))
        self.assertEqual(result, 0, output)
        profile = self.base / "cli-inherited"
        manifest = core.validate_profile(profile)
        judge = profile_services(profile, manifest)["guards"].judge
        self.assertEqual((judge.model_id, judge.api_key, judge.timeout_seconds), (self.payload["model_id"], self.secret, 30))
        self.assertNotIn("independent_judge_v1", manifest["features"])
        self.assertFalse((profile / "judge-key").exists())
        result, output, _ = self.call_cli(self.cli_args("cli-invalid-timeout") + ["--judge-url", self.judge_config["url"],
                  "--judge-model-id", self.judge_config["id"], "--judge-api-key-env", "YXM_TEST_JUDGE_KEY", "--judge-timeout", "46"])
        self.assertEqual(result, 1, output)
        self.assertEqual(self.received, [])


if __name__ == "__main__":
    unittest.main()
