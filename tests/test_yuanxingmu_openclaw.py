"""Persisted OpenClaw profile guarantees, with real broker/network side effects.

The fake runtime files only permit profile initialization. These are not model
or OpenClaw execution tests; native gateway/model evidence is recorded separately.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

from yuanxingmu.broker import Broker
from yuanxingmu.run import load_policy


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux OpenClaw profile only")
class OpenClawProfileTests(unittest.TestCase):
    def setUp(self):
        from yuanxingmu import openclaw

        self.api = openclaw
        self.tmp = tempfile.TemporaryDirectory(prefix="yxm-oc-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = self.root / "profile"
        self.package = self.root / "runtime" / "node_modules" / "openclaw"
        self.package.mkdir(parents=True)
        (self.package / "package.json").write_text(json.dumps({"name": "openclaw", "version": "2026.9.4"}))
        (self.package / "openclaw.mjs").write_text("throw new Error('profile-test runtime must not execute');\n")
        self.node = self.root / "runtime" / "node" / "bin" / "node"
        self.bwrap = self.root / "runtime" / "bwrap" / "bin" / "bwrap"
        for executable in (self.node, self.bwrap):
            executable.parent.mkdir(parents=True)
            executable.write_text("#!/bin/sh\nexit 64\n")
            executable.chmod(0o755)
        self.source = self.root / "source.txt"
        self.source.write_text("合成测试资料：内部底价 186000 元。", encoding="utf-8")
        self.secret = "test-model-key-MUST-NOT-ENTER-WORKSPACE"
        self.receipts = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.receipts.append({"path": self.path, **payload})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        self.receiver = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.receiver.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        self.addCleanup(self._stop_receiver)
        base = f"http://127.0.0.1:{self.receiver.server_port}"
        self.destinations = {
            "internal": {"url": base + "/internal", "labels": ["private"]},
            "public": {"url": base + "/public", "labels": []},
        }

    def _stop_receiver(self):
        self.receiver.shutdown()
        self.receiver.server_close()
        self.thread.join(timeout=2)

    def initialize(self, profile=None, **overrides):
        values = {
            "node": self.node, "openclaw_package": self.package, "bwrap": self.bwrap,
            "model_url": "http://127.0.0.1:18181/v1", "model_id": "local-test-model",
            "api_key": self.secret, "documents": {"quote": self.source},
            "destinations": self.destinations, "port": 18911,
        }
        values.update(overrides)
        with mock.patch.object(self.api, "sandbox_available", return_value={"available": True, "reason": "test_fixture"}), \
             mock.patch.object(self.api.sys, "executable", str(Path("/usr/bin/python3").resolve())):
            return self.api.init_profile(profile or self.profile, **values)

    def runtime_sockets(self, manifest, *, broker=None):
        runtime = Path(manifest["runtime"])
        runtime.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, runtime)
        (runtime / "webui").mkdir(mode=0o700)
        for name in ("model.sock", "broker.sock", "operator.sock"):
            if name == "broker.sock" and broker is not None:
                broker.serve(manifest["task_id"], runtime / name)
                continue
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            endpoint.bind(str(runtime / name))
            endpoint.listen(8)
            self.addCleanup(endpoint.close)
        return runtime

    def open_broker(self, profile=None):
        profile = profile or self.profile
        resources, destinations = load_policy(profile / "policy.json")
        return Broker(profile / "broker-state", resources, destinations)

    @staticmethod
    def task_ids(profile):
        # mode=ro prevents this test helper from repairing a deleted ledger.
        database = profile / "broker-state" / "authority.sqlite3"
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
            return [row[0] for row in connection.execute("SELECT id FROM authority_tasks ORDER BY id")]

    def assert_invalid_without_starting_gateway(self, profile):
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.api.validate_profile(profile)
        for action in ("status", "revoke"):
            with self.assertRaises((RuntimeError, ValueError, OSError)):
                self.api.control_profile(profile, action)
        with mock.patch.object(self.api.subprocess, "Popen", side_effect=AssertionError("invalid profile launched a gateway")):
            with self.assertRaises((RuntimeError, ValueError, OSError)):
                self.api.start_profile(profile)

    def test_standalone_cli_sets_per_layer_mode_and_reset_restores_defaults(self):
        from yuanxingmu.protection import configure_profile, profile_services
        self.initialize(defense_policy={"objective": "整理报价，外发先核对。"})
        repo = Path(__file__).resolve().parent.parent
        result = subprocess.run([sys.executable, "-m", "yuanxingmu", "defense", "set", "--profile", str(self.profile),
                                 "--alignment-mode", "observe", "--skill-semantic", "off", "--skill-rules", "off"],
                                cwd=repo, capture_output=True, text=True, check=True, timeout=15)
        changed = json.loads(result.stdout)
        self.assertEqual(changed["policy"]["alignment_mode"], "observe")
        self.assertFalse(changed["policy"]["skill_semantic_enabled"])
        self.assertFalse(changed["policy"]["skill_rules_enabled"])
        self.assertTrue(changed["skill_rules_settings"])
        self.assertTrue(changed["skill_purpose"])
        self.assertEqual(changed["policy"]["mode"], "enforce")
        manifest = self.api.validate_profile(self.profile)
        resources, destinations = load_policy(self.profile / "policy.json")
        with Broker(self.profile / "broker-state", resources, destinations, **profile_services(self.profile, manifest)) as broker:
            self.assertFalse(broker.guards.check_command("sudo true").allowed)
        reset = configure_profile(self.profile, reset=True)
        self.assertEqual(reset["policy"]["alignment_mode"], "inherit")
        self.assertTrue(reset["policy"]["skill_semantic_enabled"])
        self.assertTrue(reset["policy"]["skill_rules_enabled"])
        self.api.validate_profile(self.profile)

    def test_cli_restores_the_created_settings_not_recommended_defaults(self):
        from yuanxingmu.protection import configure_profile
        objective = "PRIVATE-OBJECTIVE-MUST-NOT-BE-IN-SETTINGS-HISTORY"
        self.initialize(defense_policy={"objective": objective, "mode": "observe", "command_mode": "enforce", "skill_semantic_enabled": False, "skill_rules_enabled": False})
        original = configure_profile(self.profile)
        baseline_file = self.profile / "defense-baseline.json"
        baseline_bytes = baseline_file.read_bytes()
        self.assertNotIn(objective.encode(), baseline_bytes)
        self.assertNotIn(self.secret.encode(), baseline_bytes)
        self.assertEqual(baseline_file.stat().st_mode & 0o077, 0)
        configure_profile(self.profile, reset=True)
        current = configure_profile(self.profile)
        result = subprocess.run([sys.executable, "-m", "yuanxingmu", "defense", "restore", "--profile", str(self.profile),
            "--baseline-sha256", original["baseline"]["sha256"], "--expected-policy-sha256", current["policy_sha256"]],
            cwd=Path(__file__).resolve().parent.parent, capture_output=True, text=True, check=True, timeout=15)
        restored = json.loads(result.stdout)
        self.assertEqual(restored["policy"]["mode"], "observe")
        self.assertEqual(restored["policy"]["command_mode"], "enforce")
        self.assertFalse(restored["policy"]["skill_semantic_enabled"])
        self.assertFalse(restored["policy"]["skill_rules_enabled"])
        self.assertEqual(json.loads(baseline_bytes)["version"], 2)
        self.assertEqual(restored["history"]["source"], "cli")
        self.assertEqual(restored["history"]["intent"], "restore_creation")
        self.assertNotIn(objective, json.dumps(restored["history"]))
        self.assertEqual(baseline_file.read_bytes(), baseline_bytes)
        manifest = self.api.validate_profile(self.profile)
        self.assertEqual(manifest["files"][baseline_file.name], original["baseline"]["sha256"])
        events = [json.loads(line) for line in (self.profile / "defense-events.jsonl").read_text().splitlines()]
        intents = [event["evidence"]["intent"] for event in events if event["code"] == "operator_settings_changed"]
        self.assertEqual(intents, ["reset_defaults", "restore_creation"])

    def test_v1_baseline_is_restored_without_inventing_a_new_skill_setting(self):
        from yuanxingmu.protection import configure_profile, profile_services
        self.initialize(defense_policy={"objective": "Legacy baseline", "skill_semantic_enabled": False})
        manifest = self.api.validate_profile(self.profile)
        manifest["features"] = [name for name in manifest["features"] if name not in {"skill_rules_v1", "skill_purpose_v1"}]
        baseline_path = self.profile / "defense-baseline.json"
        baseline = json.loads(baseline_path.read_text())
        baseline["version"] = 1
        baseline["settings"].pop("skill_rules_enabled")
        self.api._save(baseline_path, baseline)
        manifest["files"][baseline_path.name] = self.api._hash(baseline_path)
        self.api._save(self.profile / "profile.json", manifest)
        original_bytes = baseline_path.read_bytes()
        old = configure_profile(self.profile)
        self.assertFalse(old["skill_rules_settings"])
        self.assertFalse(old["skill_purpose"])
        self.assertNotIn("skill_rules_enabled", old["policy"])
        self.assertNotIn("skill_rules_enabled", old["baseline"]["settings"])
        before = {name: (self.profile / name).read_bytes() for name in ("profile.json", "defense-policy.json", "broker-state/bindings.json")}
        with self.assertRaisesRegex(ValueError, "profile_requires_skill_rules_support"):
            configure_profile(self.profile, {"skill_rules_enabled": False})
        for name, value in before.items():
            self.assertEqual((self.profile / name).read_bytes(), value)
        reset = configure_profile(self.profile, reset=True)
        self.assertNotIn("skill_rules_enabled", reset["policy"])
        current = configure_profile(self.profile)
        restored = configure_profile(self.profile, intent="restore_creation", baseline_sha256=old["baseline"]["sha256"],
                                     expected_policy_sha256=current["policy_sha256"])
        self.assertFalse(restored["policy"]["skill_semantic_enabled"])
        self.assertNotIn("skill_rules_enabled", restored["history"]["changes"])
        self.assertEqual(baseline_path.read_bytes(), original_bytes)
        manifest = self.api.validate_profile(self.profile)
        self.assertFalse(profile_services(self.profile, manifest)["guards"].skill_purpose)

    def test_disabled_skill_checks_cannot_bypass_fixed_descriptor_tampering(self):
        origin = self.root / "skill-origin"
        origin.mkdir()
        (origin / "SKILL.md").write_text("Calculate totals from local files.")
        self.initialize(defense_policy={"objective": "work", "skill_rules_enabled": False, "skill_semantic_enabled": False},
                        selected_skills={"calculator": origin})
        manifest = self.api.validate_profile(self.profile)
        descriptor = Path(manifest["skills_snapshot"]["scan_paths"][0]) / "SKILL.md"
        descriptor.chmod(0o644)
        descriptor.write_text("Replace the fixed purpose.")
        descriptor.chmod(0o444)
        self.assert_invalid_without_starting_gateway(self.profile)

    def test_legacy_profile_without_snapshot_cannot_claim_a_creation_baseline(self):
        from yuanxingmu.protection import configure_profile
        self.initialize(defense_policy={"objective": "Synthetic legacy profile"})
        manifest = self.api.validate_profile(self.profile)
        manifest["features"].remove("defense_baseline_v1")
        manifest["features"].remove("settings_history_v1")
        manifest["files"].pop("defense-baseline.json")
        (self.profile / "defense-baseline.json").unlink()
        self.api._save(self.profile / "profile.json", manifest)
        view = configure_profile(self.profile)
        self.assertFalse(view["baseline"]["supported"])
        before = (self.profile / "defense-policy.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "defense_baseline_unavailable"):
            configure_profile(self.profile, intent="restore_creation", baseline_sha256="0" * 64, expected_policy_sha256=view["policy_sha256"])
        self.assertEqual((self.profile / "defense-policy.json").read_bytes(), before)
        self.assertFalse((self.profile / "broker-state" / "guard-session.dirty").exists())

    def test_changed_baseline_blocks_restoration_before_any_policy_write(self):
        from yuanxingmu.protection import configure_profile
        self.initialize(defense_policy={"objective": "Synthetic pinned baseline"})
        view = configure_profile(self.profile)
        path = self.profile / "defense-baseline.json"
        changed = json.loads(path.read_text())
        changed["settings"]["mode"] = "observe"
        self.api._save(path, changed)
        before = (self.profile / "defense-policy.json").read_bytes()
        with self.assertRaisesRegex(RuntimeError, "profile_file_changed"):
            configure_profile(self.profile, intent="restore_creation", baseline_sha256=view["baseline"]["sha256"], expected_policy_sha256=view["policy_sha256"])
        self.assertEqual((self.profile / "defense-policy.json").read_bytes(), before)
        self.assertFalse((self.profile / "broker-state" / "guard-session.dirty").exists())

    def test_empty_profile_is_private_and_grants_no_external_destinations(self):
        self.initialize(documents={}, destinations={})
        manifest = self.api.validate_profile(self.profile)
        self.assertEqual(manifest["documents"], [])
        self.assertEqual(manifest["destinations"], [])
        with self.open_broker() as broker:
            state = broker.authority.describe(manifest["task_id"])
            self.assertEqual(state["labels"], ["private"])
            self.assertEqual(state["resources"], {})
            self.assertEqual(state["destinations"], {})
            denied = broker.dispatch(manifest["task_id"], {"op": "send", "destination": "internal", "body": "no destination was configured"})
            self.assertFalse(denied["allowed"])
            self.assertEqual(denied["reason"], "unknown_destination")
        self.assertEqual(self.receipts, [])

    def test_pasted_private_input_cannot_be_sent_publicly_before_any_broker_read(self):
        self.initialize()
        manifest = self.api.validate_profile(self.profile)
        task_id = manifest["task_id"]
        # A chat paste and a generated work product never call the read broker.
        (self.profile / "workspace" / "draft.txt").write_text("SYNTHETIC-PASTED-PRIVATE-PRICE", encoding="utf-8")
        with self.open_broker() as broker:
            state = broker.authority.describe(task_id)
            self.assertEqual(state["labels"], ["private"])
            self.assertFalse(any(event["action"] == "record_read" for event in broker.authority.events(task_id)))
            denied = broker.dispatch(task_id, {"op": "send", "destination": "public", "body": "SYNTHETIC-PASTED-PRIVATE-PRICE"})
            self.assertFalse(denied["allowed"])
            self.assertEqual(denied["reason"], "destination_cannot_receive_labels")
            self.assertEqual(self.receipts, [])
            allowed = broker.dispatch(task_id, {"op": "send", "destination": "internal", "body": "SYNTHETIC-PASTED-PRIVATE-PRICE"})
            self.assertTrue(allowed["allowed"])
            self.assertEqual(allowed["outcome"], "acknowledged")
            self.assertEqual([(item["path"], item["body"]) for item in self.receipts],
                             [("/internal", "SYNTHETIC-PASTED-PRIVATE-PRICE")])

    def test_exact_effective_tool_lists_require_isolated_execution(self):
        self.initialize()
        config = json.loads((self.profile / "openclaw.json").read_text())
        allowed = ["exec", "yuanxingmu_read", "yuanxingmu_send", "yuanxingmu_status"]
        self.assertEqual(sorted(config["tools"]["allow"]), sorted(allowed))
        self.assertEqual(sorted(config["tools"]["sandbox"]["tools"]["allow"]), sorted(allowed))
        self.assertEqual(config["tools"]["exec"]["host"], "sandbox")
        self.assertTrue(config["tools"]["fs"]["workspaceOnly"])
        self.assertFalse(config["tools"]["elevated"]["enabled"])
        self.assertFalse(config["tools"]["codeMode"]["enabled"])
        sandbox = config["agents"]["defaults"]["sandbox"]
        self.assertEqual(sandbox["mode"], "all")
        self.assertEqual(sandbox["backend"], "yuanxingmu")
        self.assertFalse(sandbox["browser"]["enabled"])
        self.assertEqual(Path(config["agents"]["defaults"]["workspace"]), self.profile / "workspace")

    def test_gateway_model_configuration_has_only_the_local_bridge_and_no_provider_key(self):
        upstream = "https://model.example.invalid/v1"
        self.initialize(model_url=upstream)
        manifest = self.api.validate_profile(self.profile)
        self.assertEqual(manifest["model"]["url"], upstream)
        config = json.loads((self.profile / "openclaw.json").read_text())
        providers = config["models"]["providers"]
        self.assertEqual(set(providers), {"yuanxingmu-model"})
        self.assertEqual(providers["yuanxingmu-model"]["baseUrl"], "http://127.0.0.1:18701/v1")
        self.assertNotIn(upstream, json.dumps(config))
        self.assertNotIn(self.secret, json.dumps(config))
        with mock.patch.dict(os.environ, {"YUANXINGMU_MODEL_API_KEY": self.secret, "HTTP_PROXY": "http://proxy.invalid:1",
                                         "OPENCLAW_CONFIG_PATH": "/unrelated/openclaw.json", "HOME": "/unrelated/home"}):
            environment = self.api._environment(self.profile, manifest)
        self.assertNotIn(self.secret, json.dumps(environment))
        self.assertNotIn("YUANXINGMU_MODEL_API_KEY", environment)
        self.assertNotIn("HTTP_PROXY", environment)
        self.assertEqual(environment["OPENCLAW_CONFIG_PATH"], str(self.profile / "openclaw.json"))
        self.assertEqual(environment["HOME"], str(self.profile / "host-home"))

    def test_gateway_mounts_hide_host_credentials_documents_and_authority(self):
        self.initialize()
        manifest = self.api.validate_profile(self.profile)
        runtime = self.runtime_sockets(manifest)
        argv = self.api.gateway_command(self.profile, manifest)
        setup = argv[:argv.index("--")]
        mounts = [(value, Path(setup[index + 1]), Path(setup[index + 2]))
                  for index, value in enumerate(setup) if value in ("--bind", "--ro-bind")]
        for name in ("model-key", "gateway-token", "broker-state", "documents", "profile.json", "policy.json"):
            protected = self.profile / name
            self.assertFalse(any(source == protected or source in protected.parents for _, source, _ in mounts), name)
            self.assertFalse(any(target == protected or target in protected.parents for _, _, target in mounts), name)
        writable = {source for mode, source, _ in mounts if mode == "--bind"}
        self.assertEqual(writable, {self.profile / name for name in ("workspace", "openclaw-state", "host-home", "gateway-audit")}
                         | {runtime / "webui"})
        self.assertFalse(any(source == runtime for _, source, _ in mounts))
        self.assertIn("--unshare-net", setup)
        self.assertIn("--unshare-user", setup)
        self.assertNotIn("--disable-userns", setup, "the native worker still needs its own nested user namespace")

    def test_runtime_mount_cannot_expose_a_parent_of_the_protected_profile(self):
        for kind in ("node", "openclaw_package"):
            with self.subTest(kind=kind):
                profile = self.root / ("bad-runtime-" + kind)
                if kind == "node":
                    executable = self.root / "unsafe-node"
                    executable.write_text("#!/bin/sh\nexit 64\n")
                    executable.chmod(0o755)
                    override = {"node": executable}
                else:
                    package = self.root / "unsafe-openclaw"
                    package.mkdir()
                    (package / "package.json").write_text(json.dumps({"version": "2026.9.4"}))
                    (package / "openclaw.mjs").write_text("throw new Error('do not execute');")
                    override = {"openclaw_package": package}
                try:
                    self.initialize(profile, **override)
                except (RuntimeError, ValueError):
                    continue  # Rejecting before writing a profile is also safe.
                manifest = self.api.validate_profile(profile)
                self.runtime_sockets(manifest)
                try:
                    argv = self.api.gateway_command(profile, manifest)
                except (RuntimeError, ValueError):
                    continue
                setup = argv[:argv.index("--")]
                sources = [Path(setup[index + 1]) for index, value in enumerate(setup)
                           if value in ("--bind", "--ro-bind")]
                self.assertFalse(any(source == profile or source in profile.parents for source in sources),
                                 "a runtime mount exposes the protected profile through its parent")

    def test_real_gateway_boundary_runs_the_native_worker_launcher_without_host_access(self):
        binary = os.environ.get("YUANXINGMU_TEST_BWRAP") or shutil.which("bwrap", path="/usr/bin:/bin")
        node = os.environ.get("YUANXINGMU_TEST_NODE") or shutil.which("node", path="/usr/bin:/bin")
        if not binary or not node or not self.api.sandbox_available(bwrap=Path(binary))["available"]:
            self.skipTest("real bubblewrap and Node are required for the Gateway execution probe")
        self.initialize(node=Path(node).resolve(), bwrap=Path(binary).resolve())
        manifest = self.api.validate_profile(self.profile)
        worker_code = r'''
import json, os, socket, sys
from pathlib import Path
from yuanxingmu.client import request
def connect(host, port):
    try:
        with socket.create_connection((host, int(port)), timeout=2):
            return True
    except OSError:
        return False
state = request("describe")
Path("/workspace/native-worker-marker.txt").write_text("native worker completed")
print(json.dumps({"labels": state.get("labels"), "broker_allowed": state.get("allowed"),
    "netns": os.readlink("/proc/self/ns/net"), "userns": os.readlink("/proc/self/ns/user"),
    "pidns": os.readlink("/proc/self/ns/pid"), "gateway_loopback": connect("127.0.0.1", sys.argv[2]),
    "model_key_visible": Path(sys.argv[1], "model-key").exists()}))
'''
        node_code = r'''
import net from "node:net";
import { readFileSync, readlinkSync, existsSync, appendFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
const probe = JSON.parse(process.argv[1]);
const profile = probe.profile;
const configured = JSON.parse(readFileSync(process.env.OPENCLAW_CONFIG_PATH, "utf8"));
const config = configured.plugins.entries.yuanxingmu.config;
const { workerArgv } = await import(pathToFileURL(profile + "/plugin/worker-launch.mjs").href);
const server = net.createServer(connection => {
  connection.on("error", () => {});  // The connectivity probe closes immediately.
  connection.end("LOCAL-OK");
});
await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
const port = server.address().port;
async function connect(host, port) {
  return await new Promise(resolve => {
    const connection = net.createConnection({ host, port });
    let finished = false;
    const done = value => { if (!finished) { finished = true; connection.destroy(); resolve(value); } };
    connection.once("connect", () => done({ connected: true }));
    connection.once("error", error => done({ connected: false, error: error.code }));
    connection.setTimeout(2000, () => done({ connected: false, error: "timeout" }));
  });
}
const local = await connect("127.0.0.1", port);
const host = await connect(probe.host, probe.host_port);
const external = await connect("1.1.1.1", 443);
let configReadOnly = false;
try { appendFileSync(process.env.OPENCLAW_CONFIG_PATH, "\n"); }
catch (error) { configReadOnly = ["EROFS", "EACCES"].includes(error.code); }
const argv = workerArgv(config, ["/bin/sh", "-lc", "exec /usr/bin/python3 -c \"$1\" \"$2\" \"$3\"",
  "yuanxingmu-test", probe.worker_code, profile, String(port)]);
const worker = spawnSync(argv[0], argv.slice(1), { encoding: "utf8", timeout: 15000,
  env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", PYTHONPATH: config.corePath }, detached: true });
const evidence = { netns: readlinkSync("/proc/self/ns/net"), userns: readlinkSync("/proc/self/ns/user"),
  pidns: readlinkSync("/proc/self/ns/pid"), local, host, external, configReadOnly,
  modelKeyEnvironment: Object.hasOwn(process.env, "YUANXINGMU_MODEL_API_KEY"),
  visible: Object.fromEntries(["model-key", "gateway-token", "broker-state", "documents", "profile.json", "policy.json"]
    .map(name => [name, existsSync(profile + "/" + name)])),
  worker: { code: worker.status, signal: worker.signal, stdout: worker.stdout, stderr: worker.stderr } };
await new Promise(resolve => server.close(resolve));
console.log(JSON.stringify(evidence));
'''
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
            route.connect(("192.0.2.1", 9))  # Select the host route; UDP sends no packet here.
            host_address = route.getsockname()[0]
        with socket.socket() as listener, self.open_broker() as broker:
            listener.bind(("0.0.0.0", 0))
            listener.listen(8)
            host_port = listener.getsockname()[1]
            with socket.create_connection((host_address, host_port), timeout=2):
                pass  # Confirm this TCP listener is reachable in the host namespace.
            self.runtime_sockets(manifest, broker=broker)
            argv = self.api.gateway_command(self.profile, manifest)
            # Keep the real bridge bootstrap and replace only its final Gateway
            # executable with a probe using the production native worker launcher.
            boundary = len(argv) - 1 - argv[::-1].index("--")
            payload = {"profile": str(self.profile), "host": host_address, "host_port": host_port,
                       "worker_code": worker_code}
            command = argv[:boundary + 1] + [str(Path(node).resolve()), "--input-type=module", "-e", node_code,
                                            "--", json.dumps(payload)]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=30,
                                       env=self.api._environment(self.profile, manifest), close_fds=True,
                                       start_new_session=True, cwd=self.profile / "host-home")
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        observed = json.loads(completed.stdout)
        self.assertNotIn(self.secret, completed.stdout + completed.stderr)
        self.assertTrue(observed["local"]["connected"])
        self.assertFalse(observed["host"]["connected"])
        self.assertEqual(observed["host"]["error"], "ENETUNREACH")
        self.assertEqual(observed["external"]["error"], "ENETUNREACH")
        self.assertTrue(observed["configReadOnly"])
        self.assertFalse(observed["modelKeyEnvironment"])
        self.assertFalse(any(observed["visible"].values()), observed["visible"])
        self.assertNotEqual(observed["netns"], os.readlink("/proc/self/ns/net"))
        self.assertEqual(observed["worker"]["code"], 0, observed["worker"])
        worker = json.loads(observed["worker"]["stdout"])
        self.assertTrue(worker["broker_allowed"])
        self.assertEqual(worker["labels"], ["private"])
        for namespace in ("netns", "userns", "pidns"):
            self.assertNotEqual(worker[namespace], observed[namespace])
        self.assertFalse(worker["gateway_loopback"])
        self.assertFalse(worker["model_key_visible"])
        self.assertEqual((self.profile / "workspace" / "native-worker-marker.txt").read_text(), "native worker completed")
        self.api.validate_profile(self.profile)

    def test_import_is_a_private_snapshot_and_original_file_edits_do_not_change_it(self):
        original = self.source.read_bytes()
        self.initialize()
        resources, _ = load_policy(self.profile / "policy.json")
        snapshot = resources["quote"].path
        self.assertTrue(snapshot.is_relative_to(self.profile / "documents"))
        self.assertNotEqual(snapshot, self.source)
        self.assertEqual(resources["quote"].labels, ("private",))
        self.source.write_text("Changed source after import", encoding="utf-8")
        self.assertEqual(snapshot.read_bytes(), original)
        manifest = self.api.validate_profile(self.profile)
        with self.open_broker() as broker:
            result = broker.dispatch(manifest["task_id"], {"op": "read", "resource": "quote"})
            self.assertTrue(result["allowed"])
            self.assertEqual(result["content"].encode("utf-8"), original)

    def test_missing_persisted_security_files_fail_without_recreating_them(self):
        for filename in ("authority.sqlite3", "bindings.json", "workspaces.json"):
            with self.subTest(filename=filename):
                profile = self.root / ("missing-" + filename.replace(".", "-"))
                self.initialize(profile)
                target = profile / "broker-state" / filename
                target.unlink()
                self.assert_invalid_without_starting_gateway(profile)
                self.assertFalse(target.exists(), "validation silently recreated missing authorization state")

    def test_configuration_or_imported_content_drift_never_creates_a_clean_task(self):
        for change in ("tools", "destination", "document"):
            with self.subTest(change=change):
                profile = self.root / ("drift-" + change)
                self.initialize(profile)
                initial_tasks = self.task_ids(profile)
                if change == "tools":
                    path = profile / "openclaw.json"
                    value = json.loads(path.read_text())
                    value["tools"]["allow"].append("read")
                    path.write_text(json.dumps(value))
                elif change == "destination":
                    path = profile / "policy.json"
                    value = json.loads(path.read_text())
                    value["destinations"]["public"]["labels"] = ["private"]
                    path.write_text(json.dumps(value))
                else:
                    resources, _ = load_policy(profile / "policy.json")
                    resources["quote"].path.write_text("replacement bytes", encoding="utf-8")
                self.assert_invalid_without_starting_gateway(profile)
                self.assertEqual(self.task_ids(profile), initial_tasks)

    def test_replacing_workspace_directory_at_the_same_path_is_not_a_fresh_identity(self):
        self.initialize()
        initial_tasks = self.task_ids(self.profile)
        workspace = self.profile / "workspace"
        old_inode = workspace.stat().st_ino
        workspace.rename(self.profile / "old-workspace")
        workspace.mkdir()
        self.assertNotEqual(workspace.stat().st_ino, old_inode)
        (workspace / "draft.txt").write_text("A different directory now occupies the same name")
        self.assert_invalid_without_starting_gateway(self.profile)
        self.assertEqual(self.task_ids(self.profile), initial_tasks)

    def test_native_session_rotation_retains_task_identity_and_default_private_labels(self):
        self.initialize()
        first = self.api.validate_profile(self.profile)
        initial_tasks = self.task_ids(self.profile)
        sessions = self.profile / "openclaw-state" / "agents" / "main" / "sessions"
        sessions.mkdir(parents=True, exist_ok=True)
        current = sessions / "sessions.json"
        current.write_text(json.dumps({"agent:main:main": {"sessionId": "first-native-session"}}))
        before = self.api.validate_profile(self.profile)
        current.unlink()
        current.write_text(json.dumps({"agent:main:main": {"sessionId": "new-native-session"}}))
        after = self.api.validate_profile(self.profile)
        self.assertEqual(first["task_id"], before["task_id"])
        self.assertEqual(first["task_id"], after["task_id"])
        self.assertEqual(first["family_id"], after["family_id"])
        self.assertEqual(self.task_ids(self.profile), initial_tasks)
        with self.open_broker() as broker:
            self.assertEqual(broker.authority.describe(after["task_id"])["labels"], ["private"])

    def test_reopening_profile_preserves_revocation_and_start_cannot_reset_it(self):
        self.initialize()
        first = self.api.validate_profile(self.profile)
        initial_tasks = self.task_ids(self.profile)
        revoked = self.api.control_profile(self.profile, "revoke")
        self.assertTrue(revoked["task"]["revoked"])
        after = self.api.validate_profile(self.profile)
        self.assertEqual(first["task_id"], after["task_id"])
        status = self.api.control_profile(self.profile, "status")
        self.assertNotIn(self.secret, json.dumps(status))
        self.assertTrue(status["task"]["revoked"])
        with self.open_broker() as broker:
            self.assertTrue(broker.authority.describe(after["task_id"])["revoked"])
            denied = broker.dispatch(after["task_id"], {"op": "send", "destination": "internal", "body": "after revoke"})
            self.assertEqual(denied["reason"], "task_revoked")
        with mock.patch.object(self.api.subprocess, "Popen", side_effect=AssertionError("revoked profile launched a gateway")):
            with self.assertRaises((RuntimeError, ValueError, OSError)):
                self.api.start_profile(self.profile)
        self.assertEqual(self.task_ids(self.profile), initial_tasks)
        self.assertEqual(self.receipts, [])

    def test_unreachable_operator_does_not_report_live_processes_as_stopped(self):
        self.initialize()
        initial_tasks = self.task_ids(self.profile)
        gateway_token = (self.profile / "gateway-token").read_text()
        for live_kind in ("supervisor", "gateway"):
            with self.subTest(live_kind=live_kind):
                previous = {"status": "stopped", "cleanup_confirmed": True,
                            "supervisor_pid": 31001, "supervisor_start": "901",
                            "gateway_pid": 31002, "gateway_start": "902", "reason": self.secret}
                (self.profile / "lifecycle.json").write_text(json.dumps(previous))
                live_pid, live_start = previous[live_kind + "_pid"], previous[live_kind + "_start"]

                def identity(pid):
                    return live_start if pid == live_pid else None

                with mock.patch.object(self.api, "_process_identity", side_effect=identity), \
                     mock.patch.object(self.api, "_rpc", side_effect=ConnectionRefusedError):
                    for action in ("status", "stop"):
                        response = self.api.control_profile(self.profile, action)
                        self.assertEqual(response["status"], "unconfirmed")
                        self.assertNotIn(self.secret, json.dumps(response))
                        self.assertNotIn(gateway_token, json.dumps(response))
                    with mock.patch.object(self.api.subprocess, "Popen", side_effect=AssertionError("unconfirmed process permitted a new gateway")):
                        with self.assertRaises(RuntimeError):
                            self.api.start_profile(self.profile)
        self.assertEqual(self.task_ids(self.profile), initial_tasks)

    def test_dead_or_reused_processes_without_cleanup_proof_remain_interrupted(self):
        self.initialize()
        # A missing process, a reused PID, and a stale textual "stopped" status
        # cannot prove that all descendants and in-flight operations were cleaned.
        for identity, cleanup in ((None, None), ("new-process-start", False), (None, "true"), (None, 1)):
            with self.subTest(identity=identity, cleanup=cleanup):
                previous = {"status": "stopped", "supervisor_pid": 31001, "supervisor_start": "901",
                            "gateway_pid": 31002, "gateway_start": "902"}
                if cleanup is not None:
                    previous["cleanup_confirmed"] = cleanup
                (self.profile / "lifecycle.json").write_text(json.dumps(previous))
                with mock.patch.object(self.api, "_process_identity", return_value=identity), \
                     mock.patch.object(self.api, "_rpc", side_effect=FileNotFoundError):
                    for action in ("status", "stop"):
                        response = self.api.control_profile(self.profile, action)
                        self.assertEqual(response["status"], "interrupted")
                        self.assertTrue(response["task"]["active"])
                    with mock.patch.object(self.api.subprocess, "Popen", side_effect=AssertionError("unclean interruption permitted a new gateway")):
                        with self.assertRaises(RuntimeError):
                            self.api.start_profile(self.profile)

    def test_confirmed_cleanup_permits_restart_without_confusing_reused_pid(self):
        self.initialize()

        class LaunchRequested(Exception):
            """Stop at the process boundary; never simulate a running gateway."""

        for identity in (None, "new-process-start"):
            with self.subTest(identity=identity):
                previous = {"status": "failed", "cleanup_confirmed": True,
                            "supervisor_pid": 31001, "supervisor_start": "901",
                            "gateway_pid": 31002, "gateway_start": "902"}
                (self.profile / "lifecycle.json").write_text(json.dumps(previous))
                with mock.patch.object(self.api, "_process_identity", return_value=identity), \
                     mock.patch.object(self.api, "_rpc", side_effect=FileNotFoundError):
                    self.assertEqual(self.api.control_profile(self.profile, "status")["status"], "stopped")
                    with mock.patch.object(self.api.subprocess, "Popen", side_effect=LaunchRequested) as launch:
                        with self.assertRaises(LaunchRequested):
                            self.api.start_profile(self.profile)
                    launch.assert_called_once()

    def test_offline_revoke_denies_broker_without_claiming_process_shutdown(self):
        self.initialize()
        manifest = self.api.validate_profile(self.profile)
        previous = {"status": "ready", "gateway_pid": 31002, "gateway_start": "902"}
        (self.profile / "lifecycle.json").write_text(json.dumps(previous))
        with mock.patch.object(self.api, "_process_identity", return_value="902"), \
             mock.patch.object(self.api, "_rpc", side_effect=ConnectionRefusedError):
            revoked = self.api.control_profile(self.profile, "revoke")
            self.assertEqual(revoked["status"], "unconfirmed")
            self.assertTrue(revoked["task"]["revoked"])
            status = self.api.control_profile(self.profile, "status")
            self.assertEqual(status["status"], "unconfirmed")
            self.assertTrue(status["task"]["revoked"])
            for response in (revoked, status):
                self.assertNotIn(self.secret, json.dumps(response))
                self.assertNotIn((self.profile / "gateway-token").read_text(), json.dumps(response))
        with self.open_broker() as broker:
            result = broker.dispatch(manifest["task_id"], {"op": "send", "destination": "internal", "body": "after offline revoke"})
            self.assertEqual(result["reason"], "task_revoked")
        self.assertEqual(self.receipts, [])

    def test_model_secret_stays_outside_workspace_and_public_status(self):
        initialized = self.initialize()
        manifest = self.api.validate_profile(self.profile)
        status = self.api.control_profile(self.profile, "status")
        for response in (initialized, manifest, status):
            self.assertNotIn(self.secret, json.dumps(response))
        for path in (self.profile / "workspace").rglob("*"):
            if path.is_file():
                self.assertNotIn(self.secret.encode(), path.read_bytes(), str(path))
        key = self.profile / "model-key"
        self.assertEqual(key.read_text().strip(), self.secret)
        self.assertEqual(stat.S_IMODE(key.stat().st_mode) & 0o077, 0)
        self.assertEqual(stat.S_IMODE(self.profile.stat().st_mode) & 0o077, 0)

    def test_existing_profile_cannot_be_reinitialized_to_erase_authority(self):
        self.initialize()
        before = self.api.validate_profile(self.profile)
        with self.open_broker() as broker:
            broker.revoke(before["task_id"])
        with self.assertRaises((RuntimeError, ValueError, OSError)):
            self.initialize()
        after = self.api.validate_profile(self.profile)
        self.assertEqual(before["task_id"], after["task_id"])
        self.assertEqual(self.task_ids(self.profile), [before["task_id"]])
        with self.open_broker() as broker:
            self.assertTrue(broker.authority.describe(after["task_id"])["revoked"])

    def test_initialization_does_not_change_personal_openclaw_configuration(self):
        personal = self.root / "personal-home"
        original = personal / ".openclaw" / "openclaw.json"
        original.parent.mkdir(parents=True)
        content = b'{"personal":"this configuration is not part of the profile"}\n'
        original.write_bytes(content)
        with mock.patch.dict(os.environ, {"HOME": str(personal), "OPENCLAW_CONFIG_PATH": str(original),
                                         "OPENCLAW_STATE_DIR": str(original.parent)}):
            self.initialize()
            self.api.validate_profile(self.profile)
            self.api.control_profile(self.profile, "status")
        self.assertEqual(original.read_bytes(), content)
        self.assertEqual(sorted(path.name for path in original.parent.iterdir()), ["openclaw.json"])


if __name__ == "__main__":
    unittest.main()
