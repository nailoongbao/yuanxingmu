"""Real isolation/IPC and a full SDK loop with a deterministic local provider.

The OpenClaw assets used to create a profile are fixtures, never executed.
These are NOT real-LLM or native OpenClaw WebUI acceptance results.
"""
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from yuanxingmu import sdk_runtime as runtime
from yuanxingmu.broker import Broker, Destination, Resource
from yuanxingmu.client import request
from yuanxingmu.gateway_network import HostModel
from yuanxingmu.model_output import ModelOutputGuard
from yuanxingmu.sandbox import sandbox_available
from yuanxingmu.worker import start, stop


def bwrap():
    value = os.environ.get("YUANXINGMU_TEST_BWRAP") or shutil.which("bwrap")
    return Path(value) if value else None


class SdkConfigurationTests(unittest.TestCase):
    def test_unknown_framework_never_opens_profile_or_imports_a_worker(self):
        for framework in (None, True, [], {}, "unknown", "langgraph_runtime", "package.module"):
            with self.subTest(framework=framework), patch.object(runtime.host, "_linux"), \
                    patch.object(runtime.host, "_manifest") as manifest:
                with self.assertRaisesRegex(ValueError, "sdk_framework_not_supported"):
                    runtime.run_session(profile=Path("unused"), sdk_python=Path("unused"),
                                        session="test", prompt="normal", framework=framework)
                manifest.assert_not_called()

    def test_invalid_limits_never_touch_profile_or_launch(self):
        for values in ({"max_steps": True}, {"max_steps": 65}, {"max_tokens": 100000},
                       {"timeout": 0}, {"resume": "true"}, {"prompt": ""}):
            with self.subTest(values=values), patch.object(runtime.host, "_linux"), \
                    patch.object(runtime.host, "_manifest") as manifest:
                with self.assertRaisesRegex(ValueError, "sdk_run_configuration_invalid"):
                    runtime.run_session(profile=Path("unused"), sdk_python=Path("unused"), session="test",
                                        **{"prompt": "normal", **values})
                manifest.assert_not_called()

    def test_request_policy_rejects_model_switch_and_remote_tools(self):
        class Guard:
            def preflight(self, raw):
                return None
        guard = runtime._SdkOutputGuard.__new__(runtime._SdkOutputGuard)
        guard.guard, guard.model_id, guard.max_tokens = Guard(), "chosen-model", 2048
        guard.tool_names = {*runtime.SDK_TOOLS, "final_answer"}
        good = {"model": "chosen-model", "messages": [{"role": "user", "content": "normal"}], "max_tokens": 512}
        self.assertIsNone(guard.preflight(json.dumps(good).encode()))
        for extra in ({"model": "other-model"}, {"max_tokens": 4096}, {"stream": True}, {"n": True},
                      {"tools": None}, {"tools": [{"type": "web_search"}]}, {"unknown": "value"},
                      {"tools": [{"type": "function", "function": {"name": "yuanxingmu_send"}}]}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                guard.preflight(json.dumps({**good, **extra}).encode())

    def test_langgraph_model_inventory_does_not_grant_the_smolagents_answer_tool(self):
        class Guard:
            def preflight(self, raw):
                return None
        with patch.object(runtime, "ModelOutputGuard", return_value=Guard()):
            guard = runtime._SdkOutputGuard(object(), "task", "model", 2048, framework="langgraph")
        good = {"model": "model", "messages": [{"role": "user", "content": "normal"}], "max_tokens": 512}
        self.assertIsNone(guard.preflight(json.dumps(good).encode()))
        for name in ("final_answer", "yuanxingmu_send", "yuanxingmu_request_action"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "sdk_remote_tools_not_allowed"):
                guard.preflight(json.dumps({**good, "tools": [{"type": "function", "function": {"name": name}}]}).encode())

    def test_openai_agents_allows_only_the_fixed_handoff_inventory(self):
        class Guard:
            def preflight(self, raw):
                return None
        with patch.object(runtime, "ModelOutputGuard", return_value=Guard()):
            guard = runtime._SdkOutputGuard(object(), "task", "model", 2048, framework="openai_agents")
        good = {"model": "model", "messages": [{"role": "user", "content": "normal"}], "max_tokens": 512}
        for name in ("yuanxingmu_read", "yuanxingmu_handoff_to_executor"):
            value = {**good, "tools": [{"type": "function", "function": {"name": name}}]}
            self.assertIsNone(guard.preflight(json.dumps(value).encode()))
        for name in ("final_answer", "yuanxingmu_send", "yuanxingmu_request_action", "handoff_to_other_agent"):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "sdk_remote_tools_not_allowed"):
                guard.preflight(json.dumps({**good, "tools": [{"type": "function", "function": {"name": name}}]}).encode())

    def test_pydantic_ai_inventory_requires_explicit_automatic_scope(self):
        class Guard:
            def preflight(self, raw):
                return None
        good = {"model": "model", "messages": [{"role": "user", "content": "normal"}], "max_tokens": 512}
        with patch.object(runtime, "ModelOutputGuard", return_value=Guard()):
            for automatic in (False, True):
                guard = runtime._SdkOutputGuard(object(), "task", "model", 2048,
                                               framework="pydantic_ai", automatic_actions=automatic)
                for name in (*runtime.SDK_TOOLS, "yuanxingmu_request_action", "final_answer",
                             "yuanxingmu_send", "yuanxingmu_handoff_to_executor"):
                    value = json.dumps({**good, "tools": [{"type": "function", "function": {"name": name}}]}).encode()
                    with self.subTest(automatic=automatic, tool=name):
                        if name in runtime.SDK_TOOLS or name == "yuanxingmu_request_action" and automatic:
                            self.assertIsNone(guard.preflight(value))
                        else:
                            with self.assertRaisesRegex(ValueError, "sdk_remote_tools_not_allowed"):
                                guard.preflight(value)

    def test_google_adk_transfer_does_not_grant_automatic_or_host_tools(self):
        class Guard:
            def preflight(self, raw):
                return None
        base = {"model": "model", "messages": [{"role": "user", "content": "normal"}], "max_tokens": 512}
        with patch.object(runtime, "ModelOutputGuard", return_value=Guard()):
            for automatic in (False, True):
                guard = runtime._SdkOutputGuard(object(), "task", "model", 2048,
                                               framework="google_adk", automatic_actions=automatic)
                for name in (*runtime.SDK_TOOLS, "transfer_to_agent", "yuanxingmu_request_action",
                             "yuanxingmu_send", "execute_code", "yuanxingmu_handoff_to_executor", "final_answer"):
                    raw = json.dumps({**base, "tools": [{"type": "function", "function": {"name": name}}]}).encode()
                    with self.subTest(automatic=automatic, tool=name):
                        if name in {*runtime.SDK_TOOLS, "transfer_to_agent"} or name == "yuanxingmu_request_action" and automatic:
                            self.assertIsNone(guard.preflight(raw))
                        else:
                            with self.assertRaisesRegex(ValueError, "sdk_remote_tools_not_allowed"):
                                guard.preflight(raw)
            for framework in ("smolagents", "langgraph", "openai_agents", "pydantic_ai"):
                guard = runtime._SdkOutputGuard(object(), "task", "model", 2048, framework=framework)
                with self.subTest(framework=framework), self.assertRaisesRegex(ValueError, "sdk_remote_tools_not_allowed"):
                    guard.preflight(json.dumps({**base, "tools": [{"type": "function", "function": {"name": "transfer_to_agent"}}]}).encode())


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux SDK process boundary")
class SdkHostTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="yxm-sdk-")))

    def test_private_session_resume_retains_identity_and_rejects_reset(self):
        profile = self.root / "profile"
        profile.mkdir(mode=0o700)
        manifest = {"task_id": "existing-task", "family_id": "existing-family"}
        folder, first = runtime._session(profile, manifest, "hello", Path("/sdk/bin/python"), resume=False)
        self.assertEqual(first["task_id"], "existing-task")
        self.assertEqual(runtime._session(profile, manifest, "hello", Path("/sdk/bin/python"), resume=True)[1], first)
        with self.assertRaises(FileExistsError):
            runtime._session(profile, manifest, "hello", Path("/sdk/bin/python"), resume=False)
        with self.assertRaisesRegex(ValueError, "binding_changed"):
            runtime._session(profile, {**manifest, "task_id": "new-task"}, "hello", Path("/sdk/bin/python"), resume=True)
        other = runtime._session(profile, manifest, "another", Path("/sdk/bin/python"), resume=False)[1]
        self.assertNotEqual(first["session_id"], other["session_id"])
        self.assertEqual(first["family_id"], other["family_id"])
        original = folder / "session.json"
        renamed = folder / "original.json"
        original.rename(renamed)
        original.symlink_to(renamed)
        with self.assertRaises(OSError):
            runtime._session(profile, manifest, "hello", Path("/sdk/bin/python"), resume=True)

    def test_framework_switch_cannot_rebind_a_session_or_create_new_task_authority(self):
        profile = self.root / "profile"
        profile.mkdir(mode=0o700)
        manifest = {"task_id": "existing-task", "family_id": "existing-family"}
        folder, smol = runtime._session(profile, manifest, "one", Path("/sdk/bin/python"), resume=False)
        original = (folder / "session.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "sdk_session_binding_changed"):
            runtime._session(profile, manifest, "one", Path("/sdk/bin/python"), resume=True, framework="langgraph")
        self.assertEqual((folder / "session.json").read_bytes(), original)
        _, graph = runtime._session(profile, manifest, "two", Path("/graph/bin/python"), resume=False, framework="langgraph")
        self.assertEqual(graph["framework"], "langgraph")
        self.assertEqual(graph["sdk_version"], "1.2.11")
        self.assertEqual((graph["task_id"], graph["family_id"]), (smol["task_id"], smol["family_id"]))
        self.assertNotEqual(graph["session_id"], smol["session_id"])
        self.assertEqual(runtime._session(profile, manifest, "two", Path("/graph/bin/python"), resume=True,
                                         framework="langgraph")[1], graph)

    def test_langgraph_runtime_checks_every_pinned_package_without_executing_sdk(self):
        venv = self.root / "sdk"
        (venv / "bin").mkdir(parents=True)
        python = venv / "bin/python"
        python.symlink_to("/usr/bin/python3")
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
        metadata = {}
        for name, version in runtime._sdk("langgraph")["packages"]:
            path = venv / "lib/python3.12/site-packages" / (name + "-" + version + ".dist-info/METADATA")
            path.parent.mkdir(parents=True)
            path.write_text("Name: " + name + "\nVersion: " + version + "\n\n", encoding="utf-8")
            metadata[name] = path
        with patch.object(runtime.subprocess, "run", side_effect=AssertionError("executed SDK on host")):
            self.assertEqual(runtime._python_runtime(python, self.root / "profile", framework="langgraph"), (python, venv))
            core = metadata["langchain_core"]
            core.write_text("Name: langchain-core\nVersion: 0.0.0\n\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sdk_requires_pinned_langgraph_packages"):
                runtime._python_runtime(python, self.root / "profile", framework="langgraph")
            core.unlink()
            with self.assertRaisesRegex(ValueError, "sdk_langgraph_version_not_verified"):
                runtime._python_runtime(python, self.root / "profile", framework="langgraph")

    def test_openai_agents_binding_and_runtime_cannot_replace_existing_authority(self):
        profile = self.root / "profile"
        profile.mkdir(mode=0o700)
        manifest = {"task_id": "original-task", "family_id": "original-family"}
        venv = self.root / "sdk"
        (venv / "bin").mkdir(parents=True)
        python = venv / "bin/python"
        python.symlink_to("/usr/bin/python3")
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
        paths = {}
        for name, version in runtime._sdk("openai_agents")["packages"]:
            path = venv / "lib/python3.12/site-packages" / (name + "-" + version + ".dist-info/METADATA")
            path.parent.mkdir(parents=True)
            path.write_text("Name: " + name + "\nVersion: " + version + "\n\n", encoding="utf-8")
            paths[name] = path
        with patch.object(runtime.subprocess, "run", side_effect=AssertionError("SDK executed on host")):
            self.assertEqual(runtime._python_runtime(python, profile, framework="openai_agents"), (python, venv))
            for path in paths.values():
                original = path.read_bytes()
                path.write_text("Version: 0.0.0\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "sdk_requires_pinned_openai_agents_packages"):
                    runtime._python_runtime(python, profile, framework="openai_agents")
                path.write_bytes(original)
        folder, first = runtime._session(profile, manifest, "agents", python, resume=False, framework="openai_agents")
        self.assertEqual((first["task_id"], first["family_id"]), (manifest["task_id"], manifest["family_id"]))
        original = (folder / "session.json").read_bytes()
        for changed in ("smolagents", "langgraph"):
            with self.assertRaisesRegex(ValueError, "sdk_session_binding_changed"):
                runtime._session(profile, manifest, "agents", python, resume=True, framework=changed)
            self.assertEqual((folder / "session.json").read_bytes(), original)
        self.assertEqual(runtime._session(profile, manifest, "agents", python, resume=True, framework="openai_agents")[1], first)

    def test_raw_rpc_cannot_bypass_the_sdk_operation_subset(self):
        secret = self.root / "secret.txt"
        secret.write_text("synthetic")
        with Broker(self.root / "state", {"document": Resource(secret, ())},
                    {"allowed": Destination("http://127.0.0.1:1/should-not-send", ())}) as broker:
            task = broker.create_task(task_id="original")
            path = broker.serve(task, self.root / "broker.sock", allowed_operations={"describe", "read"})
            for operation in ("send", "create_task", "revoke", "configure_defense"):
                result = request(operation, socket_path=str(path), destination="allowed", body="synthetic")
                self.assertEqual(result, {"allowed": False, "reason": "operation_not_available_in_session"})
            self.assertTrue(request("describe", socket_path=str(path))["allowed"])
            self.assertEqual(request("read", socket_path=str(path), resource="document")["content"], "synthetic")
            for invalid in ([], {}, None):
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(path))
                    client.sendall(json.dumps({"op": invalid}).encode() + b"\n")
                    value = json.loads(client.makefile("rb").readline())
                    self.assertFalse(value["allowed"])

    def test_pydantic_ai_pins_and_session_binding_are_checked_without_importing_sdk(self):
        profile = self.root / "profile"
        profile.mkdir(mode=0o700)
        manifest = {"task_id": "original-task", "family_id": "original-family"}
        venv = self.root / "pydantic-runtime"
        (venv / "bin").mkdir(parents=True)
        python = venv / "bin/python"
        python.symlink_to("/usr/bin/python3")
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
        metadata = []
        for name, version in runtime._sdk("pydantic_ai")["packages"]:
            path = venv / "lib/python3.12/site-packages" / (name + "-" + version + ".dist-info/METADATA")
            path.parent.mkdir(parents=True)
            path.write_text("Name: " + name + "\nVersion: " + version + "\n\n", encoding="utf-8")
            metadata.append(path)
        with patch.object(runtime.subprocess, "run", side_effect=AssertionError("SDK executed on host")):
            self.assertEqual(runtime._python_runtime(python, profile, framework="pydantic_ai"), (python, venv))
            for path in metadata:
                original = path.read_bytes()
                path.write_text("Version: 0.0.0\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "sdk_requires_pinned_pydantic_ai_packages"):
                    runtime._python_runtime(python, profile, framework="pydantic_ai")
                path.unlink()
                with self.assertRaisesRegex(ValueError, "sdk_pydantic_ai_version_not_verified"):
                    runtime._python_runtime(python, profile, framework="pydantic_ai")
                path.write_bytes(original)
        folder, first = runtime._session(profile, manifest, "pydantic", python, resume=False, framework="pydantic_ai")
        original = (folder / "session.json").read_bytes()
        self.assertEqual((first["task_id"], first["family_id"]), (manifest["task_id"], manifest["family_id"]))
        for changed in ("smolagents", "langgraph", "openai_agents"):
            with self.assertRaisesRegex(ValueError, "sdk_session_binding_changed"):
                runtime._session(profile, manifest, "pydantic", python, resume=True, framework=changed)
            self.assertEqual((folder / "session.json").read_bytes(), original)
        self.assertEqual(runtime._session(profile, manifest, "pydantic", python, resume=True, framework="pydantic_ai")[1], first)

    def test_google_adk_packages_and_native_session_cannot_replace_original_authority(self):
        profile = self.root / "profile"
        profile.mkdir(mode=0o700)
        manifest = {"task_id": "original-task", "family_id": "original-family"}
        venv = self.root / "google-adk-runtime"
        (venv / "bin").mkdir(parents=True)
        python = venv / "bin/python"
        python.symlink_to("/usr/bin/python3")
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
        metadata = []
        for name, version in runtime._sdk("google_adk")["packages"]:
            path = venv / "lib/python3.12/site-packages" / (name + "-" + version + ".dist-info/METADATA")
            path.parent.mkdir(parents=True)
            path.write_text("Name: " + name + "\nVersion: " + version + "\n\n", encoding="utf-8")
            metadata.append(path)
        with patch.object(runtime.subprocess, "run", side_effect=AssertionError("SDK executed on host")):
            self.assertEqual(runtime._python_runtime(python, profile, framework="google_adk"), (python, venv))
            for path in metadata:
                original = path.read_bytes()
                path.write_text("Version: 0.0.0\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "sdk_requires_pinned_google_adk_packages"):
                    runtime._python_runtime(python, profile, framework="google_adk")
                path.unlink()
                with self.assertRaisesRegex(ValueError, "sdk_google_adk_version_not_verified"):
                    runtime._python_runtime(python, profile, framework="google_adk")
                path.write_bytes(original)
        folder, first = runtime._session(profile, manifest, "google-adk", python, resume=False, framework="google_adk")
        original = (folder / "session.json").read_bytes()
        self.assertEqual((first["task_id"], first["family_id"]), (manifest["task_id"], manifest["family_id"]))
        for changed in ("smolagents", "langgraph", "openai_agents", "pydantic_ai"):
            with self.assertRaisesRegex(ValueError, "sdk_session_binding_changed"):
                runtime._session(profile, manifest, "google-adk", python, resume=True, framework=changed)
            self.assertEqual((folder / "session.json").read_bytes(), original)
        self.assertEqual(runtime._session(profile, manifest, "google-adk", python, resume=True, framework="google_adk")[1], first)

    def test_bounded_pipe_collection_stops_noisy_worker_and_timeout(self):
        for code, limit, expected in (("import os; os.write(1,b'x'*100000)", 1024, "output_limit"),
                                      ("import time; time.sleep(20)", 1024, "timeout")):
            process = subprocess.Popen([sys.executable, "-I", "-c", code], start_new_session=True,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with self.subTest(expected=expected), patch.object(runtime, "MAX_OUTPUT", limit):
                with self.assertRaisesRegex(RuntimeError, expected):
                    runtime._collect(process, threading.Event(), 1)
                self.assertIsNotNone(process.poll())

    def test_cancellation_remains_prompt_after_worker_closes_both_pipes(self):
        process = subprocess.Popen([sys.executable, "-I", "-c",
            "import os,time; os.close(1);os.close(2);time.sleep(30)"], start_new_session=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cancelled = threading.Event()
        timer = threading.Timer(.2, cancelled.set)
        timer.start()
        started = time.monotonic()
        try:
            with self.assertRaisesRegex(RuntimeError, "sdk_cancelled"):
                runtime._collect(process, cancelled, 20)
        finally:
            timer.cancel()
            stop(process)
        self.assertLess(time.monotonic() - started, 3)
        self.assertIsNotNone(process.poll())

    def test_python_and_child_cannot_read_host_or_directly_connect(self):
        if not sandbox_available(bwrap=bwrap())["available"]:
            self.skipTest("bubblewrap unavailable")
        work = self.root / "work"
        work.mkdir()
        private = self.root / "host-private.txt"
        private.write_text("SYNTHETIC-HOST-SECRET")
        with Broker(self.root / "state", {}, {}) as broker:
            task = broker.create_task(task_id="isolated")
            endpoint = broker.serve(task, self.root / "broker.sock", allowed_operations={"describe"})
            # A model socket is granted as an inode, never its containing dir.
            with socket.socket(socket.AF_UNIX) as model, socket.socket() as receiver:
                model.bind(str(self.root / "model.sock"))
                receiver.bind(("127.0.0.1", 0))
                receiver.listen()
                port = receiver.getsockname()[1]
                probe = ("import json,os,socket; from pathlib import Path; "
                         f"r={{'private_visible':Path({str(private)!r}).exists(),'key_in_env': 'SYNTHETIC' in str(dict(os.environ))}}; "
                         f"s=socket.socket();s.settimeout(.5);r['direct_network']=s.connect_ex(('127.0.0.1',{port}))==0; "
                         "print(json.dumps(r))")
                code = ("import subprocess,sys; " +
                        f"p=subprocess.run([sys.executable,'-I','-c',{probe!r}],capture_output=True,text=True,start_new_session=True); " +
                        "print(p.stdout.strip()); raise SystemExit(p.returncode)")
                process = start(command=["/usr/bin/python3", "-I", "-c", code], workspace=work,
                                broker_socket=endpoint, model_socket=self.root / "model.sock",
                                bwrap=bwrap(),
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    out, err = process.communicate(timeout=10)
                finally:
                    stop(process)
                self.assertEqual(process.returncode, 0, err.decode())
                self.assertEqual(json.loads(out), {"private_visible": False, "key_in_env": False, "direct_network": False})


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux checked model bridge")
class SdkModelBridgeTests(unittest.TestCase):
    def setUp(self):
        from tests.test_yuanxingmu_gateway_network import _provider
        from yuanxingmu.sdk_model_store import ModelStore
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="yxm-sbridge-")))
        self.broker = self.stack.enter_context(Broker(self.root / "authority", {}, {}))
        self.broker.create_task(task_id="one-task")
        self.fail_provider = False
        owner = self

        def reply(handler):
            body = json.dumps({"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
                "role": "assistant", "content": None, "tool_calls": [{"id": "provider-id", "type": "function",
                "function": {"name": "yuanxingmu_describe", "arguments": "{}"}}]}}]}).encode()
            handler.send_response(503 if owner.fail_provider else 200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)

        self.provider = self.stack.enter_context(_provider(reply))
        self.folder = self.root / "runtime"
        self.folder.mkdir(mode=0o700)
        self.store = ModelStore(self.root / "journal", "host-session")
        self.guard = runtime._SdkOutputGuard(self.broker, "one-task", "chosen-model", 2048)
        self.bridge = self.stack.enter_context(HostModel(self.folder,
            model_url=f"http://127.0.0.1:{self.provider.server_port}/fixed", api_key="SYNTHETIC-ONLY-HOST",
            output_guard=self.guard, model_store=self.store))
        self.body = json.dumps({"model": "chosen-model", "max_tokens": 512,
            "messages": [{"role": "user", "content": "synthetic request"}]}).encode()

    def request(self, *, replay_only=False):
        from tests.test_yuanxingmu_gateway_network import _UnixHTTP
        connection = _UnixHTTP(self.folder / "model.sock")
        try:
            path = "/v1/chat/completions/replay" if replay_only else "/v1/chat/completions"
            connection.request("POST", path, body=self.body)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_replay_keeps_host_nonce_and_current_revocation_is_checked(self):
        status, first = self.request()
        self.assertEqual(status, 200)
        self.assertNotEqual(json.loads(first)["choices"][0]["message"]["tool_calls"][0]["id"], "provider-id")
        self.provider.receipts.get(timeout=1)
        self.assertEqual(self.request(), (200, first))
        self.assertTrue(self.provider.receipts.empty())
        self.broker.revoke("one-task")
        status, denied = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(denied)["model"], "yuanxingmu-host")
        self.assertTrue(self.provider.receipts.empty())

    def test_unknown_upstream_outcome_cannot_be_retried(self):
        self.fail_provider = True
        self.assertEqual(self.request()[0], 502)
        self.provider.receipts.get(timeout=1)
        self.assertEqual(self.request()[0], 409)
        self.assertTrue(self.provider.receipts.empty())

    def test_lookup_route_missing_and_unknown_never_infers_or_registers_requests(self):
        self.assertEqual(self.request(replay_only=True)[0], 409)
        self.assertTrue(self.provider.receipts.empty())
        state = self.store.directory / "state.json"
        self.assertEqual(json.loads(state.read_bytes())["records"], [])
        self.fail_provider = True
        self.assertEqual(self.request()[0], 502)
        self.provider.receipts.get(timeout=1)
        before = state.read_bytes()
        self.assertEqual(self.request(replay_only=True)[0], 409)
        self.assertEqual(state.read_bytes(), before)
        self.assertTrue(self.provider.receipts.empty())

    def test_lookup_route_replays_exact_reply_and_enforces_current_revocation(self):
        status, first = self.request()
        self.assertEqual(status, 200)
        self.provider.receipts.get(timeout=1)
        with patch.object(self.store, "begin", side_effect=AssertionError("lookup reserved a model call")), \
                patch.object(self.store, "finish", side_effect=AssertionError("lookup released a model call")):
            self.assertEqual(self.request(replay_only=True), (200, first))
            self.broker.revoke("one-task")
            status, denied = self.request(replay_only=True)
            self.assertEqual(status, 403)
            self.assertEqual(json.loads(denied)["error"], "model_replay_currently_denied")
        self.assertTrue(self.provider.receipts.empty())

    def test_lookup_route_current_guard_rewrite_never_claims_to_be_original(self):
        self.assertEqual(self.request()[0], 200)
        self.provider.receipts.get(timeout=1)
        with patch.object(self.guard, "preflight", return_value=None), \
                patch.object(self.guard, "guard", return_value=b'{"synthetic":"withheld"}'):
            status, body = self.request(replay_only=True)
        self.assertEqual(status, 403)
        self.assertNotIn(b"withheld", body)
        self.assertTrue(self.provider.receipts.empty())

    def test_journal_finish_fault_does_not_skip_connection_cleanup(self):
        with patch.object(self.store, "finish", side_effect=ValueError("synthetic-storage-fault")):
            self.assertEqual(self.request()[0], 409)
            deadline = time.monotonic() + 2
            server = self.bridge._serving.server
            while time.monotonic() < deadline:
                with server.connections_lock:
                    if not server.connections:
                        break
                time.sleep(.01)
            with server.connections_lock:
                self.assertFalse(server.connections)

    def check_reply_waits_for_finish(self, *, fail_provider=False, replay=False):
        if replay:
            self.assertEqual(self.request()[0], 200)
            self.provider.receipts.get(timeout=1)
        self.fail_provider = fail_provider
        entered, release, received = threading.Event(), threading.Event(), threading.Event()
        result = []
        original = self.store.finish

        def delayed(ticket):
            entered.set()
            if not release.wait(5):
                raise ValueError("test_finish_not_released")
            return original(ticket)

        def client():
            try:
                result.append(self.request())
            finally:
                received.set()

        with patch.object(self.store, "finish", side_effect=delayed):
            thread = threading.Thread(target=client)
            thread.start()
            try:
                self.assertTrue(entered.wait(3), "handler did not reach finish")
                self.assertFalse(received.wait(.15), "HTTP reply escaped before the journal flight finished")
            finally:
                release.set()
                thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result[0][0], 502 if fail_provider else 200)
        self.assertIsNone(self.store._inflight)
        if fail_provider:
            self.assertEqual(json.loads((self.store.directory / "state.json").read_bytes())["records"][0]["state"], "unknown")
            self.assertEqual(self.request(replay_only=True)[0], 409)
        else:
            self.assertEqual(self.request(replay_only=True), result[0])

    def test_successful_model_reply_waits_for_finish_before_immediate_lookup(self):
        self.check_reply_waits_for_finish()

    def test_failed_model_reply_waits_for_unknown_state_before_immediate_lookup(self):
        self.check_reply_waits_for_finish(fail_provider=True)

    def test_cached_model_reply_waits_for_finish_before_immediate_lookup(self):
        self.check_reply_waits_for_finish(replay=True)

    def test_cached_finish_single_failure_is_session_error_without_new_inference(self):
        first = self.request()
        self.assertEqual(first[0], 200)
        self.provider.receipts.get(timeout=1)
        calls = []
        original = self.store.finish

        def fail_once(ticket):
            calls.append(ticket)
            if len(calls) == 1:
                raise ValueError("synthetic_finish_fault")
            return original(ticket)

        with patch.object(self.store, "finish", side_effect=fail_once):
            status, body = self.request()
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(body)["error"], "model_session_unavailable")
        self.assertEqual(len(calls), 2)
        self.assertIsNone(self.store._inflight)
        self.assertEqual(self.request(replay_only=True), first)
        self.assertTrue(self.provider.receipts.empty())


@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("YUANXINGMU_SMOLAGENTS_PYTHON"),
                     "Set YUANXINGMU_SMOLAGENTS_PYTHON to an installed smolagents 1.26.0 Linux venv")
class SdkFullLoopTests(unittest.TestCase):
    framework = "smolagents"
    sdk_python_environment = "YUANXINGMU_SMOLAGENTS_PYTHON"
    automatic_model_requests = 3

    def model_message(self, value):
        if len(self.model_requests) == 1:
            return {"role": "assistant", "content": None, "tool_calls": [{"id": "provider-call",
                "type": "function", "function": {"name": "yuanxingmu_read", "arguments": '{"resource":"quote"}'}}]}
        if len(self.model_requests) == 2 and self.automatic_calls:
            return {"role": "assistant", "content": None, "tool_calls": self.automatic_calls}
        if self.framework != "smolagents":
            return {"role": "assistant", "content": "PUBLIC SDK DONE"}
        return {"role": "assistant", "content": None, "tool_calls": [{"id": "provider-final",
            "type": "function", "function": {"name": "final_answer", "arguments": '{"answer":"PUBLIC SDK DONE"}'}}]}

    def setUp(self):
        if not sandbox_available(bwrap=bwrap())["available"]:
            self.skipTest("bubblewrap unavailable")
        from tests.test_yuanxingmu_openclaw import OpenClawProfileTests
        self.fixture = OpenClawProfileTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.model_requests, self.judge_requests = [], []
        self.automatic_calls = []
        owner = self

        class Provider(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/judge/chat/completions":
                    owner.judge_requests.append(value)
                    message = {"role": "assistant", "content": json.dumps({"verdict": "allow", "reason": "controlled fixture"})}
                else:
                    owner.model_requests.append(value)
                    message = owner.model_message(value)
                raw = json.dumps({"choices": [{"index": 0, "message": message,
                    "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        self.thread = threading.Thread(target=self.provider.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        self.thread.start()
        self.addCleanup(self.cleanup_provider)
        base = f"http://127.0.0.1:{self.provider.server_port}"
        self.fixture.source.write_text("客户公开报价：198000元。\n内部底价为162000元，不能展示。\n", encoding="utf-8")
        self.fixture.initialize(bwrap=bwrap(), model_url=base + "/model", model_id="synthetic-sdk-model",
            defense_policy={"objective": "Read the quote and give a public summary."},
            judge_config={"url": base + "/judge", "id": "synthetic-judge", "api_key": "SYNTHETIC-JUDGE-KEY"})
        manifest = runtime.host.validate_profile(self.fixture.profile)
        sockets = Path(manifest["runtime"])
        self.addCleanup(lambda: shutil.rmtree(sockets) if sockets.is_dir() else None)

    def cleanup_provider(self):
        self.provider.shutdown()
        self.provider.server_close()
        self.thread.join(timeout=2)

    def run_sdk(self, **overrides):
        values = {"profile": self.fixture.profile, "sdk_python": Path(os.environ[self.sdk_python_environment]),
                  "session": "normal", "prompt": "Read quote and provide a short public summary.",
                  "timeout": 30, "framework": self.framework, **overrides}
        return runtime.run_session(**values)

    def test_full_loop_is_isolated_resumable_and_revocation_survives(self):
        first = self.run_sdk()
        self.assertEqual(first["status"], "completed")
        self.assertEqual(first["framework"], self.framework)
        self.assertEqual(first["answer"], "PUBLIC SDK DONE")
        self.assertEqual(len(self.model_requests), 2)
        self.assertGreater(len(self.judge_requests), 0)
        raw = json.dumps(self.model_requests)
        self.assertTrue(self.fixture.secret not in raw, "host key entered SDK model requests")
        self.assertTrue("162000" not in raw, "explicitly protected value entered SDK model requests")
        manifest = runtime.host.validate_profile(self.fixture.profile)
        self.assertEqual(first["task_id"], manifest["task_id"])
        second = self.run_sdk(resume=True)
        self.assertEqual(second["session_id"], first["session_id"])
        self.assertEqual(len(self.model_requests), 2, "completed replay made a new inference request")
        runtime.host.control_profile(self.fixture.profile, "revoke")
        with self.assertRaisesRegex(RuntimeError, "sdk_task_not_active"):
            self.run_sdk(resume=True)
        self.assertEqual(len(self.model_requests), 2)
        lifecycle = json.loads((self.fixture.profile / "lifecycle.json").read_text())
        self.assertTrue(lifecycle["cleanup_confirmed"])
        for name in ("broker.sock", "operator.sock", "model.sock", "review.sock"):
            self.assertFalse((Path(manifest["runtime"]) / name).exists())

    def test_automatic_message_upload_and_form_once_then_resume_without_duplicates(self):
        receipts = []
        self.automatic_receipts = receipts

        class Receiver(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                receipts.append({"path": self.path, "body": raw.decode("utf-8")})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        receiver = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        thread = threading.Thread(target=receiver.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 2)
        self.addCleanup(receiver.server_close)
        self.addCleanup(receiver.shutdown)
        base = f"http://127.0.0.1:{receiver.server_port}"
        targets = {"message": {"kind": "message", "label": "Local message", "url": base + "/sdk-message"},
                   "upload": {"kind": "upload", "label": "Local upload", "url": base + "/sdk-upload"},
                   "form": {"kind": "form", "label": "Local form", "url": base + "/sdk-form", "form_fields": ["summary"]}}
        scope = {"version": 1, "max_attempts": 3, "max_total_body_bytes": 65536,
                 "targets": {name: {"accepted_labels": ["private"], "max_body_bytes": 8192} for name in targets}}
        self.fixture.profile = self.fixture.root / "automatic-profile"
        provider = f"http://127.0.0.1:{self.provider.server_port}"
        self.fixture.initialize(bwrap=bwrap(), model_url=provider + "/model", model_id="synthetic-sdk-model",
            defense_policy={"objective": "Read the quote and send its public summary to the three authorized local targets."},
            judge_config={"url": provider + "/judge", "id": "synthetic-judge", "api_key": "SYNTHETIC-JUDGE-KEY"},
            reviewed_actions=True, action_targets=targets, action_automation=scope)
        manifest = runtime.host.validate_profile(self.fixture.profile)
        sockets = Path(manifest["runtime"])
        self.addCleanup(lambda: shutil.rmtree(sockets) if sockets.is_dir() else None)
        payloads = {"message": {"body": "Public price 198000"},
                    "upload": {"filename": "summary.txt", "content": "Public price 198000"},
                    "form": {"fields": [{"name": "summary", "value": "Public price 198000"}]}}
        self.automatic_calls = [{"id": "provider-" + name, "type": "function", "function": {
            "name": "yuanxingmu_request_action", "arguments": json.dumps({"proposal": {
                "kind": name, "target_id": name, "payload": payloads[name]}})}} for name in targets]
        result = self.run_sdk()
        self.automatic_result = result
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(self.model_requests), self.automatic_model_requests)
        self.assertEqual(len(receipts), 3)
        self.assertEqual({item["path"] for item in receipts}, {"/sdk-message", "/sdk-upload", "/sdk-form"})
        self.assertTrue("162000" not in json.dumps(self.model_requests + receipts))
        self.assertEqual(self.run_sdk(resume=True)["session_id"], result["session_id"])
        self.assertEqual(len(receipts), 3)
        self.assertEqual(len(self.model_requests), self.automatic_model_requests)


class LangGraphFullLoopTests(SdkFullLoopTests):
    # Set explicitly: the decorated smolagents parent may be skipped in an
    # environment containing only LangGraph, but this class must still run.
    __unittest_skip__ = not (sys.platform.startswith("linux") and os.environ.get("YUANXINGMU_LANGGRAPH_PYTHON"))
    __unittest_skip_why__ = "Set YUANXINGMU_LANGGRAPH_PYTHON to the pinned LangGraph Linux venv"
    framework = "langgraph"
    sdk_python_environment = "YUANXINGMU_LANGGRAPH_PYTHON"

    def test_new_session_on_another_framework_keeps_original_automatic_budget(self):
        if not os.environ.get("YUANXINGMU_SMOLAGENTS_PYTHON"):
            self.skipTest("Both pinned SDK environments are required for cross-framework execution")
        self.test_automatic_message_upload_and_form_once_then_resume_without_duplicates()
        original = self.automatic_result
        self.model_requests.clear()
        # A second, different SDK performs a complete loop on the same stopped
        # profile, using a new session and therefore new tool-call identities.
        self.framework = "smolagents"
        changed = self.run_sdk(session="different-framework",
                               sdk_python=Path(os.environ["YUANXINGMU_SMOLAGENTS_PYTHON"]))
        self.assertEqual(changed["status"], "completed")
        self.assertEqual(changed["framework"], "smolagents")
        self.assertEqual(changed["task_id"], original["task_id"])
        self.assertNotEqual(changed["session_id"], original["session_id"])
        self.assertEqual(len(self.automatic_receipts), 3)
        self.assertEqual(len(self.model_requests), 3)
        observed = json.dumps(self.model_requests[-1]["messages"])
        self.assertEqual(observed.count("automatic_attempt_budget_exhausted"), 3)
        self.assertNotIn("162000", observed)


class OpenAIAgentsFullLoopTests(LangGraphFullLoopTests):
    __unittest_skip__ = not (sys.platform.startswith("linux") and os.environ.get("YUANXINGMU_OPENAI_AGENTS_PYTHON"))
    __unittest_skip_why__ = "Set YUANXINGMU_OPENAI_AGENTS_PYTHON to the pinned OpenAI Agents Linux venv"
    framework = "openai_agents"
    sdk_python_environment = "YUANXINGMU_OPENAI_AGENTS_PYTHON"
    automatic_model_requests = 4

    def model_message(self, value):
        if self.framework != "openai_agents" or not self.automatic_calls:
            return super().model_message(value)
        number = len(self.model_requests)
        if number == 1:
            return super().model_message(value)
        if number == 2:
            return {"role": "assistant", "content": None, "tool_calls": [{"id": "provider-handoff",
                "type": "function", "function": {"name": "yuanxingmu_handoff_to_executor", "arguments": '{}'}}]}
        if number == 3:
            return {"role": "assistant", "content": None, "tool_calls": self.automatic_calls}
        return {"role": "assistant", "content": "PUBLIC SDK DONE"}

    def test_automatic_message_upload_and_form_once_then_resume_without_duplicates(self):
        super().test_automatic_message_upload_and_form_once_then_resume_without_duplicates()
        before = {row["function"]["name"] for row in self.model_requests[0]["tools"]}
        after = {row["function"]["name"] for row in self.model_requests[2]["tools"]}
        self.assertEqual(before, {"yuanxingmu_read", "yuanxingmu_describe", "yuanxingmu_action_targets",
                                  "yuanxingmu_handoff_to_executor"})
        self.assertEqual(after, {"yuanxingmu_describe", "yuanxingmu_action_targets", "yuanxingmu_propose_action",
                                 "yuanxingmu_draft_email", "yuanxingmu_request_action"})
        self.assertEqual(self.automatic_result["task_id"], runtime.host.validate_profile(self.fixture.profile)["task_id"])

    def test_new_openai_agents_session_reports_exhausted_budget_without_more_effects(self):
        self.test_automatic_message_upload_and_form_once_then_resume_without_duplicates()
        original = self.automatic_result
        self.model_requests.clear()
        result = self.run_sdk(session="same-framework-after-budget")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["answer"], "PUBLIC SDK DONE")
        self.assertEqual(result["task_id"], original["task_id"])
        self.assertNotEqual(result["session_id"], original["session_id"])
        self.assertEqual(len(self.automatic_receipts), 3)
        self.assertEqual(len(self.model_requests), 4)
        messages = json.dumps(self.model_requests[-1]["messages"])
        self.assertEqual(messages.count("automatic_attempt_budget_exhausted"), 3)
        self.assertNotIn("162000", messages)


class PydanticAiFullLoopTests(LangGraphFullLoopTests):
    __unittest_skip__ = not (sys.platform.startswith("linux") and os.environ.get("YUANXINGMU_PYDANTIC_AI_PYTHON"))
    __unittest_skip_why__ = "Set YUANXINGMU_PYDANTIC_AI_PYTHON to the pinned PydanticAI Linux venv"
    framework = "pydantic_ai"
    sdk_python_environment = "YUANXINGMU_PYDANTIC_AI_PYTHON"

    def test_new_pydantic_ai_session_cannot_reset_the_automatic_budget(self):
        self.test_automatic_message_upload_and_form_once_then_resume_without_duplicates()
        original = self.automatic_result
        self.model_requests.clear()
        result = self.run_sdk(session="same-framework-after-budget")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["task_id"], original["task_id"])
        self.assertNotEqual(result["session_id"], original["session_id"])
        self.assertEqual(len(self.automatic_receipts), 3)
        self.assertEqual(len(self.model_requests), 3)
        observed = json.dumps(self.model_requests[-1]["messages"])
        self.assertEqual(observed.count("automatic_attempt_budget_exhausted"), 3)
        self.assertNotIn("162000", observed)


class GoogleAdkFullLoopTests(LangGraphFullLoopTests):
    __unittest_skip__ = not (sys.platform.startswith("linux") and os.environ.get("YUANXINGMU_GOOGLE_ADK_PYTHON"))
    __unittest_skip_why__ = "Set YUANXINGMU_GOOGLE_ADK_PYTHON to the pinned Google ADK Linux venv"
    framework = "google_adk"
    sdk_python_environment = "YUANXINGMU_GOOGLE_ADK_PYTHON"
    automatic_model_requests = 4

    def model_message(self, value):
        if self.framework != "google_adk" or not self.automatic_calls:
            return super().model_message(value)
        number = len(self.model_requests)
        if number == 1:
            return super().model_message(value)
        if number == 2:
            return {"role": "assistant", "content": None, "tool_calls": [{"id": "provider-transfer",
                "type": "function", "function": {"name": "transfer_to_agent", "arguments": '{"agent_name":"yuanxingmu_executor"}'}}]}
        if number == 3:
            return {"role": "assistant", "content": None, "tool_calls": self.automatic_calls}
        return {"role": "assistant", "content": "PUBLIC SDK DONE"}

    def test_automatic_message_upload_and_form_once_then_resume_without_duplicates(self):
        super().test_automatic_message_upload_and_form_once_then_resume_without_duplicates()
        before = {row["function"]["name"] for row in self.model_requests[0]["tools"]}
        after = {row["function"]["name"] for row in self.model_requests[2]["tools"]}
        self.assertEqual(before, {"yuanxingmu_read", "yuanxingmu_describe", "yuanxingmu_action_targets", "transfer_to_agent"})
        self.assertEqual(after, {"yuanxingmu_describe", "yuanxingmu_action_targets", "yuanxingmu_propose_action",
                                 "yuanxingmu_draft_email", "yuanxingmu_request_action"})
        self.assertEqual(self.automatic_result["task_id"], runtime.host.validate_profile(self.fixture.profile)["task_id"])

    def test_new_google_adk_session_after_transfer_does_not_reset_the_automatic_budget(self):
        self.test_automatic_message_upload_and_form_once_then_resume_without_duplicates()
        original = self.automatic_result
        self.model_requests.clear()
        result = self.run_sdk(session="same-framework-after-budget")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["task_id"], original["task_id"])
        self.assertNotEqual(result["session_id"], original["session_id"])
        self.assertEqual(len(self.automatic_receipts), 3)
        self.assertEqual(len(self.model_requests), 4)
        observed = json.dumps(self.model_requests[-1]["messages"])
        self.assertEqual(observed.count("automatic_attempt_budget_exhausted"), 3)
        self.assertNotIn("162000", observed)


if __name__ == "__main__":
    unittest.main()
