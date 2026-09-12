"""Independent failure-boundary checks for the SDK host entry.

These use real private files, subprocess pipes, Broker sockets and model HTTP.
Supervisor tests replace only the SDK launch with a controlled Python process
and use an explicit local judge fixture. They are not SDK or real-model safety
acceptance tests. Process isolation has separate runtime tests.
"""
from contextlib import ExitStack
import json
import os
from pathlib import Path
import queue
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from yuanxingmu import sdk_runtime as runtime
from yuanxingmu import sdk_model_store as storage
from yuanxingmu.worker import stop as stop_process


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux SDK host boundary")
class SdkSupervisorFailureTests(unittest.TestCase):
    def setUp(self):
        from tests.test_yuanxingmu_openclaw import OpenClawProfileTests
        from tests.test_yuanxingmu_gateway_network import _provider

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.fixture = OpenClawProfileTests()
        self.stack.callback(self.fixture.doCleanups)
        self.fixture.setUp()

        def judge(handler):
            raw = json.dumps({"choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant", "content": json.dumps({"verdict": "allow", "reason": "controlled failure test"})}}]}).encode()
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(raw)))
            handler.end_headers()
            handler.wfile.write(raw)

        self.provider = self.stack.enter_context(_provider(judge))
        base = f"http://127.0.0.1:{self.provider.server_port}"
        self.fixture.source.write_text("公开合成资料。", encoding="utf-8")
        self.fixture.initialize(defense_policy={"objective": "Provide a public synthetic answer."},
                                model_url=base + "/model", model_id="synthetic-sdk-model",
                                judge_config={"url": base + "/judge", "id": "synthetic-judge", "api_key": "SYNTHETIC-ONLY"})
        self.manifest = runtime.host.validate_profile(self.fixture.profile)
        self.runtime_path = Path(self.manifest["runtime"])
        self.stack.callback(self._remove_runtime)
        self.processes = []
        self.stack.callback(self._stop_processes)
        self.normal_code = "import json; print(json.dumps({'status':'completed','answer':'SYNTHETIC PUBLIC ANSWER'}))"

    def _remove_runtime(self):
        if self.runtime_path.exists():
            # This runtime belongs only to the temporary profile created here.
            for path in self.runtime_path.iterdir():
                self.assertFalse(path.is_dir())
                path.unlink()
            self.runtime_path.rmdir()

    def _stop_processes(self):
        for process in self.processes:
            stop_process(process)
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    def _spawn(self, code, **kwargs):
        process = subprocess.Popen([sys.executable, "-I", "-B", "-c", code],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, close_fds=True)
        self.processes.append(process)
        return process

    def run_controlled(self, *, session="controlled", resume=False, launch=None):
        launch = launch or (lambda **kwargs: self._spawn(self.normal_code, **kwargs))
        with patch.object(runtime, "_python_runtime", return_value=(Path(sys.executable), self.fixture.root / "unused-sdk-runtime")), \
                patch.object(runtime, "sandbox_available", return_value={"available": True}), \
                patch.object(runtime, "start", side_effect=launch) as start:
            result = runtime.run_session(profile=self.fixture.profile, sdk_python=Path(sys.executable), session=session,
                                         prompt="Provide a public synthetic answer.", resume=resume, timeout=10)
            return result, start

    def test_missing_response_directory_or_state_cannot_be_recreated_on_resume(self):
        for missing in ("directory", "state"):
            with self.subTest(missing=missing):
                result, _ = self.run_controlled(session=missing)
                self.assertEqual(result["status"], "completed")
                folder = self.fixture.profile / "sdk-sessions" / missing / "model-responses"
                if missing == "directory":
                    for child in folder.iterdir():
                        self.assertTrue(stat.S_ISREG(child.lstat().st_mode))
                        child.unlink()
                    folder.rmdir()
                else:
                    (folder / "state.json").unlink()
                before = runtime.host._task_state(self.fixture.profile, self.manifest)
                with patch.object(storage, "ModelStore", side_effect=AssertionError("a lost journal was recreated")) as store:
                    with self.assertRaises((OSError, ValueError)):
                        self.run_controlled(session=missing, resume=True,
                                            launch=lambda **kwargs: self.fail("a lost journal launched a worker"))
                    store.assert_not_called()
                self.assertFalse((folder / "state.json").exists())
                self.assertEqual(runtime.host._task_state(self.fixture.profile, self.manifest), before)

    def test_service_close_failure_never_certifies_cleanup_or_allows_resume(self):
        original = runtime.HostModel.close
        previous_handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}

        def failed_close(bridge):
            original(bridge)
            raise OSError("synthetic_service_close_failure")

        with patch.object(runtime.HostModel, "close", failed_close):
            with self.assertRaisesRegex(OSError, "synthetic_service_close_failure"):
                self.run_controlled()
        lifecycle = json.loads((self.fixture.profile / "lifecycle.json").read_bytes())
        self.assertEqual(lifecycle["status"], "failed")
        self.assertIs(lifecycle["cleanup_confirmed"], False)
        self.assertNotEqual(runtime.host._offline_lifecycle(self.fixture.profile), "stopped")
        for name in ("broker.sock", "model.sock", "operator.sock", "review.sock"):
            self.assertFalse((self.runtime_path / name).exists())
        for process in self.processes:
            self.assertIsNotNone(process.poll())
            self.assertTrue(process.stdout.closed and process.stderr.closed)
        self.assertEqual({sig: signal.getsignal(sig) for sig in previous_handlers}, previous_handlers)
        with self.assertRaisesRegex(RuntimeError, "sdk_requires_confirmed_stopped_profile"):
            self.run_controlled(resume=True, launch=lambda **kwargs: self.fail("uncertain cleanup launched a worker"))

    def test_supervisor_socket_blocks_raw_send_despite_existing_destination_grant(self):
        def launch(**kwargs):
            code = ("import json,socket; "
                    "s=socket.socket(socket.AF_UNIX); s.settimeout(3); "
                    f"s.connect({str(kwargs['broker_socket'])!r}); "
                    "s.sendall(json.dumps({'op':'send','destination':'internal','body':'SYNTHETIC RAW RPC'}).encode()+b'\\n'); "
                    "r=json.loads(s.makefile('rb').readline()); s.close(); "
                    "print(json.dumps({'status':'completed','answer':json.dumps(r)}))")
            return self._spawn(code, **kwargs)

        result, _ = self.run_controlled(launch=launch)
        self.assertEqual(result["status"], "completed")
        self.assertEqual(json.loads(result["answer"]), {"allowed": False, "reason": "operation_not_available_in_session"})
        self.assertEqual(self.fixture.receipts, [])
        self.assertEqual(result["task_id"], self.manifest["task_id"])

    def test_operator_stop_preserves_authority_and_revoke_removes_it_for_children(self):
        self.runtime_path.mkdir(mode=0o700)
        cancelled = threading.Event()
        with self.fixture.open_broker() as broker:
            child = broker.delegate(self.manifest["task_id"])
            operator = runtime._Operator(self.fixture.profile, self.manifest, broker, {"status": "running"}, cancelled)
            try:
                stopped = runtime.host._rpc(operator.path, "stop")
                self.assertEqual(stopped["status"], "stopping")
                self.assertTrue(cancelled.wait(1))
                self.assertTrue(broker.authority.describe(child)["active"])
                cancelled.clear()
                revoked = runtime.host._rpc(operator.path, "revoke")
                self.assertFalse(revoked["task"]["active"])
                self.assertTrue(cancelled.wait(1))
                denied = broker.dispatch(child, {"op": "read", "resource": "quote"})
                self.assertEqual(denied["reason"], "task_revoked")
            finally:
                operator.close()
        with self.fixture.open_broker() as reopened:
            self.assertFalse(reopened.authority.describe(self.manifest["task_id"])["active"])
            self.assertFalse(reopened.authority.describe(child)["active"])


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux subprocess collection")
class SdkCollectorFailureTests(unittest.TestCase):
    def test_failed_stop_still_closes_both_pipes_and_selector(self):
        process = subprocess.Popen([sys.executable, "-I", "-c", "print('synthetic')"],
                                   start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        selector = selectors.DefaultSelector()
        try:
            with patch.object(runtime.selectors, "DefaultSelector", return_value=selector), \
                    patch.object(runtime, "stop", side_effect=OSError("synthetic_stop_failure")):
                with self.assertRaisesRegex(OSError, "synthetic_stop_failure"):
                    runtime._collect(process, threading.Event(), 3)
            self.assertTrue(process.stdout.closed)
            self.assertTrue(process.stderr.closed)
            self.assertIsNone(selector.get_map())
        finally:
            stop_process(process)
            selector.close()
            process.stdout.close()
            process.stderr.close()


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux checked HTTP and durable journal")
class SdkModelInFlightFailureTests(unittest.TestCase):
    def setUp(self):
        from tests.test_yuanxingmu_sdk_runtime import SdkModelBridgeTests
        self.fixture = SdkModelBridgeTests()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.arrived, self.release = threading.Event(), threading.Event()
        self.results = queue.Queue()
        original = self.fixture.provider.reply

        def delayed_reply(handler):
            self.arrived.set()
            if self.release.wait(5):
                try:
                    original(handler)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.fixture.provider.reply = delayed_reply
        self.addCleanup(self.release.set)

    def start_request(self):
        def request():
            try:
                self.results.put(self.fixture.request())
            except Exception as exc:
                self.results.put(exc)

        thread = threading.Thread(target=request, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 3)
        self.assertTrue(self.arrived.wait(2), "model request did not reach the controlled provider")
        return thread

    def test_revocation_during_inference_withholds_returned_tool_calls(self):
        thread = self.start_request()
        try:
            self.fixture.broker.revoke("one-task")
        finally:
            self.release.set()
        thread.join(3)
        self.assertFalse(thread.is_alive())
        result = self.results.get_nowait()
        self.assertIsInstance(result, tuple)
        status, raw = result
        self.assertEqual(status, 200)
        parsed = json.loads(raw)
        self.assertEqual(parsed["model"], "yuanxingmu-host")
        self.assertFalse(parsed["choices"][0]["message"].get("tool_calls"))
        self.fixture.provider.receipts.get(timeout=1)
        self.assertEqual(self.fixture.request()[0], 200)
        self.assertTrue(self.fixture.provider.receipts.empty())

    def test_bridge_stop_preserves_unknown_inflight_without_an_automatic_retry(self):
        finished = threading.Event()
        original = self.fixture.store.finish

        def finish(ticket):
            try:
                return original(ticket)
            finally:
                finished.set()

        with patch.object(self.fixture.store, "finish", side_effect=finish):
            thread = self.start_request()
            try:
                self.fixture.bridge.close()
                self.assertTrue(finished.wait(2), "interrupted model flight was not finalized")
                thread.join(3)
                self.assertFalse(thread.is_alive())
                self.assertIsInstance(self.results.get_nowait(), Exception)
                reopened = storage.ModelStore(self.fixture.root / "journal", "host-session")
                with self.assertRaisesRegex(storage.ModelStoreError, "sdk_model_outcome_unknown"):
                    reopened.begin(self.fixture.body)
                self.fixture.provider.receipts.get(timeout=1)
                self.assertTrue(self.fixture.provider.receipts.empty())
            finally:
                self.release.set()


if __name__ == "__main__":
    unittest.main()
