"""Real task/journal and local Unix/HTTP checks; no model or external service."""
from contextlib import ExitStack
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import queue
import socket
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("unused-host", timeout=3)
        self.path = str(path)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class _SyntheticUpstream(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.server.receipts.put(self.rfile.read(int(self.headers["Content-Length"])))
        body = json.dumps({"choices": [{"index": 0, "finish_reason": "stop",
            "message": {"role": "assistant", "content": "synthetic answer"}}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux task/journal and Unix model transport")
class AuditMetadataStateTests(unittest.TestCase):
    def setUp(self):
        # Keep platform-specific setup inside the skipped class's setup method.
        from yuanxingmu.broker import Broker
        from yuanxingmu.gateway_network import HostModel
        from yuanxingmu.sdk_model_store import ModelStore
        from yuanxingmu.sdk_runtime import _SdkOutputGuard

        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="yxm-audit-state-")))
        self.broker = self.stack.enter_context(Broker(self.root / "authority", {}, {}))
        self.broker.create_task(task_id="one-task")
        self.store = ModelStore(self.root / "journal", "audit-session")
        self.journal = self.store.directory / "state.json"
        self.begin = self.stack.enter_context(patch.object(self.store, "begin", wraps=self.store.begin))
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.body = json.dumps({"model": "chosen-model", "max_tokens": 512,
            "messages": [{"role": "user", "content": "synthetic request"}]}).encode()
        self.metadata = lambda: {"X-YXM-Audit-Correlation-ID": "corr-" + "a" * 32,
                                "X-YXM-Audit-Protocol-Version": "1.0"}
        self.provider = Mock(side_effect=lambda: self.metadata())

        self.upstream = ThreadingHTTPServer(("127.0.0.1", 0), _SyntheticUpstream)
        self.upstream.receipts = queue.Queue()
        server_thread = threading.Thread(target=self.upstream.serve_forever,
                                         kwargs={"poll_interval": .05}, daemon=True)
        server_thread.start()
        self.stack.callback(server_thread.join, 2)
        self.stack.callback(self.upstream.server_close)
        self.stack.callback(self.upstream.shutdown)
        self.connections = 0
        original_connect = http.client.HTTPConnection.connect

        def connect(connection):
            # The Unix client overrides connect, so this records actual upstream
            # TCP attempts synchronously, not just asynchronously read HTTP bodies.
            self.connections += 1
            return original_connect(connection)

        self.stack.enter_context(patch.object(http.client.HTTPConnection, "connect", connect))
        self.stack.enter_context(HostModel(self.runtime,
            model_url=f"http://127.0.0.1:{self.upstream.server_port}/fixed",
            api_key="SYNTHETIC-AUDIT-STATE", model_store=self.store,
            output_guard=_SdkOutputGuard(self.broker, "one-task", "chosen-model", 2048),
            audit_metadata_provider=self.provider))

    def request(self, *, replay_only=False):
        connection = _UnixHTTP(self.runtime / "model.sock")
        try:
            path = "/v1/chat/completions/replay" if replay_only else "/v1/chat/completions"
            connection.request("POST", path, body=self.body)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def assert_no_attempt(self, original_journal):
        self.assertEqual(self.connections, 0)
        self.begin.assert_not_called()
        self.assertEqual(self.journal.read_bytes(), original_journal)
        self.assertTrue(self.upstream.receipts.empty())

    def test_bad_metadata_keeps_journal_retryable_when_provider_is_fixed(self):
        original = self.journal.read_bytes()
        valid = self.metadata
        self.metadata = lambda: {"X-YXM-Audit-Task-ID": "synthetic-private-task"}
        self.assertEqual(self.request()[0], 500)
        self.assert_no_attempt(original)
        self.metadata = valid
        status, result = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(result)["choices"][0]["message"]["content"], "synthetic answer")
        self.assertEqual(self.connections, 1)
        self.begin.assert_called_once_with(self.body)
        self.assertEqual(self.store.lookup(self.body), result)
        self.assertEqual([row["state"] for row in json.loads(self.journal.read_bytes())["records"]], ["complete"])

    def test_revocation_during_provider_prevents_connection_and_journal_begin(self):
        original = self.journal.read_bytes()
        valid = self.metadata

        def revoke_then_generate():
            self.broker.revoke("one-task")
            return valid()

        self.metadata = revoke_then_generate
        status, result = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(result)["model"], "yuanxingmu-host")
        self.provider.assert_called_once_with()
        self.assert_no_attempt(original)

    def test_prior_revocation_never_calls_provider(self):
        original = self.journal.read_bytes()
        self.broker.revoke("one-task")
        status, result = self.request()
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(result)["model"], "yuanxingmu-host")
        self.provider.assert_not_called()
        self.assert_no_attempt(original)

    def test_explicit_replay_does_not_call_provider_or_create_another_ticket(self):
        first = self.request()
        self.assertEqual(first[0], 200)
        self.upstream.receipts.get(timeout=1)
        original = self.journal.read_bytes()
        self.connections = 0
        self.begin.reset_mock()
        self.provider.reset_mock()
        self.provider.side_effect = AssertionError("Replay must not generate audit metadata")
        self.assertEqual(self.request(replay_only=True), first)
        self.provider.assert_not_called()
        self.assert_no_attempt(original)


if __name__ == "__main__":
    unittest.main()
