import concurrent.futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import sys
import tempfile
import threading
import unittest

from yuanxingmu.authority import AuthorizationError
from yuanxingmu.broker import Broker, Destination, Resource
from yuanxingmu.client import request


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux broker only")
class BrokerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yxm-test-")
        self.root = Path(self.tmp.name)
        self.secret = self.root / "private.txt"
        self.secret.write_text("SYNTHETIC-PRIVATE-CONTENT")
        self.receipts = []
        self.receiver_entered = threading.Event()
        self.receiver_release = threading.Event()
        self.receiver_release.set()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                value = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.receipts.append({"path": self.path, **value})
                owner.receiver_entered.set()
                owner.receiver_release.wait(5)
                self.send_response(503 if self.path == "/error" else 200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

            def log_message(self, *args):
                pass

        self.receiver = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.receiver.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.thread.start()
        url = f"http://127.0.0.1:{self.receiver.server_port}"
        self.resources = {"private": Resource(self.secret, ("internal",))}
        self.destinations = {"internal": Destination(url + "/internal", ("internal",)),
                             "public": Destination(url + "/public"), "error": Destination(url + "/error")}
        self.broker = Broker(self.root / "state", self.resources, self.destinations)
        self.task = self.broker.create_task()

    def tearDown(self):
        self.receiver_release.set()
        self.broker.close()
        self.receiver.shutdown()
        self.receiver.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def test_bound_socket_rejects_identity_and_arbitrary_destination_and_preserves_reconnect_state(self):
        endpoint = self.broker.serve(self.task, self.root / "bound.sock")
        clean = self.broker.create_task()
        self.assertTrue(request("read", socket_path=str(endpoint), resource="private")["allowed"])
        self.assertFalse(request("send", socket_path=str(endpoint), destination="public", body="encoded-or-plain")["allowed"])
        for extra in ({"task_id": clean}, {"url": self.destinations["public"].url}, {"labels": []}):
            result = request("send", socket_path=str(endpoint), destination="public", body="try", **extra)
            self.assertEqual(result["reason"], "invalid_request")
        good = request("send", socket_path=str(endpoint), destination="internal", body="internal correction")
        self.assertEqual(good["outcome"], "acknowledged")
        self.assertEqual([r["path"] for r in self.receipts], ["/internal"])

    def test_restart_preserves_labels_and_policy_drift_cannot_reset_state(self):
        self.broker.dispatch(self.task, {"op": "read", "resource": "private"})
        self.broker.close()
        self.broker = Broker(self.root / "state", self.resources, self.destinations)
        self.assertFalse(self.broker.dispatch(self.task, {"op": "send", "destination": "public", "body": "secret"})["allowed"])
        self.broker.close()
        with self.assertRaisesRegex(RuntimeError, "changed"):
            Broker(self.root / "state", {"private": Resource(self.secret)}, self.destinations)
        self.broker = Broker(self.root / "state", self.resources, self.destinations)

    def test_changed_resource_never_returns_unlabelled_new_bytes(self):
        self.secret.write_text("changed synthetic resource")
        result = self.broker.dispatch(self.task, {"op": "read", "resource": "private"})
        self.assertEqual(result["reason"], "resource_changed")
        self.assertNotIn("content", result)
        self.assertEqual(self.broker.authority.describe(self.task)["labels"], ["internal"])

    def test_same_state_cannot_be_owned_by_two_brokers(self):
        with self.assertRaisesRegex(RuntimeError, "already_owned"):
            Broker(self.root / "state", self.resources, self.destinations)

    def test_read_cannot_release_private_data_during_an_authorized_public_send(self):
        self.receiver_release.clear()
        read_started = threading.Event()

        def read():
            read_started.set()
            return self.broker.dispatch(self.task, {"op": "read", "resource": "private"})

        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            sending = pool.submit(self.broker.dispatch, self.task, {"op": "send", "destination": "public", "body": "still public"})
            self.assertTrue(self.receiver_entered.wait(3))
            reading = pool.submit(read)
            self.assertTrue(read_started.wait(2))
            with self.assertRaises(concurrent.futures.TimeoutError):
                reading.result(timeout=0.1)
            self.receiver_release.set()
            self.assertEqual(sending.result(3)["outcome"], "acknowledged")
            self.assertTrue(reading.result(3)["allowed"])
        denied = self.broker.dispatch(self.task, {"op": "send", "destination": "public", "body": "now private"})
        self.assertFalse(denied["allowed"])
        self.assertEqual([r["body"] for r in self.receipts], ["still public"])

    def test_unconfirmed_send_is_not_reported_as_no_side_effect(self):
        result = self.broker.dispatch(self.task, {"op": "send", "destination": "error", "body": "public"})
        self.assertTrue(result["allowed"])
        self.assertEqual(result["outcome"], "unconfirmed")
        self.assertEqual(len(self.receipts), 1)
        events = [json.loads(line) for line in (self.root / "state/broker-events.jsonl").read_text().splitlines()]
        self.assertEqual([e["operation"] for e in events], ["send_intent", "send"])
        self.assertFalse(any("body" in e for e in events))

    def test_workspace_cannot_expose_state_resources_or_reset_under_a_new_task(self):
        with self.assertRaisesRegex(ValueError, "overlaps"):
            self.broker.bind_workspace(self.task, self.root)
        work = self.root / "worker"
        work.mkdir()
        self.broker.bind_workspace(self.task, work)
        self.broker.bind_workspace(self.task, work)
        clean = self.broker.create_task()
        with self.assertRaises(AuthorizationError):
            self.broker.bind_workspace(clean, work)
        child_path = work / "nested"
        child_path.mkdir()
        with self.assertRaises(AuthorizationError):
            self.broker.bind_workspace(clean, child_path)

    def test_revoke_blocks_existing_endpoints_and_descendant_send(self):
        child = self.broker.delegate(self.task)
        endpoint = self.broker.serve(child, self.root / "child.sock")
        self.broker.revoke(self.task)
        result = request("send", socket_path=str(endpoint), destination="internal", body="try")
        self.assertEqual(result["reason"], "task_revoked")
        self.assertEqual(self.receipts, [])

    def test_protocol_unknown_operations_and_malformed_json_fail_closed(self):
        endpoint = self.broker.serve(self.task, self.root / "protocol.sock")
        for data in (b'{broken\n', b'[]\n', b'{"op":"create_task"}\n', b'{"op":"describe","task_id":"x"}\n'):
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(str(endpoint))
                connection.sendall(data)
                with connection.makefile("rb") as stream:
                    result = json.loads(stream.readline())
            self.assertFalse(result["allowed"])
        self.assertEqual(self.receipts, [])


if __name__ == "__main__":
    unittest.main()
