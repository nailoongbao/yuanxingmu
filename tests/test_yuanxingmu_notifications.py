"""Persistent background webhook delivery to synthetic loopback receivers only.

No browser, model, real external webhook or task permission transition is used.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, asdict, replace
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from yuanxingmu import notifications
from yuanxingmu.notifications import NotificationConfig, NotificationQueue


class QueueClock:
    """Only the outbox sees this clock; socket/thread deadlines stay real."""
    def __init__(self, wall=1700000000.0, elapsed=100.0):
        self.wall = wall
        self.elapsed = elapsed

    def time(self):
        return self.wall

    def monotonic(self):
        return self.elapsed


class NotificationConfigTests(unittest.TestCase):
    def test_config_is_frozen_strict_and_public_report_omits_key_and_webhook_path(self):
        value = NotificationConfig("https://receiver.example.test/private-webhook-token", api_key="PRIVATE-AUTH-KEY")
        self.assertNotIn("PRIVATE-AUTH-KEY", repr(value))
        self.assertNotIn("PRIVATE-AUTH-KEY", json.dumps(value.public()))
        self.assertNotIn("private-webhook-token", json.dumps(value.public()))
        with self.assertRaises(FrozenInstanceError):
            value.url = "https://other.example.test/"
        with self.assertRaises(ValueError):
            NotificationConfig.from_dict({"url": value.url, "headers": {"Authorization": "not allowed"}})

    def test_fixed_endpoint_and_delivery_limits_are_validated(self):
        for url in ("https://receiver.example.test/hook", "http://127.0.0.1:8080/hook", "http://[::1]:8080/hook"):
            self.assertEqual(NotificationConfig(url).url, url)
        for url in ("http://localhost/hook", "http://192.0.2.1/hook", "http://127.0.0.1.evil.test/hook",
                    "https://user:key@receiver.example.test/hook", "https://receiver.example.test/hook?secret=x",
                    "https://receiver.example.test/hook#fragment", "https://receiver.example.test\\elsewhere/hook"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                NotificationConfig(url)
        bad = {"timeout_seconds": (0,31,True,float("nan")), "max_attempts": (0,21,True),
               "backoff_seconds": (0,-1), "max_backoff_seconds": (1,86401),
               "max_response_bytes": (0,65537,False), "queue_capacity": (0,100001,True),
               "strict_receipt": (1,None), "api_key": ("header\r\nattack","has space",None)}
        for field, values in bad.items():
            for value in values:
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    NotificationConfig("http://127.0.0.1/hook", **{field:value})


@unittest.skipUnless(sys.platform.startswith("linux"), "Durable host queue uses Linux private directories")
class NotificationQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="yxm-notifications-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.receipts = []
        self.http_status = 204
        self.body = b""
        self.delay = 0
        self.trickle_delay = 0
        self.response_headers = {}
        self.receiver_ready = threading.Event()
        case = self

        class Receiver(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self):
                self.close_connection = True
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                case.receipts.append({"body": raw, "headers": dict(self.headers), "path": self.path})
                case.receiver_ready.set()
                if case.delay:
                    time.sleep(case.delay)
                body = case.body
                if body is None:
                    body = json.dumps({"accepted": True, "event_id": json.loads(raw)["event_id"]}).encode()
                try:
                    self.send_response(case.http_status)
                    for name, value in case.response_headers.items():
                        self.send_header(name, value)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if case.trickle_delay:
                        for byte in body:
                            self.wfile.write(bytes([byte]))
                            self.wfile.flush()
                            time.sleep(case.trickle_delay)
                    else:
                        self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_receiver)
        self.config = NotificationConfig(f"http://127.0.0.1:{self.server.server_port}/fixed/hook", api_key="SYNTHETIC-HOST-NOTIFY-KEY",
                    timeout_seconds=.5, backoff_seconds=.02, max_backoff_seconds=.08, max_attempts=3)
        self.queues = []
        self.addCleanup(self.close_queues)
        original = socket.socket.connect

        def only_receiver(connection, address):
            if connection.family not in (socket.AF_INET,socket.AF_INET6) or tuple(address[:2]) != ("127.0.0.1",self.server.server_port):
                raise AssertionError("Notification test attempted non-fixture network access")
            return original(connection, address)

        patcher = mock.patch.object(socket.socket, "connect", new=only_receiver)
        patcher.start()
        self.addCleanup(patcher.stop)

    def close_receiver(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def close_queues(self):
        for queue in self.queues:
            queue.close()

    def queue(self, name="queue", **changes):
        queue = NotificationQueue(self.root / name, replace(self.config, **changes))
        self.queues.append(queue)
        return queue

    def wait_delivery(self, queue, expected="delivered", *, count=1):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = queue.status()
            if status["counts"][expected] == count:
                return status
            time.sleep(.01)
        self.fail(f"Expected {count} {expected} events: {queue.status()}")

    def test_enqueue_and_inspection_have_no_network_then_background_delivers_without_browser(self):
        queue = self.queue()
        result = queue.enqueue("event-1", "paused")
        self.assertTrue(result["created"])
        self.assertEqual(queue.status()["counts"]["pending"], 1)
        self.assertEqual(self.receipts, [])
        queue.start()
        self.wait_delivery(queue)
        self.assertEqual(len(self.receipts), 1)
        payload = json.loads(self.receipts[0]["body"])
        self.assertEqual(set(payload), {"version","event_id","status","message"})
        self.assertEqual((payload["event_id"],payload["status"]), ("event-1","paused"))
        self.assertEqual(self.receipts[0]["headers"]["Authorization"], "Bearer " + self.config.api_key)
        self.assertEqual(self.receipts[0]["path"], "/fixed/hook")
        self.assertNotIn(self.config.api_key, json.dumps(queue.status()))
        self.assertNotIn(self.config.api_key.encode(), (queue.state_dir / "notifications.sqlite3").read_bytes())

    def test_four_statuses_have_only_fixed_generic_messages(self):
        queue = self.queue()
        for status in ("paused","resumed","revoked","approval_required"):
            queue.enqueue("event-"+status,status)
        queue.start()
        self.wait_delivery(queue, count=4)
        for receipt in self.receipts:
            body = json.loads(receipt["body"])
            self.assertEqual(body["message"], notifications._MESSAGES[body["status"]])
            self.assertNotIn("command", body)
            self.assertNotIn("task_id", body)

    def test_invalid_event_payloads_cannot_smuggle_candidate_or_document_text(self):
        queue = self.queue()
        for event, status in (("space in identifier","paused"), ("\r\nheader","paused"), ("a"*129,"paused"),
                              ("ok","PRIVATE DOCUMENT CONTENT"), ("ok",[]), (None,"paused")):
            with self.subTest(event=event), self.assertRaises(ValueError):
                queue.enqueue(event,status)
        with self.assertRaises(TypeError):
            queue.enqueue("valid","paused", command="PRIVATE-COMMAND")
        self.assertEqual(queue.status()["events"], [])
        self.assertEqual(self.receipts, [])

    def test_duplicate_event_is_stable_across_restart_and_status_conflict_is_rejected(self):
        queue = self.queue()
        queue.enqueue("same-event","paused")
        queue.dispatch_once()
        self.assertFalse(queue.enqueue("same-event","paused")["created"])
        with self.assertRaisesRegex(ValueError,"event_conflict"):
            queue.enqueue("same-event","resumed")
        queue.close()
        restarted = self.queue()
        self.assertFalse(restarted.enqueue("same-event","paused")["created"])
        self.assertFalse(restarted.dispatch_once())
        self.assertEqual(len(self.receipts),1)

    def test_two_queue_instances_concurrently_deduplicate_and_lease_one_event(self):
        first, second = self.queue(), self.queue()
        with ThreadPoolExecutor(max_workers=2) as executor:
            created = list(executor.map(lambda queue: queue.enqueue("shared-event","approval_required")["created"], [first,second]))
        self.assertEqual(sorted(created),[False,True])
        with ThreadPoolExecutor(max_workers=2) as executor:
            attempted = list(executor.map(lambda queue: queue.dispatch_once(),[first,second]))
        self.assertEqual(sum(attempted),1)
        self.assertEqual(len(self.receipts),1)

    def test_failed_delivery_retries_boundedly_with_identical_body_and_idempotency_key(self):
        self.http_status = 503
        queue = self.queue()
        queue.enqueue("retry-event","paused")
        queue.start()
        status = self.wait_delivery(queue,"failed")
        self.assertEqual(status["events"][0]["attempts"],3)
        self.assertEqual(status["events"][0]["last_error"],"http_503")
        self.assertEqual(len(self.receipts),3)
        self.assertEqual(len({r["body"] for r in self.receipts}),1)
        self.assertEqual({r["headers"]["Idempotency-Key"] for r in self.receipts},{"yuanxingmu-notification:retry-event"})
        self.assertFalse(queue.dispatch_once())

    def test_clock_rollback_and_forward_jump_neither_stall_nor_accelerate_retries(self):
        self.http_status = 503
        clock = QueueClock()
        with mock.patch.object(notifications, "time", clock):
            queue = self.queue(backoff_seconds=2, max_backoff_seconds=4)
            queue.enqueue("clock-event", "paused")
            clock.wall -= 86400
            self.assertTrue(queue.dispatch_once(), "A new event is due even after the wall clock rolls back")
            clock.wall -= 86400
            clock.elapsed = 101
            self.assertFalse(queue.dispatch_once())
            clock.elapsed = 102
            self.assertTrue(queue.dispatch_once(), "Elapsed backoff must permit a retry despite wall-clock rollback")
            clock.wall += 315360000
            clock.elapsed = 105
            self.assertFalse(queue.dispatch_once(), "Moving wall time forward must not skip the next backoff")
            clock.elapsed = 106
            self.assertTrue(queue.dispatch_once())
            self.assertFalse(queue.dispatch_once())
        report = queue.status()
        self.assertEqual(report["counts"]["failed"], 1)
        self.assertEqual(report["events"][0]["attempts"], 3)
        self.assertEqual(report["events"][0]["last_error"], "http_503")
        self.assertEqual(len(self.receipts), 3)
        self.assertEqual(len({receipt["body"] for receipt in self.receipts}), 1)
        self.assertEqual({receipt["headers"]["Idempotency-Key"] for receipt in self.receipts},
                         {"yuanxingmu-notification:clock-event"})

    def test_retry_deadline_survives_reopen_and_is_shared_by_competing_instances_after_rollback(self):
        self.http_status = 503
        clock = QueueClock()
        with mock.patch.object(notifications, "time", clock):
            original = self.queue(backoff_seconds=2, max_backoff_seconds=4)
            original.enqueue("shared-retry", "revoked")
            self.assertTrue(original.dispatch_once())
            original.close()
            clock.wall -= 86400
            clock.elapsed = 101
            first = self.queue(backoff_seconds=2, max_backoff_seconds=4)
            second = self.queue(backoff_seconds=2, max_backoff_seconds=4)
            self.assertFalse(first.dispatch_once())
            self.assertFalse(second.dispatch_once())
            clock.elapsed = 102
            with ThreadPoolExecutor(max_workers=2) as executor:
                attempted = list(executor.map(lambda queue: queue.dispatch_once(), [first, second]))
            self.assertEqual(sum(attempted), 1, "Reopening cannot restart backoff or claim the same due event twice")
        self.assertEqual(first.status()["events"][0]["attempts"], 2)
        self.assertEqual(len(self.receipts), 2)

    def test_new_boot_rebases_retry_and_recovers_old_lease_without_resetting_attempts_or_ids(self):
        self.http_status = 503
        clock = QueueClock(elapsed=10000)
        with mock.patch.object(notifications, "time", clock):
            with mock.patch.object(notifications, "_boot_identifier", return_value="old-boot"):
                original = self.queue(backoff_seconds=2, max_backoff_seconds=4)
                original.enqueue("retry-after-boot", "paused")
                self.assertTrue(original.dispatch_once())
                original.enqueue("claimed-before-boot", "revoked")
                self.assertEqual(original._claim()["event_id"], "claimed-before-boot")
                original.close()
            clock.wall -= 86400
            clock.elapsed = 10
            self.http_status = 204
            with mock.patch.object(notifications, "_boot_identifier", return_value="new-boot"):
                restarted = self.queue(backoff_seconds=2, max_backoff_seconds=4)
                self.assertTrue(restarted.dispatch_once(), "An old boot cannot retain a live lease")
                self.assertFalse(restarted.dispatch_once())
                clock.elapsed = 12
                self.assertTrue(restarted.dispatch_once(), "Retry recovery waits at most one configured backoff")
                self.assertFalse(restarted.enqueue("retry-after-boot", "paused")["created"])
        report = restarted.status()
        self.assertEqual(report["counts"]["delivered"], 2)
        self.assertEqual({event["event_id"]: event["attempts"] for event in report["events"]},
                         {"retry-after-boot": 2, "claimed-before-boot": 2})
        self.assertEqual([json.loads(receipt["body"])["event_id"] for receipt in self.receipts],
                         ["retry-after-boot", "claimed-before-boot", "retry-after-boot"])

    def test_new_boot_does_not_grant_another_attempt_to_an_exhausted_unconfirmed_lease(self):
        clock = QueueClock(elapsed=10000)
        with mock.patch.object(notifications, "time", clock):
            with mock.patch.object(notifications, "_boot_identifier", return_value="old-boot"):
                original = self.queue(max_attempts=1)
                original.enqueue("exhausted-before-boot", "paused")
                original._claim()
                original.close()
            clock.wall -= 86400
            clock.elapsed = 10
            with mock.patch.object(notifications, "_boot_identifier", return_value="new-boot"):
                restarted = self.queue(max_attempts=1)
                self.assertFalse(restarted.dispatch_once())
        event = restarted.status()["events"][0]
        self.assertEqual((event["delivery"], event["attempts"], event["last_error"]),
                         ("failed", 1, "delivery_unconfirmed"))
        self.assertEqual(self.receipts, [])

    def test_legacy_queue_migration_bounds_retry_and_preserves_a_full_unknown_lease(self):
        path = self.root / "legacy"
        path.mkdir(mode=0o700)
        database = path / "notifications.sqlite3"
        config = replace(self.config, backoff_seconds=2, max_backoff_seconds=4)
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE notification_binding(version INTEGER NOT NULL, digest TEXT NOT NULL)")
            db.execute("INSERT INTO notification_binding VALUES(1,?)",
                       (hashlib.sha256(notifications._json(asdict(config))).hexdigest(),))
            db.execute("""CREATE TABLE notification_events(event_id TEXT PRIMARY KEY,status TEXT NOT NULL,
                          delivery TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,created_at REAL NOT NULL,
                          updated_at REAL NOT NULL,available_at REAL NOT NULL,lease_token TEXT,lease_until REAL,
                          last_error TEXT,delivered_at REAL)""")
            db.execute("""INSERT INTO notification_events VALUES
                          ('legacy-retry','paused','pending',1,1700000000,1700000000,1700000002,NULL,NULL,'http_503',NULL),
                          ('legacy-lease','revoked','in_flight',1,1700000000,1700000000,1700000000,'old-token',1700000005.5,NULL,NULL)""")
        database.chmod(0o600)
        clock = QueueClock(wall=1600000000)
        with mock.patch.object(notifications, "time", clock):
            queue = self.queue("legacy", backoff_seconds=2, max_backoff_seconds=4)
            self.assertFalse(queue.dispatch_once())
            clock.elapsed = 102
            self.assertTrue(queue.dispatch_once())
            self.assertEqual(json.loads(self.receipts[0]["body"])["event_id"], "legacy-retry")
            self.assertFalse(queue.dispatch_once(), "Unknown legacy leases retain a full timeout plus grace")
            clock.elapsed = 105
            self.assertFalse(queue.dispatch_once())
            clock.elapsed = 105.5
            self.assertTrue(queue.dispatch_once())
        self.assertEqual(queue.status()["counts"]["delivered"], 2)
        self.assertEqual({event["attempts"] for event in queue.status()["events"]}, {2})
        with sqlite3.connect(database) as db:
            self.assertEqual(db.execute("SELECT version FROM notification_binding").fetchone()[0], 2)

    def test_pending_retry_survives_restart_and_then_delivers(self):
        self.http_status = 503
        queue = self.queue()
        queue.enqueue("restart-event","approval_required")
        queue.dispatch_once()
        self.assertEqual(queue.status()["counts"]["pending"],1)
        queue.close()
        self.http_status = 204
        restarted = self.queue()
        restarted.start()
        status = self.wait_delivery(restarted)
        self.assertEqual(status["events"][0]["attempts"],2)
        self.assertEqual(self.receipts[0]["body"],self.receipts[1]["body"])

    def test_process_crash_after_durable_claim_recovers_expired_lease(self):
        config = {name:getattr(self.config,name) for name in self.config.__dataclass_fields__}
        program = """import json,os,sys
from pathlib import Path
from yuanxingmu.notifications import NotificationQueue,NotificationConfig
value=json.load(sys.stdin)
queue=NotificationQueue(Path(value['path']),NotificationConfig.from_dict(value['config']))
queue.enqueue('crash-event','paused')
assert queue._claim()['event_id']=='crash-event'
os._exit(0)
"""
        child = subprocess.run([sys.executable,"-c",program],input=json.dumps({"path":str(self.root/"crash"),"config":config}),
                               text=True,capture_output=True,timeout=10,check=True)
        self.assertEqual(child.stdout,"")
        queue = self.queue("crash")
        self.assertEqual(queue.status()["counts"]["in_flight"],1)
        self.assertFalse(queue.dispatch_once())
        clock = QueueClock(wall=time.time()+86400, elapsed=time.monotonic())
        with mock.patch.object(notifications, "time", clock):
            self.assertFalse(queue.dispatch_once(), "A forward wall-clock jump must not steal the current boot's lease")
            clock.wall -= 172800
            clock.elapsed += 20
            self.assertTrue(queue.dispatch_once())
        self.assertEqual(queue.status()["counts"]["delivered"],1)
        self.assertEqual(queue.status()["events"][0]["attempts"],2)
        self.assertEqual(len(self.receipts),1)

    def test_default_any_2xx_accepts_empty_or_non_protocol_response(self):
        for index,(status,body) in enumerate(((204,b""),(200,b"OK"),(202,b"not JSON"))):
            self.http_status,self.body = status,body
            queue=self.queue("ordinary-"+str(index))
            queue.enqueue("ordinary","revoked")
            queue.dispatch_once()
            self.assertEqual(queue.status()["counts"]["delivered"],1)

    def test_strict_receipt_requires_matching_event_id_and_acceptance(self):
        self.http_status,self.body=200,None
        queue=self.queue(strict_receipt=True)
        queue.enqueue("strict","paused")
        queue.dispatch_once()
        self.assertEqual(queue.status()["counts"]["delivered"],1)
        for index,body in enumerate((b'{}',b'{"accepted":true,"event_id":"wrong"}',
                                    b'{"accepted":true,"event_id":"strict","event_id":"strict"}',b'not-json',b'x'*1025)):
            self.body=body
            bad=self.queue("bad-receipt-"+str(index),strict_receipt=True,max_response_bytes=1024)
            bad.enqueue("strict","paused")
            bad.dispatch_once()
            self.assertEqual(bad.status()["counts"]["failed"],1)
            self.assertEqual(bad.status()["events"][0]["attempts"],1)

    def test_redirects_and_auth_failure_never_forward_or_retry_credentials(self):
        for status in (301,307,401,403):
            self.http_status=status
            self.response_headers={"Location":"https://outside.example.test/STEAL-KEY"}
            queue=self.queue("status-"+str(status))
            queue.enqueue("denied","paused")
            queue.dispatch_once()
            self.assertEqual(queue.status()["counts"]["failed"],1)
            self.assertFalse(queue.dispatch_once())
        self.assertEqual(len(self.receipts),4)

    def test_late_success_after_timeout_does_not_mark_delivered(self):
        self.http_status,self.delay=200,.2
        queue=self.queue(timeout_seconds=.05)
        queue.enqueue("slow-event","paused")
        started=time.monotonic()
        self.assertTrue(queue.dispatch_once())
        self.assertLess(time.monotonic()-started,.5)
        time.sleep(.25)
        self.assertEqual(queue.status()["counts"]["delivered"],0)
        self.assertEqual(queue.status()["counts"]["pending"],1)

    def test_capacity_counts_durable_deduplication_records_and_never_drops_alerts(self):
        queue=self.queue(queue_capacity=2)
        queue.enqueue("one","paused")
        queue.enqueue("two","revoked")
        queue.dispatch_once()
        with self.assertRaisesRegex(ValueError,"queue_full"):
            queue.enqueue("three","resumed")
        self.assertFalse(queue.enqueue("one","paused")["created"])
        self.assertEqual(sum(queue.status()["counts"].values()),2)

    def test_queue_binding_covers_endpoint_key_and_delivery_policy(self):
        queue=self.queue()
        with self.assertRaises(AttributeError):
            queue.config=replace(self.config,url="https://elsewhere.example.test/hook")
        queue.close()
        changes=({"url":self.config.url+"/other"},{"api_key":"REPLACEMENT-KEY"},{"timeout_seconds":1},
                 {"strict_receipt":True},{"queue_capacity":20},{"max_attempts":4},{"max_response_bytes":4096})
        for value in changes:
            with self.subTest(fields=list(value)),self.assertRaisesRegex(ValueError,"configuration_changed"):
                NotificationQueue(self.root/"queue",replace(self.config,**value))

    def test_private_storage_rejects_links_and_missing_binding_instead_of_resetting(self):
        queue=self.queue()
        queue.enqueue("retained","paused")
        queue.close()
        database=self.root/"queue"/"notifications.sqlite3"
        with sqlite3.connect(database) as db:
            db.execute("DELETE FROM notification_binding")
        with self.assertRaisesRegex(ValueError,"configuration_changed"):
            NotificationQueue(self.root/"queue",self.config)
        linked=self.root/"linked"
        linked.symlink_to(self.root/"queue",target_is_directory=True)
        with self.assertRaises(OSError):
            NotificationQueue(linked,self.config)
        hard=self.root/"hard"
        hard.mkdir(mode=0o700)
        os.link(database,hard/"notifications.sqlite3")
        with self.assertRaisesRegex(ValueError,"state_file"):
            NotificationQueue(hard,self.config)

    def test_database_failure_latches_fault_without_sending_or_inventing_success(self):
        queue=self.queue()
        with queue._lock:
            queue._db.execute("PRAGMA query_only=ON")
        with self.assertRaises(sqlite3.Error):
            queue.enqueue("unwritten","paused")
        self.assertTrue(queue.status()["storage_fault"])
        self.assertEqual(queue.status()["events"],[])
        with self.assertRaisesRegex(RuntimeError,"storage_fault"):
            queue.enqueue("later","paused")
        self.assertEqual(self.receipts,[])

    def test_replaced_open_database_faults_closed_instead_of_writing_orphaned_state(self):
        queue=self.queue()
        queue.enqueue("retained","paused")
        database=queue.state_dir/"notifications.sqlite3"
        moved=queue.state_dir/"original.sqlite3"
        database.rename(moved)
        database.write_bytes(moved.read_bytes())
        database.chmod(0o600)
        with self.assertRaisesRegex(RuntimeError,"storage_fault"):
            queue.enqueue("must-not-enter-orphan","paused")
        report=queue.status()
        self.assertTrue(report["storage_fault"])
        self.assertIsNone(report["counts"])
        self.assertFalse(report["worker_running"])
        self.assertEqual(self.receipts,[])

    def test_strict_slow_body_cannot_extend_deadline_with_small_chunks(self):
        self.http_status,self.body,self.trickle_delay=200,None,.03
        queue=self.queue(timeout_seconds=.08,strict_receipt=True)
        queue.enqueue("trickle-event","paused")
        started=time.monotonic()
        self.assertTrue(queue.dispatch_once())
        self.assertLess(time.monotonic()-started,.5)
        time.sleep(.15)
        self.assertEqual(queue.status()["counts"]["delivered"],0)
        self.assertFalse(queue.status()["transport_busy"])

    def test_slow_connection_resolution_has_one_bounded_transport_and_no_late_send(self):
        queue=self.queue(timeout_seconds=.04)
        queue.enqueue("connect-wait","paused")
        released=threading.Event()
        entered=threading.Event()
        def delayed_connect(connection):
            entered.set()
            released.wait(1)
        with mock.patch.object(notifications.http.client.HTTPConnection,"connect",new=delayed_connect):
            try:
                self.assertTrue(queue.dispatch_once())
                self.assertTrue(entered.is_set())
                self.assertTrue(queue.status()["transport_busy"])
                for _ in range(20):
                    self.assertFalse(queue.dispatch_once())
                self.assertEqual(queue.status()["events"][0]["attempts"],1)
            finally:
                released.set()
            deadline=time.monotonic()+1
            while queue.status()["transport_busy"] and time.monotonic()<deadline:
                time.sleep(.01)
        self.assertFalse(queue.status()["transport_busy"])
        self.assertEqual(self.receipts,[])

    def test_close_cancels_a_not_yet_sent_request_even_if_connection_returns_later(self):
        queue=self.queue(timeout_seconds=.04)
        queue.enqueue("closing-connect","paused")
        entered,released=threading.Event(),threading.Event()
        def delayed_connect(connection):
            entered.set()
            released.wait(1)
        with mock.patch.object(notifications.http.client.HTTPConnection,"connect",new=delayed_connect):
            try:
                queue.start()
                self.assertTrue(entered.wait(1))
                queue.close()
            finally:
                released.set()
            deadline=time.monotonic()+1
            while queue._transport_lock.locked() and time.monotonic()<deadline:
                time.sleep(.01)
        self.assertFalse(queue._transport_lock.locked())
        self.assertEqual(self.receipts,[])
        restarted=self.queue(timeout_seconds=.04)
        self.assertEqual(restarted.status()["counts"]["pending"],1)

    def test_close_cannot_retract_an_already_sent_request_and_keeps_unconfirmed_attempt(self):
        self.http_status,self.delay=200,.2
        queue=self.queue()
        queue.enqueue("already-sent","paused")
        queue.start()
        self.assertTrue(self.receiver_ready.wait(1))
        queue.close()
        self.assertEqual(len(self.receipts),1,"Receiver already obtained the request before cancellation")
        restarted=self.queue()
        self.assertEqual(restarted.status()["counts"]["pending"],1)
        self.assertEqual(restarted.status()["counts"]["delivered"],0)


if __name__ == "__main__":
    unittest.main()
