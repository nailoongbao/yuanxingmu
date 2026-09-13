"""Real host storage and Unix IPC checks; no SDK or external model required."""
from contextlib import ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from yuanxingmu.actions import ActionTarget
from yuanxingmu.broker import Broker, Resource
from yuanxingmu.client import request
from yuanxingmu.sdk_model_store import ModelStore
from yuanxingmu.sdk_tool_store import SdkToolServer


def encoded(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "POSIX private storage and Unix sockets")
class SdkToolStoreTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="yxm-tool-store-")))
        self.note = self.root / "note.txt"
        self.note.write_text("ORIGINAL REGISTERED CONTENT", encoding="utf-8")
        self.broker = self.stack.enter_context(Broker(self.root / "broker", {"note": Resource(self.note)}, {},
            reviewed_mail=True, action_targets={"form": ActionTarget("form", "Synthetic form",
                url="http://127.0.0.1:9/form", form_fields=("note",))}))
        self.task = self.broker.create_task()
        self.models = ModelStore(self.root / "models", "session")
        self.server = self.stack.enter_context(SdkToolServer(self.broker, self.task, self.root / "tool.sock",
            self.root / "tools", "session", self.models))
        self.counter = 0

    def issue(self, operation, args=None):
        self.counter += 1
        raw = encoded({"model": "fixture", "messages": [{"role": "user", "content": str(self.counter)}]})
        ticket = self.models.begin(raw)
        reply = encoded({"choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": None, "tool_calls": [{"id": "provider-only", "type": "function",
                "function": {"name": "yuanxingmu_" + operation, "arguments": json.dumps(args or {})}}]}}]})
        saved = self.models.complete(ticket, reply, "application/json")
        self.models.finish(ticket)
        return json.loads(saved)["choices"][0]["message"]["tool_calls"][0]["id"]

    def invoke(self, nonce, call, *, lookup=False, **extra):
        return request("sdk_tool_result" if lookup else "sdk_tool", socket_path=str(self.server.path),
                       nonce=nonce, call=call, **extra)

    def inventory(self):
        return {p.name: p.read_bytes() for p in (self.root / "tools").iterdir()}

    def test_original_read_result_lookup_is_read_only_and_current_change_stops_replay(self):
        nonce = self.issue("read", {"resource": "note"})
        call = {"op": "read", "resource": "note"}
        first = self.invoke(nonce, call)
        self.assertTrue(first["allowed"])
        self.assertEqual(first["result"]["content"], "ORIGINAL REGISTERED CONTENT")
        before = self.inventory()
        with patch.object(self.broker, "dispatch", side_effect=AssertionError("lookup dispatched a tool")):
            self.assertEqual(self.invoke(nonce, call, lookup=True), {"allowed": True, "result": first["result"]})
        self.assertEqual(self.inventory(), before)
        self.note.write_text("RESOURCE HAS CHANGED", encoding="utf-8")
        replay = self.invoke(nonce, call)
        self.assertEqual(replay["result"], first["result"])
        self.assertFalse(replay["current"]["allowed"])
        self.assertEqual(replay["current"]["reason"], "resource_changed")

    def test_unknown_call_changed_arguments_and_worker_supplied_result_cannot_get_signed(self):
        nonce = self.issue("read", {"resource": "note"})
        valid = {"op": "read", "resource": "note"}
        before = self.inventory()
        candidates = [("provider-only", valid, {}), ("yxm_" + "0" * 48, valid, {}),
            (nonce, {"op": "describe"}, {}), (nonce, {**valid, "resource": "other"}, {}),
            (nonce, {**valid, "request_key": "forged"}, {}),
            (nonce, valid, {"result": {"allowed": True, "content": "FORGED"}}),
            (nonce, valid, {"task_id": self.task})]
        with patch.object(self.broker, "dispatch", side_effect=AssertionError("invalid call reached broker")):
            for identifier, call, fields in candidates:
                with self.subTest(call=call, fields=fields):
                    self.assertFalse(self.invoke(identifier, call, **fields)["allowed"])
            self.assertFalse(self.invoke(nonce, valid, lookup=True)["allowed"])
        self.assertEqual(self.inventory(), before)

    def test_changed_host_response_bytes_are_refused_before_effects(self):
        nonce = self.issue("read", {"resource": "note"})
        path = next((self.root / "models").glob("response-*.json"))
        path.write_bytes(path.read_bytes().replace(b"note", b"fake"))
        with patch.object(self.broker, "dispatch", side_effect=AssertionError("tampered model dispatched")):
            self.assertFalse(self.invoke(nonce, {"op": "read", "resource": "fake"})["allowed"])

    def test_definite_denial_is_not_redispatched_after_restart(self):
        nonce = self.issue("read", {"resource": "missing"})
        call = {"op": "read", "resource": "missing"}
        first = self.invoke(nonce, call)
        self.assertFalse(first["result"]["allowed"])
        self.server.close()
        reopened = self.stack.enter_context(SdkToolServer(self.broker, self.task, self.root / "again.sock",
            self.root / "tools", "session", self.models, resume=True))
        with patch.object(self.broker, "dispatch", side_effect=AssertionError("cached denial retried")):
            replay = request("sdk_tool", socket_path=str(reopened.path), nonce=nonce, call=call)
        self.assertEqual(replay, first)

    def test_lost_result_after_dispatch_blocks_same_and_new_effects(self):
        args = {"draft": {"recipient": "synthetic@example.invalid", "subject": "Test", "body": "Synthetic"}}
        nonce = self.issue("draft_email", args)
        other = self.issue("draft_email", args)
        call = {"op": "draft_email", **args}
        with patch.object(self.server.store, "complete", side_effect=OSError("synthetic disk fault")):
            self.assertFalse(self.invoke(nonce, call)["allowed"])
        self.assertEqual(len(self.broker.mail.list(self.task)["drafts"]), 1)
        self.server.close()
        reopened = self.stack.enter_context(SdkToolServer(self.broker, self.task, self.root / "again.sock",
            self.root / "tools", "session", self.models, resume=True))
        with patch.object(self.broker, "dispatch", side_effect=AssertionError("unknown effect retried")):
            for identifier in (nonce, other):
                self.assertFalse(request("sdk_tool", socket_path=str(reopened.path), nonce=identifier, call=call)["allowed"])
        self.assertEqual(len(self.broker.mail.list(self.task)["drafts"]), 1)

    def test_committed_draft_reply_replays_original_after_edit_without_new_submit(self):
        args = {"draft": {"recipient": "synthetic@example.invalid", "subject": "Test", "body": "Original"}}
        nonce = self.issue("draft_email", args)
        call = {"op": "draft_email", **args}
        original = self.invoke(nonce, call)["result"]
        draft = self.broker.mail.get(self.task, original["draft_id"])["draft"]
        self.broker.mail.cancel(self.task, draft["id"], draft["revision"], draft["digest"])
        with patch.object(self.broker.mail, "submit", side_effect=AssertionError("replayed effect was submitted")):
            replay = self.invoke(nonce, call)
        self.assertEqual(replay["result"], original)
        self.assertEqual(replay["current"]["status"], "cancelled")
        self.assertEqual(len(self.broker.mail.list(self.task)["drafts"]), 1)

    def test_form_normalization_host_key_and_missing_business_record_fail_closed(self):
        args = {"proposal": {"kind": "form", "target_id": "form", "payload": {
            "fields": [{"name": "note", "value": "PUBLIC"}]}}}
        nonce = self.issue("propose_action", args)
        call = {"op": "propose_action", **deepcopy(args)}
        call["proposal"]["payload"]["fields"] = {"note": "PUBLIC"}
        first = self.invoke(nonce, call)
        self.assertTrue(first["result"]["allowed"])
        binding = ["yuanxingmu-google-adk-reviewed-v1", "session", "propose_action", nonce]
        key = "adk_reviewed_v1_" + hashlib.sha256(encoded(binding)).hexdigest()
        prior = self.broker.actions.prior(self.task, key, call["proposal"])
        self.assertEqual(prior["id"], first["result"]["id"])
        with patch.object(self.broker.actions, "submit", side_effect=AssertionError("replay submitted")):
            self.assertEqual(self.invoke(nonce, call)["result"], first["result"])
            with patch.object(self.broker.actions, "prior", return_value=None):
                self.assertFalse(self.invoke(nonce, call)["allowed"])

    def test_resume_requires_original_private_store_and_same_session(self):
        for path, session in ((self.root / "lost", "session"), (self.root / "tools", "other")):
            with self.assertRaises(ValueError):
                SdkToolServer(self.broker, self.task, self.root / "unused.sock", path, session, self.models, resume=True)
        self.assertFalse((self.root / "lost").exists())
        (self.root / "tools" / "state.json").unlink()
        with self.assertRaises(ValueError):
            SdkToolServer(self.broker, self.task, self.root / "unused.sock", self.root / "tools", "session", self.models, resume=True)
        self.assertFalse((self.root / "tools" / "state.json").exists())

    def test_current_revocation_blocks_lookup_and_replay_of_original(self):
        nonce = self.issue("describe")
        call = {"op": "describe"}
        self.assertTrue(self.invoke(nonce, call)["allowed"])
        self.broker.revoke(self.task)
        for lookup in (False, True):
            result = self.invoke(nonce, call, lookup=lookup)
            self.assertFalse(result["allowed"])
            self.assertEqual(result["reason"], "task_revoked")
            self.assertNotIn("result", result)

    def test_raw_rpc_bypass_and_duplicate_keys_do_not_reach_business_operations(self):
        nonce = self.issue("describe")
        before = self.inventory()
        payloads = [b'{"op":"describe"}\n', b'{"op":"sdk_tool","op":"describe"}\n',
            encoded({"op": "sdk_tool", "nonce": nonce, "call": {"op": "send", "body": "x", "destination": "x"}}) + b"\n"]
        with patch.object(self.broker, "dispatch", side_effect=AssertionError("raw bypass reached broker")):
            for raw in payloads:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(5)
                    connection.connect(str(self.server.path))
                    connection.sendall(raw)
                    with connection.makefile("rb") as stream:
                        self.assertFalse(json.loads(stream.readline())["allowed"])
        self.assertEqual(self.inventory(), before)


if __name__ == "__main__":
    unittest.main()
