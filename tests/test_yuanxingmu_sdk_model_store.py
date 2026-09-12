"""Host model replay, crash ambiguity and private filesystem boundary checks."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from yuanxingmu import sdk_model_store as storage


def encoded(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def request(text="synthetic task"):
    return encoded({"model": "synthetic-model", "messages": [{"role": "user", "content": text}], "stream": False})


def response(*, tools=0, text="synthetic answer"):
    message = {"role": "assistant", "content": text}
    if tools:
        message["tool_calls"] = [
            {"id": f"untrusted-provider-{index}", "type": "function",
             "function": {"name": "yuanxingmu_propose_action", "arguments": '{"target":"synthetic","body":"测试"}'}}
            for index in range(tools)
        ]
    return encoded({"id": "synthetic-response", "object": "chat.completion", "model": "synthetic-model", "created": 1,
                    "choices": [{"index": 0, "finish_reason": "tool_calls" if tools else "stop", "message": message}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})


class ModelSchemaTests(unittest.TestCase):
    def assert_blocked(self, operation, *args, reason=None, **kwargs):
        with self.assertRaises(storage.ModelStoreError) as caught:
            operation(*args, **kwargs)
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)

    def test_standard_smolagents_text_messages_and_function_schema_are_supported(self):
        value = json.loads(request())
        value.update(tools=[{"type": "function", "function": {"name": "final_answer", "description": "Return text.",
                           "parameters": {"type": "object", "properties": {"answer": {"type": "string"}},
                                          "required": ["answer"]}}}],
                     tool_choice="required", stop=["Observation:", "Calling tools:"], max_tokens=1024)
        value["messages"][0]["content"] = [{"type": "text", "text": "task"}]
        self.assertEqual(storage._request(encoded(value)), value)
        self.assertEqual(storage._response(response(tools=2), "application/json; charset=utf-8")["choices"][0]["finish_reason"], "tool_calls")

    def test_duplicate_keys_nonfinite_unicode_depth_and_size_are_rejected(self):
        examples = [b'{"model":"x","model":"y","messages":[]}', b'{"value":NaN}', b'{"value":1e999}',
                    b'{"value":"\\ud800"}', b'\xff', b'[' * 40 + b'0' + b']' * 40]
        for raw in examples:
            with self.subTest(raw=raw[:40]):
                self.assert_blocked(storage._json, raw)
        with mock.patch.object(storage, "MAX_BODY_BYTES", 32):
            self.assert_blocked(storage._request, request(), reason="sdk_model_body_limit")

    def test_stream_multi_choice_credentials_and_unknown_request_fields_fail_closed(self):
        for updates in ({"stream": True}, {"stream": 0}, {"n": 2}, {"n": True}, {"api_key": "SYNTHETIC-KEY"},
                        {"base_url": "http://example.invalid"}, {"reasoning_effort": []}, {"tools": None}):
            with self.subTest(updates=updates):
                value = json.loads(request())
                value.update(updates)
                self.assert_blocked(storage._request, encoded(value))
        value = json.loads(request())
        value["messages"][0]["role"] = []
        self.assert_blocked(storage._request, encoded(value))

    def test_unknown_or_incomplete_responses_do_not_become_replayable(self):
        original = json.loads(response(tools=1))
        candidates = []
        for key, value in (("audio", "hidden"), ("provider_metadata", {"secret": "hidden"})):
            candidate = copy.deepcopy(original)
            candidate[key] = value
            candidates.append(candidate)
        candidate = copy.deepcopy(original)
        candidate["choices"].append(copy.deepcopy(candidate["choices"][0]))
        candidates.append(candidate)
        for reason in ("length", "content_filter", "stop", None, []):
            candidate = copy.deepcopy(original)
            candidate["choices"][0]["finish_reason"] = reason
            candidates.append(candidate)
        candidate = copy.deepcopy(original)
        candidate["choices"][0]["message"]["hidden"] = "not reviewed"
        candidates.append(candidate)
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                self.assert_blocked(storage._response, encoded(candidate), "application/json")
        self.assert_blocked(storage._response, response(), "text/event-stream")

    def test_duplicate_provider_ids_and_nonobject_tool_arguments_are_rejected(self):
        value = json.loads(response(tools=2))
        calls = value["choices"][0]["message"]["tool_calls"]
        calls[1]["id"] = calls[0]["id"]
        self.assert_blocked(storage._response, encoded(value), "application/json", reason="sdk_model_duplicate_tool_id")
        for arguments in ('[]', '{"x":1,"x":2}', '{"x":NaN}'):
            candidate = json.loads(response(tools=1))
            candidate["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = arguments
            self.assert_blocked(storage._response, encoded(candidate), "application/json")


@unittest.skipUnless(os.name == "posix" and storage.fcntl is not None and hasattr(os, "O_NOFOLLOW"),
                     "requires POSIX secure directory-relative storage")
class ModelStoreTests(unittest.TestCase):
    assert_blocked = ModelSchemaTests.assert_blocked

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="yxm-model-store-")
        self.addCleanup(self.temporary.cleanup)
        self.parent = Path(self.temporary.name).resolve()
        self.path = self.parent / "private-model"
        self.store = storage.ModelStore(self.path, "synthetic-session")

    def state(self):
        return json.loads((self.path / "state.json").read_bytes())

    def committed(self, raw=None, *, tools=1):
        raw = request() if raw is None else raw
        ticket = self.store.begin(raw)
        result = self.store.complete(ticket, response(tools=tools), "application/json")
        self.store.finish(ticket)
        return result

    def test_begin_durably_records_pending_without_storing_request_text(self):
        marker = "SYNTHETIC-REQUEST-PRIVATE-MARKER"
        raw = request(marker)
        ticket = self.store.begin(raw)
        state = self.state()
        self.assertIsNone(ticket.replay)
        self.assertEqual(ticket.content_type, "application/json")
        self.assertEqual(state["session_id"], "synthetic-session")
        self.assertEqual(state["records"][0]["state"], "pending")
        self.assertEqual(state["records"][0]["request_sha256"], hashlib.sha256(raw).hexdigest())
        for path in self.path.iterdir():
            self.assertNotIn(marker.encode(), path.read_bytes())
        self.store.finish(ticket)

    def test_complete_rewrites_every_tool_id_and_restart_replays_exact_bytes(self):
        result = self.committed(tools=2)
        parsed = json.loads(result)
        calls = parsed["choices"][0]["message"]["tool_calls"]
        self.assertEqual(len({call["id"] for call in calls}), 2)
        for call in calls:
            self.assertRegex(call["id"], r"^yxm_[0-9a-f]{48}$")
            self.assertEqual(call["function"]["arguments"], '{"target":"synthetic","body":"测试"}')
        reopened = storage.ModelStore(self.path, "synthetic-session")
        ticket = reopened.begin(request())
        self.assertEqual(ticket.replay, result)
        reopened.finish(ticket)
        self.assertEqual(len(self.state()["records"]), 1)

    def test_json_whitespace_is_a_distinct_request_and_gets_fresh_nonce(self):
        first = self.committed()
        second = self.committed(request() + b"\n")
        get_id = lambda raw: json.loads(raw)["choices"][0]["message"]["tool_calls"][0]["id"]
        self.assertNotEqual(get_id(first), get_id(second))
        self.assertEqual(len(self.state()["records"]), 2)

    def test_finish_of_failed_request_preserves_unknown_and_does_not_refund_capacity(self):
        ticket = self.store.begin(request())
        self.store.finish(ticket)
        self.assertEqual(self.state()["records"][0]["state"], "unknown")
        reopened = storage.ModelStore(self.path, "synthetic-session")
        self.assert_blocked(reopened.begin, request(), reason="sdk_model_outcome_unknown")
        second = reopened.begin(request("different work"))
        reopened.finish(second)
        self.assertEqual(len(self.state()["records"]), 2)

    def test_crashed_pending_cannot_retry_or_make_a_second_flight_in_another_process(self):
        other = self.parent / "interrupted-session"
        code = ("import sys; from yuanxingmu.sdk_model_store import ModelStore; "
                "s=ModelStore(sys.argv[1], 'interrupted'); s.begin(bytes.fromhex(sys.argv[2]))")
        completed = subprocess.run([sys.executable, "-B", "-c", code, str(other), request().hex()],
                                   capture_output=True, text=True, timeout=15, cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(completed.returncode, 0, completed.stderr)
        reopened = storage.ModelStore(other, "interrupted")
        self.assert_blocked(reopened.begin, request(), reason="sdk_model_outcome_unknown")
        self.assert_blocked(reopened.begin, request("new work"), reason="sdk_model_busy")

    def test_singleflight_does_not_hold_file_lock_across_upstream_wait(self):
        ticket = self.store.begin(request())
        second = storage.ModelStore(self.path, "synthetic-session")
        descriptor = os.open(self.path / "store.lock", os.O_RDWR | os.O_NOFOLLOW)
        try:
            storage.fcntl.flock(descriptor, storage.fcntl.LOCK_EX | storage.fcntl.LOCK_NB)
            storage.fcntl.flock(descriptor, storage.fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
        self.assert_blocked(self.store.begin, request("parallel"), reason="sdk_model_busy")
        self.assert_blocked(second.begin, request("parallel"), reason="sdk_model_busy")
        self.store.finish(ticket)

    def test_stale_foreign_and_replay_tickets_cannot_finalize_or_release_new_flight(self):
        first = self.store.begin(request())
        self.store.complete(first, response(), "application/json")
        self.store.finish(first)
        second = self.store.begin(request("second"))
        self.store.finish(first)
        self.assert_blocked(self.store.begin, request("third"), reason="sdk_model_busy")
        self.assert_blocked(self.store.complete, first, response(), "application/json", reason="sdk_model_invalid_ticket")
        foreign = storage.ModelStore(self.parent / "other", "other")
        self.assert_blocked(foreign.finish, second, reason="sdk_model_invalid_ticket")
        self.store.finish(second)
        replay = self.store.begin(request())
        self.assert_blocked(self.store.complete, replay, response(), "application/json", reason="sdk_model_invalid_ticket")
        self.store.finish(replay)

    def test_invalid_reply_becomes_unknown_when_finished(self):
        ticket = self.store.begin(request())
        self.assert_blocked(self.store.complete, ticket, b'{"choices":[]}', "application/json")
        self.store.finish(ticket)
        self.assert_blocked(self.store.begin, request(), reason="sdk_model_outcome_unknown")

    def test_session_mismatch_missing_state_and_existing_empty_directory_fail_closed(self):
        self.committed()
        self.assert_blocked(storage.ModelStore, self.path, "different-session", reason="sdk_model_invalid_state")
        (self.path / "state.json").unlink()
        self.assert_blocked(storage.ModelStore, self.path, "synthetic-session", reason="sdk_model_storage_unavailable")
        empty = self.parent / "already-exists"
        empty.mkdir(mode=0o700)
        self.assert_blocked(storage.ModelStore, empty, "synthetic-session", reason="sdk_model_storage_unavailable")

    def test_private_modes_and_bounded_state_loading(self):
        self.committed()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)
        for path in self.path.iterdir():
            info = path.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 1)
            self.assertEqual(info.st_uid, os.geteuid())
        with (self.path / "state.json").open("ab") as handle:
            handle.write(b" " * storage.MAX_STATE_BYTES)
        with mock.patch.object(storage.os, "read", side_effect=AssertionError("oversize state was read")):
            self.assert_blocked(storage.ModelStore, self.path, "synthetic-session", reason="sdk_model_file_permissions")

    def test_symlink_in_any_parent_or_final_directory_is_rejected(self):
        self.committed()
        alias = self.parent / "alias"
        alias.symlink_to(self.path, target_is_directory=True)
        self.assert_blocked(storage.ModelStore, alias, "synthetic-session", reason="sdk_model_storage_unavailable")
        parent_alias = self.parent / "parent-alias"
        parent_alias.symlink_to(self.parent, target_is_directory=True)
        self.assert_blocked(storage.ModelStore, parent_alias / "private-model", "synthetic-session", reason="sdk_model_storage_unavailable")

    def test_response_symlink_or_hardlink_is_not_replayed(self):
        result = self.committed()
        response_path = next(self.path.glob("response-*.json"))
        outside = self.parent / "outside-response"
        outside.write_bytes(result)
        outside.chmod(0o600)
        response_path.unlink()
        response_path.symlink_to(outside)
        self.assert_blocked(storage.ModelStore, self.path, "synthetic-session", reason="sdk_model_storage_unavailable")
        response_path.unlink()
        os.link(outside, response_path)
        self.assert_blocked(storage.ModelStore, self.path, "synthetic-session", reason="sdk_model_file_permissions")

    def test_changed_response_hash_cannot_replay(self):
        self.committed(tools=0)
        path = next(self.path.glob("response-*.json"))
        old = path.read_bytes()
        new = old.replace(b"synthetic answer", b"changedxx answer")
        self.assertEqual(len(old), len(new))
        path.write_bytes(new)
        self.assert_blocked(self.store.begin, request(), reason="sdk_model_response_changed")

    def test_group_readable_file_and_directory_permissions_are_rejected(self):
        (self.path / "state.json").chmod(0o640)
        self.assert_blocked(self.store.begin, request(), reason="sdk_model_file_permissions")
        (self.path / "state.json").chmod(0o600)
        self.path.chmod(0o750)
        self.assert_blocked(self.store.begin, request(), reason="sdk_model_directory_permissions")

    def test_replaced_directory_and_lock_cannot_change_session_identity(self):
        original = self.parent / "original"
        self.path.rename(original)
        storage.ModelStore(self.path, "synthetic-session")
        self.assert_blocked(self.store.begin, request(), reason="sdk_model_directory_changed")
        current = storage.ModelStore(self.path, "synthetic-session")
        (self.path / "store.lock").rename(self.path / "old-lock")
        (self.path / "store.lock").write_bytes(b"")
        (self.path / "store.lock").chmod(0o600)
        self.assert_blocked(current.begin, request(), reason="sdk_model_lock_changed")

    def test_foreign_owner_fifo_and_extra_files_fail_before_content_read(self):
        info = os.stat_result((stat.S_IFREG | 0o600, 1, 1, 1, os.geteuid() + 1, os.getegid(), 0, 0, 0, 0))
        with mock.patch.object(storage.os, "fstat", return_value=info):
            self.assert_blocked(self.store._file_stat, -1, limit=0, reason="sdk_model_file_permissions")
        (self.path / "state.json").unlink()
        os.mkfifo(self.path / "state.json", 0o600)
        self.assert_blocked(storage.ModelStore, self.path, "synthetic-session", reason="sdk_model_file_permissions")

    def test_unrecognized_or_interrupted_temporary_files_stop_new_work(self):
        extra = self.path / ".tmp-interrupted"
        extra.write_bytes(b"unfinished")
        extra.chmod(0o600)
        self.assert_blocked(self.store.begin, request(), reason="sdk_model_invalid_inventory")

    def test_request_count_and_total_response_budget_are_durable(self):
        with mock.patch.object(storage, "MAX_REQUESTS", 2):
            self.committed(request("one"), tools=0)
            failed = self.store.begin(request("two"))
            self.store.finish(failed)
            reopened = storage.ModelStore(self.path, "synthetic-session")
            self.assert_blocked(reopened.begin, request("three"), reason="sdk_model_capacity_exhausted")
            replay = reopened.begin(request("one"))
            self.assertIsNotNone(replay.replay)
            reopened.finish(replay)
        size = sum(path.stat().st_size for path in self.path.glob("response-*.json"))
        with mock.patch.object(storage, "MAX_CACHE_BYTES", size + storage.MAX_BODY_BYTES - 1):
            self.assert_blocked(self.store.begin, request("four"), reason="sdk_model_capacity_exhausted")

    def test_pending_is_fsynced_before_begin_and_response_before_completion_record(self):
        events = []
        real_fsync, real_replace = storage.os.fsync, storage.os.replace

        def fsync(descriptor):
            events.append(("fsync", stat.S_ISDIR(os.fstat(descriptor).st_mode)))
            return real_fsync(descriptor)

        def replace(source, target, **kwargs):
            events.append(("replace", target))
            return real_replace(source, target, **kwargs)

        with mock.patch.object(storage.os, "fsync", side_effect=fsync), mock.patch.object(storage.os, "replace", side_effect=replace):
            ticket = self.store.begin(request())
            self.assertEqual(events[-1], ("fsync", True))
            events.clear()
            result = self.store.complete(ticket, response(), "application/json")
            response_replace = next(i for i, item in enumerate(events) if item[0] == "replace" and item[1].startswith("response-"))
            state_replace = events.index(("replace", "state.json"))
            self.assertLess(response_replace, state_replace)
            self.assertEqual(events[response_replace - 1], ("fsync", False))
            self.assertEqual(events[response_replace + 1], ("fsync", True))
            self.assertEqual(events[-1], ("fsync", True))
            self.assertEqual(next(self.path.glob("response-*.json")).read_bytes(), result)
        self.store.finish(ticket)

    def test_write_failure_does_not_return_reply_or_retry_the_pending_request(self):
        ticket = self.store.begin(request())
        original = self.store._write_state

        def fail_complete(directory, state, **kwargs):
            if state["records"][-1]["state"] == "complete":
                raise OSError("synthetic_disk_failure")
            return original(directory, state, **kwargs)

        with mock.patch.object(self.store, "_write_state", side_effect=fail_complete):
            self.assert_blocked(self.store.complete, ticket, response(tools=1), "application/json", reason="sdk_model_storage_unavailable")
        self.assert_blocked(self.store.finish, ticket, reason="sdk_model_storage_unavailable")
        self.assertIsNone(self.store._inflight)
        reopened = storage.ModelStore(self.path, "synthetic-session")
        self.assert_blocked(reopened.begin, request(), reason="sdk_model_outcome_unknown")
        self.assert_blocked(reopened.begin, request("new work"), reason="sdk_model_busy")

    def test_finish_that_cannot_acquire_method_lock_does_not_release_inflight(self):
        ticket = self.store.begin(request())
        self.store._mutex.acquire()
        try:
            self.assert_blocked(self.store.finish, ticket, reason="sdk_model_busy")
            self.assertIs(self.store._inflight, ticket)
        finally:
            self.store._mutex.release()
        self.store.finish(ticket)


if __name__ == "__main__":
    unittest.main()
