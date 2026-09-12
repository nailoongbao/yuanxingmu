"""Optional Hermes action integration using real installed contextvars/classes.

No model, host profile or external delivery is used. RPCs are recorded test
responses, so this validates tool identity/cancellation, not native acceptance.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import copy_context
from copy import deepcopy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest import mock


@unittest.skipUnless(sys.platform.startswith("linux") and importlib.util.find_spec("agent") is not None,
                     "requires the optional real Hermes installation")
class HermesAutomaticActionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory(prefix="yxm-hermes-auto-home-")
        cls.home_patch = mock.patch.dict(os.environ, {"HERMES_HOME": cls.home.name})
        cls.home_patch.start()
        from yuanxingmu import hermes_backend
        cls.api = hermes_backend

    @classmethod
    def tearDownClass(cls):
        cls.home_patch.stop()
        cls.home.cleanup()

    def setUp(self):
        self.binding = {"version": 1, "task_id": "fixed-host-task", "broker_socket": "/fixture/broker.sock",
                        "workspace": "/fixture/workspace", "bwrap": "/usr/bin/bwrap", "core_root": "/fixture/core",
                        "resource_ids": ["quote"], "destination_ids": [], "reviewed_mail": True,
                        "reviewed_actions": True, "automatic_actions": True, "defense_enabled": True}
        self.proposal = {"kind": "message", "target_id": "team", "payload": {"body": "合成公开摘要"}}
        self.declarations, self.middleware = self.register(self.binding)
        self.handler = self.declarations["yuanxingmu_request_action"]["handler"]

    def register(self, binding):
        with tempfile.TemporaryDirectory(prefix="yxm-hermes-auto-binding-") as directory:
            config = Path(directory) / "binding.json"
            config.write_text(json.dumps(binding), encoding="utf-8")
            ctx = mock.Mock()
            ctx.get_config.return_value = str(config)
            with mock.patch.object(self.api, "sandbox_available", return_value={"available": True}):
                self.api.register(ctx)
        tools = {call.kwargs["name"]: call.kwargs for call in ctx.register_tool.call_args_list}
        return tools, ctx.register_middleware.call_args.args[1]

    @contextmanager
    def native_context(self, *, call="native-call", session="native-session", scope_args=None, scope=False):
        from tools.approval_context import set_current_observability_context, reset_current_observability_context
        tokens = set_current_observability_context(session_id=session, tool_call_id=call)
        try:
            if scope:
                with self.api._invocation_scope(self.binding, "yuanxingmu_request_action", scope_args or self.proposal,
                        {"session_id": session, "tool_call_id": call}) as invocation:
                    yield invocation
            else:
                yield
        finally:
            reset_current_observability_context(tokens)

    def run_tool(self, proposal=None, *, name="yuanxingmu_request_action", call="native-call", session="native-session"):
        args = self.proposal if proposal is None else proposal
        handler = self.declarations[name]["handler"]
        with self.native_context(call=call, session=session):
            return json.loads(self.middleware(tool_name=name, args=args, next_call=lambda value: handler(value),
                                             session_id=session, tool_call_id=call))

    def test_new_tool_requires_exact_host_flag_and_declares_real_effects(self):
        new = self.declarations["yuanxingmu_request_action"]
        schema = new["schema"]["parameters"]
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual({"kind", "target_id", "payload"}, set(schema["properties"]))
        self.assertEqual(["message", "upload", "form"], schema["properties"]["kind"]["enum"])
        self.assertIn("立即执行", new["description"])
        self.assertIn("不会立即执行", self.declarations["yuanxingmu_prepare_action"]["description"])
        for flag in (False, None, 1, "true"):
            tools, _ = self.register({**self.binding, "automatic_actions": flag})
            self.assertNotIn("yuanxingmu_request_action", tools)
            self.assertIn("yuanxingmu_prepare_action", tools)
        with self.assertRaisesRegex(ValueError, "automatic_actions_require_action_targets"):
            self.register({**self.binding, "reviewed_actions": False})

    def test_three_kinds_route_one_exact_request_with_official_stable_identity(self):
        proposals = [self.proposal,
                     {"kind": "upload", "target_id": "documents", "payload": {"filename": "summary.txt", "content": "一行\n二行"}},
                     {"kind": "form", "target_id": "order", "payload": {"fields": {"project": "合成项目", "amount": "123"}}}]
        for index, proposal in enumerate(proposals):
            with self.subTest(kind=proposal["kind"]), mock.patch.object(self.api, "request",
                    return_value={"allowed": True, "status": "acknowledged"}) as rpc:
                result = self.run_tool(proposal, call="call-" + str(index))
                self.assertEqual("acknowledged", result["status"])
                rpc.assert_called_once()
                self.assertEqual(("request_action",), rpc.call_args.args)
                self.assertEqual(proposal, rpc.call_args.kwargs["proposal"])
                expected = hashlib.sha256(("native-session\0call-" + str(index)).encode()).hexdigest()
                self.assertEqual(expected, rpc.call_args.kwargs["request_key"])
                self.assertEqual(60, rpc.call_args.kwargs["timeout_seconds"])
        self.assertIsNone(self.api._INVOCATION.get())

    def test_retry_same_native_call_keeps_same_key_and_new_call_changes_it(self):
        with mock.patch.object(self.api, "request", return_value={"allowed": True, "status": "pending"}) as rpc:
            self.run_tool()
            self.run_tool()
            self.run_tool(call="new-call")
        keys = [call.kwargs["request_key"] for call in rpc.call_args_list]
        self.assertEqual(keys[0], keys[1])
        self.assertNotEqual(keys[1], keys[2])

    def test_prepare_keeps_inert_propose_operation(self):
        with mock.patch.object(self.api, "request", return_value={"allowed": True, "status": "pending"}) as rpc:
            result = self.run_tool(name="yuanxingmu_prepare_action")
        self.assertEqual("pending", result["status"])
        self.assertEqual(("propose_action",), rpc.call_args.args)
        self.assertNotIn("automatic", rpc.call_args.kwargs)

    def test_missing_official_context_or_middleware_cannot_send(self):
        with mock.patch.object(self.api, "request") as rpc:
            result = json.loads(self.handler(self.proposal, session_id="fake", tool_call_id="fake"))
            self.assertFalse(result["allowed"])
            with self.native_context():
                result = json.loads(self.handler(self.proposal))
                self.assertEqual("tool_correlation_unavailable", result["reason"])
            rpc.assert_not_called()

    def test_context_kwargs_cannot_replace_missing_official_session(self):
        with self.native_context(session=None), mock.patch.object(self.api, "request") as rpc:
            result = json.loads(self.handler(self.proposal, session_id="native-session"))
        self.assertFalse(result["allowed"])
        rpc.assert_not_called()

    def test_closed_copied_context_cannot_start_a_late_request(self):
        with self.native_context(scope=True) as invocation:
            copied = copy_context()
        self.assertTrue(invocation.closed)
        with mock.patch.object(self.api, "request") as rpc:
            result = json.loads(copied.run(self.handler, self.proposal))
        self.assertFalse(result["allowed"])
        rpc.assert_not_called()

    def test_owner_cancellation_reaches_worker_copied_context(self):
        from tools.interrupt import set_interrupt
        owner = threading.get_ident()
        try:
            with self.native_context(scope=True), mock.patch.object(self.api, "request") as rpc:
                copied = copy_context()
                set_interrupt(True, owner)
                with ThreadPoolExecutor(max_workers=1) as pool:
                    result = json.loads(pool.submit(copied.run, self.handler, self.proposal).result(timeout=5))
                self.assertFalse(result["allowed"])
                rpc.assert_not_called()
        finally:
            set_interrupt(False, owner)

    def test_cancelled_middleware_never_calls_request(self):
        with mock.patch.object(self.api, "is_interrupted", return_value=True), mock.patch.object(self.api, "request") as rpc:
            self.assertFalse(self.run_tool()["allowed"])
        rpc.assert_not_called()

    def test_candidate_changed_after_scope_entry_cannot_send(self):
        args = deepcopy(self.proposal)
        with self.native_context(scope=True, scope_args=args), mock.patch.object(self.api, "request") as rpc:
            args["payload"]["body"] = "changed after entry"
            result = json.loads(self.handler(args))
        self.assertEqual("tool_correlation_unavailable", result["reason"])
        rpc.assert_not_called()

    def test_mismatched_live_context_cannot_borrow_another_invocation(self):
        with self.native_context(scope=True), self.native_context(call="another-call"), mock.patch.object(self.api, "request") as rpc:
            result = json.loads(self.handler(self.proposal))
        self.assertFalse(result["allowed"])
        rpc.assert_not_called()

    def test_strict_schema_rejects_authority_fields_file_effects_and_malformed_payloads(self):
        bad = [
            {**self.proposal, "approved": True}, {**self.proposal, "request_key": "chosen"},
            {**self.proposal, "kind": []}, {**self.proposal, "kind": "delete", "payload": {}},
            {**self.proposal, "kind": "overwrite", "payload": {"content": "replace"}},
            {**self.proposal, "target_id": "https://fixture.invalid"},
            {**self.proposal, "payload": {"body": "x", "url": "https://fixture.invalid"}},
            {**self.proposal, "payload": {"body": 42}},
            {**self.proposal, "payload": {"body": "汉" * 30000}},
            {"kind": "upload", "target_id": "docs", "payload": {"filename": "../outside.txt", "content": "x"}},
            {"kind": "upload", "target_id": "docs", "payload": {"filename": "file.txt", "path": "/private/file"}},
            {"kind": "form", "target_id": "order", "payload": {"fields": {"constructor": "x"}}},
            {"kind": "form", "target_id": "order", "payload": {"fields": {"amount": 1}}},
            {"kind": "form", "target_id": "order", "payload": {"fields": {"note": "a" * 8193}}},
        ]
        for args in bad:
            with self.subTest(args=str(args)[:120]), mock.patch.object(self.api, "request") as rpc:
                self.assertFalse(self.run_tool(args)["allowed"])
                rpc.assert_not_called()

    def test_lost_response_is_unknown_and_rpc_is_never_retried(self):
        with mock.patch.object(self.api, "request", side_effect=OSError("synthetic lost response")) as rpc:
            result = self.run_tool()
        self.assertIsNone(result["allowed"])
        self.assertEqual("unknown", result["outcome"])
        rpc.assert_called_once()

    def test_pending_and_label_denial_results_are_not_changed_into_success(self):
        for reply in ({"allowed": True, "status": "pending", "reason": "automatic_attempt_budget_exhausted"},
                      {"allowed": False, "reason": "destination_cannot_receive_labels"},
                      {"allowed": True, "status": "unconfirmed"}):
            with self.subTest(reply=reply), mock.patch.object(self.api, "request", return_value=reply):
                self.assertEqual(reply, self.run_tool())

    def test_correlation_scope_remains_required_when_optional_defense_checks_are_disabled(self):
        self.declarations, self.middleware = self.register({**self.binding, "defense_enabled": False})
        with mock.patch.object(self.api, "request", return_value={"allowed": True, "status": "acknowledged"}) as rpc:
            self.assertEqual("acknowledged", self.run_tool()["status"])
        rpc.assert_called_once()


if __name__ == "__main__":
    unittest.main()
