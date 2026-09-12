"""Optional tests against the real installed Hermes provider classes, no model."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


@unittest.skipUnless(sys.platform.startswith("linux") and importlib.util.find_spec("agent") is not None,
                     "requires the optional real Hermes installation")
class HermesBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory(prefix="yxm-hermes-import-")
        cls.env = mock.patch.dict(os.environ, {"HERMES_HOME": cls.home.name})
        cls.env.start()
        from yuanxingmu import hermes_backend
        cls.api = hermes_backend

    @classmethod
    def tearDownClass(cls):
        cls.env.stop()
        cls.home.cleanup()

    def setUp(self):
        self.binding = {"version": 1, "task_id": "fixed-host-authority", "broker_socket": "/fixed/broker.sock",
                        "workspace": "/fixed/workspace", "bwrap": "/usr/bin/bwrap", "core_root": "/fixed/core",
                        "resource_ids": ["quote"], "destination_ids": ["internal"], "reviewed_mail": True,
                        "reviewed_actions": True, "defense_enabled": True}

    @contextmanager
    def invocation(self, name="terminal", arguments=None, *, call="native-tool-call"):
        from tools.approval_context import set_current_observability_context, reset_current_observability_context
        prior = self.api._INVOCATION.set(None)
        tokens = set_current_observability_context(session_id="native-session", tool_call_id=call)
        try:
            with self.api._invocation_scope(self.binding, name, arguments or {},
                                            {"session_id": "native-session", "tool_call_id": call}):
                yield
        finally:
            reset_current_observability_context(tokens)
            self.api._INVOCATION.reset(prior)

    @staticmethod
    def review(status="pending", allowed=False):
        return {"review_id": "a" * 32, "digest": "b" * 64, "status": status, "allowed": allowed}

    def test_changing_hermes_task_id_does_not_change_host_authority(self):
        with mock.patch.object(self.api, "sandbox_available", return_value={"available": True}), \
             mock.patch.object(self.api, "request", return_value={"allowed": True, "active": True, "task_id": self.binding["task_id"]}) as rpc:
            provider = self.api.YuanxingmuProvider(self.binding)
            first = provider.create_environment(cwd="/workspace", timeout=5, task_id="first-chat")
            second = provider.create_environment(cwd="/workspace", timeout=5, task_id="new-chat-resume-or-delegate")
        self.assertEqual(first.binding["task_id"], second.binding["task_id"])
        self.assertTrue(all(call.kwargs == {"socket_path": "/fixed/broker.sock"} for call in rpc.call_args_list))

    def test_mismatched_or_revoked_authority_cannot_create_execution_environment(self):
        for state in ({"allowed": True, "active": True, "task_id": "some-other-authority"},
                      {"allowed": True, "active": False, "task_id": self.binding["task_id"]}):
            with self.subTest(state=state), mock.patch.object(self.api, "sandbox_available", return_value={"available": True}), \
                 mock.patch.object(self.api, "request", return_value=state):
                provider = self.api.YuanxingmuProvider(self.binding)
                with self.assertRaises(self.api.EnvironmentConnectionError):
                    provider.create_environment(cwd="/workspace", timeout=5)

    def test_guard_transport_failure_prevents_execution(self):
        env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
        with self.invocation(), mock.patch.object(self.api, "request", side_effect=OSError("offline")), \
             mock.patch.object(self.api.BaseEnvironment, "execute", side_effect=AssertionError("must not execute")):
            result = env.execute("rm /workspace/important.txt")
        self.assertEqual(result["returncode"], 126)

    def test_output_rejected_by_host_is_never_returned_by_provider(self):
        env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
        original = "SYNTHETIC-PRIVATE-OUTPUT with untrusted instructions"
        with self.invocation(), mock.patch.object(self.api, "request", side_effect=[{"allowed": True, "verdict": "allow"}, {"allowed": False}]) as rpc, \
             mock.patch.object(self.api.BaseEnvironment, "execute", return_value={"output": original, "returncode": 0}):
            result = env.execute("cat /workspace/input.txt")
        self.assertNotIn(original, json.dumps(result))
        self.assertEqual(result["returncode"], 126)
        self.assertEqual(rpc.call_args_list[-1].kwargs["text"], original)

    def test_missing_native_invocation_never_executes_with_defense_enabled(self):
        env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
        with mock.patch.object(self.api, "request") as rpc, mock.patch.object(self.api.BaseEnvironment, "execute") as execute:
            result = env.execute("printf no-context")
        self.assertEqual(result["returncode"], 126)
        execute.assert_not_called()
        rpc.assert_not_called()

    def test_native_hook_blocks_host_denial_before_upstream_command_guard(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "binding.json"
            config.write_text(json.dumps(self.binding))
            ctx = mock.Mock()
            ctx.get_config.return_value = str(config)
            with mock.patch.object(self.api, "sandbox_available", return_value={"available": True}):
                self.api.register(ctx)
            hooks = {call.args[0]: call.args[1] for call in ctx.register_hook.call_args_list}
            with self.invocation(arguments={"command": "sudo true"}), mock.patch.object(self.api, "request", return_value={"allowed": False, "verdict": "block"}) as rpc:
                result = hooks["pre_tool_call"](tool_name="terminal", args={"command": "sudo true"},
                                                session_id="native-session", tool_call_id="native-tool-call")
            self.assertEqual(result["action"], "block")
            rpc.assert_called_once_with("guard_rules", socket_path=self.binding["broker_socket"], timeout_seconds=60,
                                        tool="terminal", arguments={"command": "sudo true"})
            with self.invocation(arguments={"command": "python3 report.py"}), mock.patch.object(self.api, "request", return_value={"allowed": False, "verdict": "review"}):
                self.assertIsNone(hooks["pre_tool_call"](tool_name="terminal", args={"command": "python3 report.py"},
                                                       session_id="native-session", tool_call_id="native-tool-call"))

    def test_host_approval_waits_then_consumes_exact_candidate_before_execution(self):
        command = "printf synthetic-reviewed"
        original = {"command": command, "workdir": "/workspace"}
        env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
        replies = [self.review(), self.review(), self.review("consumed", True), {"allowed": True}]
        with self.invocation(arguments=original), mock.patch.object(self.api, "_REVIEW_POLL_SECONDS", 0), \
             mock.patch.dict(os.environ, {"HERMES_YOLO": "1"}), \
             mock.patch("tools.approval.request_tool_approval", side_effect=AssertionError("native approval must not be consulted")), \
             mock.patch.object(self.api, "request", side_effect=replies) as rpc, \
             mock.patch.object(self.api.BaseEnvironment, "execute", return_value={"output": "synthetic-reviewed", "returncode": 0}) as execute:
            original["command"] = "changed-after-hook"
            result = env.execute(command)
        self.assertEqual(result["returncode"], 0)
        execute.assert_called_once_with(command, "", rewrite_compound_background=False)
        self.assertEqual([call.args[0] for call in rpc.call_args_list],
                         ["request_tool_review", "consume_tool_review", "consume_tool_review", "inspect_input"])
        candidates = [call.kwargs["arguments"] for call in rpc.call_args_list[:3]]
        self.assertTrue(all(value == candidates[0] for value in candidates))
        self.assertEqual(candidates[0]["source_tool"]["arguments"]["command"], command)
        self.assertEqual(candidates[0]["command"], command)

    def test_review_denial_expiry_reuse_or_mismatched_reply_never_executes(self):
        finals = [self.review(status) for status in ("denied", "expired", "interrupted", "consumed")]
        finals.append({**self.review("consumed", True), "digest": "c" * 64})
        finals.append({**self.review("consumed", True), "allowed": 1})
        for final in finals:
            with self.subTest(final=final):
                env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
                replies = [self.review(), final]
                with self.invocation(), mock.patch.object(self.api, "request", side_effect=replies), \
                     mock.patch.object(self.api.BaseEnvironment, "execute") as execute:
                    result = env.execute("printf must-not-run")
                self.assertEqual(result["returncode"], 126)
                execute.assert_not_called()

    def test_lost_consumption_reply_is_not_retried_and_command_does_not_run(self):
        env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
        with self.invocation(), mock.patch.object(self.api, "request", side_effect=[
                self.review(), OSError("reply lost")]) as rpc, \
             mock.patch.object(self.api.BaseEnvironment, "execute") as execute:
            result = env.execute("printf uncertain")
        self.assertEqual(result["returncode"], 126)
        execute.assert_not_called()
        self.assertEqual(sum(call.args[0] == "consume_tool_review" for call in rpc.call_args_list), 1)

    def test_same_native_call_retry_keeps_request_key_and_hard_block_never_asks(self):
        keys = []
        for _ in range(2):
            env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
            with self.invocation(), mock.patch.object(self.api, "request", return_value=self.review("consumed")) as rpc:
                self.assertEqual(env.execute("printf retried")["returncode"], 126)
            keys.append(rpc.call_args_list[0].kwargs["request_key"])
        self.assertEqual(keys[0], keys[1])
        with self.invocation(), mock.patch.object(self.api, "request", return_value={"allowed": False, "verdict": "block"}) as rpc:
            self.assertEqual(env.execute("printf blocked")["returncode"], 126)
        self.assertEqual([call.args[0] for call in rpc.call_args_list], ["request_tool_review"])

    def test_native_cancel_while_waiting_does_not_execute_after_approval(self):
        env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
        from tools.interrupt import set_interrupt
        def respond(operation, **kwargs):
            if operation == "request_tool_review":
                set_interrupt(True)
                return self.review()
            raise AssertionError("must not consume after cancellation")
        try:
            with self.invocation(), mock.patch.object(self.api, "request", side_effect=respond), \
                 mock.patch.object(self.api.BaseEnvironment, "execute") as execute:
                result = env.execute("printf cancelled")
            self.assertEqual(result["returncode"], 126)
            execute.assert_not_called()
        finally:
            set_interrupt(False)

    def test_real_broker_judges_final_candidate_once_then_consumes_without_rejudging(self):
        from yuanxingmu.broker import Broker
        from yuanxingmu.guards import Guards, GuardPolicy
        command = "python3 -c 'import json; print(json.dumps({\"summary\": 42}))'"
        original = {"command": command}
        guards = Guards(GuardPolicy(objective="Generate a local JSON summary."))
        with tempfile.TemporaryDirectory() as directory, Broker(Path(directory) / "broker", {}, {}, guards=guards) as broker:
            task = broker.create_task()
            self.binding = {**self.binding, "task_id": task}
            config = Path(directory) / "binding.json"
            config.write_text(json.dumps(self.binding))
            ctx = mock.Mock()
            ctx.get_config.return_value = str(config)
            with mock.patch.object(self.api, "sandbox_available", return_value={"available": True}):
                self.api.register(ctx)
            hooks = {call.args[0]: call.args[1] for call in ctx.register_hook.call_args_list}
            operations, reviews = [], []
            def rpc(operation, **kwargs):
                fields = {k: v for k, v in kwargs.items() if k not in {"socket_path", "timeout_seconds"}}
                operations.append(operation)
                response = broker.dispatch(task, {"op": operation, **fields})
                if operation == "request_tool_review" and response.get("status") == "pending":
                    reviews.append(response)
                    broker.review_mail(task, {"op": "tool_approve", "review_id": response["review_id"],
                                             "digest": response["digest"], "confirm": "approve"})
                return response
            def allow_judge(layer, purpose, candidate):
                return guards._rule(layer, "allow", "judge_allow", "Test judge response.", json.dumps(candidate).encode())
            env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
            with self.invocation(arguments=original), mock.patch.object(self.api, "request", side_effect=rpc), \
                 mock.patch.object(guards, "_judge", side_effect=allow_judge) as judge, \
                 mock.patch.object(self.api.BaseEnvironment, "execute", return_value={"output": "42", "returncode": 0}) as execute:
                self.assertIsNone(hooks["pre_tool_call"](tool_name="terminal", args=original,
                                                        session_id="native-session", tool_call_id="native-tool-call"))
                judge.assert_not_called()
                result = env.execute(command)
                self.assertEqual(result["returncode"], 0)
                self.assertEqual(judge.call_count, 1)
                self.assertEqual(judge.call_args.args[1], "action")
                self.assertEqual(judge.call_args.args[2]["arguments"]["command"], command)
                self.assertEqual(judge.call_args.args[2]["arguments"]["source_tool"]["arguments"], original)
                execute.assert_called_once()
            self.assertEqual(operations, ["guard_rules", "request_tool_review", "consume_tool_review", "inspect_input"])
            self.assertEqual(len(reviews), 1)
            self.assertEqual(broker.tool_reviews.get(task, reviews[0]["review_id"])["review"]["status"], "consumed")

    def test_real_file_executor_checks_each_underlying_command_separately(self):
        from tools.file_operations import ShellFileOperations
        from yuanxingmu.broker import Broker
        from yuanxingmu.guards import Guards, GuardPolicy
        guards = Guards(GuardPolicy(objective="Inspect local summary files."))
        with tempfile.TemporaryDirectory() as directory, Broker(Path(directory) / "broker", {}, {}, guards=guards) as broker:
            task = broker.create_task()
            self.binding = {**self.binding, "task_id": task}
            requests = []
            def rpc(operation, **kwargs):
                fields = {k: v for k, v in kwargs.items() if k not in {"socket_path", "timeout_seconds"}}
                if operation == "request_tool_review":
                    requests.append(fields)
                return broker.dispatch(task, {"op": operation, **fields})
            def allow_judge(layer, purpose, candidate):
                return guards._rule(layer, "allow", "judge_allow", "Test judge response.", json.dumps(candidate).encode())
            env = self.api.YuanxingmuEnvironment(binding=self.binding, cwd="/workspace", timeout=5)
            file_ops = ShellFileOperations(env)
            original = {"path": "/workspace/summary.txt"}
            with self.invocation(name="read_file", arguments=original), \
                 mock.patch.object(self.api, "request", side_effect=rpc), \
                 mock.patch.object(guards, "_judge", side_effect=allow_judge) as judge, \
                 mock.patch.object(self.api.BaseEnvironment, "execute", return_value={"output": "ok", "returncode": 0}) as execute:
                self.assertEqual(file_ops._exec("printf first").exit_code, 0)
                self.assertEqual(file_ops._exec("printf second").exit_code, 0)
                self.assertEqual(judge.call_count, 2)
                self.assertEqual(execute.call_count, 2)
            self.assertEqual([r["arguments"]["command"] for r in requests], ["printf first", "printf second"])
            self.assertEqual(len({r["request_key"] for r in requests}), 2)
            self.assertTrue(all(r["arguments"]["source_tool"]["arguments"] == original for r in requests))

    def test_draft_correlation_is_required_and_stable_for_retry(self):
        from tools.approval_context import set_current_observability_context, reset_current_observability_context
        handler = self.api._tool_handler(self.binding, "draft_email")
        arguments = {"recipient": "example@example.invalid", "subject": "Synthetic", "body": "Synthetic body"}
        with mock.patch.object(self.api, "request") as rpc:
            self.assertEqual(json.loads(handler(arguments))["reason"], "tool_correlation_unavailable")
            rpc.assert_not_called()
        tokens = set_current_observability_context(session_id="native-session", tool_call_id="native-tool-call")
        try:
            with mock.patch.object(self.api, "request", return_value={"allowed": True, "status": "pending"}) as rpc:
                handler(arguments)
                handler(arguments)
            self.assertEqual(rpc.call_args_list[0].kwargs["request_key"], rpc.call_args_list[1].kwargs["request_key"])
            self.assertEqual(rpc.call_args_list[0].args, ("draft_email",))
        finally:
            reset_current_observability_context(tokens)

    def test_model_cannot_supply_approval_or_extra_destination_fields(self):
        for operation, arguments in (
            ("send", {"destination": "internal", "body": "x", "url": "http://elsewhere.invalid"}),
            ("draft_email", {"recipient": "example@example.invalid", "subject": "x", "body": "x", "approved": True}),
            ("propose_action", {"kind": "delete", "target_id": "work", "payload": {}, "approved": True}),
        ):
            with self.subTest(operation=operation), mock.patch.object(self.api, "request") as rpc:
                result = json.loads(self.api._tool_handler(self.binding, operation)(arguments))
                self.assertFalse(result["allowed"])
                rpc.assert_not_called()

    def test_action_schema_exposes_payload_fields_without_host_authority_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "binding.json"
            config.write_text(json.dumps(self.binding))
            ctx = mock.Mock()
            ctx.get_config.return_value = str(config)
            with mock.patch.object(self.api, "sandbox_available", return_value={"available": True}):
                self.api.register(ctx)
        declarations = {call.kwargs["name"]: call.kwargs["schema"]
                        for call in ctx.register_tool.call_args_list}
        payload = declarations["yuanxingmu_prepare_action"]["parameters"]["properties"]["payload"]
        # A bare object was emitted as {} by a real constrained tool caller.
        self.assertEqual(set(payload["properties"]), {"body", "filename", "content", "fields"})
        self.assertEqual(payload["properties"]["body"]["type"], "string")
        self.assertFalse(payload["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
