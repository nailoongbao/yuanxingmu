"""Optional no-model regressions through the installed official Hermes chain.

The real plugin manager, agent execution middleware, bounded hook dispatcher,
registry handlers, ShellFileOperations and BaseEnvironment all run here. Only
the outer sandbox spawn is replaced by local bash in a temporary directory;
these tests verify integration, not the operating-system isolation boundary.
Broker approvals below are unit-test decisions, not native UI acceptance.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from contextvars import copy_context
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


@unittest.skipUnless(sys.platform.startswith("linux") and importlib.util.find_spec("agent") is not None,
                     "requires the optional real Hermes installation")
class HermesOfficialDispatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.home = tempfile.TemporaryDirectory(prefix="yxm-hermes-dispatch-home-")
        cls.env_patch = mock.patch.dict(os.environ, {"HERMES_HOME": cls.home.name})
        cls.env_patch.start()
        from yuanxingmu import hermes_backend
        from agent import tool_executor
        from hermes_cli import plugins
        import model_tools
        from tools import file_tools, terminal_tool
        cls.api, cls.executor, cls.plugins, cls.model_tools = hermes_backend, tool_executor, plugins, model_tools
        cls.file_tools, cls.terminal_tool = file_tools, terminal_tool

    @classmethod
    def tearDownClass(cls):
        cls.env_patch.stop()
        cls.home.cleanup()

    def setUp(self):
        from tools.file_operations import ShellFileOperations
        from yuanxingmu.broker import Broker
        from yuanxingmu.guards import Guards, GuardPolicy
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="yxm-hermes-dispatch-")))
        self.workspace = self.directory / "workspace"
        self.workspace.mkdir()
        self.guards = Guards(GuardPolicy(objective="Write and inspect synthetic local summary files."))
        self.broker = self.stack.enter_context(Broker(self.directory / "broker", {}, {}, guards=self.guards))
        task = self.broker.create_task()
        self.binding = {"version": 1, "task_id": task, "broker_socket": str(self.directory / "broker.sock"),
                        "workspace": str(self.workspace), "bwrap": "/usr/bin/bwrap", "core_root": str(self.directory),
                        "resource_ids": [], "destination_ids": [], "defense_enabled": True}
        self.manager = self.plugins.PluginManager(scope_key=self.home.name)
        self.manager._discovered = True
        self.patch(self.plugins, "get_plugin_manager", return_value=self.manager)
        self.patch(self.plugins, "_resolve_hook_callback_timeout", return_value=5)
        config = self.directory / "binding.json"
        config.write_text(json.dumps(self.binding), encoding="utf-8")
        ctx = self.plugins.PluginContext(self.plugins.PluginManifest(name="yuanxingmu", path=str(self.directory)), self.manager)
        # Keep registration of hooks/middleware real, while injecting the one
        # test environment instead of changing the process-global provider list.
        with mock.patch.object(ctx, "get_config", return_value=str(config)), \
             mock.patch.object(ctx, "register_tool"), mock.patch.object(ctx, "register_terminal_environment_provider"), \
             mock.patch.object(self.api, "sandbox_available", return_value={"available": True}):
            self.api.register(ctx)
        self.environment = self.api.YuanxingmuEnvironment(binding=self.binding, cwd=str(self.workspace), timeout=5)
        self.stack.callback(self.environment.cleanup)
        self.patch(self.file_tools, "_get_file_ops", return_value=ShellFileOperations(self.environment))
        self.patch(self.terminal_tool, "_acquire_env", return_value=self.environment)
        self.patch(self.terminal_tool, "_get_env_config", return_value={
            "env_type": "yuanxingmu", "cwd": str(self.workspace), "timeout": 5})
        self.patch(self.terminal_tool, "_run_approval_guards", return_value=self.terminal_tool._ApprovalVerdict())
        self.patch(self.api, "start", side_effect=self.local_spawn)
        self.patch(self.api, "_REVIEW_POLL_SECONDS", new=0)
        self.rpc_log, self.spawn_log, self.scopes, self.hook_threads = [], [], [], []
        self.log_lock = threading.Lock()
        self.auto_approve = True
        self.rpc = self.patch(self.api, "request", side_effect=self.dispatch)
        self.judge = self.patch(self.guards, "_judge", side_effect=self.allow_judge)
        # Observe the actual bounded callback worker, not a synchronous stand-in.
        before = self.manager._hooks["pre_tool_call"][0]
        def observe_before(**kwargs):
            with self.log_lock:
                self.hook_threads.append(threading.get_ident())
            return before(**kwargs)
        self.manager._hooks["pre_tool_call"][0] = observe_before

    def patch(self, target, attribute, **kwargs):
        return self.stack.enter_context(mock.patch.object(target, attribute, **kwargs))

    def allow_judge(self, layer, purpose, candidate):
        return self.guards._rule(layer, "allow", "judge_allow", "Unit-test judge response.", json.dumps(candidate).encode())

    def dispatch(self, operation, **kwargs):
        fields = {k: v for k, v in kwargs.items() if k not in {"socket_path", "timeout_seconds"}}
        invocation = self.api._INVOCATION.get()
        with self.log_lock:
            self.rpc_log.append((operation, json.loads(json.dumps(fields)), invocation))
        response = self.broker.dispatch(self.binding["task_id"], {"op": operation, **fields})
        if operation == "request_tool_review" and response.get("status") == "pending" and self.auto_approve:
            self.broker.review_mail(self.binding["task_id"], {
                "op": "tool_approve", "review_id": response["review_id"], "digest": response["digest"], "confirm": "approve"})
        return response

    def local_spawn(self, *, command, workspace, stdout, stderr, stdin, text, encoding, errors, **kwargs):
        invocation = self.api._current_invocation(self.binding)
        self.assertIsNotNone(invocation)
        with self.log_lock:
            self.spawn_log.append((list(command), invocation.session_id, invocation.tool_call_id))
            self.scopes.append((invocation, copy_context()))
        return subprocess.Popen(command, cwd=workspace, stdout=stdout, stderr=stderr, stdin=stdin,
                                text=text, encoding=encoding, errors=errors, start_new_session=True)

    def agent(self, session):
        return SimpleNamespace(session_id=session, _current_turn_id="test-turn", _current_api_request_id="test-api",
                               _tool_guardrails=SimpleNamespace(before_call=lambda *args: SimpleNamespace(allows_execution=True)),
                               quiet_mode=True, verbose_logging=False, _touch_activity=lambda *args: None,
                               tool_progress_callback=None, tool_start_callback=None, _checkpoint_mgr=SimpleNamespace(enabled=False),
                               _tool_worker_threads_lock=threading.Lock(), _tool_worker_threads=set(), _interrupt_requested=False)

    def run_tool(self, name, arguments, *, session="native-session", call="native-call", sequential=False, execute=None):
        agent = self.agent(session)
        if execute is None:
            execute = lambda args: self.model_tools.handle_function_call(
                name, args, task_id="test-task", session_id=session, tool_call_id=call,
                skip_pre_tool_call_hook=True, skip_tool_request_middleware=True, skip_tool_execution_middleware=True)
        runner = (self.executor._run_sequential_tool_execution_middleware if sequential
                  else self.executor._run_agent_tool_execution_middleware)
        return runner(agent, function_name=name, function_args=arguments, effective_task_id="test-task",
                      tool_call_id=call, execute=execute)

    def requests(self):
        return [(fields, scope) for operation, fields, scope in self.rpc_log if operation == "request_tool_review"]

    def test_official_write_and_true_reach_real_bash_with_one_decision_per_command(self):
        target = self.workspace / "summary.txt"
        content = "项目 HERMES-LAYERS；对外报价 186000 元。\n"
        write = self.run_tool("write_file", {"path": str(target), "content": content}, call="write-call")
        self.assertFalse(json.loads(write.result).get("error"), write.result)
        self.assertEqual(target.read_bytes(), content.encode())
        normal = self.run_tool("terminal", {"command": "true", "workdir": str(self.workspace)}, call="true-call")
        self.assertEqual(json.loads(normal.result)["exit_code"], 0, normal.result)
        self.assertTrue(self.hook_threads)
        self.assertTrue(all(tid != threading.get_ident() for tid in self.hook_threads))
        requests = self.requests()
        self.assertGreater(len(requests), 1)
        decisions = [call for call in self.judge.call_args_list if call.args[1] == "action"]
        self.assertEqual(len(decisions), len(requests))
        self.assertEqual(len({fields["request_key"] for fields, _ in requests}), len(requests))
        for fields, invocation in requests:
            self.assertEqual(fields["arguments"]["source_tool"], invocation.source_tool)
            self.assertTrue(invocation.closed)
        self.assertEqual(requests[-1][0]["arguments"]["command"], "true")
        self.assertTrue(all(invocation.closed for invocation, _ in self.scopes))
        self.assertIsNone(self.api._INVOCATION.get())

    def test_concurrent_native_calls_do_not_mix_identity_sources_or_reviews(self):
        barrier = threading.Barrier(2)
        original_dispatch = self.dispatch
        def interleaved(operation, **kwargs):
            if operation == "request_tool_review":
                barrier.wait(timeout=5)
            return original_dispatch(operation, **kwargs)
        self.rpc.side_effect = interleaved
        commands = {"call-one": "python3 -c 'import json; print(json.dumps(11))'",
                    "call-two": "python3 -c 'import json; print(json.dumps(22))'"}
        # Official bounded hook callbacks intentionally suppress concurrent
        # invocation of the *same* callback. Serialize only this policy phase,
        # as Hermes's own concurrent authorization gate does, then overlap RPCs.
        gate = self.executor._ConcurrentToolAuthorizationGate()
        def run(call):
            session = "session-" + call
            args = {"command": commands[call], "workdir": str(self.workspace)}
            return self.executor._run_agent_tool_execution_middleware(
                self.agent(session), function_name="terminal", function_args=args,
                effective_task_id="test-task", tool_call_id=call, authorization_gate=gate,
                execute=lambda final: self.model_tools.handle_function_call(
                    "terminal", final, task_id="test-task", session_id=session, tool_call_id=call,
                    skip_pre_tool_call_hook=True, skip_tool_request_middleware=True, skip_tool_execution_middleware=True))
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, commands))
        self.assertTrue(all(json.loads(result.result)["exit_code"] == 0 for result in results))
        self.assertEqual(len(self.requests()), 2)
        for fields, invocation in self.requests():
            self.assertEqual(invocation.session_id, "session-" + invocation.tool_call_id)
            self.assertEqual(fields["arguments"]["command"], commands[invocation.tool_call_id])
            self.assertEqual(fields["arguments"]["source_tool"]["arguments"]["command"], commands[invocation.tool_call_id])
            expected_key = hashlib.sha256(self.api._canonical([
                "hermes-execute-v1", self.binding["task_id"], invocation.session_id,
                invocation.tool_call_id, 0, fields["arguments"]]).encode()).hexdigest()
            self.assertEqual(fields["request_key"], expected_key)
        consumes = [fields for op, fields, _ in self.rpc_log if op == "consume_tool_review"]
        self.assertEqual(len(consumes), 2)
        self.assertEqual(len({fields["review_id"] for fields in consumes}), 2)
        for fields in consumes:
            response = self.broker.dispatch(self.binding["task_id"], {"op": "consume_tool_review", **fields})
            self.assertFalse(response["allowed"])

    def test_closed_copied_context_cannot_reuse_provider_or_spawn(self):
        result = self.run_tool("terminal", {"command": "true"})
        self.assertEqual(json.loads(result.result)["exit_code"], 0)
        invocation, copied = self.scopes[-1]
        self.assertTrue(invocation.closed)
        count = len(self.rpc_log), len(self.spawn_log)
        denied = copied.run(self.environment.execute, "printf late")
        self.assertEqual(denied["returncode"], 126)
        with self.assertRaises(self.api.EnvironmentConnectionError):
            copied.run(self.environment._run_bash, "printf late")
        self.assertEqual((len(self.rpc_log), len(self.spawn_log)), count)

    def test_missing_identity_is_explicitly_blocked_by_official_middleware(self):
        from hermes_cli.middleware import run_tool_execution_middleware
        for context in ({}, {"session_id": "session"}, {"session_id": "session", "tool_call_id": 42}):
            with self.subTest(context=context):
                next_call = mock.Mock(side_effect=AssertionError("must not dispatch"))
                result = run_tool_execution_middleware("terminal", {"command": "true"}, next_call, **context)
                self.assertFalse(json.loads(result)["allowed"])
                next_call.assert_not_called()
        self.assertEqual(self.rpc_log, [])

    def test_process_control_guard_survives_skipped_pre_hook(self):
        self.manager._hooks.clear()
        self.rpc.side_effect = lambda op, **kw: {"allowed": False, "verdict": "block"}
        execute = mock.Mock(side_effect=AssertionError("process handler must not run"))
        result = self.run_tool("process_manage", {"action": "kill", "session_id": "synthetic"}, execute=execute)
        self.assertFalse(json.loads(result.result)["allowed"])
        execute.assert_not_called()
        self.rpc.assert_called_once_with("guard_tool", socket_path=self.binding["broker_socket"], timeout_seconds=60,
                                        tool="terminal", arguments={"action": "kill", "session_id": "synthetic"})

    def test_unexpected_guard_failure_cannot_trigger_middleware_fail_open(self):
        self.manager._hooks.clear()
        self.rpc.side_effect = lambda op, **kw: []  # malformed reply makes the guard raise AttributeError
        execute = mock.Mock(side_effect=AssertionError("process handler must not run"))
        result = self.run_tool("process_manage", {"action": "kill", "session_id": "synthetic"}, execute=execute)
        self.assertFalse(json.loads(result.result)["allowed"])
        execute.assert_not_called()
        self.assertIsNone(self.api._INVOCATION.get())

    def test_official_sequential_timeout_revokes_waiting_call_before_late_approval(self):
        from tools.interrupt import set_interrupt
        entered, release, finished = threading.Event(), threading.Event(), threading.Event()
        seen, results = [], []
        original_dispatch = self.dispatch
        def delayed(operation, **kwargs):
            if operation == "request_tool_review":
                seen.append((self.api._INVOCATION.get(), copy_context()))
                entered.set()
                if not release.wait(timeout=5):
                    raise AssertionError("test did not release pending review")
            return original_dispatch(operation, **kwargs)
        self.rpc.side_effect = delayed
        self.patch(self.executor, "_resolve_sequential_tool_timeout", return_value=0.2)
        # The official executor calls run_agent._set_interrupt; use that same
        # real interrupt function without importing the full model runner.
        self.patch(self.executor, "_ra", return_value=SimpleNamespace(_set_interrupt=set_interrupt))
        def execute(args):
            try:
                result = self.model_tools.handle_function_call(
                    "terminal", args, task_id="test-task", session_id="native-session", tool_call_id="native-call",
                    skip_pre_tool_call_hook=True, skip_tool_request_middleware=True, skip_tool_execution_middleware=True)
                results.append(result)
                return result
            finally:
                finished.set()
        try:
            timed_out = self.run_tool("terminal", {"command": "true"}, sequential=True, execute=execute)
            self.assertIsInstance(timed_out.result, self.executor._ToolTimeoutResult)
            self.assertTrue(entered.is_set())
        finally:
            release.set()
            self.assertTrue(finished.wait(timeout=5))
        self.assertEqual(json.loads(results[0])["exit_code"], 126)
        self.assertEqual(self.spawn_log, [])
        invocation, copied = seen[0]
        deadline = time.monotonic() + 5
        while not invocation.closed and time.monotonic() < deadline:
            threading.Event().wait(0.005)
        self.assertTrue(invocation.closed)
        count = len(self.rpc_log)
        self.assertEqual(copied.run(self.environment.execute, "printf stale")["returncode"], 126)
        self.assertEqual(len(self.rpc_log), count)
        self.assertFalse(any(operation == "consume_tool_review" for operation, _, _ in self.rpc_log))

    def test_owner_cancellation_reaches_handler_running_in_copied_context(self):
        from tools.interrupt import is_interrupted, set_interrupt
        owner = threading.get_ident()
        original_dispatch = self.dispatch
        workers = []
        def cancel_owner(operation, **kwargs):
            if operation == "request_tool_review":
                workers.append(threading.get_ident())
                self.assertNotEqual(workers[-1], owner)
                set_interrupt(True, owner)
                self.assertFalse(is_interrupted())  # cancellation is on the owner, not this child
            return original_dispatch(operation, **kwargs)
        self.rpc.side_effect = cancel_owner
        def execute(args):
            copied = copy_context()
            with ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(copied.run, lambda: self.model_tools.handle_function_call(
                    "terminal", args, task_id="test-task", session_id="native-session", tool_call_id="native-call",
                    skip_pre_tool_call_hook=True, skip_tool_request_middleware=True,
                    skip_tool_execution_middleware=True)).result(timeout=5)
        try:
            result = self.run_tool("terminal", {"command": "true"}, execute=execute)
            self.assertEqual(json.loads(result.result)["exit_code"], 126)
            self.assertEqual(len(workers), 1)
            self.assertEqual(self.spawn_log, [])
        finally:
            set_interrupt(False, owner)

    def test_handler_identity_mismatch_cannot_use_middleware_authority(self):
        result = self.run_tool("terminal", {"command": "true"}, execute=lambda args: self.model_tools.handle_function_call(
            "terminal", args, task_id="test-task", session_id="other-session", tool_call_id="native-call",
            skip_pre_tool_call_hook=True, skip_tool_request_middleware=True, skip_tool_execution_middleware=True))
        self.assertEqual(json.loads(result.result)["exit_code"], 126)
        self.assertEqual(self.requests(), [])
        self.assertEqual(self.spawn_log, [])


if __name__ == "__main__":
    unittest.main()
