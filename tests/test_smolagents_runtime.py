"""Real smolagents model loops through local Unix HTTP and Broker sockets.

The model bridge is deterministic. These tests exercise the installed SDK's
Agent.run loop; they do not claim external model inference or process isolation.
"""
from collections import deque
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from yuanxingmu.actions import ActionTarget
from yuanxingmu.adapters import NativeTools
from yuanxingmu.broker import Broker, Destination, Resource


ROOT = Path(__file__).resolve().parents[1]
HAS_SDK = importlib.util.find_spec("smolagents") is not None
COMPLETE = "LOCAL-SDK-LOOP-COMPLETE"


def tool_call(nonce, name, arguments):
    return {"id": nonce, "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}}


def completion(*calls):
    return {"id": "local-host-response", "object": "chat.completion", "model": "local-fixture",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                          "tool_calls": list(calls)}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def final_response():
    return completion(tool_call("host_dispatch_final", "final_answer", {"answer": COMPLETE}))


class UnixHTTPServer(socketserver.ThreadingMixIn, getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)):
    daemon_threads = True


@unittest.skipUnless(sys.platform.startswith("linux") and HAS_SDK,
                     "Requires Linux and the pinned smolagents SDK environment")
class SmolagentsRuntimeTests(unittest.TestCase):
    def setUp(self):
        from yuanxingmu.adapters import smolagents_runtime
        self.runtime = smolagents_runtime
        temporary = tempfile.TemporaryDirectory(prefix="yxm-sdk-loop-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.receipts, self.requests = [], []
        self.responses = deque()
        self.response_lock = threading.Lock()
        owner = self

        class Receiver(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.receipts.append({"path": self.path, "body": body.decode("utf-8")})
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        receiver = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        self.start_server(receiver)
        url = f"http://127.0.0.1:{receiver.server_port}"
        resource = self.root / "note.txt"
        resource.write_text("LOCAL-REGISTERED-RESOURCE", encoding="utf-8")
        self.broker = Broker(self.root / "broker-state", {"note": Resource(resource, ())},
                             {"public": Destination(url + "/public")}, reviewed_mail=True,
                             action_targets={"chat": ActionTarget("message", "Local chat", url=url + "/message")})
        self.addCleanup(self.broker.close)
        self.task = self.broker.create_task()
        endpoint = self.broker.serve(self.task, self.root / "worker.sock")
        self.client = NativeTools(str(endpoint), "host-persisted-session")

        class Bridge(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                with owner.response_lock:
                    owner.requests.append({"path": self.path, "headers": dict(self.headers),
                                           "body": json.loads(raw), "raw": raw})
                    if owner.responses:
                        response = owner.responses.popleft()
                    else:
                        response = (500, {"error": {"message": "local fixture exhausted"}})
                status, body = response if isinstance(response, tuple) else (200, response)
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)

        self.model_socket = self.root / "model.sock"
        self.start_server(UnixHTTPServer(str(self.model_socket), Bridge))
        self.config = {"version": 1, "framework": "smolagents",
                       "session_id": self.client.session_id, "task_id": self.task,
                       "model_id": "local-fixture", "max_steps": 8, "max_tokens": 512,
                       "prompt": "Use the registered local tools and report completion.", "resume": False,
                       "checkpoint": str(self.root / "checkpoint.json"),
                       "broker_socket": str(endpoint), "model_socket": str(self.model_socket)}

    def start_server(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(3)

        self.addCleanup(close)

    @staticmethod
    def proposal(body="LOCAL-PROPOSAL"):
        return {"proposal": {"kind": "message", "target_id": "chat", "payload": {"body": body}}}

    def actions(self):
        return self.broker.review_action(self.task, {"op": "action_list"})["actions"]

    def events(self):
        path = self.root / "broker-state/broker-events.jsonl"
        return path.read_bytes() if path.exists() else b""

    def agent(self):
        return self.runtime.ProtectedToolCallingAgent(client=self.client,
                model=self.runtime.BridgeModel(deepcopy(self.config)), max_steps=8)

    @staticmethod
    def sdk_message(*calls):
        from smolagents.models import ChatMessage
        parsed = deepcopy(list(calls))
        # Native _step_stream parses JSON arguments before process_tool_calls.
        for call in parsed:
            call["function"]["arguments"] = json.loads(call["function"]["arguments"])
        return ChatMessage.from_dict({"role": "assistant", "content": None, "tool_calls": parsed})

    @staticmethod
    def sdk_step():
        from smolagents.memory import ActionStep
        from smolagents.monitoring import Timing
        return ActionStep(step_number=0, timing=Timing(start_time=0.0))

    def dispatch(self, agent, *calls):
        step = self.sdk_step()
        outputs = list(agent.process_tool_calls(self.sdk_message(*calls), step))
        results = [json.loads(output.output) for output in outputs if hasattr(output, "output")]
        return results, step

    def test_agent_run_reaches_model_and_broker_and_preserves_each_proposal_identity(self):
        self.responses.extend([
            completion(tool_call("host_dispatch_read", "yuanxingmu_read", {"resource": "note"})),
            completion(tool_call("host_dispatch_one", "yuanxingmu_propose_action", self.proposal()),
                       tool_call("host_dispatch_two", "yuanxingmu_propose_action", self.proposal())),
            final_response(),
        ])
        result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(result["framework"], "smolagents")
        self.assertEqual(result["session_id"], self.client.session_id)
        self.assertGreaterEqual(result["steps"], 3)
        self.assertEqual(len(self.requests), 3)
        self.assertTrue(all(row["path"] == "/v1/chat/completions" for row in self.requests))
        self.assertTrue(all(not row["body"].get("stream", False) for row in self.requests))
        self.assertTrue(all("Authorization" not in row["headers"] for row in self.requests))
        self.assertIn("LOCAL-REGISTERED-RESOURCE", json.dumps(self.requests[1]["body"]["messages"]))
        last_messages = json.dumps(self.requests[-1]["body"]["messages"])
        self.assertIn("host_dispatch_one", last_messages)
        self.assertIn("host_dispatch_two", last_messages)
        actions = self.actions()
        self.assertEqual(len(actions), 2)
        self.assertEqual(len({row["id"] for row in actions}), 2)
        self.assertTrue(all(row["status"] == "pending" for row in actions))
        self.assertEqual(self.receipts, [])
        selected = actions[0]
        committed = self.broker.review_action(self.task, {"op": "action_commit", "action_id": selected["id"],
                    "revision": selected["revision"], "digest": selected["digest"], "confirm": "commit"})
        self.assertTrue(committed["started"])
        self.assertEqual(len(self.receipts), 1)
        self.assertEqual(self.receipts[0]["path"], "/message")

    def test_rebuilt_agent_replays_same_host_nonce_without_another_proposal(self):
        call = tool_call("host_dispatch_stable", "yuanxingmu_propose_action", self.proposal())
        first, _ = self.dispatch(self.agent(), call)
        replay, _ = self.dispatch(self.agent(), call)
        self.assertEqual(first[0]["id"], replay[0]["id"])
        self.assertEqual(len(self.actions()), 1)
        changed = tool_call("host_dispatch_stable", "yuanxingmu_propose_action", self.proposal("changed"))
        conflict, _ = self.dispatch(self.agent(), changed)
        self.assertFalse(conflict[0]["allowed"])
        self.assertEqual(conflict[0]["reason"], "action_request_conflict")
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.receipts, [])

    def test_single_dispatch_binding_does_not_escape_generator_yields(self):
        agent = self.agent()
        direct = agent.tools["yuanxingmu_propose_action"]
        calls = (tool_call("host_dispatch_a", "yuanxingmu_propose_action", self.proposal("one")),
                 tool_call("host_dispatch_b", "yuanxingmu_propose_action", self.proposal("two")))
        step = self.sdk_step()
        iterator = agent.process_tool_calls(self.sdk_message(*calls), step)
        yielded = 0
        while True:
            try:
                next(iterator)
            except StopIteration:
                break
            yielded += 1
            before = self.events()
            with self.assertRaisesRegex(ValueError, "native_tool_call_id_required"):
                direct(**self.proposal())
            self.assertEqual(self.events(), before)
        self.assertGreaterEqual(yielded, 4)
        self.assertEqual(len(step.tool_calls), 2)
        self.assertEqual({call.id for call in step.tool_calls}, {"host_dispatch_a", "host_dispatch_b"})
        self.assertEqual(len(self.actions()), 2)
        with self.assertRaisesRegex(ValueError, "native_tool_call_id_required"):
            direct(**self.proposal())

    def test_unknown_tools_and_forged_host_arguments_fail_before_broker(self):
        from smolagents.utils import AgentError
        bad_calls = [tool_call("host_dispatch_unknown", "unregistered_http_sender", {"body": "not allowed"}),
                     tool_call("host_dispatch_send", "yuanxingmu_send", {"destination": "public", "body": "not allowed"}),
                     tool_call("host_dispatch_forged", "yuanxingmu_propose_action",
                               {**self.proposal(), "tool_call_id": "forged", "approved": True,
                                "broker_socket": str(self.root / "other.sock")})]
        for call in bad_calls:
            with self.subTest(tool=call["function"]["name"]):
                before = self.events()
                with self.assertRaises((ValueError, TypeError, RuntimeError, AgentError)):
                    self.dispatch(self.agent(), call)
                self.assertEqual(self.events(), before)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_completed_checkpoint_resumes_without_model_or_duplicate_effects(self):
        self.responses.extend([completion(tool_call("host_dispatch_saved", "yuanxingmu_propose_action", self.proposal())),
                               final_response()])
        first = self.runtime.run_session(deepcopy(self.config))
        checkpoint = Path(self.config["checkpoint"])
        self.assertTrue(checkpoint.is_file())
        self.assertIsInstance(json.loads(checkpoint.read_text(encoding="utf-8")), dict)
        count = len(self.requests)
        resumed = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(resumed["answer"], first["answer"])
        self.assertEqual(len(self.requests), count)
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.receipts, [])

    def test_checkpoint_refuses_new_run_overwrite_and_other_session_or_task(self):
        self.responses.append(final_response())
        self.runtime.run_session(deepcopy(self.config))
        checkpoint = Path(self.config["checkpoint"])
        original = checkpoint.read_bytes()
        count = len(self.requests)
        variants = [deepcopy(self.config), {**self.config, "resume": True, "session_id": "another-host-session"},
                    {**self.config, "resume": True, "task_id": self.broker.create_task()}]
        for config in variants:
            with self.subTest(session=config["session_id"], task=config["task_id"], resume=config["resume"]):
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session(config)
                self.assertEqual(checkpoint.read_bytes(), original)
                self.assertEqual(len(self.requests), count)

    def test_resume_rejects_missing_and_corrupt_checkpoint_before_model_or_broker(self):
        checkpoint = Path(self.config["checkpoint"])
        config = {**self.config, "resume": True}
        before = self.events()
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            self.runtime.run_session(deepcopy(config))
        for content in (b'{"version": 1, broken', b'[]', b'null'):
            with self.subTest(content=content):
                checkpoint.write_bytes(content)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session(deepcopy(config))
                self.assertEqual(checkpoint.read_bytes(), content)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.events(), before)

    def test_model_bridge_rejects_multiple_choices_before_any_tool_dispatch(self):
        from smolagents.utils import AgentError
        response = final_response()
        response["choices"].append(deepcopy(response["choices"][0]))
        self.responses.append(response)
        before = self.events()
        with self.assertRaises((ValueError, RuntimeError, AgentError)):
            self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(self.events(), before)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_worker_failure_keeps_prompt_and_model_error_body_out_of_stdout_and_stderr(self):
        prompt_secret = "SYNTHETIC-PRIVATE-PROMPT-DO-NOT-PRINT"
        response_secret = "SYNTHETIC-PRIVATE-UPSTREAM-BODY-DO-NOT-PRINT"
        self.responses.append((500, {"error": {"message": response_secret}}))
        config = {**self.config, "prompt": prompt_secret}
        path = self.root / "worker-config.json"
        path.write_text(json.dumps(config), encoding="utf-8")
        env = dict(os.environ)
        env["PYTHONPATH"] = str(ROOT)
        result = subprocess.run([sys.executable, "-B", "-m", "yuanxingmu.adapters.smolagents_runtime",
                                 "--config", str(path)], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.requests), 1)
        self.assertNotIn(prompt_secret, result.stdout + result.stderr)
        self.assertNotIn(response_secret, result.stdout + result.stderr)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def interrupt_before_dispatch(self, response):
        self.responses.append(response)
        with patch.object(self.runtime.ProtectedToolCallingAgent, "process_tool_calls",
                          side_effect=RuntimeError("simulated_worker_interruption")):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        checkpoint = Path(self.config["checkpoint"])
        saved = json.loads(checkpoint.read_bytes())
        self.assertIsNotNone(saved["pending"]["response"])
        self.assertEqual(saved["completed_tools"], {})
        self.assertEqual(self.actions(), [])
        return checkpoint

    def test_pending_response_is_rechecked_before_recovering_native_dispatch(self):
        response = completion(tool_call("host_recover_first", "yuanxingmu_propose_action", self.proposal()))
        self.interrupt_before_dispatch(response)
        self.responses.extend([response, final_response()])
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(self.requests[0]["raw"], self.requests[1]["raw"])
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.receipts, [])

    def test_crash_after_broker_acceptance_before_checkpoint_does_not_duplicate_proposal(self):
        response = completion(tool_call("host_recover_one", "yuanxingmu_propose_action", self.proposal("one")),
                              tool_call("host_recover_two", "yuanxingmu_propose_action", self.proposal("two")))
        self.responses.append(response)
        save = self.runtime._Checkpoint.save
        interrupted = []

        def crash_before_save(checkpoint):
            if checkpoint.value["completed_tools"] and not interrupted:
                interrupted.append(True)
                raise RuntimeError("simulated_loss_after_broker_acceptance")
            return save(checkpoint)

        with patch.object(self.runtime._Checkpoint, "save", crash_before_save):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        first_id = self.actions()[0]["id"]
        saved = json.loads(Path(self.config["checkpoint"]).read_bytes())
        self.assertEqual(saved["completed_tools"], {})
        self.responses.extend([response, final_response()])
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.requests[0]["raw"], self.requests[1]["raw"])
        self.assertEqual(len(self.actions()), 2)
        self.assertIn(first_id, {row["id"] for row in self.actions()})
        self.assertEqual(self.receipts, [])

    def test_completed_call_in_pending_batch_is_not_dispatched_again(self):
        response = completion(tool_call("host_partial_one", "yuanxingmu_propose_action", self.proposal("one")),
                              tool_call("host_partial_two", "yuanxingmu_propose_action", self.proposal("two")))
        self.responses.append(response)
        execute = self.runtime.ProtectedToolCallingAgent.execute_tool_call

        def interrupt_second(agent, name, arguments):
            if agent.invocations.current() == "host_partial_two":
                raise RuntimeError("simulated_second_call_interruption")
            return execute(agent, name, arguments)

        with patch.object(self.runtime.ProtectedToolCallingAgent, "execute_tool_call", interrupt_second):
            with self.assertRaises(RuntimeError):
                self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(len(self.actions()), 1)
        saved = json.loads(Path(self.config["checkpoint"]).read_bytes())
        self.assertEqual(set(saved["completed_tools"]), {"host_partial_one"})
        self.responses.extend([response, final_response()])
        invoked, original_invoke = [], self.runtime._RuntimeTools.invoke

        def track(client, operation, arguments, **context):
            invoked.append(context.get("tool_call_id"))
            return original_invoke(client, operation, arguments, **context)

        with patch.object(self.runtime._RuntimeTools, "invoke", track):
            result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(invoked, ["host_partial_two"])
        self.assertEqual(len(self.actions()), 2)
        self.assertEqual(self.receipts, [])

    def test_changed_pending_host_response_does_not_overwrite_recovery_record(self):
        response = completion(tool_call("host_original", "yuanxingmu_propose_action", self.proposal()))
        checkpoint = self.interrupt_before_dispatch(response)
        original = checkpoint.read_bytes()
        self.responses.append(completion(tool_call("host_different", "yuanxingmu_propose_action", self.proposal())))
        with self.assertRaisesRegex(RuntimeError, "sdk_checkpoint_response_changed"):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(checkpoint.read_bytes(), original)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_new_turn_keeps_history_and_uses_a_new_plain_text_answer(self):
        response = {"choices": [{"message": {"role": "assistant", "content": "FIRST-ANSWER"}}]}
        self.responses.append(response)
        first = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(first["answer"], "FIRST-ANSWER")
        response = {"choices": [{"message": {"role": "assistant", "content": "SECOND-ANSWER"}}]}
        self.responses.append(response)
        second = self.runtime.run_session({**self.config, "resume": True, "prompt": "Continue with a new question."})
        self.assertEqual(second["answer"], "SECOND-ANSWER")
        self.assertEqual(len(self.requests), 2)
        self.assertIn("FIRST-ANSWER", json.dumps(self.requests[-1]["body"]["messages"]))
        self.assertEqual(self.actions(), [])

    def test_step_limit_stops_without_extra_model_summarization_or_resume_retry(self):
        self.responses.append(completion(tool_call("host_limit", "yuanxingmu_describe", {})))
        config = {**self.config, "max_steps": 1}
        with self.assertRaisesRegex(RuntimeError, "sdk_max_steps_reached"):
            self.runtime.run_session(config)
        self.assertEqual(len(self.requests), 1)
        with self.assertRaisesRegex(RuntimeError, "sdk_max_steps_reached"):
            self.runtime.run_session({**config, "resume": True})
        self.assertEqual(len(self.requests), 1)


if __name__ == "__main__":
    unittest.main()
