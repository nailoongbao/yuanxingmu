"""Native PydanticAI Agent loops with local deterministic model replies.

The fixtures exercise actual Tool validation, deferred approvals, native
message recovery and real Broker Unix RPC. They do not test model inference
or the process sandbox; host integration tests cover the latter separately.
"""
from collections import deque
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import socket
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
from yuanxingmu.guards import GuardPolicy, Guards, JudgeConfig
from test_yuanxingmu_guards import _JudgeFixture


ROOT = Path(__file__).resolve().parents[1]
HAS_SDK = all(importlib.util.find_spec(name) is not None for name in ("pydantic_ai", "pydantic_graph", "pydantic"))
REQUIRES_SDK = unittest.skipUnless(sys.platform.startswith("linux") and HAS_SDK,
                                  "Requires Linux and the pinned PydanticAI SDK environment")
COMPLETE = "LOCAL-PYDANTIC-AI-LOOP-COMPLETE"


def tool_call(nonce, name, arguments):
    return {"id": nonce, "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}}


def completion(*calls):
    return {"id": "host-local-response", "object": "chat.completion", "model": "local-fixture",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": None,
                          "tool_calls": list(calls)}, "finish_reason": "tool_calls"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


def final_response(answer=COMPLETE):
    return {"id": "host-local-final", "object": "chat.completion", "model": "local-fixture",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": answer},
                          "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}


class UnixHTTPServer(socketserver.ThreadingMixIn, getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)):
    daemon_threads = True


class PydanticAiFixture:
    enable_automation = False

    def setUp(self):
        from yuanxingmu.adapters import pydantic_ai_runtime
        self.runtime = pydantic_ai_runtime
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"OTEL_SDK_DISABLED": "true"}).start()
        temporary = tempfile.TemporaryDirectory(prefix="yxm-pydantic_ai-loop-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.receipts, self.requests, self.upstream_requests = [], [], []
        self.responses, self.journal = deque(), {}
        self.bridge_hook = None
        self.drop_model_response = None
        self.response_lock = threading.Lock()
        self.drop_receipts = False
        owner = self

        class Receiver(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                owner.receipts.append({"path": self.path, "body": body.decode("utf-8")})
                if owner.drop_receipts:
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"{}")

        self.receiver = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
        self.start_server(self.receiver)
        receiver_url = f"http://127.0.0.1:{self.receiver.server_port}"
        note = self.root / "note.txt"
        note.write_text("LOCAL-REGISTERED-RESOURCE", encoding="utf-8")
        self.host_files = self.root / "host-files"
        self.host_files.mkdir()
        (self.host_files / "report.txt").write_text("ORIGINAL-REPORT", encoding="utf-8")
        (self.host_files / "delete.txt").write_text("ORIGINAL-KEEP", encoding="utf-8")
        targets = {
            "chat": ActionTarget("message", "Authorized team", url=receiver_url + "/message"),
            "outside": ActionTarget("message", "Outside scope", url=receiver_url + "/outside"),
            "upload": ActionTarget("upload", "Authorized upload", url=receiver_url + "/upload"),
            "form": ActionTarget("form", "Authorized form", url=receiver_url + "/form", form_fields=("note",)),
            "replace": ActionTarget("overwrite", "Host report", workspace=self.host_files, relative_path="report.txt"),
            "remove": ActionTarget("delete", "Host file", workspace=self.host_files, relative_path="delete.txt"),
        }
        self.scope = {"version": 1, "max_attempts": 3, "max_total_body_bytes": 65536,
                      "targets": {name: {"accepted_labels": ["private"], "max_body_bytes": 8192}
                                  for name in ("chat", "upload", "form")}}
        self.guard_events = []
        self.judge = self.guards = None
        if self.enable_automation:
            self.judge = _JudgeFixture()
            self.addCleanup(self.judge.close)
            self.guards = Guards(GuardPolicy("Send progress to the authorized internal team; keep other actions for review."),
                                 JudgeConfig(self.judge.url, "synthetic-judge"), audit=self.guard_events.append)
        self.broker = Broker(self.root / "broker-state", {"note": Resource(note, ("private",) if self.enable_automation else ())},
                             {"public": Destination(receiver_url + "/public")}, guards=self.guards,
                             action_targets=targets, action_automation=self.scope if self.enable_automation else None,
                             input_containment=self.enable_automation, reviewed_mail=True)
        self.addCleanup(self.broker.close)
        self.task = self.broker.create_task(initial_labels=["private"] if self.enable_automation else [])
        endpoint = self.broker.serve(self.task, self.root / "worker.sock")
        self.client = NativeTools(str(endpoint), "host-pydantic_ai-session")

        class Bridge(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                row = {"path": self.path, "headers": dict(self.headers), "body": json.loads(raw), "raw": raw}
                with owner.response_lock:
                    owner.requests.append(row)
                    reply = owner.bridge_hook(row) if owner.bridge_hook is not None else None
                    if reply is None:
                        if raw in owner.journal:
                            reply = owner.journal[raw]
                        else:
                            owner.upstream_requests.append(row)
                            reply = owner.responses.popleft() if owner.responses else (
                                500, {"error": {"message": "local fixture exhausted"}})
                            if not isinstance(reply, tuple) or reply[0] == 200:
                                owner.journal[raw] = deepcopy(reply)
                status, body = reply if isinstance(reply, tuple) else (200, reply)
                if owner.drop_model_response is not None and owner.drop_model_response(row):
                    self.close_connection = True
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)

        self.model_socket = self.root / "model.sock"
        self.start_server(UnixHTTPServer(str(self.model_socket), Bridge))
        self.config = {"version": 1, "framework": "pydantic_ai", "session_id": self.client.session_id,
                       "task_id": self.task, "model_id": "local-fixture", "max_steps": 8, "max_tokens": 512,
                       "prompt": "Use the registered local tools and report completion.", "resume": False,
                       "checkpoint": str(self.root / "checkpoint.json"), "broker_socket": str(endpoint),
                       "model_socket": str(self.model_socket), "automatic_actions": self.enable_automation}

    def start_server(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(3)

        self.addCleanup(close)

    @staticmethod
    def proposal(body="LOCAL-PYDANTIC-AI-PROGRESS", *, target="chat"):
        return {"proposal": {"kind": "message", "target_id": target, "payload": {"body": body}}}

    def actions(self):
        return self.broker.review_action(self.task, {"op": "action_list"})["actions"]

    def events(self):
        path = self.root / "broker-state/broker-events.jsonl"
        return path.read_bytes() if path.exists() else b""

    def run_calls(self, *calls, **changes):
        self.responses.extend([completion(*calls), final_response()])
        result = self.runtime.run_session({**self.config, **changes})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(result["framework"], "pydantic_ai")
        return result


@REQUIRES_SDK
class PydanticAiRuntimeTests(PydanticAiFixture, unittest.TestCase):
    def test_native_agent_reads_and_automatically_resumes_deferred_tool(self):
        from pydantic_ai import Agent, DeferredToolRequests, DeferredToolResults
        original, observed = Agent.run, []

        async def run(agent, *args, **kwargs):
            self.assertIsInstance(agent, Agent)
            result = await original(agent, *args, **kwargs)
            observed.append((kwargs.get("deferred_tool_results"), result))
            return result

        self.responses.extend([completion(tool_call("host-read", "yuanxingmu_read", {"resource": "note"})),
                               final_response()])
        with patch.object(Agent, "run", run):
            result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(result["steps"], 2)
        self.assertTrue(any(isinstance(row.output, DeferredToolRequests) for _, row in observed))
        approvals = [approval for approval, _ in observed if approval is not None]
        self.assertEqual(len(approvals), 1)
        self.assertIsInstance(approvals[0], DeferredToolResults)
        self.assertEqual(approvals[0].approvals, {"host-read": True})
        self.assertEqual(approvals[0].calls, {})
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertIn("LOCAL-REGISTERED-RESOURCE", json.dumps(self.upstream_requests[-1]["body"]["messages"]))
        self.assertTrue(all(row["path"] == "/v1/chat/completions" for row in self.requests))
        self.assertTrue(all(row["body"]["parallel_tool_calls"] is False for row in self.requests))
        self.assertTrue(all("Authorization" not in row["headers"] for row in self.requests))
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_native_bridge_has_no_internet_client_or_global_tracing(self):
        from pydantic_ai import Agent
        original_connect, connections = socket.socket.connect, []

        def connect(stream, address):
            connections.append(stream.family)
            if stream.family != socket.AF_UNIX:
                raise AssertionError("Native worker attempted an Internet socket")
            return original_connect(stream, address)

        self.responses.extend([completion(tool_call("host-local-read", "yuanxingmu_read", {"resource": "note"})),
                               final_response()])
        with patch.object(Agent, "_instrument_default", True), \
                patch.object(socket.socket, "connect", connect), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("Unexpected DNS lookup")):
            result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["answer"], COMPLETE)
        self.assertTrue(connections)
        self.assertEqual(set(connections), {socket.AF_UNIX})

    def test_native_email_tool_saves_draft_without_sending_or_requesting_approval(self):
        draft = {"recipient": "recipient@example.test", "subject": "Local draft", "body": "Review this text"}
        self.run_calls(tool_call("host-draft", "yuanxingmu_draft_email", {"draft": draft}))
        drafts = self.broker.review_mail(self.task, {"op": "list"})["drafts"]
        self.assertEqual(len(drafts), 1)
        self.assertEqual(drafts[0]["status"], "pending")
        full = self.broker.review_mail(self.task, {"op": "get", "draft_id": drafts[0]["id"]})["draft"]
        self.assertEqual({field: full[field] for field in draft}, draft)
        self.assertEqual(self.receipts, [])
        self.assertIn("mail_draft_saved", json.dumps(self.upstream_requests[-1]["body"]["messages"]))

    def test_plain_text_that_looks_like_a_tool_call_stays_text(self):
        answer = json.dumps(completion(tool_call("text-only", "yuanxingmu_propose_action", self.proposal())))
        self.responses.append(final_response(answer))
        result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["answer"], answer)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.upstream_requests), 1)

    def test_reused_host_nonce_in_a_later_model_round_stops_before_second_dispatch(self):
        self.responses.extend([completion(tool_call("host-repeat", "yuanxingmu_describe", {})),
                               completion(tool_call("host-repeat", "yuanxingmu_propose_action", self.proposal())),
                               final_response()])
        with self.assertRaisesRegex(ValueError, "repeated_host_nonce"):
            self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(len(self.responses), 1)
        self.assertEqual(self.actions(), [])

    def test_native_tools_strictly_validate_closed_models_and_keep_host_ids(self):
        from pydantic import ValidationError
        from pydantic_ai._function_schema import FunctionSchema
        original, dispatched = FunctionSchema.call, []

        async def call(schema, arguments, context):
            dispatched.append((schema.name, context.tool_call_id))
            return await original(schema, arguments, context)

        with patch.object(FunctionSchema, "call", call):
            self.run_calls(tool_call("host-review", "yuanxingmu_propose_action", self.proposal()),
                           tool_call("host-targets", "yuanxingmu_action_targets", {}))
        self.assertEqual(dispatched, [("yuanxingmu_propose_action", "host-review"),
                                      ("yuanxingmu_action_targets", "host-targets")])
        loop = self.runtime._Loop(self.config, self.runtime.Checkpoint({**self.config, "resume": True}))
        for tool in loop.function_tools.values():
            self.assertTrue(tool.requires_approval)
            self.assertTrue(tool.sequential)
            self.assertEqual(tool.max_retries, 0)
            self.assertNotIn("$ref", json.dumps(next(item["function"]["parameters"] for item in loop.schemas
                                                    if item["function"]["name"] == tool.name)))
            with self.assertRaises(ValidationError):
                tool.function_schema.validator.validate_python({"extra": "forbidden"})
        with self.assertRaises(ValidationError):
            loop.function_tools["yuanxingmu_read"].function_schema.validator.validate_python({"resource": 7})
        self.assertEqual(self.actions()[0]["status"], "pending")
        self.assertEqual(self.receipts, [])

    def test_whole_batch_rejects_bad_later_arguments_before_first_proposal(self):
        self.responses.append(completion(
            tool_call("host-valid-first", "yuanxingmu_propose_action", self.proposal()),
            tool_call("host-invalid-later", "yuanxingmu_read", {"resource": 9})))
        before = self.events()
        with self.assertRaises((ValueError, RuntimeError)):
            self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(self.events(), before)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])
        self.assertEqual(len(self.upstream_requests), 1)

    def test_unregistered_tools_and_host_parameters_are_not_exposed(self):
        invalid = [("yuanxingmu_send", {"destination": "public", "body": "NO"}),
                   ("yuanxingmu_handoff_to_executor", {}),
                   ("yuanxingmu_read", {"resource": "note", "timeout_seconds": 120})]
        for index, (name, arguments) in enumerate(invalid):
            with self.subTest(name=name):
                self.responses.append(completion(tool_call(f"host-invalid-{index}", name, arguments)))
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session({**self.config, "prompt": f"Invalid tool {index}",
                                              "checkpoint": str(self.root / f"bad-{index}.json")})
                names = [tool["function"]["name"] for tool in self.upstream_requests[-1]["body"]["tools"]]
                self.assertEqual(names, ["yuanxingmu_read", "yuanxingmu_describe", "yuanxingmu_action_targets",
                                         "yuanxingmu_propose_action", "yuanxingmu_draft_email"])
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_duplicate_json_keys_and_repeated_batch_nonces_fail_closed(self):
        repeated = completion(tool_call("same", "yuanxingmu_describe", {}),
                              tool_call("same", "yuanxingmu_action_targets", {}))
        duplicate = completion(tool_call("duplicate", "yuanxingmu_read", {}))
        duplicate["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = '{"resource":"note","resource":"other"}'
        for index, response in enumerate((repeated, duplicate)):
            with self.subTest(index=index):
                self.responses.append(response)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session({**self.config, "prompt": f"Malformed {index}",
                                              "checkpoint": str(self.root / f"malformed-{index}.json")})
        self.assertEqual(self.actions(), [])

    def test_native_completed_checkpoint_reopen_is_exact_without_model_or_tool(self):
        self.run_calls(tool_call("host-review", "yuanxingmu_propose_action", self.proposal()))
        path = Path(self.config["checkpoint"])
        checkpoint, requests, events = path.read_bytes(), len(self.requests), self.events()
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(len(self.requests), requests)
        self.assertEqual(self.events(), events)
        self.assertEqual(path.read_bytes(), checkpoint)
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.receipts, [])

    def test_native_history_new_user_turn_retains_first_answer_and_task(self):
        self.responses.append(final_response("first answer"))
        self.runtime.run_session(deepcopy(self.config))
        self.responses.append(final_response("second answer"))
        result = self.runtime.run_session({**self.config, "resume": True, "prompt": "A new user turn"})
        self.assertEqual(result["answer"], "second answer")
        self.assertEqual(result["steps"], 1)
        self.assertEqual(self.upstream_requests[-1]["body"]["messages"][-2:],
                         [{"role": "assistant", "content": "first answer"}, {"role": "user", "content": "A new user turn"}])
        saved = json.loads(Path(self.config["checkpoint"]).read_bytes())
        self.assertEqual(saved["binding"]["task_id"], self.task)
        self.assertEqual(len(saved["native"]), 4)

    def test_max_steps_stops_before_an_extra_model_request_and_allows_larger_resume(self):
        self.responses.extend([completion(tool_call("host-step1", "yuanxingmu_describe", {})),
                               completion(tool_call("host-step2", "yuanxingmu_action_targets", {})), final_response()])
        with self.assertRaisesRegex(RuntimeError, "max_steps"):
            self.runtime.run_session({**self.config, "max_steps": 1})
        self.assertEqual(len(self.upstream_requests), 1)
        result = self.runtime.run_session({**self.config, "resume": True, "max_steps": 3})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(result["steps"], 3)
        self.assertEqual(len(self.upstream_requests), 3)

    def test_checkpoint_unknown_fields_native_provider_content_and_bindings_are_rejected(self):
        self.responses.append(final_response())
        self.runtime.run_session(deepcopy(self.config))
        path = Path(self.config["checkpoint"])
        original = json.loads(path.read_bytes())
        mutations = [lambda state: state["native"][-1].update(unknown_native_option=True),
                     lambda state: state["native"][-1].update(provider_url="https://invalid.local"),
                     lambda state: state["native"][-1].update(state="suspended"),
                     lambda state: state["binding"].update(task_id="forged")]
        for mutate in mutations:
            saved = deepcopy(original)
            mutate(saved)
            raw = json.dumps(saved).encode()
            path.write_bytes(raw)
            with self.assertRaises((ValueError, RuntimeError)):
                self.runtime.run_session({**self.config, "resume": True})
            self.assertEqual(path.read_bytes(), raw)
        self.assertEqual(len(self.upstream_requests), 1)

    def test_cli_failure_redacts_configuration_and_sdk_errors(self):
        config = {**self.config, "model_id": "PRIVATE-MODEL-URL-SECRET", "extra": "PRIVATE-TOKEN"}
        path = self.root / "invalid-config.json"
        path.write_text(json.dumps(config))
        completed = subprocess.run([sys.executable, "-m", "yuanxingmu.adapters.pydantic_ai_runtime",
                                    "--config", str(path)], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(json.loads(completed.stdout), {"status": "failed", "reason": "sdk_session_failed"})
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
