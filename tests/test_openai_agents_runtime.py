"""Real OpenAI Agents loops with a local journal and real Broker Unix RPC.

Model replies are deterministic fixtures. These tests exercise Runner,
native FunctionTool dispatch, handoff and RunState recovery, not inference or
the process sandbox. They do not require the separate smolagents environment.
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
HAS_SDK = all(importlib.util.find_spec(name) is not None for name in ("agents", "openai", "pydantic"))
REQUIRES_SDK = unittest.skipUnless(sys.platform.startswith("linux") and HAS_SDK,
                                  "Requires Linux and the pinned OpenAI Agents SDK environment")
COMPLETE = "LOCAL-OPENAI-AGENTS-LOOP-COMPLETE"
RESEARCHER = "yuanxingmu_researcher"
EXECUTOR = "yuanxingmu_executor"
HANDOFF = "yuanxingmu_handoff_to_executor"


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


def handoff_response(nonce="host-handoff"):
    return completion(tool_call(nonce, HANDOFF, {}))


class UnixHTTPServer(socketserver.ThreadingMixIn, getattr(socketserver, "UnixStreamServer", socketserver.TCPServer)):
    daemon_threads = True


class OpenaiAgentsFixture:
    enable_automation = False

    def setUp(self):
        from yuanxingmu.adapters import openai_agents_runtime
        self.runtime = openai_agents_runtime
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"OPENAI_AGENTS_DISABLE_TRACING": "1", "OTEL_SDK_DISABLED": "true"}).start()
        temporary = tempfile.TemporaryDirectory(prefix="yxm-openai_agents-loop-")
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
        self.client = NativeTools(str(endpoint), "host-openai_agents-session")

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
        self.config = {"version": 1, "framework": "openai_agents", "session_id": self.client.session_id,
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
    def proposal(body="LOCAL-OPENAI-AGENTS-PROGRESS", *, target="chat"):
        return {"proposal": {"kind": "message", "target_id": target, "payload": {"body": body}}}

    def actions(self):
        return self.broker.review_action(self.task, {"op": "action_list"})["actions"]

    def events(self):
        path = self.root / "broker-state/broker-events.jsonl"
        return path.read_bytes() if path.exists() else b""

    def run_calls(self, *calls, **changes):
        self.responses.extend([handoff_response(), completion(*calls), final_response()])
        result = self.runtime.run_session({**self.config, **changes})
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(result["framework"], "openai_agents")
        return result


@REQUIRES_SDK
class OpenaiAgentsRuntimeTests(OpenaiAgentsFixture, unittest.TestCase):
    def test_native_runner_reads_registered_resource_before_answer(self):
        from agents import Agent, FunctionTool, Runner, RunState
        original = Runner.run
        observed = []

        async def runner(starting_agent, input, *args, **kwargs):
            self.assertIsInstance(starting_agent, Agent)
            self.assertEqual(starting_agent.name, RESEARCHER)
            self.assertTrue(all(isinstance(tool, FunctionTool) and tool.needs_approval is True
                                for tool in starting_agent.tools))
            result = await original(starting_agent, input, *args, **kwargs)
            observed.append((isinstance(input, RunState), result))
            return result

        self.responses.extend([completion(tool_call("host-read", "yuanxingmu_read", {"resource": "note"})),
                               final_response()])
        with patch.object(Runner, "run", staticmethod(runner)):
            result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(result["framework"], "openai_agents")
        self.assertTrue(observed)
        self.assertTrue(any(native for native, _ in observed))
        self.assertTrue(any(row.interruptions for _, row in observed))
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertIn("LOCAL-REGISTERED-RESOURCE", json.dumps(self.upstream_requests[-1]["body"]["messages"]))
        self.assertTrue(all(row["path"] == "/v1/chat/completions" for row in self.requests))
        self.assertTrue(all(not row["body"].get("stream", False) for row in self.requests))
        self.assertTrue(all("Authorization" not in row["headers"] for row in self.requests))
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_native_handoff_and_serial_approvals_preserve_host_call_ids(self):
        from agents import Runner
        from agents.run_internal import tool_execution
        original_runner = Runner.run
        original_tool = tool_execution._invoke_function_tool_with_metadata
        results, dispatched = [], []

        async def runner(*args, **kwargs):
            result = await original_runner(*args, **kwargs)
            results.append(result)
            return result

        async def invoke(*, function_tool, context, arguments):
            dispatched.append((function_tool.name, context.tool_call_id, context.agent.name))
            return await original_tool(function_tool=function_tool, context=context, arguments=arguments)

        self.responses.extend([handoff_response(),
                               completion(tool_call("host-proposal-one", "yuanxingmu_propose_action", self.proposal("one")),
                                          tool_call("host-proposal-two", "yuanxingmu_propose_action", self.proposal("two"))),
                               final_response()])
        with patch.object(Runner, "run", staticmethod(runner)), \
                patch.object(tool_execution, "_invoke_function_tool_with_metadata", invoke):
            result = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(result["answer"], COMPLETE)
        self.assertTrue(any(item.type == "handoff_output_item" for row in results for item in row.new_items))
        self.assertEqual(dispatched, [("yuanxingmu_propose_action", "host-proposal-one", EXECUTOR),
                                      ("yuanxingmu_propose_action", "host-proposal-two", EXECUTOR)])
        self.assertTrue(all(row.last_agent.name == EXECUTOR for row in results))
        self.assertEqual(len(self.upstream_requests), 3)
        self.assertGreaterEqual(len(self.requests), 6)
        first_names = {tool["function"]["name"] for tool in self.upstream_requests[0]["body"]["tools"]}
        executor_names = {tool["function"]["name"] for tool in self.upstream_requests[1]["body"]["tools"]}
        self.assertEqual(first_names, {"yuanxingmu_read", "yuanxingmu_describe", "yuanxingmu_action_targets", HANDOFF})
        self.assertNotIn("yuanxingmu_read", executor_names)
        self.assertNotIn(HANDOFF, executor_names)
        self.assertNotIn("yuanxingmu_request_action", executor_names)
        self.assertIn("host-handoff", json.dumps(self.upstream_requests[1]["body"]["messages"]))
        self.assertEqual(len(self.actions()), 2)
        self.assertTrue(all(row["status"] == "pending" for row in self.actions()))
        self.assertEqual(self.receipts, [])

    def test_completed_checkpoint_resumes_without_model_or_duplicate_actions(self):
        first = self.run_calls(tool_call("host-completed", "yuanxingmu_propose_action", self.proposal()))
        checkpoint = Path(self.config["checkpoint"])
        self.assertIsInstance(json.loads(checkpoint.read_bytes()), dict)
        count = len(self.requests)
        resumed = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(resumed["answer"], first["answer"])
        self.assertEqual(len(self.requests), count)
        self.assertEqual(len(self.actions()), 1)
        self.assertEqual(self.receipts, [])

    def test_checkpoint_rejects_overwrite_or_different_authority_binding(self):
        self.responses.append(final_response())
        self.runtime.run_session(deepcopy(self.config))
        checkpoint = Path(self.config["checkpoint"])
        original, count = checkpoint.read_bytes(), len(self.requests)
        variants = [deepcopy(self.config), {**self.config, "resume": True, "session_id": "different-session"},
                    {**self.config, "resume": True, "task_id": self.broker.create_task()},
                    {**self.config, "resume": True, "automatic_actions": True}]
        for config in variants:
            with self.subTest(config=config):
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session(config)
                self.assertEqual(checkpoint.read_bytes(), original)
                self.assertEqual(len(self.requests), count)

    def test_missing_or_corrupt_checkpoint_fails_before_model_and_broker(self):
        checkpoint = Path(self.config["checkpoint"])
        before = self.events()
        with self.assertRaises((ValueError, RuntimeError, OSError)):
            self.runtime.run_session({**self.config, "resume": True})
        for content in (b'{"version":1,broken', b'[]', b'null'):
            with self.subTest(content=content):
                checkpoint.write_bytes(content)
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session({**self.config, "resume": True})
                self.assertEqual(checkpoint.read_bytes(), content)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.events(), before)

    def test_invalid_member_rejects_entire_executor_tool_batch_before_broker(self):
        invalid = [tool_call("host-unknown", "unknown_sender", {}),
                   tool_call("host-direct-send", "yuanxingmu_send", {"destination": "public", "body": "blocked"}),
                   tool_call("host-forged", "yuanxingmu_propose_action",
                             {**self.proposal(), "tool_call_id": "forged", "approved": True})]
        for index, bad in enumerate(invalid):
            with self.subTest(tool=bad["function"]["name"]):
                self.responses.extend([handoff_response(f"handoff-invalid-{index}"), completion(
                    tool_call(f"host-valid-{index}", "yuanxingmu_propose_action", self.proposal()), bad)])
                before = self.events()
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session({**self.config, "prompt": f"Validate batch {index}.",
                                              "checkpoint": str(self.root / f"invalid-{index}.json")})
                self.assertEqual(self.events(), before)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])

    def test_researcher_cannot_invoke_executor_actions_or_forged_handoff(self):
        variants = [completion(tool_call("host-wrong-role", "yuanxingmu_propose_action", self.proposal())),
                    completion(tool_call("host-forged-target", HANDOFF, {"agent": "foreign_executor"})),
                    completion(tool_call("host-mixed-handoff", HANDOFF, {}),
                               tool_call("host-mixed-read", "yuanxingmu_read", {"resource": "note"})),
                    completion(tool_call("host-unknown-handoff", "transfer_to_other_agent", {}))]
        for index, response in enumerate(variants):
            with self.subTest(case=index):
                self.responses.append(response)
                before = self.events()
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session({**self.config, "prompt": f"Invalid agent role {index}.",
                                              "checkpoint": str(self.root / f"role-{index}.json")})
                self.assertEqual(self.events(), before)
        self.assertEqual(self.actions(), [])

    def test_executor_cannot_read_or_handoff_back(self):
        for index, bad in enumerate((tool_call("host-executor-read", "yuanxingmu_read", {"resource": "note"}),
                                     tool_call("host-return", "yuanxingmu_handoff_to_researcher", {}),
                                     tool_call("host-repeat-handoff", HANDOFF, {}))):
            with self.subTest(case=index):
                self.responses.extend([handoff_response(f"host-role-handoff-{index}"), completion(bad)])
                before = self.events()
                with self.assertRaises((ValueError, RuntimeError)):
                    self.runtime.run_session({**self.config, "prompt": f"Invalid executor role {index}.",
                                              "checkpoint": str(self.root / f"executor-{index}.json")})
                self.assertEqual(self.events(), before)
        self.assertEqual(self.actions(), [])

    def test_multiple_model_choices_fail_before_tool_dispatch(self):
        response = completion(tool_call("host-choice", "yuanxingmu_read", {"resource": "note"}))
        response["choices"].append(deepcopy(response["choices"][0]))
        self.responses.append(response)
        before = self.events()
        with self.assertRaises((ValueError, RuntimeError)):
            self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(self.events(), before)
        self.assertEqual(self.actions(), [])

    def test_new_turn_keeps_history_and_uses_new_answer(self):
        self.responses.append(final_response("FIRST-ANSWER"))
        first = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(first["answer"], "FIRST-ANSWER")
        self.responses.append(final_response("SECOND-ANSWER"))
        second = self.runtime.run_session({**self.config, "resume": True, "prompt": "Continue with a new question."})
        self.assertEqual(second["answer"], "SECOND-ANSWER")
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertIn("FIRST-ANSWER", json.dumps(self.upstream_requests[-1]["body"]["messages"]))
        self.assertEqual(self.actions(), [])

    def test_model_schema_inlining_preserves_action_contract(self):
        config = {**self.config, "automatic_actions": True}
        loop = self.runtime._Loop(config, self.runtime.Checkpoint(config))
        name = self.runtime.AUTOMATIC_TOOL
        native = deepcopy(loop.function_tools[name].params_json_schema)
        parameters = next(tool["function"]["parameters"] for tool in loop.schemas[self.runtime.EXECUTOR]
                          if tool["function"]["name"] == name)
        self.assertIn("$defs", native)
        self.assertNotIn("$defs", parameters)
        self.assertEqual(parameters["required"], ["proposal"])
        self.assertIs(parameters["additionalProperties"], False)
        branches = {branch["properties"]["kind"]["const"]: branch
                    for branch in parameters["properties"]["proposal"]["anyOf"]}
        self.assertEqual(set(branches), {"message", "upload", "form"})
        for kind, payload_fields in (("message", {"body"}), ("upload", {"filename", "content"}),
                                     ("form", {"fields"})):
            branch = branches[kind]
            self.assertEqual(branch["type"], "object")
            self.assertEqual(set(branch["required"]), {"kind", "target_id", "payload"})
            self.assertIs(branch["additionalProperties"], False)
            payload = branch["properties"]["payload"]
            self.assertEqual(payload["type"], "object")
            self.assertEqual(set(payload["required"]), payload_fields)
            self.assertEqual(set(payload["properties"]), payload_fields)
            self.assertIs(payload["additionalProperties"], False)
        fields = branches["form"]["properties"]["payload"]["properties"]["fields"]
        self.assertEqual(fields["maxItems"], 64)
        self.assertEqual(set(fields["items"]["required"]), {"name", "value"})
        self.assertIs(fields["items"]["additionalProperties"], False)
        valid = [self.proposal("message"),
                 {"proposal": {"kind": "upload", "target_id": "upload",
                               "payload": {"filename": "report.txt", "content": "report"}}},
                 {"proposal": {"kind": "form", "target_id": "form",
                               "payload": {"fields": [{"name": "note", "value": "report"}]}}}]
        for index, arguments in enumerate(valid):
            with self.subTest(valid=index):
                message = completion(tool_call("host-schema-" + str(index), name, arguments))["choices"][0]["message"]
                self.assertEqual(loop.calls(message, self.runtime.EXECUTOR)[0]["arguments"], arguments)
        extra = deepcopy(valid[0])
        extra["proposal"]["approved"] = True
        missing = deepcopy(valid[0])
        del missing["proposal"]["target_id"]
        too_many = deepcopy(valid[2])
        too_many["proposal"]["payload"]["fields"] = [{"name": str(index), "value": "report"} for index in range(65)]
        invalid = [{"proposal": json.dumps(valid[0]["proposal"])}, extra, missing, too_many,
                   {**valid[0], "request_key": "forged"},
                   {"proposal": {"kind": "overwrite", "target_id": "replace", "payload": {"content": "changed"}}},
                   {"proposal": {"kind": "delete", "target_id": "remove", "payload": {}}}]
        for index, arguments in enumerate(invalid):
            with self.subTest(invalid=index):
                message = completion(tool_call("host-invalid-schema-" + str(index), name, arguments))["choices"][0]["message"]
                with self.assertRaises(ValueError):
                    loop.calls(message, self.runtime.EXECUTOR)
        inline = self.runtime.inline_model_schema
        literal = {"title": "literal data", "$ref": "literal data"}
        example = {"$defs": {"A/B": {"type": "string", "minLength": 3}}, "type": "object",
                   "properties": {"title": {"$ref": "#/$defs/A~1B", "minLength": 1},
                                  "$ref": {"const": literal}}, "required": ["title", "$ref"],
                   "additionalProperties": False}
        expanded = inline(example)
        self.assertEqual(expanded["properties"]["title"],
                         {"allOf": [{"type": "string", "minLength": 3}, {"minLength": 1}]})
        self.assertEqual(expanded["properties"]["$ref"]["const"], literal)
        for unsupported in ({"$ref": "https://example.invalid/schema"}, {"$ref": "#/$defs/missing"},
                            {"$defs": {"A": {"$ref": "#/$defs/A"}}, "$ref": "#/$defs/A"},
                            {"$defs": {"A": {"type": "object", "properties": {"a": {"type": "string"}}}},
                             "$ref": "#/$defs/A", "unevaluatedProperties": False},
                            {"$defs": {"A": {"type": "array", "prefixItems": [{"type": "string"}]}},
                             "$ref": "#/$defs/A", "unevaluatedItems": False}):
            with self.subTest(unsupported=unsupported):
                with self.assertRaises(ValueError):
                    inline(unsupported)
        self.assertEqual(loop.function_tools[name].params_json_schema, native)
        self.assertEqual(self.requests, [])
        self.assertEqual(self.actions(), [])

    def test_new_turn_restarts_researcher_with_complete_history_and_identical_final_response(self):
        self.responses.extend([
            completion(tool_call("host-first-turn-read", "yuanxingmu_read", {"resource": "note"})),
            handoff_response("host-first-turn-handoff"),
            completion(tool_call("host-first-turn-action", "yuanxingmu_propose_action", self.proposal("first turn"))),
            final_response()])
        first = self.runtime.run_session(deepcopy(self.config))
        self.assertEqual(first["answer"], COMPLETE)
        count = len(self.upstream_requests)
        self.responses.extend([
            handoff_response("host-second-turn-handoff"),
            completion(tool_call("host-second-turn-action", "yuanxingmu_propose_action", self.proposal("second turn"))),
            final_response()])
        second = self.runtime.run_session({**self.config, "resume": True,
                                           "prompt": "Prepare a second reviewed update using the earlier reading."})
        self.assertEqual(second["answer"], COMPLETE)
        second_start = self.upstream_requests[count]["body"]
        names = {item["function"]["name"] for item in second_start["tools"]}
        self.assertIn("yuanxingmu_read", names)
        self.assertIn(HANDOFF, names)
        self.assertNotIn("yuanxingmu_propose_action", names)
        history = json.dumps(second_start["messages"])
        for retained in ("host-first-turn-read", "LOCAL-REGISTERED-RESOURCE", "host-first-turn-handoff",
                         "host-first-turn-action", COMPLETE):
            self.assertIn(retained, history)
        self.assertEqual(len(self.upstream_requests), 7)
        self.assertEqual(len(self.actions()), 2)
        self.assertTrue(all(item["status"] == "pending" for item in self.actions()))
        self.assertEqual(self.receipts, [])
        count = len(self.requests)
        resumed = self.runtime.run_session({**self.config, "resume": True,
                                            "prompt": "Prepare a second reviewed update using the earlier reading."})
        self.assertEqual(resumed["answer"], COMPLETE)
        self.assertEqual(len(self.requests), count)

    def test_step_limit_has_no_extra_model_summary_or_resume_retry(self):
        self.responses.append(completion(tool_call("host-limit", "yuanxingmu_describe", {})))
        config = {**self.config, "max_steps": 1}
        with self.assertRaisesRegex(RuntimeError, "max_steps"):
            self.runtime.run_session(config)
        count = len(self.requests)
        self.assertEqual(len(self.upstream_requests), 1)
        with self.assertRaisesRegex(RuntimeError, "max_steps"):
            self.runtime.run_session({**config, "resume": True})
        self.assertEqual(len(self.requests), count)

    def test_worker_error_output_hides_prompt_and_upstream_body(self):
        prompt_secret = "SYNTHETIC-PRIVATE-OPENAI-AGENTS-PROMPT-DO-NOT-PRINT"
        response_secret = "SYNTHETIC-PRIVATE-UPSTREAM-BODY-DO-NOT-PRINT"
        self.responses.append((500, {"error": {"message": response_secret}}))
        path = self.root / "worker-config.json"
        path.write_text(json.dumps({**self.config, "prompt": prompt_secret}), encoding="utf-8")
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        result = subprocess.run([sys.executable, "-B", "-m", "yuanxingmu.adapters.openai_agents_runtime",
                                 "--config", str(path)], cwd=ROOT, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.upstream_requests), 1)
        self.assertNotIn(prompt_secret, result.stdout + result.stderr)
        self.assertNotIn(response_secret, result.stdout + result.stderr)
        self.assertEqual(self.actions(), [])
        self.assertEqual(self.receipts, [])


if __name__ == "__main__":
    unittest.main()
