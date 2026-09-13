"""Native Google ADK Agent loops with local deterministic model replies.

The fixtures exercise actual native tool dispatch, agent transfer, native
session recovery and real Broker Unix RPC. They do not test model inference
or the process sandbox; host integration tests cover the latter separately.
"""
from collections import deque
from contextlib import aclosing
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
try:
    HAS_SDK = importlib.util.find_spec("google.adk") is not None
except ModuleNotFoundError:
    HAS_SDK = False
REQUIRES_SDK = unittest.skipUnless(sys.platform.startswith("linux") and HAS_SDK,
                                  "Requires Linux and the pinned Google ADK SDK environment")
COMPLETE = "LOCAL-GOOGLE-ADK-LOOP-COMPLETE"


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


class GoogleAdkFixture:
    enable_automation = False

    def setUp(self):
        from yuanxingmu.adapters import google_adk_runtime
        self.runtime = google_adk_runtime
        self.addCleanup(patch.stopall)
        patch.dict(os.environ, {"OTEL_SDK_DISABLED": "true"}).start()
        temporary = tempfile.TemporaryDirectory(prefix="yxm-google_adk-loop-")
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
        endpoint = self.root / "worker.sock"
        self.client = NativeTools(str(endpoint), "host-google_adk-session")

        class RecordedModel:
            """Only already committed deterministic model replies can bind tools."""
            def lookup_tool_call(self, nonce):
                found = []
                with owner.response_lock:
                    for entry in owner.journal.values():
                        status, body = entry if isinstance(entry, tuple) else (200, entry)
                        if status == 200:
                            found.extend(call for choice in body.get("choices", [])
                                         for call in choice.get("message", {}).get("tool_calls") or []
                                         if call.get("id") == nonce)
                if len(found) != 1:
                    raise RuntimeError("sdk_model_tool_call_not_found")
                return deepcopy(found[0])

        from yuanxingmu.sdk_tool_store import SdkToolServer
        self.model_ledger = RecordedModel()
        self.tool_private = self.root / "host-tool-results"
        self.tool_server = SdkToolServer(self.broker, self.task, endpoint, self.tool_private,
                                        self.client.session_id, self.model_ledger,
                                        automatic_actions=self.enable_automation)
        self.enterContext(self.tool_server)

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
                        elif self.path == "/v1/chat/completions/replay":
                            reply = (409, {"error": "committed response unavailable"})
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
        self.config = {"version": 1, "framework": "google_adk", "session_id": self.client.session_id,
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
    def proposal(body="LOCAL-GOOGLE-ADK-PROGRESS", *, target="chat"):
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
        self.assertEqual(result["framework"], "google_adk")
        return result

    def saved(self):
        return json.loads(Path(self.config["checkpoint"]).read_text())

    def transfer(self, nonce="host-transfer"):
        return tool_call(nonce, "transfer_to_agent", {"agent_name": "yuanxingmu_executor"})

    def run_executor(self, *calls, **changes):
        self.responses.extend([completion(self.transfer()), completion(*calls), final_response()])
        return self.runtime.run_session({**self.config, **changes})

    def interrupt_after(self, predicate, **changes):
        from google.adk.runners import Runner
        original = Runner.run_async

        async def run(runner, **kwargs):
            async with aclosing(original(runner, **kwargs)) as events:
                async for event in events:
                    yield event
                    if predicate(event):
                        raise RuntimeError("fixture_consumer_interruption")

        with patch.object(Runner, "run_async", run), self.assertRaisesRegex(RuntimeError, "fixture_consumer_interruption"):
            self.runtime.run_session({**self.config, **changes})
        return self.saved()


@REQUIRES_SDK
class GoogleAdkRuntimeTests(GoogleAdkFixture, unittest.TestCase):
    def test_real_runner_app_session_and_read(self):
        from google.adk.runners import Runner
        original, observed = Runner.run_async, []

        async def run(runner, **kwargs):
            observed.append((runner, kwargs))
            async for event in original(runner, **kwargs):
                yield event

        with patch.object(Runner, "run_async", run):
            result = self.run_calls(tool_call("host-read", "yuanxingmu_read", {"resource": "note"}))
        self.assertEqual(result["steps"], 2)
        self.assertEqual(len(observed), 1)
        runner, kwargs = observed[0]
        self.assertTrue(runner.app.resumability_config.is_resumable)
        self.assertEqual(kwargs["invocation_id"], self.saved()["invocation_id"])
        self.assertEqual(self.saved()["native"]["state"], {})
        self.assertEqual(len(self.saved()["native"]["events"]), 5)
        self.assertIn("LOCAL-REGISTERED-RESOURCE", json.dumps(self.upstream_requests[-1]["body"]["messages"]))

    def test_native_transfer_changes_agent_and_available_tools(self):
        result = self.run_executor(tool_call("host-draft", "yuanxingmu_draft_email", {"draft": {"recipient": "draft@example.test", "subject": "Progress", "body": "Draft only"}}))
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(self.receipts, [])
        native = self.saved()["native"]["events"]
        transfer = next(event for event in native if event["actions"].get("transfer_to_agent"))
        self.assertEqual(transfer["actions"]["transfer_to_agent"], "yuanxingmu_executor")
        self.assertTrue(any(event["node_info"]["path"] == "yuanxingmu_coordinator@1/yuanxingmu_executor@1" for event in native))
        inventories = [{tool["function"]["name"] for tool in row["body"]["tools"]} for row in self.upstream_requests]
        self.assertIn("transfer_to_agent", inventories[0])
        self.assertNotIn("yuanxingmu_draft_email", inventories[0])
        self.assertNotIn("transfer_to_agent", inventories[1])
        self.assertNotIn("yuanxingmu_read", inventories[1])
        self.assertIn("yuanxingmu_draft_email", inventories[1])

    def test_completed_reopen_verifies_originals_without_new_generation_or_effect(self):
        first = self.run_calls(tool_call("host-read", "yuanxingmu_read", {"resource": "note"}))
        count, upstream, receipts = len(self.requests), len(self.upstream_requests), deepcopy(self.receipts)
        second = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(first, second)
        self.assertEqual(len(self.requests), count + 2)
        self.assertTrue(all(row["path"] == "/v1/chat/completions/replay" for row in self.requests[count:]))
        self.assertEqual(len(self.upstream_requests), upstream)
        self.assertEqual(receipts, self.receipts)

    def test_native_transfer_caption_survives_interruption_and_rejects_tampering(self):
        caption = "资料已准备好，接下来交给执行助手。"
        response = completion(self.transfer())
        response["choices"][0]["message"]["content"] = caption
        self.responses.extend([response, final_response()])
        interrupted = self.interrupt_after(lambda event: event.actions.transfer_to_agent is not None)
        self.assertEqual(len(self.upstream_requests), 1)
        self.assertTrue(any(event["content"]["parts"][0].get("text") == caption
                            for event in interrupted["native"]["events"] if "content" in event))
        result = self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(result["answer"], COMPLETE)
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(self.receipts, [])
        count = len(self.upstream_requests)
        self.assertEqual(self.runtime.run_session({**self.config, "resume": True}), result)
        self.assertEqual(len(self.upstream_requests), count)
        requests = len(self.requests)
        changed = self.saved()
        event = next(event for event in changed["native"]["events"]
                     if any("function_call" in part for part in event.get("content", {}).get("parts", [])))
        event["content"]["parts"][0]["text"] = "Forged transfer explanation."
        Path(self.config["checkpoint"]).write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "sdk_native_replay_changed"):
            self.runtime.run_session({**self.config, "resume": True})
        self.assertEqual(len(self.requests), requests)

    def test_new_turn_keeps_native_conversation(self):
        self.run_calls(tool_call("host-read", "yuanxingmu_read", {"resource": "note"}))
        first = self.saved()
        self.responses.append(final_response("SECOND TURN"))
        outcome = self.runtime.run_session({**self.config, "resume": True, "prompt": "Report again using prior context."})
        self.assertEqual(outcome["answer"], "SECOND TURN")
        self.assertEqual(outcome["steps"], 1)
        self.assertEqual(self.saved()["round_start"], 2)
        self.assertEqual(self.saved()["native"]["events"][:5], first["native"]["events"])
        self.assertIn("LOCAL-REGISTERED-RESOURCE", json.dumps(self.upstream_requests[-1]["body"]["messages"]))

    def test_complete_batch_validated_before_any_effect(self):
        self.responses.append(completion(tool_call("good", "yuanxingmu_read", {"resource": "note"}),
                                         tool_call("bad", "unknown", {})))
        before = self.events()
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertEqual(before, self.events())
        self.assertEqual(self.saved()["records"][0]["results"], {})
        self.assertIsNone(self.saved()["records"][0]["response"])

    def test_strict_extra_field_and_type_fail_before_batch(self):
        for arguments in ({"resource": "note", "extra": True}, {"resource": 12}):
            with self.subTest(arguments=arguments):
                checkpoint = str(self.root / ("strict-" + str(len(self.requests)) + ".json"))
                self.responses.append(completion(tool_call("bad", "yuanxingmu_read", arguments)))
                # Distinct prompts prevent fixture journal reuse between invalid batches.
                with self.assertRaises(RuntimeError):
                    self.runtime.run_session({**self.config, "checkpoint": checkpoint, "prompt": repr(arguments)})
        self.assertEqual(self.receipts, [])

    def test_send_and_unavailable_automatic_tool_are_not_registered(self):
        for name in ("yuanxingmu_send", "yuanxingmu_request_action"):
            with self.subTest(name=name):
                self.responses.append(completion(tool_call("bad", name, self.proposal())))
                with self.assertRaises(RuntimeError):
                    self.runtime.run_session({**self.config, "checkpoint": str(self.root / (name + ".json")), "prompt": name})
        self.assertEqual(self.receipts, [])

    def test_transfer_target_extra_fields_and_mixed_batch_rejected(self):
        batches = [(tool_call("t", "transfer_to_agent", {"agent_name": "outside"}),),
                   (tool_call("t", "transfer_to_agent", {"agent_name": "yuanxingmu_executor", "transfer_reason": "extra"}),),
                   (self.transfer(), tool_call("r", "yuanxingmu_read", {"resource": "note"}))]
        for i, calls in enumerate(batches):
            with self.subTest(index=i):
                self.responses.append(completion(*calls))
                with self.assertRaises(RuntimeError):
                    self.runtime.run_session({**self.config, "checkpoint": str(self.root / f"transfer-{i}.json"), "prompt": f"case {i}"})
        self.assertEqual(self.receipts, [])

    def test_executor_cannot_transfer_to_parent(self):
        self.responses.extend([completion(self.transfer()), completion(tool_call("back", "transfer_to_agent", {"agent_name": "yuanxingmu_coordinator"}))])
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertEqual(len(self.upstream_requests), 2)
        self.assertEqual(self.receipts, [])

    def test_provider_media_or_code_message_is_rejected(self):
        response = final_response()
        response["choices"][0]["message"]["audio"] = {"data": "ignored"}
        self.responses.append(response)
        with self.assertRaises(RuntimeError):
            self.runtime.run_session(self.config)
        self.assertEqual(self.receipts, [])
