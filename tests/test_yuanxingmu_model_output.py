"""Protocol and real Unix HTTP checks with synthetic local provider replies.

No model or native Agent runs. These verify admission and delivery boundaries,
not semantic detection accuracy. Tool arguments retain their separate native
action checks; this response layer inspects prose, refusal and reasoning text.
"""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import select
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from yuanxingmu import gateway_network as network
from yuanxingmu import model_output as output
from yuanxingmu.authority import AuthorizationError
from yuanxingmu.broker import Broker
from yuanxingmu.guards import GuardPolicy, Guards, JudgeConfig


def _json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _completion(text="合成回答", *, message=None, finish="stop"):
    return _json_bytes({"id": "synthetic-provider", "object": "chat.completion", "created": 0,
        "model": "synthetic-fixture", "choices": [{"index": 0, "finish_reason": finish,
        "message": {"role": "assistant", "content": text} if message is None else message}]})


def _event(delta, finish=None):
    return b"data: " + _json_bytes({"id": "synthetic-provider", "object": "chat.completion.chunk",
        "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}) + b"\n\n"


def _stream(text="合成回答"):
    return _event({"role": "assistant", "content": text}) + _event({}, "stop") + b"data: [DONE]\n\n"


def _judge_reply(verdict="allow"):
    # The security reviewer uses the same supported chat envelope, but returns
    # a synthetic, explicit verdict. This fixture is never a real model.
    return _completion(json.dumps({"verdict": verdict, "reason": "合成协议测试判定。"}, ensure_ascii=False))


def _send(handler, body, content_type="application/json", status=200):
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Connection", "close")
    handler.end_headers()
    handler.wfile.write(body)
    handler.wfile.flush()


@contextmanager
def _provider(reply):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            self.server.receipts.append({"path": self.path, "body": body})
            try:
                self.server.reply(self)
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.receipts, server.reply = [], reply
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


class ModelOutputParserTests(unittest.TestCase):
    def test_json_collects_full_content_refusal_and_both_reasoning_fields(self):
        text = "正文" * 40000 + "FULL_CONTENT_TAIL"
        raw = _completion(message={"role": "assistant", "content": text,
            "refusal": "拒绝内容", "reasoning": "思考甲", "reasoning_content": "思考乙"})
        parsed = output.inspect_text(raw, "application/json; charset=utf-8")
        self.assertIn(text, parsed)
        self.assertIn("refusal:\n拒绝内容", parsed)
        self.assertIn("reasoning:\n思考甲", parsed)
        self.assertIn("reasoning_content:\n思考乙", parsed)

    def test_sse_joins_each_fragmented_text_field_before_inspection(self):
        raw = (_event({"role": "assistant", "content": "AL", "reasoning_content": "ONE"})
            + _event({"content": "PHA", "refusal": "NO"})
            + _event({"content": "_OMEGA", "refusal": "PE", "reasoning_content": "_TWO"}, "stop")
            + b'data: {"choices":[],"usage":{"total_tokens":3}}\n\n'
            + b"data: [DONE]\n\n")
        parsed = output.inspect_text(raw, "text/event-stream")
        self.assertIn("content:\nALPHA_OMEGA", parsed)
        self.assertIn("refusal:\nNOPE", parsed)
        self.assertIn("reasoning_content:\nONE_TWO", parsed)
        self.assertEqual(parsed, output.inspect_text(raw.replace(b"\n", b"\r\n"), "text/event-stream"))

    def test_supported_tool_only_response_is_not_mislabelled_as_checked_prose(self):
        raw = _completion(message={"role": "assistant", "content": None,
            "tool_calls": [{"id": "fixture-call", "type": "function",
                "function": {"name": "terminal", "arguments": '{"command":"printf synthetic"}'}}]}, finish="tool_calls")
        self.assertEqual(output.inspect_text(raw, "application/json"), "")
        # Deliberately no assertion that tool arguments were semantically checked.

    def test_invalid_or_ambiguous_json_cannot_be_accepted_as_complete_text(self):
        valid = json.loads(_completion())
        cases = [b'{"choices":[],"choices":[]}', b'{"choices":[],"score":NaN}', b'{"choices":', b'[]']
        for change in (
            {"choices": []}, {"choices": valid["choices"] * 2},
            {"choices": [{**valid["choices"][0], "index": True}]},
            {"choices": [{**valid["choices"][0], "finish_reason": "length"}]},
            {"choices": [{**valid["choices"][0], "message": {"role": "user", "content": "WRONG_ROLE"}}]},
            {"choices": [{**valid["choices"][0], "message": {"role": "assistant", "content": [{"text": "UNKNOWN_ARRAY"}]}}]},
            {"choices": [{**valid["choices"][0], "message": {"role": "assistant", "content": "visible", "audio": {"transcript": "UNSCANNED"}}}]},
        ):
            cases.append(_json_bytes({**valid, **change}))
        for raw in cases:
            with self.subTest(raw=raw[:60]), self.assertRaises(output.InvalidModelOutput):
                output.inspect_text(raw, "application/json")

    def test_incomplete_or_trailing_sse_never_becomes_an_accepted_answer(self):
        for raw in (
            _event({"content": "UNFINISHED"}),
            _event({"content": "MISSING_FINISH"}) + b"data: [DONE]\n\n",
            _stream()[:-1],
            _stream() + _event({"content": "AFTER_DONE"}),
            _event({"content": "STOP"}, "stop") + _event({"content": "AFTER_FINISH"}) + b"data: [DONE]\n\n",
            _event({"content": "TRUNCATED"}, "length") + b"data: [DONE]\n\n",
            b'data: {"choices":[]}\n\ndata: [DONE]\n\n',
            b"event: unknown\n" + _stream(),
            b"\xff\xfe" + _stream(),
        ):
            with self.subTest(raw=raw[:50]), self.assertRaises(output.InvalidModelOutput):
                output.inspect_text(raw, "text/event-stream")

    def test_unsupported_media_and_oversize_fail_without_prefix_truncation(self):
        with self.assertRaises(output.InvalidModelOutput):
            output.inspect_text(_completion(), "application/octet-stream")
        with patch.object(output, "MAX_RESPONSE", 128), self.assertRaises(output.InvalidModelOutput):
            output.inspect_text(_completion("FULL_TAIL" * 40), "application/json")

    def test_withheld_protocol_is_explicit_host_notice_with_no_tool_calls(self):
        for content_type in ("application/json", "text/event-stream"):
            raw = output.withheld_response(content_type)
            self.assertIn(output.WITHHELD, output.inspect_text(raw, content_type))
            self.assertIn(b"yuanxingmu-host-intervention", raw)
            self.assertNotIn(b"tool_calls", raw)
            self.assertNotIn(b"function_call", raw)

    def test_admission_notices_do_not_echo_unknown_reasons_or_claim_a_checked_answer(self):
        for reason in ("task_paused", "task_revoked", "storage_fault", "defense_storage_fault",
                       "UNKNOWN_PRIVATE_REASON"):
            for content_type in ("application/json", "text/event-stream"):
                with self.subTest(reason=reason, content_type=content_type):
                    raw = output.withheld_response(content_type, reason=reason, preflight=True)
                    text = output.inspect_text(raw, content_type)
                    self.assertIn("未发送给模型", text)
                    self.assertNotIn("回答未通过检查", text)
                    self.assertNotIn("UNKNOWN_PRIVATE_REASON", text)
                    self.assertNotIn(b"tool_calls", raw)
                    self.assertNotIn(b"function_call", raw)
                    self.assertIn(b"yuanxingmu-host-intervention", raw)


@unittest.skipUnless(sys.platform.startswith("linux"), "Real Linux broker and Unix model socket")
class ModelOutputTransportTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(prefix="yxm-output-")))
        self.events = []
        self.policy = GuardPolicy("阅读合成资料并汇报结果；对外操作先由本人核对。")

    def start(self, provider_reply, *, verdict="allow", policy=None, judge_reply=None, judge_timeout=2):
        self.provider = self.stack.enter_context(_provider(provider_reply))
        self.judge = self.stack.enter_context(_provider(judge_reply or (lambda h: _send(h, _judge_reply(verdict)))))
        guards = Guards(policy or self.policy,
            JudgeConfig(f"http://127.0.0.1:{self.judge.server_port}/v1", "synthetic-fixture", timeout_seconds=judge_timeout),
            audit=self.events.append)
        self.broker = self.stack.enter_context(Broker(self.root / "state", {}, {}, guards=guards))
        self.task = self.broker.create_task()
        self.guard = output.ModelOutputGuard(self.broker, self.task)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        self.bridge = self.stack.enter_context(network.HostNetwork(self.root / "runtime",
            model_url=f"http://127.0.0.1:{self.provider.server_port}/v1", api_key="SYNTHETIC-HOST-KEY",
            webui_port=port, output_guard=self.guard))

    def connect(self, body=b'{"stream":true}'):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(connection.close)
        connection.settimeout(3)
        connection.connect(str(self.bridge.runtime / "model.sock"))
        connection.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\n"
                           + b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        return connection

    def response(self, connection):
        response = http.client.HTTPResponse(connection)
        response.begin()
        result = response.status, dict(response.getheaders()), response.read()
        response.close()
        return result

    def assert_no_bytes(self, connection):
        self.assertEqual(select.select([connection], [], [], .1)[0], [],
                         "HTTP headers or provider bytes reached the client before release")

    def test_json_allow_releases_identical_bytes_after_full_candidate_review(self):
        raw = _completion("SYNTHETIC_FULL_ANSWER_TAIL")
        self.start(lambda h: _send(h, raw))
        status, headers, delivered = self.response(self.connect())
        self.assertEqual(status, 200)
        self.assertEqual(delivered, raw)
        self.assertEqual(int(headers["Content-Length"]), len(raw))
        reviewed = json.loads(json.loads(self.judge.receipts[0]["body"])["messages"][1]["content"])
        self.assertEqual(reviewed["purpose"], "response")
        self.assertIn("SYNTHETIC_FULL_ANSWER_TAIL", reviewed["candidate"]["assistant_text"])

    def test_sse_first_chunk_waits_for_final_chunk_and_completed_check(self):
        first_sent, finish_upstream, check_started, finish_check = (threading.Event() for _ in range(4))
        self.addCleanup(finish_upstream.set)
        self.addCleanup(finish_check.set)
        first = _event({"role": "assistant", "content": "FIRST_HALF_"})
        last = _event({"content": "LAST_HALF"}, "stop") + b"data: [DONE]\n\n"
        def stream(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Transfer-Encoding", "chunked")
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.wfile.write(f"{len(first):X}\r\n".encode() + first + b"\r\n")
            handler.wfile.flush()
            first_sent.set()
            if not finish_upstream.wait(3):
                return
            handler.wfile.write(f"{len(last):X}\r\n".encode() + last + b"\r\n0\r\n\r\n")
            handler.wfile.flush()
        def reviewer(handler):
            check_started.set()
            if finish_check.wait(3):
                _send(handler, _judge_reply())
        self.start(stream, judge_reply=reviewer)
        connection = self.connect()
        self.assertTrue(first_sent.wait(2))
        self.assert_no_bytes(connection)
        self.assertFalse(check_started.is_set())
        finish_upstream.set()
        self.assertTrue(check_started.wait(2))
        self.assert_no_bytes(connection)
        finish_check.set()
        status, _, delivered = self.response(connection)
        self.assertEqual(status, 200)
        self.assertEqual(delivered, first + last)

    def test_rejection_releases_no_original_prose_or_associated_tool_call(self):
        marker = "SYNTHETIC_WITHHELD_PRIVATE_TEXT"
        raw = _completion(message={"role": "assistant", "content": marker,
            "tool_calls": [{"id": "WITHHELD_CALL_ID", "type": "function",
                "function": {"name": "WITHHELD_TOOL_NAME", "arguments": '{"body":"WITHHELD_ARGUMENTS"}'}}]}, finish="tool_calls")
        self.start(lambda h: _send(h, raw), verdict="block")
        status, _, delivered = self.response(self.connect())
        self.assertEqual(status, 200)
        self.assertIn(output.WITHHELD, output.inspect_text(delivered, "application/json"))
        for value in (marker, "WITHHELD_CALL_ID", "WITHHELD_TOOL_NAME", "WITHHELD_ARGUMENTS"):
            self.assertNotIn(value.encode(), delivered)
        self.assertTrue(self.broker.quarantine.status(self.task)["paused"])

    def test_malformed_stream_is_replaced_without_querying_the_judge(self):
        raw = _event({"content": "SYNTHETIC_INCOMPLETE_STREAM"})
        self.start(lambda h: _send(h, raw, "text/event-stream"))
        status, _, delivered = self.response(self.connect())
        self.assertEqual(status, 200)
        self.assertIn(output.WITHHELD, output.inspect_text(delivered, "text/event-stream"))
        self.assertNotIn(b"SYNTHETIC_INCOMPLETE_STREAM", delivered)
        self.assertEqual(self.judge.receipts, [])

    def test_oversize_body_sends_only_host_error_without_any_prefix(self):
        raw = _completion("SYNTHETIC_OVERSIZE_PREFIX_" * 100)
        self.start(lambda h: _send(h, raw))
        with patch.object(output, "MAX_RESPONSE", 256):
            status, _, delivered = self.response(self.connect())
        self.assertEqual(status, 502)
        self.assertIn(b"model_response_too_large", delivered)
        self.assertNotIn(b"SYNTHETIC_OVERSIZE_PREFIX", delivered)
        self.assertEqual(self.judge.receipts, [])

    def test_stalled_upstream_times_out_without_releasing_first_chunk(self):
        release = threading.Event()
        self.addCleanup(release.set)
        def stall(handler):
            handler.send_response(200)
            handler.send_header("Content-Type", "text/event-stream")
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.wfile.write(_event({"content": "SYNTHETIC_TIMEOUT_PREFIX"}))
            handler.wfile.flush()
            release.wait(3)
        self.start(stall)
        with patch.object(network, "MODEL_RESPONSE_TIMEOUT", .15):
            status, _, delivered = self.response(self.connect())
        self.assertIn(status, (502, 504))
        self.assertNotIn(b"SYNTHETIC_TIMEOUT_PREFIX", delivered)
        self.assertEqual(self.judge.receipts, [])
        release.set()

    def test_judge_timeout_withholds_complete_answer_and_never_releases_late_allow(self):
        release, late_done = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def slow_judge(handler):
            if release.wait(3):
                try:
                    _send(handler, _judge_reply())
                finally:
                    late_done.set()
        self.start(lambda h: _send(h, _completion("SYNTHETIC_LATE_ALLOW")), judge_reply=slow_judge, judge_timeout=.15)
        connection = self.connect()
        status, _, delivered = self.response(connection)
        self.assertEqual(status, 200)
        self.assertNotIn(b"SYNTHETIC_LATE_ALLOW", delivered)
        self.assertIn(output.WITHHELD.encode(), delivered)
        self.assertTrue(self.broker.quarantine.status(self.task)["paused"])
        release.set()
        self.assertTrue(late_done.wait(2))
        self.assertEqual(connection.recv(4096), b"")

    def test_alignment_observation_releases_reviewed_bytes_but_not_revoked_requests(self):
        raw = _completion("SYNTHETIC_OBSERVED_RESPONSE")
        self.start(lambda h: _send(h, raw), verdict="block", policy=replace(self.policy, alignment_mode="observe"))
        status, _, delivered = self.response(self.connect())
        self.assertEqual(status, 200)
        self.assertEqual(delivered, raw)
        event = next(event for event in self.events if event.get("code") == "judge_block")
        self.assertEqual(event["mode"], "observe")
        self.assertFalse(event["enforced"])
        self.assertEqual(event["would_verdict"], "block")
        self.assertFalse(self.broker.quarantine.status(self.task)["paused"])
        self.assertFalse(self.broker.guards.check_command("sudo true").allowed)
        provider_count = len(self.provider.receipts)
        self.broker.revoke(self.task)
        _, _, after_revoke = self.response(self.connect())
        self.assertNotIn(b"SYNTHETIC_OBSERVED_RESPONSE", after_revoke)
        self.assertEqual(len(self.provider.receipts), provider_count)

    def assert_preflight_notice(self, state_text):
        for stream in (False, True):
            with self.subTest(stream=stream):
                request = _json_bytes({"stream": stream, "messages": [{"role": "user", "content": "PRIVATE_REQUEST_CANDIDATE"}],
                    "reason": "PRIVATE_CALLER_REASON", "notice": "PRIVATE_CALLER_NOTICE"})
                status, headers, delivered = self.response(self.connect(request))
                kind = "text/event-stream" if stream else "application/json"
                self.assertEqual((status, headers["Content-Type"]), (200, kind))
                text = output.inspect_text(delivered, kind)
                self.assertIn(state_text, text)
                self.assertIn("未发送给模型", text)
                self.assertNotIn("回答未通过检查", text)
                self.assertNotIn("PRIVATE_", text)
                self.assertIn(b"yuanxingmu-host-intervention", delivered)
                self.assertNotIn(b"tool_calls", delivered)
                self.assertEqual(self.provider.receipts, [])
                self.assertEqual(self.judge.receipts, [])

    def test_paused_task_gets_precise_notice_before_contacting_upstream(self):
        self.start(lambda h: _send(h, _completion("MUST_NOT_REQUEST")))
        self.broker.quarantine.pause(self.task, layer="input", code="fixture_pause", reason="PRIVATE_PAUSE_EVIDENCE")
        self.assert_preflight_notice("这份工作已暂停")

    def test_revoked_task_gets_precise_notice_and_cannot_be_described_as_resumable(self):
        self.start(lambda h: _send(h, _completion("MUST_NOT_REQUEST")))
        self.broker.revoke(self.task)
        self.assert_preflight_notice("权限已撤销")
        text = output.inspect_text(self.response(self.connect(b'{"stream":false}'))[2], "application/json")
        self.assertIn("恢复暂停不会重新授予权限", text)

    def test_latched_storage_failure_gets_precise_notice_with_zero_upstream_requests(self):
        self.start(lambda h: _send(h, _completion("MUST_NOT_REQUEST")))
        result = self.broker.guards._rule("input", "block", "fixture_block", "PRIVATE_CANDIDATE_REASON")
        with patch.object(self.broker, "_event", side_effect=OSError("PRIVATE_STORAGE_LOCATION")):
            with self.assertRaises(OSError):
                self.broker._guard_result(self.task, result)
        self.assertTrue(self.broker._fault)
        self.assert_preflight_notice("防护状态无法可靠读取或保存")

    def test_failed_state_read_has_no_upstream_request_or_raw_database_exception(self):
        self.start(lambda h: _send(h, _completion("MUST_NOT_REQUEST")))
        with patch.object(self.broker, "_require_admission", side_effect=sqlite3.OperationalError("PRIVATE_DATABASE_LOCATION")):
            self.assert_preflight_notice("防护状态无法可靠读取或保存")

    def test_unknown_admission_denial_and_malformed_request_never_echo_private_details(self):
        self.start(lambda h: _send(h, _completion("MUST_NOT_REQUEST")))
        with patch.object(self.broker, "_require_admission", side_effect=AuthorizationError("PRIVATE_UNKNOWN_CODE", "PRIVATE_ERROR_MESSAGE")):
            self.assert_preflight_notice("无法确认这份工作的权限")
            status, headers, delivered = self.response(self.connect(b'{"stream":true,"PRIVATE_BROKEN_REQUEST"'))
        self.assertEqual((status, headers["Content-Type"]), (200, "application/json"))
        text = output.inspect_text(delivered, "application/json")
        self.assertIn("未发送给模型", text)
        self.assertNotIn("PRIVATE_", text)
        self.assertEqual(self.provider.receipts, [])
        self.assertEqual(self.judge.receipts, [])

    def test_revocation_after_request_does_not_claim_that_no_request_was_sent(self):
        received, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def provider(handler):
            received.set()
            if release.wait(3):
                _send(handler, _completion("PRIVATE_INFLIGHT_ANSWER"))
        self.start(provider)
        connection = self.connect(b'{"stream":false}')
        self.assertTrue(received.wait(2))
        self.broker.revoke(self.task)
        release.set()
        status, _, delivered = self.response(connection)
        self.assertEqual(status, 200)
        text = output.inspect_text(delivered, "application/json")
        self.assertIn("权限已撤销", text)
        self.assertIn("返回的内容已暂不展示", text)
        self.assertNotIn("未发送给模型", text)
        self.assertNotIn("回答未通过检查", text)
        self.assertNotIn("PRIVATE_INFLIGHT_ANSWER", text)
        self.assertEqual(len(self.provider.receipts), 1)
        self.assertEqual(self.judge.receipts, [])

    def test_storage_failure_while_recording_a_checked_answer_never_releases_the_answer(self):
        self.start(lambda h: _send(h, _completion("PRIVATE_CHECKED_ANSWER")))
        with patch.object(self.broker, "_event", side_effect=OSError("PRIVATE_STORAGE_LOCATION")):
            status, _, delivered = self.response(self.connect(b'{"stream":false}'))
        self.assertEqual(status, 200)
        text = output.inspect_text(delivered, "application/json")
        self.assertIn("防护状态无法可靠读取或保存", text)
        self.assertNotIn("未发送给模型", text)
        self.assertNotIn("回答未通过检查", text)
        self.assertNotIn("PRIVATE_", text)
        self.assertTrue(self.broker._fault)
        self.assertEqual(len(self.provider.receipts), 1)
        self.assertEqual(len(self.judge.receipts), 1)

    def test_observe_records_a_block_without_intercepting_or_pausing(self):
        raw = _completion("SYNTHETIC_OBSERVE_NOT_INTERCEPTED")
        self.start(lambda h: _send(h, raw), verdict="block", policy=replace(self.policy, mode="observe"))
        status, _, delivered = self.response(self.connect())
        self.assertEqual((status, delivered), (200, raw))
        event = self.events[-1]
        self.assertEqual((event["verdict"], event["would_verdict"], event["enforced"]), ("allow", "block", False))
        self.assertFalse(self.broker.quarantine.status(self.task)["paused"])

    def test_disabled_response_layer_does_not_claim_a_check_or_interception(self):
        raw = b"SYNTHETIC_UNCHECKED_UNSUPPORTED_RESPONSE"
        self.start(lambda h: _send(h, raw), policy=replace(self.policy, alignment_enabled=False))
        status, _, delivered = self.response(self.connect())
        self.assertEqual((status, delivered), (200, raw))
        event = self.events[-1]
        self.assertEqual(event["code"], "layer_disabled")
        self.assertFalse(event["assessed"])
        self.assertFalse(event["enforced"])
        self.assertEqual(self.judge.receipts, [])
        self.assertFalse(self.broker.quarantine.status(self.task)["paused"])


if __name__ == "__main__":
    unittest.main()
