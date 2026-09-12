"""Protected model boundaries with real field matching and local TCP transport.

No real model or Agent is used. The broker admission/audit object is a small
contract fixture; private source compilation and candidate matching are real.
Transport tests exercise the production _ModelHandler over ephemeral loopback
ports, including its whole-response buffer, on Windows as well as Linux.
"""
from contextlib import ExitStack
from dataclasses import replace
import hashlib
import http.client
import json
from pathlib import Path
import select
import socket
import sqlite3
import sys
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from yuanxingmu import gateway_network as network
from yuanxingmu import model_output as output
from yuanxingmu.authority import AuthorizationError
from yuanxingmu.protected_boundary import ProtectedContentError, check_candidate
from yuanxingmu.protected_data import HostProtectedData, HostResource
from tests.test_yuanxingmu_model_output import _completion, _event, _json_bytes, _provider, _send, _stream
from tests import test_yuanxingmu_protected_broker as broker_fixture
from tests.test_yuanxingmu_guards import _answer


def _protected():
    source = "对外报价218000元；内部底价162000元。\napi_key=sk_demo-ABC123"
    return HostProtectedData.compile({"quote": HostResource(source, hashlib.sha256(source.encode()).hexdigest())})


class _Guards:
    def __init__(self, *, alignment=True, mode="enforce", callback=None):
        self.policy = SimpleNamespace(alignment_enabled=alignment, mode=mode)
        self.responses = []
        self.callback = callback

    def check_response(self, text, **context):
        self.responses.append(text)
        if self.callback:
            self.callback()
        return {"verdict": "allow", "synthetic_judge": True}

    def _rule(self, *args):
        return {"verdict": "block"}


class _Broker:
    """Only admission/pause/audit mechanics are substituted, never matching."""
    def __init__(self, guards=None, *, protected=True):
        self._lock = threading.RLock()
        self.protected_data = _protected() if protected else None
        self.guards = guards
        self.paused = False
        self.failures = []
        self.semantic_results = []

    def _require_admission(self, task):
        if self.paused:
            raise AuthorizationError("task_paused")

    def _protected_failure(self, task, error):
        self.failures.append({"task": task, "reason": error.reason})
        self.paused = True

    def _protect(self, task, candidate):
        try:
            check_candidate(self.protected_data, candidate)
        except ProtectedContentError as error:
            self._protected_failure(task, error)
            raise

    def _check_protected(self, candidate):
        check_candidate(self.protected_data, candidate)

    def _review_context(self, task):
        return {}

    def _guard_result(self, task, result):
        self.semantic_results.append(result)
        if result["verdict"] == "block" and self.guards.policy.mode != "observe":
            raise AuthorizationError("response_blocked")


def _call(arguments, *, name="yuanxingmu_request_action", call_id="fixture-call"):
    return {"id": call_id, "type": "function", "function": {"name": name, "arguments": arguments}}


def _tool_reply(arguments, **kwargs):
    return _completion(message={"role": "assistant", "content": None,
                                "tool_calls": [_call(arguments, **kwargs)]}, finish="tool_calls")


class VisibleModelOutputTests(unittest.TestCase):
    def test_legacy_prose_inspector_stays_prose_only_but_visible_parser_covers_arguments(self):
        raw = _tool_reply('{"body":"162000"}')
        self.assertEqual("", output.inspect_text(raw, "application/json"))
        visible = output.inspect_visible(raw, "application/json")
        self.assertEqual("162000", visible["assembled"]["tool_calls"][0]["function"]["arguments"]["body"])
        self.assertEqual(json.loads(raw), visible["provider_envelopes"][0])

    def test_interleaved_sse_tools_reassemble_by_index_and_keep_metadata(self):
        raw = (_event({"role": "assistant", "tool_calls": [
            {"index": 1, "id": "second", "type": "function", "function": {"name": "up", "arguments": '{"body":"21'}},
            {"index": 0, "id": "first", "type": "function", "function": {"name": "send", "arguments": '{"body":"16'}},
        ]}) + _event({"tool_calls": [
            {"index": 0, "function": {"name": "_message", "arguments": '2000"}'}},
            {"index": 1, "function": {"name": "load", "arguments": '8000"}'}},
        ]}, "tool_calls") + b'data: {"choices":[],"usage":{"total_tokens":17},"extra":"extra-visible"}\n\n'
        + b"data: [DONE]\n\n")
        parsed = output.inspect_visible(raw, "text/event-stream")
        calls = parsed["assembled"]["tool_calls"]
        self.assertEqual(["first", "second"], [item["id"] for item in calls])
        self.assertEqual(["send_message", "upload"], [item["function"]["name"] for item in calls])
        self.assertEqual(["162000", "218000"], [item["function"]["arguments"]["body"] for item in calls])
        self.assertEqual("extra-visible", parsed["provider_envelopes"][-1]["extra"])

    def test_legacy_function_call_and_split_json_escape_are_fully_decoded(self):
        raw = (_event({"role": "assistant", "function_call": {"name": "send", "arguments": '{"body":"\\u00'}})
               + _event({"function_call": {"name": "_message", "arguments": '31\\u0036\\u0032\\u0030\\u0030\\u0030"}'}}, "function_call")
               + b"data: [DONE]\n\n")
        parsed = output.inspect_visible(raw, "text/event-stream")
        self.assertEqual({"name": "send_message", "arguments": {"body": "162000"}}, parsed["assembled"]["function_call"])

    def test_each_text_stream_is_complete_and_sse_comments_are_retained(self):
        raw = (b": comment-visible\n\n" + _event({"role": "assistant", "content": "16", "reasoning": "A", "refusal": "N", "reasoning_content": "X"})
               + _event({"content": "2000", "reasoning": "B", "refusal": "O", "reasoning_content": "Y"}, "stop")
               + b"data: [DONE]\n\n: trailing-comment\n\n")
        parsed = output.inspect_visible(raw, "text/event-stream")
        self.assertEqual({"content": "162000", "reasoning": "AB", "refusal": "NO", "reasoning_content": "XY"}, parsed["assembled"])
        self.assertEqual([" comment-visible", " trailing-comment"], parsed["sse_comments"])

    def test_unsupported_tool_shapes_and_incomplete_or_duplicate_arguments_fail(self):
        cases = [_tool_reply('{"body":"162000"'), _tool_reply('{"body":"safe","body":"162000"}'),
                 _tool_reply('["162000"]'), _tool_reply('"162000"'), _tool_reply(""),
                 _completion(message={"role":"assistant", "content": None}, finish="tool_calls"),
                 _completion(message={"role":"assistant", "tool_calls":[_call("{}")], "function_call":{"name":"x","arguments":"{}"}}, finish="tool_calls")]
        for mutate in (
            lambda call: call.update(type="custom"),
            lambda call: call.update(index=True),
            lambda call: call.update(id=None),
            lambda call: call.update(extra="unexpected"),
            lambda call: call["function"].update(arguments={"body":"162000"}),
            lambda call: call["function"].update(name=""),
        ):
            call = _call("{}")
            mutate(call)
            cases.append(_completion(message={"role":"assistant","tool_calls":[call]},finish="tool_calls"))
        for raw in cases:
            with self.subTest(size=len(raw)), self.assertRaises(output.InvalidModelOutput):
                output.inspect_visible(raw, "application/json")

    def test_ambiguous_sse_indices_identity_finish_and_extra_events_fail(self):
        tool = {"index":0, **_call("{}")}
        for raw in (
            _event({"tool_calls":[{**tool,"index":1}]},"tool_calls")+b"data: [DONE]\n\n",
            _event({"tool_calls":[tool,tool]},"tool_calls")+b"data: [DONE]\n\n",
            _event({"tool_calls":[tool]})+_event({"tool_calls":[{"index":0,"id":"changed"}]},"tool_calls")+b"data: [DONE]\n\n",
            _event({"content":"partial"}),
            _event({"content":"partial"},"length")+b"data: [DONE]\n\n",
            _stream()+_event({"content":"after-done"}),
            _stream()[:-1],
            b"event: unknown\n"+_stream(),
        ):
            with self.subTest(size=len(raw)), self.assertRaises(output.InvalidModelOutput):
                output.inspect_visible(raw, "text/event-stream")
        with patch.object(output,"MAX_EVENTS",1), self.assertRaises(output.InvalidModelOutput):
            output.inspect_visible(_stream(),"text/event-stream")

    def test_visible_parser_rejects_unsupported_text_and_multiple_choices(self):
        for raw in (_completion(message={"role":"assistant","content":[{"text":"162000"}]}),
                    _completion(message={"role":"assistant","content":"safe","audio":{"transcript":"162000"}}),
                    b'{"choices":[],"choices":[]}', _json_bytes({"choices":[]}),
                    _completion(finish=["stop"]), _completion("safe")[:-1]):
            with self.subTest(size=len(raw)), self.assertRaises(output.InvalidModelOutput):
                output.inspect_visible(raw,"application/json")
        with patch.object(output,"MAX_RESPONSE",64), self.assertRaises(output.InvalidModelOutput):
            output.inspect_visible(_completion("tail"*100),"application/json")


class ProtectedOutputGuardTests(unittest.TestCase):
    def assertWithheld(self, delivered, kind="application/json"):
        self.assertIn(b"yuanxingmu-host-intervention", delivered)
        self.assertNotIn(b"162000", delivered)
        self.assertNotIn(b"sk_demo-ABC123", delivered)
        self.assertNotIn(b"tool_calls", delivered)
        self.assertNotIn(b"function_call", delivered)
        self.assertIn("元星木防护提醒", output.inspect_text(delivered, kind))

    def test_protected_values_block_with_no_guard_alignment_disabled_observe_and_allow_judge(self):
        for guards in (None, _Guards(alignment=False), _Guards(mode="observe"), _Guards()):
            for raw in (_completion("底价为162000元"), _tool_reply('{"body":"162000"}')):
                with self.subTest(guards=guards):
                    broker = _Broker(guards)
                    self.assertWithheld(output.ModelOutputGuard(broker,"task")(raw,"application/json"))
                    self.assertTrue(broker.paused)
                    self.assertEqual([{"task":"task","reason":"protected_value_blocked"}],broker.failures)
                    self.assertEqual([],broker.semantic_results)
                    if guards is not None:
                        self.assertEqual([],guards.responses)

    def test_clean_public_quote_and_larger_number_release_identical_bytes(self):
        for text in ("对外报价218000元", "编号X162000Y，记录1620000条", "日期2026-162000-09"):
            for guards in (None, _Guards(alignment=False), _Guards(mode="observe"), _Guards()):
                with self.subTest(text=text,guards=guards):
                    broker = _Broker(guards)
                    raw = _completion(text)
                    self.assertEqual(raw,output.ModelOutputGuard(broker,"task")(raw,"application/json"))
                    self.assertFalse(broker.paused)

    def test_reasoning_refusal_tool_name_id_and_unused_metadata_are_not_dropped(self):
        raws = []
        for field in ("content","reasoning","reasoning_content","refusal"):
            raws.append(_completion(message={"role":"assistant",field:"162000"}))
        raws += [_tool_reply("{}", name="sk_demo-ABC123"), _tool_reply("{}",call_id="sk_demo-ABC123")]
        for field, value in (("request_id","162000"),("extra",{"nested":"sk_demo-ABC123"})):
            envelope = json.loads(_completion("clean"));envelope[field]=value;raws.append(_json_bytes(envelope))
        for raw in raws:
            with self.subTest(size=len(raw)):
                broker = _Broker()
                self.assertWithheld(output.ModelOutputGuard(broker,"task")(raw,"application/json"))
                self.assertEqual("protected_value_blocked",broker.failures[0]["reason"])

    def test_json_and_nested_argument_escapes_are_checked_after_decoding(self):
        raw = _tool_reply(r'{"body":"\u0031\u0036\u0032\u0030\u0030\u0030"}')
        broker = _Broker()
        self.assertWithheld(output.ModelOutputGuard(broker,"task")(raw,"application/json"))
        raw = _completion("\\u0031")  # Arbitrary prose escape text is not a new JSON string.
        self.assertEqual(raw,output.ModelOutputGuard(_Broker(),"task")(raw,"application/json"))

    def test_split_visible_text_arguments_and_comments_block_sse(self):
        streams = [
            _event({"content":"16"})+_event({"content":"2000"},"stop")+b"data: [DONE]\n\n",
            _event({"reasoning_content":"sk_demo-"})+_event({"reasoning_content":"ABC123"},"stop")+b"data: [DONE]\n\n",
            _event({"tool_calls":[{"index":0,**_call('{"body":"16')} ]})+_event({"tool_calls":[{"index":0,"function":{"arguments":'2000"}'}}]},"tool_calls")+b"data: [DONE]\n\n",
            b": 162000\n\n"+_stream("clean"),
            _event({"content":"clean"},"stop")+b'data: {"choices":[],"usage":{"note":"162000"}}\n\ndata: [DONE]\n\n',
        ]
        for raw in streams:
            with self.subTest(size=len(raw)):
                broker = _Broker()
                self.assertWithheld(output.ModelOutputGuard(broker,"task")(raw,"text/event-stream"),"text/event-stream")

    def test_different_tool_indices_do_not_join_into_false_sensitive_value(self):
        raw = _event({"tool_calls":[{"index":0,**_call('{"body":"162"}',call_id="first")},
                                          {"index":1,**_call('{"body":"000"}',call_id="second")}]},"tool_calls")+b"data: [DONE]\n\n"
        self.assertEqual(raw,output.ModelOutputGuard(_Broker(),"task")(raw,"text/event-stream"))

    def test_malformed_output_records_fixed_failure_and_releases_no_prefix(self):
        for raw, kind in ((_completion("VISIBLE_PREFIX")[:-1],"application/json"),
                          (_event({"content":"VISIBLE_PREFIX"}),"text/event-stream"),
                          (_tool_reply('{"body":"incomplete"'),"application/json")):
            with self.subTest(kind=kind):
                broker = _Broker()
                delivered = output.ModelOutputGuard(broker,"task")(raw,kind)
                self.assertWithheld(delivered,kind)
                self.assertNotIn(b"VISIBLE_PREFIX",delivered)
                self.assertEqual([{"task":"task","reason":"protected_check_failed"}],broker.failures)

    def test_request_preflight_checks_decoded_messages_definitions_arguments_and_metadata(self):
        requests = [
            r'{"stream":true,"messages":[{"role":"user","content":"\u0031\u0036\u0032\u0030\u0030\u0030"}]}'.encode(),
            _json_bytes({"messages":[],"tools":[{"function":{"description":"162000"}}]}),
            _json_bytes({"messages":[{"tool_calls":[{"function":{"arguments":r'{"body":"\u0031\u0036\u0032\u0030\u0030\u0030"}'}}]}]}),
            _json_bytes({"messages":[],"metadata":{"note":"sk_demo-ABC123"}}),
        ]
        for raw in requests:
            with self.subTest(size=len(raw)):
                broker = _Broker()
                kind,notice = output.ModelOutputGuard(broker,"task").preflight(raw)
                self.assertWithheld(notice,kind)
                self.assertIn("请求未发送给模型",output.inspect_text(notice,kind))
                self.assertEqual("protected_value_blocked",broker.failures[0]["reason"])
                self.assertTrue(broker.paused)

    def test_invalid_request_is_not_forwarded_or_accepted_as_raw_text(self):
        for raw in (b'{"messages":', b'[]', b'{"messages":[],"messages":[]}', b'{"value":NaN}'):
            with self.subTest(raw=raw):
                broker = _Broker()
                kind,notice = output.ModelOutputGuard(broker,"task").preflight(raw)
                self.assertWithheld(notice,kind)
                self.assertEqual("protected_check_failed",broker.failures[0]["reason"])

    def test_clean_request_is_allowed_and_paused_request_never_reaches_check(self):
        broker = _Broker()
        guard = output.ModelOutputGuard(broker,"task")
        self.assertIsNone(guard.preflight(_json_bytes({"messages":[{"role":"user","content":"公开报价218000元"}]})))
        broker.paused=True
        kind,notice=guard.preflight(b'{"stream":true}')
        self.assertWithheld(notice,kind)
        self.assertEqual([],broker.failures)

    def test_protected_error_from_judge_callback_is_caught_before_original_answer(self):
        guards = _Guards()
        broker = _Broker(guards)
        guards.callback=lambda:broker._check_protected({"judge_request":"162000"})
        raw=_completion("clean-provider-answer")
        delivered=output.ModelOutputGuard(broker,"task")(raw,"application/json")
        self.assertWithheld(delivered)
        self.assertNotIn(b"clean-provider-answer",delivered)
        self.assertTrue(broker.paused)
        self.assertEqual([{"task":"task","reason":"protected_value_blocked"}],broker.failures)

    def test_protected_error_inside_semantic_rule_fallback_also_pauses_once(self):
        guards=_Guards()
        broker=_Broker(guards)
        with patch.object(output,"inspect_text",side_effect=output.InvalidModelOutput("synthetic_parse_failure")), \
                patch.object(guards,"_rule",side_effect=lambda *args:broker._check_protected({"rule_result":"162000"})):
            delivered=output.ModelOutputGuard(broker,"task")(_completion("clean"),"application/json")
        self.assertWithheld(delivered)
        self.assertTrue(broker.paused)
        self.assertEqual([{"task":"task","reason":"protected_value_blocked"}],broker.failures)

    def test_audit_failure_does_not_restore_original_bytes(self):
        broker=_Broker()
        with patch.object(broker,"_protected_failure",side_effect=sqlite3.OperationalError("PRIVATE_STORAGE_DETAIL")):
            delivered=output.ModelOutputGuard(broker,"task")(_completion("VISIBLE_PREFIX")[:-1],"application/json")
        self.assertWithheld(delivered)
        self.assertNotIn(b"PRIVATE_STORAGE_DETAIL",delivered)
        self.assertNotIn(b"VISIBLE_PREFIX",delivered)

    def test_legacy_without_protected_data_keeps_existing_prose_review_contract(self):
        guards=_Guards()
        broker=_Broker(guards,protected=False)
        raw=_tool_reply('{"body":"162000"}')
        self.assertEqual(raw,output.ModelOutputGuard(broker,"task")(raw,"application/json"))
        self.assertEqual([""],guards.responses)


class ProtectedOutputTransportTests(unittest.TestCase):
    assertWithheld=ProtectedOutputGuardTests.assertWithheld

    def setUp(self):
        self.stack=ExitStack();self.addCleanup(self.stack.close)

    def start(self, reply):
        self.provider=self.stack.enter_context(_provider(reply))
        self.broker=_Broker()
        proxy=network._TCPServer(("127.0.0.1",0),network._ModelHandler)
        proxy.upstream=("http","127.0.0.1",self.provider.server_port,"/v1/chat/completions")
        proxy.api_key="synthetic-key"
        proxy.output_guard=output.ModelOutputGuard(self.broker,"task")
        self.stack.enter_context(network._Serving(proxy))
        self.address=proxy.server_address

    def connect(self, body=b'{"stream":true,"messages":[]}'):
        connection=socket.create_connection(self.address,timeout=4)
        self.addCleanup(connection.close)
        connection.sendall(b"POST /v1/chat/completions HTTP/1.1\r\nHost: fixture\r\nContent-Type: application/json\r\n"
                           +b"Content-Length: "+str(len(body)).encode()+b"\r\nConnection: close\r\n\r\n"+body)
        return connection

    def response(self, connection):
        response=http.client.HTTPResponse(connection);response.begin()
        result=(response.status,response.read());response.close();return result

    def test_request_with_escaped_value_never_calls_provider(self):
        self.start(lambda handler:_send(handler,_completion("should-not-run")))
        request=r'{"messages":[{"role":"user","content":"\u0031\u0036\u0032\u0030\u0030\u0030"}]}'.encode()
        status,delivered=self.response(self.connect(request))
        self.assertEqual(200,status);self.assertWithheld(delivered)
        self.assertEqual([],self.provider.receipts)

    def test_sse_sends_no_headers_or_first_chunk_before_complete_blocked_answer(self):
        first_sent,finish=threading.Event(),threading.Event()
        self.addCleanup(finish.set)
        first=_event({"role":"assistant","content":"PUBLIC_EARLY_PREFIX 218000元；底价16"})
        last=_event({"content":"2000元"},"stop")+b"data: [DONE]\n\n"
        def reply(handler):
            handler.send_response(200);handler.send_header("Content-Type","text/event-stream")
            handler.send_header("Transfer-Encoding","chunked");handler.send_header("Connection","close");handler.end_headers()
            handler.wfile.write(f"{len(first):X}\r\n".encode()+first+b"\r\n");handler.wfile.flush();first_sent.set()
            if finish.wait(3):
                handler.wfile.write(f"{len(last):X}\r\n".encode()+last+b"\r\n0\r\n\r\n");handler.wfile.flush()
        self.start(reply)
        connection=self.connect()
        self.assertTrue(first_sent.wait(2))
        self.assertEqual([],select.select([connection],[],[],.1)[0],"No provider header or prefix may be released")
        finish.set();status,delivered=self.response(connection)
        self.assertEqual(200,status);self.assertWithheld(delivered,"text/event-stream")
        self.assertNotIn(b"PUBLIC_EARLY_PREFIX",delivered)
        self.assertTrue(self.broker.paused)

    def test_complete_clean_stream_releases_identical_bytes(self):
        raw=_stream("公开报价218000元")
        self.start(lambda handler:_send(handler,raw,"text/event-stream"))
        status,delivered=self.response(self.connect())
        self.assertEqual(200,status);self.assertEqual(raw,delivered)
        self.assertFalse(self.broker.paused)


@unittest.skipUnless(sys.platform.startswith("linux"), "Real Linux Broker and durable pause")
class RealProtectedOutputTests(unittest.TestCase):
    setUp=broker_fixture.ProtectedBrokerTests.setUp
    start=broker_fixture.ProtectedBrokerTests.start
    guards=broker_fixture.ProtectedBrokerTests.guards
    assert_private_audits=broker_fixture.ProtectedBrokerTests.assert_private_audits
    assertWithheld=ProtectedOutputGuardTests.assertWithheld

    def test_synthetic_judge_leak_pauses_real_broker_without_audit_value(self):
        guards,judge=self.guards(policy=replace(self.policy,alignment_enabled=True,mode="observe"),
                                 answer=_answer(reason="允许，内部底价162000元。"))
        broker=self.start(guards=guards)
        delivered=output.ModelOutputGuard(broker,self.task)(_completion("公开报价218000元"),"application/json")
        self.assertWithheld(delivered)
        self.assertEqual(1,len(judge.requests))
        self.assertTrue(broker.quarantine.status(self.task)["paused"])
        self.assert_private_audits()
        raw=(self.root/"state"/"broker-events.jsonl").read_text()
        self.assertEqual(1,raw.count('"operation": "protected_content_withheld"'))

    def test_known_value_in_objective_pauses_before_real_judge_request(self):
        guards,judge=self.guards(policy=replace(self.policy,alignment_enabled=True,objective="不要披露162000元"))
        broker=self.start(guards=guards)
        delivered=output.ModelOutputGuard(broker,self.task)(_completion("公开报价218000元"),"application/json")
        self.assertWithheld(delivered)
        self.assertEqual([],judge.requests)
        self.assertTrue(broker.quarantine.status(self.task)["paused"])
        self.assert_private_audits()


class RecordedGLMCompatibilityTests(unittest.TestCase):
    def test_auto17_and_auto18_real_sse_formats_and_known_auto18_leaks(self):
        evidence=Path(__file__).resolve().parents[1]/"docs/evidence"
        if not (evidence/"hermes-auto18-2026-09-12/raw").is_dir():
            self.skipTest("Frozen public evidence not included in this source checkout")
        expected={"hermes-auto17-2026-09-12":17,"hermes-auto18-2026-09-12":3}
        blocked=[]
        for run,count in expected.items():
            files=sorted((evidence/run/"raw").glob("*main-response.sse"))
            self.assertEqual(count,len(files),run)
            for path in files:
                with self.subTest(run=run,file=path.name):
                    visible=output.inspect_visible(path.read_bytes(),"text/event-stream")
                    self.assertIn("assembled",visible)
                    if run.startswith("hermes-auto18"):
                        try:
                            check_candidate(_protected(),visible)
                        except ProtectedContentError as error:
                            self.assertEqual("protected_value_blocked",error.reason)
                            blocked.append(path.name)
        self.assertEqual(["00193-main-response.sse","00198-main-response.sse"],blocked)


if __name__ == "__main__":
    unittest.main()
