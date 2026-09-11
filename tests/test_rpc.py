from __future__ import annotations

import io
import json
import queue
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from defensecheck.rpc import ProtocolError, RPCSession, require_tool_success


def response(result=None, **overrides):
    value = {"jsonrpc": "2.0", "id": 1, "result": {} if result is None else result}
    value.update(overrides)
    return value


def tool_result(**overrides):
    value = {"content": [{"type": "text", "text": "LOCAL_RECEIPT"}], "isError": False}
    value.update(overrides)
    return value


def initialize_result(**overrides):
    value = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
             "serverInfo": {"name": "local-fixture", "version": "1"}}
    value.update(overrides)
    return value


def tool(name="send_email", **overrides):
    value = {"name": name, "inputSchema": {"type": "object", "properties": {}}}
    value.update(overrides)
    return value


def session(*messages, timeout=0.1):
    # Exercise the real request parser without starting gateways or external tools.
    client = RPCSession.__new__(RPCSession)
    client.id = 0
    client.trace = []
    client.timeout = timeout
    client.process = SimpleNamespace(stdin=io.StringIO())
    client.queue = queue.Queue()
    for message in messages:
        client.queue.put(message if isinstance(message, str) or message is None else json.dumps(message))
    return client


class EnvelopeTests(unittest.TestCase):
    def test_valid_response_matches_request_and_is_recorded(self):
        expected = response({"value": "receipt"})
        client = session(expected)
        self.assertEqual(expected, client.request("ping", {}))
        self.assertEqual(1, json.loads(client.process.stdin.getvalue())["id"])
        self.assertEqual(expected, client.trace[-1]["response"])

    def test_id_must_match_in_type_and_value(self):
        for identifier in [True, False, 1.0, "1", None, 2, [], {}]:
            with self.subTest(identifier=identifier), self.assertRaises(ProtocolError):
                session(response(id=identifier)).request("ping", {})

    def test_jsonrpc_version_is_required_and_exact(self):
        for version in [None, 2.0, "2", "1.0", True, [], {}]:
            with self.subTest(version=version), self.assertRaises(ProtocolError):
                session(response(jsonrpc=version)).request("ping", {})
        with self.assertRaises(ProtocolError):
            session({"id": 1, "result": {}}).request("ping", {})

    def test_response_requires_exactly_one_result_or_error(self):
        for message in [
            {"jsonrpc": "2.0", "id": 1},
            response(error={"code": -32600, "message": "policy"}),
            response(params={}),
            response(unrecognized="field"),
        ]:
            with self.subTest(message=message), self.assertRaises(ProtocolError):
                session(message).request("ping", {})

    def test_legal_policy_error_is_returned_unchanged(self):
        expected = {"jsonrpc": "2.0", "id": 1,
                    "error": {"code": -32600, "message": "[Invariant Guardrails] denied", "data": {"rule": "test"}}}
        actual = session(expected).call("send_email", to="outside@example.invalid")
        self.assertEqual(expected, actual)
        with self.assertRaisesRegex(ProtocolError, "JSON-RPC error"):
            require_tool_success(actual)

    def test_error_structure_cannot_fake_a_policy_block(self):
        for error in [None, False, [], "blocked", {}, {"code": -32600},
                      {"code": True, "message": "policy"}, {"code": -32600.0, "message": "policy"},
                      {"code": "-32600", "message": "policy"}, {"code": -32600, "message": []},
                      {"code": -32600, "message": "policy", "result": {}}]:
            message = {"jsonrpc": "2.0", "id": 1, "error": error}
            with self.subTest(error=error), self.assertRaises(ProtocolError):
                session(message).call("send_email")

    def test_unsolicited_requests_are_never_mistaken_for_responses(self):
        for message in [
            {"jsonrpc": "2.0", "id": 1, "method": "sampling/createMessage", "params": {}},
            response(method="ping"),
            {"jsonrpc": "2.0", "id": None, "method": "notifications/message", "params": {}},
        ]:
            with self.subTest(message=message), self.assertRaises(ProtocolError):
                session(message).request("ping", {})

    def test_duplicate_keys_and_non_json_numbers_are_rejected(self):
        for raw in [
            '{"jsonrpc":"2.0","id":2,"id":1,"result":{}}',
            '{"jsonrpc":"2.0","id":1,"result":{"content":[],"isError":true,"isError":false}}',
            '{"jsonrpc":"2.0","id":1,"result":{"value":NaN}}',
            '{"jsonrpc":"2.0","id":1,"result":{"value":Infinity}}',
        ]:
            with self.subTest(raw=raw), self.assertRaises(ProtocolError):
                session(raw).request("ping", {})

    def test_closed_output_garbage_and_batches_are_incomplete(self):
        for message in [None, "not JSON", [], [response()], False]:
            with self.subTest(message=message), self.assertRaises(ProtocolError):
                session(message).request("ping", {})


class NotificationTests(unittest.TestCase):
    def test_one_hundred_notifications_then_response_are_allowed(self):
        notice = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
        client = session(*([notice] * 100), response())
        with patch("defensecheck.rpc.time.monotonic", return_value=0):
            client.request("ping", {})
        self.assertEqual(100, sum("notification" in event for event in client.trace))

    def test_notification_flood_is_bounded(self):
        notice = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
        with patch("defensecheck.rpc.time.monotonic", return_value=0):
            with self.assertRaisesRegex(ProtocolError, "Too many notifications"):
                session(*([notice] * 101), response()).request("ping", {})

    def test_notifications_do_not_reset_the_total_deadline(self):
        clock = [0.0]
        timeouts = []
        notice = json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})

        def get(*, timeout):
            timeouts.append(timeout)
            clock[0] += 0.6
            return notice

        client = session(timeout=1)
        client.queue = SimpleNamespace(get=get)
        with patch("defensecheck.rpc.time.monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(ProtocolError, "timed out"):
                client.request("ping", {})
        self.assertEqual(2, len(timeouts))
        self.assertAlmostEqual(1.0, timeouts[0])
        self.assertAlmostEqual(0.4, timeouts[1])

    def test_malformed_notifications_are_not_silently_skipped(self):
        for notice in [
            {"method": "notifications/tools/list_changed"},
            {"jsonrpc": "1.0", "method": "notifications/tools/list_changed"},
            {"jsonrpc": "2.0", "method": "notifications/"},
            {"jsonrpc": "2.0", "method": "ping"},
            {"jsonrpc": "2.0", "method": False},
            {"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": []},
            {"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "result": {}},
            {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": [], "data": "hello"}},
            {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}},
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": True, "progress": 1}},
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": 1, "progress": False}},
        ]:
            with self.subTest(notice=notice), self.assertRaises(ProtocolError):
                session(notice, response()).request("ping", {})

    def test_valid_logging_and_progress_notifications_are_recorded(self):
        notices = [
            {"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info", "data": {"status": "working"}}},
            {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": "job", "progress": 1, "total": 2}},
        ]
        client = session(*notices, response())
        client.request("ping", {})
        self.assertEqual(notices, [e["notification"] for e in client.trace if "notification" in e])


class ToolResultTests(unittest.TestCase):
    def test_valid_result_is_returned_for_the_caller_to_check_receipts(self):
        result = tool_result(structuredContent={"receipt": "local"})
        self.assertIs(result, require_tool_success(response(result)))
        del result["isError"]
        self.assertIs(result, require_tool_success(response(result)))

    def test_tool_error_is_valid_protocol_but_never_success(self):
        expected = response(tool_result(isError=True))
        self.assertEqual(expected, session(expected).call("send_email"))
        with self.assertRaisesRegex(ProtocolError, "isError=true"):
            require_tool_success(expected)

    def test_truthy_or_falsey_non_boolean_error_flags_are_invalid(self):
        for flag in [0, 1, "false", "true", None, [], {}]:
            with self.subTest(flag=flag), self.assertRaises(ProtocolError):
                require_tool_success(response(tool_result(isError=flag)))

    def test_missing_or_malformed_content_does_not_count_as_success(self):
        for result in [None, [], False, "success", {}, {"content": None}, {"content": {}},
                       {"content": "LOCAL_RECEIPT"}, {"content": ["LOCAL_RECEIPT"]},
                       {"content": [{}]}, {"content": [{"type": "text", "text": 1}]},
                       {"content": [{"type": "text"}]}, {"content": [{"type": "new-unknown", "text": "ok"}]},
                       tool_result(structuredContent=[]), tool_result(_meta=[]),
                       {"content": [{"type": "text", "text": "ok", "annotations": {"priority": True}}]}]:
            envelope = {"jsonrpc": "2.0", "id": 1, "result": result}
            with self.subTest(result=result), self.assertRaises(ProtocolError):
                require_tool_success(envelope)

    def test_malformed_result_is_rejected_on_the_actual_call_path(self):
        with self.assertRaises(ProtocolError):
            session(response(tool_result(isError="false"))).call("send_email")

    def test_valid_content_variants(self):
        content = [
            {"type": "text", "text": "", "annotations": {"audience": ["user"], "priority": 0.5}},
            {"type": "image", "data": "eA==", "mimeType": "image/png"},
            {"type": "audio", "data": "eA==", "mimeType": "audio/wav"},
            {"type": "resource", "resource": {"uri": "memory://test", "text": "content"}},
            {"type": "resource", "resource": {"uri": "memory://test", "blob": "eA=="}},
            {"type": "resource_link", "uri": "memory://test", "name": "test", "size": 1},
        ]
        self.assertEqual(content, require_tool_success(response({"content": content}))["content"])
        self.assertEqual([], require_tool_success(response({"content": []}))["content"])

    def test_malformed_nested_resources_are_rejected(self):
        for block in [
            {"type": "image", "data": "invalid!", "mimeType": "image/png"},
            {"type": "image", "data": "eA==", "mimeType": 1},
            {"type": "resource", "resource": {"uri": "memory://test", "text": "both", "blob": "eA=="}},
            {"type": "resource", "resource": {"uri": "memory://test"}},
            {"type": "resource_link", "uri": "memory://test", "name": "test", "size": True},
        ]:
            with self.subTest(block=block), self.assertRaises(ProtocolError):
                require_tool_success(response({"content": [block]}))


class DiscoveryTests(unittest.TestCase):
    def test_valid_initialize_acknowledges_only_after_validation(self):
        client = session(response(initialize_result()))
        self.assertIs(client, client.__enter__())
        sent = [json.loads(line) for line in client.process.stdin.getvalue().splitlines()]
        self.assertEqual("2024-11-05", sent[0]["params"]["protocolVersion"])
        self.assertEqual({"jsonrpc": "2.0", "method": "notifications/initialized"}, sent[1])

    def test_invalid_initialize_never_sends_initialized(self):
        for result in [
            {}, initialize_result(protocolVersion="future-version"), initialize_result(protocolVersion={}),
            initialize_result(capabilities=[]), initialize_result(capabilities={"tools": {"listChanged": "true"}}),
            initialize_result(serverInfo={"name": "missing version"}), initialize_result(serverInfo={"name": [], "version": "1"}),
        ]:
            client = session(response(result))
            with self.subTest(result=result), patch.object(RPCSession, "__exit__") as close:
                with self.assertRaises(ProtocolError):
                    client.__enter__()
                close.assert_called_once()
                self.assertNotIn("notifications/initialized", client.process.stdin.getvalue())

    def test_valid_tools_list_is_returned(self):
        self.assertEqual(["send_email"], session(response({"tools": [tool()]})).tools())

    def test_malformed_tool_catalogs_are_not_accepted(self):
        for result in [
            {}, {"tools": None}, {"tools": "send_email"}, {"tools": ["send_email"]},
            {"tools": [tool(name=False)]}, {"tools": [tool(name="")]},
            {"tools": [tool(), tool()]}, {"tools": [tool(inputSchema=None)]},
            {"tools": [tool(inputSchema={"type": "array"})]},
            {"tools": [tool(inputSchema={"type": "object", "required": "to"})]},
            {"tools": [tool()], "nextCursor": True},
        ]:
            with self.subTest(result=result), self.assertRaises(ProtocolError):
                session(response(result)).tools()

    def test_pagination_is_explicitly_incomplete_not_a_complete_catalog(self):
        with self.assertRaisesRegex(ProtocolError, "Paginated"):
            session(response({"tools": [tool()], "nextCursor": "page-2"})).tools()


if __name__ == "__main__":
    unittest.main()
