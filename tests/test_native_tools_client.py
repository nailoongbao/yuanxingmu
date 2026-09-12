"""No optional SDK dependency is required for this client's contract tests."""
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from yuanxingmu.adapters import NativeTools
from yuanxingmu.adapters.client import decode_arguments


class NativeClientTests(unittest.TestCase):
    def setUp(self):
        self.endpoint = str(Path("native-test.sock").absolute())
        self.client = NativeTools(socket_path=self.endpoint, session_id="host-session-1")

    def test_import_needs_no_optional_sdk(self):
        result = subprocess.run([sys.executable, "-S", "-B", "-c",
                                 "from yuanxingmu.adapters import NativeTools; print(NativeTools.__name__)"],
                                cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "NativeTools")

    def test_binding_is_explicit_and_never_reads_environment(self):
        with self.assertRaisesRegex(ValueError, "absolute_socket"):
            NativeTools("relative.sock", "session")
        for session in ("", None, 123, "a" * 257):
            with self.assertRaisesRegex(ValueError, "host_session"):
                NativeTools(self.endpoint, session)
        with self.assertRaises(FrozenInstanceError):
            self.client.session_id = "model-selected-session"
        with patch.dict(os.environ, {"YUANXINGMU_BROKER_SOCKET": "model-selected.sock"}), \
                patch("yuanxingmu.adapters.client.request", return_value={"allowed": True}) as sent:
            self.client.invoke("read", {"resource": "private"}, framework="langchain")
        sent.assert_called_once_with("read", socket_path=self.endpoint, resource="private")
        self.assertNotIn(self.endpoint, repr(self.client))
        self.assertNotIn("host-session-1", repr(self.client))

    def test_proposal_identity_survives_reconstruction_but_separates_sessions_and_operations(self):
        key = self.client.request_key("propose_action", "langchain", "native-call-1")
        restored = NativeTools(self.endpoint, "host-session-1")
        self.assertEqual(restored.request_key("propose_action", "langchain", "native-call-1"), key)
        self.assertRegex(key, r"^native_v1_[0-9a-f]{64}$")
        variants = [self.client.request_key("propose_action", "langchain", "native-call-2"),
                    self.client.request_key("propose_action", "openai_agents", "native-call-1"),
                    self.client.request_key("draft_email", "langchain", "native-call-1"),
                    NativeTools(self.endpoint, "other-session").request_key("propose_action", "langchain", "native-call-1")]
        self.assertEqual(len({key, *variants}), 5)
        for call_id in (None, "", 4, "x" * 513):
            with self.assertRaisesRegex(ValueError, "native_tool_call_id_required"):
                self.client.request_key("propose_action", "langchain", call_id)

    def test_content_and_host_fields_are_separated_before_connecting(self):
        proposal = {"kind": "message", "target_id": "chat", "payload": {"body": "synthetic message"}}
        cases = [("send", {"destination": "public", "body": "synthetic", name: "forged"})
                 for name in ("task_id", "socket_path", "session_id", "url", "headers", "credentials", "confirm", "request_key")]
        cases += [("action_commit", {}), ("read", {"resource": 3}), ("describe", {"op": "read"}),
                  ("propose_action", {"proposal": {**proposal, "approved": True}}),
                  ("draft_email", {"draft": {"recipient": "x@example.test", "subject": "s", "body": "b", "account_id": "evil"}})]
        with patch("yuanxingmu.adapters.client.request") as sent:
            for operation, arguments in cases:
                with self.subTest(operation=operation, arguments=arguments), self.assertRaises(ValueError):
                    self.client.invoke(operation, arguments, framework="langchain", tool_call_id="call")
            with self.assertRaisesRegex(ValueError, "native_tool_call_id_required"):
                self.client.invoke("propose_action", {"proposal": proposal}, framework="langchain")
        sent.assert_not_called()

    def test_form_pairs_are_copied_and_duplicate_names_rejected(self):
        fields = [{"name": "note", "value": "synthetic"}]
        arguments = {"proposal": {"kind": "form", "target_id": "form", "payload": {"fields": fields}}}
        with patch("yuanxingmu.adapters.client.request", return_value={"allowed": True}) as sent:
            self.client.invoke("propose_action", arguments, framework="pydantic_ai", tool_call_id="call")
        self.assertEqual(sent.call_args.kwargs["proposal"]["payload"], {"fields": {"note": "synthetic"}})
        self.assertIsInstance(arguments["proposal"]["payload"]["fields"], list)
        fields.append({"name": "note", "value": "second value"})
        with patch("yuanxingmu.adapters.client.request") as sent, self.assertRaisesRegex(ValueError, "duplicate_form_field"):
            self.client.invoke("propose_action", arguments, framework="pydantic_ai", tool_call_id="call")
        sent.assert_not_called()

    def test_uncertain_transport_is_never_retried(self):
        with patch("yuanxingmu.adapters.client.request", side_effect=TimeoutError("synthetic lost response")) as sent:
            with self.assertRaises(TimeoutError):
                self.client.invoke("send", {"destination": "public", "body": "synthetic"}, framework="openai_agents")
        self.assertEqual(sent.call_count, 1)

    def test_raw_json_rejects_duplicate_keys_and_nonobjects(self):
        self.assertEqual(decode_arguments('{"draft":{"body":"a"}}'), {"draft": {"body": "a"}})
        for value in ('[]', 'null', '{"body":"a","body":"b"}', '{"draft":{"body":"a","body":"b"}}',
                      '{"value":NaN}', '{"value":Infinity}', '{'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                decode_arguments(value)


if __name__ == "__main__":
    unittest.main()
