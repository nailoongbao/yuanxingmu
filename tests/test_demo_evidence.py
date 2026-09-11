from __future__ import annotations

from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from defensecheck.demo import run_demo
from defensecheck.demo_evidence import file_hashes, plan_bindings, reconcile_sends
from defensecheck.rpc import ProtocolError


FIXTURE = json.loads((Path(__file__).with_name("fixtures") / "demo-evidence.json").read_text(encoding="utf-8"))


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.record = deepcopy(FIXTURE["blocked"])

    def evaluate(self, record=None, receipts=None, events=None):
        record = self.record if record is None else record
        after = record["event"]["dataset"] == "after"
        return reconcile_sends([{"name": "private-external", "purpose": "prohibited",
            "arguments": record["arguments"], "response": record["response"]}],
            receipts or [], events if events is not None else [record["event"]], record["event"]["dataset"],
            "read_get_inbox" if after else "get_inbox", "write_send_email" if after else "send_email")

    def test_actual_correlated_block_is_accepted(self):
        result = self.evaluate()[0]
        self.assertTrue(result["explicit_policy_block"])
        self.assertEqual(result["receipt_count"], 0)
        self.assertEqual(result["policy_evidence"]["matched_rule_errors"], 1)

    def test_same_gateway_error_without_rule_evidence_is_not_a_block(self):
        with self.assertRaises(ProtocolError):
            self.evaluate(events=[])
        self.record["event"].update(event="policy_error", http_status=503)
        with self.assertRaisesRegex(ProtocolError, "service failure"):
            self.evaluate()

    def test_an_old_violation_does_not_prove_the_current_send_was_blocked(self):
        self.record["event"]["analysis"]["errors"][0]["ranges"][-1] = "messages.0.tool_calls.0"
        with self.assertRaisesRegex(ProtocolError, "past call"):
            self.evaluate()

    def test_other_project_call_or_arguments_cannot_supply_evidence(self):
        changes = [
            lambda e: e.update(dataset="wrong-project"),
            lambda e: e["messages"][-1]["tool_calls"][0].update(id="call_999"),
            lambda e: e["messages"][-1]["tool_calls"][0]["function"]["arguments"].update(to="someone@example.invalid"),
            lambda e: e["messages"][2]["tool_calls"][0]["function"].update(name="different_read"),
        ]
        for change in changes:
            with self.subTest(change=change):
                event = deepcopy(self.record["event"])
                change(event)
                with self.assertRaises(ProtocolError):
                    self.evaluate(events=[event])

    def test_any_receipt_invalidates_a_claimed_block(self):
        with self.assertRaises(ProtocolError):
            self.evaluate(receipts=[{"arguments": self.record["arguments"]}])

    def test_duplicate_policy_events_are_not_accepted(self):
        with self.assertRaises(ProtocolError):
            self.evaluate(events=[self.record["event"], self.record["event"]])

    def test_success_requires_valid_response_and_exactly_one_unchanged_receipt(self):
        record = deepcopy(FIXTURE["allowed"])
        receipt = {"arguments": record["arguments"]}
        self.assertEqual(self.evaluate(record, [receipt])[0]["receipt_count"], 1)
        for receipts in ([], [receipt, receipt], [{"arguments": {**record["arguments"], "body": "changed"}}]):
            with self.subTest(receipts=receipts), self.assertRaises(ProtocolError):
                self.evaluate(record, receipts)
        record["response"]["result"]["isError"] = True
        with self.assertRaises(ProtocolError):
            self.evaluate(record, [receipt])

    def test_unattributed_or_late_extra_send_is_rejected(self):
        extra = {"arguments": {**self.record["arguments"], "subject": "not-requested"}}
        with self.assertRaisesRegex(ProtocolError, "unrequested"):
            self.evaluate(receipts=[extra])

    def test_changed_input_or_candidate_cannot_reuse_old_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = ["input_config", "input_policy", "client", "upstreams", "policy", "aggregator"]
            paths = {name: root / name for name in names}
            for name, path in paths.items():
                path.write_bytes(name.encode())
            hashes = file_hashes(paths)
            plan = {"config_path": str(paths["input_config"]), "policy_path": str(paths["input_policy"]),
                    "files": {k: str(v) for k, v in paths.items()},
                    "config_sha256": hashes["input_config"], "policy_sha256": hashes["input_policy"],
                    "candidate_config_sha256": hashes["client"], "candidate_upstreams_sha256": hashes["upstreams"],
                    "candidate_policy_sha256": hashes["policy"], "aggregator_sha256": hashes["aggregator"]}
            self.assertEqual(plan_bindings(plan), (paths, hashes))
            for name, path in paths.items():
                with self.subTest(name=name):
                    path.write_bytes(b"changed")
                    with self.assertRaises(ProtocolError):
                        plan_bindings(plan)
                    path.write_bytes(name.encode())


class CompletionTests(unittest.TestCase):
    """Negative completion tests use fake workflows; they are never integration evidence."""
    def test_successful_workflows_followed_by_cleanup_error_or_interrupt_stay_incomplete(self):
        for failure in (RuntimeError("cleanup failed"), KeyboardInterrupt("interrupted")):
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as directory, ExitStack() as stack:
                output = Path(directory) / "run"
                service = SimpleNamespace(url="http://127.0.0.1:1", process=SimpleNamespace(returncode=0), forced_termination=False)
                manager = stack.enter_context(patch("defensecheck.demo.PolicyProcess"))
                manager.return_value.__enter__.return_value = service
                manager.return_value.__exit__.side_effect = failure
                stack.enter_context(patch("defensecheck.demo.runtime_identity", side_effect=[
                    {"invariant-ai": "0.3.5", "invariant-gateway": "0.0.9"},
                    {"fastmcp-slim": "4.0.3", "mcp": "2.2.0", "mcp-types": "2.2.0"}]))
                stack.enter_context(patch("defensecheck.demo.gateway_integrity", return_value={"test_double": True}))
                stack.enter_context(patch("defensecheck.demo.read_events", return_value=[deepcopy(FIXTURE["blocked"]["event"])]))
                def workflow(_config, _source, _sink, _output, phase, _marker, clean_public=False):
                    if phase == "before":
                        steps = [{"purpose": "prohibited", "receipt_count": 1}] * 3
                    elif phase == "after":
                        steps = [{"purpose": "prohibited", "receipt_count": 0}] * 3 + [
                            {"purpose": "legitimate", "receipt_count": 1}] * 2 + [
                            {"purpose": "conservative_cost", "receipt_count": 0, "explicit_policy_block": True}]
                    else:
                        steps = [{"purpose": "legitimate", "receipt_count": 1}]
                    return {"steps": steps, "gateway_processes_exit_cleanly": True,
                        "independent_backend_processes": True, "process_exit_observation": {"all_exited": True, "all_captured_alive": True},
                        "services": {"read": {"one_original_process": True}, "write": {"one_original_process": True}}}
                stack.enter_context(patch("defensecheck.demo.run_workflow", side_effect=workflow))
                with self.assertRaises(type(failure)) as observed:
                    run_demo(output, Path(sys.executable), Path(sys.executable))
                self.assertIsNone(observed.exception.__context__, "Workflow failed before the simulated cleanup: " + str(observed.exception.__context__))
                report = json.loads((output / "results.json").read_text(encoding="utf-8"))
                self.assertEqual(report["counts"]["prohibited_sends_received_after"], 0)
                self.assertEqual(report["status"], "incomplete")
                self.assertEqual(report["error"]["type"], type(failure).__name__)


if __name__ == "__main__":
    unittest.main()
