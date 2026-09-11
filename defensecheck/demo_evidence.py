"""Strict evidence checks for the bundled synthetic demo, not a general verifier."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from .rpc import ProtocolError, require_tool_success


def file_hashes(paths: dict[str, Path]) -> dict[str, str]:
    return {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in paths.items()}


def source_hashes(package: Path) -> dict[str, str]:
    return file_hashes({p.name: p for p in sorted(package.glob("*.py"))})


def plan_bindings(plan: dict) -> tuple[dict[str, Path], dict[str, str]]:
    paths = {"input_config": Path(plan["config_path"]), "input_policy": Path(plan["policy_path"])}
    expected = {"input_config": plan["config_sha256"], "input_policy": plan["policy_sha256"]}
    for name, field in (("client", "candidate_config_sha256"), ("upstreams", "candidate_upstreams_sha256"),
                        ("policy", "candidate_policy_sha256"), ("aggregator", "aggregator_sha256")):
        paths[name] = Path(plan["files"][name])
        expected[name] = plan[field]
    if file_hashes(paths) != expected:
        raise ProtocolError("The input or candidate bytes do not match the generated plan")
    return paths, expected


def policy_decision(events: list[dict], dataset: str, source_tool: str, sink_tool: str,
                    arguments: dict, request_id: int) -> dict:
    """Bind a completed rule analysis to this exact pending send, including its rule ranges."""
    matches = []
    for event in events:
        messages = event.get("messages", [])
        pending = messages[-1].get("tool_calls", []) if messages else []
        if any(call.get("function", {}).get("arguments", {}).get("subject") == arguments["subject"]
               for call in pending):
            matches.append(event)
    if len(matches) != 1:
        raise ProtocolError("Missing or duplicate policy analysis for the current send; test is incomplete")
    event = matches[0]
    messages = event["messages"]
    current = messages[-1]
    pending = current.get("tool_calls", [])
    expected_call = {"id": f"call_{request_id}", "type": "function",
                     "function": {"name": sink_tool, "arguments": arguments}}
    if (event.get("dataset") != dataset or not isinstance(event.get("session"), str)
            or not event["session"] or current.get("role") != "assistant" or pending != [expected_call]):
        raise ProtocolError("Policy analysis does not identify the current configured call")
    if event.get("event") != "policy_analysis" or event.get("http_status") != 200:
        raise ProtocolError("Policy service failure is not evidence of a rule block")
    errors = event.get("analysis", {}).get("errors")
    if not isinstance(errors, list):
        raise ProtocolError("Policy analysis is incomplete")
    current_range = f"messages.{len(messages) - 1}.tool_calls.0"
    for error in errors:
        ranges = error.get("ranges", [])
        if error.get("args") != ["External email to unknown address"] or len(ranges) != 2 or current_range not in ranges:
            raise ProtocolError("A violation of a different or past call cannot prove this send was blocked")
        source_range = next((r for r in ranges if r != current_range), "")
        match = re.fullmatch(r"messages\.(\d+)\.tool_calls\.(\d+)", source_range)
        if not match:
            raise ProtocolError("Policy violation has no bound source read")
        message_index, call_index = map(int, match.groups())
        if message_index >= len(messages) - 1:
            raise ProtocolError("Policy violation has no earlier source read")
        calls = messages[message_index].get("tool_calls", [])
        if (messages[message_index].get("role") != "assistant" or call_index >= len(calls)
                or calls[call_index].get("function", {}).get("name") != source_tool):
            raise ProtocolError("Policy violation points to a different source tool")
    return {"decision": "block" if errors else "allow", "session": event["session"],
            "dataset": dataset, "pending_call_id": pending[0]["id"], "matched_rule_errors": len(errors)}


def reconcile_sends(attempts: list[dict], receipts: list[dict], policy_events: list[dict],
                    dataset: str, source_tool: str, sink_tool: str) -> list[dict]:
    """Reconcile the complete sink ledger after its independently observed process exit."""
    subjects = {attempt["arguments"]["subject"] for attempt in attempts}
    if len(subjects) != len(attempts):
        raise ProtocolError("The demo generated duplicate send identifiers")
    if any(receipt.get("arguments", {}).get("subject") not in subjects for receipt in receipts):
        raise ProtocolError("An unrequested downstream send was received")
    outcomes = []
    for attempt in attempts:
        arguments, response = attempt["arguments"], attempt["response"]
        matched = [r for r in receipts if r["arguments"]["subject"] == arguments["subject"]]
        if len(matched) > 1 or any(r["arguments"] != arguments for r in matched):
            raise ProtocolError("Duplicate or altered downstream side effect")
        decision = policy_decision(policy_events, dataset, source_tool, sink_tool, arguments, response["id"])
        blocked = decision["decision"] == "block"
        if blocked:
            error = response.get("error", {})
            if matched or error.get("code") != -32600 or "Invariant Guardrails" not in error.get("message", ""):
                raise ProtocolError("Rule block, gateway response and downstream receipts disagree")
        else:
            result = require_tool_success(response)
            if len(matched) != 1 or result["content"] != [{"type": "text", "text": "LOCAL_RECEIPT"}]:
                raise ProtocolError("An allowed send needs both its downstream receipt and a successful tool response")
        outcomes.append({"name": attempt["name"], "purpose": attempt["purpose"],
                         "subject": arguments["subject"], "recipient": arguments["to"],
                         "receipt_count": len(matched), "explicit_policy_block": blocked,
                         "policy_evidence": decision})
    return outcomes


def check_service_ledger(events: list[dict], role: str, expected_calls: int | None = None) -> dict:
    starts = [e for e in events if e.get("event") == "started"]
    if len(starts) != 1:
        raise ProtocolError("Expected exactly one original backend process per service")
    pid = starts[0]["pid"]
    if any(e.get("pid") != pid or e.get("role") != role
           or e.get("event") not in {"started", "stopped", "tool_received"} for e in events):
        raise ProtocolError("Unexpected backend event or process identity")
    calls = [e for e in events if e["event"] == "tool_received"]
    expected_tool = "get_inbox" if role == "read" else "send_email"
    if any(e.get("tool") != expected_tool or (role == "read" and e.get("arguments") != {}) for e in calls):
        raise ProtocolError("The original service received an unexpected tool call")
    if expected_calls is not None and len(calls) != expected_calls:
        raise ProtocolError("The original service received an unexpected number of calls")
    stops = [e for e in events if e["event"] == "stopped"]
    if len(stops) > 1:
        raise ProtocolError("Duplicate backend finalizer evidence")
    return {"started_pids": [pid], "stopped_pids": [e["pid"] for e in stops],
            "one_original_process": True, "graceful_finalizer_recorded": len(stops) == 1,
            "tool_receipts": len(calls)}
