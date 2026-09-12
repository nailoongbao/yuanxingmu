"""Validate the small RunState subset emitted by the fixed pinned worker.

Do this before native deserialization: fixed agents and tools, plain JSON,
empty SDK approvals, no hosted tools, sandbox state, callbacks, or sessions.
Every future effect is independently matched against the host model journal.
"""
from agents._tool_invocation import tool_invocation_identity_and_scope
from agents.usage import Usage, serialize_usage

from ._runtime_support import checked_text, json_bytes


NATIVE_FIELDS = {"$schemaVersion", "current_turn", "current_agent", "original_input", "pending_input",
    "model_responses", "context", "tool_use_tracker", "max_turns", "no_active_agent_run",
    "input_guardrail_results", "output_guardrail_results", "tool_input_guardrail_results",
    "tool_output_guardrail_results", "conversation_id", "previous_response_id", "auto_previous_response_id",
    "generated_prompt_cache_key", "reasoning_item_id_policy", "nested_history_owned_session_item_refs",
    "generated_session_item_indexes", "generated_items", "session_items", "current_step", "last_model_response",
    "last_processed_response", "current_turn_persisted_item_count", "trace"}
EMPTY_LISTS = {"pending_input", "input_guardrail_results", "output_guardrail_results",
    "tool_input_guardrail_results", "tool_output_guardrail_results", "nested_history_owned_session_item_refs"}
NULLS = {"conversation_id", "previous_response_id", "generated_prompt_cache_key", "reasoning_item_id_policy", "trace"}
UNUSED_ACTIONS = {"computer_actions", "custom_tool_actions", "local_shell_actions", "shell_actions",
                  "apply_patch_actions", "handoffs", "mcp_approval_requests"}


def _object(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("sdk_invalid_native_state")


def _list(value, maximum=8192):
    if type(value) is not list or len(value) > maximum:
        raise ValueError("sdk_invalid_native_state")
    return value


def validate_saved(loop):
    from .openai_agents_runtime import EXECUTOR, HANDOFF_TOOL, RESEARCHER, _check_action_outcome

    saver, value = loop.checkpoint, loop.checkpoint.value
    saver.check_envelope()
    native = value["native"]
    if (type(native) is not dict or not NATIVE_FIELDS <= set(native)
            or set(native) - NATIVE_FIELDS - {"current_response_generated_item_ownership"}
            or native["$schemaVersion"] != "1.17" or native["auto_previous_response_id"] is not False
            or native["no_active_agent_run"] is not True or type(native["current_turn_persisted_item_count"]) is not int
            or native["current_turn_persisted_item_count"] != 0
            or any(native[key] != [] for key in EMPTY_LISTS) or any(native[key] is not None for key in NULLS)):
        raise ValueError("sdk_native_state_not_supported")
    if (type(native["current_turn"]) is not int or type(native["max_turns"]) is not int
            or not 1 <= native["max_turns"] <= 128
            or native["current_turn"] != value["native_cursor"] - value["round_start"]
            or not 0 <= native["current_turn"] <= native["max_turns"]
            or value["status"] == "running" and native["max_turns"] != loop.config["max_steps"]):
        raise ValueError("sdk_native_turn_changed")

    all_calls, output_messages, response_rows = {}, {}, []
    for index, row in enumerate(value["records"]):
        loop.check_record(row)
        if row["response"] is None:
            continue
        response = loop.native_response(row["response"], row["agent"], index)
        serialized = {"usage": serialize_usage(response.usage),
                      "output": [item.model_dump(exclude_unset=True) for item in response.output],
                      "response_id": None, "request_id": None}
        for raw in serialized["output"]:
            if raw["type"] == "function_call":
                if raw["call_id"] in all_calls:
                    raise ValueError("sdk_reused_host_nonce")
                all_calls[raw["call_id"]] = (index, row["agent"], raw)
            else:
                output_messages[raw["id"]] = (index, row["agent"], raw)
        if value["round_start"] <= index < value["native_cursor"]:
            response_rows.append(serialized)
    if (json_bytes(native["model_responses"]) != json_bytes(response_rows)
            or json_bytes(native["last_model_response"]) != json_bytes(response_rows[-1] if response_rows else None)):
        raise ValueError("sdk_native_model_response_changed")

    agent = RESEARCHER
    current_calls = []
    for index in range(value["round_start"], value["native_cursor"]):
        row = value["records"][index]
        if row["agent"] != agent:
            raise ValueError("sdk_native_handoff_changed")
        _, calls = loop.response(row["response"], agent)
        current_calls += [call["id"] for call in calls]
        if any(call["name"] == HANDOFF_TOOL for call in calls):
            agent = EXECUTOR
    if native["current_agent"] != {"name": agent}:
        raise ValueError("sdk_native_agent_changed")

    def raw_call(raw, *, accepted=True):
        if type(raw) is not dict:
            raise ValueError("sdk_invalid_native_call")
        known = all_calls.get(raw.get("call_id"))
        if known is None or raw != known[2] or accepted and known[0] >= value["native_cursor"]:
            raise ValueError("sdk_native_call_changed")
        return known

    def raw_output(raw):
        _object(raw, {"type", "call_id", "output"})
        if raw["type"] != "function_call_output" or raw["call_id"] not in all_calls:
            raise ValueError("sdk_invalid_native_output")
        index, owner, call = all_calls[raw["call_id"]]
        expected = ('{"assistant": "yuanxingmu_executor"}' if call["name"] == HANDOFF_TOOL
                    else value["records"][index]["results"].get(raw["call_id"]))
        if expected is None or raw["output"] != expected:
            raise ValueError("sdk_native_tool_output_changed")
        if call["name"] != HANDOFF_TOOL:
            _check_action_outcome(raw["output"])
        return index, owner, call

    def message(raw):
        if type(raw) is not dict:
            raise ValueError("sdk_invalid_native_message")
        known = output_messages.get(raw.get("id"))
        if known is None or raw != known[2]:
            raise ValueError("sdk_native_message_changed")
        return known

    def item(value):
        if type(value) is not dict or not {"type", "agent", "raw_item"} <= set(value):
            raise ValueError("sdk_invalid_native_item")
        kind, raw = value["type"], value["raw_item"]
        fields = {"type", "agent", "raw_item"}
        if kind == "message_output_item":
            index, owner, _ = message(raw)
        elif kind in ("handoff_call_item", "tool_call_item", "tool_approval_item"):
            index, owner, call = raw_call(raw)
            name = call["name"]
            if kind == "handoff_call_item":
                if name != HANDOFF_TOOL:
                    raise ValueError("sdk_invalid_native_handoff")
            else:
                if name == HANDOFF_TOOL:
                    raise ValueError("sdk_invalid_native_handoff")
                fields |= {"tool_name", "tool_origin"}
                if value.get("tool_name") != name or value.get("tool_origin") != {"type": "function"}:
                    raise ValueError("sdk_native_tool_changed")
                if kind == "tool_call_item":
                    fields.add("description")
                    if value.get("description") != loop.function_tools[name].description:
                        raise ValueError("sdk_native_tool_changed")
                else:
                    fields.add("tool_lookup_key")
                    if value.get("tool_lookup_key") != {"kind": "bare", "name": name}:
                        raise ValueError("sdk_native_tool_changed")
        elif kind in ("tool_call_output_item", "handoff_output_item"):
            index, owner, call = raw_output(raw)
            if kind == "handoff_output_item":
                fields |= {"source_agent", "target_agent"}
                if (call["name"] != HANDOFF_TOOL or value.get("source_agent") != {"name": RESEARCHER}
                        or value.get("target_agent") != {"name": EXECUTOR}):
                    raise ValueError("sdk_native_handoff_changed")
            else:
                fields |= {"output", "tool_origin"}
                if (call["name"] == HANDOFF_TOOL or value.get("output") != raw["output"]
                        or value.get("tool_origin") != {"type": "function"}):
                    raise ValueError("sdk_native_tool_output_changed")
        else:
            raise ValueError("sdk_native_item_not_supported")
        _object(value, fields)
        if value["agent"] != {"name": owner}:
            raise ValueError("sdk_native_agent_changed")
        return index

    original = native["original_input"]
    old_outputs = set()
    if type(original) is str:
        if original != value["prompt"]:
            raise ValueError("sdk_native_prompt_changed")
    else:
        users = []
        for raw in _list(original):
            if type(raw) is not dict:
                raise ValueError("sdk_native_input_not_supported")
            kind = raw.get("type")
            if raw.get("role") == "user":
                _object(raw, {"role", "content"})
                users.append(checked_text(raw["content"], 256 * 1024))
            elif kind == "function_call":
                index, _, _ = raw_call(raw)
                if index >= value["round_start"]:
                    raise ValueError("sdk_native_input_changed")
            elif kind == "function_call_output":
                index, _, _ = raw_output(raw)
                if index >= value["round_start"]:
                    raise ValueError("sdk_native_input_changed")
                old_outputs.add(raw["call_id"])
            elif kind == "message":
                index, _, _ = message(raw)
                if index >= value["round_start"]:
                    raise ValueError("sdk_native_input_changed")
            else:
                raise ValueError("sdk_native_input_not_supported")
        if not users or users[-1] != value["prompt"]:
            raise ValueError("sdk_native_prompt_changed")

    for key in ("generated_items", "session_items"):
        for entry in _list(native[key]):
            index = item(entry)
            if not value["round_start"] <= index < value["native_cursor"]:
                raise ValueError("sdk_native_item_changed")
    indexes = _list(native["generated_session_item_indexes"])
    if (any(type(index) is not int or not 0 <= index < len(native["session_items"]) for index in indexes)
            or indexes != sorted(set(indexes)) or [native["session_items"][index] for index in indexes] != native["generated_items"]):
        raise ValueError("sdk_native_history_changed")

    outputs, call_items = {}, []
    for entry in native["generated_items"]:
        if entry["type"] in ("handoff_call_item", "tool_call_item"):
            call_items.append(entry["raw_item"]["call_id"])
        elif entry["type"] in ("handoff_output_item", "tool_call_output_item"):
            nonce = entry["raw_item"]["call_id"]
            if nonce in outputs:
                raise ValueError("sdk_duplicate_native_output")
            outputs[nonce] = entry
    if call_items != current_calls:
        raise ValueError("sdk_native_call_history_changed")
    context = native["context"]
    _object(context, {"usage", "approvals", "tool_invocations", "context", "context_meta"})
    if (context["approvals"] != {} or context["context"] != {}
            or context["context_meta"] != {"original_type": "mapping", "serialized_via": "mapping",
                                           "requires_deserializer": False, "omitted": False}
            or json_bytes(context["usage"]) != json_bytes(serialize_usage(Usage(requests=native["current_turn"])))):
        raise ValueError("sdk_native_context_not_allowed")
    ledger = context["tool_invocations"]
    if type(ledger) is not dict or set(ledger) - set(current_calls) - old_outputs or set(current_calls) - set(ledger):
        raise ValueError("sdk_native_ledger_changed")
    for nonce, record in ledger.items():
        _object(record, {"type", "approval_scope", "fingerprint", "executed", "completed"})
        raw = all_calls[nonce][2]
        identity = tool_invocation_identity_and_scope(raw, invocation_role="handoff" if raw["name"] == HANDOFF_TOOL else None)
        complete = nonce in outputs or nonce in old_outputs
        if (type(record["executed"]) is not bool or type(record["completed"]) is not bool
                or identity is None or record != {"type": identity[0], "approval_scope": identity[2], "fingerprint": identity[3],
                                         "executed": complete, "completed": complete}):
            raise ValueError("sdk_native_ledger_changed")
    tracker = native["tool_use_tracker"]
    if type(tracker) is not dict or set(tracker) - set(loop.names):
        raise ValueError("sdk_native_tools_changed")
    for owner, names in tracker.items():
        if any(type(name) is not str or name not in loop.names[owner] for name in _list(names)):
            raise ValueError("sdk_native_tools_changed")

    processed, step = native["last_processed_response"], native["current_step"]
    if not response_rows:
        if (processed is not None or step is not None or native["generated_items"] or value["status"] != "running"
                or "current_response_generated_item_ownership" in native):
            raise ValueError("sdk_native_initial_state_changed")
        return
    if value["status"] == "completed":
        last_row = value["records"][value["native_cursor"] - 1]
        final_message, final_calls = loop.response(last_row["response"], last_row["agent"])
        if (processed is not None or step is not None or final_calls
                or any(nonce not in outputs for nonce in current_calls)
                or value["answer"] != final_message.get("content")
                or value["native_cursor"] != len(value["records"])
                or "current_response_generated_item_ownership" in native):
            raise ValueError("sdk_native_completion_changed")
        return
    _object(processed, {"new_items", "tools_used", "functions", "interruptions", *UNUSED_ACTIONS})
    if any(processed[key] != [] for key in UNUSED_ACTIONS):
        raise ValueError("sdk_native_tools_not_supported")
    last_row = value["records"][value["native_cursor"] - 1]
    _, last_calls = loop.response(last_row["response"], last_row["agent"])
    for entry in _list(processed["new_items"]):
        if item(entry) != value["native_cursor"] - 1 or entry["type"] not in ("message_output_item", "tool_call_item"):
            raise ValueError("sdk_native_processed_response_changed")
    if [entry["raw_item"] for entry in processed["new_items"]] != response_rows[-1]["output"]:
        raise ValueError("sdk_native_processed_response_changed")
    if processed["tools_used"] != [call["name"] for call in last_calls]:
        raise ValueError("sdk_native_processed_response_changed")
    functions = _list(processed["functions"], 32)
    if len(functions) != len(last_calls):
        raise ValueError("sdk_native_processed_response_changed")
    for function, call in zip(functions, last_calls):
        _object(function, {"tool", "tool_call"})
        raw_call(function["tool_call"])
        tool = loop.function_tools.get(call["name"])
        if (tool is None or function["tool_call"] != all_calls[call["id"]][2]
                or function["tool"] != {"name": tool.name, "lookupKey": {"kind": "bare", "name": tool.name},
                                       "description": tool.description, "paramsJsonSchema": tool.params_json_schema}):
            raise ValueError("sdk_native_tool_definition_changed")
    pending = [nonce for nonce in current_calls if nonce not in outputs]
    interruptions = _list(processed["interruptions"], 32)
    for entry in interruptions:
        if item(entry) != value["native_cursor"] - 1 or entry["type"] != "tool_approval_item":
            raise ValueError("sdk_native_interruption_changed")
    if [entry["raw_item"]["call_id"] for entry in interruptions] != pending:
        raise ValueError("sdk_native_interruption_changed")
    if pending:
        ids = [call["id"] for call in last_calls]
        if pending != ids[len(ids) - len(pending):] or value["status"] != "running":
            raise ValueError("sdk_native_dispatch_order_changed")
        if step != {"type": "next_step_interruption", "data": {"interruptions": interruptions,
                     "response_accepted": False, "llm_end_hooks_started": True}}:
            raise ValueError("sdk_native_interruption_changed")
    else:
        raise ValueError("sdk_native_interruption_missing")
    ownership = native.get("current_response_generated_item_ownership")
    _object(ownership, {"start", "end", "interruptions"})
    current_indexes = [index for index, entry in enumerate(native["generated_items"])
                       if item(entry) == value["native_cursor"] - 1]
    pending_indexes = [index for index in current_indexes
                       if native["generated_items"][index]["type"] == "tool_approval_item"
                       and native["generated_items"][index]["raw_item"]["call_id"] in pending]
    if (not current_indexes or len(pending_indexes) != len(pending)
            or json_bytes(ownership) != json_bytes({"start": current_indexes[0], "end": len(native["generated_items"]),
                                                    "interruptions": pending_indexes})):
        raise ValueError("sdk_native_ownership_changed")
    start = current_indexes[0]
    if (native["generated_items"][start:start + len(processed["new_items"])] != processed["new_items"]
            or [native["generated_items"][index] for index in pending_indexes] != interruptions):
        raise ValueError("sdk_native_ownership_changed")
