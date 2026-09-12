"""Validate the fixed native message subset before SDK deserialization.

PydanticAI's message TypeAdapter discards unknown fields. These checks run
first, reject provider-specific/stateful content, and match the native history
to original host responses and cached tool outputs. Checkpoints are recovery
data; each future effect also rechecks the host journal and current authority.
"""
from ._runtime_support import checked_text, json_bytes


REQUEST_FIELDS = {"parts", "timestamp", "instructions", "kind", "run_id", "conversation_id", "metadata", "state"}
RESPONSE_FIELDS = {"parts", "usage", "model_name", "timestamp", "kind", "provider_name", "provider_url",
                   "provider_details", "provider_response_id", "finish_reason", "run_id", "conversation_id",
                   "metadata", "state"}
TEXT_FIELDS = {"content", "id", "provider_name", "provider_details", "part_kind"}
CALL_FIELDS = {"tool_name", "args", "tool_call_id", "tool_kind", "id", "provider_name", "provider_details", "part_kind"}
RETURN_FIELDS = {"tool_name", "content", "tool_call_id", "tool_kind", "metadata", "timestamp", "outcome", "part_kind"}
USAGE_FIELDS = {"input_tokens", "cache_write_tokens", "cache_read_tokens", "output_tokens", "input_audio_tokens",
                "cache_audio_read_tokens", "output_audio_tokens", "details", "cost"}


def _object(value, fields):
    if type(value) is not dict or set(value) != fields:
        raise ValueError("sdk_invalid_native_state")


def assistant(loop, response):
    message, calls = loop.response(response)
    result = {"role": "assistant", "content": message.get("content")}
    if calls:
        result["tool_calls"] = [{"id": call["id"], "type": "function", "function": {
            "name": call["name"], "arguments": json_bytes(call["arguments"]).decode()}} for call in calls]
    return result


def native_messages(loop, native):
    from .pydantic_ai_runtime import INSTRUCTIONS, _check_action_outcome

    if type(native) is not list or len(native) > 256:
        raise ValueError("sdk_invalid_native_state")
    output = []
    for index, message in enumerate(native):
        if type(message) is not dict:
            raise ValueError("sdk_invalid_native_state")
        kind = message.get("kind")
        _object(message, REQUEST_FIELDS if kind == "request" else RESPONSE_FIELDS)
        if (kind != ("request" if index % 2 == 0 else "response") or message["metadata"] is not None
                or message["state"] != "complete" or type(message["parts"]) is not list
                or not 1 <= len(message["parts"]) <= 33):
            raise ValueError("sdk_invalid_native_state")
        for key in ("run_id", "conversation_id", "timestamp"):
            if not checked_text(message[key], 128):
                raise ValueError("sdk_invalid_native_state")
        if kind == "request":
            if message["instructions"] != INSTRUCTIONS:
                raise ValueError("sdk_native_instructions_changed")
            kinds = {part.get("part_kind") for part in message["parts"] if type(part) is dict}
            if kinds not in ({"user-prompt"}, {"tool-return"}):
                raise ValueError("sdk_native_request_part_not_supported")
            if kinds == {"user-prompt"} and len(message["parts"]) != 1:
                raise ValueError("sdk_invalid_native_state")
            for part in message["parts"]:
                if kinds == {"user-prompt"}:
                    _object(part, {"content", "timestamp", "part_kind"})
                    checked_text(part["timestamp"], 128)
                    output.append({"role": "user", "content": checked_text(part["content"])})
                else:
                    _object(part, RETURN_FIELDS)
                    if part["tool_kind"] is not None or part["metadata"] is not None or part["outcome"] != "success":
                        raise ValueError("sdk_native_tool_return_changed")
                    checked_text(part["tool_name"], 128)
                    checked_text(part["timestamp"], 128)
                    nonce = checked_text(part["tool_call_id"], 512)
                    _check_action_outcome(part["content"])
                    output.append({"role": "tool", "tool_call_id": nonce, "content": part["content"]})
        else:
            if (message["model_name"] != loop.config["model_id"] or message["provider_name"] != "yuanxingmu-host"
                    or any(message[key] is not None for key in ("provider_url", "provider_details", "provider_response_id"))):
                raise ValueError("sdk_native_provider_state_not_supported")
            usage = message["usage"]
            _object(usage, USAGE_FIELDS)
            if usage["details"] != {} or usage["cost"] is not None or any(
                    type(usage[key]) is not int or usage[key] != 0 for key in USAGE_FIELDS - {"details", "cost"}):
                raise ValueError("sdk_native_usage_changed")
            content, calls = None, []
            for position, part in enumerate(message["parts"]):
                if type(part) is not dict:
                    raise ValueError("sdk_invalid_native_state")
                if part.get("part_kind") == "text":
                    _object(part, TEXT_FIELDS)
                    if position != 0:
                        raise ValueError("sdk_native_response_part_changed")
                    content = checked_text(part["content"])
                elif part.get("part_kind") == "tool-call":
                    _object(part, CALL_FIELDS)
                    if part["tool_kind"] is not None or type(part["args"]) is not dict:
                        raise ValueError("sdk_native_tool_call_changed")
                    calls.append({"id": part["tool_call_id"], "type": "function", "function": {
                        "name": part["tool_name"], "arguments": json_bytes(part["args"]).decode()}})
                else:
                    raise ValueError("sdk_native_response_part_not_supported")
                if any(part[key] is not None for key in ("id", "provider_name", "provider_details")):
                    raise ValueError("sdk_native_provider_state_not_supported")
            if message["finish_reason"] != ("tool_call" if calls else "stop"):
                raise ValueError("sdk_native_finish_reason_changed")
            translated = {"role": "assistant", "content": content}
            if calls:
                translated["tool_calls"] = calls
            loop.calls(translated)
            output.append(translated)
    return output


def validate_saved(loop):
    from .pydantic_ai_runtime import INSTRUCTIONS

    value = loop.checkpoint.value
    loop.checkpoint.check_envelope()
    for row in value["records"]:
        loop.check_record(row)
    native = value["native"]
    projected = native_messages(loop, native)
    cursor = value["native_cursor"]
    if len(native) != cursor * 2:
        raise ValueError("sdk_native_cursor_changed")
    previous, all_ids = [], set()
    for index, row in enumerate(value["records"]):
        request = row["request"]["messages"][1:]
        if not request or request[:len(previous)] != previous:
            raise ValueError("sdk_checkpoint_history_changed")
        additions = request[len(previous):]
        if index == 0 or not previous[-1].get("tool_calls"):
            if len(additions) != 1 or additions[0].get("role") != "user":
                raise ValueError("sdk_checkpoint_user_turn_changed")
        else:
            last_row = value["records"][index - 1]
            calls = loop.response(last_row["response"])[1]
            expected = [{"role": "tool", "tool_call_id": call["id"],
                         "content": last_row["results"].get(call["id"])} for call in calls]
            if any(item["content"] is None for item in expected) or additions != expected:
                raise ValueError("sdk_checkpoint_tool_history_changed")
        if row["response"] is not None:
            calls = loop.response(row["response"])[1]
            ids = {call["id"] for call in calls}
            if all_ids & ids:
                raise ValueError("sdk_repeated_host_nonce")
            all_ids.update(ids)
            ordered_results = [call["id"] for call in calls if call["id"] in row["results"]]
            if ordered_results != [call["id"] for call in calls[:len(row["results"])]]:
                raise ValueError("sdk_checkpoint_dispatch_order_changed")
            previous = [*request, assistant(loop, row["response"])]
        if index < cursor:
            current = native_messages(loop, native[:2 * index + 2])
            if current != previous:
                raise ValueError("sdk_native_history_changed")
            # ToolReturnPart.tool_name is not sent on the bridge wire. Bind it
            # to the original native call too, before parsing the saved JSON.
            if native[2 * index]["parts"][0]["part_kind"] == "tool-return":
                names = {call["id"]: call["name"] for call in loop.response(value["records"][index - 1]["response"])[1]}
                if any(part["tool_name"] != names.get(part["tool_call_id"]) for part in native[2 * index]["parts"]):
                    raise ValueError("sdk_native_tool_return_changed")
    if cursor:
        if projected != [*value["records"][cursor - 1]["request"]["messages"][1:],
                         assistant(loop, value["records"][cursor - 1]["response"])]:
            raise ValueError("sdk_native_history_changed")
        last = projected[-1]
        if value["status"] == "completed":
            if (last.get("tool_calls") or last["content"] != value["answer"]
                    or cursor != len(value["records"])):
                raise ValueError("sdk_native_completion_changed")
        elif not last.get("tool_calls") and cursor != value["round_start"]:
            raise ValueError("sdk_native_pause_missing")
    elif native or value["status"] != "running":
        raise ValueError("sdk_native_pause_missing")
    if value["round_start"] < len(value["records"]):
        current_request = value["records"][value["round_start"]]["request"]["messages"]
        if current_request[-1] != {"role": "user", "content": value["prompt"]}:
            raise ValueError("sdk_checkpoint_prompt_changed")
