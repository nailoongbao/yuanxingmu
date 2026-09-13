"""Closed text/tool ADK event subset, checked before native deserialization.

Event defaults ignore unknown fields in this SDK. Recovery must instead bind
every accepted event to the original host message, tool result and workflow
position. Only event IDs/timestamps and the session update time are excluded
from replay comparison; native invocation/agent/node identities are retained.
"""
from copy import deepcopy
import math

from ._google_adk_checkpoint import invocation_id
from ._runtime_support import checked_text, json_bytes


EMPTY_ACTIONS = {"state_delta": {}, "artifact_delta": {}, "requested_auth_configs": {},
                 "requested_tool_confirmations": {}}
EVENT_FIELDS = {"invocation_id", "author", "actions", "node_info", "id", "timestamp"}
SESSION_FIELDS = {"id", "app_name", "user_id", "state", "events", "last_update_time"}


def _object(value, fields):
    if type(value) is not dict or set(value) != fields:
        raise ValueError("sdk_invalid_native_state")


def _parts(content):
    _object(content, {"role", "parts"})
    if content["role"] not in ("user", "model") or type(content["parts"]) is not list or not 1 <= len(content["parts"]) <= 33:
        raise ValueError("sdk_native_content_not_supported")
    kinds = []
    for part in content["parts"]:
        if type(part) is not dict or len(part) != 1:
            raise ValueError("sdk_native_part_not_supported")
        kind = next(iter(part))
        kinds.append(kind)
        if kind == "text":
            checked_text(part[kind])
        elif kind == "function_call":
            call = part[kind]
            _object(call, {"id", "name", "args"})
            if not checked_text(call["id"], 512) or not checked_text(call["name"], 128) or type(call["args"]) is not dict:
                raise ValueError("sdk_native_tool_call_changed")
        elif kind == "function_response":
            result = part[kind]
            _object(result, {"id", "name", "response"})
            _object(result["response"], {"result"})
            if not checked_text(result["id"], 512) or not checked_text(result["name"], 128):
                raise ValueError("sdk_native_tool_result_changed")
            if result["response"]["result"] is not None:
                checked_text(result["response"]["result"])
        else:
            # Includes remote auth, media, code execution, thought signatures,
            # provider-managed tools and any future unreviewed Part extension.
            raise ValueError("sdk_native_part_not_supported")
    if content["role"] == "model":
        if "function_response" in kinds or kinds.count("text") > 1 or "text" in kinds and kinds[0] != "text":
            raise ValueError("sdk_native_content_not_supported")
    elif set(kinds) not in ({"text"}, {"function_response"}):
        raise ValueError("sdk_native_content_not_supported")
    return kinds


def translate_contents(contents):
    if type(contents) is not list or not 1 <= len(contents) <= 512:
        raise ValueError("sdk_native_content_not_supported")
    messages = []
    for content in contents:
        kinds = _parts(content)
        if content["role"] == "user" and kinds[0] == "function_response":
            for part in content["parts"]:
                result = part["function_response"]
                text = result["response"]["result"]
                messages.append({"role": "tool", "tool_call_id": result["id"], "content": "null" if text is None else text})
        elif content["role"] == "user":
            messages.append({"role": "user", "content": "\n".join(part["text"] for part in content["parts"])})
        else:
            message = {"role": "assistant", "content": content["parts"][0].get("text")}
            calls = [part["function_call"] for part in content["parts"] if "function_call" in part]
            if calls:
                message["tool_calls"] = [{"id": call["id"], "type": "function", "function": {
                    "name": call["name"], "arguments": json_bytes(call["args"]).decode()}} for call in calls]
            messages.append(message)
    return messages


def validate_event(event):
    from .google_adk_runtime import COORDINATOR, EXECUTOR, STOP_REASONS
    if (type(event) is not dict or not EVENT_FIELDS <= set(event)
            or set(event) - EVENT_FIELDS - {"content", "long_running_tool_ids", "error_code", "error_message"}):
        raise ValueError("sdk_native_event_not_supported")
    for key in ("invocation_id", "id"):
        if not checked_text(event[key], 256):
            raise ValueError("sdk_invalid_native_state")
    if event["author"] not in ("user", COORDINATOR, EXECUTOR):
        raise ValueError("sdk_native_agent_changed")
    if type(event["timestamp"]) not in (int, float) or not math.isfinite(event["timestamp"]) or event["timestamp"] <= 0:
        raise ValueError("sdk_invalid_native_timestamp")
    _object(event["node_info"], {"path"})
    checked_text(event["node_info"]["path"], 256)
    actions = event["actions"]
    if actions not in (EMPTY_ACTIONS, {**EMPTY_ACTIONS, "transfer_to_agent": EXECUTOR},
                        {**EMPTY_ACTIONS, "end_of_agent": True}):
        raise ValueError("sdk_native_actions_not_supported")
    # bool equality must not admit an integer standing in for a native flag.
    if "end_of_agent" in actions and actions["end_of_agent"] is not True:
        raise ValueError("sdk_native_actions_not_supported")
    if "error_code" in event or "error_message" in event:
        if (set(event) != EVENT_FIELDS | {"error_code", "error_message"}
                or event["error_code"] != "RuntimeError" or event["error_message"] not in STOP_REASONS
                or actions != EMPTY_ACTIONS or event["author"] == "user"):
            raise ValueError("sdk_native_error_changed")
    elif "content" in event:
        kinds = _parts(event["content"])
        if ("long_running_tool_ids" in event and event["long_running_tool_ids"] != []
                or ("function_call" in kinds) != ("long_running_tool_ids" in event)):
            raise ValueError("sdk_native_long_running_not_supported")
    elif set(event) != EVENT_FIELDS or actions != {**EMPTY_ACTIONS, "end_of_agent": True}:
        raise ValueError("sdk_native_event_not_supported")


def event_projection(event):
    return {key: value for key, value in event.items() if key not in ("id", "timestamp")}


def _session(loop, native):
    from .google_adk_runtime import APP_NAME, USER_ID
    _object(native, SESSION_FIELDS)
    if (native["id"] != loop.config["session_id"] or native["app_name"] != APP_NAME or native["user_id"] != USER_ID
            or native["state"] != {} or type(native["events"]) is not list or len(native["events"]) > 768
            or type(native["last_update_time"]) not in (int, float) or not math.isfinite(native["last_update_time"])
            or native["last_update_time"] <= 0):
        raise ValueError("sdk_native_session_changed")
    ids = set()
    for index, event in enumerate(native["events"]):
        validate_event(event)
        if event["id"] in ids or "error_code" in event and index != len(native["events"]) - 1:
            raise ValueError("sdk_native_event_order_changed")
        ids.add(event["id"])
    if native["events"] and native["last_update_time"] != native["events"][-1]["timestamp"]:
        raise ValueError("sdk_native_session_time_changed")
    return [event for event in native["events"] if "error_code" not in event]


def _records(loop):
    from .google_adk_runtime import TRANSFER_TOOL, _check_action_outcome
    all_ids = set()
    for row in loop.checkpoint.value["records"]:
        loop.check_native_request(row["native_request"], row["agent"])
        if row["request"] != loop.payload(row["native_request"], row["agent"]):
            raise ValueError("sdk_checkpoint_request_changed")
        if row["response"] is None:
            if row["results"]:
                raise ValueError("sdk_checkpoint_tool_result_changed")
            continue
        _, calls = loop.response(row["response"], row["agent"])
        ids = {call["id"] for call in calls}
        if ids & all_ids:
            raise ValueError("sdk_repeated_host_nonce")
        all_ids.update(ids)
        if set(row["results"]) != {call["id"] for call in calls[:len(row["results"]) ]}:
            raise ValueError("sdk_checkpoint_dispatch_order_changed")
        for call in calls:
            if call["id"] not in row["results"]:
                continue
            result = row["results"][call["id"]]
            if call["name"] == TRANSFER_TOOL:
                if result != "null":
                    raise ValueError("sdk_native_transfer_changed")
            else:
                _check_action_outcome(result)


def _workflow(loop, events):
    from .google_adk_runtime import COORDINATOR, EXECUTOR, TRANSFER_TOOL
    records = loop.checkpoint.value["records"]
    state = {"phase": "initial", "agent": COORDINATOR, "path": "", "invocation": None}
    states = [deepcopy(state)]
    mapped, pending, last_user, answer = 0, None, None, None
    for index, event in enumerate(events):
        content = event.get("content")
        if event["author"] == "user":
            if (state["phase"] not in ("initial", "done") or event["node_info"] != {"path": ""}
                    or event["actions"] != EMPTY_ACTIONS or not content or content["role"] != "user"
                    or len(content["parts"]) != 1 or set(content["parts"][0]) != {"text"}):
                raise ValueError("sdk_native_user_turn_changed")
            prompt = content["parts"][0]["text"]
            if event["invocation_id"] != invocation_id(loop.checkpoint.binding, prompt, mapped):
                raise ValueError("sdk_native_invocation_changed")
            # With parent transfer disabled the native Runner starts each new
            # user turn at the coordinator; this does not create new authority.
            state.update(phase="model", agent=COORDINATOR, path=COORDINATOR + "@1", invocation=event["invocation_id"])
            last_user = (index, mapped, prompt, event["invocation_id"])
        else:
            if (event["author"] != state["agent"] or event["node_info"] != {"path": state["path"]}
                    or event["invocation_id"] != state["invocation"]):
                raise ValueError("sdk_native_agent_changed")
            if content and content["role"] == "model":
                if state["phase"] != "model" or mapped >= len(records):
                    raise ValueError("sdk_native_model_event_changed")
                row = records[mapped]
                if row["response"] is None or row["agent"] != state["agent"] or row["event_count"] != index:
                    raise ValueError("sdk_native_model_event_changed")
                expected = loop.native_response(row["response"], row["agent"]).content.model_dump(mode="json", exclude_none=True)
                if content != expected or event["actions"] != EMPTY_ACTIONS:
                    raise ValueError("sdk_native_model_event_changed")
                message, calls = loop.response(row["response"], row["agent"])
                pending = row
                state["phase"] = "result" if calls else "end"
                answer = None if calls else message["content"]
                mapped += 1
            elif content:
                if state["phase"] != "result" or pending is None:
                    raise ValueError("sdk_native_tool_result_changed")
                calls = loop.response(pending["response"], pending["agent"])[1]
                if any(call["id"] not in pending["results"] for call in calls):
                    raise ValueError("sdk_native_tool_result_changed")
                transfer = calls[0]["name"] == TRANSFER_TOOL
                expected = {"role": "user", "parts": [{"function_response": {"id": call["id"], "name": call["name"],
                    "response": {"result": None if transfer else pending["results"][call["id"]]}}} for call in calls]}
                if content != expected or event["actions"] != ({**EMPTY_ACTIONS, "transfer_to_agent": EXECUTOR} if transfer else EMPTY_ACTIONS):
                    raise ValueError("sdk_native_tool_result_changed")
                state["phase"] = "transfer_end" if transfer else "model"
            elif event["actions"] == {**EMPTY_ACTIONS, "end_of_agent": True}:
                if state["phase"] == "transfer_end":
                    state.update(agent=EXECUTOR, path=state["path"] + "/" + EXECUTOR + "@1", phase="model")
                elif state["phase"] == "end":
                    state["phase"] = "done"
                else:
                    raise ValueError("sdk_native_terminal_changed")
            else:
                raise ValueError("sdk_native_event_order_changed")
        states.append(deepcopy(state))
    return mapped, states, last_user, answer


def validate_saved(loop):
    value = loop.checkpoint.value
    loop.checkpoint.check_envelope()
    _records(loop)
    if value["native"] is None:
        if (value["records"] or value["attempts"] or value["round_start"] or value["round_event_start"]
                or value["status"] != "running"):
            raise ValueError("sdk_native_session_missing")
        return
    sessions = [value["native"], *value["attempts"]]
    prefixes = [_session(loop, native) for native in sessions]
    canonical = max(prefixes, key=len)
    for events in prefixes:
        if [event_projection(event) for event in events] != [event_projection(event) for event in canonical[:len(events)]]:
            raise ValueError("sdk_native_replay_changed")
    mapped, states, last_user, answer = _workflow(loop, canonical)
    for native, prefix in zip(sessions, prefixes):
        if native["events"] and "error_code" in native["events"][-1]:
            error, state = native["events"][-1], states[len(prefix)]
            if (state["phase"] in ("initial", "done") or error["author"] != state["agent"]
                    or error["node_info"] != {"path": state["path"]} or error["invocation_id"] != state["invocation"]):
                raise ValueError("sdk_native_error_changed")
    records = value["records"]
    if len(records) > mapped + 1:
        raise ValueError("sdk_native_record_cursor_changed")
    if len(records) == mapped + 1:
        row, state = records[-1], states[-1]
        if state["phase"] != "model" or row["agent"] != state["agent"] or row["event_count"] != len(canonical):
            raise ValueError("sdk_native_record_cursor_changed")
    # Structural checks and the complete workflow/record binding above run
    # before Event's extra='ignore' parser sees any persisted native object.
    from google.adk.events.event import Event
    from google.adk.flows.llm_flows.contents import _get_contents
    parsed = [Event.model_validate(event) for event in canonical]
    for row in records:
        count = row["event_count"]
        if not 1 <= count <= len(parsed) or states[count]["agent"] != row["agent"] or states[count]["phase"] != "model":
            raise ValueError("sdk_native_request_history_changed")
        contents = [content.model_dump(mode="json", exclude_none=True) for content in
                    _get_contents(None, parsed[:count], row["agent"])]
        if row["native_request"]["contents"] != contents:
            raise ValueError("sdk_native_request_history_changed")
    active_started = last_user is not None and last_user[3] == value["invocation_id"]
    if active_started:
        if last_user[:3] != (value["round_event_start"], value["round_start"], value["prompt"]):
            raise ValueError("sdk_checkpoint_prompt_changed")
    elif (value["round_event_start"] != len(canonical) or value["round_start"] != len(records)
          or states[-1]["phase"] not in ("initial", "done")):
        raise ValueError("sdk_checkpoint_prompt_changed")
    if value["round_event_start"] > len(value["native"]["events"]):
        raise ValueError("sdk_invalid_checkpoint_cursor")
    if value["status"] == "completed":
        if (not active_started or mapped != len(records) or states[-1]["phase"] != "done"
                or value["answer"] != answer or len(value["native"]["events"]) != len(canonical)
                or value["native"]["events"][-1].get("error_code")):
            raise ValueError("sdk_native_completion_changed")
