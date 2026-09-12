"""Private, bounded replay storage for one host-owned SDK model session.

The caller checks current authority before ``begin`` (including replays), calls
the upstream only for a new ticket, checks its complete response, then publishes
only the bytes returned by ``complete``. Host-generated tool IDs are replay
identities, not permissions. Request bodies and provider credentials are not
stored. A pending/unknown request is never automatically retried.

Each directory belongs to exactly one session and must initially be absent.
POSIX directory-relative NOFOLLOW opens protect every path component. All disk
and thread locks are short-lived method locks; none is held across network IO.
A crashed, still-pending flight deliberately blocks new requests as well: this
module cannot prove that its remote operation ended. It does not invent recovery.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import threading

try:
    import fcntl
except ImportError:  # The SDK's isolated runtime is POSIX-only.
    fcntl = None


MAX_REQUESTS = 128
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_CACHE_BYTES = 64 * 1024 * 1024
MAX_STATE_BYTES = 64 * 1024
MAX_JSON_NODES = 65_536
MAX_JSON_DEPTH = 32
MAX_TOOL_CALLS = 64
_STATE = "state.json"
_LOCK = "store.lock"
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.:-]{0,127}\Z")
_SESSION = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z")
_HOST_ID = re.compile(r"yxm_[0-9a-f]{48}\Z")


class ModelStoreError(ValueError):
    """Stable code only; never include model text, private paths or credentials."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class ModelTicket:
    replay: bytes | None = field(repr=False)
    content_type: str = "application/json"
    _request_key: str = field(default="", repr=False)
    _owner: object = field(default=None, repr=False, compare=False)


def _fail(reason="sdk_model_invalid_json"):
    raise ModelStoreError(reason)


def _json(raw: bytes, *, limit=MAX_BODY_BYTES):
    if type(raw) is not bytes or not raw or len(raw) > limit:
        _fail("sdk_model_body_limit")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                _fail("sdk_model_duplicate_key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: _fail())
        stack, count = [(value, 0)], 0
        while stack:
            item, depth = stack.pop()
            count += 1
            if count > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
                _fail("sdk_model_json_limit")
            if type(item) is dict:
                for key, child in item.items():
                    key.encode("utf-8")
                    stack.append((child, depth + 1))
            elif type(item) is list:
                stack.extend((child, depth + 1) for child in item)
            elif type(item) is str:
                item.encode("utf-8")
            elif type(item) is float and not math.isfinite(item):
                _fail()
        return value
    except ModelStoreError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        _fail()


def _dump(value) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        _fail()


def _text(value, *, limit=256, empty=False):
    return type(value) is str and (empty or bool(value)) and len(value) <= limit


def _tool_call(call, *, host_ids=False):
    if (type(call) is not dict or set(call) != {"id", "type", "function"}
            or call["type"] != "function" or not _text(call["id"])
            or (host_ids and _HOST_ID.fullmatch(call["id"]) is None)):
        _fail("sdk_model_invalid_tool_call")
    function = call["function"]
    if (type(function) is not dict or set(function) != {"name", "arguments"}
            or type(function["name"]) is not str or _NAME.fullmatch(function["name"]) is None
            or type(function["arguments"]) is not str):
        _fail("sdk_model_invalid_tool_call")
    arguments = _json(function["arguments"].encode("utf-8"), limit=MAX_BODY_BYTES)
    if type(arguments) is not dict:
        _fail("sdk_model_invalid_tool_arguments")


def _request(raw: bytes):
    value = _json(raw, limit=MAX_BODY_BYTES)
    allowed = {"model", "messages", "tools", "tool_choice", "stream", "n", "stop", "max_tokens",
               "max_completion_tokens", "temperature", "top_p", "seed", "parallel_tool_calls",
               "presence_penalty", "frequency_penalty", "reasoning_effort"}
    if (type(value) is not dict or set(value) - allowed or not {"model", "messages"} <= set(value)
            or not _text(value["model"]) or value.get("stream", False) is not False
            or ("n" in value and (type(value["n"]) is not int or value["n"] != 1))):
        _fail("sdk_model_unsupported_request")
    messages = value["messages"]
    if type(messages) is not list or not 1 <= len(messages) <= 512:
        _fail("sdk_model_invalid_messages")
    for message in messages:
        if (type(message) is not dict or set(message) - {"role", "content", "name", "tool_call_id", "tool_calls"}
                or type(message.get("role")) is not str
                or message["role"] not in {"system", "developer", "user", "assistant", "tool"}):
            _fail("sdk_model_invalid_messages")
        if "name" in message and not _text(message["name"], limit=128):
            _fail("sdk_model_invalid_messages")
        content = message.get("content")
        if type(content) is list:
            if not content or any(type(part) is not dict or set(part) != {"type", "text"}
                                  or part["type"] != "text" or type(part["text"]) is not str for part in content):
                _fail("sdk_model_unsupported_message_content")
        elif content is not None and type(content) is not str:
            _fail("sdk_model_unsupported_message_content")
        calls = message.get("tool_calls")
        if calls is not None:
            if message["role"] != "assistant" or type(calls) is not list or not 1 <= len(calls) <= MAX_TOOL_CALLS:
                _fail("sdk_model_invalid_messages")
            ids = set()
            for call in calls:
                _tool_call(call)
                if call["id"] in ids:
                    _fail("sdk_model_duplicate_tool_id")
                ids.add(call["id"])
        if content is None and not calls:
            _fail("sdk_model_invalid_messages")
        if message["role"] == "tool":
            if not _text(message.get("tool_call_id")):
                _fail("sdk_model_invalid_messages")
        elif "tool_call_id" in message:
            _fail("sdk_model_invalid_messages")
    if "tools" in value:
        tools = value["tools"]
        if type(tools) is not list or not 1 <= len(tools) <= MAX_TOOL_CALLS:
            _fail("sdk_model_invalid_tools")
        names = set()
        for tool in tools:
            if type(tool) is not dict or set(tool) != {"type", "function"} or tool["type"] != "function":
                _fail("sdk_model_invalid_tools")
            function = tool["function"]
            if (type(function) is not dict or set(function) - {"name", "description", "parameters", "strict"}
                    or not {"name", "parameters"} <= set(function) or type(function["name"]) is not str
                    or _NAME.fullmatch(function["name"]) is None or function["name"] in names
                    or type(function["parameters"]) is not dict
                    or ("description" in function and type(function["description"]) is not str)
                    or ("strict" in function and type(function["strict"]) is not bool)):
                _fail("sdk_model_invalid_tools")
            names.add(function["name"])
    if "tool_choice" in value:
        choice = value["tool_choice"]
        if type(choice) is str:
            if choice not in {"none", "auto", "required"}:
                _fail("sdk_model_invalid_tool_choice")
        elif (type(choice) is not dict or set(choice) != {"type", "function"}
              or choice["type"] != "function" or type(choice["function"]) is not dict
              or set(choice["function"]) != {"name"} or not _text(choice["function"]["name"], limit=128)):
            _fail("sdk_model_invalid_tool_choice")
    for key in ("max_tokens", "max_completion_tokens"):
        if key in value and (type(value[key]) is not int or not 1 <= value[key] <= 1_000_000):
            _fail("sdk_model_invalid_request_option")
    for key, lower, upper in (("temperature", 0, 2), ("top_p", 0, 1),
                               ("presence_penalty", -2, 2), ("frequency_penalty", -2, 2)):
        if key in value and (type(value[key]) not in {int, float} or not lower <= value[key] <= upper):
            _fail("sdk_model_invalid_request_option")
    if "seed" in value and (type(value["seed"]) is not int or not -(2 ** 63) <= value["seed"] < 2 ** 63):
        _fail("sdk_model_invalid_request_option")
    if "parallel_tool_calls" in value and type(value["parallel_tool_calls"]) is not bool:
        _fail("sdk_model_invalid_request_option")
    if "reasoning_effort" in value and (type(value["reasoning_effort"]) is not str
                                        or value["reasoning_effort"] not in {"none", "minimal", "low", "medium", "high"}):
        _fail("sdk_model_invalid_request_option")
    if "stop" in value:
        stop = value["stop"]
        if not (type(stop) is str or (type(stop) is list and 1 <= len(stop) <= 4 and all(type(s) is str for s in stop))):
            _fail("sdk_model_invalid_request_option")
    return value


def _response(raw: bytes, content_type: str, *, host_ids=False):
    if type(content_type) is not str or content_type.split(";", 1)[0].strip().lower() != "application/json":
        _fail("sdk_model_unsupported_content_type")
    value = _json(raw, limit=MAX_BODY_BYTES)
    allowed = {"id", "object", "created", "model", "choices", "usage", "system_fingerprint", "service_tier"}
    if (type(value) is not dict or set(value) - allowed or type(value.get("choices")) is not list
            or len(value["choices"]) != 1):
        _fail("sdk_model_unsupported_response")
    for key in ("id", "model"):
        if key in value and not _text(value[key]):
            _fail("sdk_model_unsupported_response")
    if "object" in value and value["object"] != "chat.completion":
        _fail("sdk_model_unsupported_response")
    if "created" in value and (type(value["created"]) is not int or value["created"] < 0):
        _fail("sdk_model_unsupported_response")
    for key in ("system_fingerprint", "service_tier"):
        if key in value and value[key] is not None and not _text(value[key], empty=True):
            _fail("sdk_model_unsupported_response")
    if "usage" in value and value["usage"] is not None:
        usage = value["usage"]
        counters = {"prompt_tokens", "completion_tokens", "total_tokens"}
        details = {"prompt_tokens_details": {"cached_tokens", "audio_tokens"},
                   "completion_tokens_details": {"reasoning_tokens", "audio_tokens", "accepted_prediction_tokens", "rejected_prediction_tokens"}}
        if type(usage) is not dict or set(usage) - counters - set(details):
            _fail("sdk_model_unsupported_usage")
        for key, item in usage.items():
            if key in counters:
                if type(item) is not int or item < 0:
                    _fail("sdk_model_unsupported_usage")
            elif item is not None and (type(item) is not dict or set(item) - details[key]
                                      or any(type(n) is not int or n < 0 for n in item.values())):
                _fail("sdk_model_unsupported_usage")
    choice = value["choices"][0]
    if (type(choice) is not dict or set(choice) - {"index", "message", "finish_reason", "logprobs"}
            or type(choice.get("index")) is not int or choice["index"] != 0
            or type(choice.get("finish_reason")) is not str
            or choice["finish_reason"] not in {"stop", "tool_calls"} or choice.get("logprobs") is not None):
        _fail("sdk_model_unsupported_choice")
    message = choice.get("message")
    if (type(message) is not dict or set(message) - {"role", "content", "refusal", "reasoning", "reasoning_content", "tool_calls"}
            or message.get("role") != "assistant"):
        _fail("sdk_model_unsupported_message")
    for key in ("content", "refusal", "reasoning", "reasoning_content"):
        if message.get(key) is not None and type(message[key]) is not str:
            _fail("sdk_model_unsupported_message")
    calls = message.get("tool_calls")
    if calls is not None and (type(calls) is not list or len(calls) > MAX_TOOL_CALLS):
        _fail("sdk_model_invalid_tool_call")
    if calls:
        if choice["finish_reason"] != "tool_calls":
            _fail("sdk_model_incomplete_response")
        ids = set()
        for call in calls:
            _tool_call(call, host_ids=host_ids)
            if call["id"] in ids:
                _fail("sdk_model_duplicate_tool_id")
            ids.add(call["id"])
    elif (choice["finish_reason"] != "stop"
          or not any(type(message.get(key)) is str for key in ("content", "refusal"))):
        _fail("sdk_model_incomplete_response")
    return value


class ModelStore:
    def __init__(self, private_directory, session_id):
        if (fcntl is None or os.name != "posix" or not hasattr(os, "O_NOFOLLOW")
                or not hasattr(os, "O_DIRECTORY")):
            _fail("sdk_model_secure_storage_unavailable")
        if type(session_id) is not str or _SESSION.fullmatch(session_id) is None:
            _fail("sdk_model_invalid_session")
        try:
            path = Path(private_directory)
            if ".." in path.parts:
                _fail("sdk_model_invalid_directory")
            self.directory = Path(os.path.abspath(path))
        except (TypeError, ValueError, OSError):
            _fail("sdk_model_invalid_directory")
        self.session_id = session_id
        self._mutex = threading.Lock()
        self._owner = object()
        self._inflight = None
        self._completed = False
        self._faulted = False
        self._directory_identity = None
        self._lock_identity = None
        try:
            with self._directory(create=True) as (directory, created):
                if created:
                    lock = os.open(_LOCK, self._flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL), 0o600, dir_fd=directory)
                    try:
                        self._file_stat(lock, limit=0)
                        os.fsync(lock)
                    finally:
                        os.close(lock)
                    os.fsync(directory)
                with self._file_lock(directory):
                    if created:
                        self._write_state(directory, {"version": 1, "session_id": session_id, "records": []}, initial=True)
                    else:
                        self._load_state(directory)
        except OSError:
            _fail("sdk_model_storage_unavailable")

    @staticmethod
    def _flags(access):
        return access | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | os.O_NONBLOCK

    @contextmanager
    def _directory(self, *, create=False):
        flags = self._flags(os.O_RDONLY) | os.O_DIRECTORY
        current = os.open("/", flags)
        created = False
        try:
            parts = self.directory.parts[1:]
            if not parts:
                _fail("sdk_model_invalid_directory")
            for index, part in enumerate(parts):
                if create and index == len(parts) - 1:
                    try:
                        os.mkdir(part, 0o700, dir_fd=current)
                        os.fsync(current)
                        created = True
                    except FileExistsError:
                        pass
                child = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = child
            info = os.fstat(current)
            if not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700 or info.st_uid != os.geteuid():
                _fail("sdk_model_directory_permissions")
            identity = (info.st_dev, info.st_ino)
            if self._directory_identity is not None and identity != self._directory_identity:
                _fail("sdk_model_directory_changed")
            self._directory_identity = identity
            yield current, created
        finally:
            os.close(current)

    @staticmethod
    def _file_stat(descriptor, *, limit):
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.geteuid() or info.st_nlink != 1 or info.st_size > limit):
            _fail("sdk_model_file_permissions")
        return info

    @contextmanager
    def _file_lock(self, directory):
        descriptor = os.open(_LOCK, self._flags(os.O_RDWR), dir_fd=directory)
        try:
            info = self._file_stat(descriptor, limit=0)
            identity = (info.st_dev, info.st_ino)
            if self._lock_identity is not None and identity != self._lock_identity:
                _fail("sdk_model_lock_changed")
            self._lock_identity = identity
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _fail("sdk_model_busy")
            self._file_stat(descriptor, limit=0)
            yield
        finally:
            os.close(descriptor)

    @contextmanager
    def _locked(self, *, finishing=None):
        if not self._mutex.acquire(blocking=False):
            _fail("sdk_model_busy")
        try:
            if self._faulted:
                _fail("sdk_model_storage_unavailable")
            with self._directory() as (directory, _):
                with self._file_lock(directory):
                    yield directory
        except OSError:
            self._faulted = True
            _fail("sdk_model_storage_unavailable")
        finally:
            if finishing is not None and self._inflight is finishing:
                self._inflight, self._completed = None, False
            self._mutex.release()

    def _read_file(self, directory, name, *, limit):
        descriptor = os.open(name, self._flags(os.O_RDONLY), dir_fd=directory)
        try:
            before = self._file_stat(descriptor, limit=limit)
            parts, length = [], 0
            while length <= limit:
                chunk = os.read(descriptor, min(64 * 1024, limit + 1 - length))
                if not chunk:
                    break
                parts.append(chunk)
                length += len(chunk)
            after = self._file_stat(descriptor, limit=limit)
            if (length > limit or length != before.st_size
                    or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                _fail("sdk_model_file_changed")
            return b"".join(parts)
        finally:
            os.close(descriptor)

    @staticmethod
    def _response_name(key):
        return "response-" + key + ".json"

    def _load_state(self, directory):
        state = _json(self._read_file(directory, _STATE, limit=MAX_STATE_BYTES), limit=MAX_STATE_BYTES)
        if (type(state) is not dict or set(state) != {"version", "session_id", "records"}
                or type(state["version"]) is not int or state["version"] != 1
                or state["session_id"] != self.session_id or type(state["records"]) is not list
                or len(state["records"]) > MAX_REQUESTS):
            _fail("sdk_model_invalid_state")
        keys, required, responses, pending = set(), {_LOCK, _STATE}, {}, 0
        for record in state["records"]:
            fields = {"request_sha256", "request_bytes", "state", "response_bytes", "response_sha256"}
            if (type(record) is not dict or set(record) != fields
                    or type(record["request_sha256"]) is not str or _HEX.fullmatch(record["request_sha256"]) is None
                    or record["request_sha256"] in keys or type(record["request_bytes"]) is not int
                    or not 1 <= record["request_bytes"] <= MAX_BODY_BYTES
                    or type(record["state"]) is not str or record["state"] not in {"pending", "unknown", "complete"}
                    or type(record["response_bytes"]) is not int):
                _fail("sdk_model_invalid_state")
            key = record["request_sha256"]
            keys.add(key)
            name = self._response_name(key)
            responses[name] = record
            if record["state"] == "complete":
                if (not 1 <= record["response_bytes"] <= MAX_BODY_BYTES
                        or type(record["response_sha256"]) is not str or _HEX.fullmatch(record["response_sha256"]) is None):
                    _fail("sdk_model_invalid_state")
                required.add(name)
            elif record["response_bytes"] != 0 or record["response_sha256"] is not None:
                _fail("sdk_model_invalid_state")
            pending += record["state"] == "pending"
        if pending > 1:
            _fail("sdk_model_invalid_state")
        seen, total = set(), 0
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(seen) >= MAX_REQUESTS + 2 or entry.name in seen or entry.name not in {_LOCK, _STATE} | set(responses):
                    _fail("sdk_model_invalid_inventory")
                seen.add(entry.name)
                limit = 0 if entry.name == _LOCK else MAX_STATE_BYTES if entry.name == _STATE else MAX_BODY_BYTES
                descriptor = os.open(entry.name, self._flags(os.O_RDONLY), dir_fd=directory)
                try:
                    info = self._file_stat(descriptor, limit=limit)
                    if entry.name in responses:
                        record = responses[entry.name]
                        if record["state"] == "complete" and info.st_size != record["response_bytes"]:
                            _fail("sdk_model_invalid_inventory")
                        total += info.st_size
                finally:
                    os.close(descriptor)
        if not required <= seen or total > MAX_CACHE_BYTES:
            _fail("sdk_model_invalid_inventory")
        return state, total

    def _atomic_write(self, directory, name, data, *, new=False):
        try:
            descriptor = os.open(name, self._flags(os.O_RDONLY), dir_fd=directory)
        except FileNotFoundError:
            if not new:
                raise
        else:
            try:
                self._file_stat(descriptor, limit=MAX_STATE_BYTES if name == _STATE else MAX_BODY_BYTES)
            finally:
                os.close(descriptor)
            if new:
                _fail("sdk_model_existing_response")
        temporary = ".tmp-" + secrets.token_hex(16)
        descriptor = None
        try:
            descriptor = os.open(temporary, self._flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL), 0o600, dir_fd=directory)
            self._file_stat(descriptor, limit=0)
            position = 0
            while position < len(data):
                written = os.write(descriptor, data[position:])
                if written <= 0:
                    raise OSError("short_write")
                position += written
            os.fsync(descriptor)
            self._file_stat(descriptor, limit=len(data))
            os.close(descriptor)
            descriptor = None
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

    def _write_state(self, directory, state, *, initial=False):
        raw = _dump(state)
        if len(raw) > MAX_STATE_BYTES:
            _fail("sdk_model_state_limit")
        self._atomic_write(directory, _STATE, raw, new=initial)

    def _owns(self, ticket):
        if type(ticket) is not ModelTicket or ticket._owner is not self._owner:
            _fail("sdk_model_invalid_ticket")

    def begin(self, raw_request: bytes) -> ModelTicket:
        _request(raw_request)
        key = hashlib.sha256(raw_request).hexdigest()
        with self._locked() as directory:
            if self._inflight is not None:
                _fail("sdk_model_busy")
            state, total = self._load_state(directory)
            record = next((r for r in state["records"] if r["request_sha256"] == key), None)
            replay = None
            if record is not None:
                if record["request_bytes"] != len(raw_request):
                    _fail("sdk_model_invalid_state")
                if record["state"] != "complete":
                    _fail("sdk_model_outcome_unknown")
                replay = self._read_file(directory, self._response_name(key), limit=MAX_BODY_BYTES)
                if hashlib.sha256(replay).hexdigest() != record["response_sha256"]:
                    _fail("sdk_model_response_changed")
                _response(replay, "application/json", host_ids=True)
            else:
                if any(r["state"] == "pending" for r in state["records"]):
                    _fail("sdk_model_busy")
                if len(state["records"]) >= MAX_REQUESTS or total + MAX_BODY_BYTES > MAX_CACHE_BYTES:
                    _fail("sdk_model_capacity_exhausted")
                state["records"].append({"request_sha256": key, "request_bytes": len(raw_request), "state": "pending",
                                         "response_bytes": 0, "response_sha256": None})
                self._write_state(directory, state)
            ticket = ModelTicket(replay=replay, _request_key=key, _owner=self._owner)
            self._inflight, self._completed = ticket, False
            return ticket

    def complete(self, ticket: ModelTicket, checked: bytes, content_type: str) -> bytes:
        self._owns(ticket)
        value = _response(checked, content_type)
        with self._locked() as directory:
            if self._inflight is not ticket or ticket.replay is not None or self._completed:
                _fail("sdk_model_invalid_ticket")
            state, total = self._load_state(directory)
            record = next((r for r in state["records"] if r["request_sha256"] == ticket._request_key), None)
            if record is None or record["state"] != "pending":
                _fail("sdk_model_outcome_unknown")
            identifiers = set()
            for call in value["choices"][0]["message"].get("tool_calls") or []:
                for _ in range(8):
                    identifier = "yxm_" + secrets.token_hex(24)
                    if identifier not in identifiers:
                        break
                else:
                    _fail("sdk_model_nonce_unavailable")
                identifiers.add(identifier)
                call["id"] = identifier
            result = _dump(value)
            if len(result) > MAX_BODY_BYTES or total + len(result) > MAX_CACHE_BYTES:
                _fail("sdk_model_capacity_exhausted")
            self._atomic_write(directory, self._response_name(ticket._request_key), result, new=True)
            record.update(state="complete", response_bytes=len(result), response_sha256=hashlib.sha256(result).hexdigest())
            self._write_state(directory, state)
            self._completed = True
            return result

    def finish(self, ticket: ModelTicket) -> None:
        self._owns(ticket)
        # Release this ticket only while owning the method mutex. An old finish
        # must not release a newer ticket, nor race a still-running complete.
        with self._locked(finishing=ticket) as directory:
            if self._inflight is not ticket:
                return
            if ticket.replay is None and not self._completed:
                state, _ = self._load_state(directory)
                record = next((r for r in state["records"] if r["request_sha256"] == ticket._request_key), None)
                if record is None or record["state"] != "pending":
                    _fail("sdk_model_outcome_unknown")
                record["state"] = "unknown"
                self._write_state(directory, state)
