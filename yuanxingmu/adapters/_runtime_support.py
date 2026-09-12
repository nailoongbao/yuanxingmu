"""Standard-library utilities for fixed, host-supervised SDK workers."""
from __future__ import annotations

import http.client
import json
import os
from pathlib import Path
import socket
import stat
import sys
import uuid


MAX_JSON = 16 * 1024 * 1024


def json_bytes(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def load_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("sdk_duplicate_json_key")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("sdk_invalid_json")

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def checked_text(value, maximum=MAX_JSON):
    if type(value) is not str or len(value.encode()) > maximum or "\x00" in value:
        raise ValueError("sdk_invalid_text")
    return value


def checked_config(value, framework):
    required = {"version", "framework", "session_id", "task_id", "model_id", "max_steps", "max_tokens",
                "prompt", "resume", "checkpoint", "broker_socket", "model_socket"}
    if (type(value) is not dict or not required <= set(value) or set(value) - required - {"automatic_actions"}
            or type(value["version"]) is not int or value["version"] != 1):
        raise ValueError("sdk_invalid_config")
    value = dict(value)
    value.setdefault("automatic_actions", False)
    if (value["framework"] != framework or type(value["resume"]) is not bool
            or type(value["automatic_actions"]) is not bool):
        raise ValueError("sdk_invalid_config")
    for name in ("session_id", "task_id", "model_id"):
        if not checked_text(value[name], 256):
            raise ValueError("sdk_invalid_config")
    for name, maximum in (("max_steps", 128), ("max_tokens", 32768)):
        if type(value[name]) is not int or not 1 <= value[name] <= maximum:
            raise ValueError("sdk_invalid_config")
    if not checked_text(value["prompt"], 256 * 1024).strip():
        raise ValueError("sdk_invalid_prompt")
    for name in ("checkpoint", "broker_socket", "model_socket"):
        if not Path(checked_text(value[name], 4096)).is_absolute():
            raise ValueError("sdk_requires_absolute_path")
    return value


def read_json(path, maximum=MAX_JSON):
    path = Path(path)
    if path.is_symlink():
        raise ValueError("sdk_invalid_state_file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
            raise ValueError("sdk_invalid_state_file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("sdk_state_file_too_large")
        return load_json(raw)
    finally:
        os.close(descriptor)


def atomic_json(path, value, maximum=MAX_JSON):
    path = Path(path)
    raw = json_bytes(value)
    if len(raw) > maximum:
        raise RuntimeError("sdk_checkpoint_too_large")
    temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if sys.platform.startswith("linux"):
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path):
        super().__init__("localhost", timeout=210)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def model_request(config, payload):
    body = json_bytes(payload)
    if len(body) > MAX_JSON:
        raise ValueError("sdk_model_request_too_large")
    connection = _UnixHTTP(config["model_socket"])
    try:
        connection.request("POST", "/v1/chat/completions", body=body, headers={"Content-Type": "application/json"})
        response = connection.getresponse()
        raw = response.read(MAX_JSON + 1)
        if response.status != 200 or len(raw) > MAX_JSON:
            raise ValueError("sdk_model_request_failed")
        return load_json(raw)
    except Exception:
        raise RuntimeError("sdk_model_request_failed") from None
    finally:
        connection.close()
