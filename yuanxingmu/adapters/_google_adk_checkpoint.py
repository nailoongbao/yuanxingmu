"""Atomic, bounded native ADK snapshots with untrusted response copies.

An interrupted invocation is replayed by the real Runner from its saved
session prefix. Earlier native events, including failure events, are retained
as attempts; replay changes neither the host task nor its action budget.
Structural consistency is not authenticity: the worker verifies every saved
response and result against the host's read-only original records before use.
"""
from copy import deepcopy
import hashlib
import math
from pathlib import Path

from ._runtime_support import atomic_json, json_bytes, read_json


FORMAT = "google-adk-session-v1"
FIELDS = {"format", "binding", "prompt", "status", "answer", "round_start", "round_event_start",
          "invocation_id", "native", "attempts", "records"}


def check_tree(value):
    stack, count = [(value, 0)], 0
    while stack:
        item, depth = stack.pop()
        count += 1
        if count > 262144 or depth > 64:
            raise ValueError("sdk_checkpoint_json_limit")
        if type(item) is dict:
            if any(type(key) is not str for key in item):
                raise ValueError("sdk_invalid_checkpoint_json")
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("sdk_invalid_checkpoint_json")
        elif item is not None and type(item) not in (str, int, bool):
            raise ValueError("sdk_invalid_checkpoint_json")


def invocation_id(binding, prompt, start):
    return "yxm-adk-" + hashlib.sha256(json_bytes([binding, prompt, start])).hexdigest()


class Checkpoint:
    def __init__(self, config):
        self.path = Path(config["checkpoint"])
        self.failed = False
        self.binding = {key: config[key] for key in
                        ("version", "framework", "session_id", "task_id", "model_id", "automatic_actions")}
        if self.path.is_symlink():
            raise ValueError("sdk_invalid_checkpoint")
        if self.path.exists() != config["resume"]:
            raise ValueError("sdk_checkpoint_resume_required" if self.path.exists() else "sdk_checkpoint_missing")
        self.value = read_json(self.path) if config["resume"] else {
            "format": FORMAT, "binding": self.binding, "prompt": config["prompt"], "status": "running",
            "answer": None, "round_start": 0, "round_event_start": 0,
            "invocation_id": invocation_id(self.binding, config["prompt"], 0),
            "native": None, "attempts": [], "records": []}
        self.check_envelope()

    def check_envelope(self):
        value = self.value
        check_tree(value)
        if (type(value) is not dict or set(value) != FIELDS or value["format"] != FORMAT
                or json_bytes(value["binding"]) != json_bytes(self.binding) or type(value["prompt"]) is not str
                or not value["prompt"].strip() or len(value["prompt"].encode()) > 256 * 1024
                or value["status"] not in ("running", "completed")
                or value["native"] is not None and type(value["native"]) is not dict
                or type(value["records"]) is not list or len(value["records"]) > 128
                or type(value["attempts"]) is not list or len(value["attempts"]) > 16):
            raise ValueError("sdk_checkpoint_binding_mismatch")
        if (type(value["round_start"]) is not int or not 0 <= value["round_start"] <= len(value["records"])
                or type(value["round_event_start"]) is not int or not 0 <= value["round_event_start"] <= 768
                or value["invocation_id"] != invocation_id(self.binding, value["prompt"], value["round_start"])):
            raise ValueError("sdk_invalid_checkpoint_cursor")
        if ((value["status"] == "running" and value["answer"] is not None)
                or (value["status"] == "completed" and type(value["answer"]) is not str)):
            raise ValueError("sdk_invalid_checkpoint_status")
        for index, row in enumerate(value["records"]):
            if (type(row) is not dict or set(row) != {"agent", "event_count", "native_request", "request", "response", "results"}
                    or type(row["event_count"]) is not int or not 1 <= row["event_count"] <= 768
                    or type(row["request"]) is not dict or type(row["native_request"]) is not dict
                    or type(row["results"]) is not dict
                    or row["response"] is not None and type(row["response"]) is not dict
                    or row["response"] is None and index != len(value["records"]) - 1):
                raise ValueError("sdk_invalid_checkpoint_record")

    def save(self):
        if self.failed:
            raise RuntimeError("sdk_checkpoint_write_failed")
        try:
            self.check_envelope()
            atomic_json(self.path, self.value)
        except BaseException:
            self.failed = True
            raise

    def restart_invocation(self):
        value = self.value
        native = value["native"]
        if native is None or len(native["events"]) == value["round_event_start"]:
            return
        value["attempts"].append(deepcopy(native))
        value["native"] = deepcopy(native)
        value["native"]["events"] = value["native"]["events"][:value["round_event_start"]]
        if value["native"]["events"]:
            value["native"]["last_update_time"] = value["native"]["events"][-1]["timestamp"]
        self.save()

    def start_turn(self, prompt):
        value = self.value
        value.update(prompt=prompt, status="running", answer=None, round_start=len(value["records"]),
                     round_event_start=len(value["native"]["events"]))
        value["invocation_id"] = invocation_id(self.binding, prompt, value["round_start"])
        self.save()
