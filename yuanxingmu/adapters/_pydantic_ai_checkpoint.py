"""Bounded native-message checkpoints for the fixed PydanticAI worker.

Only stable native deferred pauses and completed runs are saved. Automatic
SDK approval decisions are reconstructed in memory, never persisted as host
authority. The interval journal retains original model and tool results.
"""
from copy import deepcopy
from pathlib import Path

from ._runtime_support import atomic_json, read_json


FORMAT = "pydantic-ai-messages-v1"
FIELDS = {"format", "binding", "prompt", "status", "answer", "round_start",
          "native_cursor", "native", "records"}


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
        elif item is not None and type(item) not in (str, int, bool):
            raise ValueError("sdk_invalid_checkpoint_json")


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
            "format": FORMAT, "binding": self.binding, "prompt": config["prompt"],
            "status": "running", "answer": None, "round_start": 0, "native_cursor": 0,
            "native": [], "records": []}
        self.check_envelope()

    def check_envelope(self):
        value = self.value
        check_tree(value)
        if (type(value) is not dict or set(value) != FIELDS or value["format"] != FORMAT
                or value["binding"] != self.binding or type(value["prompt"]) is not str
                or not value["prompt"].strip() or len(value["prompt"].encode()) > 256 * 1024
                or value["status"] not in ("running", "completed")
                or type(value["native"]) is not list or type(value["records"]) is not list
                or len(value["records"]) > 128):
            raise ValueError("sdk_checkpoint_binding_mismatch")
        for field in ("native_cursor", "round_start"):
            if type(value[field]) is not int or not 0 <= value[field] <= len(value["records"]):
                raise ValueError("sdk_invalid_checkpoint_cursor")
        if value["round_start"] > value["native_cursor"]:
            raise ValueError("sdk_invalid_checkpoint_cursor")
        if ((value["status"] == "running" and value["answer"] is not None)
                or (value["status"] == "completed" and type(value["answer"]) is not str)):
            raise ValueError("sdk_invalid_checkpoint_status")
        for index, row in enumerate(value["records"]):
            if (type(row) is not dict or set(row) != {"request", "response", "results"}
                    or type(row["request"]) is not dict or type(row["results"]) is not dict
                    or row["response"] is not None and type(row["response"]) is not dict
                    or row["response"] is None and index != len(value["records"]) - 1):
                raise ValueError("sdk_invalid_checkpoint_record")
        if any(row["response"] is None for row in value["records"][:value["native_cursor"]]):
            raise ValueError("sdk_checkpoint_incomplete")

    def save(self):
        if self.failed:
            raise RuntimeError("sdk_checkpoint_write_failed")
        try:
            self.check_envelope()
            atomic_json(self.path, self.value)
        except BaseException:
            self.failed = True
            raise

    def snapshot(self, native, cursor, *, status="running", answer=None):
        self.value.update(native=deepcopy(native), native_cursor=cursor, status=status, answer=answer)
