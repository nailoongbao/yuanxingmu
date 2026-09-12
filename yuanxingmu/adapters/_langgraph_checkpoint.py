"""A bounded JSON-only native LangGraph checkpointer for one fixed worker graph.

It retains the latest checkpoint and its immediate predecessor, including
native pending writes. It is working data, never an authorization record.
"""
from copy import deepcopy
from pathlib import Path
from threading import RLock

from langgraph.checkpoint.base import BaseCheckpointSaver, CheckpointTuple, WRITES_IDX_MAP

from ._runtime_support import atomic_json, checked_text, json_bytes, load_json, read_json


STATE_FIELDS = frozenset({"prompt", "messages", "pending", "cursor", "turn_steps", "answer", "status"})
CHANNELS = STATE_FIELDS | {"__start__", "branch:to:prepare", "branch:to:model", "branch:to:tools"}
WRITE_CHANNELS = CHANNELS | set(WRITES_IDX_MAP)


class JsonOnlySerializer:
    def dumps(self, value):
        return json_bytes(value)

    def loads(self, value):
        return load_json(value)

    def dumps_typed(self, value):
        return "json", self.dumps(value)

    def loads_typed(self, value):
        kind, data = value
        if kind != "json":
            raise ValueError("sdk_checkpoint_serialization_not_allowed")
        return self.loads(data)


class CheckpointSaver(BaseCheckpointSaver[int]):
    def __init__(self, config):
        super().__init__(serde=JsonOnlySerializer())
        self.path = Path(config["checkpoint"])
        self.lock = RLock()
        self.failed = False
        self.binding = {key: config[key] for key in
                        ("version", "framework", "session_id", "task_id", "model_id", "automatic_actions")}
        if self.path.is_symlink():
            raise ValueError("sdk_invalid_checkpoint")
        if self.path.exists() != config["resume"]:
            raise ValueError("sdk_checkpoint_resume_required" if self.path.exists() else "sdk_checkpoint_missing")
        self.value = read_json(self.path) if config["resume"] else {
            "format": "langgraph-json-v1", "binding": self.binding, "latest": None, "records": []}
        self._validate()

    def _validate(self):
        value = self.value
        if (type(value) is not dict or set(value) != {"format", "binding", "latest", "records"}
                or value["format"] != "langgraph-json-v1" or value["binding"] != self.binding
                or type(value["records"]) is not list or len(value["records"]) > 2):
            raise ValueError("sdk_checkpoint_binding_mismatch")
        ids = []
        for row in value["records"]:
            if type(row) is not dict or set(row) != {"checkpoint", "metadata", "parent", "writes"}:
                raise ValueError("sdk_invalid_checkpoint")
            checkpoint = row["checkpoint"]
            fields = {"v", "id", "ts", "channel_values", "channel_versions", "versions_seen", "updated_channels"}
            if (type(checkpoint) is not dict or set(checkpoint) != fields
                    or type(checkpoint["v"]) is not int or checkpoint["v"] < 1
                    or type(checkpoint["channel_values"]) is not dict or set(checkpoint["channel_values"]) - CHANNELS
                    or type(checkpoint["channel_versions"]) is not dict or set(checkpoint["channel_versions"]) - CHANNELS
                    or any(type(version) is not int or version < 0 for version in checkpoint["channel_versions"].values())
                    or type(checkpoint["versions_seen"]) is not dict):
                raise ValueError("sdk_invalid_native_checkpoint")
            identifier = checked_text(checkpoint["id"], 128)
            if not identifier or identifier in ids:
                raise ValueError("sdk_invalid_native_checkpoint")
            ids.append(identifier)
            checked_text(checkpoint["ts"], 128)
            updated = checkpoint["updated_channels"]
            if updated is not None and (type(updated) is not list or any(type(name) is not str or name not in CHANNELS for name in updated)):
                raise ValueError("sdk_invalid_native_checkpoint")
            for node, versions in checkpoint["versions_seen"].items():
                if (type(node) is not str or type(versions) is not dict or set(versions) - CHANNELS
                        or any(type(version) is not int or version < 0 for version in versions.values())):
                    raise ValueError("sdk_invalid_native_checkpoint")
            if (type(row["metadata"]) is not dict or type(row["writes"]) is not list or len(row["writes"]) > 1024
                    or row["parent"] is not None and type(row["parent"]) is not str):
                raise ValueError("sdk_invalid_native_checkpoint")
            seen = set()
            for write in row["writes"]:
                if (type(write) is not dict or set(write) != {"task_id", "index", "channel", "value", "task_path"}
                        or type(write["task_id"]) is not str or type(write["index"]) is not int
                        or type(write["channel"]) is not str or write["channel"] not in WRITE_CHANNELS
                        or type(write["task_path"]) is not str):
                    raise ValueError("sdk_invalid_native_checkpoint_write")
                key = (write["task_id"], write["index"])
                if key in seen:
                    raise ValueError("sdk_invalid_native_checkpoint_write")
                seen.add(key)
        if (ids and value["latest"] != ids[-1]) or (not ids and value["latest"] is not None):
            raise ValueError("sdk_invalid_native_checkpoint")

    def _config(self, identifier):
        return {"configurable": {"thread_id": self.binding["session_id"], "checkpoint_ns": "", "checkpoint_id": identifier}}

    def _identifier(self, config):
        options = config.get("configurable", {})
        if options.get("thread_id") != self.binding["session_id"] or options.get("checkpoint_ns", "") != "":
            raise ValueError("sdk_checkpoint_thread_mismatch")
        identifier = options.get("checkpoint_id", self.value["latest"])
        if identifier is not None:
            checked_text(identifier, 128)
        return identifier

    def save(self):
        if self.failed:
            raise RuntimeError("sdk_checkpoint_write_failed")
        try:
            self._validate()
            atomic_json(self.path, self.value)
        except Exception:
            self.failed = True
            raise RuntimeError("sdk_checkpoint_write_failed") from None

    def get_tuple(self, config):
        with self.lock:
            identifier = self._identifier(config)
            row = next((row for row in self.value["records"] if row["checkpoint"]["id"] == identifier), None)
            if row is None:
                return None
            return CheckpointTuple(self._config(identifier), deepcopy(row["checkpoint"]), deepcopy(row["metadata"]),
                self._config(row["parent"]) if row["parent"] else None,
                [(write["task_id"], write["channel"], deepcopy(write["value"])) for write in row["writes"]])

    def put(self, config, checkpoint, metadata, new_versions):
        with self.lock:
            parent = self._identifier(config)
            row = {"checkpoint": deepcopy(checkpoint), "metadata": deepcopy(metadata), "parent": parent, "writes": []}
            self.value["records"] = [*self.value["records"], row][-2:]
            self.value["latest"] = checkpoint["id"]
            self.save()
            return self._config(checkpoint["id"])

    def put_writes(self, config, writes, task_id, task_path=""):
        with self.lock:
            identifier = self._identifier(config)
            row = next((row for row in self.value["records"] if row["checkpoint"]["id"] == identifier), None)
            if row is None:
                raise RuntimeError("sdk_checkpoint_write_parent_missing")
            for index, (channel, value) in enumerate(writes):
                if isinstance(value, BaseException) and channel == "__error__":
                    value = "sdk_node_failed"
                index = WRITES_IDX_MAP.get(channel, index)
                previous = next((item for item in row["writes"] if item["task_id"] == task_id and item["index"] == index), None)
                if previous is not None and index >= 0:
                    continue
                write = {"task_id": task_id, "index": index, "channel": channel, "value": deepcopy(value), "task_path": task_path}
                if previous is not None:
                    row["writes"].remove(previous)
                row["writes"].append(write)
            self.save()
