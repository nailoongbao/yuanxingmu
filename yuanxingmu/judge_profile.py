"""Host-only storage for an optional judge independent of the working model.

These helpers make no network requests. Callers own the profile lock and append
the paths returned by ``save_judge_profile`` to the manifest's immutable files.
``pins=None`` is for initialization, before that manifest exists. Existing
profiles must pass their trusted manifest's ``files`` mapping on every load.
The protected profile runtime, including descriptor-relative storage, is Linux.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from .guards import JudgeConfig


CONFIG_NAME = "judge-config.json"
KEY_NAME = "judge-key"
DEFAULT_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 45  # Leave time for IPC (60 s) and framework hooks (65 s).
_CONFIG_FIELDS = {"url", "id", "timeout_seconds"}
_INPUT_FIELDS = _CONFIG_FIELDS | {"api_key"}
_CONFIG_LIMIT = 8192
_KEY_LIMIT = 16384


def normalize_judge_config(value: dict) -> dict:
    """Validate host input, supplying defaults without changing URL/key bytes.

    The returned input object contains the key and is for host code only. Use
    ``judge_profile_report`` for any UI/API response.
    """
    if (type(value) is not dict or not {"url", "id"} <= set(value)
            or set(value) - _INPUT_FIELDS):
        raise ValueError("invalid_judge_profile_configuration")
    timeout = value.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS)
    if type(timeout) not in {int, float} or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise ValueError("invalid_judge_profile_timeout")
    judge = JudgeConfig(model_url=value["url"], model_id=value["id"],
                        api_key=value.get("api_key", ""), timeout_seconds=timeout)
    # Backslashes have differing URL/path interpretations across HTTP clients.
    if "\\" in judge.model_url:
        raise ValueError("invalid_judge_profile_configuration")
    return {"url": judge.model_url, "id": judge.model_id,
            "api_key": judge.api_key, "timeout_seconds": judge.timeout_seconds}


@contextmanager
def _profile_directory(profile: Path):
    if not sys.platform.startswith("linux"):
        raise RuntimeError("judge_profile_requires_linux")
    path = Path(profile)
    if (not path.is_absolute() or ".." in path.parts or "\x00" in str(path)
            or path == Path("/")):
        raise ValueError("invalid_judge_profile_path")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError("judge_profile_directory_not_host_owned")
        yield path, descriptor
    finally:
        os.close(descriptor)


def _exists(directory: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink, info.st_uid)


def _read(directory: int, name: str, maximum: int) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) & 0o077
                or before.st_size > maximum):
            raise ValueError("invalid_judge_profile_file")
        chunks = []
        count = 0
        while count <= maximum:
            chunk = os.read(descriptor, min(8192, maximum + 1 - count))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
        after = os.fstat(descriptor)
        if count > maximum or _identity(before) != _identity(after):
            raise ValueError("judge_profile_file_changed")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _write(directory: int, name: str, content: bytes) -> tuple[int, int]:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=directory)
    try:
        os.fchmod(descriptor, 0o600)
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("judge_profile_write_failed")
            view = view[written:]
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        return info.st_dev, info.st_ino
    finally:
        os.close(descriptor)


def save_judge_profile(profile: Path, config: dict | None) -> list[Path]:
    """Create the two fixed private files once; return paths for manifest pins.

    No config means no files and retains the working-model fallback. No existing
    file, including a dangling symlink or partial prior write, is overwritten.
    A failed partial creation stays un-loadable until the host repairs it.
    """
    if config is None:
        return []
    value = normalize_judge_config(config)
    public = {name: value[name] for name in sorted(_CONFIG_FIELDS)}
    encoded = (json.dumps(public, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n").encode("utf-8")
    with _profile_directory(profile) as (path, directory):
        if any(_exists(directory, name) for name in (CONFIG_NAME, KEY_NAME)):
            raise ValueError("judge_profile_already_exists")
        # Publish the complete config last. A crash can leave only a key; loads
        # reject that state rather than silently falling back to the agent.
        _write(directory, KEY_NAME, value["api_key"].encode("utf-8"))
        _write(directory, CONFIG_NAME, encoded)
        os.fsync(directory)
        return [path / CONFIG_NAME, path / KEY_NAME]


def _strict_config(raw: bytes) -> dict:
    def pairs(items):
        value = {}
        for name, item in items:
            if name in value:
                raise ValueError("invalid_judge_profile_configuration")
            value[name] = item
        return value

    def constant(_):
        raise ValueError("invalid_judge_profile_configuration")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("invalid_judge_profile_configuration") from None
    if type(value) is not dict or set(value) != _CONFIG_FIELDS:
        raise ValueError("invalid_judge_profile_configuration")
    return value


def _validate_in_directory(directory: int, pins: dict | None) -> JudgeConfig | None:
    if pins is not None and type(pins) is not dict:
        raise ValueError("invalid_judge_profile_pins")
    names = (CONFIG_NAME, KEY_NAME)
    present = [_exists(directory, name) for name in names]
    pinned = [pins is not None and name in pins for name in names]
    if not any(present):
        if any(pinned):
            raise ValueError("judge_profile_file_missing")
        return None
    if not all(present):
        raise ValueError("judge_profile_incomplete")
    if pins is not None and (not all(pinned) or any(
            type(pins[name]) is not str or not re.fullmatch(r"[0-9a-f]{64}", pins[name]) for name in names)):
        raise ValueError("judge_profile_not_pinned")
    values = {CONFIG_NAME: _read(directory, CONFIG_NAME, _CONFIG_LIMIT),
              KEY_NAME: _read(directory, KEY_NAME, _KEY_LIMIT)}
    if pins is not None and any(hashlib.sha256(values[name]).hexdigest() != pins[name] for name in names):
        raise ValueError("judge_profile_file_changed")
    config = _strict_config(values[CONFIG_NAME])
    try:
        key = values[KEY_NAME].decode("utf-8")
    except UnicodeError:
        raise ValueError("invalid_judge_profile_key") from None
    value = normalize_judge_config({**config, "api_key": key})
    return JudgeConfig(model_url=value["url"], model_id=value["id"],
                       api_key=value["api_key"], timeout_seconds=value["timeout_seconds"])


def validate_judge_profile(profile: Path, pins: dict | None = None) -> JudgeConfig | None:
    """Validate the fixed pair and both hashes, or return None for legacy profiles.

    Pass the entire manifest ``files`` mapping; unrelated immutable files are
    ignored. A new independent pair absent from that mapping is rejected.
    """
    with _profile_directory(profile) as (_, directory):
        return _validate_in_directory(directory, pins)


def _load(profile: Path, agent_model: dict, pins: dict | None) -> tuple[JudgeConfig, bool]:
    with _profile_directory(profile) as (_, directory):
        judge = _validate_in_directory(directory, pins)
        if judge is not None:
            return judge, True
        # These are the same source and defaults used before independent judges.
        # The ordinary profile validator remains responsible for model-key pins.
        key = _read(directory, "model-key", _KEY_LIMIT).decode("utf-8")
        return JudgeConfig(model_url=agent_model["url"], model_id=agent_model["id"],
                           api_key=key, timeout_seconds=DEFAULT_TIMEOUT_SECONDS), False


def load_judge_profile(profile: Path, agent_model: dict, *, pins: dict | None = None) -> JudgeConfig:
    """Load an independent judge, or use the unchanged working-model fallback."""
    return _load(profile, agent_model, pins)[0]


def judge_profile_report(profile: Path, agent_model: dict, *, pins: dict | None = None) -> dict:
    """Return an explicit UI allowlist; no key, key digest or host file path."""
    judge, independent = _load(profile, agent_model, pins)

    def visible(value):
        # Also redact a credential accidentally pasted into an otherwise valid
        # model identifier or URL path; never echo credentials to the frontend.
        return value.replace(judge.api_key, "[已隐藏]") if judge.api_key else value

    return {"independent": independent, "source": "independent" if independent else "agent",
            "url": visible(judge.model_url), "id": visible(judge.model_id),
            "timeout_seconds": judge.timeout_seconds}
