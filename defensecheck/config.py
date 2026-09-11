"""Read-only configuration analysis. Never launches configured commands."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any


class ConfigurationError(ValueError):
    pass


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ConfigurationError("Duplicate JSON key; refusing ambiguous configuration")
        result[key] = value
    return result


@dataclass(frozen=True)
class Endpoint:
    server: str
    tool: str

    @classmethod
    def parse(cls, value: str) -> "Endpoint":
        parts = value.split(":")
        if len(parts) != 2 or any(not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", part) for part in parts):
            raise ConfigurationError("An endpoint must be SERVER:TOOL, using letters, digits, '_' or '-'")
        return cls(*parts)


def load_config(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    if len(raw) > 2_000_000:
        raise ConfigurationError("Configuration exceeds the supported 2 MB limit")
    try:
        value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigurationError("Expected a UTF-8 JSON configuration") from exc
    if not isinstance(value, dict) or not isinstance(value.get("mcpServers"), dict):
        raise ConfigurationError("Expected a JSON object containing mcpServers")
    return value, hashlib.sha256(raw).hexdigest()


def gateway_parts(entry: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Recognize explicit official stdio launcher forms; return guard prefix/upstream argv."""
    command, args = entry.get("command"), entry.get("args", [])
    if not isinstance(command, str) or not command or not isinstance(args, list) or any(not isinstance(a, str) for a in args):
        raise ConfigurationError("Expected an explicit command and string args; shell commands are unsupported")
    # Recognize Windows paths even when inspecting them on another OS.
    basename = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if re.fullmatch(r"python(?:3(?:\.\d+)?)?(?:\.exe)?", basename) and args[:3] == ["-m", "gateway", "mcp"]:
        offset = 3
    elif basename in ("invariant-gateway", "invariant-gateway.exe") and args[:1] == ["mcp"]:
        offset = 1
    elif basename in ("uvx", "uvx.exe") and len(args) >= 2 and args[0].split("@", 1)[0] == "invariant-gateway" and args[1] == "mcp":
        offset = 2
    else:
        raise ConfigurationError("This launcher is not a supported Invariant stdio gateway form")
    try:
        split = args.index("--exec", offset)
    except ValueError as exc:
        raise ConfigurationError("The gateway is missing --exec") from exc
    upstream = args[split + 1:]
    if not upstream:
        raise ConfigurationError("The gateway has no upstream command")
    flags = args[offset:split]
    position = 0
    has_project = False
    while position < len(flags):
        option = flags[position]
        if option == "--project-name" and not has_project and position + 1 < len(flags):
            if not flags[position + 1] or flags[position + 1].startswith("--"):
                raise ConfigurationError("Invalid gateway project name")
            has_project = True
            position += 2
        elif option == "--verbose":
            position += 1
        else:
            raise ConfigurationError("Unsupported gateway options: policy filtering, telemetry and other modes require manual review")
    if not has_project:
        raise ConfigurationError("Use an explicit gateway project name")
    return [command, *args[:split + 1]], upstream


def inspect_config(path: Path, source: Endpoint, sink: Endpoint) -> dict[str, Any]:
    config, digest = load_config(path)
    servers = config["mcpServers"]
    for endpoint in (source, sink):
        if endpoint.server not in servers:
            raise ConfigurationError("A selected server is absent from mcpServers")
    reasons = []
    if set(config) != {"mcpServers"}:
        reasons.append({"reason": "Additional top-level configuration requires manual review"})
    if set(servers) != {source.server, sink.server}:
        reasons.append({"reason": "Additional server entries may preserve a direct route; automatic grouping is unsupported"})
    parsed = {}
    for name in dict.fromkeys((source.server, sink.server)):
        entry = servers[name]
        if not isinstance(entry, dict):
            raise ConfigurationError("A selected server configuration is not an object")
        try:
            if set(entry) - {"command", "args", "env", "cwd"}:
                raise ConfigurationError("Unsupported server fields require manual review")
            env = entry.get("env", {})
            if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items()):
                raise ConfigurationError("env must contain string keys and values")
            if "cwd" in entry and (not isinstance(entry["cwd"], str) or not entry["cwd"]):
                raise ConfigurationError("cwd must be a nonempty string")
            parsed[name] = gateway_parts(entry)
        except ConfigurationError as exc:
            reasons.append({"server": name, "reason": str(exc)})
    same = source.server == sink.server
    if not same and len(parsed) == 2:
        if parsed[source.server][0] != parsed[sink.server][0]:
            reasons.append({"reason": "Gateway launcher/options differ; merging could drop an existing protection"})
        if servers[source.server].get("env", {}) != servers[sink.server].get("env", {}):
            reasons.append({"reason": "Server environments differ; credentials and executable resolution must not be merged implicitly"})
        if servers[source.server].get("cwd") != servers[sink.server].get("cwd"):
            reasons.append({"reason": "Working directories differ; automatic migration is unsupported"})
    return {
        "schema_version": 1,
        "config_sha256": digest,
        "source": {"server": source.server, "tool": source.tool},
        "sink": {"server": sink.server, "tool": sink.tool},
        "observation": "same_configured_connection" if same else "separate_configured_connections",
        "security_result": "not_tested",
        "migration": "not_needed_for_this_pair" if same else "manual_review" if reasons else "candidate_requires_behavior_test",
        "reasons": reasons,
        "required_evidence": [
            "The complete active policy set is preserved with the actual exposed tool names",
            "A trusted host keeps private context bound to the guarded connection; no direct or reset bypass",
            "Independent receipts show prohibited sends blocked and required legitimate tasks completed",
        ],
        "limits": "Static configuration only. No commands, tools, network requests or secret-value output.",
    }
