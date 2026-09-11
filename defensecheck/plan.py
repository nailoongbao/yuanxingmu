"""Prepare a local, unverified migration candidate without starting any services."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from .config import ConfigurationError, Endpoint, gateway_parts, load_config
from .policy import email_policy, require_template_policy


_DYNAMIC = re.compile(r"\$(?:[A-Za-z_({])|%[A-Za-z_][A-Za-z0-9_]*%")
_PROJECT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _reject_dynamic(value: str) -> None:
    if "\0" in value or value.startswith("~") or _DYNAMIC.search(value) or chr(96) in value:
        raise ConfigurationError("Dynamic expansion, shell expressions and NUL bytes require manual review")


def _absolute_local_path(value: str | Path, *, directory: bool, label: str) -> Path:
    text = str(value)
    _reject_dynamic(text)
    if text.startswith(("\\\\", "//")):
        raise ConfigurationError(f"{label} must be a local absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise ConfigurationError(f"{label} must be an absolute path")
    resolved = path.resolve(strict=True)
    if not (resolved.is_dir() if directory else resolved.is_file()):
        raise ConfigurationError(f"{label} must identify an existing {'directory' if directory else 'file'}")
    # A virtualenv Python is commonly a symlink to the system executable. Python
    # locates pyvenv.cfg relative to the invoked path, so keep the executable path.
    return resolved if directory else path.absolute()


def _check_entry(entry: Any) -> tuple[list[str], list[str]]:
    if not isinstance(entry, dict) or set(entry) - {"command", "args", "env", "cwd"}:
        raise ConfigurationError("Only command, args, env and cwd are supported for a selected server")
    prefix, upstream = gateway_parts(entry)
    env = entry.get("env", {})
    if not isinstance(env, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in env.items()):
        raise ConfigurationError("env must contain string keys and values")
    if any(not key or "=" in key or "\0" in key for key in env):
        raise ConfigurationError("env contains an invalid variable name")
    if len({key.casefold() for key in env}) != len(env):
        raise ConfigurationError("Environment variable names must not differ only by letter case")
    cwd = entry.get("cwd")
    if not isinstance(cwd, str) or not cwd:
        raise ConfigurationError("An explicit absolute working directory is required")
    for value in [*prefix, *upstream, cwd, *env.values()]:
        _reject_dynamic(value)
    _absolute_local_path(entry["command"], directory=False, label="Gateway command")
    _absolute_local_path(upstream[0], directory=False, label="Upstream command")
    _absolute_local_path(cwd, directory=True, label="Working directory")
    return prefix, upstream


def _aggregate_bytes() -> bytes:
    path = Path(__file__).with_name("aggregate.py")
    if not path.is_file():
        raise ConfigurationError("The packaged aggregate.py launcher is unavailable")
    return path.read_bytes()


def prepare_plan(
    config_path: Path,
    source: Endpoint,
    sink: Endpoint,
    policy_path: Path,
    allowed_domain: str,
    aggregation_python: Path,
    target_project: str,
    output: Path,
) -> dict[str, Any]:
    """Write a fresh candidate directory; leave the supplied configuration untouched."""
    for endpoint in (source, sink):
        if not isinstance(endpoint, Endpoint):
            raise ConfigurationError("Source and sink must be explicit endpoints")
        Endpoint.parse(f"{endpoint.server}:{endpoint.tool}")
    if source.server == sink.server:
        raise ConfigurationError("This migration requires two different selected servers")
    if not isinstance(target_project, str) or not _PROJECT.fullmatch(target_project):
        raise ConfigurationError("Use an explicit target project with letters, digits, '.', '_' or '-'")

    config_path, policy_path = Path(config_path).resolve(strict=True), Path(policy_path).resolve(strict=True)
    config, config_hash = load_config(config_path)
    if set(config) != {"mcpServers"}:
        raise ConfigurationError("Top-level configuration fields beyond mcpServers require manual review")
    servers = config["mcpServers"]
    if set(servers) != {source.server, sink.server}:
        raise ConfigurationError("The configuration must contain exactly the two selected servers; other routes require manual review")

    source_entry, sink_entry = servers[source.server], servers[sink.server]
    source_prefix, source_upstream = _check_entry(source_entry)
    sink_prefix, sink_upstream = _check_entry(sink_entry)
    if source_prefix != sink_prefix:
        raise ConfigurationError("Gateway launcher/options differ; automatic migration could discard an existing protection")
    if source_entry.get("env", {}) != sink_entry.get("env", {}):
        raise ConfigurationError("Server environments differ; credentials must not be merged")
    if source_entry["cwd"] != sink_entry["cwd"]:
        raise ConfigurationError("Working directories differ; automatic migration is unsupported")

    exposed_source = f"{source.server}_{source.tool}"
    exposed_sink = f"{sink.server}_{sink.tool}"
    if exposed_source == exposed_sink:
        raise ConfigurationError("The selected tools collide after namespace mapping")
    candidate_policy = email_policy(exposed_source, exposed_sink, allowed_domain)
    raw_policy = policy_path.read_bytes()
    if len(raw_policy) > 20_000:
        raise ConfigurationError("The policy exceeds the supported single-template size")
    try:
        policy_text = raw_policy.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ConfigurationError("The source policy must be UTF-8 text") from exc
    require_template_policy(policy_text, source.tool, sink.tool, allowed_domain)
    aggregation_python = _absolute_local_path(aggregation_python, directory=False, label="Aggregation Python")

    # Read trusted package code as data; importing it could load optional runtime dependencies.
    aggregate = _aggregate_bytes()
    output = Path(output).absolute()
    if os.path.lexists(output):
        raise ConfigurationError("The output directory already exists; choose a fresh directory")
    output = output.parent.resolve() / output.name
    if os.path.lexists(output):
        raise ConfigurationError("The output directory already exists; choose a fresh directory")
    files = {
        "upstreams": output / "upstreams.json",
        "client": output / "client.after.json",
        "policy": output / "policy.after.txt",
        "aggregator": output / "aggregate.py",
        "plan": output / "plan.json",
    }
    upstreams = {}
    for endpoint, entry, argv in (
        (source, source_entry, source_upstream),
        (sink, sink_entry, sink_upstream),
    ):
        upstream_entry = {"command": argv[0], "args": argv[1:]}
        for field in ("env", "cwd"):
            if field in entry:
                upstream_entry[field] = deepcopy(entry[field])
        upstreams[endpoint.server] = upstream_entry

    launcher = list(source_prefix)
    launcher[launcher.index("--project-name") + 1] = target_project
    launcher.extend([
        str(aggregation_python), str(files["aggregator"]), str(files["upstreams"]),
        "--require-tool", exposed_source, "--require-tool", exposed_sink,
    ])
    client_entry = {"command": launcher[0], "args": launcher[1:]}
    for field in ("env", "cwd"):
        if field in source_entry:
            client_entry[field] = deepcopy(source_entry[field])
    client_after = {"mcpServers": {"guarded": client_entry}}
    candidate_policy_bytes = candidate_policy.encode("utf-8")
    client_bytes = _json_bytes(client_after)
    upstreams_bytes = _json_bytes({"mcpServers": upstreams})
    report = {
        "schema_version": 1,
        "status": "candidate_unverified",
        "security_result": "not_tested",
        "migration": "candidate_requires_behavior_test",
        "config_path": str(config_path),
        "config_sha256": config_hash,
        "policy_path": str(policy_path),
        "policy_sha256": hashlib.sha256(raw_policy).hexdigest(),
        "source": {"server": source.server, "tool": source.tool, "exposed_tool": exposed_source},
        "sink": {"server": sink.server, "tool": sink.tool, "exposed_tool": exposed_sink},
        "target_project": target_project,
        "target_policy_installed": False,
        "files": {name: str(path) for name, path in files.items()},
        "candidate_config_sha256": hashlib.sha256(client_bytes).hexdigest(),
        "candidate_upstreams_sha256": hashlib.sha256(upstreams_bytes).hexdigest(),
        "candidate_policy_sha256": hashlib.sha256(candidate_policy_bytes).hexdigest(),
        "aggregator_sha256": hashlib.sha256(aggregate).hexdigest(),
        "required_evidence": [
            "Install and verify the complete candidate rule in the explicit target project; this plan does not deploy it",
            "Use the tested pending-event policy adapter for this supported rule; arbitrary policies are not compatible by assumption",
            "Verify actual exposed tool names and that private reads and sends share one guarded connection",
            "Observe independent downstream receipts for prohibited sends, legitimate sends and recovery",
            "Verify no alternate connection or state reset bypass exists in the declared host scope",
        ],
        "limits": [
            "No configured command, policy engine, tool or network request was executed",
            "The supplied policy file was checked; the live active policy set was not fetched",
            "Only the selected tool names were statically mapped; runtime discovery is still required",
            "Candidate configuration files preserve supplied environment values and must be kept private",
            "Changing configuration, rules, component versions or session routing invalidates any later verification",
        ],
    }
    artifacts = {
        files["upstreams"]: upstreams_bytes,
        files["client"]: client_bytes,
        files["policy"]: candidate_policy_bytes,
        files["aggregator"]: aggregate,
        files["plan"]: _json_bytes(report),
    }
    # Exclusively reserve a fresh directory. Partial writes are never installed or marked verified.
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise ConfigurationError("The output directory already exists; choose a fresh directory") from exc
    for path, contents in artifacts.items():
        with path.open("xb") as stream:
            stream.write(contents)
    return report
