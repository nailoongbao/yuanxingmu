"""Official Hermes dashboard profiles using the shared host supervisor.

The WebUI, TUI and Agent all run inside the outer network namespace. The
terminal provider adds the worker boundary; neither layer holds host secrets.
"""
from __future__ import annotations

import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import sys
import uuid

from .broker import Broker, MAX_CONTENT
from .run import load_policy
from .sandbox import sandbox_available, _overlaps, _reject_broad_grant, _system_mount_args

HERMES_VERSION = "0.21.2"
HERMES_RELEASE = "v2026.9.11"
HERMES_COMMIT = "939e45c91d751fadd94dcd1b873ac3cb44846213"
PACKAGE = Path(__file__).resolve().parent
PLUGIN = PACKAGE / "integrations" / "hermes" / "plugin"
TOOLSETS = ["terminal", "file", "yuanxingmu"]
_MAIN = "import sys; sys.path.insert(0, sys.argv.pop(1)); from hermes_cli.main import main; main()"
_TOKEN = re.compile(r'window\.__HERMES_SESSION_TOKEN__\s*=\s*("(?:\\.|[^"\\])*")')


def _runtime(*, node: Path, hermes_python: Path, hermes_source: Path, bwrap: Path) -> dict:
    from .openclaw import _linux
    _linux()
    node, source, bwrap = (Path(p).resolve(strict=True) for p in (node, hermes_source, bwrap))
    # Preserve the venv's Python symlink: resolving its leaf would select the
    # system interpreter and silently lose the Hermes installation.
    raw_python = Path(hermes_python).absolute()
    venv = raw_python.parent.parent.resolve(strict=True)
    python = venv / raw_python.parent.name / raw_python.name
    if raw_python.parent.name != "bin" or not (venv / "pyvenv.cfg").is_file():
        raise ValueError("hermes_python_requires_a_dedicated_venv")
    for path in (node, python, bwrap):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError("hermes_runtime_must_be_executable")
    for path in (node, venv, source, bwrap):
        _reject_broad_grant(path, "Hermes runtime")
    version = re.search(r'^__version__\s*=\s*[\'"]([^\'"]+)',
                        (source / "hermes_cli" / "__init__.py").read_text(encoding="utf-8"), re.M)
    if version is None or version.group(1) != HERMES_VERSION:
        raise ValueError("本版支持 Hermes " + HERMES_RELEASE + " / " + HERMES_VERSION)
    required = ("hermes_cli/main.py", "hermes_cli/web_server.py", "hermes_cli/web_dist/index.html",
                "ui-tui/dist/entry.js", "agent/terminal_env_provider.py", "tools/environments/base.py")
    for name in required:
        if not (source / name).is_file():
            raise ValueError("hermes_runtime_file_missing: " + name)
    return {"node": str(node), "hermes_python": str(python), "hermes_venv": str(venv),
            "hermes_source": str(source), "hermes_version": HERMES_VERSION, "bwrap": str(bwrap)}


def runtime_available(*, node: Path, hermes_python: Path, hermes_source: Path, bwrap: Path) -> dict:
    """Check explicit runtime files and the Linux boundary without model calls."""
    try:
        runtime = _runtime(node=node, hermes_python=hermes_python, hermes_source=hermes_source, bwrap=bwrap)
        isolation = sandbox_available(bwrap=Path(runtime["bwrap"]))
        return {"available": bool(isolation["available"]), "version": HERMES_VERSION,
                "reason": "ready" if isolation["available"] else str(isolation["reason"])}
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        return {"available": False, "version": HERMES_VERSION, "reason": str(exc)}


def init_profile(profile: Path, *, node: Path, hermes_python: Path, hermes_source: Path, bwrap: Path,
                 model_url: str, model_id: str, api_key: str = "local-unused",
                 documents: dict[str, Path] | None = None, destinations: dict | None = None,
                 reviewed_mail=False, reviewed_actions=False, action_targets: dict | None = None,
                 action_automation: dict | None = None,
                 selected_skills: dict[str, Path] | None = None,
                 defense_policy: dict | None = None, judge_config: dict | None = None, port: int = 18921,
                 context_window: int = 65536, max_tokens: int = 2048) -> dict:
    """Create a fresh, private Hermes profile; lifecycle stays in openclaw.py."""
    from . import openclaw as host
    runtime = _runtime(node=node, hermes_python=hermes_python, hermes_source=hermes_source, bwrap=bwrap)
    model_url = host._model_url(model_url)
    if not isinstance(model_id, str) or not model_id.strip() or any(c in model_id for c in "\x00\r\n"):
        raise ValueError("需要有效的模型名称。")
    if not isinstance(api_key, str) or not api_key or any(c in api_key for c in "\x00\r\n"):
        raise ValueError("invalid_model_api_key")
    if selected_skills is not None and not isinstance(selected_skills, dict):
        raise ValueError("selected_skills_must_be_an_object")
    if judge_config is not None and defense_policy is None:
        raise ValueError("independent_judge_requires_layered_defense")
    if action_automation is not None and (defense_policy is None or reviewed_actions is not True):
        raise ValueError("automatic_actions_require_defense_and_reviewed_actions")
    if (type(port) is not int or not 1024 <= port <= 65535 or port == 18701
            or type(context_window) is not int or context_window < 64000
            or type(max_tokens) is not int or not 128 <= max_tokens < context_window):
        raise ValueError("invalid_port_or_context_window")
    readiness = sandbox_available(bwrap=Path(runtime["bwrap"]))
    if not readiness["available"]:
        raise RuntimeError(str(readiness["reason"]))
    imported = {}
    for name, source in (documents or {}).items():
        host._name(name)
        source = Path(source).resolve(strict=True)
        if not source.is_file() or source.stat().st_size > MAX_CONTENT:
            raise ValueError("资料须为不超过 256 KiB 的 UTF-8 文本文件。")
        data = source.read_bytes()
        data.decode("utf-8")
        imported[name] = data
    destinations = destinations or {}
    if not isinstance(destinations, dict):
        raise ValueError("destinations_must_be_an_object")
    for name, item in destinations.items():
        host._name(name)
        if not isinstance(item, dict) or set(item) not in ({"url", "labels"}, {"url", "labels", "headers"}):
            raise ValueError("destination_requires_url_and_labels")
        if item["labels"] not in ([], ["private"]):
            raise ValueError("destination_labels_must_be_private_or_empty")
    profile = Path(profile).absolute()
    if profile.exists() or profile.is_symlink():
        raise RuntimeError("此位置已有内容，请使用新的目录；已有实例请用 start。")
    for key in ("node", "hermes_source", "hermes_venv", "bwrap"):
        if _overlaps(Path(runtime[key]), profile.resolve()):
            raise ValueError("runtime_mount_overlaps_private_profile")
    bootstrap_python = Path(sys.executable).resolve(strict=True)
    if not bootstrap_python.is_relative_to(Path("/usr")):
        raise RuntimeError("Gateway isolation currently requires a system Python under /usr.")
    profile.parent.mkdir(parents=True, exist_ok=True)
    profile.mkdir(mode=0o700)
    profile = profile.resolve()
    directories = ("documents", "workspace", "trusted-core", "plugin", "hermes-home", "host-home", "gateway-audit", "runtime-etc", "skill-store")
    for name in directories:
        (profile / name).mkdir(mode=0o700)
    (profile / "trusted-core" / "yuanxingmu").mkdir(mode=0o700)
    for source in PACKAGE.glob("*.py"):
        host._bytes(profile / "trusted-core" / "yuanxingmu" / source.name, source.read_bytes())
    for source in PLUGIN.iterdir():
        if source.is_file():
            host._bytes(profile / "plugin" / source.name, source.read_bytes())
    (profile / "hermes-home" / "plugins" / "yuanxingmu").mkdir(parents=True, mode=0o700)
    (profile / "hermes-home" / "skills").mkdir(mode=0o700)
    from .skills import create_snapshot
    empty_skills = create_snapshot(profile / "skill-store", {})
    chosen_skills = create_snapshot(profile / "skill-store", selected_skills or {})
    resources = {}
    for name, data in imported.items():
        host._bytes(profile / "documents" / (name + ".txt"), data)
        resources[name] = {"path": "documents/" + name + ".txt", "labels": ["private"]}
    host._save(profile / "policy.json", {"resources": resources, "destinations": destinations})
    host._bytes(profile / "model-key", api_key.encode())
    from .judge_profile import save_judge_profile
    judge_paths = save_judge_profile(profile, judge_config)
    guards = None
    if defense_policy is not None:
        if not isinstance(defense_policy, dict):
            raise ValueError("defense_policy_must_be_an_object")
        host._save(profile / "defense-policy.json", defense_policy)
        from .protection import load_guards, save_settings_baseline
        guards = load_guards(profile, {"url": model_url, "id": model_id})
        save_settings_baseline(profile, guards.policy)
    loaded_resources, loaded_destinations = load_policy(profile / "policy.json")
    from .protection import save_protected_profile
    broker_options = {"reviewed_mail": reviewed_mail,
                      "protected_data": save_protected_profile(profile, loaded_resources)}
    if guards is not None:
        broker_options["guards"] = guards
        broker_options["input_containment"] = True
    if reviewed_actions:
        from .protection import load_action_targets
        host._save(profile / "action-targets.json", action_targets if action_targets is not None else {})
        broker_options["action_targets"] = load_action_targets(profile)
    if action_automation is not None:
        from .action_automation import AutomaticActionPolicy
        action_automation = AutomaticActionPolicy.from_config(action_automation, broker_options["action_targets"]).to_config()
        host._save(profile / "action-automation.json", action_automation)
        broker_options["action_automation"] = action_automation
    with Broker(profile / "broker-state", loaded_resources, loaded_destinations, **broker_options) as broker:
        task = broker.create_task(initial_labels=["private"])
        broker.bind_workspace(task, profile / "workspace")
        family = broker.authority._db.execute("SELECT family_id FROM authority_tasks WHERE id=?", (task,)).fetchone()[0]
    profile_id = uuid.uuid4().hex
    sockets = Path("/tmp") / ("yxm-" + str(os.getuid()) + "-" + profile_id)
    host._bytes(profile / "gateway-token", secrets.token_urlsafe(32).encode())
    for name, value in {
        "passwd": f"yuanxingmu:x:{os.getuid()}:{os.getgid()}:Yuanxingmu:{profile / 'host-home'}:/bin/sh\n",
        "group": f"yuanxingmu:x:{os.getgid()}:\n", "nsswitch.conf": "passwd: files\ngroup: files\nhosts: files\n",
        "hosts": "127.0.0.1 localhost\n::1 localhost\n",
    }.items():
        host._bytes(profile / "runtime-etc" / name, value.encode())
    binding = {"version": 1, "task_id": task, "workspace": str(profile / "workspace"),
               "broker_socket": str(sockets / "broker.sock"), "bwrap": runtime["bwrap"],
               "core_root": str(profile / "trusted-core"), "resource_ids": sorted(resources),
               "destination_ids": sorted(destinations), "reviewed_mail": reviewed_mail is True,
               "reviewed_actions": reviewed_actions is True, "defense_enabled": defense_policy is not None,
               "automatic_actions": action_automation is not None,
               "skill_dir": str(profile / "hermes-home" / "skills"), "skill_names": sorted(chosen_skills.source_paths)}
    host._save(profile / "hermes-binding.json", binding)
    model = {"provider": "custom", "default": model_id, "base_url": "http://127.0.0.1:18701/v1",
             "api_mode": "chat_completions", "api_key": "local-bridge-no-key", "context_length": context_window,
             "max_tokens": max_tokens}
    auxiliary = {name: {"provider": "custom", "model": model_id, "base_url": model["base_url"],
                        "api_key": model["api_key"], "timeout": 120}
                 for name in ("compression", "approval", "vision", "skills_hub", "mcp")}
    auxiliary.update(title_generation={"enabled": False}, background_review={"enabled": False})
    config = {"model": model, "fallback_providers": [], "auxiliary": auxiliary,
              "terminal": {"backend": "yuanxingmu", "cwd": "/workspace", "timeout": 25},
              "platform_toolsets": {"cli": TOOLSETS},
              # This fixed profile exposes only a small tool set. Keep their
              # real schemas visible instead of adding a discovery round-trip.
              "tools": {"tool_search": {"enabled": "off"}},
              "skills": {"project_discovery": False, "external_dirs": [], "trusted_project_dirs": [], "create_dir": ""},
              "delegation": {"fallback_providers": []},
              "plugins": {"enabled": ["yuanxingmu"], "entries": {"yuanxingmu": {
                  "settings": {"host_config": str(profile / "hermes-binding.json"), "defenseEnabled": defense_policy is not None}}}},
              "display": {"interface": "tui"}}
    # JSON is valid YAML and avoids a host-side PyYAML dependency.
    host._save(profile / "hermes-config.yaml", config)
    host._bytes(profile / "hermes-home" / "config.yaml", b"{}\n")
    immutable = [profile / name for name in ("hermes-config.yaml", "hermes-binding.json", "policy.json", "model-key", "gateway-token",
                 "protected-data.json", "broker-state/bindings.json", "broker-state/workspaces.json")]
    if defense_policy is not None:
        immutable.append(profile / "defense-policy.json")
        immutable.append(profile / "defense-baseline.json")
    immutable.extend(judge_paths)
    if reviewed_actions:
        immutable.append(profile / "action-targets.json")
    if action_automation is not None:
        immutable.append(profile / "action-automation.json")
    for directory in ("documents", "trusted-core", "plugin", "runtime-etc", "skill-store"):
        immutable.extend(p for p in (profile / directory).rglob("*") if p.is_file())
    source = Path(runtime["hermes_source"])
    runtime_files = [Path(runtime[key]) for key in ("node", "hermes_python", "bwrap")]
    runtime_files += [Path(runtime["hermes_venv"]) / "pyvenv.cfg"]
    runtime_files += [source / name for name in ("hermes_cli/__init__.py", "hermes_cli/main.py", "hermes_cli/web_server.py", "ui-tui/dist/entry.js")]
    runtime_files += [p for p in (source / "hermes_cli" / "web_dist").rglob("*") if p.is_file()]
    features = ((["reviewed_email_v1"] if reviewed_mail else []) + (["reviewed_actions_v1"] if reviewed_actions else [])
                + (["layered_defense_v1", "quarantine_v1", "buffered_response_v1", "live_settings_v1", "per_layer_settings_v1", "settings_history_v1", "defense_baseline_v1", "skill_rules_v1", "skill_purpose_v1", "input_containment_v1"] if defense_policy is not None else [])
                + (["independent_judge_v1"] if judge_config is not None else [])
                + (["automatic_actions_v1"] if action_automation is not None else []))
    features = list(dict.fromkeys([*features, "protected_fields_v1", "quarantine_v1", "buffered_response_v1"]))
    manifest = {"version": 2, "framework": "hermes", "profile": str(profile), "profile_id": profile_id,
                "task_id": task, "family_id": family, "features": features, **runtime,
                "python": str(bootstrap_python), "runtime": str(sockets), "port": port,
                "model": {"url": model_url, "id": model_id}, "documents": sorted(resources), "destinations": sorted(destinations),
                "skills_snapshot": chosen_skills.to_dict(), "skills_empty_snapshot": empty_skills.to_dict(),
                "files": {str(p.relative_to(profile)): host._hash(p) for p in immutable},
                "identities": {name: host._identity(profile / name) for name in (*directories, ".", "broker-state", "broker-state/authority.sqlite3")},
                "runtime_files": {str(p): host._hash(p) for p in runtime_files}}
    host._save(profile / "profile.json", manifest)
    return {"status": "created", **host._public(profile, manifest)}


def validate_binding(profile: Path, manifest: dict) -> None:
    runtime = _runtime(node=Path(manifest["node"]), hermes_python=Path(manifest["hermes_python"]),
                       hermes_source=Path(manifest["hermes_source"]), bwrap=Path(manifest["bwrap"]))
    if any(manifest.get(key) != value for key, value in runtime.items()):
        raise RuntimeError("profile_hermes_binding_changed")
    binding = json.loads((profile / "hermes-binding.json").read_text(encoding="utf-8"))
    if (binding.get("task_id") != manifest["task_id"] or binding.get("workspace") != str(profile / "workspace")
            or binding.get("broker_socket") != str(Path(manifest["runtime"]) / "broker.sock")):
        raise RuntimeError("profile_hermes_authority_binding_changed")
    for key in ("node", "hermes_source", "hermes_venv", "bwrap"):
        if _overlaps(Path(manifest[key]), profile):
            raise RuntimeError("runtime_mount_overlaps_private_profile")
    snapshots = _skill_snapshots(profile, manifest)
    if snapshots is not None:
        selected, empty = snapshots
        config = json.loads((profile / "hermes-config.yaml").read_text(encoding="utf-8"))
        if (binding.get("skill_dir") != str(profile / "hermes-home" / "skills")
                or binding.get("skill_names") != sorted(selected.source_paths)
                or config.get("skills") != {"project_discovery": False, "external_dirs": [], "trusted_project_dirs": [], "create_dir": ""}):
            raise RuntimeError("profile_hermes_skills_binding_changed")


def _skill_snapshots(profile: Path, manifest: dict):
    from .skills import verify_snapshot
    if "skills_snapshot" not in manifest and "skills_empty_snapshot" not in manifest:
        return None  # An older profile remains explicitly unpinned.
    result = []
    for name in ("skills_snapshot", "skills_empty_snapshot"):
        value = manifest.get(name)
        if not isinstance(value, dict) or not isinstance(value.get("digest"), str):
            raise RuntimeError("profile_hermes_skills_snapshot_missing")
        if value.get("path") != str(profile / "skill-store" / value["digest"]):
            raise RuntimeError("profile_hermes_skills_snapshot_path_changed")
        snapshot = verify_snapshot(Path(value["path"]), value["digest"])
        if snapshot.to_dict() != value:
            raise RuntimeError("profile_hermes_skills_snapshot_changed")
        result.append(snapshot)
    if result[1].file_count or result[1].source_paths:
        raise RuntimeError("profile_hermes_skills_mask_not_empty")
    return result


def environment(profile: Path, manifest: dict) -> dict[str, str]:
    source = Path(manifest["hermes_source"])
    env = {"PATH": str(Path(manifest["node"]).parent) + ":/usr/bin:/bin", "HOME": str(profile / "host-home"),
            "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "HERMES_HOME": str(profile / "hermes-home"),
            "HERMES_WEB_DIST": str(source / "hermes_cli" / "web_dist"), "HERMES_TUI_DIR": str(source / "ui-tui"),
            "HERMES_NODE": manifest["node"], "HERMES_PYTHON": manifest["hermes_python"],
            "HERMES_PYTHON_SRC_ROOT": str(source), "HERMES_SKIP_NODE_BOOTSTRAP": "1", "HERMES_ENABLE_PROJECT_PLUGINS": "0",
            "HERMES_TUI_TOOLSETS": ",".join(TOOLSETS), "HERMES_CWD": "/workspace", "TERMINAL_ENV": "yuanxingmu",
            # The TUI bootstrap inventories env credentials separately from
            # the runtime resolver. These are bridge hints, never host keys.
            "OPENAI_BASE_URL": "http://127.0.0.1:18701/v1", "CUSTOM_BASE_URL": "http://127.0.0.1:18701/v1",
            "OPENAI_API_KEY": "local-bridge-no-key", "HERMES_INFERENCE_PROVIDER": "custom",
            "YUANXINGMU_CORE_ROOT": str(profile / "trusted-core"), "YUANXINGMU_HERMES_CONFIG": str(profile / "hermes-binding.json"),
            "HERMES_DASHBOARD_SESSION_TOKEN": (profile / "gateway-token").read_text(encoding="utf-8")}
    if "skills_snapshot" in manifest:
        # The official sync returns immediately for an absent bundled root;
        # a read-only parent prevents creating that root during startup.
        env["HERMES_BUNDLED_SKILLS"] = str(profile / "hermes-home" / "skills" / ".yuanxingmu-no-bundled")
        env["HERMES_OPTIONAL_SKILLS"] = str(profile / "hermes-home" / "skills" / ".yuanxingmu-no-optional")
    return env


def gateway_command(profile: Path, manifest: dict) -> list[str]:
    from .gateway_network import INNER_BOOTSTRAP
    validate_binding(profile, manifest)
    runtime = Path(manifest["runtime"])
    args = [manifest["bwrap"], "--unshare-user", "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts",
            "--hostname", "yuanxingmu-hermes", "--cap-drop", "ALL", "--new-session", "--die-with-parent", "--as-pid-1",
            *_system_mount_args(), "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for path in (Path(manifest["node"]), Path(manifest["bwrap"]), Path(manifest["hermes_venv"]),
                 Path(manifest["hermes_source"]), profile / "trusted-core", profile / "hermes-binding.json"):
        args += ["--ro-bind", str(path), str(path)]
    for name in ("passwd", "group", "nsswitch.conf", "hosts"):
        args += ["--ro-bind", str(profile / "runtime-etc" / name), "/etc/" + name]
    for name in ("hermes-home", "host-home", "workspace", "gateway-audit"):
        args += ["--bind", str(profile / name), str(profile / name)]
    args += ["--bind", str(profile / "workspace"), "/workspace",
             "--ro-bind", str(profile / "plugin"), str(profile / "hermes-home" / "plugins" / "yuanxingmu"),
             "--ro-bind", str(profile / "hermes-config.yaml"), str(profile / "hermes-home" / "config.yaml")]
    snapshots = _skill_snapshots(profile, manifest)
    if snapshots is not None:
        selected, empty = snapshots
        args += ["--ro-bind", str(selected.tree_path), str(profile / "hermes-home" / "skills")]
        for name in ("skills", "optional-skills"):
            path = Path(manifest["hermes_source"]) / name
            if path.is_dir():
                args += ["--ro-bind", str(empty.tree_path), str(path)]
    for name in ("model.sock", "broker.sock", "operator.sock"):
        args += ["--ro-bind", str(runtime / name), str(runtime / name)]
    args += ["--bind", str(runtime / "webui"), str(runtime / "webui"), "--chdir", "/workspace", "--remount-ro", "/", "--",
             manifest["python"], "-I", "-B", "-c", INNER_BOOTSTRAP, str(profile / "trusted-core"),
             "--runtime", str(runtime), "--webui-port", str(manifest["port"]), "--",
             manifest["hermes_python"], "-I", "-B", "-c", _MAIN, manifest["hermes_source"],
             "dashboard", "--host", "127.0.0.1", "--port", str(manifest["port"]), "--no-open", "--isolated", "--skip-build"]
    return args


def dashboard_url(profile: Path, manifest: dict) -> str:
    return f"http://127.0.0.1:{manifest['port']}/"


def foundation_config(profile: Path, manifest: dict) -> dict:
    """Declare the fixed single-owner profile's actual runtime boundaries."""
    names = ["terminal", "process_manage", "read_file", "write_file", "patch", "search_files",
             "yuanxingmu_read", "yuanxingmu_send", "yuanxingmu_status"]
    if "reviewed_email_v1" in manifest.get("features", []):
        names.append("yuanxingmu_prepare_email")
    if "reviewed_actions_v1" in manifest.get("features", []):
        names += ["yuanxingmu_action_targets", "yuanxingmu_prepare_action"]
    if "automatic_actions_v1" in manifest.get("features", []):
        names += ["yuanxingmu_request_action"]
    return {"framework": "hermes", "bind": "127.0.0.1", "auth_enabled": True, "tool_names": names,
            "allow_elevated": False, "allow_direct_network": False, "isolated_execution": True,
            "per_user_sessions": True, "credentials_host_only": True,
            "skills_pinned": _skill_snapshots(profile, manifest) is not None}


def _http(port: int, path: str, token: str | None = None) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
    try:
        headers = {"X-Hermes-Session-Token": token} if token is not None else {}
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        return response.status, response.read(1024 * 1024 + 1)
    finally:
        connection.close()


def check_ready(profile: Path, manifest: dict) -> dict:
    """Authenticate the expected SPA before disclosing its token to API routes."""
    try:
        status, page = _http(manifest["port"], "/")
        if status != 200 or len(page) > 1024 * 1024:
            return {"ok": False, "reason": "hermes_frontend_not_ready"}
        html = page.decode("utf-8")
        token_match = _TOKEN.search(html)
        expected = (profile / "gateway-token").read_text(encoding="utf-8")
        if token_match is None or not hmac.compare_digest(json.loads(token_match.group(1)).encode(), expected.encode()):
            return {"ok": False, "reason": "hermes_instance_identity_mismatch"}
        # Headless serve also injects a token, but has no official SPA module.
        if not re.search(r'<script\b[^>]*\btype=[\'"]module[\'"][^>]*\bsrc=[\'"][^\'"]+', html):
            return {"ok": False, "reason": "hermes_native_spa_missing"}
        status, body = _http(manifest["port"], "/api/sessions?limit=1", expected)
        if status != 200 or not isinstance(json.loads(body), (list, dict)):
            return {"ok": False, "reason": "hermes_authenticated_api_not_ready"}
        denied, _ = _http(manifest["port"], "/api/sessions?limit=1", "wrong-" + secrets.token_hex(16))
        if denied not in (401, 403):
            return {"ok": False, "reason": "hermes_authentication_not_enforced"}
        return {"ok": True, "authenticated": True, "framework": "hermes", "version": HERMES_VERSION}
    except (OSError, ValueError, http.client.HTTPException):
        return {"ok": False, "reason": "hermes_not_ready"}
