"""Host-only construction and evidence for opt-in layered profile defenses."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path


def load_guards(profile: Path, model: dict, *, policy_value=None, pins=None):
    from .guards import GuardPolicy, Guards
    from .judge_profile import load_judge_profile
    value = policy_value if policy_value is not None else json.loads((profile / "defense-policy.json").read_text(encoding="utf-8"))
    policy = GuardPolicy.from_dict(value)
    judge = load_judge_profile(profile, model, pins=pins)

    def audit(event):
        raw = json.dumps({"time": datetime.now(timezone.utc).isoformat(), **event}, ensure_ascii=True) + "\n"
        descriptor = os.open(profile / "defense-events.jsonl", os.O_APPEND | os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())

    return Guards(policy, judge, audit=audit)


def configure_profile(profile: Path, updates: dict | None = None, *, reset=False):
    """Host-only settings change through a live broker or a confirmed stop.

    The manifest is committed last. A crash between the three files leaves a
    mismatched profile which cannot start, rather than a silently weaker policy.
    """
    from . import openclaw as core
    from .broker import Broker
    from .guards import GuardPolicy
    from .run import load_policy
    profile = profile.expanduser().absolute()
    manifest = core.validate_profile(profile)
    if "layered_defense_v1" not in manifest.get("features", []):
        raise ValueError("layered_defense_not_enabled")
    allowed = {name + "_enabled" for name in ("input", "memory", "command", "alignment", "foundation")} | {"mode"}
    if updates is not None and (type(updates) is not dict or set(updates) - allowed):
        raise ValueError("invalid_defense_settings")
    changes = {key: "enforce" if key == "mode" else True for key in allowed} if reset else updates
    if changes is not None and core._offline_lifecycle(profile) != "stopped" and "live_settings_v1" in manifest.get("features", []):
        return core.review_profile(profile, "protection_set", {"settings": changes})
    if updates is None and not reset:
        manifest = core.validate_profile(profile)
        if "layered_defense_v1" not in manifest.get("features", []):
            raise ValueError("layered_defense_not_enabled")
        value = json.loads((profile / "defense-policy.json").read_text())
        return {"policy": GuardPolicy.from_dict(value).to_dict(), "changed": False}
    with core._profile_lock(profile):
        manifest = core.validate_profile(profile)
        if "layered_defense_v1" not in manifest.get("features", []):
            raise ValueError("layered_defense_not_enabled")
        value = json.loads((profile / "defense-policy.json").read_text())
        if updates is None and not reset:
            return {"policy": GuardPolicy.from_dict(value).to_dict(), "changed": False}
        if core._offline_lifecycle(profile) != "stopped":
            raise ValueError("profile_must_be_stopped_for_settings")
        allowed = {name + "_enabled" for name in ("input", "memory", "command", "alignment", "foundation")} | {"mode"}
        if updates is not None and (type(updates) is not dict or set(updates) - allowed):
            raise ValueError("invalid_defense_settings")
        if reset:
            changes = {key: "enforce" if key == "mode" else True for key in allowed}
        else:
            changes = updates
        policy = GuardPolicy.from_dict({**value, **changes}).to_dict()
        resources, destinations = load_policy(profile / "policy.json")
        with Broker(profile / "broker-state", resources, destinations, **profile_services(profile, manifest)) as broker:
            if not broker.authority.describe(manifest["task_id"])["active"]:
                raise ValueError("task_revoked")
            return apply_profile_settings(profile, manifest, broker, changes, running=False)


def apply_profile_settings(profile, manifest, broker, changes, *, running=True):
    """Called only by the host while holding the broker lock and profile ownership.

    File updates commit before the live guard is exposed. Any partial update
    latches the broker fault and retains its dirty marker for recovery.
    """
    from . import openclaw as core
    from .guards import GuardPolicy
    with broker._lock:
        broker._require_healthy()
        if running:
            core.validate_profile(profile)
        if not broker.authority.describe(manifest["task_id"])["active"]:
            raise ValueError("task_revoked")
        allowed = {name + "_enabled" for name in ("input", "memory", "command", "alignment", "foundation")} | {"mode"}
        if type(changes) is not dict or set(changes) - allowed:
            raise ValueError("invalid_defense_settings")
        policy = GuardPolicy.from_dict({**broker.guards.policy.to_dict(), **changes}).to_dict()
        replacement = load_guards(profile, manifest["model"], policy_value=policy, pins=manifest["files"])
        old = broker.guards
        try:
            broker.guards = replacement
            binding = broker._binding()
            core._save(profile / "defense-policy.json", policy)
            core._save(profile / "broker-state" / "bindings.json", binding)
            with broker.authority._transaction() as db:
                task = broker.authority._task(db, manifest["task_id"], require_active=False)
                invalidated = broker.quarantine._invalidate(db, task["family_id"], datetime.now(timezone.utc).isoformat())
                revision = broker.authority._revision(db, task["family_id"], advance=True)
                broker.authority._event(db, manifest["task_id"], "operator_settings_changed", True, "host_changed_defense_settings",
                                       {"invalidated": invalidated, "revision": revision})
            for name in ("defense-policy.json", "broker-state/bindings.json"):
                manifest["files"][name] = core._hash(profile / name)
            core._save(profile / "profile.json", manifest)
            replacement._audit({"layer": "foundation", "verdict": "review", "code": "operator_settings_changed",
                                "reason": "本人修改了防护设置，后续操作使用新设置；安装与技能检查将在下次启动时重做。" if running else "本人修改了防护设置，下一次启动时会重新检查。",
                                "enforced": False, "assessed": False,
                                "evidence": {"policy_sha256": manifest["files"]["defense-policy.json"], "live": running}})
        except BaseException:
            broker.guards = old
            broker._fault = True
            raise
        return {"policy": policy, "changed": True, "live": running, "task_id": manifest["task_id"]}


def profile_services(profile: Path, manifest: dict):
    features = manifest.get("features", [])
    options = {"reviewed_mail": "reviewed_email_v1" in features}
    if "layered_defense_v1" in features:
        options["guards"] = load_guards(profile, manifest["model"], pins=manifest["files"])
    if "reviewed_actions_v1" in features:
        options["action_targets"] = load_action_targets(profile)
    return options


def load_action_targets(profile: Path):
    from .actions import ActionTarget
    from .sandbox import _overlaps
    value = json.loads((profile / "action-targets.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict) or len(value) > 32:
        raise ValueError("invalid_action_targets")
    targets = {name: ActionTarget(**item) for name, item in value.items()}
    for target in targets.values():
        if target.workspace is not None and _overlaps(target.workspace, profile):
            raise ValueError("reviewed_file_target_must_be_outside_profile")
    return targets


def foundation_config(profile: Path, manifest: dict):
    """Derive statements from immutable native configuration, not browser claims."""
    framework = manifest.get("framework", "openclaw")
    if framework == "openclaw":
        value = json.loads((profile / "openclaw.json").read_text())
        gateway = value.get("gateway", {})
        tools = value.get("tools", {})
        defaults = value.get("agents", {}).get("defaults", {})
        sandbox = defaults.get("sandbox", {})
        return {"framework": framework, "bind": gateway.get("bind"),
                "auth_enabled": gateway.get("auth", {}).get("mode") == "token",
                "tool_names": tools.get("allow", []),
                "allow_elevated": tools.get("elevated", {}).get("enabled") is not False,
                "allow_direct_network": False,
                "isolated_execution": sandbox.get("mode") == "all" and sandbox.get("backend") == "yuanxingmu",
                "per_user_sessions": True, "credentials_host_only": True,
                "skills_pinned": "skills_snapshot" in manifest and value.get("skills") == {"allowBundled": [], "load": {"extraDirs": [], "watch": False}}}
    from .hermes import foundation_config as hermes_foundation
    return hermes_foundation(profile, manifest)
