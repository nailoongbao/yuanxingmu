"""Host-only construction and evidence for opt-in layered profile defenses."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path


_SETTINGS_INTENTS = {"set", "reset_defaults", "restore_creation"}
_SETTINGS_SOURCES = {"cli", "workbench", "host"}


def save_settings_baseline(profile: Path, policy):
    """Capture only the host-approved switches when an instance is created."""
    from . import openclaw as core
    path = profile / "defense-baseline.json"
    core._save(path, {"version": 2, "settings": policy.settings()})
    return path


def _profile_setting_fields(manifest):
    from .guards import DEFENSE_SETTING_FIELDS, EXTENDED_DEFENSE_SETTING_FIELDS, SKILL_RULE_SETTING_FIELDS
    names = DEFENSE_SETTING_FIELDS
    if "per_layer_settings_v1" not in manifest.get("features", []):
        names = names - EXTENDED_DEFENSE_SETTING_FIELDS
    if "skill_rules_v1" not in manifest.get("features", []):
        names = names - SKILL_RULE_SETTING_FIELDS
    return names


def _public_policy(policy, manifest):
    value = policy.to_dict(include_defaults="per_layer_settings_v1" in manifest.get("features", []))
    if "skill_rules_v1" not in manifest.get("features", []):
        value.pop("skill_rules_enabled", None)
    return value


def settings_baseline(profile: Path, manifest: dict):
    from . import openclaw as core
    from .guards import DEFENSE_SETTING_FIELDS, SKILL_RULE_SETTING_FIELDS, validate_defense_settings
    if "defense_baseline_v1" not in manifest.get("features", []):
        return {"supported": False, "reason": "这份旧工作没有保存创建时设置，不能恢复为未经记录的配置。"}
    path = profile / "defense-baseline.json"
    expected = manifest.get("files", {}).get(path.name)
    if not expected or path.is_symlink() or core._hash(path) != expected:
        raise ValueError("defense_baseline_changed")
    value = json.loads(path.read_text(encoding="utf-8"))
    skill_rules = "skill_rules_v1" in manifest.get("features", [])
    baseline_fields = DEFENSE_SETTING_FIELDS if skill_rules else DEFENSE_SETTING_FIELDS - SKILL_RULE_SETTING_FIELDS
    if (type(value) is not dict or set(value) != {"version", "settings"} or type(value["version"]) is not int
            or value["version"] != (2 if skill_rules else 1) or type(value["settings"]) is not dict
            or set(value["settings"]) != baseline_fields):
        raise ValueError("invalid_defense_baseline")
    validate_defense_settings(value["settings"], skill_rules=skill_rules)
    return {"supported": True, "settings": value["settings"], "sha256": expected}


def settings_diff(before: dict, after: dict):
    from .guards import DEFENSE_SETTING_FIELDS
    return {name: {"before": before[name], "after": after[name]} for name in sorted(DEFENSE_SETTING_FIELDS & before.keys() & after.keys())
            if before[name] != after[name]}


def public_settings_history(evidence: dict):
    """Project safe setting fields, never arbitrary text from the audit file."""
    from .guards import DEFENSE_SETTING_FIELDS, validate_defense_settings
    if (type(evidence) is not dict or type(evidence.get("source")) is not str
            or evidence["source"] not in _SETTINGS_SOURCES or type(evidence.get("intent")) is not str
            or evidence["intent"] not in _SETTINGS_INTENTS or type(evidence.get("changes")) is not dict):
        return None
    changes = {}
    for name, values in evidence["changes"].items():
        if name not in DEFENSE_SETTING_FIELDS or type(values) is not dict or set(values) != {"before", "after"}:
            continue
        try:
            validate_defense_settings({name: values["before"]})
            validate_defense_settings({name: values["after"]})
        except (TypeError, ValueError):
            continue
        changes[name] = {"before": values["before"], "after": values["after"]}
    return {"source": evidence["source"], "intent": evidence["intent"], "changes": changes}


def _settings_intent(profile, manifest, changes, intent, baseline_sha256, expected_policy_sha256):
    from .guards import GuardPolicy
    from .authority import AuthorizationError
    if intent not in _SETTINGS_INTENTS:
        raise ValueError("invalid_settings_intent")
    if expected_policy_sha256 is not None and expected_policy_sha256 != manifest["files"]["defense-policy.json"]:
        raise AuthorizationError("defense_settings_preview_expired")
    if intent == "restore_creation":
        baseline = settings_baseline(profile, manifest)
        if not baseline["supported"]:
            raise AuthorizationError("defense_baseline_unavailable")
        if baseline_sha256 != baseline["sha256"] or changes != baseline["settings"]:
            raise AuthorizationError("defense_baseline_preview_changed")
        if expected_policy_sha256 != manifest["files"]["defense-policy.json"]:
            raise AuthorizationError("defense_settings_preview_expired")
    elif baseline_sha256 is not None:
        raise ValueError("unexpected_settings_preview")
    if intent == "reset_defaults":
        expected = GuardPolicy("Recommended settings").settings()
        expected = {name: value for name, value in expected.items() if name in _profile_setting_fields(manifest)}
        if changes != expected:
            raise AuthorizationError("defense_reset_preview_changed")


def load_guards(profile: Path, model: dict, *, policy_value=None, pins=None, features=None):
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

    return Guards(policy, judge, audit=audit, skill_purpose=features is None or "skill_purpose_v1" in features)


def configure_profile(profile: Path, updates: dict | None = None, *, reset=False, intent="set",
                      baseline_sha256=None, expected_policy_sha256=None, _workbench=False):
    """Host-only settings change through a live broker or a confirmed stop.

    The manifest is committed last. A crash between the three files leaves a
    mismatched profile which cannot start, rather than a silently weaker policy.
    """
    from . import openclaw as core
    from .broker import Broker
    from .guards import GuardPolicy, validate_defense_settings
    from .run import load_policy
    profile = profile.expanduser().absolute()
    manifest = core.validate_profile(profile)
    if "layered_defense_v1" not in manifest.get("features", []):
        raise ValueError("layered_defense_not_enabled")
    if reset:
        if intent != "set":
            raise ValueError("invalid_settings_intent")
        intent = "reset_defaults"
    if intent not in _SETTINGS_INTENTS:
        raise ValueError("invalid_settings_intent")
    if (updates is not None or intent != "set") and not _workbench:
        resolved = profile.resolve(strict=True)
        storage = resolved.parent.parent
        # Workbench pins the manifest in its own catalog. Its authenticated
        # action path updates both records; standalone CLI writes cannot do so.
        # Keep reads available and reject before any profile or Broker write.
        if resolved.parent.name == "profiles" and any(
                (storage / name).exists() or (storage / name).is_symlink()
                for name in ("catalog.json", "manager.lock")):
            raise ValueError("workbench_managed_profile: 请在元星木工作台的防护记录中修改设置；CLI get 仍可查看。")
    extended = "per_layer_settings_v1" in manifest.get("features", [])
    skill_rules = "skill_rules_v1" in manifest.get("features", [])
    if updates is not None:
        validate_defense_settings(updates, extended=extended, skill_rules=skill_rules)
    changes = GuardPolicy("Recommended settings").settings() if reset else updates
    if reset:
        changes = {key: value for key, value in changes.items() if key in _profile_setting_fields(manifest)}
    if intent == "restore_creation" and changes is None:
        baseline = settings_baseline(profile, manifest)
        if not baseline["supported"]:
            raise ValueError("defense_baseline_unavailable")
        changes = baseline["settings"]
    if changes is None and intent != "set":
        raise ValueError("invalid_defense_settings")
    if changes is not None:
        if _workbench and "settings_history_v1" in manifest.get("features", []) and expected_policy_sha256 is None:
            raise ValueError("defense_settings_preview_required")
        _settings_intent(profile, manifest, changes, intent, baseline_sha256, expected_policy_sha256)
    elif baseline_sha256 is not None or expected_policy_sha256 is not None:
        raise ValueError("unexpected_settings_preview")
    source = "workbench" if _workbench else "cli"
    if changes is not None and core._offline_lifecycle(profile) != "stopped" and "live_settings_v1" in manifest.get("features", []):
        metadata = {"source": source, "intent": intent, "baseline_sha256": baseline_sha256,
                    "expected_policy_sha256": expected_policy_sha256}
        payload = {"settings": changes, "metadata": metadata} if "settings_history_v1" in manifest.get("features", []) else {"settings": changes}
        return core.review_profile(profile, "protection_set", payload)
    if changes is None:
        manifest = core.validate_profile(profile)
        if "layered_defense_v1" not in manifest.get("features", []):
            raise ValueError("layered_defense_not_enabled")
        value = json.loads((profile / "defense-policy.json").read_text())
        return {"policy": _public_policy(GuardPolicy.from_dict(value), manifest), "changed": False,
                "per_layer_settings": extended, "skill_rules_settings": skill_rules,
                "skill_purpose": "skill_purpose_v1" in manifest.get("features", []), "baseline": settings_baseline(profile, manifest),
                "policy_sha256": manifest["files"]["defense-policy.json"]}
    with core._profile_lock(profile):
        manifest = core.validate_profile(profile)
        if "layered_defense_v1" not in manifest.get("features", []):
            raise ValueError("layered_defense_not_enabled")
        value = json.loads((profile / "defense-policy.json").read_text())
        if core._offline_lifecycle(profile) != "stopped":
            raise ValueError("profile_must_be_stopped_for_settings")
        validate_defense_settings(changes, extended="per_layer_settings_v1" in manifest.get("features", []),
                                  skill_rules="skill_rules_v1" in manifest.get("features", []))
        GuardPolicy.from_dict({**value, **changes})
        resources, destinations = load_policy(profile / "policy.json")
        with Broker(profile / "broker-state", resources, destinations, **profile_services(profile, manifest)) as broker:
            if not broker.authority.describe(manifest["task_id"])["active"]:
                raise ValueError("task_revoked")
            return apply_profile_settings(profile, manifest, broker, changes, running=False, source=source, intent=intent,
                                          baseline_sha256=baseline_sha256, expected_policy_sha256=expected_policy_sha256)


def apply_profile_settings(profile, manifest, broker, changes, *, running=True, source="host", intent="set",
                           baseline_sha256=None, expected_policy_sha256=None):
    """Called only by the host while holding the broker lock and profile ownership.

    File updates commit before the live guard is exposed. Any partial update
    latches the broker fault and retains its dirty marker for recovery.
    """
    from . import openclaw as core
    from .guards import GuardPolicy, validate_defense_settings
    with broker._lock:
        broker._require_healthy()
        if running:
            core.validate_profile(profile)
        if not broker.authority.describe(manifest["task_id"])["active"]:
            raise ValueError("task_revoked")
        extended = "per_layer_settings_v1" in manifest.get("features", [])
        validate_defense_settings(changes, extended=extended, skill_rules="skill_rules_v1" in manifest.get("features", []))
        if source not in _SETTINGS_SOURCES:
            raise ValueError("invalid_settings_source")
        if source == "workbench" and "settings_history_v1" in manifest.get("features", []) and expected_policy_sha256 is None:
            raise ValueError("defense_settings_preview_required")
        _settings_intent(profile, manifest, changes, intent, baseline_sha256, expected_policy_sha256)
        policy = GuardPolicy.from_dict({**broker.guards.policy.to_dict(), **changes}).to_dict()
        replacement = load_guards(profile, manifest["model"], policy_value=policy, pins=manifest["files"], features=manifest.get("features", []))
        old = broker.guards
        differences = settings_diff(old.policy.settings(), replacement.policy.settings())
        history = {"source": source, "intent": intent, "changes": differences}
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
                                       {**history, "invalidated": invalidated, "revision": revision})
            for name in ("defense-policy.json", "broker-state/bindings.json"):
                manifest["files"][name] = core._hash(profile / name)
            core._save(profile / "profile.json", manifest)
            replacement._audit({"layer": "foundation", "verdict": "review", "code": "operator_settings_changed",
                                "reason": "本人修改了防护设置，后续操作使用新设置；安装与技能检查将在下次启动时重做。" if running else "本人修改了防护设置，下一次启动时会重新检查。",
                                "enforced": False, "assessed": False,
                                "evidence": {**history, "policy_sha256": manifest["files"]["defense-policy.json"], "live": running,
                                             "invalidated": invalidated, "revision": revision}})
        except BaseException:
            broker.guards = old
            broker._fault = True
            raise
        return {"policy": _public_policy(replacement.policy, manifest), "changed": True,
                "per_layer_settings": extended, "skill_rules_settings": "skill_rules_v1" in manifest.get("features", []),
                "skill_purpose": replacement.skill_purpose, "live": running, "task_id": manifest["task_id"], "history": history}


def profile_services(profile: Path, manifest: dict):
    features = manifest.get("features", [])
    options = {"reviewed_mail": "reviewed_email_v1" in features}
    if "layered_defense_v1" in features:
        options["guards"] = load_guards(profile, manifest["model"], pins=manifest["files"], features=features)
        options["input_containment"] = "input_containment_v1" in features
    if "reviewed_actions_v1" in features:
        options["action_targets"] = load_action_targets(profile)
    if "automatic_actions_v1" in features:
        if "layered_defense_v1" not in features or "reviewed_actions_v1" not in features:
            raise ValueError("automatic_actions_require_defense_and_reviewed_actions")
        from .action_automation import AutomaticActionPolicy
        path = profile / "action-automation.json"
        if path.is_symlink():
            raise RuntimeError("profile_automatic_action_scope_changed")
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != manifest["files"].get("action-automation.json"):
            raise RuntimeError("profile_automatic_action_scope_changed")
        options["action_automation"] = AutomaticActionPolicy.from_config(
            json.loads(raw), options["action_targets"]).to_config()
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
