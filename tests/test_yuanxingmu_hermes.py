"""Hermes profile security contracts; fake assets are not native UI evidence."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from yuanxingmu import hermes, openclaw
from yuanxingmu.broker import Broker
from yuanxingmu.run import load_policy


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux Hermes profile only")
class HermesProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yxm-hermes-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.profile = self.root / "profile"
        self.source = self.root / "source"
        self.venv = self.root / "venv"
        self.python = self.venv / "bin" / "python"
        self.node = self.root / "node" / "bin" / "node"
        self.bwrap = self.root / "bwrap" / "bin" / "bwrap"
        for path in (self.python, self.node, self.bwrap):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("#!/bin/sh\nexit 64\n")
            path.chmod(0o755)
        (self.venv / "pyvenv.cfg").write_text("home = /usr/bin\n")
        for name in ("hermes_cli/__init__.py", "hermes_cli/main.py", "hermes_cli/web_server.py", "hermes_cli/web_dist/index.html",
                     "ui-tui/dist/entry.js", "agent/terminal_env_provider.py", "tools/environments/base.py"):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n")
        (self.source / "hermes_cli" / "__init__.py").write_text('__version__ = "0.21.2"\n')
        self.secret = "model-key-ONLY-FOR-HOST"
        self.options = {"node": self.node, "hermes_python": self.python, "hermes_source": self.source,
                        "bwrap": self.bwrap, "model_url": "http://127.0.0.1:18109/v1", "model_id": "fixture-model",
                        "api_key": self.secret, "port": 18921}

    def initialize(self, **overrides):
        with mock.patch.object(hermes, "sandbox_available", return_value={"available": True, "reason": "test_fixture"}), \
             mock.patch.object(hermes.sys, "executable", str(Path("/usr/bin/python3").resolve())):
            return hermes.init_profile(self.profile, **{**self.options, **overrides})

    def test_profile_is_private_before_reads_and_uses_shared_lifecycle(self):
        result = self.initialize()
        self.assertEqual(result["framework"], "hermes")
        manifest = openclaw.validate_profile(self.profile)
        resources, destinations = load_policy(self.profile / "policy.json")
        with Broker(self.profile / "broker-state", resources, destinations) as broker:
            state = broker.authority.describe(manifest["task_id"])
            self.assertEqual(state["labels"], ["private"])
            before = broker.authority._db.execute("SELECT count(*) FROM authority_tasks").fetchone()[0]
            broker.revoke(manifest["task_id"])
        self.assertFalse(openclaw._task_state(self.profile, manifest)["active"])
        openclaw.validate_profile(self.profile)
        with Broker(self.profile / "broker-state", resources, destinations) as broker:
            self.assertEqual(broker.authority._db.execute("SELECT count(*) FROM authority_tasks").fetchone()[0], before)

    def test_created_settings_baseline_is_host_only_and_hash_bound(self):
        from yuanxingmu.protection import configure_profile
        objective = "PRIVATE-BASELINE-OBJECTIVE"
        self.initialize(model_url="http://127.0.0.1:18181/v1", defense_policy={"objective": objective, "alignment_mode": "observe"})
        manifest = openclaw.validate_profile(self.profile)
        self.assertIn("defense_baseline_v1", manifest["features"])
        self.assertIn("settings_history_v1", manifest["features"])
        baseline = configure_profile(self.profile)["baseline"]
        self.assertEqual(baseline["settings"]["alignment_mode"], "observe")
        path = self.profile / "defense-baseline.json"
        self.assertEqual(baseline["sha256"], manifest["files"][path.name])
        self.assertEqual(path.stat().st_mode & 0o077, 0)
        self.assertNotIn(objective, path.read_text())
        self.assertNotIn(self.secret, path.read_text())
        command = openclaw.gateway_command(self.profile, manifest)
        self.assertNotIn(str(path), command)

    def test_new_defense_profile_pins_input_containment_on_reopen(self):
        from yuanxingmu.protection import profile_services
        self.initialize(defense_policy={"objective": "Summarize the supplied records", "alignment_enabled": False})
        manifest = openclaw.validate_profile(self.profile)
        self.assertIn("input_containment_v1", manifest["features"])
        resources, destinations = load_policy(self.profile / "policy.json")
        with Broker(self.profile / "broker-state", resources, destinations, **profile_services(self.profile, manifest)) as broker:
            self.assertTrue(broker.input_containment)
            self.assertEqual(broker._binding()["input_containment"], 1)
        changed = {**manifest, "features": [name for name in manifest["features"] if name != "input_containment_v1"]}
        with self.assertRaisesRegex(RuntimeError, "state_policy_or_resource_changed"):
            Broker(self.profile / "broker-state", resources, destinations, **profile_services(self.profile, changed))

    def test_credentials_and_inherited_overrides_do_not_enter_hermes(self):
        self.initialize()
        manifest = openclaw.validate_profile(self.profile)
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": self.secret, "HTTP_PROXY": "http://untrusted.invalid:1",
                                         "HERMES_HOME": "/another-profile", "HERMES_SERVE_HEADLESS": "1"}):
            env = openclaw._environment(self.profile, manifest)
        self.assertNotIn(self.secret, json.dumps(env))
        self.assertNotIn("HTTP_PROXY", env)
        self.assertNotIn("HERMES_SERVE_HEADLESS", env)
        self.assertEqual(env["HERMES_HOME"], str(self.profile / "hermes-home"))
        self.assertEqual(env["HERMES_DASHBOARD_SESSION_TOKEN"], (self.profile / "gateway-token").read_text())
        config = json.loads((self.profile / "hermes-config.yaml").read_text())
        self.assertEqual(config["model"]["base_url"], "http://127.0.0.1:18701/v1")
        self.assertEqual(config["model"]["api_mode"], "chat_completions")
        self.assertEqual(config["fallback_providers"], [])
        self.assertNotIn(self.secret, json.dumps(config))
        self.assertEqual(config["terminal"]["backend"], "yuanxingmu")

    def test_automatic_scope_is_host_only_pinned_and_requires_both_features(self):
        from yuanxingmu.protection import profile_services
        scope = {"version": 1, "max_attempts": 8, "max_total_body_bytes": 65536,
                 "targets": {"team": {"accepted_labels": ["private"], "max_body_bytes": 8192}}}
        targets = {"team": {"kind": "message", "label": "内部团队", "url": "http://127.0.0.1:18337/team"}}
        with self.assertRaisesRegex(ValueError, "automatic_actions_require_defense"):
            self.initialize(action_automation=scope, reviewed_actions=True, action_targets=targets)
        self.assertFalse(self.profile.exists())
        self.initialize(action_automation=scope, reviewed_actions=True, action_targets=targets,
                        defense_policy={"objective": "Send progress to the authorized internal team."})
        manifest = openclaw.validate_profile(self.profile)
        self.assertIn("automatic_actions_v1", manifest["features"])
        self.assertIn("trusted-core/yuanxingmu/action_automation.py", manifest["files"])
        self.assertIn("action-automation.json", manifest["files"])
        binding = json.loads((self.profile / "hermes-binding.json").read_text())
        self.assertTrue(binding["automatic_actions"])
        self.assertEqual((self.profile / "action-automation.json").stat().st_mode & 0o077, 0)
        self.assertNotIn(str(self.profile / "action-automation.json"), hermes.gateway_command(self.profile, manifest))
        resources, destinations = load_policy(self.profile / "policy.json")
        with Broker(self.profile / "broker-state", resources, destinations, **profile_services(self.profile, manifest)) as broker:
            self.assertEqual(broker.automation.describe(manifest["task_id"])["attempts_remaining"], 8)
        (self.profile / "action-automation.json").write_text(json.dumps({**scope, "max_attempts": 100}))
        with self.assertRaisesRegex(RuntimeError, "changed"):
            profile_services(self.profile, manifest)

    def test_independent_judge_requires_defense_and_keeps_credential_host_only(self):
        judge = {"url": "http://127.0.0.1:18333/v1", "id": "fixture-judge", "api_key": "synthetic-judge-host-only-key"}
        with self.assertRaisesRegex(ValueError, "independent_judge_requires_layered_defense"):
            self.initialize(judge_config=judge)
        self.assertFalse(self.profile.exists())
        self.initialize(defense_policy={"objective": "Summarize local synthetic notes."}, judge_config=judge)
        manifest = openclaw.validate_profile(self.profile)
        self.assertIn("independent_judge_v1", manifest["features"])
        self.assertTrue({"judge-config.json", "judge-key"} <= set(manifest["files"]))
        from yuanxingmu.protection import load_guards
        guards = load_guards(self.profile, manifest["model"], pins=manifest["files"])
        self.assertEqual(guards.judge.model_id, judge["id"])
        self.assertEqual(guards.judge.api_key, judge["api_key"])
        self.assertNotIn(judge["api_key"], json.dumps(hermes.environment(self.profile, manifest)))
        self.assertNotIn(judge["api_key"], (self.profile / "hermes-config.yaml").read_text())
        self.assertNotIn(str(self.profile / "judge-key"), hermes.gateway_command(self.profile, manifest))
        (self.profile / "judge-key").write_text("changed")
        with self.assertRaisesRegex((ValueError, RuntimeError), "changed"):
            openclaw.validate_profile(self.profile)

    def test_runtime_requires_both_native_frontends_and_exact_supported_version(self):
        asset = self.source / "ui-tui" / "dist" / "entry.js"
        asset.unlink()
        result = hermes.runtime_available(**{k: self.options[k] for k in ("node", "hermes_python", "hermes_source", "bwrap")})
        self.assertFalse(result["available"])
        self.assertIn("ui-tui/dist/entry.js", result["reason"])
        with self.assertRaisesRegex(ValueError, "hermes_runtime_file_missing"):
            self.initialize()
        self.assertFalse(self.profile.exists())
        asset.write_text("fixture\n")
        (self.source / "hermes_cli" / "__init__.py").write_text('__version__ = "0.21.1"\n')
        with self.assertRaisesRegex(ValueError, "Hermes"):
            self.initialize()

    def test_python_keeps_venv_identity_when_binary_is_a_symlink(self):
        self.python.unlink()
        self.python.symlink_to(Path("/usr/bin/python3").resolve())
        self.initialize()
        manifest = openclaw.validate_profile(self.profile)
        self.assertEqual(manifest["hermes_python"], str(self.python))
        self.assertEqual(manifest["hermes_venv"], str(self.venv))

    def test_outer_mounts_exclude_secrets_ledger_and_review_socket(self):
        self.initialize(reviewed_mail=True)
        manifest = openclaw.validate_profile(self.profile)
        argv = openclaw.gateway_command(self.profile, manifest)
        setup = argv[:argv.index("--")]
        mounts = [(item, Path(setup[i + 1]), Path(setup[i + 2])) for i, item in enumerate(setup) if item in ("--bind", "--ro-bind")]
        protected = [self.profile / name for name in ("documents", "model-key", "gateway-token", "broker-state", "profile.json", "policy.json")]
        protected.append(Path(manifest["runtime"]) / "review.sock")
        for target in protected:
            self.assertFalse(any(source == target or source in target.parents for _, source, _ in mounts), str(target))
        self.assertIn("--unshare-net", setup)
        self.assertNotIn("--disable-userns", setup)
        self.assertIn("dashboard", argv)
        self.assertIn("--isolated", argv)
        self.assertIn("--skip-build", argv)
        self.assertNotIn("serve", argv)
        self.assertTrue(any(mode == "--ro-bind" and dest == self.profile / "hermes-home" / "config.yaml" for mode, _, dest in mounts))
        self.assertEqual(hermes.dashboard_url(self.profile, manifest), "http://127.0.0.1:18921/")

    def test_tampered_plugin_or_binding_is_rejected_before_launch(self):
        self.initialize()
        path = self.profile / "plugin" / "__init__.py"
        path.write_text("raise RuntimeError('tampered')\n")
        with self.assertRaisesRegex(RuntimeError, "profile_file_changed"):
            openclaw.validate_profile(self.profile)

    def test_selected_skill_snapshot_is_effective_and_builtin_roots_are_hidden(self):
        selected = self.root / "selected-skill"
        selected.mkdir()
        text = "---\nname: selected\ndescription: Synthetic skill\n---\nRead synthetic data.\n"
        (selected / "SKILL.md").write_text(text)
        for name in ("skills", "optional-skills"):
            (self.source / name).mkdir()
        self.initialize(selected_skills={"selected": selected})
        (selected / "SKILL.md").write_text("Changed after profile creation.\n")
        manifest = openclaw.validate_profile(self.profile)
        snapshot = Path(manifest["skills_snapshot"]["tree_path"])
        empty = Path(manifest["skills_empty_snapshot"]["tree_path"])
        self.assertEqual((snapshot / "selected" / "SKILL.md").read_text(), text)
        self.assertEqual(list(empty.iterdir()), [])
        argv = hermes.gateway_command(self.profile, manifest)
        mounts = [(argv[i], argv[i + 1], argv[i + 2]) for i in range(len(argv) - 2) if argv[i] in {"--bind", "--ro-bind"}]
        self.assertIn(("--ro-bind", str(snapshot), str(self.profile / "hermes-home" / "skills")), mounts)
        for name in ("skills", "optional-skills"):
            self.assertIn(("--ro-bind", str(empty), str(self.source / name)), mounts)
        env = hermes.environment(self.profile, manifest)
        self.assertTrue(env["HERMES_BUNDLED_SKILLS"].endswith("/.yuanxingmu-no-bundled"))
        config = json.loads((self.profile / "hermes-config.yaml").read_text())
        self.assertFalse(config["skills"]["project_discovery"])
        self.assertEqual(config["skills"]["external_dirs"], [])
        self.assertTrue(hermes.foundation_config(self.profile, manifest)["skills_pinned"])

    def test_readiness_does_not_disclose_token_to_wrong_instance(self):
        self.initialize()
        manifest = openclaw.validate_profile(self.profile)
        page = b'<script>window.__HERMES_SESSION_TOKEN__ = "some-other-server";</script>'
        with mock.patch.object(hermes, "_http", return_value=(200, page)) as request:
            result = hermes.check_ready(self.profile, manifest)
        self.assertFalse(result["ok"])
        request.assert_called_once_with(18921, "/")

    def test_readiness_rejects_token_only_headless_server_and_ungated_api(self):
        self.initialize()
        manifest = openclaw.validate_profile(self.profile)
        token = (self.profile / "gateway-token").read_text()
        headless = ('<script>window.__HERMES_SESSION_TOKEN__ = ' + json.dumps(token) + ';</script>').encode()
        with mock.patch.object(hermes, "_http", return_value=(200, headless)):
            self.assertEqual(hermes.check_ready(self.profile, manifest)["reason"], "hermes_native_spa_missing")
        native = headless + b'<script type="module" crossorigin src="/assets/index-example.js"></script>'
        with mock.patch.object(hermes, "_http", side_effect=[(200, native), (200, b'{"sessions":[]}'), (200, b'{}')]):
            self.assertEqual(hermes.check_ready(self.profile, manifest)["reason"], "hermes_authentication_not_enforced")
        with mock.patch.object(hermes, "_http", side_effect=[(200, native), (200, b'{"sessions":[]}'), (401, b'{}')]):
            self.assertTrue(hermes.check_ready(self.profile, manifest)["ok"])


if __name__ == "__main__":
    unittest.main()
