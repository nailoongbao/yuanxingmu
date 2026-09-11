from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from defensecheck.config import ConfigurationError, Endpoint, gateway_parts, inspect_config, load_config
from defensecheck.plan import prepare_plan
from defensecheck.policy import email_policy, require_template_policy


# Extracted with ast.literal_eval from the independently exercised research probe.
# The fixture's provenance identifies that source and the successful result artifact.
REFERENCE_PATH = Path(__file__).with_name("fixtures") / "invariant-fixed.policy"
REFERENCE_FIXED = REFERENCE_PATH.read_text(encoding="utf-8")


class PolicyTests(unittest.TestCase):
    def test_versioned_python_launchers_keep_their_invoked_path(self):
        for name in ("python", "python3", "python3.12", "python3.13", "python.exe"):
            with self.subTest(name=name):
                command = "/opt/venv/bin/" + name
                args = ["-m", "gateway", "mcp", "--project-name", "demo", "--exec", "/opt/tool"]
                prefix, upstream = gateway_parts({"command": command, "args": args})
                self.assertEqual(prefix, [command, *args[:-1]])
                self.assertEqual(upstream, ["/opt/tool"])

    def test_known_policy_is_preserved_exactly(self):
        provenance = json.loads(REFERENCE_PATH.with_suffix(".provenance.json").read_text(encoding="utf-8"))
        self.assertEqual(hashlib.sha256(REFERENCE_PATH.read_bytes()).hexdigest(), provenance["policy_sha256"])
        self.assertTrue(provenance["matches_validated_result"])
        self.assertEqual(email_policy().encode("utf-8"), REFERENCE_PATH.read_bytes())
        self.assertEqual(require_template_policy(REFERENCE_FIXED.replace("\n", "\r\n")), REFERENCE_FIXED)

    def test_unknown_rule_is_never_silently_discarded(self):
        for text in (
            REFERENCE_FIXED + 'raise "Another rule" if:\n    True\n',
            REFERENCE_FIXED.replace("ourcompany", "anothercompany"),
            "# A comment is outside the exact supported template\n" + REFERENCE_FIXED,
        ):
            with self.subTest(text=text):
                with self.assertRaises(ConfigurationError):
                    require_template_policy(text)

    def test_domain_and_tool_names_cannot_inject_policy(self):
        for domain in ("company.com|.*", "company.com\n", "*.company.com", "a..com"):
            with self.subTest(domain=domain), self.assertRaises(ConfigurationError):
                email_policy(allowed_domain=domain)
        with self.assertRaises(ConfigurationError):
            email_policy(source_tool="get_inbox\nraise")


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "配置 有空格"
        self.root.mkdir()
        self.python = self.root / "python.exe"
        self.python.write_bytes(b"THIS FILE MUST NEVER BE EXECUTED")
        self.cwd = self.root / "原工作目录"
        self.cwd.mkdir()
        self.config_path = self.root / "client.json"
        self.policy_path = self.root / "original.policy"
        self.policy_path.write_bytes(REFERENCE_FIXED.encode("utf-8"))
        self.source = Endpoint("internal", "get_inbox")
        self.sink = Endpoint("mail", "send_email")
        common = {
            "command": str(self.python),
            "env": {"INVARIANT_API_KEY": "private-value-do-not-print"},
            "cwd": str(self.cwd),
        }
        self.config = {"mcpServers": {}}
        for server, module in (("internal", "reader.py"), ("mail", "writer.py")):
            entry = deepcopy(common)
            entry["args"] = [
                "-m", "gateway", "mcp", "--verbose", "--project-name", "existing-project",
                "--exec", str(self.python), module, "--literal-argument", "中文 and spaces",
            ]
            self.config["mcpServers"][server] = entry
        self.save_config()
        self.launcher_bytes = b'raise RuntimeError("Only copy this launcher; never import it during plan")\n'
        self.aggregate_mock = patch("defensecheck.plan._aggregate_bytes", return_value=self.launcher_bytes)
        self.aggregate_mock.start()
        self.addCleanup(self.aggregate_mock.stop)

    def save_config(self):
        self.config_path.write_bytes((json.dumps(self.config, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))

    def plan(self, **overrides):
        options = {
            "config_path": self.config_path, "source": self.source, "sink": self.sink,
            "policy_path": self.policy_path, "allowed_domain": "ourcompany.com",
            "aggregation_python": self.python, "target_project": "candidate-project",
            "output": self.root / "迁移 计划",
        }
        options.update(overrides)
        return prepare_plan(**options)

    def test_aggregation_virtualenv_interpreter_symlink_is_not_replaced_by_system_python(self):
        virtualenv_python = self.root / "venv" / "bin" / "python"
        virtualenv_python.parent.mkdir(parents=True)
        try:
            virtualenv_python.symlink_to(self.python)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("This platform does not permit creating test symlinks: " + str(exc))
        self.assertEqual(virtualenv_python.resolve(), self.python.resolve())
        report = self.plan(aggregation_python=virtualenv_python)
        client = json.loads(Path(report["files"]["client"]).read_text(encoding="utf-8"))
        args = client["mcpServers"]["guarded"]["args"]
        self.assertEqual(args[args.index("--exec") + 1], str(virtualenv_python))

    def test_plan_preserves_inputs_and_independent_upstreams_without_execution(self):
        original = self.config_path.read_bytes()
        original_policy = self.policy_path.read_bytes()
        with patch("subprocess.Popen", side_effect=AssertionError("Must not start a process")), patch(
            "socket.create_connection", side_effect=AssertionError("Must not make a network request")
        ), patch("os.system", side_effect=AssertionError("Must not start a shell")):
            report = self.plan()
        self.assertEqual(self.config_path.read_bytes(), original)
        self.assertEqual(self.policy_path.read_bytes(), original_policy)
        self.assertEqual(report["config_sha256"], hashlib.sha256(original).hexdigest())
        self.assertEqual(report["policy_sha256"], hashlib.sha256(original_policy).hexdigest())
        self.assertEqual(report["security_result"], "not_tested")
        self.assertEqual(report["status"], "candidate_unverified")
        self.assertFalse(report["target_policy_installed"])
        self.assertNotIn("private-value-do-not-print", json.dumps(report))
        files = {name: Path(value) for name, value in report["files"].items()}
        upstreams = json.loads(files["upstreams"].read_text(encoding="utf-8"))["mcpServers"]
        self.assertEqual(set(upstreams), {"internal", "mail"})
        for name, old in self.config["mcpServers"].items():
            split = old["args"].index("--exec")
            self.assertEqual(upstreams[name], {
                "command": old["args"][split + 1],
                "args": old["args"][split + 2:],
                "env": old["env"], "cwd": old["cwd"],
            })
        client = json.loads(files["client"].read_text(encoding="utf-8"))["mcpServers"]
        self.assertEqual(set(client), {"guarded"})
        entry = client["guarded"]
        self.assertEqual(entry["command"], str(self.python))
        self.assertEqual(entry["env"], self.config["mcpServers"]["internal"]["env"])
        self.assertEqual(entry["cwd"], str(self.cwd))
        self.assertEqual(entry["args"][:7], [
            "-m", "gateway", "mcp", "--verbose", "--project-name", "candidate-project", "--exec",
        ])
        # Preserve the supplied invocation path, including Windows short names
        # and virtualenv symlinks, rather than its resolved target.
        self.assertEqual(entry["args"][7:], [
            str(self.python), str(files["aggregator"]), str(files["upstreams"]),
            "--require-tool", "internal_get_inbox", "--require-tool", "mail_send_email",
        ])
        self.assertEqual(files["aggregator"].read_bytes(), self.launcher_bytes)
        self.assertEqual(files["policy"].read_text(encoding="utf-8"), email_policy("internal_get_inbox", "mail_send_email"))
        for artifact, digest_field in (
            ("client", "candidate_config_sha256"),
            ("upstreams", "candidate_upstreams_sha256"),
            ("policy", "candidate_policy_sha256"),
            ("aggregator", "aggregator_sha256"),
        ):
            self.assertEqual(
                report[digest_field], hashlib.sha256(files[artifact].read_bytes()).hexdigest(),
                f"The plan must bind the exact written {artifact} bytes",
            )
        self.assertEqual(json.loads(files["plan"].read_text(encoding="utf-8")), report)

    def test_unknown_policy_refuses_before_creating_output(self):
        self.policy_path.write_text(REFERENCE_FIXED + 'raise "Other guard" if:\n    True\n', encoding="utf-8")
        with self.assertRaises(ConfigurationError):
            self.plan()
        self.assertFalse((self.root / "迁移 计划").exists())

    def test_different_environments_never_merge_credentials(self):
        self.config["mcpServers"]["mail"]["env"]["MAIL_TOKEN"] = "second-private-value"
        self.save_config()
        with self.assertRaisesRegex(ConfigurationError, "environments differ"):
            self.plan()
        observation = inspect_config(self.config_path, self.source, self.sink)
        self.assertEqual(observation["migration"], "manual_review")
        self.assertNotIn("second-private-value", json.dumps(observation))

    def test_duplicate_json_is_rejected(self):
        self.config_path.write_text('{"mcpServers": {}, "mcpServers": {}}', encoding="utf-8")
        with self.assertRaisesRegex(ConfigurationError, "Duplicate JSON"):
            load_config(self.config_path)
        with self.assertRaises(ConfigurationError):
            self.plan()

    def test_namespaced_selected_tool_collision_is_rejected(self):
        entries = list(self.config["mcpServers"].values())
        self.config["mcpServers"] = {"a_b": entries[0], "a": entries[1]}
        self.save_config()
        self.policy_path.write_text(email_policy("c", "b_c"), encoding="utf-8")
        with self.assertRaisesRegex(ConfigurationError, "collide"):
            self.plan(source=Endpoint("a_b", "c"), sink=Endpoint("a", "b_c"))

    def test_existing_output_is_never_overwritten(self):
        output = self.root / "已有 输出"
        output.mkdir()
        sentinel = output / "plan.json"
        sentinel.write_bytes(b"original user content")
        with self.assertRaisesRegex(ConfigurationError, "already exists"):
            self.plan(output=output)
        self.assertEqual(sentinel.read_bytes(), b"original user content")
        self.assertEqual(list(output.iterdir()), [sentinel])

    def test_extra_route_or_unknown_fields_are_not_dropped(self):
        original = deepcopy(self.config)
        variants = []
        extra = deepcopy(original)
        extra["mcpServers"]["alternate"] = deepcopy(extra["mcpServers"]["mail"])
        variants.append(extra)
        extra = deepcopy(original)
        extra["clientPolicy"] = {"requiresApproval": True}
        variants.append(extra)
        extra = deepcopy(original)
        extra["mcpServers"]["mail"]["alwaysAllow"] = ["send_email"]
        variants.append(extra)
        for config in variants:
            with self.subTest(config=config):
                self.config = config
                self.save_config()
                with self.assertRaises(ConfigurationError):
                    self.plan()

    def test_relative_paths_and_dynamic_environment_are_unsupported(self):
        original = deepcopy(self.config)
        for field, value in (("cwd", "."), ("command", "python.exe"), ("cwd", "")):
            with self.subTest(field=field, value=value):
                self.config = deepcopy(original)
                for entry in self.config["mcpServers"].values():
                    entry[field] = value
                self.save_config()
                with self.assertRaises(ConfigurationError):
                    self.plan()
        self.config = deepcopy(original)
        for entry in self.config["mcpServers"].values():
            entry["env"]["DYNAMIC"] = "$" + "{EXTERNAL_TOKEN}"
        self.save_config()
        with self.assertRaisesRegex(ConfigurationError, "Dynamic expansion"):
            self.plan()

    def test_different_gateway_options_are_not_silently_discarded(self):
        self.config["mcpServers"]["mail"]["args"].remove("--verbose")
        self.save_config()
        with self.assertRaisesRegex(ConfigurationError, "options differ"):
            self.plan()

    def test_different_working_directories_are_not_silently_changed(self):
        other = self.root / "other directory"
        other.mkdir()
        self.config["mcpServers"]["mail"]["cwd"] = str(other)
        self.save_config()
        with self.assertRaisesRegex(ConfigurationError, "directories differ"):
            self.plan()


if __name__ == "__main__":
    unittest.main()
