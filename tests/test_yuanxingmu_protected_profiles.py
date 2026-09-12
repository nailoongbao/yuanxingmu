"""Real Linux profile files/DBs with fake runtime assets, without model calls.

These reuse the native-profile initialization fixtures. Inspecting a generated
mount command is not evidence of executing Hermes, OpenClaw, or a real model.
"""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest

from tests import test_yuanxingmu_hermes as hermes_fixtures
from tests import test_yuanxingmu_openclaw as openclaw_fixtures
from yuanxingmu import openclaw
from yuanxingmu.broker import Broker
from yuanxingmu.protected_data import HostProtectedData, HostResource, MAX_PRIVATE_BYTES
from yuanxingmu.protection import configure_profile, profile_services
from yuanxingmu.run import load_policy


_FRAMEWORKS = ("hermes", "openclaw")
_TEXT = "客户公开报价：198000元。\n内部底价为162000元，不能展示。\n"


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


@unittest.skipUnless(sys.platform.startswith("linux"), "real Linux profiles only")
class ProtectedProfileTests(unittest.TestCase):
    def fixture(self, framework, *, text=_TEXT, **overrides):
        cls = (hermes_fixtures.HermesProfileTests if framework == "hermes"
               else openclaw_fixtures.OpenClawProfileTests)
        fixture = cls()
        self.addCleanup(fixture.doCleanups)
        fixture.setUp()
        # Hermes' fixture.source is a runtime DIRECTORY, not an imported file.
        fixture.protected_source = fixture.root / "protected-source.txt"
        fixture.protected_source.write_text(text, encoding="utf-8")
        options = {"documents": {"quote": fixture.protected_source}, "destinations": {}}
        options.update(overrides)
        result = fixture.initialize(**options)
        manifest = openclaw.validate_profile(fixture.profile)
        return fixture, manifest, result

    @staticmethod
    def open_broker(fixture):
        manifest = openclaw.validate_profile(fixture.profile)
        resources, destinations = load_policy(fixture.profile / "policy.json")
        return Broker(fixture.profile / "broker-state", resources, destinations,
                      **profile_services(fixture.profile, manifest))

    @staticmethod
    def write_manifest(fixture, manifest):
        (fixture.profile / "profile.json").write_text(
            json.dumps(manifest, ensure_ascii=False), encoding="utf-8")

    def repin(self, fixture, manifest, name):
        manifest["files"][name] = _sha((fixture.profile / name).read_bytes())
        self.write_manifest(fixture, manifest)

    def assert_refused(self, fixture, code=None):
        with self.assertRaises((RuntimeError, ValueError, OSError)) as caught:
            with self.open_broker(fixture):
                self.fail("a changed protected profile was reopened")
        if code is not None:
            self.assertIn(code, str(caught.exception))
        self.assertNotIn("162000", str(caught.exception))
        self.assertNotIn("162000", repr(caught.exception))

    def test_creation_is_private_pinned_and_independent_of_semantic_guards(self):
        for framework in _FRAMEWORKS:
            with self.subTest(framework=framework):
                fixture, manifest, result = self.fixture(framework)
                path = fixture.profile / "protected-data.json"
                info, raw = path.lstat(), path.read_bytes()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(0o600, stat.S_IMODE(info.st_mode))
                self.assertEqual(os.getuid(), info.st_uid)
                self.assertEqual(1, info.st_nlink)
                self.assertIn("protected_fields_v1", manifest["features"])
                self.assertIn("quarantine_v1", manifest["features"])
                self.assertIn("buffered_response_v1", manifest["features"])
                self.assertNotIn("layered_defense_v1", manifest["features"])
                self.assertEqual(_sha(raw), manifest["files"][path.name])
                self.assertIn(b"162000", raw)  # Private storage is not encryption.
                with self.open_broker(fixture) as broker:
                    self.assertIsNone(broker.guards)
                    self.assertIsNotNone(broker.quarantine)
                    summary = broker.protected_data.public_summary()
                    self.assertEqual(1, summary["resource_count"])
                    self.assertEqual(1, summary["field_count"])
                    self.assertEqual(_sha(raw), broker._binding()["protected_data"])
                    public = json.dumps(result) + json.dumps(summary) + repr(broker.protected_data)
                    self.assertNotIn("162000", public)
                    self.assertNotIn(fixture.secret, public)
                    self.assertNotIn(_sha(raw), public)

    def test_gateway_mount_sources_and_targets_exclude_private_sources_and_protection(self):
        for framework in _FRAMEWORKS:
            with self.subTest(framework=framework):
                fixture, manifest, _ = self.fixture(framework)
                openclaw_fixtures.OpenClawProfileTests.runtime_sockets(fixture, manifest)
                argv = openclaw.gateway_command(fixture.profile, manifest)
                setup = argv[:argv.index("--")]
                mounts = [(Path(setup[i + 1]), Path(setup[i + 2]))
                          for i, flag in enumerate(setup) if flag in {"--bind", "--ro-bind"}]
                self.assertTrue(mounts)
                self.assertIn("--unshare-net", setup)
                for name in ("protected-data.json", "documents", "broker-state", "policy.json", "profile.json"):
                    protected = fixture.profile / name
                    for source, target in mounts:
                        self.assertFalse(source == protected or source in protected.parents,
                                         f"host mount exposes {name}")
                        self.assertFalse(target == protected or target in protected.parents,
                                         f"agent mount exposes {name}")
                self.assertNotIn(str(fixture.profile / "protected-data.json"), argv)

    def test_masked_reads_child_tasks_and_workspace_survive_reopening(self):
        for framework in _FRAMEWORKS:
            with self.subTest(framework=framework):
                fixture, manifest, _ = self.fixture(framework)
                task = manifest["task_id"]
                workspace_file = fixture.profile / "workspace" / "public-draft.txt"
                with self.open_broker(fixture) as broker:
                    read = broker.dispatch(task, {"op": "read", "resource": "quote"})
                    self.assertTrue(read["allowed"], read)
                    self.assertIn("198000元", read["content"])
                    self.assertNotIn("162000", read["content"])
                    self.assertIn("[PROTECTED:", read["content"])
                    child = broker.delegate(task)
                    child_read = broker.dispatch(child, {"op": "read", "resource": "quote"})
                    self.assertTrue(child_read["allowed"], child_read)
                    self.assertEqual(read["content"], child_read["content"])
                    binding = broker.protected_data.binding_digest()
                    workspace_file.write_text("公开报价198000元，待客户核对。\n", encoding="utf-8")
                    workspace_before = workspace_file.read_bytes()
                # The user's original import is outside the frozen profile.
                fixture.protected_source.write_text("原始文件后来发生变化。\n", encoding="utf-8")
                with self.open_broker(fixture) as broker:
                    self.assertEqual(binding, broker.protected_data.binding_digest())
                    self.assertEqual(read["content"], broker.dispatch(task, {"op": "read", "resource": "quote"})["content"])
                    self.assertEqual(read["content"], broker.dispatch(child, {"op": "read", "resource": "quote"})["content"])
                    self.assertFalse(broker.quarantine.status(task)["paused"])
                self.assertEqual(workspace_before, workspace_file.read_bytes())
                self.assertEqual(_TEXT, (fixture.profile / "documents" / "quote.txt").read_text(encoding="utf-8"))

    def test_zero_field_sources_and_empty_profiles_still_have_real_bindings(self):
        public = "公开报价198000元。编号A162000，日期2026-09-12，路径/orders/162000。\n"
        for framework in _FRAMEWORKS:
            for empty in (False, True):
                with self.subTest(framework=framework, empty=empty):
                    overrides = {"documents": {}} if empty else {}
                    fixture, manifest, _ = self.fixture(framework, text=public, **overrides)
                    with self.open_broker(fixture) as broker:
                        summary = broker.protected_data.public_summary()
                        self.assertEqual(0, summary["field_count"])
                        self.assertEqual(0 if empty else 1, summary["resource_count"])
                        binding = broker.protected_data.binding_digest()
                        self.assertTrue(broker.dispatch(manifest["task_id"], {"op": "describe"})["allowed"])
                        if not empty:
                            read = broker.dispatch(manifest["task_id"], {"op": "read", "resource": "quote"})
                            self.assertTrue(read["allowed"], read)
                            self.assertEqual(public, read["content"])
                    with self.open_broker(fixture) as broker:
                        self.assertEqual(binding, broker.protected_data.binding_digest())

    def test_removing_feature_file_or_pin_never_disables_a_created_protection_set(self):
        for framework in _FRAMEWORKS:
            for change in ("feature", "file", "pin", "feature_file_and_pin"):
                with self.subTest(framework=framework, change=change):
                    fixture, manifest, _ = self.fixture(framework)
                    if change in {"feature", "feature_file_and_pin"}:
                        manifest["features"].remove("protected_fields_v1")
                    if change in {"pin", "feature_file_and_pin"}:
                        manifest["files"].pop("protected-data.json")
                    if change in {"file", "feature_file_and_pin"}:
                        (fixture.profile / "protected-data.json").unlink()
                    self.write_manifest(fixture, manifest)
                    self.assert_refused(fixture)

    def test_changed_private_file_and_symlink_are_rejected(self):
        for framework in _FRAMEWORKS:
            for change in ("bytes", "symlink"):
                with self.subTest(framework=framework, change=change):
                    fixture, _, _ = self.fixture(framework)
                    path = fixture.profile / "protected-data.json"
                    if change == "bytes":
                        path.write_bytes(path.read_bytes() + b" ")
                    else:
                        copy = fixture.root / "private-copy.json"
                        copy.write_bytes(path.read_bytes())
                        copy.chmod(0o600)
                        path.unlink()
                        path.symlink_to(copy)
                    self.assert_refused(fixture)

    def test_repinned_field_or_mask_edits_still_fail_recompilation(self):
        for framework in _FRAMEWORKS:
            for change in ("field_value", "field_span", "masked_text", "source_sha256"):
                with self.subTest(framework=framework, change=change):
                    fixture, manifest, _ = self.fixture(framework)
                    path = fixture.profile / "protected-data.json"
                    private = json.loads(path.read_bytes())
                    resource = private["resources"][0]
                    if change == "field_value":
                        resource["fields"][0]["value"] = "198000"
                    elif change == "field_span":
                        resource["fields"][0]["source_start"] = 0
                    elif change == "masked_text":
                        resource["masked_text"] = _TEXT
                    else:
                        resource["source_sha256"] = "0" * 64
                    path.write_bytes(json.dumps(private, ensure_ascii=True).encode("utf-8"))
                    self.repin(fixture, manifest, path.name)
                    self.assert_refused(fixture, "protected_data_binding_mismatch")

    def test_private_file_permissions_or_hardlinks_cannot_change_on_reopen(self):
        for framework in _FRAMEWORKS:
            for change in ("world_readable", "hardlink"):
                with self.subTest(framework=framework, change=change):
                    fixture, manifest, _ = self.fixture(framework)
                    path = fixture.profile / "protected-data.json"
                    if change == "world_readable":
                        path.chmod(0o644)
                    else:
                        os.link(path, fixture.root / "unbound-private-alias.json")
                    # Content-only pins still pass: the loader must check the
                    # file descriptor's ownership, permissions, and link count.
                    self.assertEqual(manifest["files"][path.name], _sha(path.read_bytes()))
                    self.assert_refused(fixture, "profile_protected_data_changed")

    def test_profile_validation_rejects_fifo_and_oversized_file_before_hashing(self):
        probe = (
            "import sys\nfrom pathlib import Path\n"
            "from yuanxingmu.openclaw import validate_profile\n"
            "try:\n    validate_profile(Path(sys.argv[1]))\n"
            "except (RuntimeError, ValueError) as error:\n"
            "    if str(error) == 'profile_protected_data_changed':\n        sys.exit(0)\n"
            "    raise\n"
            "raise AssertionError('changed private file accepted')\n"
        )
        for framework in _FRAMEWORKS:
            for change in ("fifo", "oversized_sparse_file"):
                with self.subTest(framework=framework, change=change):
                    fixture, _, _ = self.fixture(framework)
                    path = fixture.profile / "protected-data.json"
                    if change == "fifo":
                        path.unlink()
                        os.mkfifo(path, mode=0o600)
                    else:
                        with path.open("r+b") as stream:
                            stream.truncate(MAX_PRIVATE_BYTES + 1)
                    # A separate real Python process gives a regression in
                    # nonblocking reads a deadline; no fake runtime is launched.
                    result = subprocess.run([sys.executable, "-B", "-c", probe, str(fixture.profile)],
                        cwd=Path(__file__).resolve().parents[1], capture_output=True, text=True, timeout=3)
                    self.assertEqual(0, result.returncode, result.stderr)

    def test_turning_off_semantic_layers_preserves_bound_data_checks(self):
        for framework in _FRAMEWORKS:
            with self.subTest(framework=framework):
                fixture, manifest, _ = self.fixture(framework,
                    defense_policy={"objective": "使用公开报价完成工作。", "mode": "observe"})
                path = fixture.profile / "protected-data.json"
                before = path.read_bytes()
                binding = json.loads((fixture.profile / "broker-state" / "bindings.json").read_bytes())["protected_data"]
                changed = configure_profile(fixture.profile, {
                    layer + "_enabled": False for layer in ("input", "memory", "command", "alignment", "foundation")})
                self.assertTrue(changed["changed"])
                updated = openclaw.validate_profile(fixture.profile)
                self.assertIn("protected_fields_v1", updated["features"])
                self.assertEqual(manifest["files"][path.name], updated["files"][path.name])
                self.assertEqual(before, path.read_bytes())
                with self.open_broker(fixture) as broker:
                    self.assertEqual(binding, broker.protected_data.binding_digest())
                    self.assertEqual(binding, broker._binding()["protected_data"])
                    self.assertTrue(all(not getattr(broker.guards.policy, layer + "_enabled")
                                        for layer in ("input", "memory", "command", "alignment", "foundation")))
                    self.assertIsNotNone(broker.guards.check_content)
                    read = broker.dispatch(manifest["task_id"], {"op": "read", "resource": "quote"})
                    self.assertTrue(read["allowed"], read)
                    self.assertIn("198000元", read["content"])
                    self.assertNotIn("162000", read["content"])

    def test_repinned_bound_source_change_is_rejected(self):
        for framework in _FRAMEWORKS:
            with self.subTest(framework=framework):
                fixture, manifest, _ = self.fixture(framework)
                name = "documents/quote.txt"
                (fixture.profile / name).write_text("公开报价197000元。内部底价161000元。\n", encoding="utf-8")
                self.repin(fixture, manifest, name)
                self.assert_refused(fixture, "protected_data_binding_mismatch")

    def test_recompiled_and_repinned_source_cannot_replace_existing_broker_binding(self):
        for framework in _FRAMEWORKS:
            with self.subTest(framework=framework):
                fixture, manifest, _ = self.fixture(framework)
                text = "公开报价197000元。内部底价161000元。\n"
                source_name = "documents/quote.txt"
                (fixture.profile / source_name).write_text(text, encoding="utf-8")
                rebuilt = HostProtectedData.compile({"quote": HostResource(text, _sha(text.encode("utf-8")))})
                (fixture.profile / "protected-data.json").write_bytes(rebuilt.to_private_json())
                self.repin(fixture, manifest, source_name)
                self.repin(fixture, manifest, "protected-data.json")
                self.assert_refused(fixture, "state_policy_or_resource_changed")

    def test_repinned_broker_protection_digest_change_is_rejected(self):
        for framework in _FRAMEWORKS:
            with self.subTest(framework=framework):
                fixture, manifest, _ = self.fixture(framework)
                name = "broker-state/bindings.json"
                path = fixture.profile / name
                binding = json.loads(path.read_bytes())
                binding["protected_data"] = "0" * 64
                path.write_text(json.dumps(binding), encoding="utf-8")
                self.repin(fixture, manifest, name)
                self.assert_refused(fixture, "state_policy_or_resource_changed")

    def test_protected_only_profile_can_inspect_and_resume_its_persisted_pause(self):
        for framework in _FRAMEWORKS:
            with self.subTest(framework=framework):
                fixture, manifest, _ = self.fixture(framework)
                self.assertNotIn("layered_defense_v1", manifest["features"])
                with self.open_broker(fixture) as broker:
                    broker.quarantine.pause(manifest["task_id"], layer="protected_fields",
                        code="synthetic_profile_pause", reason="合成保护测试，请检查后恢复。")
                    live_status = openclaw._operator_protection_status(fixture.profile, manifest, broker)
                    self.assertEqual("available", live_status["state"])
                    self.assertTrue(live_status["paused"])
                    self.assertTrue(live_status["protected_fields_enabled"])
                    self.assertTrue(all(not item["enabled"] for item in live_status["layers"].values()))
                status = openclaw.review_profile(fixture.profile, "quarantine_status")
                self.assertTrue(status["ok"])
                self.assertTrue(status["paused"])
                self.assertTrue(status["can_resume"])
                resumed = openclaw.review_profile(fixture.profile, "quarantine_resume", {
                    "epoch": status["epoch"], "incident_id": status["incident_id"], "confirm": "resume"})
                self.assertTrue(resumed["ok"])
                self.assertFalse(resumed["paused"])
                with self.open_broker(fixture) as broker:
                    read = broker.dispatch(manifest["task_id"], {"op": "read", "resource": "quote"})
                    self.assertTrue(read["allowed"], read)
                    self.assertIn("198000元", read["content"])
                    self.assertNotIn("162000", read["content"])


if __name__ == "__main__":
    unittest.main()
