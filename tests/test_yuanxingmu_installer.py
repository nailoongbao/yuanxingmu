"""Installer boundaries using private temporary directories and real processes.

Archives, receipts, locks, download caches, and timeout process groups are real.
Download HTTP responses, npm failures, environment checks, and runtime readiness
are substituted where stated. The loopback server tests use the real repository
HTTP server/handler with a synthetic manager. These tests do not install or run
OpenClaw, use sudo, alter the host, or establish that a fresh installation succeeds.
"""
from contextlib import ExitStack
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import warnings
import zipfile

from install.yxm_setup import setup as installer
from install.yxm_setup import launcher


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux installer filesystem and process boundaries")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="yxm-installer-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "installation"
        self.fixture_bwrap = self.write(self.base / "fixture-bwrap", b"synthetic isolation binary; never executed")
        self.system_bwrap = Path("/usr/bin/bwrap")
        self.guards = ExitStack()
        self.addCleanup(self.guards.close)
        # Verify all install-owned files on disk. Only the fixed system-bwrap
        # read is redirected, so these tests neither require nor alter a host
        # package. Keep this shim local to the installer module, not pathlib.
        real_record = installer.record
        self.guards.enter_context(mock.patch.object(
            installer, "Path", side_effect=lambda *parts: self.fixture_bwrap
            if len(parts) == 1 and str(parts[0]) == "/usr/bin/bwrap" else Path(*parts)))
        self.guards.enter_context(mock.patch.object(
            installer, "record", side_effect=lambda path: real_record(
                self.fixture_bwrap if str(path) == "/usr/bin/bwrap" else path)))
        self.guards.enter_context(mock.patch.object(
            installer.urllib.request, "urlopen", side_effect=AssertionError("Real network is forbidden in installer tests")))
        self.real_scoped_apparmor = installer.scoped_apparmor
        for name in ("system_dependencies", "scoped_apparmor"):
            self.guards.enter_context(mock.patch.object(
                installer, name, side_effect=AssertionError("System changes are forbidden in installer tests")))

    def directory(self, name):
        path = self.base / name
        path.mkdir(mode=0o700)
        return path

    def spec(self, content=b"synthetic download", name="fixture.whl"):
        return {"name": name, "url": "https://downloads.invalid/" + name,
                "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}

    def write(self, path, content=b"fixture"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(0o600)
        return path

    def fixture_state(self, *, complete=False, openclaw=True):
        """An owned synthetic receipt, never a real installed runtime."""
        with installer.installation(self.root) as state:
            retained = self.write(self.root / "app/keep.txt", b"installed fixture bytes")
            state["files"] = {"app/keep.txt": installer.record(retained)}
            for name in ("__init__.py", "cli.py", "dashboard/__init__.py", "dashboard/server.py", "dashboard/web/index.html",
                         "dashboard/web/app.js", "dashboard/web/styles.css", "dashboard/web/mark.svg"):
                key = "app/yuanxingmu/" + name
                path = self.write(self.root / key, b"synthetic package resource; never imported")
                state["files"][key] = installer.record(path)
            node_key = "tools/node-v24.16.0-linux-x64/bin/node"
            state["files"][node_key] = installer.record(self.write(self.root / node_key, b"synthetic node; never executed"))
            state["components"] = {"app": "complete", "node": "complete"}
            if openclaw:
                state["components"]["openclaw"] = "complete"
                for name in ("package.json", "openclaw.mjs"):
                    key = "openclaw/node_modules/openclaw/" + name
                    state["files"][key] = installer.record(self.write(self.root / key, b"synthetic OpenClaw; never executed"))
            state["paths"] = {"app": "app", "node": node_key,
                              "openclaw": "openclaw/node_modules/openclaw", "bwrap": str(self.system_bwrap)}
            if complete:
                launcher = self.write(self.root / "open-yuanxingmu", b"synthetic launcher; never executed")
                state["files"]["open-yuanxingmu"] = installer.record(launcher)
                state["files"]["bwrap:/usr/bin/bwrap"] = installer.record(self.system_bwrap)
                state["launcher_sha256"] = hashlib.sha256(launcher.read_bytes()).hexdigest()
            state["status"] = "complete" if complete else "installing"
            installer.save(self.root, state)
        return state, self.system_bwrap

    def state_on_disk(self):
        return json.loads((self.root / installer.MARKER).read_bytes())

    def wheel(self, name, entries):
        archive = self.base / name
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(archive, "w") as stream:
                for path, content in entries:
                    stream.writestr(path, content)
        return archive

    def node_tar(self, name, entries):
        archive = self.base / name
        with tarfile.open(archive, "w:xz") as stream:
            for path, content, kind, link in entries:
                item = tarfile.TarInfo(path)
                item.mode = 0o755 if path.endswith("/node") else 0o644
                item.type = kind
                item.linkname = link
                item.size = len(content) if kind == tarfile.REGTYPE else 0
                stream.addfile(item, io.BytesIO(content) if item.isfile() else None)
        return archive

    def node_tree_archive(self, name):
        """A tiny full-tree tar, with explicit parents as in the official tar."""
        prefix = "node-v24.16.0-linux-x64"
        directories = ("", "/bin", "/lib", "/lib/node_modules", "/lib/node_modules/npm", "/lib/node_modules/npm/bin")
        entries = [(prefix + suffix, b"", tarfile.DIRTYPE, "") for suffix in directories]
        entries.extend([
            (prefix + "/bin/node", b"synthetic node; never executed", tarfile.REGTYPE, ""),
            (prefix + "/lib/node_modules/npm/bin/npm-cli.js", b"synthetic npm; never executed", tarfile.REGTYPE, ""),
            (prefix + "/bin/npm", b"", tarfile.SYMTYPE, "../lib/node_modules/npm/bin/npm-cli.js"),
        ])
        return self.node_tar(name, entries)

    def development_archive(self, name="development.whl", *, metadata_version=None, package_version=None, hermes=True):
        version = metadata_version or installer.RUNTIME
        entries = [
            ("agent_defense_check-" + version + ".dist-info/METADATA",
             "Metadata-Version: 2.4\nName: agent-defense-check\nVersion: " + version + "\n"),
            ("yuanxingmu/__init__.py", '__version__ = "' + (package_version or installer.RUNTIME) + '"\n'),
        ]
        if hermes:
            entries.append(("yuanxingmu/hermes.py", "# synthetic fixture; never imported\n"))
        path = self.wheel(name, entries)
        return path, installer.digest(path)

    def hermes_fixture(self, state):
        """Ordinary files only; no installed third-party code or subprocesses."""
        keys = ("env/bin/python", "env/pyvenv.cfg", "source/pyproject.toml", "source/uv.lock",
                "source/package.json", "source/package-lock.json", "source/hermes_cli/__init__.py",
                "source/hermes_cli/main.py", "source/hermes_cli/web_server.py", "source/hermes_cli/web_dist/index.html",
                "source/ui-tui/dist/entry.js", "source/agent/terminal_env_provider.py", "source/tools/environments/base.py",
                "source/run_agent.py", "env/lib/python3.12/site-packages/fixture.pth",
                "SOURCE.json", "build-constraints.txt", "uv.toml")
        records = {}
        for key in keys:
            path = self.write(self.root / "hermes" / key, b"synthetic Hermes runtime; never executed")
            records["hermes/" + key] = installer.record(path)
        (self.root / "hermes/env/bin/python").chmod(0o700)
        (self.root / "hermes/env/lib64").symlink_to("lib")
        state["features"] = ["hermes"]
        state["components"]["hermes"] = "complete"
        state["files"].update(records)
        state["paths"].update({"hermes_python": "hermes/env/bin/python", "hermes_source": "hermes/source"})
        installer.save(self.root, state)
        return records

    def test_development_wheel_requires_matching_hash_metadata_and_package_version(self):
        valid, digest = self.development_archive()
        result = installer.development_wheel(valid, digest)
        self.assertEqual(result["version"], installer.RUNTIME)
        self.assertEqual(result["sha256"], digest)
        with self.assertRaises(installer.InstallError):
            installer.development_wheel(valid, "0" * 64)
        for path, value in ((valid, None), (None, digest)):
            with self.assertRaises(installer.InstallError):
                installer.development_wheel(path, value)
        for name, kwargs in (("metadata", {"metadata_version": "99.0.0"}),
                             ("package", {"package_version": "99.0.0"}), ("old", {"hermes": False})):
            with self.subTest(name=name):
                path, value = self.development_archive(name + ".whl", **kwargs)
                with self.assertRaises(installer.InstallError):
                    installer.development_wheel(path, value)
        self.assertFalse(self.root.exists())

    def test_development_wheel_rejects_symlink_and_duplicate_metadata(self):
        path, digest = self.development_archive()
        link = self.base / "linked.whl"
        link.symlink_to(path)
        with self.assertRaises(installer.InstallError):
            installer.development_wheel(link, digest)
        name = "agent_defense_check-" + installer.RUNTIME + ".dist-info/METADATA"
        duplicate = self.wheel("duplicate-metadata.whl", [(name, b"a"), (name, b"b")])
        with self.assertRaises(installer.InstallError):
            installer.development_wheel(duplicate, installer.digest(duplicate))

    def test_development_wheel_never_replaces_completed_or_legacy_incomplete_install(self):
        path, digest = self.development_archive()
        for complete in (False, True):
            with self.subTest(complete=complete):
                self.root = self.base / ("existing-" + str(complete))
                self.fixture_state(complete=complete)
                before = (self.root / installer.MARKER).read_bytes()
                with mock.patch.object(installer, "check_environment"), \
                     mock.patch.object(installer, "fetch") as fetch, \
                     mock.patch.object(installer, "verify_runtime") as runtime:
                    with self.assertRaises(installer.InstallError):
                        installer.install(self.root, dev_wheel=path, dev_sha256=digest)
                fetch.assert_not_called()
                runtime.assert_not_called()
                self.assertEqual((self.root / installer.MARKER).read_bytes(), before)
                self.assertEqual((self.root / "app/keep.txt").read_bytes(), b"installed fixture bytes")

    def test_development_retry_requires_original_explicit_input(self):
        path, digest = self.development_archive()
        spec = installer.development_wheel(path, digest)
        with installer.installation(self.root, features=["hermes"], development=spec):
            pass
        before = (self.root / installer.MARKER).read_bytes()
        other, other_digest = self.development_archive("different.whl", package_version=installer.RUNTIME)
        for kwargs in ({}, {"dev_wheel": other, "dev_sha256": other_digest}):
            with mock.patch.object(installer, "check_environment"), mock.patch.object(installer, "fetch") as fetch:
                with self.assertRaises(installer.InstallError):
                    installer.install(self.root, **kwargs)
            fetch.assert_not_called()
            self.assertEqual((self.root / installer.MARKER).read_bytes(), before)

    def test_hermes_inventory_covers_python_environment_source_and_web_assets(self):
        state, _ = self.fixture_state(complete=True)
        records = self.hermes_fixture(state)
        installer.verify_files(self.root, state)
        self.assertIn("hermes/env/lib/python3.12/site-packages/fixture.pth", records)
        for key in ("hermes/source/run_agent.py", "hermes/env/lib/python3.12/site-packages/fixture.pth",
                    "hermes/source/hermes_cli/web_dist/index.html"):
            with self.subTest(key=key):
                original = (self.root / key).read_bytes()
                self.write(self.root / key, b"changed fixture")
                with self.assertRaises(installer.InstallError):
                    installer.verify_files(self.root, state)
                self.write(self.root / key, original)
        self.write(self.root / "hermes/env/lib/python3.12/site-packages/unrecorded.pth", b"unrecorded fixture")
        with self.assertRaises(installer.InstallError):
            installer.verify_files(self.root, state)

    def test_hermes_environment_rejects_changed_lib64_or_external_python_link(self):
        state, _ = self.fixture_state(complete=True)
        self.hermes_fixture(state)
        link = self.root / "hermes/env/lib64"
        link.unlink()
        outside = self.directory("outside-lib")
        sentinel = self.write(outside / "keep", b"untouched")
        link.symlink_to(outside)
        with self.assertRaises(installer.InstallError):
            installer.verify_files(self.root, state)
        self.assertEqual(sentinel.read_bytes(), b"untouched")
        link.unlink()
        link.symlink_to("lib")
        python = self.root / "hermes/env/bin/python"
        original = self.write(self.base / "outside-python", python.read_bytes())
        python.unlink()
        python.symlink_to(original)
        with self.assertRaises(installer.InstallError):
            installer.verify_files(self.root, state)

    def test_hermes_missing_records_or_paths_prevent_completed_install_use(self):
        state, _ = self.fixture_state(complete=True)
        self.hermes_fixture(state)
        for key in ("hermes/SOURCE.json", "hermes/source/ui-tui/dist/entry.js"):
            record = state["files"].pop(key)
            with self.assertRaises(installer.InstallError):
                installer.verify_files(self.root, state)
            state["files"][key] = record
        state["paths"]["hermes_python"] = "/usr/bin/python3"
        with self.assertRaises(installer.InstallError):
            installer.verify_files(self.root, state)

    def test_completed_hermes_install_checks_without_rebuilding(self):
        state, _ = self.fixture_state(complete=True)
        self.hermes_fixture(state)
        document = self.write(self.root / "workbench/keep", b"keep previous work")
        before = (self.root / installer.MARKER).read_bytes()
        with mock.patch.object(installer, "check_environment"), \
             mock.patch.object(installer, "verify_runtime") as runtime, \
             mock.patch.object(installer.hermes_installer, "install") as install_hermes, \
             mock.patch.object(installer, "fetch") as fetch:
            result = installer.install(self.root, shortcut=False)
        self.assertEqual(result, state)
        runtime.assert_called_once_with(self.root, self.fixture_bwrap, hermes=True)
        install_hermes.assert_not_called()
        fetch.assert_not_called()
        self.assertEqual((self.root / installer.MARKER).read_bytes(), before)
        self.assertEqual(document.read_bytes(), b"keep previous work")

    def test_hermes_failure_preserves_openclaw_and_never_marks_complete(self):
        state, bwrap = self.fixture_state()
        state["features"] = ["hermes"]
        installer.save(self.root, state)
        with mock.patch.object(installer, "check_environment"), \
             mock.patch.object(installer, "require_hermes_app"), \
             mock.patch.object(installer, "isolation", return_value=bwrap), \
             mock.patch.object(installer, "fetch", return_value=self.base / "not-used"), \
             mock.patch.object(installer, "verify_node_tree"), \
             mock.patch.object(installer.hermes_installer, "install", side_effect=installer.InstallError("synthetic Hermes failure")), \
             mock.patch.object(installer, "npm_install") as npm, \
             mock.patch.object(installer, "verify_runtime") as runtime:
            with self.assertRaises(installer.InstallError):
                installer.install(self.root, shortcut=False)
        self.assertEqual(self.state_on_disk()["status"], "installing")
        self.assertNotIn("hermes", self.state_on_disk()["components"])
        self.assertEqual(self.state_on_disk()["components"]["openclaw"], "complete")
        self.assertFalse((self.root / "open-yuanxingmu").exists())
        npm.assert_not_called()
        runtime.assert_not_called()

    def test_hermes_build_environment_has_private_home_without_user_keys_or_config(self):
        with installer.installation(self.root):
            pass
        (self.root / "hermes").mkdir(mode=0o700)
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "synthetic-key", "HOME": "/other/home",
                                         "UV_INDEX": "https://untrusted.invalid", "HTTPS_PROXY": "https://proxy.invalid"}, clear=True):
            env = installer.hermes_installer.environment(self.root)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("UV_INDEX", env)
        self.assertEqual(env["HOME"], str(self.root / "hermes/build-home"))
        self.assertEqual(env["UV_PROJECT_ENVIRONMENT"], str(self.root / "hermes/env"))
        self.assertEqual(env["HTTPS_PROXY"], "https://proxy.invalid")
        self.assertEqual((self.root / "hermes/npm-user.conf").read_bytes(), b"")

    def test_hermes_source_rejects_traversal_links_duplicates_before_writing_members(self):
        prefix = "hermes-agent-" + "a" * 40
        outside = self.write(self.base / "outside-source", b"must survive")
        attacks = [(prefix + "/../outside-source", tarfile.REGTYPE, ""),
                   (prefix + "/evil", tarfile.SYMTYPE, str(outside)),
                   (prefix + "/evil", tarfile.LNKTYPE, str(outside)),
                   (prefix + "/evil", tarfile.FIFOTYPE, ""),
                   (prefix + "/would-write", tarfile.REGTYPE, "")]
        for index, (name, kind, link) in enumerate(attacks):
            root = self.directory("source-" + str(index))
            (root / "hermes").mkdir(mode=0o700)
            archive = self.base / ("source-" + str(index) + ".tar.gz")
            with tarfile.open(archive, "w:gz") as stream:
                valid = tarfile.TarInfo(prefix + "/would-write")
                valid.size = 1
                stream.addfile(valid, io.BytesIO(b"x"))
                bad = tarfile.TarInfo(name)
                bad.type, bad.linkname = kind, link
                stream.addfile(bad, io.BytesIO(b"") if bad.isfile() else None)
            with self.assertRaises(installer.InstallError):
                installer.hermes_installer.extract_source(root, archive, {"commit": "a" * 40, "version": "0.21.2"})
            self.assertFalse((root / "hermes/source/would-write").exists())
            self.assertEqual(outside.read_bytes(), b"must survive")

    def test_uv_lock_is_made_private_without_following_a_link(self):
        with installer.installation(self.root):
            pass
        lock = self.write(self.root / "hermes/env/.lock", b"")
        lock.chmod(0o666)  # uv 0.12.13 creates this inside its private venv.
        installer.hermes_installer.secure_uv_lock(self.root)
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
        lock.unlink()
        target = self.write(self.base / "outside-uv-lock", b"unchanged")
        lock.symlink_to(target)
        with self.assertRaises(installer.InstallError):
            installer.hermes_installer.secure_uv_lock(self.root)
        self.assertEqual(target.read_bytes(), b"unchanged")

    def test_launcher_returns_recorded_hermes_paths_after_real_file_verification(self):
        state, _ = self.fixture_state(complete=True)
        self.hermes_fixture(state)
        (self.root / state["paths"]["node"]).chmod(0o700)
        actual_digest = launcher._digest
        with mock.patch.object(launcher, "_bwrap_path", return_value=self.system_bwrap), \
             mock.patch.object(launcher, "_digest", side_effect=lambda path, **kwargs: actual_digest(
                 self.fixture_bwrap if str(path) == "/usr/bin/bwrap" else path)):
            result = launcher._verify_installation(self.root / "open-yuanxingmu")
        self.assertEqual(result[-2:], (self.root / "hermes/env/bin/python", self.root / "hermes/source"))

    def test_new_receipt_and_lock_are_private_and_identity_bound(self):
        with installer.installation(self.root) as state:
            info = self.root.stat()
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o700)
            self.assertEqual(state["root_identity"], [info.st_dev, info.st_ino])
            self.assertEqual(state["status"], "installing")
            self.assertRegex(state["install_id"], "^[0-9a-f]{32}$")
            for name in (installer.MARKER, ".install.lock"):
                self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)
        before = (self.root / installer.MARKER).read_bytes()
        with installer.installation(self.root) as reopened:
            self.assertEqual(reopened, state)
        self.assertEqual((self.root / installer.MARKER).read_bytes(), before)

    def test_existing_unmarked_directory_is_not_adopted(self):
        self.root.mkdir(mode=0o700)
        original = self.write(self.root / "keep.txt", b"operator-owned content")
        with self.assertRaises((installer.InstallError, OSError)):
            with installer.installation(self.root):
                self.fail("an unrelated directory was adopted")
        self.assertEqual(original.read_bytes(), b"operator-owned content")
        self.assertFalse((self.root / installer.MARKER).exists())

    def test_unknown_empty_directory_is_not_given_a_lock_or_receipt(self):
        self.root.mkdir(mode=0o700)
        with self.assertRaises((installer.InstallError, OSError)):
            with installer.installation(self.root):
                self.fail("an unknown empty directory was adopted")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_private_directory_check_rejects_group_access(self):
        self.root.mkdir(mode=0o700)
        self.root.chmod(0o750)
        with self.assertRaises(installer.InstallError):
            installer.private(self.root, directory=True)

    def test_receipt_from_another_directory_is_rejected(self):
        with installer.installation(self.root):
            pass
        other = self.directory("other")
        copied = self.write(other / installer.MARKER, (self.root / installer.MARKER).read_bytes())
        before = copied.read_bytes()
        with self.assertRaises(installer.InstallError):
            with installer.installation(other):
                self.fail("a receipt was rebound to a new directory")
        self.assertEqual(copied.read_bytes(), before)

    def test_real_lock_excludes_another_open_handle(self):
        with installer.installation(self.root):
            before = (self.root / installer.MARKER).read_bytes()
            with self.assertRaises(installer.InstallError):
                with installer.installation(self.root):
                    self.fail("a second installation acquired the same lock")
            self.assertEqual((self.root / installer.MARKER).read_bytes(), before)
        with installer.installation(self.root):
            pass  # Closing the first context actually releases the OS lock.

    def test_lock_symlink_never_changes_its_target(self):
        with installer.installation(self.root):
            pass
        lock = self.root / ".install.lock"
        lock.unlink()
        outside = self.write(self.base / "outside-lock", b"must stay intact")
        lock.symlink_to(outside)
        with self.assertRaises((installer.InstallError, OSError)):
            with installer.installation(self.root):
                self.fail("a lock symlink was accepted")
        self.assertEqual(outside.read_bytes(), b"must stay intact")

    def test_incomplete_workbench_entry_blocks_retry_even_if_link_is_broken(self):
        outside = self.directory("outside-work")
        sentinel = self.write(outside / "authority", b"preserve existing authority")
        for kind in ("directory", "file", "symlink", "broken-symlink"):
            with self.subTest(kind=kind):
                root = self.base / ("retry-" + kind)
                with installer.installation(root):
                    pass
                work = root / "workbench"
                if kind == "directory":
                    work.mkdir(mode=0o700)
                elif kind == "file":
                    self.write(work)
                else:
                    work.symlink_to(outside if kind == "symlink" else self.base / "missing-work")
                before = (root / installer.MARKER).read_bytes()
                with self.assertRaises(installer.InstallError):
                    with installer.installation(root):
                        self.fail("an incomplete install with a workbench entry was retried")
                self.assertEqual((root / installer.MARKER).read_bytes(), before)
                self.assertEqual(sentinel.read_bytes(), b"preserve existing authority")
                self.assertTrue(work.exists() or work.is_symlink())

    def test_complete_install_checks_files_without_overwriting_work(self):
        state, bwrap = self.fixture_state(complete=True)
        document = self.write(self.root / "workbench/private.txt", b"existing work must survive")
        receipt = (self.root / installer.MARKER).read_bytes()
        kept = (self.root / "app/keep.txt").read_bytes()
        with ExitStack() as patches:
            patches.enter_context(mock.patch.object(installer, "check_environment"))
            readiness = patches.enter_context(mock.patch.object(installer, "verify_runtime"))
            forbidden = [patches.enter_context(mock.patch.object(installer, name, side_effect=AssertionError("completed install must not rebuild")))
                         for name in ("fetch", "extract_wheel", "extract_node", "npm_install", "clear_partial", "isolation", "desktop_entry")]
            result = installer.install(self.root, shortcut=False)
        self.assertEqual(result, state)
        readiness.assert_called_once_with(self.root, self.fixture_bwrap)
        for operation in forbidden:
            operation.assert_not_called()
        self.assertEqual((self.root / installer.MARKER).read_bytes(), receipt)
        self.assertEqual((self.root / "app/keep.txt").read_bytes(), kept)
        self.assertEqual(document.read_bytes(), b"existing work must survive")

    def test_modified_complete_install_is_not_repaired(self):
        self.fixture_state(complete=True)
        self.write(self.root / "app/keep.txt", b"operator replacement")
        before = (self.root / installer.MARKER).read_bytes()
        with mock.patch.object(installer, "check_environment"), \
             mock.patch.object(installer, "fetch") as fetch, \
             mock.patch.object(installer, "verify_runtime") as runtime:
            with self.assertRaises(installer.InstallError):
                installer.install(self.root, shortcut=False)
        fetch.assert_not_called()
        runtime.assert_not_called()
        self.assertEqual((self.root / "app/keep.txt").read_bytes(), b"operator replacement")
        self.assertEqual((self.root / installer.MARKER).read_bytes(), before)

    def test_matching_content_via_symlink_is_still_rejected(self):
        state, _ = self.fixture_state(complete=True)
        path = self.root / "app/keep.txt"
        outside = self.write(self.base / "same-content", path.read_bytes())
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(installer.InstallError):
            installer.verify_files(self.root, state)
        self.assertEqual(outside.read_bytes(), b"installed fixture bytes")

    def test_runtime_failure_never_writes_complete_or_launcher(self):
        _, bwrap = self.fixture_state()
        archive = self.base / "synthetic-node-archive-not-read.tar.xz"
        # This test isolates final readiness failure. Full Node-tree verification
        # is exercised separately against real temporary tar files below.
        with mock.patch.object(installer, "check_environment"), \
             mock.patch.object(installer, "isolation", return_value=bwrap), \
             mock.patch.object(installer, "fetch", return_value=archive) as fetch, \
             mock.patch.object(installer, "verify_node_tree") as node_tree, \
             mock.patch.object(installer, "verify_runtime", side_effect=installer.InstallError("synthetic runtime unavailable")) as runtime, \
             mock.patch.object(installer, "npm_install") as npm, \
             mock.patch.object(installer, "desktop_entry") as shortcut:
            with self.assertRaises(installer.InstallError):
                installer.install(self.root)
        self.assertEqual(self.state_on_disk()["status"], "installing")
        self.assertFalse((self.root / "open-yuanxingmu").exists())
        self.assertNotIn("launcher_sha256", self.state_on_disk())
        npm.assert_not_called()
        shortcut.assert_not_called()
        runtime.assert_called_once()
        fetch.assert_called_once()
        node_tree.assert_called_once_with(self.root, archive)

    def test_app_complete_without_file_receipts_is_rejected_before_runtime_import(self):
        with installer.installation(self.root) as state:
            self.write(self.root / "app/yuanxingmu/cli.py", b"raise AssertionError('must not import an unverified app')\n")
            state["components"]["app"] = "complete"
            state["files"] = {}
            installer.save(self.root, state)
        before = (self.root / installer.MARKER).read_bytes()
        with mock.patch.object(installer, "check_environment"), \
             mock.patch.object(installer, "isolation") as isolation, \
             mock.patch.object(installer, "command") as command, \
             mock.patch.object(installer, "verify_runtime") as runtime:
            with self.assertRaises(installer.InstallError):
                installer.install(self.root, shortcut=False)
        isolation.assert_not_called()
        command.assert_not_called()
        runtime.assert_not_called()
        self.assertEqual((self.root / installer.MARKER).read_bytes(), before)

    def test_npm_failure_keeps_completed_components_but_not_install_complete(self):
        _, bwrap = self.fixture_state(openclaw=False)
        archive = self.base / "synthetic-node-archive-not-read.tar.xz"
        # The download, Node check, and npm result are substituted here; only
        # receipt progression and preservation of completed files are asserted.
        with mock.patch.object(installer, "check_environment"), \
             mock.patch.object(installer, "isolation", return_value=bwrap), \
             mock.patch.object(installer, "fetch", return_value=archive) as fetch, \
             mock.patch.object(installer, "verify_node_tree") as node_tree, \
             mock.patch.object(installer, "npm_install", side_effect=installer.InstallError("synthetic npm failure")) as npm, \
             mock.patch.object(installer, "verify_runtime") as runtime:
            with self.assertRaises(installer.InstallError):
                installer.install(self.root, shortcut=False)
        state = self.state_on_disk()
        self.assertEqual(state["status"], "installing")
        self.assertEqual(state["components"], {"app": "complete", "node": "complete"})
        self.assertEqual((self.root / "app/keep.txt").read_bytes(), b"installed fixture bytes")
        runtime.assert_not_called()
        npm.assert_called_once()
        fetch.assert_called_once()
        node_tree.assert_called_once_with(self.root, archive)

    def test_dangling_apparmor_profile_is_rejected_without_writing_system_files(self):
        root = self.directory("apparmor-fixture")
        profile = root / "profile-link"
        missing = root / "missing-system-profile"
        profile.symlink_to(missing)

        class TrustedSystemPath:
            """Only system-path metadata is simulated; no sudo is executed."""
            def __init__(self, text):
                self.text = text

            def __str__(self):
                return self.text

            @property
            def parent(self):
                return TrustedSystemPath(str(Path(self.text).parent))

            def is_symlink(self):
                return False

            def exists(self):
                return True

            def is_dir(self):
                return True

            def stat(self):
                return SimpleNamespace(st_uid=0, st_mode=0o755)

        class SystemProfilePath:
            # The parent metadata is simulated; the leaf is a real dangling
            # symlink. Do not depend on root ownership of temporary directories.
            parent = TrustedSystemPath("/etc/apparmor.d")

            def is_symlink(self):
                return profile.is_symlink()

            def exists(self):
                return profile.exists()

        def mapped_path(value):
            if str(value) == "/etc/apparmor.d/yuanxingmu-bwrap":
                return SystemProfilePath()
            if str(value) in {"/opt/yuanxingmu/bin/bwrap", "/usr/bin/bwrap", "/opt", "/etc"}:
                return TrustedSystemPath(str(value))
            return Path(value)

        with mock.patch.object(installer, "Path", side_effect=mapped_path), \
             mock.patch.object(installer, "digest", return_value="1" * 64), \
             mock.patch.object(installer.subprocess, "run", return_value=SimpleNamespace(returncode=0)), \
             mock.patch.object(installer, "command") as command:
            with self.assertRaisesRegex(installer.InstallError, "AppArmor 链接"):
                self.real_scoped_apparmor(root)
        command.assert_not_called()
        self.assertTrue(profile.is_symlink())
        self.assertFalse(missing.exists())
        self.assertEqual(list(root.iterdir()), [profile])

    def test_cache_download_is_verified_private_and_reused_without_network(self):
        root, cache = self.directory("download-root"), self.directory("cache")
        content = b"a small verified download"
        spec = self.spec(content)
        cached = self.write(cache / spec["name"], content)
        target = installer.fetch(root, spec, cache)
        self.assertEqual(target.read_bytes(), content)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(target.parent.stat().st_mode), 0o700)
        cached.write_bytes(b"changed cache is not needed for a completed download")
        self.assertEqual(installer.fetch(root, spec, cache), target)
        self.assertEqual(target.read_bytes(), content)

    def test_cached_digest_mismatch_removes_partial_and_never_extracts_or_executes(self):
        cache = self.directory("bad-cache")
        content = b"untrusted fixture archive"
        spec = self.spec(content)
        spec["sha256"] = "0" * 64
        self.write(cache / spec["name"], content)
        pins = {"installer_version": installer.VERSION, "runtime_version": installer.RUNTIME, "wheel": spec}
        with mock.patch.object(installer, "check_environment"), \
             mock.patch.object(installer, "bundled", return_value=json.dumps(pins).encode()), \
             mock.patch.object(installer, "command") as command, \
             mock.patch.object(installer, "extract_wheel") as extract, \
             mock.patch.object(installer, "npm_install") as npm:
            with self.assertRaises(installer.InstallError):
                installer.install(self.root, cache=cache, shortcut=False)
        command.assert_not_called()
        extract.assert_not_called()
        npm.assert_not_called()
        self.assertEqual(self.state_on_disk()["status"], "installing")
        self.assertEqual(self.state_on_disk()["components"], {})
        self.assertEqual(list((self.root / "downloads").iterdir()), [])

    def test_http_download_hash_and_size_fail_closed(self):
        for label, body, expected in (("wrong-digest", b"abcd", b"wxyz"), ("too-long", b"abcde", b"abcd"), ("too-short", b"abc", b"abcd")):
            with self.subTest(case=label):
                root = self.directory(label)
                source = io.BytesIO(body)
                with mock.patch.object(installer.urllib.request, "urlopen", return_value=source) as request:
                    with self.assertRaises(installer.InstallError):
                        installer.fetch(root, self.spec(expected), None)
                request.assert_called_once()
                self.assertTrue(source.closed)
                self.assertEqual(list((root / "downloads").iterdir()), [])

    def test_valid_http_response_is_saved_only_after_verification(self):
        root = self.directory("http-download")
        content = b"verified mocked HTTP response"
        with mock.patch.object(installer.urllib.request, "urlopen", return_value=io.BytesIO(content)):
            target = installer.fetch(root, self.spec(content), None)
        self.assertEqual(target.read_bytes(), content)
        self.assertEqual(list((root / "downloads").iterdir()), [target])

    def test_corrupted_previous_download_is_preserved_and_not_replaced(self):
        root, cache = self.directory("old-download"), self.directory("old-cache")
        content = b"correct bytes"
        spec = self.spec(content)
        self.write(cache / spec["name"], content)
        target = installer.fetch(root, spec, cache)
        target.write_bytes(b"wrong!! bytes")
        with self.assertRaises(installer.InstallError):
            installer.fetch(root, spec, cache)
        self.assertEqual(target.read_bytes(), b"wrong!! bytes")

    def test_plain_http_is_rejected_before_network(self):
        root = self.directory("plain-http")
        spec = self.spec()
        spec["url"] = "http://downloads.invalid/fixture.whl"
        with self.assertRaises(installer.InstallError):
            installer.fetch(root, spec, None)
        self.assertEqual(list((root / "downloads").iterdir()), [])

    def test_safe_wheel_files_are_extracted_privately(self):
        root = self.directory("safe-wheel")
        archive = self.wheel("safe.whl", [("yuanxingmu/example.py", b"# synthetic, not executed\n")])
        records = installer.extract_wheel(root, archive)
        target = root / "app/yuanxingmu/example.py"
        self.assertEqual(target.read_bytes(), b"# synthetic, not executed\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(records, {"app/yuanxingmu/example.py": installer.record(target)})

    def test_wheel_path_traversal_does_not_touch_outside_files(self):
        sentinel = self.write(self.base / "escape", b"original outside bytes")
        names = ("../escape", "yuanxingmu/../../escape", "yuanxingmu/./escape", "/escape", "yuanxingmu\\..\\escape", "yuanxingmu/C:/escape")
        for index, name in enumerate(names):
            with self.subTest(member=name):
                root = self.directory("wheel-traversal-" + str(index))
                archive = self.wheel("traversal-" + str(index) + ".whl", [(name, b"replacement")])
                with self.assertRaises(installer.InstallError):
                    installer.extract_wheel(root, archive)
                self.assertEqual(sentinel.read_bytes(), b"original outside bytes")

    def test_wheel_symlink_and_duplicate_members_are_rejected(self):
        link = zipfile.ZipInfo("yuanxingmu/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive = self.wheel("symlink.whl", [(link, b"../../outside")])
        with self.assertRaises(installer.InstallError):
            installer.extract_wheel(self.directory("wheel-link"), archive)
        duplicate = self.wheel("duplicate.whl", [("yuanxingmu/a.py", b"first"), ("yuanxingmu/a.py", b"second")])
        root = self.directory("wheel-duplicate")
        with self.assertRaises(installer.InstallError):
            installer.extract_wheel(root, duplicate)
        self.assertEqual((root / "app/yuanxingmu/a.py").read_bytes(), b"first")

    def test_existing_extraction_directory_symlink_is_not_followed(self):
        outside = self.directory("outside-extraction")
        sentinel = self.write(outside / "keep", b"untouched")
        wheel = self.wheel("outside.whl", [("yuanxingmu/a.py", b"test")])
        node = self.node_tar("outside.tar.xz", [("node-v24.16.0-linux-x64/bin/node", b"not executable", tarfile.REGTYPE, "")])
        for name, archive, extract in (("app", wheel, installer.extract_wheel), ("tools", node, installer.extract_node)):
            with self.subTest(directory=name):
                root = self.directory("existing-" + name)
                (root / name).symlink_to(outside, target_is_directory=True)
                with self.assertRaises(installer.InstallError):
                    extract(root, archive)
                self.assertEqual(sentinel.read_bytes(), b"untouched")
                self.assertEqual(list(outside.iterdir()), [sentinel])

    def test_safe_node_archive_allows_only_internal_symlink(self):
        prefix = "node-v24.16.0-linux-x64/"
        archive = self.node_tar("safe-node.tar.xz", [
            (prefix + "bin/node", b"fixture node: never executed", tarfile.REGTYPE, ""),
            (prefix + "lib/node_modules/npm/bin/npm-cli.js", b"fixture npm: never executed", tarfile.REGTYPE, ""),
            (prefix + "bin/npm", b"", tarfile.SYMTYPE, "../lib/node_modules/npm/bin/npm-cli.js"),
        ])
        root = self.directory("safe-node")
        records = installer.extract_node(root, archive)
        node = root / "tools" / prefix / "bin/node"
        npm = root / "tools" / prefix / "bin/npm"
        self.assertTrue(npm.is_symlink())
        self.assertTrue(npm.resolve().is_relative_to(root / "tools" / prefix))
        self.assertEqual(npm.read_bytes(), b"fixture npm: never executed")
        self.assertEqual(records, {"tools/" + prefix + "bin/node": installer.record(node)})

    def test_node_archive_traversal_external_links_and_special_files_fail_closed(self):
        sentinel = self.write(self.base / "escape", b"outside remains unchanged")
        prefix = "node-v24.16.0-linux-x64/"
        entries = [
            (prefix + "../../escape", b"replacement", tarfile.REGTYPE, ""),
            ("/escape", b"replacement", tarfile.REGTYPE, ""),
            (prefix + "bin/bad", b"", tarfile.SYMTYPE, "../../../escape"),
            (prefix + "bin/bad", b"", tarfile.SYMTYPE, str(sentinel)),
            (prefix + "bin/bad", b"", tarfile.LNKTYPE, "../../escape"),
            (prefix + "bin/bad", b"", tarfile.FIFOTYPE, ""),
            (prefix + "bin/bad", b"", tarfile.CHRTYPE, ""),
        ]
        for index, entry in enumerate(entries):
            with self.subTest(member=index):
                root = self.directory("bad-node-" + str(index))
                archive = self.node_tar("bad-node-" + str(index) + ".tar.xz", [entry])
                with self.assertRaises((installer.InstallError, tarfile.TarError)):
                    installer.extract_node(root, archive)
                self.assertEqual(sentinel.read_bytes(), b"outside remains unchanged")

    def test_full_node_tree_matches_real_archive_without_executing_it(self):
        root = self.directory("verified-node-tree")
        archive = self.node_tree_archive("verified-node-tree.tar.xz")
        installer.extract_node(root, archive)
        installer.verify_node_tree(root, archive)
        npm = root / "tools/node-v24.16.0-linux-x64/bin/npm"
        self.assertTrue(npm.is_symlink())
        self.assertEqual(npm.read_bytes(), b"synthetic npm; never executed")

    def check_resumed_node_tampering(self, *, change):
        _, bwrap = self.fixture_state(openclaw=False)
        archive = self.node_tree_archive("resumed-node.tar.xz")
        npm_root = self.root / "tools/node-v24.16.0-linux-x64"
        script = self.write(npm_root / "lib/node_modules/npm/bin/npm-cli.js", b"synthetic npm; never executed")
        link = npm_root / "bin/npm"
        link.symlink_to("../lib/node_modules/npm/bin/npm-cli.js")
        # Prove the fixture is complete before changing the selected entry.
        installer.verify_node_tree(self.root, archive)
        if change == "link":
            link.unlink()
            link.symlink_to("node")
        else:
            script.write_bytes(b"replaced npm script; must never execute")
        with mock.patch.object(installer, "check_environment"), \
             mock.patch.object(installer, "isolation", return_value=bwrap), \
             mock.patch.object(installer, "fetch", return_value=archive) as fetch, \
             mock.patch.object(installer, "npm_install") as npm, \
             mock.patch.object(installer, "verify_runtime") as runtime, \
             mock.patch.object(installer, "command") as command:
            # fetch/isolation are substitutes. The existing receipt and the full
            # installed Node/npm tree are actually read and verified on disk.
            with self.assertRaisesRegex(installer.InstallError, "发生变化"):
                installer.install(self.root, shortcut=False)
        fetch.assert_called_once()
        npm.assert_not_called()
        runtime.assert_not_called()
        command.assert_not_called()
        self.assertEqual(self.state_on_disk()["status"], "installing")
        self.assertEqual(self.state_on_disk()["components"], {"app": "complete", "node": "complete"})
        self.assertFalse((self.root / "open-yuanxingmu").exists())
        if change == "link":
            self.assertEqual(os.readlink(link), "node")
        else:
            self.assertEqual(script.read_bytes(), b"replaced npm script; must never execute")

    def test_check_environment_accepts_ubuntu_24_04_and_debian_12(self):
        root = self.directory("check-env-ok")
        for distro, version in (("ubuntu", "24.04"), ("debian", "12")):
            with self.subTest(distro=distro, version=version):
                os_release_content = f'ID="{distro}"\nVERSION_ID="{version}"\n'
                with mock.patch("pathlib.Path.read_text", return_value=os_release_content), \
                     mock.patch("sys.platform", "linux"), \
                     mock.patch("platform.machine", return_value="x86_64"), \
                     mock.patch("sys.version_info", (3, 12, 0)), \
                     mock.patch("os.geteuid", return_value=1000), \
                     mock.patch("pathlib.Path.resolve", return_value=root), \
                     mock.patch("pathlib.Path.is_relative_to", side_effect=lambda other: str(other) != "/mnt"), \
                     mock.patch("pathlib.Path.home", return_value=root.parent), \
                     mock.patch("shutil.disk_usage", return_value=mock.Mock(free=10 * 1024 ** 3)):
                    installer.check_environment(root)

    def test_check_environment_rejects_unsupported_distro(self):
        root = self.directory("check-env-fail")
        os_release_content = 'ID="fedora"\nVERSION_ID="40"\n'
        with mock.patch("pathlib.Path.read_text", return_value=os_release_content), \
             mock.patch("sys.platform", "linux"), \
             mock.patch("platform.machine", return_value="x86_64"), \
             mock.patch("sys.version_info", (3, 12, 0)), \
             mock.patch("os.geteuid", return_value=1000), \
             mock.patch("pathlib.Path.resolve", return_value=root), \
             mock.patch("pathlib.Path.is_relative_to", side_effect=lambda other: str(other) != "/mnt"), \
             mock.patch("pathlib.Path.home", return_value=root.parent), \
             mock.patch("shutil.disk_usage", return_value=mock.Mock(free=10 * 1024 ** 3)):
            with self.assertRaisesRegex(installer.InstallError, "当前只验证了 Ubuntu 24.04 与 Debian 12"):
                installer.check_environment(root)

    def test_resumed_install_rejects_changed_npm_symlink_before_execution(self):
        self.check_resumed_node_tampering(change="link")

    def test_resumed_install_rejects_changed_npm_script_before_execution(self):
        self.check_resumed_node_tampering(change="script")

    def test_node_tree_missing_and_unrecorded_files_are_rejected(self):
        for change in ("missing", "extra"):
            with self.subTest(change=change):
                root = self.directory("node-tree-" + change)
                archive = self.node_tree_archive("node-tree-" + change + ".tar.xz")
                installer.extract_node(root, archive)
                installer.verify_node_tree(root, archive)
                if change == "missing":
                    (root / "tools/node-v24.16.0-linux-x64/lib/node_modules/npm/bin/npm-cli.js").unlink()
                else:
                    self.write(root / "tools/unrecorded-file", b"unrecorded fixture")
                with self.assertRaises(installer.InstallError):
                    installer.verify_node_tree(root, archive)

    def exchange_http(self, server, request):
        server.timeout = 3
        worker = threading.Thread(target=server.handle_request, daemon=True)
        worker.start()
        try:
            with socket.create_connection(server.server_address, timeout=3) as client:
                client.sendall(request)
                response = b""
                # Read through the server's FIN before closing the client, so
                # the server endpoint is the active closer and gets TIME_WAIT.
                while chunk := client.recv(65536):
                    response += chunk
            return response
        finally:
            worker.join(timeout=4)
            self.assertFalse(worker.is_alive(), "the local HTTP accept worker must stop")

    def test_launcher_server_factory_rejects_live_port_and_keeps_handler_checks(self):
        from yuanxingmu.dashboard.server import Handler, Server

        manager = SimpleNamespace(port=0, token="synthetic-test-token-never-authorized")
        with launcher._make_server(manager) as server:
            self.assertIsInstance(server, Server)
            self.assertIs(server.RequestHandlerClass, Handler)
            self.assertEqual(server.server_address, ("127.0.0.1", manager.port))
            port = manager.port
            with self.assertRaises(OSError) as caught:
                launcher._check_port(port)
            self.assertEqual(caught.exception.errno, errno.EADDRINUSE)
            with self.assertRaises(OSError) as caught:
                launcher._make_server(SimpleNamespace(port=port))
            self.assertEqual(caught.exception.errno, errno.EADDRINUSE)
            rejected_host = self.exchange_http(server, b"GET / HTTP/1.1\r\nHost: outside.invalid\r\n\r\n")
            self.assertIn(b"HTTP/1.1 403 Forbidden\r\n", rejected_host)
            self.assertIn(b'"invalid_host"', rejected_host)
            no_credential = self.exchange_http(server, (
                f"GET /api/info HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n").encode())
            self.assertIn(b"HTTP/1.1 401 Unauthorized\r\n", no_credential)
            self.assertIn(b'"unauthorized"', no_credential)

    def test_launcher_server_factory_reopens_after_real_closed_http(self):
        from yuanxingmu.dashboard.server import Handler, Server

        # Server and Handler are the actual runtime classes. Only the manager is
        # synthetic; no Runtime checks, workbench directories or OpenClaw run.
        manager = SimpleNamespace(port=0)
        with launcher._make_server(manager) as server:
            port = manager.port
            request = f"GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode()
            response = self.exchange_http(server, request)
            self.assertIn(b"HTTP/1.1 200 OK\r\n", response)
            self.assertIn(b"Connection: close\r\n", response)
        # The v0.4 base Server explicitly disables address reuse. Demonstrate its
        # actual failure during TIME_WAIT, rather than only checking a raw bind.
        self.assertIs(Server.allow_reuse_address, False)
        with self.assertRaises(OSError) as caught:
            Server(SimpleNamespace(port=port))
        self.assertEqual(caught.exception.errno, errno.EADDRINUSE)
        launcher._check_port(port)
        with launcher._make_server(SimpleNamespace(port=port)) as reopened:
            self.assertIsInstance(reopened, Server)
            self.assertIs(reopened.RequestHandlerClass, Handler)
            self.assertEqual(reopened.server_address, ("127.0.0.1", port))
            self.assertEqual(reopened.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR), 1)
            response = self.exchange_http(reopened, request)
            self.assertIn(b"HTTP/1.1 200 OK\r\n", response)

    def test_nonzero_real_command_retains_private_log(self):
        root = self.directory("failed-command")
        with self.assertRaises(installer.InstallError):
            installer.command(root, "synthetic-command", [sys.executable, "-I", "-c", "print('synthetic failure'); raise SystemExit(7)"], timeout=5)
        logs = list((root / "install-logs").iterdir())
        self.assertEqual(len(logs), 1)
        self.assertIn(b"synthetic failure", logs[0].read_bytes())
        self.assertEqual(stat.S_IMODE(logs[0].stat().st_mode), 0o600)

    @staticmethod
    def process_alive(info):
        try:
            fields = Path(f"/proc/{info['pid']}/stat").read_text().rsplit(")", 1)[1].split()
        except FileNotFoundError:
            return False
        return fields[19] == info["start_ticks"] and fields[0] != "Z"

    def test_timeout_kills_same_group_child_even_after_parent_exits_on_term(self):
        root = self.directory("timeout-command")
        receipt = root / "child.json"
        child = (
            "import json,os,signal,time;from pathlib import Path;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "ticks=Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19];"
            f"Path({str(receipt)!r}).write_text(json.dumps({{'pid':os.getpid(),'pgrp':os.getpgrp(),'start_ticks':ticks}}));"
            "time.sleep(120)"
        )
        parent = "import subprocess,sys,time;subprocess.Popen([sys.executable,'-I','-c'," + repr(child) + "]);time.sleep(120)"
        info = None
        try:
            with self.assertRaises(subprocess.TimeoutExpired):
                installer.command(root, "timeout-fixture", [sys.executable, "-I", "-c", parent], timeout=1.5)
            self.assertTrue(receipt.is_file(), "the local child must reach its ready receipt before the timeout")
            info = json.loads(receipt.read_bytes())
            self.assertNotEqual(info["pgrp"], os.getpgrp())
            deadline = time.monotonic() + 2
            while self.process_alive(info) and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertFalse(self.process_alive(info), "command returned while its SIGTERM-ignoring child remained alive")
        finally:
            # A failing regression must never leave the test's own child running.
            if info is None and receipt.is_file():
                info = json.loads(receipt.read_bytes())
            if info and self.process_alive(info) and info["pgrp"] != os.getpgrp():
                try:
                    if os.getpgid(info["pid"]) == info["pgrp"]:
                        os.killpg(info["pgrp"], signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == "__main__":
    unittest.main()
