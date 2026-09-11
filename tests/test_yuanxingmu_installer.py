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
