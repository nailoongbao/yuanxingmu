"""Real Linux filesystem tests for selection, publication and mount boundaries.

These cases do not run an Agent or a model and do not rate skill detection.
They exercise actual links, FIFOs, concurrent source changes, tampered snapshots
and (where bubblewrap is available) a read-only mount as the same host user.
"""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from yuanxingmu.skills import (SkillsSnapshotError, SnapshotLimits,
                              create_snapshot, verify_snapshot)


class SnapshotConfigurationTests(unittest.TestCase):
    def test_limits_reject_unbounded_and_noninteger_values(self):
        for changes in ({"max_files": 0}, {"max_files": True}, {"max_depth": 100},
                        {"max_total_bytes": 10**12}, {"max_file_bytes": 1.5},
                        {"max_entries": -1}):
            with self.subTest(changes=changes), self.assertRaises(SkillsSnapshotError):
                SnapshotLimits(**changes)

    def test_unsupported_platform_never_creates_a_fallback(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch("yuanxingmu.skills.sys.platform", "win32"):
            path = Path(temp) / "store"
            with self.assertRaisesRegex(SkillsSnapshotError, "unsupported_platform"):
                create_snapshot(path, {})
            with self.assertRaisesRegex(SkillsSnapshotError, "unsupported_platform"):
                verify_snapshot(path, "a" * 64)
            self.assertFalse(path.exists())


@unittest.skipUnless(sys.platform.startswith("linux"), "secure snapshots require Linux file descriptors")
class SkillSnapshotFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="yxm-skill-test-")
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        self.store = self.root / "store"
        (self.source / "SKILL.md").write_text("# Selected skill\nRead the selected local text.\n", encoding="utf-8")

    def tearDown(self):
        # Host-owned readonly trees require host chmod before ordinary cleanup.
        for directory, dirs, files in os.walk(self.root, topdown=True, followlinks=False):
            os.chmod(directory, 0o700)
            for name in dirs:
                path = Path(directory) / name
                if not path.is_symlink():
                    os.chmod(path, 0o700)
            for name in files:
                path = Path(directory) / name
                if not path.is_symlink():
                    os.chmod(path, 0o600)
        self.temp.cleanup()

    def capture(self, **kwargs):
        return create_snapshot(self.store, {"chosen": self.source}, **kwargs)

    def assert_rejected(self, code, action):
        with self.assertRaises(SkillsSnapshotError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_default_empty_library_has_no_implicit_source(self):
        value = create_snapshot(self.store, {})
        self.assertEqual(value.file_count, 0)
        self.assertEqual(value.total_bytes, 0)
        self.assertEqual(value.scan_paths, ())
        self.assertEqual(list(value.tree_path.iterdir()), [])
        self.assertEqual(value.source_paths, {})
        self.assertEqual(verify_snapshot(value.path, value.digest).to_dict(), value.to_dict())
        self.assertEqual(stat.S_IMODE(value.tree_path.stat().st_mode), 0o555)

    def test_exact_content_origins_paths_and_executable_modes_are_bound(self):
        scripts = self.source / "scripts"
        scripts.mkdir()
        script = scripts / "read.sh"
        script.write_bytes(b"#!/bin/sh\nprintf 'hello'\n")
        script.chmod(0o700)
        (self.source / "empty").mkdir()
        value = self.capture()
        self.assertEqual(value.path.name, value.digest)
        self.assertEqual(hashlib.sha256((value.path / "manifest.json").read_bytes()).hexdigest(), value.digest)
        self.assertEqual(value.scan_paths, (value.tree_path / "chosen",))
        self.assertEqual(value.source_paths, {"chosen": str(self.source)})
        self.assertEqual(value.file_count, 2)
        self.assertEqual(value.total_bytes, len(script.read_bytes()) + len((self.source / "SKILL.md").read_bytes()))
        self.assertEqual(stat.S_IMODE((value.tree_path / "chosen/SKILL.md").stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE((value.tree_path / "chosen/scripts/read.sh").stat().st_mode), 0o555)
        self.assertTrue((value.tree_path / "chosen/empty").is_dir())
        self.assertEqual(self.capture().digest, value.digest)
        self.assertFalse(any(p.name.startswith(".stage-") for p in self.store.iterdir()))

    def test_source_changes_do_not_modify_published_snapshot(self):
        first = self.capture()
        (self.source / "SKILL.md").write_text("Changed selected skill.\n", encoding="utf-8")
        second = self.capture()
        self.assertNotEqual(first.digest, second.digest)
        self.assertIn("Read the selected", (first.tree_path / "chosen/SKILL.md").read_text())
        self.assertEqual(verify_snapshot(first.path, first.digest).digest, first.digest)

    def test_foundation_scanner_reads_snapshot_paths_after_original_changes(self):
        from yuanxingmu.guards import GuardPolicy, Guards
        value = self.capture()
        (self.source / "SKILL.md").write_text("Different mutable content.\n", encoding="utf-8")
        scanned = Guards(GuardPolicy("Read selected text"))._skill_snapshots(value.scan_paths)
        self.assertEqual(len(scanned), 1)
        self.assertIn("Read the selected", scanned[0][1])
        self.assertNotIn("Different mutable", scanned[0][1])
        self.assertIn(str(value.tree_path), json.dumps(scanned[0][0]))

    def test_aliases_and_absolute_paths_reject_traversal(self):
        for alias in ("../escape", "/absolute", "..", "a/b", "a\\b", "a\n"):
            with self.subTest(alias=alias):
                self.assert_rejected("invalid_alias", lambda: create_snapshot(self.store, {alias: self.source}))
        for path in (Path("relative"), self.source / "../source"):
            with self.subTest(path=path):
                self.assert_rejected("invalid_path", lambda: create_snapshot(self.store, {"selected": path}))
        self.assertFalse(self.store.exists())

    def test_source_and_store_must_not_overlap(self):
        self.assert_rejected("overlapping_store", lambda: create_snapshot(self.source / "snapshots", {"x": self.source}))
        self.assert_rejected("overlapping_store", lambda: create_snapshot(self.root, {"x": self.source}))

    def test_source_root_and_ancestor_symlinks_are_not_followed(self):
        link = self.root / "link"
        link.symlink_to(self.source, target_is_directory=True)
        self.assert_rejected("snapshot_io_error", lambda: create_snapshot(self.store, {"x": link}))
        parent = self.root / "parent-link"
        parent.symlink_to(self.root, target_is_directory=True)
        self.assert_rejected("snapshot_io_error", lambda: create_snapshot(self.store, {"x": parent / "source"}))
        self.assertFalse(self.store.exists())

    def test_nested_symlink_and_broken_link_are_rejected(self):
        for target in (self.root / "missing", self.root):
            link = self.source / "linked"
            link.symlink_to(target)
            try:
                self.assert_rejected("unsupported_file", self.capture)
            finally:
                link.unlink()

    def test_hardlinks_are_rejected_without_touching_target(self):
        outside = self.root / "outside.txt"
        outside.write_text("untouched\n")
        os.link(outside, self.source / "linked.txt")
        self.assert_rejected("unsupported_file", self.capture)
        self.assertEqual(outside.read_text(), "untouched\n")
        self.assertFalse(self.store.exists())

    def test_fifo_and_socket_are_rejected_without_blocking(self):
        fifo = self.source / "fifo"
        os.mkfifo(fifo)
        self.assert_rejected("unsupported_file", self.capture)
        fifo.unlink()
        with socket.socket(socket.AF_UNIX) as server:
            server.bind(str(self.source / "socket"))
            self.assert_rejected("unsupported_file", self.capture)

    def test_binary_non_utf8_and_control_content_are_explicit_errors(self):
        target = self.source / "asset.dat"
        for data in (b"\xff\xfe", b"image\x00bytes", b"\x1b[31mhidden"):
            with self.subTest(data=data):
                target.write_bytes(data)
                with self.assertRaises(SkillsSnapshotError) as caught:
                    self.capture()
                self.assertEqual(caught.exception.code, "non_text_skill")
                self.assertIn("chosen/asset.dat", str(caught.exception))
        self.assertFalse(self.store.exists())

    def test_file_total_count_depth_and_entry_limits_fail_without_partial_publish(self):
        base = SnapshotLimits()
        self.assert_rejected("file_too_large", lambda: self.capture(limits=replace(base, max_file_bytes=4)))
        self.assert_rejected("total_too_large", lambda: self.capture(limits=replace(base, max_total_bytes=4)))
        (self.source / "second.txt").write_text("second\n")
        self.assert_rejected("too_many_files", lambda: self.capture(limits=replace(base, max_files=1)))
        self.assert_rejected("too_many_entries", lambda: self.capture(limits=replace(base, max_entries=1)))
        (self.source / "a/b").mkdir(parents=True)
        self.assert_rejected("tree_too_deep", lambda: self.capture(limits=replace(base, max_depth=1)))
        self.assertFalse(self.store.exists())

    def test_unsafe_names_and_privilege_bits_are_rejected(self):
        bad = self.source / "bad\\name"
        bad.write_text("text")
        self.assert_rejected("invalid_entry_name", self.capture)
        bad.unlink()
        (self.source / "SKILL.md").chmod(0o4755)
        self.assert_rejected("special_permissions", self.capture)

    def test_existing_store_permissions_are_not_silently_repaired(self):
        self.store.mkdir(mode=0o755)
        self.assert_rejected("unsafe_store", self.capture)
        self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), 0o755)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_untrusted_writable_store_parent_is_rejected(self):
        shared = self.root / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        self.assert_rejected("unsafe_store_parent", lambda: create_snapshot(shared / "store", {"x": self.source}))
        self.assertFalse((shared / "store").exists())

    def test_store_symlinks_are_rejected_without_writing_outside(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        (outside / "sentinel").write_text("untouched")
        self.store.symlink_to(outside, target_is_directory=True)
        self.assert_rejected("snapshot_io_error", self.capture)
        self.assertEqual(sorted(p.name for p in outside.iterdir()), ["sentinel"])

    def test_source_modified_during_read_is_not_published(self):
        original = os.read
        target = self.source / "SKILL.md"
        identity = (target.stat().st_dev, target.stat().st_ino)
        changed = False
        def mutate(fd, size):
            nonlocal changed
            value = original(fd, size)
            info = os.fstat(fd)
            if not changed and (info.st_dev, info.st_ino) == identity:
                changed = True
                target.write_bytes(b"x" * target.stat().st_size)
            return value
        with mock.patch("yuanxingmu.skills.os.read", side_effect=mutate):
            self.assert_rejected("source_changed", self.capture)
        self.assertTrue(changed)
        self.assertFalse(self.store.exists())

    def test_regular_file_swapped_for_fifo_between_stat_and_open_does_not_hang(self):
        original = os.open
        changed = False
        target = self.source / "SKILL.md"
        def swap(path, flags, *args, **kwargs):
            nonlocal changed
            if not changed and path == "SKILL.md":
                changed = True
                target.unlink()
                os.mkfifo(target)
            return original(path, flags, *args, **kwargs)
        with mock.patch("yuanxingmu.skills.os.open", side_effect=swap):
            self.assert_rejected("unsupported_file", self.capture)
        self.assertTrue(changed)

    def test_verify_detects_changed_content_even_after_readonly_mode_is_restored(self):
        value = self.capture()
        target = value.tree_path / "chosen/SKILL.md"
        target.chmod(0o600)
        target.write_text("modified after scan\n")
        target.chmod(0o444)
        self.assert_rejected("snapshot_changed", lambda: verify_snapshot(value.path, value.digest))

    def test_verify_detects_writable_permissions(self):
        value = self.capture()
        (value.tree_path / "chosen/SKILL.md").chmod(0o644)
        self.assert_rejected("snapshot_permissions_changed", lambda: verify_snapshot(value.path, value.digest))

    def test_verify_detects_extra_and_missing_entries(self):
        value = self.capture()
        chosen = value.tree_path / "chosen"
        chosen.chmod(0o700)
        extra = chosen / "extra.txt"
        extra.write_text("unrecorded")
        extra.chmod(0o444)
        chosen.chmod(0o555)
        self.assert_rejected("snapshot_changed", lambda: verify_snapshot(value.path, value.digest))
        chosen.chmod(0o700)
        extra.unlink()
        (chosen / "SKILL.md").unlink()
        chosen.chmod(0o555)
        self.assert_rejected("snapshot_changed", lambda: verify_snapshot(value.path, value.digest))

    def test_verify_rejects_replaced_file_symlink(self):
        value = self.capture()
        chosen = value.tree_path / "chosen"
        chosen.chmod(0o700)
        (chosen / "SKILL.md").unlink()
        (chosen / "SKILL.md").symlink_to(self.source / "SKILL.md")
        chosen.chmod(0o555)
        self.assert_rejected("unsupported_file", lambda: verify_snapshot(value.path, value.digest))

    def test_verify_requires_the_pinned_manifest_digest(self):
        value = self.capture()
        self.assert_rejected("invalid_digest", lambda: verify_snapshot(value.path, "a" * 64))
        manifest = value.path / "manifest.json"
        manifest.chmod(0o600)
        manifest.write_bytes(manifest.read_bytes().replace(b'"version":1', b'"version":2'))
        manifest.chmod(0o444)
        self.assert_rejected("digest_mismatch", lambda: verify_snapshot(value.path, value.digest))

    def test_existing_invalid_digest_directory_is_never_overwritten(self):
        value = self.capture()
        manifest = value.path / "manifest.json"
        value.path.chmod(0o700)
        manifest.unlink()
        value.path.chmod(0o555)
        self.assert_rejected("snapshot_changed", self.capture)
        self.assertFalse(manifest.exists())
        self.assertFalse(any(p.name.startswith(".stage-") for p in self.store.iterdir()))

    def test_concurrent_identical_creations_publish_one_exact_snapshot(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            values = list(pool.map(lambda _: self.capture(), range(4)))
        self.assertEqual(len({v.digest for v in values}), 1)
        self.assertEqual([p.name for p in self.store.iterdir()], [values[0].digest])
        self.assertEqual(verify_snapshot(values[0].path, values[0].digest).file_count, 1)

    def test_actual_readonly_mount_prevents_same_user_write_and_chmod(self):
        from yuanxingmu.sandbox import build_command, sandbox_available
        availability = sandbox_available()
        if not availability["available"]:
            self.skipTest(str(availability["reason"]))
        value = self.capture()
        work = self.root / "workspace"
        work.mkdir()
        target = str(value.tree_path / "chosen/SKILL.md")
        program = ("import errno,json,os,pathlib,sys; p=pathlib.Path(sys.argv[1]); results=[]\n"
                   "for change in [lambda: p.write_text('changed'),lambda: p.chmod(0o600)]:\n"
                   " try: change(); results.append('changed')\n"
                   " except OSError as e: results.append(e.errno)\n"
                   "print(json.dumps({'results':results,'text':p.read_text()}))")
        with socket.socket(socket.AF_UNIX) as broker:
            broker.bind(str(self.root / "broker.sock"))
            argv = build_command(command=["/usr/bin/python3", "-c", program, target], workspace=work,
                                 broker_socket=self.root / "broker.sock", readonly_paths=[value.tree_path])
            result = subprocess.run(argv, capture_output=True, text=True, timeout=15,
                                    close_fds=True, start_new_session=True, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["results"], [30, 30])  # EROFS, including chmod by the same UID.
        self.assertIn("Read the selected", output["text"])
        self.assertEqual(verify_snapshot(value.path, value.digest).file_count, 1)


if __name__ == "__main__":
    unittest.main()
