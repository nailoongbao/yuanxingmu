"""Synthetic artifact and filesystem regressions; no package installation or network."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from yuanxingmu import wheel_store as ws


class WheelManifestValidationTests(unittest.TestCase):
    def test_limits_and_sizes_require_integers_not_bool_or_float(self):
        for field in ("max_wheels", "max_wheel_bytes", "max_total_bytes"):
            for value in (True, 1.0, "1", 0, -1):
                with self.subTest(field=field, value=value), self.assertRaises(ws.WheelStoreError):
                    ws.WheelLimits(**{field: value})
        for value in (True, 1.0, "1", 0, -1):
            with self.subTest(size=value), self.assertRaises(ws.WheelStoreError):
                ws.ExpectedWheel("demo-1.0-py3-none-any.whl", "a" * 64, value)

    def test_manifest_requires_immutable_typed_entries_and_limits(self):
        wheel = ws.ExpectedWheel("demo-1.0-py3-none-any.whl", "a" * 64, 1)
        for changes in ({"wheels": [wheel]}, {"wheels": (object(),)}, {"wheels": None},
                        {"limits": {}}, {"limits": None}, {"manifest_version": 1.0}):
            with self.subTest(changes=changes), self.assertRaises(ws.WheelStoreError):
                ws.ExpectedWheelManifest(**changes)

    def test_real_wheel_filename_forms_and_ambiguous_names(self):
        for name in ("some_pkg-1.2.3-py2.py3-none-any.whl",
                     "demo-1.2.3+cpu-cp312-cp312-manylinux_2_17_x86_64.whl",
                     "demo-1.2.3-2-cp312-cp312-win_amd64.whl"):
            with self.subTest(name=name):
                self.assertEqual(ws.ExpectedWheel(name, "a" * 64, 1).filename, name)
        for name in ("../demo-1.0-py3-none-any.whl", "dir/demo-1.0-py3-none-any.whl",
                     "dir\\demo-1.0-py3-none-any.whl", "x" * 256 + "-1-py3-none-any.whl"):
            with self.subTest(name=name), self.assertRaises(ws.WheelStoreError):
                ws.ExpectedWheel(name, "a" * 64, 1)
        wheel = ws.ExpectedWheel("Demo-1.0-py3-none-any.whl", "a" * 64, 1)
        duplicate = ws.ExpectedWheel("demo-1.0-py3-none-any.whl", "a" * 64, 1)
        with self.assertRaises(ws.WheelStoreError):
            ws.ExpectedWheelManifest(wheels=(wheel, duplicate))

    @unittest.skipIf(sys.platform.startswith("linux"), "Checks the unsupported-platform contract")
    def test_both_public_filesystem_operations_fail_explicitly_off_linux(self):
        manifest = ws.ExpectedWheelManifest()
        with self.assertRaises(ws.WheelStoreError):
            ws.publish_wheel_store("unused-source", manifest, "unused-store")
        with self.assertRaises(ws.WheelStoreError):
            ws.verify_wheel_store("unused-store", manifest)


@unittest.skipUnless(sys.platform.startswith("linux"), "Requires native Linux descriptors and permissions")
class WheelStoreFilesystemSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.store = self.root / "store"
        self.source.mkdir()
        self.store.mkdir(mode=0o700)
        self.content = b"Synthetic binary artifact\x00\xff; not an installable wheel."
        self.name = "demo-1.0-py3-none-any.whl"
        (self.source / self.name).write_bytes(self.content)
        self.wheel = ws.ExpectedWheel(self.name, hashlib.sha256(self.content).hexdigest(), len(self.content))
        self.manifest = ws.ExpectedWheelManifest(wheels=(self.wheel,))

    def tearDown(self):
        # Only owned temporary fixtures; never follow test symlinks while chmodding.
        for directory, dirs, files in os.walk(self.root, followlinks=False):
            os.chmod(directory, 0o700)
            for name in (*dirs, *files):
                path = Path(directory) / name
                if not path.is_symlink():
                    os.chmod(path, 0o700 if path.is_dir() else 0o600)
        self.temporary.cleanup()

    def publish(self, **options):
        return ws.publish_wheel_store(self.source, self.manifest, self.store, **options)

    def replace_store_file(self, published, name, content):
        path = published.store_path / name
        os.chmod(published.store_path, 0o700)
        path.unlink()
        path.write_bytes(content)
        os.chmod(path, 0o400)
        os.chmod(published.store_path, 0o500)

    def prospective_target(self):
        primer = self.root / "primer"
        primer.mkdir(mode=0o700)
        published = ws.publish_wheel_store(self.source, self.manifest, primer)
        return self.store / published.manifest_digest

    def test_source_directory_symlink_is_not_resolved_then_accepted(self):
        alias = self.root / "source-link"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(ws.WheelStoreError):
            ws.publish_wheel_store(alias, self.manifest, self.store)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_store_symlink_and_existing_unsafe_permissions_are_not_repaired(self):
        original_mode = 0o755
        os.chmod(self.store, original_mode)
        alias = self.root / "store-link"
        alias.symlink_to(self.store, target_is_directory=True)
        for target in (alias, self.store):
            with self.subTest(target=target), self.assertRaises(ws.WheelStoreError):
                ws.publish_wheel_store(self.source, self.manifest, target)
            self.assertEqual(stat.S_IMODE(self.store.stat().st_mode), original_mode)
            self.assertEqual(list(self.store.iterdir()), [])

    def test_symlinked_ancestors_and_shared_writable_store_parent_are_rejected(self):
        alias = self.root / "parent-link"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ws.WheelStoreError):
            ws.publish_wheel_store(alias / "source", self.manifest, self.store)
        with self.assertRaises(ws.WheelStoreError):
            ws.publish_wheel_store(self.source, self.manifest, alias / "store")
        shared = self.root / "shared"
        shared.mkdir()
        os.chmod(shared, 0o777)
        with self.assertRaises(ws.WheelStoreError):
            ws.publish_wheel_store(self.source, self.manifest, shared / "new-store")
        self.assertEqual(list(shared.iterdir()), [])

    def test_source_and_store_overlap_is_rejected_before_mutation(self):
        mode = stat.S_IMODE(self.source.stat().st_mode)
        for destination in (self.source, self.source / "nested-store"):
            with self.subTest(destination=destination), self.assertRaises(ws.WheelStoreError):
                ws.publish_wheel_store(self.source, self.manifest, destination)
        self.assertEqual(stat.S_IMODE(self.source.stat().st_mode), mode)
        self.assertEqual(sorted(p.name for p in self.source.iterdir()), [self.name])

    def test_new_source_entry_during_copy_rejects_and_cleans_staging(self):
        def change(_):
            (self.source / "unexpected.txt").write_bytes(b"extra")
        with self.assertRaises(ws.WheelStoreError):
            self.publish(sync_hook=change)
        self.assertEqual(list(self.store.iterdir()), [])

    def test_source_hardlink_is_rejected(self):
        os.link(self.source / self.name, self.root / "source-alias")
        with self.assertRaises(ws.WheelStoreError):
            self.publish()
        self.assertEqual(list(self.store.iterdir()), [])

    def test_empty_target_appearing_during_copy_is_never_overwritten(self):
        target = self.prospective_target()
        created = []
        def reserve(_):
            target.mkdir(mode=0o500)
            created.append(target.stat().st_ino)
        with self.assertRaises(ws.WheelStoreError):
            self.publish(sync_hook=reserve)
        self.assertEqual(target.stat().st_ino, created[0])
        self.assertEqual(list(target.iterdir()), [])
        self.assertEqual(list(self.store.iterdir()), [target])

    def test_publish_failure_after_sealing_cleans_staging_and_preserves_conflict(self):
        target = self.prospective_target()
        def reserve(_):
            target.write_bytes(b"existing reservation")
        with self.assertRaises(ws.WheelStoreError):
            self.publish(sync_hook=reserve)
        self.assertEqual(target.read_bytes(), b"existing reservation")
        self.assertEqual(list(self.store.iterdir()), [target])

    def test_partial_writes_publish_complete_artifacts_and_manifest(self):
        original = os.write
        def short_write(fd, data):
            return original(fd, data[:max(1, len(data) // 2)])
        with mock.patch.object(ws.os, "write", side_effect=short_write):
            published = self.publish()
        verified = ws.verify_wheel_store(published.store_path, self.manifest, published.manifest_digest)
        self.assertEqual(verified.total_bytes, len(self.content))
        self.assertEqual((published.store_path / self.name).read_bytes(), self.content)
        self.assertEqual(hashlib.sha256((published.store_path / "manifest.json").read_bytes()).hexdigest(),
                         published.manifest_digest)

    def test_manifest_is_fully_bound_even_when_digest_argument_is_omitted(self):
        published = self.publish()
        self.replace_store_file(published, "manifest.json", b"not the expected manifest\n")
        with self.assertRaises(ws.WheelStoreError):
            ws.verify_wheel_store(published.store_path, self.manifest)

    def test_complete_manifest_larger_than_one_read_round_trips(self):
        (self.source / self.name).unlink()
        wheels = []
        for number in range(500):
            name = f"demo_{number:04d}-1.0-py3-none-any.whl"
            (self.source / name).write_bytes(b"x")
            wheels.append(ws.ExpectedWheel(name, hashlib.sha256(b"x").hexdigest(), 1))
        expected = ws.ExpectedWheelManifest(wheels=tuple(wheels), limits=ws.WheelLimits(max_wheels=512))
        published = ws.publish_wheel_store(self.source, expected, self.store)
        self.assertGreater((published.store_path / "manifest.json").stat().st_size, 65536)
        verified = ws.verify_wheel_store(published.store_path, expected, published.manifest_digest)
        self.assertEqual((verified.file_count, verified.total_bytes), (500, 500))

    def test_republishing_preserves_existing_snapshot_and_removes_staging(self):
        first = self.publish()
        directory_inode = first.store_path.stat().st_ino
        file_inode = (first.store_path / self.name).stat().st_ino
        second = self.publish()
        self.assertEqual(second, first)
        self.assertEqual(first.store_path.stat().st_ino, directory_inode)
        self.assertEqual((first.store_path / self.name).stat().st_ino, file_inode)
        self.assertEqual(list(self.store.iterdir()), [first.store_path])

    def test_manifest_trailing_bytes_are_not_ignored(self):
        published = self.publish()
        raw = (published.store_path / "manifest.json").read_bytes()
        self.replace_store_file(published, "manifest.json", raw + b" " * 70000)
        with self.assertRaises(ws.WheelStoreError):
            ws.verify_wheel_store(published.store_path, self.manifest)

    def test_manifest_hardlinks_and_wrong_digest_or_directory_name_are_rejected(self):
        published = self.publish()
        with self.assertRaises(ws.WheelStoreError):
            ws.verify_wheel_store(published.store_path, self.manifest, "0" * 64)
        os.link(published.store_path / "manifest.json", self.root / "manifest-alias")
        with self.assertRaises(ws.WheelStoreError):
            ws.verify_wheel_store(published.store_path, self.manifest)
        (self.root / "manifest-alias").unlink()
        renamed = published.store_path.with_name("0" * 64)
        published.store_path.rename(renamed)
        with self.assertRaises(ws.WheelStoreError):
            ws.verify_wheel_store(renamed, self.manifest)

    def test_verify_rejects_store_symlink(self):
        published = self.publish()
        alias = self.root / "verified-link"
        alias.symlink_to(published.store_path, target_is_directory=True)
        with self.assertRaises(ws.WheelStoreError):
            ws.verify_wheel_store(alias, self.manifest, published.manifest_digest)

    def assert_fifo_rejected_without_blocking(self, name):
        published = self.publish()
        os.chmod(published.store_path, 0o700)
        (published.store_path / name).unlink()
        os.mkfifo(published.store_path / name, mode=0o400)
        os.chmod(published.store_path, 0o500)
        program = """
import json, sys
sys.path.insert(0, sys.argv[1])
from yuanxingmu import wheel_store as ws
w = ws.ExpectedWheel(**json.loads(sys.argv[3]))
try:
    ws.verify_wheel_store(sys.argv[2], ws.ExpectedWheelManifest(wheels=(w,)))
except ws.WheelStoreError:
    print('rejected')
else:
    raise AssertionError('FIFO was accepted')
"""
        result = subprocess.run(
            [sys.executable, "-I", "-c", program, str(Path(ws.__file__).resolve().parents[1]),
             str(published.store_path), json.dumps({"filename": self.name, "sha256": self.wheel.sha256,
                                                   "size_bytes": self.wheel.size_bytes})],
            cwd=self.root, env={"PATH": os.defpath, "HOME": str(self.root), "LANG": "C.UTF-8"},
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5, check=True)
        self.assertEqual(result.stdout.strip(), "rejected")

    def test_manifest_fifo_fails_without_waiting_for_a_writer(self):
        self.assert_fifo_rejected_without_blocking("manifest.json")

    def test_wheel_fifo_fails_without_waiting_for_a_writer(self):
        self.assert_fifo_rejected_without_blocking(self.name)

    def test_verify_detects_path_replacement_after_reading_pinned_inode(self):
        published = self.publish()
        inode = (published.store_path / self.name).stat().st_ino
        original = os.read
        replaced = []
        def racing_read(fd, count):
            data = original(fd, count)
            if data and os.fstat(fd).st_ino == inode and not replaced:
                replaced.append(True)
                self.replace_store_file(published, self.name, b"X" * len(self.content))
            return data
        with mock.patch.object(ws.os, "read", side_effect=racing_read):
            with self.assertRaises(ws.WheelStoreError):
                ws.verify_wheel_store(published.store_path, self.manifest)
        self.assertTrue(replaced)

    def test_verify_stops_reading_a_continuously_growing_wheel(self):
        published = self.publish()
        path = published.store_path / self.name
        inode = path.stat().st_ino
        original = os.read
        reads = []
        def growing_read(fd, count):
            data = original(fd, count)
            if os.fstat(fd).st_ino == inode:
                reads.append(count)
                if len(reads) > 4:
                    raise AssertionError("Verifier read a growing artifact beyond its declared size")
                os.chmod(path, 0o600)
                with path.open("ab") as stream:
                    stream.write(self.content)
                os.chmod(path, 0o400)
            return data
        with mock.patch.object(ws.os, "read", side_effect=growing_read):
            with self.assertRaises(ws.WheelStoreError):
                ws.verify_wheel_store(published.store_path, self.manifest)
        self.assertLessEqual(len(reads), 4)


if __name__ == "__main__":
    unittest.main()
