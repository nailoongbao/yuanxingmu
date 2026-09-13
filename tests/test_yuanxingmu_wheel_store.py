"""Unit tests for host-verified wheel snapshot and atomic publishing."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

from yuanxingmu import wheel_store


@unittest.skipUnless(sys.platform.startswith("linux"), "Wheel store requires Linux file descriptors")
class WheelStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.source_dir = self.root / "source"
        self.store_root = self.root / "store"
        self.source_dir.mkdir()
        self.store_root.mkdir(mode=0o700)

    def tearDown(self):
        # Restore write permissions before cleanup
        for p in self.root.rglob("*"):
            try:
                p.chmod(0o700)
            except Exception:
                pass
        self.tmp.cleanup()

    def _create_synthetic_wheel(self, filename: str, content: bytes) -> wheel_store.ExpectedWheel:
        path = self.source_dir / filename
        path.write_bytes(content)
        return wheel_store.ExpectedWheel(
            filename=filename,
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content)
        )

    def test_publish_and_verify_valid_wheel_store_success(self):
        w1 = self._create_synthetic_wheel("requests-2.31.0-py3-none-any.whl", b"PK synthetic requests wheel content")
        w2 = self._create_synthetic_wheel("urllib3-2.0.7-py3-none-any.whl", b"PK synthetic urllib3 wheel content")
        manifest = wheel_store.ExpectedWheelManifest(wheels=(w1, w2))

        published = wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root)
        self.assertEqual(published.file_count, 2)
        self.assertEqual(published.total_bytes, len(b"PK synthetic requests wheel content") + len(b"PK synthetic urllib3 wheel content"))
        self.assertTrue(published.store_path.is_dir())

        # Verify read-only permissions
        dir_stat = published.store_path.stat()
        self.assertEqual(stat.S_IMODE(dir_stat.st_mode), 0o500)
        for w in (w1, w2):
            f_stat = (published.store_path / w.filename).stat()
            self.assertEqual(stat.S_IMODE(f_stat.st_mode), 0o400)
            self.assertEqual((published.store_path / w.filename).read_bytes(), (self.source_dir / w.filename).read_bytes())

        # Source changes later do not affect published store
        (self.source_dir / w1.filename).write_bytes(b"tampered content")
        verified = wheel_store.verify_wheel_store(published.store_path, manifest, published.manifest_digest)
        self.assertEqual(verified.manifest_digest, published.manifest_digest)

    def test_missing_or_extra_files_rejected(self):
        w1 = self._create_synthetic_wheel("pkg_a-1.0.0-py3-none-any.whl", b"content-a")
        w2 = self._create_synthetic_wheel("pkg_b-1.0.0-py3-none-any.whl", b"content-b")

        # Case 1: Extra file in source
        (self.source_dir / "pkg_extra-1.0.0-py3-none-any.whl").write_bytes(b"extra")
        manifest = wheel_store.ExpectedWheelManifest(wheels=(w1, w2))
        with self.assertRaisesRegex(wheel_store.WheelStoreError, "manifest_mismatch"):
            wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root)

        # Case 2: Missing file in source
        (self.source_dir / "pkg_extra-1.0.0-py3-none-any.whl").unlink()
        (self.source_dir / "pkg_b-1.0.0-py3-none-any.whl").unlink()
        with self.assertRaisesRegex(wheel_store.WheelStoreError, "manifest_mismatch"):
            wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root)

    def test_digest_or_size_mismatch_fails_and_leaves_no_staging(self):
        w1 = self._create_synthetic_wheel("pkg_a-1.0.0-py3-none-any.whl", b"real-content")
        # Tamper manifest sha
        bad_manifest = wheel_store.ExpectedWheelManifest(
            wheels=(wheel_store.ExpectedWheel("pkg_a-1.0.0-py3-none-any.whl", "0" * 64, len(b"real-content")),)
        )
        with self.assertRaisesRegex(wheel_store.WheelStoreError, "digest_mismatch"):
            wheel_store.publish_wheel_store(self.source_dir, bad_manifest, self.store_root)

        # Ensure no staging directory leaked in store_root
        subdirs = list(self.store_root.glob("staging-*"))
        self.assertEqual(subdirs, [])

    def test_symlinks_and_special_files_rejected(self):
        target = self.root / "real_file.whl"
        target.write_bytes(b"content")
        symlink_whl = self.source_dir / "symlink-1.0.0-py3-none-any.whl"
        symlink_whl.symlink_to(target)

        manifest = wheel_store.ExpectedWheelManifest(
            wheels=(wheel_store.ExpectedWheel("symlink-1.0.0-py3-none-any.whl", hashlib.sha256(b"content").hexdigest(), len(b"content")),)
        )
        with self.assertRaisesRegex(wheel_store.WheelStoreError, "unsupported_file"):
            wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root)

    def test_source_tampered_during_read_fails_closed(self):
        w1 = self._create_synthetic_wheel("racing-1.0.0-py3-none-any.whl", b"initial-valid-bytes")
        manifest = wheel_store.ExpectedWheelManifest(wheels=(w1,))

        def race_hook(name):
            # Mutate source file mid-read
            (self.source_dir / name).write_bytes(b"swapped-during-read-race")

        with self.assertRaisesRegex(wheel_store.WheelStoreError, "source_changed"):
            wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root, sync_hook=race_hook)


if __name__ == "__main__":
    unittest.main()
