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
        self.root = Path(self.tmp.name).resolve()
        self.source_dir = self.root / "source"
        self.store_root = self.root / "store"
        self.source_dir.mkdir()
        self.store_root.mkdir(mode=0o700)
        self.store_root.chmod(0o700)

    def tearDown(self):
        # Restore permissions for cleanup
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

        # Verify read-only permissions: dir 0500, files 0400
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

        # Extra file in source
        (self.source_dir / "pkg_extra-1.0.0-py3-none-any.whl").write_bytes(b"extra")
        manifest = wheel_store.ExpectedWheelManifest(wheels=(w1, w2))
        with self.assertRaisesRegex(wheel_store.WheelStoreError, "manifest_mismatch"):
            wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root)

        # Missing file in source
        (self.source_dir / "pkg_extra-1.0.0-py3-none-any.whl").unlink()
        (self.source_dir / "pkg_b-1.0.0-py3-none-any.whl").unlink()
        with self.assertRaisesRegex(wheel_store.WheelStoreError, "manifest_mismatch"):
            wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root)

    def test_digest_or_size_mismatch_fails_and_leaves_no_staging(self):
        w1 = self._create_synthetic_wheel("pkg_a-1.0.0-py3-none-any.whl", b"real-content")
        bad_manifest = wheel_store.ExpectedWheelManifest(
            wheels=(wheel_store.ExpectedWheel("pkg_a-1.0.0-py3-none-any.whl", "0" * 64, len(b"real-content")),)
        )
        with self.assertRaisesRegex(wheel_store.WheelStoreError, "digest_mismatch"):
            wheel_store.publish_wheel_store(self.source_dir, bad_manifest, self.store_root)

        # Ensure no staging directory leaked
        subdirs = list(self.store_root.iterdir())
        self.assertEqual(subdirs, [])

    def test_source_or_store_symlink_rejected(self):
        # Symlink in file
        target = self.root / "real_file.whl"
        target.write_bytes(b"content")
        symlink_whl = self.source_dir / "symlink-1.0.0-py3-none-any.whl"
        symlink_whl.symlink_to(target)

        manifest = wheel_store.ExpectedWheelManifest(
            wheels=(wheel_store.ExpectedWheel("symlink-1.0.0-py3-none-any.whl", hashlib.sha256(b"content").hexdigest(), len(b"content")),)
        )
        with self.assertRaisesRegex(wheel_store.WheelStoreError, "unsupported_file"):
            wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root)

        symlink_whl.unlink()

        # Symlink source directory
        source_link = self.root / "source_link"
        source_link.symlink_to(self.source_dir)
        w1 = self._create_synthetic_wheel("ok-1.0.0-py3-none-any.whl", b"ok")
        m_ok = wheel_store.ExpectedWheelManifest(wheels=(w1,))
        with self.assertRaises(wheel_store.WheelStoreError):
            wheel_store.publish_wheel_store(source_link, m_ok, self.store_root)

    def test_source_tampered_during_read_fails_closed(self):
        w1 = self._create_synthetic_wheel("racing-1.0.0-py3-none-any.whl", b"initial-valid-bytes")
        manifest = wheel_store.ExpectedWheelManifest(wheels=(w1,))

        def race_hook(name):
            (self.source_dir / name).write_bytes(b"swapped-during-read-race")

        with self.assertRaisesRegex(wheel_store.WheelStoreError, "source_changed"):
            wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root, sync_hook=race_hook)

    def test_existing_store_reuse_and_tamper_detection(self):
        w1 = self._create_synthetic_wheel("pkg_reuse-1.0.0-py3-none-any.whl", b"immutable-package")
        manifest = wheel_store.ExpectedWheelManifest(wheels=(w1,))

        pub1 = wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root)
        # Publishing again reuses verified store
        pub2 = wheel_store.publish_wheel_store(self.source_dir, manifest, self.store_root)
        self.assertEqual(pub1.manifest_digest, pub2.manifest_digest)

        # Tampering with published store file triggers verification failure
        target_file = pub1.store_path / w1.filename
        target_file.chmod(0o600)
        target_file.write_bytes(b"tampered-in-store")
        target_file.chmod(0o400)
        with self.assertRaisesRegex(wheel_store.WheelStoreError, "file_digest_tampered"):
            wheel_store.verify_wheel_store(pub1.store_path, manifest, pub1.manifest_digest)


if __name__ == "__main__":
    unittest.main()
