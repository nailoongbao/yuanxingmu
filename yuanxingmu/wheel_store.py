"""Host-verified binary wheel snapshot store.

This module allows a trusted host to verify a directory of binary Python wheels
against a pre-existing, strictly expected manifest, and atomically publish it
into an immutable, read-only content-addressed store directory.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


class WheelStoreError(ValueError):
    """A wheel collection could not be verified or published safely."""

    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _fail(code: str, detail: str):
    raise WheelStoreError(code, detail)


_WHEEL_FILENAME_PATTERN = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9._]*[A-Za-z0-9])?-[A-Za-z0-9.]+"
    r"(?:-[A-Za-z0-9.]+)?-[A-Za-z0-9.]+(?:-[A-Za-z0-9.]+)?-[A-Za-z0-9.]+\.whl$"
)


@dataclass(frozen=True, slots=True)
class WheelLimits:
    max_wheels: int = 64
    max_wheel_bytes: int = 50 * 1024 * 1024  # 50 MB
    max_total_bytes: int = 200 * 1024 * 1024  # 200 MB

    def __post_init__(self):
        if not (1 <= self.max_wheels <= 1024):
            _fail("invalid_limits", "允许的 wheel 数量超出限制范围。")
        if not (1 <= self.max_wheel_bytes <= 500 * 1024 * 1024):
            _fail("invalid_limits", "允许的单文件字节数超出限制范围。")
        if not (1 <= self.max_total_bytes <= 2000 * 1024 * 1024):
            _fail("invalid_limits", "允许的总字节数超出限制范围。")


@dataclass(frozen=True, slots=True)
class ExpectedWheel:
    filename: str
    sha256: str
    size_bytes: int

    def __post_init__(self):
        if not isinstance(self.filename, str) or not _WHEEL_FILENAME_PATTERN.fullmatch(self.filename):
            _fail("invalid_filename", f"非法的 wheel 文件名: {self.filename!r}")
        if not isinstance(self.sha256, str) or not re.fullmatch(r"^[0-9a-f]{64}$", self.sha256):
            _fail("invalid_sha256", f"非法的 SHA-256 哈希值: {self.sha256!r}")
        if not isinstance(self.size_bytes, int) or self.size_bytes <= 0:
            _fail("invalid_size", f"非法的 wheel 大小: {self.size_bytes!r}")


@dataclass(frozen=True, slots=True)
class ExpectedWheelManifest:
    manifest_version: str = "1.0"
    wheels: tuple[ExpectedWheel, ...] = ()
    limits: WheelLimits = WheelLimits()

    def __post_init__(self):
        if self.manifest_version != "1.0":
            _fail("unsupported_manifest_version", "仅支持 1.0 版本清单。")
        filenames = [w.filename for w in self.wheels]
        if len(filenames) != len(set(filenames)):
            _fail("duplicate_filename", "清单中存在重复的文件名。")
        if len(self.wheels) > self.limits.max_wheels:
            _fail("too_many_wheels", "清单中的 wheel 数量超过上限。")
        total = sum(w.size_bytes for w in self.wheels)
        if total > self.limits.max_total_bytes:
            _fail("total_bytes_exceeded", "清单声明的总字节数超出上限。")
        for w in self.wheels:
            if w.size_bytes > self.limits.max_wheel_bytes:
                _fail("wheel_too_large", f"文件 {w.filename} 大小超出单文件上限。")


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_and_copy_wheel(source_dir_fd: int, name: str, expected: ExpectedWheel,
                         dest_fd: int, sync_hook=None) -> tuple[str, int]:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=source_dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            _fail("unsupported_file", f"文件 {name} 不能是符号链接。")
        raise
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _fail("unsupported_file", f"文件 {name} 必须是普通单链接文件，不支持符号链接或设备文件。")
        if before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            _fail("special_permissions", f"文件 {name} 不能包含特殊权限位。")
        if before.st_size != expected.size_bytes:
            _fail("size_mismatch", f"文件 {name} 大小与预期不符: 实际 {before.st_size}, 预期 {expected.size_bytes}")

        hasher = hashlib.sha256()
        copied = 0
        while True:
            chunk = os.read(fd, min(65536, expected.size_bytes + 1 - copied))
            if not chunk:
                break
            copied += len(chunk)
            if copied > expected.size_bytes:
                _fail("size_mismatch", f"文件 {name} 实际读取字节数超过预期。")
            hasher.update(chunk)
            # Write to destination in staging
            total_written = 0
            while total_written < len(chunk):
                written = os.write(dest_fd, chunk[total_written:])
                if written <= 0:
                    _fail("write_error", "写入目标 staging 失败。")
                total_written += written

        if sync_hook is not None and callable(sync_hook):
            sync_hook(name)

        # Verification pass on the file descriptor
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=source_dir_fd, follow_symlinks=False)
        if (_identity(before) != _identity(after) or _identity(after) != _identity(current)
                or copied != before.st_size):
            _fail("source_changed", f"读取期间源文件 {name} 发生改变。")

        digest = hasher.hexdigest()
        if digest != expected.sha256:
            _fail("digest_mismatch", f"文件 {name} 的 SHA-256 与预期不符: {digest} != {expected.sha256}")
        return digest, copied
    finally:
        os.close(fd)


@dataclass(frozen=True, slots=True)
class PublishedWheelStore:
    manifest_digest: str
    store_path: Path
    file_count: int
    total_bytes: int


def publish_wheel_store(source_dir: Path | str, expected_manifest: ExpectedWheelManifest,
                        store_root: Path | str, sync_hook=None) -> PublishedWheelStore:
    """Verify source_dir strictly against expected_manifest and atomically publish to store_root."""
    if not sys.platform.startswith("linux"):
        _fail("platform_unsupported", "Wheel 制品快照与发布机制依赖 Linux 目录与描述符检查。")

    source_path = Path(source_dir).resolve()
    store_root_path = Path(store_root).resolve()

    if not source_path.is_dir():
        _fail("source_directory_missing", "源目录不存在或不是目录。")
    if source_path.is_symlink():
        _fail("source_is_symlink", "源目录不能是符号链接。")

    store_root_path.mkdir(parents=True, exist_ok=True)
    os.chmod(store_root_path, 0o700)

    # 1. Open source dir by fd without symlink traversal
    source_fd = os.open(str(source_path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        source_stat = os.fstat(source_fd)
        if source_stat.st_uid != os.geteuid():
            _fail("untrusted_source_owner", "源目录属主必须与当前进程一致。")

        entries = sorted(os.listdir(source_fd))
        expected_names = sorted(w.filename for w in expected_manifest.wheels)

        if entries != expected_names:
            diff_missing = set(expected_names) - set(entries)
            diff_extra = set(entries) - set(expected_names)
            _fail("manifest_mismatch", f"源目录内容与预期清单不一致。缺失: {sorted(diff_missing)}, 多余: {sorted(diff_extra)}")

        expected_map = {w.filename: w for w in expected_manifest.wheels}

        # 2. Compute the canonical manifest digest
        canonical_manifest_dict = {
            "version": expected_manifest.manifest_version,
            "wheels": [
                {"filename": w.filename, "sha256": w.sha256, "size_bytes": w.size_bytes}
                for w in sorted(expected_manifest.wheels, key=lambda x: x.filename)
            ]
        }
        manifest_bytes = (json.dumps(canonical_manifest_dict, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
        manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()

        target_store = store_root_path / manifest_digest

        # Check if identical published store already exists
        if target_store.exists():
            return verify_wheel_store(target_store, expected_manifest, manifest_digest)

        # 3. Create a private staging directory on the same filesystem
        staging_dir = Path(tempfile.mkdtemp(prefix="staging-wheels-", dir=str(store_root_path)))
        staging_fd = os.open(str(staging_dir), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            total_bytes = 0
            for name in entries:
                expected_wheel = expected_map[name]
                dest_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=staging_fd)
                try:
                    _, copied = _read_and_copy_wheel(source_fd, name, expected_wheel, dest_fd, sync_hook=sync_hook)
                    total_bytes += copied
                finally:
                    os.close(dest_fd)

            # Write manifest.json in staging
            m_fd = os.open("manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=staging_fd)
            try:
                os.write(m_fd, manifest_bytes)
            finally:
                os.close(m_fd)

            # Seal permissions in staging: files 0o400, dir 0o500
            for name in (*entries, "manifest.json"):
                os.chmod(staging_dir / name, 0o400)
            os.chmod(staging_dir, 0o500)

            # Atomic publish via rename
            try:
                os.rename(staging_dir, target_store)
            except OSError as exc:
                if exc.errno in (errno.EEXIST, errno.ENOTEMPTY):
                    return verify_wheel_store(target_store, expected_manifest, manifest_digest)
                raise
            return PublishedWheelStore(
                manifest_digest=manifest_digest,
                store_path=target_store,
                file_count=len(entries),
                total_bytes=total_bytes
            )
        finally:
            os.close(staging_fd)
            if staging_dir.exists():
                # Cleanup staging on failure
                for p in staging_dir.glob("*"):
                    try:
                        p.chmod(0o600)
                        p.unlink()
                    except Exception:
                        pass
                try:
                    staging_dir.chmod(0o700)
                    staging_dir.rmdir()
                except Exception:
                    pass
    finally:
        os.close(source_fd)


def verify_wheel_store(store_path: Path | str, expected_manifest: ExpectedWheelManifest,
                       expected_manifest_digest: str | None = None) -> PublishedWheelStore:
    """Verify an existing published wheel store against expectations."""
    path = Path(store_path).resolve()
    if not path.is_dir() or path.is_symlink():
        _fail("invalid_store_path", "Store 路径必须是存在的普通目录。")

    fd = os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o500:
            _fail("store_permissions_compromised", "Store 目录必须为当前用户专有只读 (0o500)。")

        entries = sorted(os.listdir(fd))
        expected_names = sorted((*[w.filename for w in expected_manifest.wheels], "manifest.json"))
        if entries != expected_names:
            _fail("store_content_mismatch", "Store 目录内容与清单不匹配。")

        # Verify manifest.json
        m_fd = os.open("manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        try:
            m_stat = os.fstat(m_fd)
            if m_stat.st_uid != os.geteuid() or stat.S_IMODE(m_stat.st_mode) != 0o400:
                _fail("manifest_permissions_compromised", "manifest.json 权限已被篡改。")
            m_bytes = os.read(m_fd, 65536)
            actual_digest = hashlib.sha256(m_bytes).hexdigest()
            if expected_manifest_digest is not None and actual_digest != expected_manifest_digest:
                _fail("manifest_digest_mismatch", "manifest.json 摘要与预期不一致。")
        finally:
            os.close(m_fd)

        total_bytes = 0
        expected_map = {w.filename: w for w in expected_manifest.wheels}
        for name in entries:
            if name == "manifest.json":
                continue
            exp = expected_map[name]
            w_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                w_stat = os.fstat(w_fd)
                if not stat.S_ISREG(w_stat.st_mode) or w_stat.st_nlink != 1:
                    _fail("unsupported_store_file", f"文件 {name} 包含非法链接。")
                if w_stat.st_uid != os.geteuid() or stat.S_IMODE(w_stat.st_mode) != 0o400:
                    _fail("file_permissions_compromised", f"文件 {name} 权限已被篡改。")
                if w_stat.st_size != exp.size_bytes:
                    _fail("file_size_tampered", f"文件 {name} 大小已被篡改。")
                hasher = hashlib.sha256()
                read_bytes = 0
                while True:
                    chunk = os.read(w_fd, 65536)
                    if not chunk:
                        break
                    read_bytes += len(chunk)
                    hasher.update(chunk)
                if hasher.hexdigest() != exp.sha256:
                    _fail("file_digest_tampered", f"文件 {name} 哈希已被篡改。")
                total_bytes += read_bytes
            finally:
                os.close(w_fd)

        return PublishedWheelStore(
            manifest_digest=actual_digest,
            store_path=path,
            file_count=len(expected_manifest.wheels),
            total_bytes=total_bytes
        )
    finally:
        os.close(fd)
