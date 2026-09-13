"""Host-verified binary wheel snapshot store.

This module allows a trusted host to verify a directory of binary Python wheels
against a pre-existing, strictly expected manifest, and atomically publish it
into an immutable, read-only content-addressed store directory.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

_RENAME_NOREPLACE = 1
_MANIFEST_MAX_BYTES = 2 * 1024 * 1024


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


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _trusted_ancestor(info: os.stat_result):
    if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
        _fail("unsafe_store_parent", "Wheel 存储的上级目录必须由主机控制，不能允许其他用户替换。")


def _open_directory(path: Path, *, trusted: bool = False) -> int:
    fd = os.open("/", _directory_flags())
    try:
        if trusted:
            _trusted_ancestor(os.fstat(fd))
        for part in path.parts[1:]:
            try:
                next_fd = os.open(part, _directory_flags(), dir_fd=fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
                    _fail("unsupported_file", f"路径包含非法符号链接或非目录: {part}")
                raise
            os.close(fd)
            fd = next_fd
            if trusted:
                _trusted_ancestor(os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _open_store_root(path: Path, *, create: bool = True) -> int:
    if path == Path("/"):
        _fail("invalid_store", "不能使用根目录作为快照存储根目录。")
    parent_fd = _open_directory(path.parent, trusted=True)
    try:
        if create:
            try:
                os.mkdir(path.name, mode=0o700, dir_fd=parent_fd)
            except FileExistsError:
                pass
        fd = os.open(path.name, _directory_flags(), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        _fail("unsafe_store", "Wheel 存储根目录必须由当前主机用户拥有，权限须严格为 0700。")
    return fd


def _rename_new(parent_fd: int, old: str, new: str):
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "renameat2"):
        _fail("unsupported_platform", "系统缺少原子且不覆盖既有快照的 renameat2 接口。")
    rename_fn = getattr(libc, "renameat2")
    rename_fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename_fn.restype = ctypes.c_int
    if rename_fn(parent_fd, old.encode(), parent_fd, new.encode(), _RENAME_NOREPLACE) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _cleanup(parent_fd: int, name: str, identity: tuple[int, int]):
    if not re.fullmatch(r"\.stage-[a-f0-9]{24}", name):
        return
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
    except OSError:
        return
    try:
        info = os.fstat(fd)
        if (info.st_dev, info.st_ino) != identity:
            return
        os.fchmod(fd, 0o700)
        for child in os.listdir(fd):
            try:
                c_info = os.stat(child, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISDIR(c_info.st_mode):
                    os.chmod(child, 0o600, dir_fd=fd)
                    os.unlink(child, dir_fd=fd)
            except OSError:
                pass
    finally:
        os.close(fd)
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            pass


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
            total_written = 0
            while total_written < len(chunk):
                written = os.write(dest_fd, chunk[total_written:])
                if written <= 0:
                    _fail("write_error", "写入目标 staging 失败。")
                total_written += written

        if sync_hook is not None and callable(sync_hook):
            sync_hook(name)

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

    source_path = Path(source_dir)
    store_root_path = Path(store_root)

    if not source_path.is_absolute() or ".." in source_path.parts:
        _fail("invalid_path", "源目录路径必须是不含上级跳转的绝对路径。")
    if not store_root_path.is_absolute() or ".." in store_root_path.parts:
        _fail("invalid_path", "Store 存储根目录路径必须是不含上级跳转的绝对路径。")

    store_fd = _open_store_root(store_root_path, create=True)
    try:
        source_fd = _open_directory(source_path, trusted=False)
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

            # Canonical manifest
            canonical_manifest_dict = {
                "manifest_version": expected_manifest.manifest_version,
                "wheels": [
                    {"filename": w.filename, "sha256": w.sha256, "size_bytes": w.size_bytes}
                    for w in sorted(expected_manifest.wheels, key=lambda x: x.filename)
                ]
            }
            manifest_bytes = (json.dumps(canonical_manifest_dict, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
            manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()

            target_store = store_root_path / manifest_digest

            # Try to open existing store atomically
            try:
                existing_fd = os.open(manifest_digest, _directory_flags(), dir_fd=store_fd)
                os.close(existing_fd)
                return verify_wheel_store(target_store, expected_manifest, manifest_digest)
            except OSError as exc:
                if exc.errno not in (errno.ENOENT, errno.ENOTDIR):
                    raise

            # Staging allocation inside store_fd
            stage_name = ".stage-" + secrets.token_hex(12)
            os.mkdir(stage_name, mode=0o700, dir_fd=store_fd)
            staging_fd = os.open(stage_name, _directory_flags(), dir_fd=store_fd)
            info = os.fstat(staging_fd)
            identity = (info.st_dev, info.st_ino)
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

                # Write manifest.json
                m_fd = os.open("manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=staging_fd)
                try:
                    os.write(m_fd, manifest_bytes)
                finally:
                    os.close(m_fd)

                # Seal staging permissions: files 0o400, dir 0o500
                for name in (*entries, "manifest.json"):
                    os.chmod(name, 0o400, dir_fd=staging_fd)
                os.fchmod(staging_fd, 0o500)
                os.fsync(staging_fd)

                # Atomic publication using renameat2 RENAME_NOREPLACE
                try:
                    _rename_new(store_fd, stage_name, manifest_digest)
                except OSError as exc:
                    if exc.errno in (errno.EEXIST, errno.ENOTEMPTY):
                        return verify_wheel_store(target_store, expected_manifest, manifest_digest)
                    raise
                os.fsync(store_fd)
                return PublishedWheelStore(
                    manifest_digest=manifest_digest,
                    store_path=target_store,
                    file_count=len(entries),
                    total_bytes=total_bytes
                )
            finally:
                os.close(staging_fd)
                _cleanup(store_fd, stage_name, identity)
        finally:
            os.close(source_fd)
    finally:
        os.close(store_fd)


def _read_exact_file(dir_fd: int, name: str, expected_size: int, expected_sha256: str | None = None) -> bytes:
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            _fail("unsupported_file", f"文件 {name} 不能是符号链接。")
        raise
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _fail("unsupported_file", f"文件 {name} 必须是普通单链接文件。")
        if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o400:
            _fail("file_permissions_compromised", f"文件 {name} 权限已被篡改，必须为 0400。")
        if before.st_size != expected_size:
            _fail("file_size_tampered", f"文件 {name} 大小已被篡改。")

        hasher = hashlib.sha256()
        read_total = 0
        buf = bytearray()
        while True:
            chunk = os.read(fd, min(65536, expected_size + 1 - read_total))
            if not chunk:
                break
            read_total += len(chunk)
            if read_total > expected_size:
                _fail("file_size_tampered", f"文件 {name} 读取字节数超过预期大小。")
            hasher.update(chunk)
            buf.extend(chunk)

        after = os.fstat(fd)
        current = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if (_identity(before) != _identity(after) or _identity(after) != _identity(current)
                or read_total != before.st_size):
            _fail("file_tampered_during_verify", f"校验期间文件 {name} 发生变化。")

        digest = hasher.hexdigest()
        if expected_sha256 is not None and digest != expected_sha256:
            _fail("file_digest_tampered", f"文件 {name} 哈希已被篡改。")
        return bytes(buf)
    finally:
        os.close(fd)


def verify_wheel_store(store_path: Path | str, expected_manifest: ExpectedWheelManifest,
                       expected_manifest_digest: str | None = None) -> PublishedWheelStore:
    """Verify an existing published wheel store strictly against expectations."""
    path = Path(store_path)
    if not path.is_absolute() or ".." in path.parts:
        _fail("invalid_path", "Store 路径必须是不含上级跳转的绝对路径。")

    fd = _open_directory(path, trusted=True)
    try:
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) != 0o500:
            _fail("store_permissions_compromised", "Store 目录必须由当前用户拥有且权限严格为 0500。")

        entries = sorted(os.listdir(fd))
        expected_names = sorted((*[w.filename for w in expected_manifest.wheels], "manifest.json"))
        if entries != expected_names:
            _fail("store_content_mismatch", "Store 目录内容与预期清单不一致。")

        # 1. Read and parse manifest.json completely
        m_stat = os.stat("manifest.json", dir_fd=fd, follow_symlinks=False)
        if m_stat.st_size > _MANIFEST_MAX_BYTES:
            _fail("manifest_too_large", "manifest.json 大小超过安全上限。")

        m_bytes = _read_exact_file(fd, "manifest.json", m_stat.st_size)
        actual_digest = hashlib.sha256(m_bytes).hexdigest()
        if expected_manifest_digest is not None and actual_digest != expected_manifest_digest:
            _fail("manifest_digest_mismatch", "manifest.json 摘要与预期不符。")

        try:
            m_dict = json.loads(m_bytes.decode("utf-8"))
        except Exception:
            raise WheelStoreError("invalid_manifest_json", "manifest.json 无法解析为有效 JSON。") from None

        # Validate canonical manifest fields match expected_manifest
        expected_canonical = {
            "manifest_version": expected_manifest.manifest_version,
            "wheels": [
                {"filename": w.filename, "sha256": w.sha256, "size_bytes": w.size_bytes}
                for w in sorted(expected_manifest.wheels, key=lambda x: x.filename)
            ]
        }
        if m_dict != expected_canonical:
            _fail("manifest_content_tampered", "manifest.json 内容与预期清单不符。")

        total_bytes = 0
        expected_map = {w.filename: w for w in expected_manifest.wheels}
        for name in entries:
            if name == "manifest.json":
                continue
            exp = expected_map[name]
            _read_exact_file(fd, name, exp.size_bytes, exp.sha256)
            total_bytes += exp.size_bytes

        # Final check that directory is still consistent
        post_st = os.fstat(fd)
        if _identity(st) != _identity(post_st):
            _fail("store_directory_tampered", "校验期间 Store 目录元数据发生变化。")

        return PublishedWheelStore(
            manifest_digest=actual_digest,
            store_path=path,
            file_count=len(expected_manifest.wheels),
            total_bytes=total_bytes
        )
    finally:
        os.close(fd)
