"""Bounded binary snapshots of a trusted host's pre-approved wheel manifest.

No dependency resolution, installation or mount is performed. The host/store
remain trusted: chmod is not protection against the same host identity. Verify
again before granting the exact snapshot through a read-only sandbox mount.
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


class WheelStoreError(ValueError):
    def __init__(self, code: str, detail: str):
        self.code, self.detail = code, detail
        super().__init__(f"{code}: {detail}")


def _fail(code, detail):
    raise WheelStoreError(code, detail)


_DIGEST = re.compile(r"[0-9a-f]{64}")
_MANIFEST_LIMIT = 1024 * 1024
_STAGE = re.compile(r"staging-wheels-[0-9a-f]{24}")


@dataclass(frozen=True, slots=True)
class WheelLimits:
    max_wheels: int = 64
    max_wheel_bytes: int = 50 * 1024 * 1024
    max_total_bytes: int = 200 * 1024 * 1024

    def __post_init__(self):
        for value, maximum in ((self.max_wheels, 1024), (self.max_wheel_bytes, 500 * 1024 * 1024),
                               (self.max_total_bytes, 2000 * 1024 * 1024)):
            if type(value) is not int or not 1 <= value <= maximum:
                _fail("invalid_limits", "数量和字节上限须为支持范围内的整数。")


def _wheel_name(name):
    # A bounded safe basename with wheel-shaped fields, not a wheel/PEP parser.
    if type(name) is not str or not name.isascii() or len(name) > 255 or not name.endswith(".whl"):
        _fail("invalid_filename", "Wheel 名称须为至多 255 字节的 ASCII 普通文件名。")
    parts = name[:-4].split("-")
    if (len(parts) not in (5, 6) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.]*", parts[0])
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.+!]*", parts[1])
            or (len(parts) == 6 and not re.fullmatch(r"[0-9][A-Za-z0-9_]*", parts[2]))
            or any(not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*", tag) for tag in parts[-3:])):
        _fail("invalid_filename", "Wheel 文件名含不支持的字段、路径或控制字符。")


@dataclass(frozen=True, slots=True)
class ExpectedWheel:
    filename: str
    sha256: str
    size_bytes: int

    def __post_init__(self):
        _wheel_name(self.filename)
        if type(self.sha256) is not str or not _DIGEST.fullmatch(self.sha256):
            _fail("invalid_sha256", "预期摘要须为完整的小写 SHA-256。")
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            _fail("invalid_size", "预期文件大小须为正整数。")


@dataclass(frozen=True, slots=True)
class ExpectedWheelManifest:
    manifest_version: str = "1.0"
    wheels: tuple[ExpectedWheel, ...] = ()
    limits: WheelLimits = WheelLimits()

    def __post_init__(self):
        if type(self.manifest_version) is not str or self.manifest_version != "1.0":
            _fail("unsupported_manifest_version", "仅支持 1.0 版本清单。")
        if type(self.wheels) is not tuple or type(self.limits) is not WheelLimits:
            _fail("invalid_manifest", "清单须使用不可变的 wheel 元组与 WheelLimits。")
        self.limits.__post_init__()
        if len(self.wheels) > self.limits.max_wheels:
            _fail("too_many_wheels", "清单中的 wheel 数量超过上限。")
        names, total = set(), 0
        for wheel in self.wheels:
            if type(wheel) is not ExpectedWheel:
                _fail("invalid_manifest", "清单条目须为 ExpectedWheel。")
            wheel.__post_init__()
            name = wheel.filename.casefold()
            if name in names:
                _fail("duplicate_filename", "清单包含大小写不敏感的重名文件。")
            names.add(name)
            if wheel.size_bytes > self.limits.max_wheel_bytes:
                _fail("wheel_too_large", "清单声明的单文件大小超过上限。")
            total += wheel.size_bytes
        if total > self.limits.max_total_bytes:
            _fail("total_bytes_exceeded", "清单声明的总字节数超过上限。")


@dataclass(frozen=True, slots=True)
class PublishedWheelStore:
    manifest_digest: str
    store_path: Path
    file_count: int
    total_bytes: int


def _linux():
    if not sys.platform.startswith("linux") or any(not hasattr(os, name) for name in
            ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")):
        _fail("platform_unsupported", "Wheel 快照发布和验证均要求 Linux 描述符保护。")


def _absolute(value):
    try:
        path = Path(value)
        raw = str(path)
        if (path.anchor != "/" or ".." in path.parts or len(raw.encode("utf-8", "strict")) > 4096
                or any(ord(c) < 32 or ord(c) == 127 for c in raw)):
            raise ValueError
        return path
    except (TypeError, ValueError, UnicodeError):
        _fail("invalid_path", "路径须为不含上级跳转或控制字符的 Linux 绝对路径。")


def _canonical(expected):
    if type(expected) is not ExpectedWheelManifest:
        _fail("invalid_manifest", "须提供宿主预先审定的 ExpectedWheelManifest。")
    expected.__post_init__()
    value = {"version": expected.manifest_version, "wheels": [
        {"filename": w.filename, "sha256": w.sha256, "size_bytes": w.size_bytes}
        for w in sorted(expected.wheels, key=lambda item: item.filename)]}
    raw = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(raw) > _MANIFEST_LIMIT:
        _fail("invalid_manifest", "规范清单超过读取上限。")
    return raw, hashlib.sha256(raw).hexdigest()


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_flags():
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _trusted_ancestor(info):
    # A root/current-user-owned sticky /tmp is acceptable; ordinary shared
    # writable ancestors can rename a store and are not trusted.
    if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
        _fail("unsafe_store_parent", "存储祖先必须由宿主控制，不能允许其他用户替换目录。")


def _open_directory(path, *, trusted=False):
    fd = os.open("/", _directory_flags())
    try:
        if trusted:
            _trusted_ancestor(os.fstat(fd))
        for part in path.parts[1:]:
            child = os.open(part, _directory_flags(), dir_fd=fd)
            os.close(fd)
            fd = child
            if trusted:
                _trusted_ancestor(os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _named_directory(path, fd, *, trusted=False):
    check = _open_directory(path, trusted=trusted)
    try:
        if _identity(os.fstat(check)) != _identity(os.fstat(fd)):
            _fail("directory_changed", "目录路径与已固定的描述符不再一致。")
    finally:
        os.close(check)


def _store(path, *, create):
    if path == Path("/"):
        _fail("invalid_store", "根目录不能用作 wheel store。")
    parent = _open_directory(path.parent, trusted=True)
    try:
        if create:
            try:
                os.mkdir(path.name, 0o700, dir_fd=parent)
            except FileExistsError:
                pass
        fd = os.open(path.name, _directory_flags(), dir_fd=parent)
    finally:
        os.close(parent)
    try:
        _check_store(path, fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _check_store(path, fd):
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        _fail("unsafe_store", "既有存储必须属于当前用户且为 0700；不会自动修改权限。")
    _named_directory(path, fd, trusted=True)


def _entries(fd, limit, code):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(names) >= limit:
                _fail(code, "目录出现超出预期数量的条目。")
            names.append(entry.name)
    return sorted(names)


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        if count <= 0 or count > len(view):
            _fail("write_error", "写入快照未完成。")
        view = view[count:]


def _stream(parent, name, size, digest, *, dest=None, readonly=False, expected_bytes=None, sync_hook=None):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            _fail("unsupported_store_file" if readonly else "unsupported_file", "文件不能是符号链接。")
        raise
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _fail("unsupported_store_file" if readonly else "unsupported_file", "只接受普通单链接文件。")
        if readonly and (before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o400):
            _fail("file_permissions_compromised", "快照文件须属于当前用户且为 0400。")
        if before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            _fail("special_permissions", "Wheel 文件不能包含特殊权限位。")
        if before.st_size != size:
            _fail("file_size_tampered" if readonly else "size_mismatch", "实际文件大小与预期不符。")
        hasher, total = hashlib.sha256(), 0
        captured = bytearray() if expected_bytes is not None else None
        while True:
            chunk = os.read(fd, min(65536, size + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > size:
                _fail("file_size_tampered" if readonly else "size_mismatch", "读取大小超过预期上限。")
            hasher.update(chunk)
            if captured is not None:
                captured.extend(chunk)
            if dest is not None:
                _write_all(dest, chunk)
        if sync_hook is not None:
            sync_hook(name)  # Optional trusted-host test synchronization only.
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if _identity(before) != _identity(after) or _identity(after) != _identity(current) or total != size:
            _fail("store_changed" if readonly else "source_changed", "读取期间文件身份、内容大小或路径发生变化。")
        if hasher.hexdigest() != digest or (captured is not None and captured != expected_bytes):
            _fail("file_digest_tampered" if readonly else "digest_mismatch", "完整文件字节与宿主预期不符。")
        return total, _identity(before)
    finally:
        os.close(fd)


def _check_source(path, fd, identity, names, files):
    if _identity(os.fstat(fd)) != identity or _entries(fd, len(names), "manifest_mismatch") != names:
        _fail("source_changed", "复制期间源目录或完整文件列表发生变化。")
    for name, expected in files.items():
        if _identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != expected:
            _fail("source_changed", "复制期间先前读取的源文件发生变化。")
    _named_directory(path, fd)


def _verify_contents(fd, expected, manifest, digest):
    before = os.fstat(fd)
    if before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o500:
        _fail("store_permissions_compromised", "快照目录须属于当前用户且为 0500。")
    names = sorted([w.filename for w in expected.wheels] + ["manifest.json"])
    if _entries(fd, len(names), "store_content_mismatch") != names:
        _fail("store_content_mismatch", "快照条目必须与预期清单完全一致。")
    _, identity = _stream(fd, "manifest.json", len(manifest), digest, readonly=True, expected_bytes=manifest)
    files, total = {"manifest.json": identity}, 0
    for wheel in expected.wheels:
        count, identity = _stream(fd, wheel.filename, wheel.size_bytes, wheel.sha256, readonly=True)
        files[wheel.filename] = identity
        total += count
    if _identity(os.fstat(fd)) != _identity(before) or _entries(fd, len(names), "store_content_mismatch") != names:
        _fail("store_changed", "复验期间快照目录发生变化。")
    for name, identity in files.items():
        if _identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != identity:
            _fail("store_changed", "复验期间已读取的快照文件发生变化。")
    return total


def _verify_at(store_fd, path, expected, manifest, digest):
    fd = os.open(path.name, _directory_flags(), dir_fd=store_fd)
    try:
        total = _verify_contents(fd, expected, manifest, digest)
        current = os.stat(path.name, dir_fd=store_fd, follow_symlinks=False)
        if _identity(current) != _identity(os.fstat(fd)):
            _fail("store_changed", "快照目录路径在复验期间被替换。")
        _check_store(path.parent, store_fd)
        return PublishedWheelStore(digest, path, len(expected.wheels), total)
    finally:
        os.close(fd)


def _rename_new(parent, stage, digest):
    rename = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if rename is None:
        _fail("platform_unsupported", "发布需要 Linux renameat2 的不覆盖语义。")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent, stage.encode(), parent, digest.encode(), 1) != 0:
        number = ctypes.get_errno()
        raise OSError(number, os.strerror(number))


def _cleanup(parent, name, identity):
    # Never follow links or chmod child files. Only this invocation's unchanged
    # staging directory can be removed; unexpected subdirectories are retained.
    if not _STAGE.fullmatch(name):
        return
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != identity or info.st_uid != os.geteuid():
                return
            os.fchmod(fd, 0o700)
            with os.scandir(fd) as entries:
                for index, entry in enumerate(entries):
                    if index >= 1025:
                        return
                    if not stat.S_ISDIR(os.stat(entry.name, dir_fd=fd, follow_symlinks=False).st_mode):
                        os.unlink(entry.name, dir_fd=fd)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != identity:
                return
            os.rmdir(name, dir_fd=parent)
        finally:
            os.close(fd)
    except OSError:
        # A retained incomplete stage is never accepted as a digest snapshot.
        pass


def publish_wheel_store(source_dir: Path | str, expected_manifest: ExpectedWheelManifest,
                        store_root: Path | str, sync_hook=None) -> PublishedWheelStore:
    """Freeze exact approved bytes; source/store roots must not overlap.

    The store's parent must already exist. Existing store permissions are
    rejected, never repaired. sync_hook is solely a trusted-host test seam.
    """
    _linux()
    manifest, digest = _canonical(expected_manifest)
    source, store = _absolute(source_dir), _absolute(store_root)
    if source.is_relative_to(store) or store.is_relative_to(source):
        _fail("source_store_overlap", "源目录与存储目录必须互不包含。")
    if sync_hook is not None and not callable(sync_hook):
        _fail("invalid_sync_hook", "同步钩子必须是宿主提供的可调用对象。")
    source_fd = store_fd = stage_fd = None
    stage = stage_identity = None
    try:
        source_fd = _open_directory(source)
        before = os.fstat(source_fd)
        if before.st_uid != os.geteuid():
            _fail("untrusted_source_owner", "源目录须属于当前宿主用户。")
        names = sorted(w.filename for w in expected_manifest.wheels)
        if _entries(source_fd, len(names), "manifest_mismatch") != names:
            _fail("manifest_mismatch", "源目录条目必须与宿主清单完全一致。")
        store_fd = _store(store, create=True)
        stage = "staging-wheels-" + secrets.token_hex(12)
        os.mkdir(stage, 0o700, dir_fd=store_fd)
        created = os.stat(stage, dir_fd=store_fd, follow_symlinks=False)
        stage_identity = (created.st_dev, created.st_ino)
        stage_fd = os.open(stage, _directory_flags(), dir_fd=store_fd)
        source_files = {}
        for wheel in expected_manifest.wheels:
            output = os.open(wheel.filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=stage_fd)
            try:
                _, identity = _stream(source_fd, wheel.filename, wheel.size_bytes, wheel.sha256,
                                      dest=output, sync_hook=sync_hook)
                source_files[wheel.filename] = identity
                os.fchmod(output, 0o400)
                os.fsync(output)
            finally:
                os.close(output)
        output = os.open("manifest.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=stage_fd)
        try:
            _write_all(output, manifest)
            os.fchmod(output, 0o400)
            os.fsync(output)
        finally:
            os.close(output)
        os.fchmod(stage_fd, 0o500)
        os.fsync(stage_fd)
        _verify_contents(stage_fd, expected_manifest, manifest, digest)
        _check_source(source, source_fd, _identity(before), names, source_files)
        _check_store(store, store_fd)
        current_stage = os.stat(stage, dir_fd=store_fd, follow_symlinks=False)
        if _identity(current_stage) != _identity(os.fstat(stage_fd)):
            _fail("store_changed", "临时发布目录已被替换。")
        try:
            _rename_new(store_fd, stage, digest)
        except OSError as exc:
            if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise
        os.fsync(store_fd)
        result = _verify_at(store_fd, store / digest, expected_manifest, manifest, digest)
        _check_source(source, source_fd, _identity(before), names, source_files)
        return result
    except OSError as exc:
        _fail("store_io_error", f"快照目录或文件操作失败（errno={exc.errno}）；不会降低验证要求。")
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        if store_fd is not None:
            if stage is not None and stage_identity is not None:
                _cleanup(store_fd, stage, stage_identity)
            os.close(store_fd)
        if source_fd is not None:
            os.close(source_fd)


def verify_wheel_store(store_path: Path | str, expected_manifest: ExpectedWheelManifest,
                       expected_manifest_digest: str | None = None) -> PublishedWheelStore:
    """Re-read every bounded file against the host's canonical expectation."""
    _linux()
    manifest, digest = _canonical(expected_manifest)
    path = _absolute(store_path)
    if (path.name != digest or (expected_manifest_digest is not None
            and (type(expected_manifest_digest) is not str or expected_manifest_digest != digest))):
        _fail("manifest_digest_mismatch", "目录名及提供的摘要必须匹配宿主预期规范清单。")
    store_fd = None
    try:
        store_fd = _store(path.parent, create=False)
        return _verify_at(store_fd, path, expected_manifest, manifest, digest)
    except OSError as exc:
        _fail("store_io_error", f"快照复验未完成（errno={exc.errno}）；不会接受不完整结果。")
    finally:
        if store_fd is not None:
            os.close(store_fd)
