"""Bounded, host-owned snapshots of explicitly selected Linux skill trees.

The host selects aliases and absolute source directories. Every selected file
must be regular, singly linked, bounded UTF-8 text; nothing is silently skipped.
The manifest includes origins and file digests, and its SHA-256 names the store
entry. Snapshot files are read-only, but chmod does not isolate a process with
the same host identity: the supervisor MUST mount ``tree_path`` read-only at
the framework's effective skills directory and hide other skill libraries.

Scan ``scan_paths`` (or ``tree_path`` for the empty selection), not the mutable
originals. Call ``verify_snapshot`` again before mounting/starting a profile.
The host and its private store are trusted; there is no Windows fallback.
"""
from __future__ import annotations

import ctypes
from dataclasses import asdict, dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys


class SkillsSnapshotError(ValueError):
    """A selected tree could not be captured completely and safely."""

    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")


def _fail(code: str, detail: str):
    raise SkillsSnapshotError(code, detail)


@dataclass(frozen=True, slots=True)
class SnapshotLimits:
    # Defaults deliberately match the default foundation scanner's file bounds.
    max_files: int = 32
    max_file_bytes: int = 65536
    max_total_bytes: int = 524288
    max_depth: int = 16
    max_entries: int = 512

    def __post_init__(self):
        bounds = {"max_files": 4096, "max_file_bytes": 1048576,
                  "max_total_bytes": 16777216, "max_depth": 64, "max_entries": 8192}
        for name, maximum in bounds.items():
            if type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= maximum:
                _fail("invalid_limits", "技能快照数量、大小和深度必须在支持范围内。")


@dataclass(frozen=True, slots=True)
class SkillSnapshot:
    digest: str
    path: Path
    tree_path: Path
    scan_paths: tuple[Path, ...]
    source_paths: dict[str, str]
    file_count: int
    total_bytes: int
    manifest: dict

    def to_dict(self) -> dict:
        return {"digest": self.digest, "path": str(self.path), "tree_path": str(self.tree_path),
                "scan_paths": [str(p) for p in self.scan_paths],
                "source_paths": dict(self.source_paths), "file_count": self.file_count,
                "total_bytes": self.total_bytes, "manifest": self.manifest}


_ALIAS = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_MANIFEST_LIMIT = 2097152


def _linux():
    if not sys.platform.startswith("linux") or not hasattr(os, "O_NOFOLLOW"):
        _fail("unsupported_platform", "技能固定快照需要 Linux；请在 Linux/WSL 主机创建。")


def _absolute(value: Path) -> Path:
    try:
        path = Path(value)
        if (path.anchor != "/" or ".." in path.parts or "\x00" in str(path)
                or any(ord(c) < 32 or ord(c) == 127 for c in str(path))):
            raise ValueError
        str(path).encode("utf-8", "strict")
        return path
    except (TypeError, ValueError, UnicodeError):
        _fail("invalid_path", "必须指定不含上级跳转的 Linux 绝对目录。")


def _directory_flags() -> int:
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _trusted_ancestor(info):
    # /tmp with the sticky bit is permitted. A user-owned private store below it
    # cannot be renamed by another ordinary user. Shared writable ancestors are
    # not suitable for a persistent authority store.
    if info.st_uid not in {0, os.geteuid()} or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX):
        _fail("unsafe_store_parent", "快照存储的上级目录必须由主机控制，不能允许其他用户替换。")


def _open_directory(path: Path, *, trusted: bool = False) -> int:
    fd = os.open("/", _directory_flags())
    try:
        if trusted:
            _trusted_ancestor(os.fstat(fd))
        for part in path.parts[1:]:
            next_fd = os.open(part, _directory_flags(), dir_fd=fd)
            os.close(fd)
            fd = next_fd
            if trusted:
                _trusted_ancestor(os.fstat(fd))
        return fd
    except BaseException:
        os.close(fd)
        raise


def _store(path: Path, *, create: bool) -> int:
    if path == Path("/"):
        _fail("invalid_store", "不能使用根目录作为技能快照存储。")
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
        _fail("unsafe_store", "快照存储必须由当前主机用户拥有，权限须为 0700。")
    return fd


def _name(value: str):
    try:
        if (value in {"", ".", ".."} or "/" in value or "\\" in value
                or len(value.encode("utf-8", "strict")) > 255
                or any(ord(c) < 32 or ord(c) == 127 for c in value)):
            raise ValueError
    except (ValueError, UnicodeError):
        _fail("invalid_entry_name", "技能文件名包含不支持的路径或控制字符。")


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file(parent_fd: int, name: str, limit: int, *, readonly: bool = False) -> tuple[bytes, bool]:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _fail("unsupported_file", "技能只接受普通单链接文件；不接受链接、设备、套接字或管道。")
        if before.st_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
            _fail("special_permissions", "技能文件不能带 setuid、setgid 或特殊权限。")
        executable = bool(before.st_mode & 0o111)
        if readonly and (before.st_uid != os.geteuid()
                         or stat.S_IMODE(before.st_mode) != (0o555 if executable else 0o444)):
            _fail("snapshot_permissions_changed", "技能快照文件的归属或只读权限已改变。")
        if before.st_size > limit:
            _fail("file_too_large", "技能文件超过单文件扫描上限，不能跳过后继续启用。")
        blocks = []
        size = 0
        while True:
            block = os.read(fd, min(65536, limit + 1 - size))
            if not block:
                break
            size += len(block)
            if size > limit:
                _fail("file_too_large", "技能文件超过单文件扫描上限，不能跳过后继续启用。")
            blocks.append(block)
        data = b"".join(blocks)
        # Timestamp granularity can hide a fast same-size overwrite. Read the
        # pinned descriptor again and compare bytes as well as metadata.
        os.lseek(fd, 0, os.SEEK_SET)
        confirmation = bytearray()
        while len(confirmation) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(confirmation)))
            if not block:
                break
            confirmation.extend(block)
        after = os.fstat(fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (_identity(before) != _identity(after) or _identity(after) != _identity(current)
                or size != before.st_size or confirmation != data):
            _fail("source_changed", "读取技能期间文件发生变化，请固定来源后重试。")
        try:
            text = data.decode("utf-8", "strict")
            if "\x00" in text or any(ord(c) < 32 and c not in "\t\n\r" for c in text):
                raise UnicodeError
        except UnicodeError:
            _fail("non_text_skill", "技能含二进制或非 UTF-8 文件；本版只支持可完整检查的 UTF-8 文本与脚本。")
        return data, executable
    finally:
        os.close(fd)


def _walk(fd: int, prefix: str, limits: SnapshotLimits, files: list, directories: list,
          budget: dict, *, depth: int, readonly: bool = False):
    before = os.fstat(fd)
    if depth > limits.max_depth:
        _fail("tree_too_deep", "技能目录超过允许深度。")
    if readonly and (before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o555):
        _fail("snapshot_permissions_changed", "技能快照目录的归属或只读权限已改变。")
    names = sorted(os.listdir(fd))
    for name in names:
        _name(name)
        budget["entries"] += 1
        if budget["entries"] > limits.max_entries:
            _fail("too_many_entries", "技能文件和目录总数超过检查上限。")
        relative = prefix + "/" + name if prefix else name
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, _directory_flags(), dir_fd=fd)
            try:
                if (info.st_dev, info.st_ino) != (os.fstat(child).st_dev, os.fstat(child).st_ino):
                    _fail("source_changed", "读取技能期间目录发生变化。")
                directories.append(relative)
                _walk(child, relative, limits, files, directories, budget, depth=depth + 1, readonly=readonly)
            finally:
                os.close(child)
        elif stat.S_ISREG(info.st_mode):
            if len(files) >= limits.max_files:
                _fail("too_many_files", "选中的技能文件数超过扫描上限。")
            try:
                data, executable = _read_file(fd, name, limits.max_file_bytes, readonly=readonly)
            except SkillsSnapshotError as exc:
                raise SkillsSnapshotError(exc.code, relative + "：" + exc.detail) from None
            budget["bytes"] += len(data)
            if budget["bytes"] > limits.max_total_bytes:
                _fail("total_too_large", "选中的技能内容总量超过扫描上限。")
            files.append(({"path": relative, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                           "executable": executable}, data))
        else:
            _fail("unsupported_file", "技能目录包含链接或特殊文件；必须完整检查，不能静默跳过。")
    if _identity(before) != _identity(os.fstat(fd)) or names != sorted(os.listdir(fd)):
        _fail("source_changed", "读取技能期间目录内容发生变化，请固定来源后重试。")


def _json(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


def _selection(sources: dict[str, Path], store: Path, limits: SnapshotLimits):
    if type(sources) is not dict or len(sources) > 64:
        _fail("invalid_selection", "技能选择须为至多 64 个名称到绝对目录的映射；默认空集合。")
    origins = {}
    for alias, value in sources.items():
        if type(alias) is not str or not _ALIAS.fullmatch(alias):
            _fail("invalid_alias", "技能名称须为 1–64 位字母数字及点、横线、下划线，且以字母数字开头。")
        path = _absolute(value)
        if path == store or path in store.parents or store in path.parents:
            _fail("overlapping_store", "技能来源和快照存储不能互相包含。")
        origins[alias] = str(path)
    files, directories = [], []
    budget = {"entries": len(origins), "bytes": 0}
    if budget["entries"] > limits.max_entries:
        _fail("too_many_entries", "选中目录数量超过检查上限。")
    for alias, origin in sorted(origins.items()):
        fd = _open_directory(Path(origin))
        try:
            directories.append(alias)
            _walk(fd, alias, limits, files, directories, budget, depth=1)
        finally:
            os.close(fd)
    files.sort(key=lambda pair: pair[0]["path"])
    manifest = {"version": 1, "source_paths": dict(sorted(origins.items())), "limits": asdict(limits),
                "directories": sorted(directories), "files": [item for item, _ in files]}
    return manifest, files


def _write(parent_fd: int, name: str, data: bytes, mode: int):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode=0o600, dir_fd=parent_fd)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short write")
            view = view[count:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def _rename_new(parent_fd: int, old: str, new: str):
    # Never replace an existing digest, even if someone left an empty directory.
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, "renameat2", None)
    if rename is None:
        _fail("unsupported_platform", "系统缺少原子且不覆盖既有快照的 renameat2 接口。")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, old.encode(), parent_fd, new.encode(), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _cleanup(parent_fd: int, name: str, identity: tuple[int, int]):
    if not re.fullmatch(r"\.stage-[a-f0-9]{24}", name):
        return
    def clear(fd):
        os.fchmod(fd, 0o700)
        for child_name in os.listdir(fd):
            info = os.stat(child_name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child_fd = os.open(child_name, _directory_flags(), dir_fd=fd)
                try:
                    clear(child_fd)
                finally:
                    os.close(child_fd)
                os.rmdir(child_name, dir_fd=fd)
            else:
                os.unlink(child_name, dir_fd=fd)
    try:
        fd = os.open(name, _directory_flags(), dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != identity or info.st_uid != os.geteuid():
                return
            clear(fd)
        finally:
            os.close(fd)
        os.rmdir(name, dir_fd=parent_fd)
    except OSError:
        # An incomplete staging directory is never a published snapshot.
        pass


def _publish(store_fd: int, digest: str, manifest: dict, files: list):
    stage = ".stage-" + secrets.token_hex(12)
    os.mkdir(stage, mode=0o700, dir_fd=store_fd)
    root = os.open(stage, _directory_flags(), dir_fd=store_fd)
    info = os.fstat(root)
    identity = (info.st_dev, info.st_ino)
    opened = {}
    try:
        os.mkdir("tree", mode=0o700, dir_fd=root)
        opened[""] = os.open("tree", _directory_flags(), dir_fd=root)
        for directory in sorted(manifest["directories"], key=lambda p: (p.count("/"), p)):
            parent, _, name = directory.rpartition("/")
            os.mkdir(name, mode=0o700, dir_fd=opened[parent])
            opened[directory] = os.open(name, _directory_flags(), dir_fd=opened[parent])
        for item, data in files:
            parent, _, name = item["path"].rpartition("/")
            _write(opened[parent], name, data, 0o555 if item["executable"] else 0o444)
        _write(root, "manifest.json", _json(manifest), 0o444)
        for fd in reversed(list(opened.values())):
            os.fchmod(fd, 0o555)
            os.fsync(fd)
        os.fchmod(root, 0o555)
        os.fsync(root)
        try:
            _rename_new(store_fd, stage, digest)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
        os.fsync(store_fd)
    finally:
        for fd in opened.values():
            os.close(fd)
        os.close(root)
        _cleanup(store_fd, stage, identity)


def _strict_manifest(data: bytes) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    try:
        value = json.loads(data, object_pairs_hook=unique)
        if (type(value) is not dict or set(value) != {"version", "source_paths", "limits", "directories", "files"}
                or type(value["version"]) is not int or value["version"] != 1
                or type(value["source_paths"]) is not dict or type(value["limits"]) is not dict
                or type(value["directories"]) is not list or type(value["files"]) is not list
                or len(value["source_paths"]) > 64 or _json(value) != data):
            raise ValueError
        if set(value["limits"]) != set(asdict(SnapshotLimits())):
            raise ValueError
        SnapshotLimits(**value["limits"])
        for name, path in value["source_paths"].items():
            if type(name) is not str or not _ALIAS.fullmatch(name) or type(path) is not str:
                raise ValueError
            _absolute(Path(path))
        return value
    except (TypeError, ValueError, UnicodeError):
        _fail("invalid_manifest", "技能快照清单格式无效或不是完整的规范记录。")


def _verify(store_fd: int, path: Path, digest: str) -> SkillSnapshot:
    root = os.open(path.name, _directory_flags(), dir_fd=store_fd)
    try:
        info = os.fstat(root)
        if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o555:
            _fail("snapshot_permissions_changed", "技能快照根目录的归属或只读权限已改变。")
        if set(os.listdir(root)) != {"tree", "manifest.json"}:
            _fail("snapshot_changed", "技能快照出现未记录的文件或缺失内容。")
        data, executable = _read_file(root, "manifest.json", _MANIFEST_LIMIT, readonly=True)
        if executable or hashlib.sha256(data).hexdigest() != digest:
            _fail("digest_mismatch", "技能清单与主机固定的摘要不一致。")
        manifest = _strict_manifest(data)
        tree = os.open("tree", _directory_flags(), dir_fd=root)
        try:
            files, directories = [], []
            _walk(tree, "", SnapshotLimits(**manifest["limits"]), files, directories,
                  {"entries": 0, "bytes": 0}, depth=0, readonly=True)
        finally:
            os.close(tree)
        if (sorted(directories) != manifest["directories"]
                or sorted((item for item, _ in files), key=lambda item: item["path"]) != manifest["files"]
                or {name.split("/")[0] for name in directories} != set(manifest["source_paths"])):
            _fail("snapshot_changed", "技能快照内容、文件清单或可执行权限与固定记录不一致。")
        return SkillSnapshot(digest, path, path / "tree",
                             tuple(path / "tree" / name for name in sorted(manifest["source_paths"])),
                             dict(manifest["source_paths"]), len(files), sum(len(data) for _, data in files), manifest)
    finally:
        os.close(root)


def create_snapshot(store_dir: Path, sources: dict[str, Path], *, limits: SnapshotLimits | None = None) -> SkillSnapshot:
    """Capture an explicit selection, or ``{}`` for an empty effective library.

    ``store_dir.parent`` must already exist. A new store is created as 0700;
    existing stores with other permissions are rejected, never chmod-repaired.
    Origins and limits are part of the content-addressed manifest. The scanner
    needs matching or larger limits; creating a snapshot does not approve its
    contents and does not grant the agent a source or mount path.
    """
    _linux()
    path = _absolute(store_dir)
    selected_limits = limits if limits is not None else SnapshotLimits()
    if type(selected_limits) is not SnapshotLimits:
        _fail("invalid_limits", "limits 必须为 SnapshotLimits。")
    try:
        manifest, files = _selection(sources, path, selected_limits)
        digest = hashlib.sha256(_json(manifest)).hexdigest()
        store_fd = _store(path, create=True)
        try:
            _publish(store_fd, digest, manifest, files)
            return _verify(store_fd, path / digest, digest)
        finally:
            os.close(store_fd)
    except OSError as exc:
        _fail("snapshot_io_error", f"无法完整创建技能快照（系统错误 {exc.errno}）；链接、缺失目录或权限问题均不会跳过。")


def verify_snapshot(path: Path, expected_digest: str) -> SkillSnapshot:
    """Re-read every file and exact entry before the supervisor scans/mounts it."""
    _linux()
    path = _absolute(path)
    if (type(expected_digest) is not str or not _DIGEST.fullmatch(expected_digest)
            or path.name != expected_digest):
        _fail("invalid_digest", "须提供主机保存的完整 SHA-256，并使用对应的快照目录。")
    try:
        store_fd = _store(path.parent, create=False)
        try:
            return _verify(store_fd, path, expected_digest)
        finally:
            os.close(store_fd)
    except OSError as exc:
        _fail("snapshot_io_error", f"无法完整验证技能快照（系统错误 {exc.errno}）；本次不启用技能。")
