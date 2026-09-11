"""Linux execution boundary built from bubblewrap, never an unsandboxed fallback.

The host must own the executable, workspace choice, read-only grants and explicit
environment. Do not accept those grants from an agent or pass ``os.environ``.
Only the command itself is untrusted. The returned argv is the exact mount and
environment record; launch it without a shell, with ``close_fds=True``, a small
host environment and ``start_new_session=True``. On cancellation, kill that
launcher process group and wait for the launcher. ``--die-with-parent`` and a
task process running as PID 1 also terminate descendants in its PID namespace.

This shares the host kernel and does not supply CPU, memory or disk quotas.
It does not inspect permissions inside the broker: that is the broker's job.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys


WORKSPACE_PATH = Path("/workspace")
BROKER_SOCKET_PATH = Path("/run/yuanxingmu/broker.sock")


class SandboxUnavailable(RuntimeError):
    """The required Linux isolation is unavailable; callers must stop."""


def _require_linux() -> None:
    if not sys.platform.startswith("linux"):
        raise SandboxUnavailable(
            "Yuanxingmu requires Linux and bubblewrap. Windows is unsupported; "
            "there is no unsandboxed fallback. Run the Linux host inside WSL."
        )


def _bwrap_path(value: Path | None) -> Path:
    _require_linux()
    candidate = value or shutil.which("bwrap", path="/usr/bin:/bin")
    if not candidate:
        raise SandboxUnavailable("bubblewrap was not found; supply its trusted absolute path")
    path = Path(candidate)
    if not path.is_absolute():
        raise ValueError("bwrap must be an absolute path selected by the trusted host")
    try:
        path = path.resolve(strict=True)
        mode = path.stat().st_mode
    except OSError as exc:
        raise SandboxUnavailable(f"bubblewrap is unavailable: {exc}") from exc
    if not stat.S_ISREG(mode) or not os.access(path, os.X_OK):
        raise SandboxUnavailable("bubblewrap must be an executable regular file")
    if mode & (stat.S_ISUID | stat.S_ISGID):
        raise SandboxUnavailable("setuid/setgid bubblewrap is unsupported by this profile")
    return path


def _source_path(value: Path, name: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise ValueError(f"{name} must be an absolute host path")
    try:
        return path.resolve(strict=True)
    except OSError as exc:
        raise ValueError(f"{name} must exist: {exc}") from exc


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _reject_broad_grant(path: Path, name: str) -> None:
    broad = {
        Path("/"), Path("/home"), Path("/root"), Path.home().resolve(),
        Path("/mnt"), Path("/media"), Path("/etc"), Path("/var"),
        Path("/run"), Path("/tmp"), Path("/proc"), Path("/sys"), Path("/dev"),
        Path("/usr"), Path("/bin").resolve(), Path("/sbin").resolve(),
        Path("/lib").resolve(), Path("/lib64").resolve(),
    }
    # In WSL, a drive root or Windows profile is still a broad host grant.
    parts = path.parts
    wsl_root = len(parts) == 3 and parts[1] == "mnt"
    wsl_home = (
        len(parts) in (4, 5) and parts[1] == "mnt"
        and parts[3].lower() == "users"
    )
    if path in broad or path.parent == Path("/home") or wsl_root or wsl_home:
        raise ValueError(f"{name} must be a specific task resource, not {path}")


def _isolation_args() -> list[str]:
    return [
        "--unshare-user", "--unshare-pid", "--unshare-net", "--unshare-ipc",
        "--unshare-uts", "--hostname", "yuanxingmu", "--disable-userns",
        "--cap-drop", "ALL", "--new-session", "--die-with-parent",
        "--as-pid-1", "--clearenv",
    ]


def _system_mount_args() -> list[str]:
    # These are OS runtime trees, not the host root, /etc or a user's home.
    if not Path("/usr").is_dir():
        raise SandboxUnavailable("this profile requires a Linux /usr runtime tree")
    args = ["--ro-bind", "/usr", "/usr"]
    for name in ("bin", "sbin", "lib", "lib64"):
        source = Path("/") / name
        if source.is_symlink():
            target = source.resolve(strict=True)
            if not target.is_relative_to(Path("/usr")):
                raise SandboxUnavailable(f"unsupported system runtime symlink: {source}")
            args += ["--symlink", os.readlink(source), str(source)]
        elif source.is_dir():
            args += ["--ro-bind", str(source), str(source)]
    return args


def _environment_args(env: dict[str, str] | None) -> list[str]:
    fixed = {
        "HOME": "/tmp", "PATH": "/usr/bin:/bin", "PWD": str(WORKSPACE_PATH),
        "TMPDIR": "/tmp", "YUANXINGMU_BROKER_SOCKET": str(BROKER_SOCKET_PATH),
    }
    selected = {
        **fixed, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for key, value in (env or {}).items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise ValueError("environment names must be valid identifiers")
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError("environment values must be NUL-free strings")
        if key in fixed and value != fixed[key]:
            raise ValueError(f"{key} is fixed by the sandbox profile")
        selected[key] = value
    args: list[str] = []
    for key, value in sorted(selected.items()):
        args += ["--setenv", key, value]
    return args


def build_command(
    *,
    command: list[str],
    workspace: Path,
    broker_socket: Path,
    readonly_paths: list[Path] | None = None,
    env: dict[str, str] | None = None,
    bwrap: Path | None = None,
) -> list[str]:
    """Build a fail-closed bubblewrap argv for one task.

    ``workspace`` is the one writable host directory, mounted at /workspace.
    ``broker_socket`` must be an existing Unix socket outside that directory;
    only its inode is read-only bound to /run/yuanxingmu/broker.sock. A read-only
    socket mount permits connections; it does not authorize broker operations.
    ``readonly_paths`` are explicit trusted-host grants, resolved and mounted
    at their canonical absolute paths. Their exact source/destination appears
    in the returned argv. No surrounding directory is implicitly granted.

    Credentials are not inherited into the command. ``env`` contains only
    intentionally granted settings; its values also appear in the audit argv.
    An existing untrusted workspace must not contain sensitive host hardlinks
    or host-created submounts. Select grants before untrusted execution starts.
    """
    binary = _bwrap_path(bwrap)
    if not isinstance(command, list) or not command or any(
        not isinstance(arg, str) or "\x00" in arg for arg in command
    ) or not command[0]:
        raise ValueError("command must be a non-empty argv list of NUL-free strings")

    work = _source_path(workspace, "workspace")
    _reject_broad_grant(work, "workspace")
    if not work.is_dir():
        raise ValueError("workspace must be a directory")
    broker = _source_path(broker_socket, "broker_socket")
    if not stat.S_ISSOCK(broker.stat().st_mode):
        raise ValueError("broker_socket must be an existing Unix domain socket")
    if _overlaps(work, broker):
        raise ValueError("broker_socket must be outside the writable workspace")

    grants: list[Path] = []
    protected = (WORKSPACE_PATH, Path("/run"), Path("/proc"), Path("/dev"), Path("/sys"))
    for value in readonly_paths or []:
        source = _source_path(value, "readonly_paths entry")
        _reject_broad_grant(source, "readonly_paths entry")
        if not source.is_dir() and not source.is_file():
            raise ValueError("readonly_paths entries must be regular files or directories")
        if _overlaps(source, work) or _overlaps(source, broker):
            raise ValueError("read-only grants must not expose the workspace or broker parent")
        if any(_overlaps(source, target) for target in protected):
            raise ValueError("read-only grants must not overlap sandbox control mounts")
        if source not in grants:
            grants.append(source)

    args = [str(binary), *_isolation_args(), *_system_mount_args()]
    args += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for source in grants:
        args += ["--ro-bind", str(source), str(source)]
    args += ["--bind", str(work), str(WORKSPACE_PATH)]
    args += ["--ro-bind", str(broker), str(BROKER_SOCKET_PATH)]
    args += _environment_args(env)
    args += ["--chdir", str(WORKSPACE_PATH), "--remount-ro", "/", "--", *command]
    return args


def sandbox_available(*, bwrap: Path | None = None) -> dict[str, object]:
    """Report availability after a real, bounded namespace/mount smoke test.

    A false result is an instruction to stop, never permission to run directly.
    This checks this profile on this host, not arbitrary commands or brokers.
    """
    result: dict[str, object] = {
        "available": False, "platform": sys.platform, "bwrap": None,
        "version": None, "reason": None,
    }
    try:
        binary = _bwrap_path(bwrap)
        result["bwrap"] = str(binary)
        version = subprocess.run(
            [str(binary), "--version"], capture_output=True, text=True,
            timeout=5, check=True, env={"PATH": "/usr/bin:/bin"}, close_fds=True,
        )
        result["version"] = version.stdout.strip()
        probe = [str(binary), *_isolation_args(), *_system_mount_args()]
        probe += [
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--chdir", "/tmp", "--remount-ro", "/", "--", "/usr/bin/true",
        ]
        completed = subprocess.run(
            probe, capture_output=True, text=True, timeout=5,
            env={"PATH": "/usr/bin:/bin"}, close_fds=True, start_new_session=True,
        )
        if completed.returncode:
            raise SandboxUnavailable(completed.stderr.strip() or f"bubblewrap exited {completed.returncode}")
        result["available"] = True
        result["reason"] = "Linux namespace and read-only runtime smoke test passed"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result["reason"] = str(exc)
    return result
