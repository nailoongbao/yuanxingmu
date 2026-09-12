#!/usr/bin/python3 -I
"""Verified, foreground entry point copied verbatim into an installation."""

import os
import sys

# A direct executable invocation is isolated by the shebang. Also handle users
# explicitly running ``python3 open-yuanxingmu`` before importing the runtime.
if __name__ == "__main__" and sys.platform.startswith("linux") and not sys.flags.isolated:
    os.execv("/usr/bin/python3", ["/usr/bin/python3", "-I", "-B", os.path.abspath(__file__), *sys.argv[1:]])

import argparse
from contextlib import contextmanager
import errno
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import signal
import socket
import stat
import subprocess
import threading
import webbrowser


INSTALLER_VERSION = "0.4.0a2"
RUNTIME_VERSION = "0.7.0a2"
HASH = re.compile(r"[0-9a-f]{64}")
DEFAULT_PORT = 18910


class LauncherError(RuntimeError):
    """An actionable startup refusal, without exposing runtime credentials."""


def _ordinary(path, *, directory=False, private=False, system_owner=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    owners = {os.getuid(), 0} if system_owner else {os.getuid()}
    if not expected(info.st_mode) or info.st_uid not in owners:
        raise LauncherError("安装文件的类型或所属用户不符，请保留目录并检查安装记录。")
    mode = stat.S_IMODE(info.st_mode)
    if private and mode != (0o700 if directory else 0o600):
        raise LauncherError("安装目录应仅供当前用户访问；目录权限须为 0700，安装记录须为 0600。")
    if mode & 0o022:
        raise LauncherError("安装文件允许其他用户修改，不能继续启动。")
    return info


def _relative_parts(value):
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise LauncherError("安装记录中的相对路径无效。")
    path = PurePosixPath(value)
    if path.is_absolute() or str(path) != value or any(part in {".", ".."} for part in path.parts):
        raise LauncherError("安装记录中的路径超出安装目录或含有路径别名。")
    if not path.parts:
        raise LauncherError("安装记录中的路径不能为空。")
    return path.parts


def _inside(root, value, *, directory=False):
    parts = _relative_parts(value)
    current = root
    for index, part in enumerate(parts):
        current = current / part
        _ordinary(current, directory=index < len(parts) - 1 or directory)
    if not current.resolve(strict=True).is_relative_to(root):
        raise LauncherError("安装文件已离开原来的安装目录。")
    return current


def _bwrap_path(value):
    if not isinstance(value, str) or not value.startswith("/") or "\0" in value:
        raise LauncherError("安装记录中的隔离程序路径无效。")
    path = Path(value)
    if str(path) != value or path.resolve(strict=True) != path:
        raise LauncherError("隔离程序路径不能包含符号链接或路径别名。")
    _ordinary(path, system_owner=True)
    if not os.access(path, os.X_OK):
        raise LauncherError("安装记录中的隔离程序不能执行。")
    return path


def _digest(path, *, system_owner=False):
    before = _ordinary(path, system_owner=system_owner)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise LauncherError("核对期间安装文件发生变化，请保留目录并重新检查。")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    if any(getattr(before, field) != getattr(after, field) for field in fields):
        raise LauncherError("核对期间安装文件发生变化，请保留目录并重新检查。")
    return before.st_size, digest


def hermes_runtime_files(root):
    """Inventory runtime source, built assets and the independent Python env.

    npm build dependencies are deliberately excluded. Hermes's official TUI
    build is self-contained; Python and web files are checked in full.
    """
    required = {"hermes/" + name for name in (
        "env/bin/python", "env/pyvenv.cfg", "source/pyproject.toml", "source/uv.lock",
        "source/package.json", "source/package-lock.json", "source/hermes_cli/__init__.py",
        "source/hermes_cli/main.py", "source/hermes_cli/web_server.py",
        "source/hermes_cli/web_dist/index.html", "source/ui-tui/dist/entry.js",
        "source/agent/terminal_env_provider.py", "source/tools/environments/base.py")}
    for location in ("hermes/source", "hermes/env"):
        base = _inside(root, location, directory=True)
        for directory, directories, names in os.walk(base, followlinks=False):
            for name in list(directories):
                path = Path(directory) / name
                relative = path.relative_to(root).as_posix()
                if relative == "hermes/env/lib64" and path.is_symlink():
                    if os.readlink(path) != "lib":
                        raise LauncherError("Hermes 虚拟环境的 lib64 链接发生变化。")
                    directories.remove(name)
                    continue
                _ordinary(path, directory=True)
                if name == "node_modules" and location == "hermes/source":
                    directories.remove(name)
            for name in names:
                path = Path(directory) / name
                _ordinary(path)
                required.add(path.relative_to(root).as_posix())
    for name in required:
        _inside(root, name)
    if not os.access(root / "hermes/env/bin/python", os.X_OK):
        raise LauncherError("Hermes 独立 Python 不能执行。")
    return required


def _verify_installation(launcher):
    _ordinary(launcher)
    root = launcher.resolve(strict=True).parent
    root_info = _ordinary(root, directory=True, private=True)
    marker_path = root / "INSTALLATION.json"
    marker_info = _ordinary(marker_path, private=True)
    if marker_info.st_size > 16 * 1024 * 1024:
        raise LauncherError("安装记录大小异常，不能继续启动。")
    descriptor = os.open(marker_path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
        opened = os.fstat(stream.fileno())
        if (marker_info.st_dev, marker_info.st_ino) != (opened.st_dev, opened.st_ino):
            raise LauncherError("核对期间安装记录发生变化。")
        marker = json.load(stream)
    if not isinstance(marker, dict):
        raise LauncherError("安装记录无效，请保留目录并检查安装结果。")
    if (type(marker.get("schema_version")) is not int or marker["schema_version"] != 1
            or marker.get("installer_version") != INSTALLER_VERSION
            or marker.get("runtime_version") != RUNTIME_VERSION):
        raise LauncherError("安装记录与这个启动入口的版本不一致，请使用原来的启动入口。")
    if marker.get("status") != "complete":
        raise LauncherError("这次安装还没有完成，请重新运行原来的安装器。")
    identity = marker.get("root_identity")
    if (not isinstance(identity, list) or len(identity) != 2
            or any(type(value) is not int for value in identity)
            or identity != [root_info.st_dev, root_info.st_ino]):
        raise LauncherError("安装目录已被替换或复制，请保留原目录，不能自动接管。")
    install_id = marker.get("install_id")
    if not isinstance(install_id, str) or not re.fullmatch(r"[0-9a-f]{32}", install_id):
        raise LauncherError("安装记录缺少有效的安装标识。")
    launcher_hash = marker.get("launcher_sha256")
    if not isinstance(launcher_hash, str) or not HASH.fullmatch(launcher_hash):
        raise LauncherError("安装记录缺少启动入口的文件校验。")
    if _digest(launcher)[1] != launcher_hash:
        raise LauncherError("启动入口与安装时的文件不同，不能继续启动。")
    paths, files = marker.get("paths"), marker.get("files")
    if not isinstance(paths, dict) or not isinstance(files, dict) or not files:
        raise LauncherError("安装记录缺少运行路径或文件校验。")
    try:
        app = _inside(root, paths["app"], directory=True)
        node = _inside(root, paths["node"])
        openclaw = _inside(root, paths["openclaw"], directory=True)
        bwrap = _bwrap_path(paths["bwrap"])
    except KeyError as exc:
        raise LauncherError("安装记录中的运行路径不完整。") from exc
    if not os.access(node, os.X_OK):
        raise LauncherError("安装记录中的 Node.js 不能执行。")
    hermes_python = hermes_source = None
    components = marker.get("components", {})
    features = marker.get("features", [])
    if features not in ([], ["hermes"]) or ("hermes" in components) != ("hermes" in features):
        raise LauncherError("安装记录中的 Hermes 组件和功能不一致。")
    required = {paths["node"], paths["openclaw"] + "/package.json",
                paths["openclaw"] + "/openclaw.mjs", "bwrap:" + str(bwrap)}
    if "hermes" in features:
        if (components.get("hermes") != "complete" or paths.get("hermes_python") != "hermes/env/bin/python"
                or paths.get("hermes_source") != "hermes/source"):
            raise LauncherError("安装记录中的 Hermes 运行路径不完整。")
        hermes_python = _inside(root, paths["hermes_python"])
        hermes_source = _inside(root, paths["hermes_source"], directory=True)
        required |= hermes_runtime_files(root) | {"hermes/SOURCE.json", "hermes/build-constraints.txt", "hermes/uv.toml"}
    for directory, directories, names in os.walk(app, followlinks=False):
        for name in directories:
            _ordinary(Path(directory) / name, directory=True)
        for name in names:
            path = Path(directory) / name
            _ordinary(path)
            required.add(path.relative_to(root).as_posix())
    required.update(paths["app"] + "/" + name for name in (
        "yuanxingmu/__init__.py", "yuanxingmu/dashboard/__init__.py",
        "yuanxingmu/dashboard/server.py", "yuanxingmu/dashboard/web/index.html",
        "yuanxingmu/dashboard/web/app.js", "yuanxingmu/dashboard/web/styles.css",
        "yuanxingmu/dashboard/web/mark.svg"))
    if not required.issubset(files):
        raise LauncherError("安装记录没有覆盖全部运行文件，不能继续启动。")
    for name, record in files.items():
        if not isinstance(name, str) or not isinstance(record, dict):
            raise LauncherError("安装记录中的文件校验无效。")
        size, digest = record.get("bytes"), record.get("sha256")
        if type(size) is not int or size < 0 or not isinstance(digest, str) or not HASH.fullmatch(digest):
            raise LauncherError("安装记录中的文件校验无效。")
        system_owner = name == "bwrap:" + str(bwrap)
        path = bwrap if system_owner else _inside(root, name)
        if _digest(path, system_owner=system_owner) != (size, digest):
            raise LauncherError("安装文件与安装时的记录不同，不能继续启动。请保留目录和已有工作。")
    return root, app, node, openclaw, bwrap, hermes_python, hermes_source


@contextmanager
def _launch_lock(root):
    import fcntl

    path = root / ".launcher.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise LauncherError("启动记录的文件类型或权限异常，请保留目录并检查。")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LauncherError("这个工作台已经打开。请回到原来的浏览器或终端窗口；无需重复启动。") from exc
        yield
    finally:
        os.close(descriptor)


def _port(value):
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise argparse.ArgumentTypeError("端口须为 1024–65535 的整数，且不能使用 18701。") from exc
    if not 1024 <= port <= 65535 or port == 18701:
        raise argparse.ArgumentTypeError("端口须为 1024–65535 的整数，且不能使用 18701。")
    return port


def _check_port(port):
    # This early check avoids creating a workbench for an already occupied port.
    # make_server remains authoritative if a listener appears after this check.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        # Match HTTPServer's reuse setting so recent closed HTTP connections do
        # not prevent an immediate reopen. A live listener still refuses bind.
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(("127.0.0.1", port))


def _is_wsl():
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        return False


def _open_browser(url):
    try:
        if webbrowser.open(url, new=2):
            return
    except Exception:
        pass
    explorer = Path("/mnt/c/Windows/explorer.exe")
    if _is_wsl() and explorer.is_file():
        try:
            # A fixed executable and one loopback URL argument; no shell or
            # management token written into a shortcut or credential file.
            subprocess.Popen([str(explorer), url], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
            return
        except OSError:
            pass
    print("未能自动打开浏览器。请把上方完整链接复制到这台电脑的浏览器。", flush=True)


def _stop_requested(signum, frame):
    raise KeyboardInterrupt


def _make_server(manager):
    # Called only after the installed app has passed verification and been loaded.
    from yuanxingmu.dashboard.server import Server

    class WorkbenchHTTPServer(Server):
        # The standalone launcher is intended to reopen immediately after exit.
        # SO_REUSEADDR permits old closed connections, never a second listener.
        allow_reuse_address = True

    return WorkbenchHTTPServer(manager)


def _serve(app, root, node, openclaw, bwrap, *, port, open_browser, hermes_python=None, hermes_source=None):
    if any(name == "yuanxingmu" or name.startswith("yuanxingmu.") for name in sys.modules):
        raise LauncherError("当前 Python 已载入其他元星木程序，请直接运行安装目录中的启动入口。")
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(app))
    import yuanxingmu
    from yuanxingmu.dashboard.server import APIError, Runtime, Workbench

    if yuanxingmu.__version__ != RUNTIME_VERSION:
        raise LauncherError("安装的程序版本与启动入口不一致，不能继续启动。")

    runtime = (Runtime(node, openclaw, bwrap, hermes_python, hermes_source)
               if hermes_python is not None else Runtime(node, openclaw, bwrap))
    readiness = runtime.public()
    if readiness.get("available") is not True:
        raise LauncherError(readiness.get("reason") or "运行环境或隔离检查未通过，不能打开工作台。")
    if hermes_python is not None and runtime.hermes_public().get("available") is not True:
        raise LauncherError("Hermes 运行环境或隔离检查未通过，不能打开工作台。")
    manager = server = None
    watched = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    previous = {signum: signal.signal(signum, _stop_requested) for signum in watched}
    try:
        try:
            manager = Workbench(root / "workbench", runtime, port=port)
        except BlockingIOError as exc:
            raise LauncherError("这份工作台数据已由另一个窗口使用。请回到原窗口，不能同时打开第二个管理程序。") from exc
        except APIError as exc:
            raise LauncherError(exc.message) from exc
        if manager.runtime_status.get("available") is not True:
            raise LauncherError(manager.runtime_status.get("reason") or "运行环境检查未通过，不能打开工作台。")
        server = _make_server(manager)
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", manager.token):
            raise LauncherError("工作台没有生成有效的管理链接，不能继续启动。")
        url = f"http://127.0.0.1:{port}/#access={manager.token}"
        if server.origin != f"http://127.0.0.1:{port}":
            raise LauncherError("工作台监听位置与请求的位置不符，不能继续启动。")
        print("元星木工作台已打开。以下管理链接请只供自己使用：", flush=True)
        print(url, flush=True)
        print("请保留此终端。若浏览器没有打开，请复制上方完整链接。", flush=True)
        print("关闭终端或浏览器不会停止已经运行的 AI。请先在页面点击“暂时关闭”，再退出工作台。", flush=True)
        if open_browser:
            try:
                threading.Thread(target=_open_browser, args=(url,), name="yuanxingmu-browser", daemon=True).start()
            except RuntimeError:
                print("未能自动打开浏览器，请复制上方完整链接。", flush=True)
        server.serve_forever(poll_interval=.25)
    except KeyboardInterrupt:
        print("正在关闭工作台，等待已提交的操作完成。已经运行的 AI 仍需在页面中单独关闭。", flush=True)
    finally:
        # A second terminal signal must not interrupt accepted operation cleanup.
        for signum in watched:
            signal.signal(signum, signal.SIG_IGN)
        try:
            try:
                if server is not None:
                    server.server_close()
            finally:
                if manager is not None:
                    manager.close()
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="打开元星木本地工作台；使用期间请保留此终端。")
    parser.add_argument("--port", type=_port, default=DEFAULT_PORT, help="本机管理端口，默认 18910")
    parser.add_argument("--no-browser", action="store_true", help="仅输出真实管理链接，不自动打开浏览器")
    args = parser.parse_args(argv)
    try:
        if not sys.platform.startswith("linux") or sys.version_info < (3, 12):
            raise LauncherError("请在 Ubuntu / WSL 中使用系统 Python 3.12 或更新版本打开工作台。")
        if os.getuid() == 0 or not Path(sys.executable).resolve(strict=True).is_relative_to("/usr"):
            raise LauncherError("请用安装时的普通用户和系统 Python 打开工作台，不要使用 sudo。")
        launcher = Path(__file__).absolute()
        print("正在核对安装文件和运行环境，请稍候。", flush=True)
        root, app, node, openclaw, bwrap, hermes_python, hermes_source = _verify_installation(launcher)
        with _launch_lock(root):
            _check_port(args.port)
            return _serve(app, root, node, openclaw, bwrap, port=args.port, open_browser=not args.no_browser,
                          hermes_python=hermes_python, hermes_source=hermes_source)
    except KeyboardInterrupt:
        print("已取消打开工作台；已有工作和权限记录仍然保留。", flush=True)
        return 130
    except OSError as exc:
        if exc.errno == errno.EADDRINUSE:
            message = "所选端口已被占用。请回到已打开的工作台，或检查占用情况；本程序不会接管其他服务。"
        else:
            message = "无法读取安装文件或打开本机服务。请保留安装目录，检查文件权限和安装记录。"
        print(message, file=sys.stderr, flush=True)
        return 2
    except (RuntimeError, ValueError, ImportError) as exc:
        message = str(exc) if isinstance(exc, LauncherError) else "安装记录或程序文件无效，请保留目录并检查安装结果。"
        print(message, file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
