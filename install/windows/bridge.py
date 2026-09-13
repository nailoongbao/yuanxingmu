"""Static, offline WSL bridge. Its stdout is a bounded JSON-lines protocol."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading

MESSAGES = {
    "unsupported_environment": "请使用支持的 Linux 和系统 Python 3.12。",
    "root_user": "请改用安装时的普通用户打开工作台。",
    "invalid_arguments": "启动参数无效。",
    "install_invalid": "安装记录或程序文件无效，请检查原安装。",
    "invalid_control": "关闭请求无效，正在清理本次工作台。",
    "already_running": "工作台已经打开，请回到原窗口。",
    "port_in_use": "本机端口已被占用，请检查原窗口。",
    "startup_failed": "工作台未能启动，请检查原安装。",
    "launcher_failed": "工作台未正常退出，请检查原安装。",
}
MAX_CONTROL = 256
MAX_LINE = 2048


class BridgeError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def event(value):
    data = (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def error(code):
    return {"event": "error", "code": code, "message": MESSAGES[code]}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def ready_url(raw, port):
    pattern = rb"http://127\.0\.0\.1:" + str(port).encode("ascii") + rb"/#access=[A-Za-z0-9_-]{32,128}\r?\n"
    if len(raw) <= MAX_LINE and re.fullmatch(pattern, raw):
        return raw.rstrip(b"\r\n").decode("ascii")
    return None


def control_command(raw):
    if raw == b"":
        return None
    try:
        if len(raw) > MAX_CONTROL or not raw.endswith(b"\n") or b"\n" in raw[:-1]:
            raise ValueError("invalid line")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
        if type(value) is not dict or value != {"command": "stop"}:
            raise ValueError("invalid command")
    except (ValueError, UnicodeError):
        raise BridgeError("invalid_control") from None
    return "stop"


def ordinary(path, uid, *, directory=False, private=False):
    info = path.lstat()
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022:
        raise BridgeError("install_invalid")
    if private and stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600):
        raise BridgeError("install_invalid")
    return info


def read_owned(path, uid, limit, *, private=False):
    before = ordinary(path, uid, private=private)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or opened.st_size > limit:
            raise BridgeError("install_invalid")
        content = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if len(content) > limit or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise BridgeError("install_invalid")
    return content


def validate_candidate(root, home, uid, check_launcher=False):
    try:
        root, home = Path(root), Path(home)
        if any(len(str(path).encode("utf-8")) > 1024 for path in (root, home)):
            raise BridgeError("install_invalid")
        if not root.is_absolute() or not home.is_absolute() or root == home:
            raise BridgeError("install_invalid")
        if root.resolve(strict=True) != root or home.resolve(strict=True) != home:
            raise BridgeError("install_invalid")
        parts = root.relative_to(home).parts
        if not parts or any(part in (".", "..") for part in parts):
            raise BridgeError("install_invalid")
        current = home
        ordinary(current, uid, directory=True)
        for part in parts:
            current = current / part
            ordinary(current, uid, directory=True)
        info = ordinary(root, uid, directory=True, private=True)
        marker = json.loads(read_owned(root / "INSTALLATION.json", uid, 16 * 1024 * 1024, private=True),
                            object_pairs_hook=unique_object)
        if (type(marker) is not dict or type(marker.get("schema_version")) is not int
                or marker["schema_version"] != 1 or marker.get("installer_version") != "0.4.0a2"
                or marker.get("runtime_version") != "0.7.0a2" or marker.get("status") != "complete"):
            raise BridgeError("install_invalid")
        identity = marker.get("root_identity")
        if (type(identity) is not list or len(identity) != 2 or any(type(n) is not int for n in identity)
                or identity != [info.st_dev, info.st_ino]):
            raise BridgeError("install_invalid")
        if (not isinstance(marker.get("install_id"), str)
                or not re.fullmatch(r"[0-9a-f]{32}", marker["install_id"])
                or not isinstance(marker.get("launcher_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", marker["launcher_sha256"])):
            raise BridgeError("install_invalid")
        if check_launcher:
            launcher = read_owned(root / "open-yuanxingmu", uid, 1024 * 1024)
            if hashlib.sha256(launcher).hexdigest() != marker["launcher_sha256"]:
                raise BridgeError("install_invalid")
        return root
    except BridgeError:
        raise
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        raise BridgeError("install_invalid") from None


def discover(home, uid):
    candidates = []
    for name in ("yuanxingmu-v07a2", "yuanxingmu"):
        try:
            root = validate_candidate(Path(home) / name, home, uid)
            candidates.append({"root": str(root), "label": "元星木 0.7.0a2 · " + name})
        except BridgeError:
            pass
    return candidates


def context():
    if not sys.platform.startswith("linux") or sys.version_info < (3, 12):
        raise BridgeError("unsupported_environment")
    if os.getuid() == 0:
        raise BridgeError("root_user")
    import pwd
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        if len(str(home).encode("utf-8")) > 1024 or not home.is_absolute() or home.resolve(strict=True) != home:
            raise ValueError("invalid home")
        ordinary(home, os.getuid(), directory=True)
        return home, os.getuid()
    except (OSError, ValueError, KeyError, BridgeError):
        raise BridgeError("unsupported_environment") from None


def classify(raw):
    for code, phrases in (
        ("already_running", ("这个工作台已经打开", "这份工作台数据已由另一个窗口使用")),
        ("port_in_use", ("端口已被占用", "端口正在使用")),
        ("install_invalid", ("安装记录", "安装文件", "启动入口", "运行环境", "隔离检查")),
    ):
        if any(phrase.encode("utf-8") in raw for phrase in phrases):
            return code
    return None


def supervise(command, port, control, emit_event=event, *, cwd=None):
    """No shell, raw-output forwarding, timed kill, or distribution-wide stop."""
    stop, wake = threading.Event(), threading.Event()
    lock = threading.Lock()
    shared = {"url": None, "failure": None, "control_error": None}
    process = None
    terminated = ready = reported_control = disconnected = False
    readers, previous = [], {}

    def send(value):
        nonlocal disconnected
        if not disconnected:
            try:
                emit_event(value)
            except (OSError, ValueError):
                disconnected = True
                stop.set()

    def controls():
        try:
            control_command(control.readline(MAX_CONTROL + 1))
        except (BridgeError, OSError, ValueError):
            with lock:
                shared["control_error"] = "invalid_control"
        finally:
            stop.set()
            wake.set()

    def output(stream, is_stdout):
        dropping = False
        try:
            while True:
                raw = stream.readline(MAX_LINE + 1)
                if not raw:
                    break
                full = raw.endswith(b"\n")
                if dropping or len(raw) > MAX_LINE:
                    dropping = not full
                    continue
                if not full:
                    dropping = True
                    continue
                url = ready_url(raw, port) if is_stdout else None
                failure = classify(raw) if not is_stdout else None
                with lock:
                    if url and shared["url"] is None:
                        shared["url"] = url
                    if failure and shared["failure"] is None:
                        shared["failure"] = failure
                wake.set()
        except (OSError, ValueError):
            pass
        finally:
            wake.set()

    def terminate_owned():
        nonlocal terminated
        if not terminated and process is not None:
            terminated = True
            # An unreaped live group leader prevents its PID being reused here.
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass

    try:
        if threading.current_thread() is threading.main_thread():
            for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                previous[number] = signal.signal(number, lambda *_: (stop.set(), wake.set()))
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, close_fds=True, cwd=cwd)
        for stream, is_stdout in ((process.stdout, True), (process.stderr, False)):
            worker = threading.Thread(target=output, args=(stream, is_stdout), daemon=True)
            readers.append(worker)
            worker.start()
        threading.Thread(target=controls, daemon=True).start()
        send({"event": "status", "message": "正在打开元星木工作台。"})
        while True:
            with lock:
                url, control_error = shared["url"], shared["control_error"]
            if control_error and not reported_control:
                send(error(control_error))
                reported_control = True
            if stop.is_set() and not terminated:
                send({"event": "status", "message": "正在关闭工作台，请等待已提交的操作完成。"})
                terminate_owned()
            if url and not ready and not stop.is_set():
                send({"event": "ready", "url": url})
                ready = True
            if process.poll() is not None:
                break
            wake.wait(.05)
            wake.clear()
        for worker in readers:
            worker.join(.2)
        code = process.wait()
        with lock:
            control_error, failure = shared["control_error"], shared["failure"]
        if control_error:
            if not reported_control:
                send(error(control_error))
            code = 2
        elif code != 0:
            send(error(failure or ("launcher_failed" if ready or terminated else "startup_failed")))
        elif not ready and not terminated:
            send(error(failure or "startup_failed"))
            code = 2
    except Exception:
        send(error("startup_failed"))
        code = 2
    finally:
        if process is not None:
            terminate_owned()
            process.wait()  # Accepted work may take arbitrarily long to clean up.
            for stream, worker in zip((process.stdout, process.stderr), readers):
                if not worker.is_alive():
                    stream.close()
        for number, handler in previous.items():
            signal.signal(number, handler)
    send({"event": "stopped", "exit_code": code})
    return code if code >= 0 else 128 - code


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        home, uid = context()
        if args == ["probe"]:
            event({"event": "probe", "home": str(home), "candidates": discover(home, uid)})
            event({"event": "stopped", "exit_code": 0})
            return 0
        if len(args) != 3 or args[0] != "start" or not re.fullmatch(r"[0-9]{4,5}", args[2]):
            raise BridgeError("invalid_arguments")
        port = int(args[2])
        if not 1024 <= port <= 65535 or port == 18701:
            raise BridgeError("invalid_arguments")
        root = validate_candidate(args[1], home, uid, check_launcher=True)
        command = ["/usr/bin/python3", "-I", "-B", str(root / "open-yuanxingmu"),
                   "--no-browser", "--port", str(port)]
        return supervise(command, port, sys.stdin.buffer, cwd=str(root))
    except BridgeError as exc:
        event(error(exc.code))
    except Exception:
        event(error("startup_failed"))
    event({"event": "stopped", "exit_code": 2})
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BrokenPipeError, OSError):
        # The GUI may disappear during probe; never print a traceback to it.
        os._exit(2)
