"""Host-supervised SDK sessions sharing an existing native profile's authority.

This entry is deliberately separate from the native WebUI. It requires a
stopped, verified OpenClaw/Hermes profile with layered defenses. SDK code is
never imported into this host process. Its full process tree runs in bubblewrap.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socketserver
import stat
import subprocess
import threading
import time
import uuid

from . import openclaw as host
from .broker import Broker
from .gateway_network import HostModel, _private_directory
from .model_output import ModelOutputGuard, _object
from .protection import profile_services
from .run import load_policy
from .sandbox import BROKER_SOCKET_PATH, MODEL_SOCKET_PATH, _overlaps, _reject_broad_grant, sandbox_available
from .worker import start, stop


MAX_OUTPUT = 512 * 1024
MAX_PROMPT = 64 * 1024
SDK_VERSION = "1.26.0"
SDK_TOOLS = ["yuanxingmu_read", "yuanxingmu_describe", "yuanxingmu_action_targets",
             "yuanxingmu_propose_action", "yuanxingmu_draft_email"]
_BOOTSTRAP = ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
              "from yuanxingmu.adapters.smolagents_runtime import main; raise SystemExit(main())")
_SDK_RUNTIMES = {
    "smolagents": {
        "version": SDK_VERSION,
        "packages": (("smolagents", SDK_VERSION),),
        "bootstrap": _BOOTSTRAP,
        "answer_tools": ("final_answer",),
    },
    "langgraph": {
        "version": "1.2.11",
        "packages": (("langgraph", "1.2.11"), ("langgraph_prebuilt", "1.1.0"),
                     ("langgraph_checkpoint", "4.2.0"), ("langchain_core", "1.6.2"),
                     ("pydantic", "2.13.5")),
        "bootstrap": ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
                      "from yuanxingmu.adapters.langgraph_runtime import main; raise SystemExit(main())"),
        "answer_tools": (),
    },
    "openai_agents": {
        "version": "0.22.2",
        "packages": (("openai_agents", "0.22.2"), ("openai", "3.13.0"),
                     ("pydantic", "2.13.5")),
        "bootstrap": ("import sys; sys.path.insert(0, sys.argv.pop(1)); "
                      "from yuanxingmu.adapters.openai_agents_runtime import main; raise SystemExit(main())"),
        "answer_tools": (),
        "handoff_tools": ("yuanxingmu_handoff_to_executor",),
    },
}


def _sdk(framework: str) -> dict:
    # Names select trusted, fixed entry points, never arbitrary Python modules.
    if type(framework) is not str or framework not in _SDK_RUNTIMES:
        raise ValueError("sdk_framework_not_supported")
    return _SDK_RUNTIMES[framework]


def _read_private(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > maximum):
            raise ValueError("sdk_private_file_invalid")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("sdk_private_file_too_large")
        return raw
    finally:
        os.close(fd)


def _save_new(path: Path, value: dict) -> None:
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, allow_nan=False) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _python_runtime(value: Path, profile: Path, *, framework: str = "smolagents") -> tuple[Path, Path]:
    """Inspect files only; do not execute a dependency in the trusted host."""
    definition = _sdk(framework)
    raw = Path(value).absolute()
    if raw.parent.name != "bin":
        raise ValueError("sdk_python_requires_dedicated_venv")
    venv = raw.parent.parent.resolve(strict=True)
    python = venv / "bin" / raw.name
    _reject_broad_grant(venv, "SDK runtime")
    if _overlaps(venv, profile) or not (venv / "pyvenv.cfg").is_file():
        raise ValueError("sdk_venv_must_be_outside_profile")
    if not python.is_file() or not os.access(python, os.X_OK):
        raise ValueError("sdk_python_not_executable")
    if not python.resolve(strict=True).is_relative_to(Path("/usr")):
        raise ValueError("sdk_venv_requires_system_python")
    for package, expected in definition["packages"]:
        metadata = list(venv.glob("lib/python*/site-packages/" + package + "-*.dist-info/METADATA"))
        if len(metadata) != 1 or metadata[0].stat().st_size > 256 * 1024:
            raise ValueError("sdk_" + framework + "_version_not_verified")
        fields = metadata[0].read_text(encoding="utf-8").split("\n\n", 1)[0].splitlines()
        if [line for line in fields if line.startswith("Version:")] != ["Version: " + expected]:
            if framework == "smolagents":
                raise ValueError("sdk_requires_smolagents_1_26_0")
            raise ValueError("sdk_requires_pinned_" + framework + "_packages")
    return python, venv


def _session(profile: Path, manifest: dict, name: str, python: Path, *, resume: bool,
             framework: str = "smolagents") -> tuple[Path, dict]:
    definition = _sdk(framework)
    if type(name) is not str or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}", name) is None:
        raise ValueError("sdk_session_name_invalid")
    parent = profile / "sdk-sessions"
    if not parent.exists():
        parent.mkdir(mode=0o700)
    _private_directory(parent)
    folder = parent / name
    binding = {"version": 1, "framework": framework, "task_id": manifest["task_id"],
               "family_id": manifest["family_id"], "python": str(python), "sdk_version": definition["version"]}
    if resume:
        _private_directory(folder)
        value = _object(_read_private(folder / "session.json", 8192))
        if (type(value) is not dict or set(value) != set(binding) | {"session_id"}
                or any(value.get(key) != item for key, item in binding.items())
                or type(value.get("session_id")) is not str
                or re.fullmatch(r"[a-f0-9]{32}", value["session_id"]) is None):
            raise ValueError("sdk_session_binding_changed")
    else:
        # A partial creation or an existing session is never silently reset.
        folder.mkdir(mode=0o700)
        value = {**binding, "session_id": uuid.uuid4().hex}
        _save_new(folder / "session.json", value)
    return folder, value


class _SdkOutputGuard:
    def __init__(self, broker: Broker, task_id: str, model_id: str, max_tokens: int, *, automatic_actions=False,
                 framework: str = "smolagents"):
        definition = _sdk(framework)
        self.guard = ModelOutputGuard(broker, task_id)
        self.model_id, self.max_tokens = model_id, max_tokens
        self.tool_names = {*SDK_TOOLS, *definition["answer_tools"], *definition.get("handoff_tools", ())}
        if automatic_actions:
            self.tool_names.add("yuanxingmu_request_action")

    def preflight(self, raw: bytes):
        notice = self.guard.preflight(raw)
        if notice is not None:
            return notice
        value = _object(raw)
        allowed = {"model", "messages", "tools", "tool_choice", "max_tokens", "temperature",
                   "stop", "stream", "n", "parallel_tool_calls"}
        if (type(value) is not dict or set(value) - allowed or value.get("model") != self.model_id
                or value.get("stream", False) is not False or type(value.get("n", 1)) is not int
                or value.get("n", 1) != 1 or type(value.get("max_tokens")) is not int
                or not 1 <= value["max_tokens"] <= self.max_tokens
                or type(value.get("messages")) is not list or not value["messages"]):
            raise ValueError("sdk_model_request_not_allowed")
        if type(value.get("tools", [])) is not list:
            raise ValueError("sdk_model_tools_invalid")
        for tool in value.get("tools", []):
            if (type(tool) is not dict or set(tool) != {"type", "function"}
                    or tool["type"] != "function" or type(tool["function"]) is not dict
                    or type(tool["function"].get("name")) is not str
                    or tool["function"].get("name") not in self.tool_names):
                raise ValueError("sdk_remote_tools_not_allowed")
        return None

    def __call__(self, raw: bytes, content_type: str) -> bytes:
        return self.guard(raw, content_type)


def _collect(process, cancelled: threading.Event, timeout: int) -> tuple[int, bytes]:
    """Bound both pipes without printing unreviewed worker or dependency text."""
    selector = selectors.DefaultSelector()
    output = bytearray()
    size = 0
    deadline = time.monotonic() + timeout
    try:
        for stream in (process.stdout, process.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            if cancelled.is_set():
                raise RuntimeError("sdk_cancelled")
            if time.monotonic() >= deadline:
                raise RuntimeError("sdk_execution_timeout")
            for key, _ in selector.select(.1):
                chunk = os.read(key.fd, 64 * 1024)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                size += len(chunk)
                if size > MAX_OUTPUT:
                    raise RuntimeError("sdk_worker_output_limit")
                if key.fileobj is process.stdout:
                    output.extend(chunk)
        # A child can close both pipes while continuing to run. Cancellation
        # must remain responsive even then; do not block in one long wait().
        while process.poll() is None:
            if cancelled.is_set():
                raise RuntimeError("sdk_cancelled")
            if time.monotonic() >= deadline:
                raise RuntimeError("sdk_execution_timeout")
            try:
                process.wait(timeout=.1)
            except subprocess.TimeoutExpired:
                pass
        return process.returncode, bytes(output)
    finally:
        try:
            stop(process)
        finally:
            selector.close()
            for stream in (process.stdout, process.stderr):
                stream.close()


class _Operator:
    """Same authenticated local control path as native profiles, never mounted."""
    def __init__(self, profile, manifest, broker, lifecycle, cancelled, *, framework="smolagents"):
        _sdk(framework)
        self.path = Path(manifest["runtime"]) / "operator.sock"

        class Handler(socketserver.StreamRequestHandler):
            def handle(inner):
                inner.connection.settimeout(20)
                try:
                    raw = inner.rfile.readline(101)
                    value = _object(raw) if len(raw) <= 100 and raw.endswith(b"\n") else None
                    if (type(value) is not dict or set(value) != {"op"} or type(value["op"]) is not str
                            or value["op"] not in {"status", "stop", "revoke"}):
                        raise ValueError("invalid_sdk_operator_request")
                    action = value["op"]
                    with broker._lock:
                        if action == "revoke":
                            broker.revoke(manifest["task_id"])
                        result = {**host._public(profile, manifest), "execution_framework": framework,
                                  "operator_action": action, "status": "stopping" if action == "stop" else lifecycle["status"],
                                  "task": broker.authority.describe(manifest["task_id"]),
                                  "protection": host._operator_protection_status(profile, manifest, broker)}
                    inner.wfile.write(json.dumps(result).encode() + b"\n")
                    inner.wfile.flush()
                    if action in {"stop", "revoke"}:
                        cancelled.set()
                except (ValueError, OSError, RuntimeError):
                    inner.wfile.write(b'{"status":"error","reason":"sdk_operator_unavailable"}\n')

        self.server = socketserver.ThreadingUnixStreamServer(str(self.path), Handler)
        self.server.daemon_threads = True
        self.path.chmod(0o600)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .05}, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.path.unlink(missing_ok=True)


def run_session(*, profile: Path, sdk_python: Path, session: str, prompt: str,
                resume: bool = False, max_steps: int = 12, max_tokens: int = 2048,
                timeout: int = 600, framework: str = "smolagents") -> dict:
    """Run one complete SDK turn. A new session never mints a new task/family."""
    host._linux()
    definition = _sdk(framework)
    if (type(prompt) is not str or not prompt.strip() or len(prompt.encode("utf-8")) > MAX_PROMPT
            or type(resume) is not bool or type(max_steps) is not int or not 1 <= max_steps <= 64
            or type(max_tokens) is not int or not 128 <= max_tokens <= 8192
            or type(timeout) is not int or not 1 <= timeout <= 1800):
        raise ValueError("sdk_run_configuration_invalid")
    if threading.current_thread() is not threading.main_thread():
        raise ValueError("sdk_supervisor_requires_main_thread")
    profile, _ = host._manifest(Path(profile))
    with host._profile_lock(profile):
        manifest = host.validate_profile(profile)
        if host._offline_lifecycle(profile) != "stopped":
            raise RuntimeError("sdk_requires_confirmed_stopped_profile")
        required = {"layered_defense_v1", "protected_fields_v1", "buffered_response_v1"}
        if not required <= set(manifest.get("features", [])):
            raise ValueError("sdk_requires_defended_profile")
        state = host._task_state(profile, manifest)
        if not state["active"] or state.get("paused"):
            raise RuntimeError("sdk_task_not_active")
        python, venv = _python_runtime(sdk_python, profile, framework=framework)
        ready = sandbox_available(bwrap=Path(manifest["bwrap"]))
        if not ready["available"]:
            raise RuntimeError("sdk_sandbox_unavailable")
        folder, binding = _session(profile, manifest, session, python, resume=resume, framework=framework)
        if resume:
            # A missing host journal cannot become a fresh nonce history.
            _private_directory(folder / "model-responses")
            _read_private(folder / "model-responses" / "state.json", 64 * 1024)
        runtime = Path(manifest["runtime"])
        runtime.mkdir(mode=0o700, exist_ok=True)
        _private_directory(runtime)
        for name in ("broker.sock", "review.sock", "operator.sock", "model.sock"):
            path = runtime / name
            if path.exists() or path.is_symlink():
                if not stat.S_ISSOCK(path.lstat().st_mode):
                    raise RuntimeError("sdk_unexpected_runtime_file")
                path.unlink()
        run_id = uuid.uuid4().hex
        automatic_actions = "automatic_actions_v1" in manifest["features"]
        config_path = runtime / ("sdk-" + run_id + ".json")
        config = {"version": 1, "framework": framework, "session_id": binding["session_id"],
                  "task_id": manifest["task_id"], "model_id": manifest["model"]["id"],
                  "max_steps": max_steps, "max_tokens": max_tokens, "prompt": prompt, "resume": resume,
                  "checkpoint": "/workspace/.yuanxingmu-" + framework + "-" + binding["session_id"] + ".json",
                  "broker_socket": str(BROKER_SOCKET_PATH), "model_socket": str(MODEL_SOCKET_PATH),
                  "automatic_actions": automatic_actions}
        _save_new(config_path, config)
        lifecycle = {"status": "starting", "execution_framework": framework, "supervisor_pid": os.getpid(),
                     "supervisor_start": host._process_identity(os.getpid()), "task_id": manifest["task_id"],
                     "session_id": binding["session_id"], "cleanup_confirmed": False}
        host._save(profile / "lifecycle.json", lifecycle)
        cancelled = threading.Event()
        previous = {sig: signal.signal(sig, lambda *_: cancelled.set()) for sig in (signal.SIGINT, signal.SIGTERM)}
        process = None
        completed = False
        services_closed = True
        try:
            resources, destinations = load_policy(profile / "policy.json")
            stack = ExitStack()
            services_closed = False
            try:
                broker = stack.enter_context(Broker(profile / "broker-state", resources, destinations,
                                                     **profile_services(profile, manifest)))
                with broker._lock:
                    broker._require_admission(manifest["task_id"])
                # Derive the configuration of THIS execution, not a statement
                # copied from the otherwise inactive native gateway.
                foundation = {"framework": framework, "bind": "loopback", "auth_enabled": True,
                              "tool_names": [*SDK_TOOLS, *definition["answer_tools"], *definition.get("handoff_tools", ()), *(["yuanxingmu_request_action"] if automatic_actions else [])], "allow_elevated": False,
                              "allow_direct_network": False, "isolated_execution": True,
                              "per_user_sessions": True, "credentials_host_only": True, "skills_pinned": True}
                report = broker.guards.scan_foundation(foundation, ())
                host._save(folder / ("foundation-" + run_id + ".json"), report.to_dict())
                if not report.allowed:
                    raise RuntimeError("sdk_foundation_check_failed")
                workspace = broker.bind_workspace(manifest["task_id"], profile / "workspace")
                operations = {"read", "describe", "action_targets", "propose_action", "draft_email"}
                if automatic_actions:
                    operations.add("request_action")
                broker.serve(manifest["task_id"], runtime / "broker.sock", allowed_operations=operations)
                broker.serve_reviews(manifest["task_id"], runtime / "review.sock")
                operator = _Operator(profile, manifest, broker, lifecycle, cancelled, framework=framework)
                stack.callback(operator.close)
                from .sdk_model_store import ModelStore
                store = ModelStore(folder / "model-responses", binding["session_id"])
                guard = _SdkOutputGuard(broker, manifest["task_id"], manifest["model"]["id"], max_tokens,
                                        automatic_actions=automatic_actions, framework=framework)
                stack.enter_context(HostModel(runtime, model_url=manifest["model"]["url"],
                                             api_key=_read_private(profile / "model-key", 16384).decode("utf-8"),
                                             output_guard=guard, model_store=store))
                package = Path(__file__).resolve().parent
                process = start(command=[str(python), "-I", "-B", "-c", definition["bootstrap"], str(package.parent),
                                         "--config", str(config_path)],
                                workspace=workspace, broker_socket=runtime / "broker.sock", model_socket=runtime / "model.sock",
                                readonly_paths=[package, venv, config_path], bwrap=Path(manifest["bwrap"]),
                                env={}, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                lifecycle.update(status="running", gateway_pid=process.pid, gateway_start=host._process_identity(process.pid))
                host._save(profile / "lifecycle.json", lifecycle)
                code, raw = _collect(process, cancelled, timeout)
                if code:
                    raise RuntimeError("sdk_worker_failed")
                value = _object(raw)
                if (type(value) is not dict or value.get("status") != "completed"
                        or type(value.get("answer")) is not str or len(value["answer"].encode()) > MAX_OUTPUT):
                    raise RuntimeError("sdk_worker_result_invalid")
                # Only the answer is eligible for release. SDK diagnostics and
                # arbitrary metadata never reach the terminal or browser.
                envelope = json.dumps({"choices": [{"index": 0, "finish_reason": "stop",
                    "message": {"role": "assistant", "content": value["answer"]}}]}, ensure_ascii=True).encode()
                checked = guard(envelope, "application/json")
                answer = _object(checked)["choices"][0]["message"]["content"]
                answer_allowed = checked == envelope
                result = {"status": "completed" if answer_allowed else "withheld", "framework": framework,
                          "task_id": manifest["task_id"], "session_id": binding["session_id"], "answer": answer}
                host._save(folder / ("run-" + run_id + ".json"), {key: item for key, item in result.items() if key != "answer"})
            finally:
                stack.close()
                services_closed = True
            completed = result["status"] == "completed"
            return result
        finally:
            try:
                if process is not None:
                    stop(process)
                config_path.unlink(missing_ok=True)
                # This is a synchronous library entry too. Its calling Python
                # process can stay alive after every owned child has stopped.
                lifecycle.update(status="stopped" if completed else "failed", cleanup_confirmed=services_closed)
                if services_closed:
                    lifecycle.update(supervisor_pid=None, supervisor_start=None, gateway_pid=None, gateway_start=None)
                host._save(profile / "lifecycle.json", lifecycle)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)


def cli(args) -> dict:
    with args.prompt_file.open("rb") as stream:
        raw = stream.read(MAX_PROMPT + 1)
    if len(raw) > MAX_PROMPT:
        raise ValueError("sdk_prompt_too_large")
    return run_session(profile=args.profile, sdk_python=args.sdk_python, session=args.session,
                       prompt=raw.decode("utf-8"), resume=args.resume, max_steps=args.max_steps,
                       max_tokens=args.max_tokens, timeout=args.timeout, framework=args.framework)
