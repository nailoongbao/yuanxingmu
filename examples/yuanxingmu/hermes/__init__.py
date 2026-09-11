"""Hermes terminal-environment plugin backed by Yuanxingmu's Linux boundary.

The trusted host creates broker tasks and binds their workspaces first. This
plugin only accepts that host's explicit task-to-socket mapping. It does not
automatically authorize browser, web, MCP, messaging or model-provider traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import subprocess
import sys
import threading

from agent.terminal_env_provider import TerminalEnvironmentProvider
from tools.environments.base import BaseEnvironment, EnvironmentConnectionError
from tools.environments.base_output import _pipe_stdin

# A Hermes host can have an agent-writable cwd. Never resolve the worker package
# from that cwd before entering the sandbox. A copied plugin needs an explicit
# trusted installation root; running in this repository derives it from itself.
CORE_ROOT = Path(os.environ.get("YUANXINGMU_CORE_ROOT") or Path(__file__).resolve().parents[3]).resolve(strict=True)
CORE_PACKAGE = CORE_ROOT / "yuanxingmu"
if not (CORE_PACKAGE / "worker.py").is_file() or not (CORE_PACKAGE / "__init__.py").is_file():
    raise RuntimeError("set YUANXINGMU_CORE_ROOT to the trusted core installation")
for module_name, loaded in tuple(sys.modules.items()):
    if module_name == "yuanxingmu" or module_name.startswith("yuanxingmu."):
        location = getattr(loaded, "__file__", None)
        if location is None or not Path(location).resolve().is_relative_to(CORE_PACKAGE):
            raise RuntimeError("an untrusted yuanxingmu module was already loaded")
sys.path.insert(0, str(CORE_ROOT))

from yuanxingmu.client import request
from yuanxingmu.sandbox import build_command, sandbox_available
from yuanxingmu.worker import start, stop


@dataclass(frozen=True)
class TaskBinding:
    security_task_id: str
    workspace: Path
    broker_socket: Path
    readonly_paths: tuple[Path, ...] = ()
    env: dict[str, str] = field(default_factory=dict)


class YuanxingmuEnvironment(BaseEnvironment):
    """Reuse Hermes execute(), file plumbing, bounded output and interrupts."""

    is_local = False

    def __init__(self, *, binding: TaskBinding, bwrap: Path, cwd: str, timeout: int):
        super().__init__(cwd=cwd, timeout=timeout)
        self.binding = binding
        self.bwrap = bwrap
        self._prefer_nonlogin = True
        self._closed = False
        self._process_lock = threading.RLock()
        self._processes: list[subprocess.Popen] = []
        self.launches: list[dict] = []

    def init_session(self):
        # /tmp is fresh per command. Do not capture host login configuration or
        # promise shell-export persistence; workspace and observed cwd persist.
        self._snapshot_ready = False
        self._prefer_nonlogin = True

    def _prepare_command(self, command: str):
        # BaseEnvironment optionally injects host SUDO_PASSWORD into stdin.
        # This backend grants no host sudo credential. Native command approval
        # still runs in terminal_tool; skip_container_guards stays False.
        return command, None

    def _before_execute(self):
        with self._process_lock:
            if self._closed:
                raise EnvironmentConnectionError("yuanxingmu_environment_closed")
        try:
            state = request("describe", socket_path=str(self.binding.broker_socket))
        except (OSError, ValueError, RuntimeError) as exc:
            raise EnvironmentConnectionError("yuanxingmu_broker_unavailable") from exc
        if not state.get("allowed") or not state.get("active"):
            raise EnvironmentConnectionError("yuanxingmu_task_not_active")
        if state.get("task_id") != self.binding.security_task_id:
            raise EnvironmentConnectionError("yuanxingmu_task_binding_mismatch")

    def _run_bash(self, cmd_string, *, login=False, timeout=120, stdin_data=None):
        command = ["/bin/bash", "--noprofile", "--norc", "-c", cmd_string]
        options = dict(
            command=command, workspace=self.binding.workspace,
            broker_socket=self.binding.broker_socket,
            readonly_paths=list(self.binding.readonly_paths), env=dict(self.binding.env),
            bwrap=self.bwrap,
        )
        argv = build_command(**options)
        with self._process_lock:
            if self._closed:
                raise EnvironmentConnectionError("yuanxingmu_environment_closed")
            process = start(
                **options, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace",
            )
            self._processes.append(process)
            self.launches.append({"argv": argv, "launcher_pid": process.pid})
        if stdin_data is not None:
            _pipe_stdin(process, stdin_data)
        return process

    def _kill_process(self, process):
        stop(process)

    def cleanup(self):
        with self._process_lock:
            self._closed = True
            processes = list(self._processes)
        for process in processes:
            stop(process)

    def process_observations(self):
        return [
            {"launcher_pid": process.pid, "returncode": process.poll(),
             "reaped": process.poll() is not None}
            for process in self._processes
        ]


class YuanxingmuProvider(TerminalEnvironmentProvider):
    name = "yuanxingmu"
    display_name = "Yuanxingmu"
    is_remote = True
    is_container = True
    skip_container_guards = False
    session_isolated_when_nonpersistent = True

    def __init__(self, *, bindings: dict[str, TaskBinding], bwrap: Path):
        self.bindings = dict(bindings)
        self.bwrap = Path(bwrap)
        # The official picker requires a cheap is_available(), so probe once at
        # trusted construction. Each execution still verifies its live broker.
        self.availability = sandbox_available(bwrap=self.bwrap)
        self.environments: list[YuanxingmuEnvironment] = []

    def is_available(self):
        return bool(self.availability["available"])

    @property
    def strip_env_keys(self):
        return frozenset({"YUANXINGMU_HERMES_CONFIG", "YUANXINGMU_CORE_ROOT"})

    @property
    def cache_path_base(self):
        return "/workspace/.hermes"

    def create_environment(self, *, cwd, timeout, task_id="default", image=None,
                           container_config=None, **kwargs):
        if not self.is_available():
            raise EnvironmentConnectionError(str(self.availability["reason"]))
        binding = self.bindings.get(task_id)
        if binding is None:
            raise EnvironmentConnectionError("yuanxingmu_task_not_bound_by_host")
        environment = YuanxingmuEnvironment(
            binding=binding, bwrap=self.bwrap, cwd=cwd or "/workspace", timeout=timeout,
        )
        environment._before_execute()
        self.environments.append(environment)
        return environment

    def cleanup(self):
        for environment in self.environments:
            environment.cleanup()


def provider_from_file(path: Path) -> YuanxingmuProvider:
    """Read trusted host configuration; never create tasks from model content."""
    if not path.is_absolute():
        raise ValueError("host_config must be an absolute trusted-host path")
    raw = json.loads(path.read_text(encoding="utf-8"))
    bindings = {
        name: TaskBinding(
            security_task_id=item["security_task_id"], workspace=Path(item["workspace"]),
            broker_socket=Path(item["broker_socket"]),
            readonly_paths=tuple(Path(value) for value in item.get("readonly_paths", [])),
            env=dict(item.get("env", {})),
        )
        for name, item in raw["tasks"].items()
    }
    return YuanxingmuProvider(bindings=bindings, bwrap=Path(raw["bwrap"]))


def register(ctx):
    path = ctx.get_config("host_config") or os.environ.get("YUANXINGMU_HERMES_CONFIG")
    if not path:
        raise ValueError("Yuanxingmu requires a trusted host_config with pre-bound tasks")
    return ctx.register_terminal_environment_provider(provider_from_file(Path(path)))
