"""Observe exit through handles acquired while trusted fixture processes are live.

The caller must acquire this witness while it still holds active fixture
connections and can associate the reported PIDs with those live processes.
Handles remain tied to those process instances even if their PIDs are reused.
This observer neither stops processes nor assesses whether Python finally ran.
"""
from __future__ import annotations

from dataclasses import dataclass
import math
import os
import select
import sys
import time
from typing import Protocol


class _Waitable(Protocol):
    def wait(self, timeout: float) -> bool: ...
    def close(self) -> None: ...


class _WindowsProcessHandle:
    def __init__(self, pid: int):
        import ctypes
        from ctypes import wintypes

        self._ctypes = ctypes
        self._api = ctypes.WinDLL("kernel32", use_last_error=True)
        self._api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self._api.OpenProcess.restype = wintypes.HANDLE
        self._api.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self._api.WaitForSingleObject.restype = wintypes.DWORD
        self._api.CloseHandle.argtypes = [wintypes.HANDLE]
        self._api.CloseHandle.restype = wintypes.BOOL
        # SYNCHRONIZE only: no read-memory, terminate, or job-object rights.
        self._handle = self._api.OpenProcess(0x00100000, False, pid)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())

    def wait(self, timeout: float) -> bool:
        milliseconds = min(math.ceil(timeout * 1000), 0xFFFFFFFE)
        result = self._api.WaitForSingleObject(self._handle, milliseconds)
        if result == 0:  # WAIT_OBJECT_0: this process instance exited.
            return True
        if result == 258:  # WAIT_TIMEOUT
            return False
        if result == 0xFFFFFFFF:  # WAIT_FAILED
            raise self._ctypes.WinError(self._ctypes.get_last_error())
        raise OSError(f"Unexpected process wait result: {result}")

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle and not self._api.CloseHandle(handle):
            raise self._ctypes.WinError(self._ctypes.get_last_error())


class _LinuxPidfd:
    def __init__(self, pid: int):
        self._fd = os.pidfd_open(pid, 0)

    def wait(self, timeout: float) -> bool:
        readable, _, _ = select.select([self._fd], [], [], timeout)
        return bool(readable)

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is not None:
            os.close(fd)


@dataclass
class _Process:
    pid: int
    handle: _Waitable | None = None
    captured_alive: bool = False
    state: str = "incomplete"
    error: str | None = None


class ProcessWitness:
    """Acquire now, call wait after connection shutdown, then close the witness.

    `wait(timeout=5)` shares one five-second budget across all processes. Its
    JSON-compatible report distinguishes observed exit, still running, and
    incomplete evidence. Empty input, acquisition failure, an already-exited
    process at acquisition, and unsupported platforms never count as success.
    """

    def __init__(self, pids: list[int]):
        if any(isinstance(pid, bool) or not isinstance(pid, int) or not 0 < pid < 2**32
               for pid in pids):
            raise ValueError("Process IDs must be positive integers below 2**32")
        self._processes = [_Process(pid) for pid in dict.fromkeys(pids)]
        self._closed = False
        if sys.platform == "win32":
            self.backend = "windows_process_handle"
            factory = _WindowsProcessHandle
        elif sys.platform.startswith("linux") and hasattr(os, "pidfd_open"):
            self.backend = "linux_pidfd"
            factory = _LinuxPidfd
        else:
            self.backend = "unsupported"
            factory = None
        for process in self._processes:
            if factory is None:
                process.error = "Platform has no supported process-instance witness"
                continue
            try:
                process.handle = factory(process.pid)
                if process.handle.wait(0):
                    process.error = "Process already exited before a live witness was acquired"
                    process.handle.close()
                    process.handle = None
                else:
                    process.captured_alive = True
                    process.state = "running"
            except (OSError, ValueError, OverflowError) as exc:
                process.error = f"Acquisition failed: {type(exc).__name__}: {exc}"
                if process.handle is not None:
                    try:
                        process.handle.close()
                    except OSError:
                        pass
                    process.handle = None

    def __enter__(self) -> ProcessWitness:
        if self._closed:
            raise RuntimeError("Process witness is already closed")
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def wait(self, timeout: float = 5) -> dict:
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout < 0:
            raise ValueError("timeout must be a finite, nonnegative number of seconds")
        started = time.monotonic()
        deadline = started + timeout
        for process in self._processes:
            if not process.captured_alive or process.state == "exited" or process.handle is None:
                continue
            try:
                exited = process.handle.wait(max(0, deadline - time.monotonic()))
                process.state = "exited" if exited else "running"
                process.error = None
            except (OSError, ValueError) as exc:
                process.state = "incomplete"
                process.error = f"Observation failed: {type(exc).__name__}: {exc}"
        processes = [{"pid": process.pid, "captured_alive": process.captured_alive,
                      "state": process.state, "error": process.error}
                     for process in self._processes]
        all_captured = bool(processes) and all(p["captured_alive"] for p in processes)
        all_exited = all_captured and all(p["state"] == "exited" for p in processes)
        incomplete = not all_captured or any(p["state"] == "incomplete" for p in processes)
        return {"backend": self.backend,
                "status": "incomplete" if incomplete else "exited" if all_exited else "running",
                "all_captured_alive": all_captured,
                "all_exited": all_exited,
                "graceful_shutdown": "not_assessed",
                "timeout_seconds": timeout,
                "elapsed_seconds": round(time.monotonic() - started, 6),
                "processes": processes}

    def close(self) -> None:
        """Release observation resources without affecting the watched processes."""
        if self._closed:
            return
        self._closed = True
        errors = []
        for process in self._processes:
            if process.handle is None:
                continue
            try:
                process.handle.close()
            except OSError as exc:
                errors.append(exc)
            finally:
                process.handle = None
                if process.state != "exited":
                    process.state = "incomplete"
                    process.error = "Witness closed before process exit was observed"
        if errors:
            raise OSError("Could not release all process witness handles") from errors[0]
