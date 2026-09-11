"""Experimental, one-use task scope around the public MCPAdapter API.

The factory must create configuration or a transport exclusively owned by this
scope. A scope belongs to one user task. It cannot restore old agent memory,
resume a checkpoint in a new scope, or share tools between users.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from functools import wraps
import math
from typing import Any

from fastmcp import Client
from langchain.mcp import MCPAdapter
from langchain_core.tools import StructuredTool


class TaskScopeClosed(RuntimeError):
    """The owning task no longer admits tool calls; no connection was opened."""


class TaskScopeDrainTimeout(TimeoutError):
    """Draining or cleanup is unfinished; this must not be reported as success."""


class TaskToolScope:
    """Hold one adapter throughout one task and invalidate tools before closing.

    Example:
        async with TaskToolScope(lambda: StdioTransport(...)) as scope:
            tools = scope.tools
            await run_task_with(tools)

    Calls admitted before closure may finish. Closure rejects later admissions
    immediately and waits for the earlier calls before releasing the adapter.
    A timeout leaves cleanup pending, still rejects calls, and raises explicitly.
    Keep the event loop alive and use wait_closed() to observe eventual cleanup.
    """

    def __init__(self, target_factory: Callable[[], Any], *, mode: str = "legacy",
                 drain_timeout: float = 5):
        if not callable(target_factory):
            raise TypeError("target_factory must create a fresh, exclusively owned target")
        self._check_timeout(drain_timeout)
        self._factory = target_factory
        self._mode = mode
        self._drain_timeout = drain_timeout
        self._state = "new"
        self._admission = asyncio.Lock()
        self._drained = asyncio.Event()
        self._drained.set()
        self._in_flight = 0
        self._owned_client = None
        self._adapter = None
        self._adapter_entered = False
        self._tools: tuple[StructuredTool, ...] = ()
        self._close_task: asyncio.Task | None = None

    @staticmethod
    def _check_timeout(timeout: float) -> None:
        if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite, positive number of seconds")

    @property
    def tools(self) -> list[StructuredTool]:
        """Task-bound copies; retaining a copy does not extend the task lifetime."""
        return list(self._tools)

    @property
    def state(self) -> str:
        return self._state

    @property
    def in_flight(self) -> int:
        return self._in_flight

    async def __aenter__(self) -> TaskToolScope:
        async with self._admission:
            if self._state != "new":
                raise TaskScopeClosed("A task scope can only be entered once")
            self._state = "opening"
        try:
            target = self._factory()
            if isinstance(target, (Client, MCPAdapter)):
                raise TypeError("The factory must return configuration or a fresh transport, not a client or adapter")
            self._owned_client = Client(target, mode=self._mode)
            self._adapter = MCPAdapter(self._owned_client)
            await self._adapter.__aenter__()
            self._adapter_entered = True
            originals = await self._adapter.list_tools()
            self._tools = tuple(self._bind(tool) for tool in originals)
            self._state = "open"
            return self
        except BaseException as exc:
            await self._begin_close(type(exc), exc, exc.__traceback__)
            await self.wait_closed(timeout=self._drain_timeout)
            raise

    def _bind(self, tool: StructuredTool) -> StructuredTool:
        if not isinstance(tool, StructuredTool) or tool.coroutine is None or tool.func is not None:
            raise TypeError("This experiment supports MCPAdapter's asynchronous StructuredTool objects only")
        original = tool.coroutine

        @wraps(original)
        async def within_task(*args, **kwargs):
            async with self._admission:
                if self._state != "open":
                    raise TaskScopeClosed(f"Task scope is {self._state}; tool invocation was not admitted")
                self._in_flight += 1
                self._drained.clear()
            try:
                return await original(*args, **kwargs)
            finally:
                # No await here: even cancellation releases the admission before
                # the coroutine exits. All scope operations use one event loop.
                self._in_flight -= 1
                if self._in_flight == 0:
                    self._drained.set()

        # Preserve schema, metadata, response format and official error handling.
        return tool.model_copy(update={"coroutine": within_task})

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        await self._begin_close(exc_type, exc, traceback)
        await self.wait_closed(timeout=self._drain_timeout)

    async def aclose(self) -> None:
        if self._state == "opening":
            raise RuntimeError("Cancel the opening task instead of closing concurrently with startup")
        await self._begin_close(None, None, None)
        await self.wait_closed(timeout=self._drain_timeout)

    async def _begin_close(self, exc_type, exc, traceback) -> None:
        async with self._admission:
            if self._close_task is None:
                self._state = "closing"
                self._close_task = asyncio.create_task(self._finish_close(exc_type, exc, traceback))

    async def _finish_close(self, exc_type, exc, traceback) -> None:
        await self._drained.wait()
        try:
            try:
                if self._adapter_entered:
                    await self._adapter.__aexit__(exc_type, exc, traceback)
            finally:
                # MCPAdapter may clone its input client. Close its actual client,
                # including keep-alive transports, not merely the input object.
                client = self._adapter.client if self._adapter is not None else self._owned_client
                if client is not None:
                    await client.close()
        except BaseException:
            self._state = "failed"
            raise
        else:
            self._state = "closed"

    async def wait_closed(self, *, timeout: float = 5) -> None:
        self._check_timeout(timeout)
        if self._close_task is None:
            raise RuntimeError("Closure has not started")
        # asyncio.wait does not cancel the owned cleanup task on caller timeout
        # or cancellation. A timed-out scope remains closing and rejects calls.
        done, _ = await asyncio.wait({self._close_task}, timeout=timeout)
        if not done:
            raise TaskScopeDrainTimeout(
                f"Task draining/cleanup did not finish within {timeout}s; result is incomplete"
            )
        self._close_task.result()
