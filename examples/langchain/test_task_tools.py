"""Scope/race unit checks with real StructuredTool objects and a fake adapter."""
from __future__ import annotations

import asyncio
import unittest
from unittest.mock import patch

from langchain_core.tools import StructuredTool
from pydantic import BaseModel

import task_tools
from task_tools import TaskScopeClosed, TaskScopeDrainTimeout, TaskToolScope


class Arguments(BaseModel):
    value: str


class TaskScopeTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.events = []
        self.start_error = None
        self.close_error = None

        async def original(value: str):
            self.events.append(("call", value))
            return value, {"origin": "adapter"}

        self.original = StructuredTool(name="echo", description="Original adapter tool",
            args_schema=Arguments, coroutine=original, metadata={"mcp": {"tool": "fixture"}},
            tags=["original"], response_format="content_and_artifact", handle_tool_error=True)
        owner = self

        class FakeClient:
            def __init__(self, target, *, mode):
                owner.events.append(("client_created", mode))
            async def close(self):
                owner.events.append("input_client_close")

        class AdapterClient:
            async def close(self):
                owner.events.append("actual_client_close")
                if owner.close_error is not None:
                    raise owner.close_error

        class FakeAdapter:
            def __init__(self, client):
                self.client = AdapterClient()  # A different object, like the official clone.
            async def __aenter__(self):
                owner.events.append("adapter_enter")
                return self
            async def __aexit__(self, *_args):
                owner.events.append("adapter_exit")
            async def list_tools(self):
                if owner.start_error is not None:
                    raise owner.start_error
                return [owner.original]

        for name, replacement in (("Client", FakeClient), ("MCPAdapter", FakeAdapter)):
            patcher = patch.object(task_tools, name, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    def scope(self, **kwargs):
        return TaskToolScope(lambda: {"mcpServers": {"fixture": {}}}, **kwargs)

    def blocking_tool(self):
        entered, release = asyncio.Event(), asyncio.Event()
        async def original(value: str):
            self.events.append("call_enter")
            entered.set()
            try:
                await release.wait()
                return value, None
            finally:
                self.events.append("call_exit")
        self.original = self.original.model_copy(update={"coroutine": original})
        return entered, release

    async def test_preserves_tool_and_rejects_old_reference_before_adapter(self):
        scope = self.scope()
        async with scope:
            tool = scope.tools[0]
            self.assertIs(tool.args_schema, self.original.args_schema)
            self.assertEqual(tool.metadata, self.original.metadata)
            self.assertEqual(tool.response_format, self.original.response_format)
            self.assertEqual(tool.tags, self.original.tags)
            self.assertEqual(tool.handle_tool_error, self.original.handle_tool_error)
            self.assertEqual(await tool.ainvoke({"value": "inside"}), "inside")
        before = list(self.events)
        with self.assertRaises(TaskScopeClosed):
            await tool.ainvoke({"value": "outside"})
        with self.assertRaises(TaskScopeClosed):
            await scope.__aenter__()
        self.assertEqual(self.events, before)
        self.assertIn(("client_created", "legacy"), self.events)
        self.assertIn("actual_client_close", self.events)
        self.assertNotIn("input_client_close", self.events)
        self.assertEqual(scope.state, "closed")

    async def test_closing_rejects_new_calls_and_drains_admitted_call(self):
        entered, release = self.blocking_tool()
        scope = await self.scope().__aenter__()
        tool = scope.tools[0]
        active = asyncio.create_task(tool.ainvoke({"value": "admitted"}))
        await asyncio.wait_for(entered.wait(), 1)
        closing = asyncio.create_task(scope.aclose())
        await asyncio.sleep(0)
        try:
            self.assertEqual(scope.state, "closing")
            with self.assertRaises(TaskScopeClosed):
                await tool.ainvoke({"value": "too-late"})
            self.assertNotIn("adapter_exit", self.events)
            self.assertEqual(scope.in_flight, 1)
        finally:
            release.set()
            await active
            await closing
        self.assertLess(self.events.index("call_exit"), self.events.index("adapter_exit"))
        self.assertLess(self.events.index("adapter_exit"), self.events.index("actual_client_close"))

    async def test_timeout_is_incomplete_and_cleanup_continues_after_drain(self):
        entered, release = self.blocking_tool()
        scope = await self.scope(drain_timeout=0.02).__aenter__()
        tool = scope.tools[0]
        active = asyncio.create_task(tool.ainvoke({"value": "admitted"}))
        await asyncio.wait_for(entered.wait(), 1)
        try:
            with self.assertRaises(TaskScopeDrainTimeout):
                await scope.aclose()
            self.assertEqual(scope.state, "closing")
            self.assertNotIn("adapter_exit", self.events)
            with self.assertRaises(TaskScopeClosed):
                await tool.ainvoke({"value": "retry"})
        finally:
            release.set()
            await active
            await scope.wait_closed(timeout=1)
        self.assertEqual(scope.state, "closed")

    async def test_cancelled_call_releases_admission(self):
        entered, _ = self.blocking_tool()
        scope = await self.scope().__aenter__()
        active = asyncio.create_task(scope.tools[0].ainvoke({"value": "cancel"}))
        await asyncio.wait_for(entered.wait(), 1)
        active.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await active
        await scope.aclose()
        self.assertEqual(scope.in_flight, 0)
        self.assertEqual(scope.state, "closed")

    async def test_cancelled_close_wait_does_not_cancel_cleanup(self):
        entered, release = self.blocking_tool()
        scope = await self.scope().__aenter__()
        active = asyncio.create_task(scope.tools[0].ainvoke({"value": "admitted"}))
        await asyncio.wait_for(entered.wait(), 1)
        closing = asyncio.create_task(scope.aclose())
        await asyncio.sleep(0)
        closing.cancel()
        try:
            with self.assertRaises(asyncio.CancelledError):
                await closing
            self.assertEqual(scope.state, "closing")
            self.assertNotIn("adapter_exit", self.events)
        finally:
            release.set()
            await active
            await scope.wait_closed(timeout=1)
        self.assertEqual(scope.state, "closed")

    async def test_startup_failure_closes_actual_client_and_cannot_reenter(self):
        self.start_error = RuntimeError("discovery failed")
        scope = self.scope()
        with self.assertRaisesRegex(RuntimeError, "discovery failed"):
            await scope.__aenter__()
        self.assertEqual(scope.tools, [])
        self.assertIn("adapter_exit", self.events)
        self.assertIn("actual_client_close", self.events)
        with self.assertRaises(TaskScopeClosed):
            await scope.__aenter__()

    async def test_cleanup_error_is_reported_and_old_tool_stays_invalid(self):
        scope = await self.scope().__aenter__()
        tool = scope.tools[0]
        self.close_error = RuntimeError("cleanup failed")
        with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
            await scope.aclose()
        self.assertEqual(scope.state, "failed")
        with self.assertRaises(TaskScopeClosed):
            await tool.ainvoke({"value": "outside"})


if __name__ == "__main__":
    unittest.main()
