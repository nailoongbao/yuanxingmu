"""Native AutoGen tools using the SDK's hidden per-dispatch call_id.

Validated with autogen-core / autogen-agentchat 0.7.5. Older dispatchers that
omit call_id cannot submit proposals. No endpoint or identity is a model arg.
"""
import asyncio
from contextvars import ContextVar

from autogen_core.tools import BaseTool

from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, TOOL_NAMES, NativeTools, encode_result


class _BrokerTool(BaseTool):
    def __init__(self, client: NativeTools, operation: str):
        super().__init__(args_type=SCHEMAS[operation], return_type=str,
                         name=TOOL_NAMES[operation], description=DESCRIPTIONS[operation], strict=True)
        self._client, self._operation = client, operation
        self._call_id = ContextVar("yuanxingmu_autogen_call_id", default=None)

    async def run_json(self, args, cancellation_token, call_id=None):
        # Preserve SDK validation, tracing and result handling. AutoGen's run()
        # has no ID argument; keep its genuine run_json call ID task-local.
        token = self._call_id.set(call_id)
        try:
            return await super().run_json(args, cancellation_token, call_id=call_id)
        finally:
            self._call_id.reset(token)

    async def run(self, args, cancellation_token) -> str:
        if cancellation_token.is_cancelled():
            raise asyncio.CancelledError()
        payload = SCHEMAS[self._operation].model_validate(args).model_dump()
        return encode_result(await self._client.ainvoke(self._operation, payload, framework="autogen",
                                                         tool_call_id=self._call_id.get()))


def build_tools(client: NativeTools) -> list[BaseTool]:
    """Create six BaseTools for AssistantAgent, StaticWorkbench or ToolAgent."""
    return [_BrokerTool(client, operation) for operation in OPERATIONS]
