"""CrewAI tools requiring host-persisted identity for each proposal dispatch.

CrewAI 1.15.21 does not inject a native call ID into BaseTool execution. The
trusted caller must wrap EACH tool dispatch in HostInvocations.bind(nonce).
Never bind one nonce around a complete Agent run, and never take it from model
arguments. Retain the nonce when reconciling an uncertain proposal submission.
"""
from contextlib import contextmanager
from contextvars import ContextVar

from crewai.tools import BaseTool
from pydantic import PrivateAttr

from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, TOOL_NAMES, NativeTools, encode_result


class HostInvocations:
    """Host-controlled, task-local nonce binding; not an isolation boundary."""

    def __init__(self):
        self._current = ContextVar("yuanxingmu_crewai_host_invocation", default=None)

    @contextmanager
    def bind(self, nonce: str):
        if type(nonce) is not str or not nonce or len(nonce) > 512:
            raise ValueError("host_invocation_nonce_required")
        token = self._current.set(nonce)
        try:
            yield
        finally:
            self._current.reset(token)

    def current(self) -> str | None:
        return self._current.get()


def _never_cache(*_args, **_kwargs) -> bool:
    return False


class _BrokerTool(BaseTool):
    _client: NativeTools = PrivateAttr()
    _operation: str = PrivateAttr()
    _invocations: HostInvocations = PrivateAttr()

    def __init__(self, client: NativeTools, operation: str, invocations: HostInvocations):
        super().__init__(name=TOOL_NAMES[operation], description=DESCRIPTIONS[operation],
                         args_schema=SCHEMAS[operation], cache_function=_never_cache)
        self._client, self._operation, self._invocations = client, operation, invocations

    def _run(self, **arguments) -> str:
        payload = SCHEMAS[self._operation].model_validate(arguments).model_dump()
        return encode_result(self._client.invoke(self._operation, payload, framework="crewai",
                                                 tool_call_id=self._invocations.current()))

    async def _arun(self, **arguments) -> str:
        payload = SCHEMAS[self._operation].model_validate(arguments).model_dump()
        return encode_result(await self._client.ainvoke(self._operation, payload, framework="crewai",
                                                         tool_call_id=self._invocations.current()))

    def to_structured_tool(self):
        result = super().to_structured_tool()
        # CrewStructuredTool.ainvoke runs sync functions in run_in_executor,
        # which drops ContextVar bindings. Keeping the native async callable
        # preserves the host's exact per-dispatch identity in both its async
        # invocation and its sync invoke/asyncio.run route.
        result.func = self._arun
        return result


def build_tools(client: NativeTools, *, invocations: HostInvocations) -> list[BaseTool]:
    """Create six real CrewAI BaseTool objects; proposal nonce binding is required."""
    if not isinstance(invocations, HostInvocations):
        raise TypeError("host_invocations_required")
    return [_BrokerTool(client, operation, invocations) for operation in OPERATIONS]
