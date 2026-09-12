"""Microsoft Agent Framework FunctionTools bound to the SDK's tool_call_id."""
from contextvars import ContextVar

from agent_framework import FunctionTool

from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, TOOL_NAMES, NativeTools, encode_result


class _BrokerTool(FunctionTool):
    def __init__(self, client: NativeTools, operation: str):
        self._call_id = ContextVar("yuanxingmu_microsoft_agent_framework_call_id", default=None)

        async def run(**arguments) -> str:
            payload = SCHEMAS[operation].model_validate(arguments).model_dump()
            return encode_result(await client.ainvoke(operation, payload, framework="microsoft_agent_framework",
                                                      tool_call_id=self._call_id.get()))

        super().__init__(name=TOOL_NAMES[operation], description=DESCRIPTIONS[operation],
                         func=run, input_model=SCHEMAS[operation], approval_mode="never_require")

    async def invoke(self, *, arguments=None, context=None, tool_call_id=None, skip_parsing=False, **kwargs):
        # The SDK forwards this separate parameter through its direct and
        # middleware dispatch routes. Do not take identity from arguments,
        # arbitrary context.metadata, or an agent-wide session identifier.
        token = self._call_id.set(tool_call_id)
        try:
            return await super().invoke(arguments=arguments, context=context, tool_call_id=tool_call_id,
                                        skip_parsing=skip_parsing, **kwargs)
        finally:
            self._call_id.reset(token)


def build_tools(client: NativeTools) -> list[FunctionTool]:
    """Create six tools. Host review stays in the Broker, not SDK approval flags."""
    return [_BrokerTool(client, operation) for operation in OPERATIONS]
