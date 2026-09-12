"""LlamaIndex FunctionTools with explicit per-dispatch host identity.

LlamaIndex 0.14.24 does not pass its workflow ToolCall.tool_id into FunctionTool
execution. The trusted host must bind a persisted nonce for EACH dispatch.
"""
from llama_index.core.tools import FunctionTool, ToolMetadata

from ._host_invocations import HostInvocations
from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, TOOL_NAMES, NativeTools, encode_result


class _ClosedToolMetadata(ToolMetadata):
    def get_parameters_dict(self) -> dict:
        # The stock metadata exporter drops top-level additionalProperties.
        # Retain the complete closed schema in every native declaration.
        return self.fn_schema.model_json_schema()


def _tool(client: NativeTools, operation: str, invocations: HostInvocations) -> FunctionTool:
    def run(**arguments) -> str:
        payload = SCHEMAS[operation].model_validate(arguments).model_dump()
        return encode_result(client.invoke(operation, payload, framework="llama_index",
                                           tool_call_id=invocations.current()))

    async def arun(**arguments) -> str:
        payload = SCHEMAS[operation].model_validate(arguments).model_dump()
        return encode_result(await client.ainvoke(operation, payload, framework="llama_index",
                                                  tool_call_id=invocations.current()))

    metadata = _ClosedToolMetadata(name=TOOL_NAMES[operation], description=DESCRIPTIONS[operation],
                                   fn_schema=SCHEMAS[operation], return_direct=False)
    return FunctionTool(fn=run, async_fn=arun, metadata=metadata)


def build_tools(client: NativeTools, *, invocations: HostInvocations) -> list[FunctionTool]:
    """Create six real FunctionTools. Proposal dispatches require a host nonce."""
    if not isinstance(invocations, HostInvocations):
        raise TypeError("host_invocations_required")
    return [_tool(client, operation, invocations) for operation in OPERATIONS]
