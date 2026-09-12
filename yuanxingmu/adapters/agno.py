"""Agno native Function objects with hidden FunctionCall identity injection."""
from agno.tools.function import Function, FunctionCall

from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, TOOL_NAMES, NativeTools, encode_result


def _tool(client: NativeTools, operation: str, asynchronous: bool) -> Function:
    schema = SCHEMAS[operation]

    def payload_and_id(fc, arguments):
        payload = schema.model_validate(arguments).model_dump()
        if not isinstance(fc, FunctionCall) or fc.function.name != TOOL_NAMES[operation]:
            raise ValueError("native_tool_context_required")
        return payload, fc.call_id

    async def ainvoke(*, fc: FunctionCall, **arguments) -> str:
        payload, call_id = payload_and_id(fc, arguments)
        return encode_result(await client.ainvoke(operation, payload, framework="agno", tool_call_id=call_id))

    def invoke(*, fc: FunctionCall, **arguments) -> str:
        payload, call_id = payload_and_id(fc, arguments)
        return encode_result(client.invoke(operation, payload, framework="agno", tool_call_id=call_id))

    # Agno supplies fc from the actual FunctionCall, before calling entrypoint.
    # This field stays out of the public schema. No cached proposal/send result
    # may bypass the Broker's current status or permissions.
    return Function(name=TOOL_NAMES[operation], description=DESCRIPTIONS[operation],
                    parameters=schema.model_json_schema(), entrypoint=ainvoke if asynchronous else invoke,
                    skip_entrypoint_processing=True, cache_results=False,
                    has_side_effects=operation in {"send", "propose_action", "draft_email"})


def build_tools(client: NativeTools, *, asynchronous: bool = True) -> list[Function]:
    """Create native tools for Agent.arun; pass asynchronous=False for Agent.run."""
    return [_tool(client, operation, asynchronous) for operation in OPERATIONS]
