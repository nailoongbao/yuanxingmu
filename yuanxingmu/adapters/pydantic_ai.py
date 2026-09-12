"""Real Pydantic AI Tool objects using framework-supplied RunContext IDs."""
from pydantic_ai import RunContext, Tool

from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, TOOL_NAMES, NativeTools, encode_result


def _tool(client: NativeTools, operation: str) -> Tool:
    schema = SCHEMAS[operation]

    async def invoke(ctx: RunContext, **arguments) -> str:
        # Tool.from_schema advertises a schema but intentionally skips native
        # schema validation. Validate here on every invocation, including a
        # direct FunctionToolset.call_tool call. A single BaseModel argument to
        # Tool(...) would otherwise be flattened by Pydantic AI.
        payload = schema.model_validate(arguments).model_dump()
        return encode_result(await client.ainvoke(operation, payload, framework="pydantic_ai",
                                                   tool_call_id=ctx.tool_call_id))

    return Tool.from_schema(invoke, name=TOOL_NAMES[operation], description=DESCRIPTIONS[operation],
                            json_schema=schema.model_json_schema(), takes_ctx=True)


def build_tools(client: NativeTools) -> list[Tool]:
    """Create six native tools accepted by Agent or FunctionToolset."""
    return [_tool(client, operation) for operation in OPERATIONS]
