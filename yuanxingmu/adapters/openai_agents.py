"""Real OpenAI Agents SDK FunctionTool objects, with no model or tracing calls."""
from agents import FunctionTool
from agents.tool_context import ToolContext

from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, TOOL_NAMES, NativeTools, decode_arguments, encode_result


def _tool(client: NativeTools, operation: str) -> FunctionTool:
    schema = SCHEMAS[operation]

    async def invoke(context: ToolContext, arguments: str) -> str:
        # FunctionTool's advertised schema is not an execution-time validator.
        # Validate the raw JSON ourselves before any Broker request.
        payload = schema.model_validate(decode_arguments(arguments)).model_dump()
        return encode_result(await client.ainvoke(operation, payload, framework="openai_agents",
                                                   tool_call_id=context.tool_call_id))

    return FunctionTool(name=TOOL_NAMES[operation], description=DESCRIPTIONS[operation],
                        params_json_schema=schema.model_json_schema(), on_invoke_tool=invoke,
                        strict_json_schema=True)


def build_tools(client: NativeTools) -> list[FunctionTool]:
    """Create six native tools. Host review remains outside the SDK's tools."""
    return [_tool(client, operation) for operation in OPERATIONS]
