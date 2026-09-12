"""Google ADK BaseTool extension using its actual ToolContext call identity."""
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, TOOL_NAMES, NativeTools, encode_result


class _BrokerTool(BaseTool):
    def __init__(self, client: NativeTools, operation: str):
        super().__init__(name=TOOL_NAMES[operation], description=DESCRIPTIONS[operation])
        self._client, self._operation = client, operation

    def _get_declaration(self) -> types.FunctionDeclaration:
        # The native BaseTool extension point avoids FunctionTool's argument
        # filtering, which would otherwise silently discard unknown fields.
        return types.FunctionDeclaration(name=self.name, description=self.description,
                                         parameters_json_schema=SCHEMAS[self._operation].model_json_schema())

    async def run_async(self, *, args: dict, tool_context: ToolContext) -> str:
        payload = SCHEMAS[self._operation].model_validate(args).model_dump()
        if not isinstance(tool_context, ToolContext):
            raise ValueError("native_tool_context_required")
        return encode_result(await self._client.ainvoke(self._operation, payload, framework="google_adk",
                                                         tool_call_id=tool_context.function_call_id))


def build_tools(client: NativeTools) -> list[BaseTool]:
    """Create six native BaseTool objects accepted by ADK Agent / LlmAgent."""
    return [_BrokerTool(client, operation) for operation in OPERATIONS]
