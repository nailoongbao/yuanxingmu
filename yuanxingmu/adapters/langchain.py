"""Real LangChain StructuredTool objects, also accepted by LangGraph ToolNode."""
from typing import Annotated

from langchain_core.tools import InjectedToolCallId, StructuredTool
from pydantic import BaseModel, Field, create_model

from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, PROPOSALS, TOOL_NAMES, NativeTools, encode_result


class _ClosedStructuredTool(StructuredTool):
    # LangChain's generated subset model currently drops extra="forbid".
    # Preserve the public, closed schema while its normal args_schema handles
    # validation and native InjectedToolCallId injection during execution.
    visible_args_schema: type[BaseModel] = Field(exclude=True, repr=False)

    @property
    def tool_call_schema(self):
        return self.visible_args_schema


def _tool(client: NativeTools, operation: str) -> StructuredTool:
    schema = SCHEMAS[operation]

    if operation in PROPOSALS:
        # The native SDK replaces this hidden argument with ToolCall.id. It is
        # omitted from tool_call_schema and must not come from model arguments.
        args_schema = create_model(schema.__name__ + "WithNativeCallId", __base__=schema,
                                   tool_call_id=(Annotated[str, InjectedToolCallId], ...))

        def run(*, tool_call_id: Annotated[str, InjectedToolCallId], **arguments):
            payload = schema.model_validate(arguments).model_dump()
            return encode_result(client.invoke(operation, payload, framework="langchain", tool_call_id=tool_call_id))

        async def arun(*, tool_call_id: Annotated[str, InjectedToolCallId], **arguments):
            payload = schema.model_validate(arguments).model_dump()
            return encode_result(await client.ainvoke(operation, payload, framework="langchain", tool_call_id=tool_call_id))
    else:
        args_schema = schema

        def run(**arguments):
            payload = schema.model_validate(arguments).model_dump()
            return encode_result(client.invoke(operation, payload, framework="langchain"))

        async def arun(**arguments):
            payload = schema.model_validate(arguments).model_dump()
            return encode_result(await client.ainvoke(operation, payload, framework="langchain"))

    return _ClosedStructuredTool.from_function(func=run, coroutine=arun, name=TOOL_NAMES[operation],
                                               description=DESCRIPTIONS[operation], args_schema=args_schema,
                                               visible_args_schema=schema, infer_schema=False)


def build_tools(client: NativeTools) -> list[StructuredTool]:
    """Create six native tools for a host-bound Broker session; no model is run."""
    return [_tool(client, operation) for operation in OPERATIONS]
