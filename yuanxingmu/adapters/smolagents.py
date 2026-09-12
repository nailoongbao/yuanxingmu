"""smolagents Tools protected at their registered Broker operations only.

ToolCallingAgent's dispatcher supplies no per-call ID to Tool.__call__. Bind a
persisted host nonce around each individual dispatch. CodeAgent's arbitrary
Python execution and other tools are outside this adapter's protection.
"""
from copy import deepcopy

from smolagents import Tool

from ._host_invocations import HostInvocations
from ._schemas import SCHEMAS
from .client import DESCRIPTIONS, OPERATIONS, TOOL_NAMES, NativeTools, encode_result


def _inputs(operation: str) -> dict:
    source = SCHEMAS[operation].model_json_schema()
    definitions = source.get("$defs", {})

    def resolve(node):
        if isinstance(node, dict):
            if "$ref" in node:
                prefix = "#/$defs/"
                if not node["$ref"].startswith(prefix):
                    raise ValueError("unsupported_native_schema_reference")
                return resolve(definitions[node["$ref"][len(prefix):]])
            return {key: resolve(value) for key, value in node.items() if key != "$defs"}
        if isinstance(node, list):
            return [resolve(value) for value in node]
        return deepcopy(node)

    properties = resolve(source)["properties"]
    for name, schema in properties.items():
        # smolagents requires an explicit type for each input, and its exporter
        # flattens top-level anyOf. These five disjoint action variants can be
        # represented equivalently with oneOf, which the exporter preserves.
        if "anyOf" in schema:
            branches = schema.pop("anyOf")
            expected = {"kind", "target_id", "payload"}
            if (operation != "propose_action" or name != "proposal"
                    or any(branch.get("type") != "object" or set(branch.get("properties", {})) != expected
                           for branch in branches)):
                raise ValueError("unsupported_native_schema_union")
            kinds = [branch["properties"]["kind"]["const"] for branch in branches]
            if len(set(kinds)) != len(kinds):
                raise ValueError("ambiguous_native_schema_union")
            schema.update(type="object", oneOf=branches, additionalProperties=False,
                          properties={"kind": {"type": "string", "enum": kinds},
                                      "target_id": {"type": "string"}, "payload": {}},
                          required=["kind", "target_id", "payload"])
        schema.setdefault("description", "Business argument: " + name)
    return properties


class _BrokerTool(Tool):
    skip_forward_signature_validation = True
    output_type = "string"

    def __init__(self, client: NativeTools, operation: str, invocations: HostInvocations):
        super().__init__()
        self.name, self.description = TOOL_NAMES[operation], DESCRIPTIONS[operation]
        self.inputs = _inputs(operation)
        self._client, self._operation, self._invocations = client, operation, invocations

    def forward(self, **arguments) -> str:
        # Native export omits top-level additionalProperties, and native input
        # checks are shallow. Always perform complete closed validation here.
        payload = SCHEMAS[self._operation].model_validate(arguments).model_dump()
        return encode_result(self._client.invoke(self._operation, payload, framework="smolagents",
                                                 tool_call_id=self._invocations.current()))


def build_tools(client: NativeTools, *, invocations: HostInvocations) -> list[Tool]:
    """Create six native Tools; this neither installs a dispatch hook nor a sandbox."""
    if not isinstance(invocations, HostInvocations):
        raise TypeError("host_invocations_required")
    return [_BrokerTool(client, operation, invocations) for operation in OPERATIONS]
