"""Inline the fixed Pydantic tool schemas for the host model bridge.

The native FunctionTools retain their original schemas and validators. This
presentation-only copy avoids requiring a provider to follow local references.
Unknown or recursive references fail before any model request is sent.
"""
from ._runtime_support import json_bytes, load_json


_MAPS = {"properties", "patternProperties", "dependentSchemas"}
_SINGLE = {"items", "additionalProperties", "unevaluatedProperties", "propertyNames", "contains",
           "not", "if", "then", "else", "additionalItems", "unevaluatedItems"}
_LISTS = {"allOf", "anyOf", "oneOf", "prefixItems"}
_RESOURCES = {"$id", "$anchor", "$dynamicRef", "$dynamicAnchor", "$recursiveRef", "$recursiveAnchor"}


def inline_model_schema(schema):
    """Return an independent, equivalent schema with root-owned refs expanded.

Only ``#/$defs/name`` references are emitted by the pinned, fixed tools. Other
reference formats and nested schema resources are deliberately unsupported.
Literal objects inside const/enum/default/examples are data, not schema nodes.
"""
    if type(schema) is not dict:
        raise ValueError("sdk_invalid_model_schema")
    stack, nodes = [(schema, 0)], 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > 16384 or depth > 64:
            raise ValueError("sdk_model_schema_limit")
        if type(value) is dict:
            if any(type(key) is not str for key in value):
                raise ValueError("sdk_invalid_model_schema")
            stack.extend((child, depth + 1) for child in value.values())
        elif type(value) is list:
            stack.extend((child, depth + 1) for child in value)
        elif value is not None and type(value) not in (str, bool, int, float):
            raise ValueError("sdk_invalid_model_schema")
    raw = json_bytes(schema)
    if len(raw) > 256 * 1024:
        raise ValueError("sdk_model_schema_limit")
    source = load_json(raw)
    definitions = source.get("$defs", {})
    if type(definitions) is not dict:
        raise ValueError("sdk_invalid_model_schema")
    expanded_nodes = 0

    def reference_name(ref):
        prefix = "#/$defs/"
        if type(ref) is not str or not ref.startswith(prefix):
            raise ValueError("sdk_model_schema_reference_not_allowed")
        token = ref[len(prefix):]
        if not token or "/" in token or "%" in token:
            raise ValueError("sdk_model_schema_reference_not_allowed")
        name, index = "", 0
        while index < len(token):
            char = token[index]
            if char == "~":
                if index + 1 >= len(token) or token[index + 1] not in "01":
                    raise ValueError("sdk_invalid_model_schema_reference")
                name += "~" if token[index + 1] == "0" else "/"
                index += 2
            else:
                name += char
                index += 1
        if name not in definitions:
            raise ValueError("sdk_unknown_model_schema_reference")
        return name

    def expand(node, active=(), depth=0, *, root=False):
        nonlocal expanded_nodes
        expanded_nodes += 1
        if expanded_nodes > 16384 or depth > 64:
            raise ValueError("sdk_model_schema_limit")
        if type(node) is bool:
            return node
        if (type(node) is not dict or set(node) & _RESOURCES
                or "$defs" in node and not root):
            raise ValueError("sdk_model_schema_not_supported")
        if "$ref" in node:
            # These keywords consume evaluation annotations from neighboring
            # applicators. Moving them into an allOf branch changes their scope.
            if {"unevaluatedProperties", "unevaluatedItems"} & set(node):
                raise ValueError("sdk_model_schema_reference_scope_not_supported")
            name = reference_name(node["$ref"])
            if name in active:
                raise ValueError("sdk_recursive_model_schema")
            target = expand(definitions[name], (*active, name), depth + 1)
            siblings = {key: value for key, value in node.items() if key not in {"$ref", "$defs", "title"}}
            # JSON Schema applies ref siblings conjunctively. An overwrite
            # merge can silently discard a bound or an additionalProperties rule.
            return {"allOf": [target, expand(siblings, active, depth + 1)]} if siblings else target
        result = {}
        for key, value in node.items():
            if key in {"$defs", "title"}:
                continue
            if key in _MAPS:
                if type(value) is not dict:
                    raise ValueError("sdk_invalid_model_schema")
                result[key] = {name: expand(child, active, depth + 1) for name, child in value.items()}
            elif key in _SINGLE:
                result[key] = expand(value, active, depth + 1)
            elif key in _LISTS:
                if type(value) is not list:
                    raise ValueError("sdk_invalid_model_schema")
                result[key] = [expand(child, active, depth + 1) for child in value]
            elif key == "dependencies":
                if type(value) is not dict:
                    raise ValueError("sdk_invalid_model_schema")
                result[key] = {name: child if type(child) is list else expand(child, active, depth + 1)
                               for name, child in value.items()}
            else:
                result[key] = value
        return result

    # Check unused definitions too; a future fixed schema cannot conceal an
    # unsupported resource or recursive definition in an unvisited branch.
    for name, definition in definitions.items():
        expand(definition, (name,))
    result = expand(source, root=True)
    if len(json_bytes(result)) > 256 * 1024:
        raise ValueError("sdk_model_schema_limit")
    return result
