"""Immutable host-owned source bindings for explicit protected fields.

No filesystem, model, or database access is performed here. The caller supplies
the original UTF-8 texts and their independently trusted SHA256 values, keeps
the resulting private JSON outside every agent mount, and binds that file in
its profile manifest. Loading always requires those same trusted sources and
recompiles them; a serialized field list is never its own authority.

This composes protected_fields' finite explicit-label policy. Empty matches do
not establish general secrecy. Only public_summary() and LeakMatch identifiers
are suitable for public reports. Source objects, private JSON, and the binding
digest are private: even a hash of a low-entropy value can disclose that value.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import hashlib
import json
import re

from .protected_fields import (
    POLICY_VERSION, LeakMatch, MaskedText, ProtectedValue, ProtectionError, ProtectionLimits,
    detect_protected_values, mask_protected_fields,
)


SCHEMA_VERSION = 1
MAX_RESOURCES = 128
MAX_RESOURCE_BYTES = 262_144
MAX_TOTAL_SOURCE_BYTES = 8_388_608
MAX_PRIVATE_BYTES = 33_554_432
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)


class ProtectedDataError(ValueError):
    """A stable code only; never a resource name, source fragment, or value."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _resource_bytes(text, digest):
    valid = type(text) is str and type(digest) is str and _SHA256.fullmatch(digest)
    if not valid or len(text) > MAX_RESOURCE_BYTES:
        raise ProtectedDataError("invalid_host_resource")
    raw = None
    try:
        raw = text.encode("utf-8")
    except UnicodeError:
        pass
    # Raise outside the decoder exception context; it may retain source text.
    if raw is None or len(raw) > MAX_RESOURCE_BYTES:
        raise ProtectedDataError("invalid_host_resource")
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ProtectedDataError("host_resource_sha256_mismatch")
    return raw


@dataclass(frozen=True, slots=True, repr=False)
class HostResource:
    """Original text and trusted digest; both are host-private inputs."""

    text: str = field(repr=False)
    sha256: str = field(repr=False)

    def __post_init__(self):
        _resource_bytes(self.text, self.sha256)

    def __repr__(self):
        return "HostResource(<private UTF-8 source>)"


@dataclass(frozen=True, slots=True, repr=False)
class _BoundResource:
    name: str
    source: HostResource
    masked: MaskedText
    resource_ref: str


def _canonical(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _strict_private_json(raw):
    if type(raw) is not bytes or not raw or len(raw) > MAX_PRIVATE_BYTES:
        raise ProtectedDataError("invalid_protected_data_json")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def constant(_):
        raise ValueError

    value = None
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, UnicodeError, RecursionError):
        pass
    if (type(value) is not dict or set(value) != {"schema_version", "rules_version", "resources"}
            or type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION
            or type(value["rules_version"]) is not str or type(value["resources"]) is not list
            or len(value["resources"]) > MAX_RESOURCES):
        raise ProtectedDataError("invalid_protected_data_json")
    if value["rules_version"] != POLICY_VERSION:
        raise ProtectedDataError("protected_data_rules_changed")
    return value


def _source_inputs(resources):
    if not isinstance(resources, Mapping) or len(resources) > MAX_RESOURCES:
        raise ProtectedDataError("invalid_host_resources")
    result, total = [], 0
    for name, source in resources.items():
        if (type(name) is not str or not name or len(name) > 128
                or any(ord(char) < 32 or ord(char) == 127 for char in name)
                or type(source) is not HostResource):
            raise ProtectedDataError("invalid_host_resources")
        name_bytes = None
        try:
            name_bytes = name.encode("utf-8")
        except UnicodeError:
            pass
        if name_bytes is None or len(name_bytes) > 512:
            raise ProtectedDataError("invalid_host_resources")
        raw = _resource_bytes(source.text, source.sha256)
        total += len(raw)
        if total > MAX_TOTAL_SOURCE_BYTES:
            raise ProtectedDataError("protected_sources_too_large")
        # Snapshot both strings; the caller's mapping is not retained.
        result.append((name, HostResource(source.text, source.sha256)))
    result.sort(key=lambda item: item[0])
    if len({name for name, _ in result}) != len(result):
        raise ProtectedDataError("invalid_host_resources")
    return result


def _scan(text):
    result = None
    try:
        result = mask_protected_fields(text)
    except ProtectionError:
        pass
    if result is None:
        raise ProtectedDataError("protected_source_scan_failed")
    return result


def _matches(text, values):
    result = None
    try:
        result = detect_protected_values(text, values)
    except ProtectionError:
        pass
    if result is None:
        raise ProtectedDataError("protected_data_match_failed")
    return result


def _masked_source_matches(masked, values):
    if _matches(masked.masked_text, values):
        return True
    if masked.parsed_format != "json" or not values:
        return False
    # The position-preserving scanner already accepted this bounded JSON;
    # placeholders only replace scalar values. Preserve ALL object pairs when
    # decoding so duplicate keys cannot erase an earlier leaking key or value.
    # Numeric tokens remain text and use the same finite amount policy.
    decoded, valid = None, False
    try:
        decoded = json.loads(masked.masked_text, object_pairs_hook=tuple,
                             parse_int=str, parse_float=str)
        valid = True
    except (ValueError, UnicodeError, RecursionError):
        pass
    if not valid:
        raise ProtectedDataError("protected_data_json_source_invalid")
    limits = ProtectionLimits()
    pending, nodes = [(decoded, 0)], 0
    while pending:
        value, depth = pending.pop()
        nodes += 1
        # Each original JSON member can contribute a key and a pair tuple.
        if nodes > 3 * limits.max_json_nodes or depth > 3 * limits.max_json_depth:
            raise ProtectedDataError("protected_data_json_source_too_large")
        if type(value) is str:
            if _matches(value, values):
                return True
        elif type(value) in (tuple, list):
            pending.extend((item, depth + 1) for item in value)
    return False


def _private_record(resource):
    fields = []
    for item in resource.masked.fields:
        fragment = resource.source.text[item.source_start:item.source_end]
        fields.append({
            "field_id": resource.resource_ref + "_" + item.field_id,
            "source_field_id": item.field_id, "kind": item.kind, "label": item.label,
            "value": item.value, "source_fragment": fragment,
            "source_start": item.source_start, "source_end": item.source_end,
            "source_byte_start": item.source_byte_start, "source_byte_end": item.source_byte_end,
            "source_sha256": item.source_sha256,
        })
    return {"name": resource.name, "resource_ref": resource.resource_ref,
            "source_sha256": resource.source.sha256,
            "source_bytes": len(resource.source.text.encode("utf-8")),
            "parsed_format": resource.masked.parsed_format,
            "masked_text": resource.masked.masked_text, "fields": fields}


@dataclass(frozen=True, slots=True, repr=False, init=False)
class HostProtectedData:
    """Fixed source snapshots, masks, and match values owned by the host.

    Construct with compile() or from_private_json(), never from worker input.
    A source SHA passed to redacted() must be computed/validated by the host.
    The returned text is always from this immutable snapshot, not caller text.
    """

    _resources: tuple[_BoundResource, ...] = field(repr=False)
    _values: tuple[ProtectedValue, ...] = field(repr=False)
    _private_json: bytes = field(repr=False)

    def __init__(self):
        raise ProtectedDataError("protected_data_compile_required")

    @classmethod
    def compile(cls, resources: Mapping[str, HostResource]) -> HostProtectedData:
        bound, values = [], []
        for index, (name, source) in enumerate(_source_inputs(resources), 1):
            masked = _scan(source.text)
            if masked.policy != POLICY_VERSION:
                raise ProtectedDataError("protected_data_rules_changed")
            resource_ref = f"r{index:04d}"
            bound.append(_BoundResource(name, source, masked, resource_ref))
            values.extend(ProtectedValue(resource_ref + "_" + item.field_id, item.kind, item.value)
                          for item in masked.fields)
        values = tuple(values)
        # Validate the TOTAL set, including the scanner's count/size limits.
        # No truncation, per-resource reset, or empty fallback is permitted.
        _matches("", values)
        for resource in bound:
            # A known value may recur in an unlabelled field in ANOTHER source.
            # Without an unambiguous labelled span, refuse to expose that source.
            if _masked_source_matches(resource.masked, values):
                raise ProtectedDataError("protected_data_cross_resource_disclosure")
        raw = _canonical({"schema_version": SCHEMA_VERSION, "rules_version": POLICY_VERSION,
                          "resources": [_private_record(item) for item in bound]})
        if len(raw) > MAX_PRIVATE_BYTES:
            raise ProtectedDataError("protected_data_json_too_large")
        result = object.__new__(cls)
        object.__setattr__(result, "_resources", tuple(bound))
        object.__setattr__(result, "_values", values)
        object.__setattr__(result, "_private_json", raw)
        return result

    @classmethod
    def from_private_json(cls, raw: bytes, *, resources: Mapping[str, HostResource]) -> HostProtectedData:
        value = _strict_private_json(raw)
        compiled = cls.compile(resources)
        # Canonical bytes distinguish bool/int and float/int as well as every
        # nested field, source fragment, range, mask, ordering, and collection.
        canonical = None
        try:
            canonical = _canonical(value)
        except (ValueError, UnicodeError, RecursionError):
            pass
        if canonical is None or canonical != compiled._private_json:
            raise ProtectedDataError("protected_data_binding_mismatch")
        return compiled

    def to_private_json(self) -> bytes:
        """Canonical private bytes; pin/store outside agent-accessible paths."""
        return self._private_json

    def binding_digest(self) -> str:
        """Private profile/Broker binding only; not a safe public fingerprint."""
        return hashlib.sha256(self._private_json).hexdigest()

    def public_summary(self) -> dict:
        return {"schema_version": SCHEMA_VERSION, "rules_version": POLICY_VERSION,
                "resource_count": len(self._resources), "field_count": len(self._values)}

    def redacted(self, resource_id: str, source_sha256: str) -> str:
        if type(resource_id) is not str or type(source_sha256) is not str or not _SHA256.fullmatch(source_sha256):
            raise ProtectedDataError("invalid_protected_resource_request")
        for resource in self._resources:
            if resource.name == resource_id:
                if resource.source.sha256 != source_sha256:
                    raise ProtectedDataError("protected_resource_changed")
                return resource.masked.masked_text
        raise ProtectedDataError("protected_resource_missing")

    def match_output(self, text: str) -> tuple[LeakMatch, ...]:
        return _matches(text, self._values)

    def __repr__(self):
        return f"HostProtectedData(resources={len(self._resources)}, fields={len(self._values)})"
