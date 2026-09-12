"""Host-only enforcement of a frozen explicit-field protection set.

Pure matching raises only fixed errors. The broker records and pauses after
the caller's transaction ends, never from inside an action admission savepoint.
No semantic judge, observe setting, audit hash, or human approval overrides it.
"""
from __future__ import annotations

import json
import math

from .authority import AuthorizationError


class ProtectedContentError(AuthorizationError):
    def __init__(self, *, invalid=False):
        super().__init__("protected_check_failed" if invalid else "protected_value_blocked",
            "敏感字段检查无法完成，内容已扣留。" if invalid else "内容含有受保护字段，已扣留并暂停后续操作。")


def check_candidate(protected_data, candidate):
    """Check text and decoded JSON leaves, including JSON-in-string arguments.

This covers literal values and the finite normalizations of explicit_labels_v1.
It does not decode arbitrary encodings, join separate requests, or stop inference.
The bounded collector rejects unsupported/oversized data without a prefix scan.
"""
    if protected_data is None:
        return
    from .protected_data import ProtectedDataError
    from .protected_fields import ProtectionError
    parts, used, nodes = [], 0, 0

    def collect(value, depth=0):
        nonlocal used, nodes
        nodes += 1
        if depth > 32 or nodes > 16384:
            raise ProtectedContentError(invalid=True)
        if type(value) is str:
            used += len(value)
            if used > 262144:
                raise ProtectedContentError(invalid=True)
            parts.append(value)
            # Tool arguments can themselves be JSON strings. Decode only a
            # complete bounded JSON value, not arbitrary backslash sequences.
            stripped = value.strip()
            if stripped and stripped[0] in '{["':
                try:
                    # Retain duplicate keys: overwriting an earlier escaped
                    # value would hide content that some tool parsers display.
                    nested = json.loads(stripped, object_pairs_hook=lambda pairs: tuple(pairs))
                except (ValueError, RecursionError):
                    return
                collect(nested, depth + 1)
        elif type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise ProtectedContentError(invalid=True)
                collect(key, depth + 1)
                collect(item, depth + 1)
        elif type(value) in (list, tuple):
            for item in value:
                collect(item, depth + 1)
        elif value is None or type(value) is bool:
            return
        elif type(value) in (int, float):
            if type(value) is float and not math.isfinite(value):
                raise ProtectedContentError(invalid=True)
            collect(str(value), depth + 1)
        else:
            raise ProtectedContentError(invalid=True)

    try:
        collect(candidate)
        if protected_data.match_output("\n\n".join(parts)):
            raise ProtectedContentError()
    except (ProtectedDataError, ProtectionError, UnicodeError, RecursionError, OverflowError):
        raise ProtectedContentError(invalid=True) from None
