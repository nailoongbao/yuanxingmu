"""Bounded, deterministic protection of explicitly labelled source fields.

This is an independent development module: no runtime hooks, IO, model calls,
logs, or storage. ``explicit_labels_v1`` is deliberately a finite policy, not a
secret detector or a guarantee that every secret has been removed. The caller
must supply host-verified source text and keep every ProtectedValue/Field
private. ``repr`` hides values and hashes, but dataclasses.asdict, pickling, or
manual serialization WILL expose them. Low-entropy value hashes are not safe
public identifiers. Public audit results should contain only LeakMatch IDs.

Recognized labels, after Unicode NFKC and case folding of labels only:
* 内部底价 / 底价: decimal amounts, including the AUTO18 natural sentence.
* api_key, access_token, password, client_secret, secret_key; underscore-free
  and hyphenated spellings of the four compound English labels also match.
Ordinary public prices, generic 'token'/'key', and unlabelled secrets do not.

Text credentials use key:value or key=value. Unquoted values are single tokens
terminated by whitespace, a comma, or semicolon. Quote values containing those
characters: double quotes use JSON escapes, single quotes/backticks are literal
and cannot contain escapes or newlines. Chinese amounts allow :, =, 为, 是,
whitespace, or an immediately following number. JSON is strictly parsed with
source positions and duplicate keys preserved. Sensitive JSON values must be
nonempty strings or (for amounts only) numbers; containers/null/bools fail.
Amounts embedded in non-sensitive JSON string fields are not recursively
classified as a second document. Choose the format explicitly for such text.

Output matching is case-sensitive. Listed normalizations are whole-string
NFKC, removal of U+200B/U+200C/U+200D/U+2060/U+FEFF, and decimal amounts with
ASCII/full-width digits, valid comma or space thousands groups, decimal zero
suffixes, optional 元/圆/人民币/RMB/CNY/¥, and 万/万元 (multiply by 10000).
Scientific notation, Chinese number words, arbitrary encoding, arithmetic,
cross-message splitting, and inference are NOT covered. Credentials use token
boundaries; numeric prices reject longer numbers, ASCII identifiers, dates and
numeric path/time components. Equality to a protected amount is conservatively
sensitive even when the same amount is also called public. A remaining known
value outside masked source spans fails with unmasked_protected_value.

Source offsets are half-open Python character AND UTF-8 byte ranges in the
original input. For quoted/JSON values the range includes the complete literal;
the private value is decoded. Masking replaces only these exact source ranges,
preserves other bytes (including duplicate JSON keys), and turns protected JSON
numbers into strings. All failures expose only a stable error code; callers
must withhold the source on failure rather than fall back to its original text.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import json
import re
import unicodedata


POLICY_VERSION = "explicit_labels_v1"
_ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\ufeff")
_KINDS = frozenset({"internal_price", "credential"})
_LABELS = {
    "内部底价": ("internal_price", "内部底价"),
    "底价": ("internal_price", "底价"),
    "apikey": ("credential", "api_key"),
    "accesstoken": ("credential", "access_token"),
    "password": ("credential", "password"),
    "clientsecret": ("credential", "client_secret"),
    "secretkey": ("credential", "secret_key"),
}
for _canonical in ("api_key", "access_token", "client_secret", "secret_key"):
    _LABELS[_canonical] = ("credential", _canonical)
    _LABELS[_canonical.replace("_", "-")] = ("credential", _canonical)
_CREDENTIAL_MARKER = re.compile(
    r"(?<!\w)(?P<label>api[_-]?key|access[_-]?token|password|"
    r"client[_-]?secret|secret[_-]?key)(?!\w)[\"']?[ \t]*[:=][ \t]*",
    re.IGNORECASE | re.ASCII,
)
_PRICE_LABEL = re.compile(r"内部底价|底价")
_NUMBER = r"(?:[0-9]{1,3}(?:[, ][0-9]{3})+|[0-9]+)(?:\.[0-9]+)?"
_AMOUNT = re.compile(
    r"(?:(?:人民币|RMB|CNY|¥)[ \t]*)?"
    r"[+-]?" + _NUMBER + r"(?:[ \t]*(?:万元|万|元|圆))?"
)
_AMOUNT_PARTS = re.compile(
    r"(?:(?:人民币|RMB|CNY|¥)[ \t]*)?"
    r"(?P<number>[+-]?" + _NUMBER + r")(?P<unit>[ \t]*(?:万元|万|元|圆))?\Z"
)
_JSON_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_FIELD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}\Z", re.ASCII)


class ProtectionError(ValueError):
    """An error code only; neither raw input nor private field values."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class ProtectionLimits:
    max_text_chars: int = 262_144
    max_utf8_bytes: int = 1_048_576
    max_normalized_chars: int = 524_288
    max_fields: int = 64
    max_value_chars: int = 4096
    max_total_value_chars: int = 16_384
    max_json_depth: int = 32
    max_json_nodes: int = 8192


@dataclass(frozen=True, slots=True)
class ProtectedValue:
    field_id: str
    kind: str
    value: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProtectedField(ProtectedValue):
    label: str
    source_start: int
    source_end: int
    source_byte_start: int
    source_byte_end: int
    source_sha256: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LeakMatch:
    field_id: str
    rule_id: str


@dataclass(frozen=True, slots=True)
class MaskedText:
    masked_text: str = field(repr=False)
    fields: tuple[ProtectedField, ...]
    parsed_format: str
    policy: str = POLICY_VERSION

    @property
    def report(self) -> str:
        return "按 explicit_labels_v1 匹配到的字段已遮盖"


_DEFAULT_LIMITS = ProtectionLimits()


def _limits(limits: ProtectionLimits) -> None:
    if not isinstance(limits, ProtectionLimits):
        raise ProtectionError("invalid_limits")
    for name in ProtectionLimits.__dataclass_fields__:
        value = getattr(limits, name)
        # Absolute caps keep even caller-supplied limits bounded.
        cap = getattr(_DEFAULT_LIMITS, name)
        if type(value) is not int or not 1 <= value <= cap:
            raise ProtectionError("invalid_limits")


def _text(value: str, limits: ProtectionLimits) -> bytes:
    if not isinstance(value, str):
        raise ProtectionError("invalid_text_type")
    if len(value) > limits.max_text_chars:
        raise ProtectionError("text_too_long")
    try:
        data = value.encode("utf-8")
    except UnicodeError:
        raise ProtectionError("invalid_unicode") from None
    if len(data) > limits.max_utf8_bytes:
        raise ProtectionError("text_too_large")
    return data


def _normalize(value: str, limits: ProtectionLimits) -> str:
    normalized = unicodedata.normalize("NFKC", value)
    if len(normalized) > limits.max_normalized_chars:
        raise ProtectionError("normalization_too_large")
    return "".join(c for c in normalized if c not in _ZERO_WIDTH)


def _shadow(value: str, limits: ProtectionLimits) -> tuple[str, list[int], list[int]]:
    """Normalize label syntax while retaining original character positions."""
    parts, starts, ends = [], [], []
    size = 0
    for index, char in enumerate(value):
        part = "".join(c for c in unicodedata.normalize("NFKC", char) if c not in _ZERO_WIDTH)
        size += len(part)
        if size > limits.max_normalized_chars:
            raise ProtectionError("normalization_too_large")
        parts.append(part)
        starts.extend([index] * len(part))
        ends.extend([index + 1] * len(part))
    return "".join(parts), starts, ends


def _label(value: str, limits: ProtectionLimits) -> tuple[str, str] | None:
    value = _normalize(value, limits).strip().casefold()
    return _LABELS.get(value)


def _amount(value: str, limits: ProtectionLimits) -> Decimal | None:
    value = _normalize(value, limits).strip()
    match = _AMOUNT_PARTS.fullmatch(value)
    if not match:
        return None
    number = match["number"]
    # Thousands groups must consistently use comma OR space, never both.
    integer = number.lstrip("+-").split(".", 1)[0]
    if "," in integer and " " in integer:
        return None
    plain = number.replace(",", "").replace(" ", "")
    if len(plain.replace(".", "").lstrip("+-")) > 64:
        return None
    try:
        with localcontext() as context:
            context.prec = 80
            result = Decimal(plain)
            if match["unit"] and match["unit"].strip() in {"万", "万元"}:
                result *= 10_000
            return result
    except InvalidOperation:
        return None


def _identifier(char: str) -> bool:
    # CJK words can immediately precede/follow a Chinese amount.
    return bool(char) and (char.isdecimal() or char == "_" or (char.isascii() and char.isalpha()))


def _numeric_boundary(text: str, start: int, end: int) -> bool:
    before = text[start - 1] if start else ""
    after = text[end] if end < len(text) else ""
    if _identifier(before) or _identifier(after):
        return False
    # Date, path, time, decimal, or invalid grouping components are not prices.
    separators = "/\\:.,+-"
    if before in separators and before:
        prior = text[start - 2] if start >= 2 else ""
        if _identifier(prior) or before in "/\\":
            return False
    if after in separators and after:
        following = text[end + 1] if end + 1 < len(text) else ""
        if _identifier(following) or after in "/\\":
            return False
    return True


def _credential_boundary(text: str, start: int, end: int, value: str) -> bool:
    def word(char: str) -> bool:
        # Chinese prose does not put spaces around an embedded credential.
        return bool(char) and (_identifier(char) or char == "-")
    before = text[start - 1] if start else ""
    after = text[end] if end < len(text) else ""
    return not ((word(value[0]) and word(before)) or (word(value[-1]) and word(after)))


def _contains_token(text: str, value: str) -> bool:
    position = 0
    while True:
        start = text.find(value, position)
        if start < 0:
            return False
        end = start + len(value)
        if _credential_boundary(text, start, end, value):
            return True
        position = start + 1


def _values(values: Sequence[ProtectedValue], limits: ProtectionLimits) -> tuple[ProtectedValue, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        raise ProtectionError("invalid_protected_values")
    if len(values) > limits.max_fields:
        raise ProtectionError("too_many_fields")
    result = tuple(values)
    identifiers: set[str] = set()
    total = 0
    for item in result:
        if not isinstance(item, ProtectedValue):
            raise ProtectionError("invalid_protected_value")
        if not isinstance(item.field_id, str) or not _FIELD_ID.fullmatch(item.field_id):
            raise ProtectionError("invalid_field_id")
        if item.field_id in identifiers:
            raise ProtectionError("duplicate_field_id")
        identifiers.add(item.field_id)
        if not isinstance(item.kind, str) or item.kind not in _KINDS:
            raise ProtectionError("invalid_field_kind")
        _text(item.value, limits)
        if not item.value or not _normalize(item.value, limits):
            raise ProtectionError("empty_protected_value")
        if len(item.value) > limits.max_value_chars:
            raise ProtectionError("value_too_long")
        total += len(item.value)
        if total > limits.max_total_value_chars:
            raise ProtectionError("total_values_too_long")
        if item.kind == "internal_price" and _amount(item.value, limits) is None:
            raise ProtectionError("unsupported_price_value")
    return result


def detect_protected_values(
    output: str,
    protected_values: Sequence[ProtectedValue],
    *,
    limits: ProtectionLimits = _DEFAULT_LIMITS,
) -> tuple[LeakMatch, ...]:
    """Return at most one field/rule result per private value, never its text.

    Rule IDs are exact_token, unicode_token, price_exact, and price_decimal.
    An empty tuple means no match under this policy, not that output is safe.
    Do not use a model-supplied list as the authoritative protection set.
    """
    _limits(limits)
    _text(output, limits)
    values = _values(protected_values, limits)
    normalized = _normalize(output, limits)
    amounts = []
    if any(item.kind == "internal_price" for item in values):
        for match in _AMOUNT.finditer(normalized):
            if _numeric_boundary(normalized, match.start(), match.end()):
                amount = _amount(match[0], limits)
                if amount is not None:
                    amounts.append((match[0], amount))
    matches = []
    for item in values:
        if item.kind == "internal_price":
            expected = _amount(item.value, limits)
            found = [literal for literal, amount in amounts if amount == expected]
            if found:
                # Only call it exact when the original output contains the
                # same full amount spelling; normalization is otherwise named.
                exact = any(literal == item.value and literal in output for literal in found)
                matches.append(LeakMatch(item.field_id, "price_exact" if exact else "price_decimal"))
        elif _contains_token(output, item.value):
            matches.append(LeakMatch(item.field_id, "exact_token"))
        elif _contains_token(normalized, _normalize(item.value, limits)):
            matches.append(LeakMatch(item.field_id, "unicode_token"))
    return tuple(matches)


class _Collector:
    def __init__(self, source: str, limits: ProtectionLimits):
        self.source, self.limits = source, limits
        self.items: list[tuple[int, int, str, str, str]] = []
        self.json_literals: list[tuple[int, int, str]] = []
        self.total = 0

    def add(self, start: int, end: int, kind: str, label: str, value: str) -> None:
        _text(value, self.limits)
        if not value or not _normalize(value, self.limits):
            raise ProtectionError("empty_protected_value")
        if len(value) > self.limits.max_value_chars:
            raise ProtectionError("value_too_long")
        if kind == "internal_price" and _amount(value, self.limits) is None:
            raise ProtectionError("unsupported_price_value")
        if len(self.items) >= self.limits.max_fields:
            raise ProtectionError("too_many_fields")
        self.total += len(value)
        if self.total > self.limits.max_total_value_chars:
            raise ProtectionError("total_values_too_long")
        self.items.append((start, end, kind, label, value))

    def finish(self, parsed_format: str) -> MaskedText:
        self.items.sort(key=lambda row: row[0])
        fields, chunks = [], []
        cursor = 0
        for index, (start, end, kind, label, value) in enumerate(self.items, 1):
            if start < cursor:
                raise ProtectionError("overlapping_protected_fields")
            field_id = f"f{index:04d}"
            raw = self.source[start:end].encode("utf-8")
            byte_start = len(self.source[:start].encode("utf-8"))
            fields.append(ProtectedField(field_id, kind, value, label, start, end,
                                         byte_start, byte_start + len(raw),
                                         hashlib.sha256(raw).hexdigest()))
            placeholder = f"[PROTECTED:{field_id}]"
            if parsed_format == "json":
                placeholder = json.dumps(placeholder, ensure_ascii=False)
            chunks.extend((self.source[cursor:start], placeholder))
            cursor = end
        chunks.append(self.source[cursor:])
        masked = "".join(chunks)
        # Do not return a document with a known value repeated elsewhere under
        # a public label or no label. This is a conflict, not reclassification.
        if detect_protected_values(masked, fields, limits=self.limits):
            raise ProtectionError("unmasked_protected_value")
        # JSON can expose the same value through escapes in another value or
        # even a key. Check its accepted, decoded meaning, not only source bytes.
        covered = {(start, end) for start, end, *_ in self.items}
        if fields:
            for start, end, literal in self.json_literals:
                if (start, end) not in covered and detect_protected_values(literal, fields, limits=self.limits):
                    raise ProtectionError("unmasked_protected_value")
        return MaskedText(masked, tuple(fields), parsed_format)


def _json_string(source: str, start: int) -> tuple[str, int]:
    try:
        value, end = json.decoder.scanstring(source, start + 1, True)
        value.encode("utf-8")
        return value, end
    except (ValueError, UnicodeError):
        raise ProtectionError("invalid_json_string") from None


class _JSONParser:
    """Small position-preserving parser; never reconstruct objects as dicts."""

    def __init__(self, source: str, collector: _Collector):
        self.source, self.collector = source, collector
        self.index, self.nodes = 0, 0

    def space(self) -> None:
        while self.index < len(self.source) and self.source[self.index] in " \t\r\n":
            self.index += 1

    def take(self, char: str) -> None:
        if self.index >= len(self.source) or self.source[self.index] != char:
            raise ProtectionError("invalid_json")
        self.index += 1

    def value(self, depth: int = 0, label: tuple[str, str] | None = None) -> None:
        self.space()
        self.nodes += 1
        if self.nodes > self.collector.limits.max_json_nodes:
            raise ProtectionError("too_many_json_nodes")
        if depth > self.collector.limits.max_json_depth:
            raise ProtectionError("json_too_deep")
        if self.index >= len(self.source):
            raise ProtectionError("invalid_json")
        start = self.index
        char = self.source[start]
        if char == '"':
            decoded, self.index = _json_string(self.source, start)
            self.collector.json_literals.append((start, self.index, decoded))
            if label:
                self.collector.add(start, self.index, *label, decoded)
            return
        if char in "{[":
            if label:
                raise ProtectionError("unsupported_sensitive_value")
            self.index += 1
            closing = "}" if char == "{" else "]"
            self.space()
            if self.index < len(self.source) and self.source[self.index] == closing:
                self.index += 1
                return
            while True:
                self.space()
                member_label = None
                if char == "{":
                    if self.index >= len(self.source) or self.source[self.index] != '"':
                        raise ProtectionError("invalid_json")
                    key_start = self.index
                    key, self.index = _json_string(self.source, self.index)
                    self.collector.json_literals.append((key_start, self.index, key))
                    member_label = _label(key, self.collector.limits)
                    self.space()
                    self.take(":")
                self.value(depth + 1, member_label)
                self.space()
                if self.index < len(self.source) and self.source[self.index] == closing:
                    self.index += 1
                    return
                self.take(",")
        number = _JSON_NUMBER.match(self.source, self.index)
        if number:
            self.index = number.end()
            if label:
                if label[0] != "internal_price":
                    raise ProtectionError("unsupported_sensitive_value")
                self.collector.add(start, self.index, *label, number[0])
            return
        for token in ("true", "false", "null"):
            if self.source.startswith(token, self.index):
                self.index += len(token)
                if label:
                    raise ProtectionError("unsupported_sensitive_value")
                return
        raise ProtectionError("invalid_json")

    def parse(self) -> None:
        self.value()
        self.space()
        if self.index != len(self.source):
            raise ProtectionError("invalid_json")


def _text_literal(source: str, start: int) -> tuple[str, int]:
    if start >= len(source):
        raise ProtectionError("missing_protected_value")
    quote = source[start]
    if quote != unicodedata.normalize("NFKC", quote) and unicodedata.normalize("NFKC", quote) in "\"'`":
        raise ProtectionError("unsupported_text_quote")
    if quote == '"':
        value, end = _json_string(source, start)
        _quoted_end(source, end)
        return value, end
    if quote in "'`":
        end = source.find(quote, start + 1)
        if end < 0:
            raise ProtectionError("unterminated_text_value")
        value = source[start + 1:end]
        if "\\" in value or "\n" in value or "\r" in value:
            raise ProtectionError("unsupported_text_escape")
        _quoted_end(source, end + 1)
        return value, end + 1
    if quote in "{[":
        raise ProtectionError("unsupported_sensitive_value")
    end = start
    while end < len(source) and not source[end].isspace() and source[end] not in ",，;；":
        end += 1
    return source[start:end], end


def _quoted_end(source: str, end: int) -> None:
    if end < len(source) and not source[end].isspace() and source[end] not in ",，;；.。!?！？)]}":
        raise ProtectionError("invalid_text_value_suffix")


def _plain_text(source: str, collector: _Collector) -> None:
    view, starts, ends = _shadow(source, collector.limits)
    for match in _CREDENTIAL_MARKER.finditer(view):
        if any(start <= starts[match.start()] < end for start, end, *_ in collector.items):
            continue
        if match.end() == len(view):
            raise ProtectionError("missing_protected_value")
        start = starts[match.end()]
        value, end = _text_literal(source, start)
        if not value:
            raise ProtectionError("empty_protected_value")
        label = _label(match["label"], collector.limits)
        assert label is not None
        collector.add(start, end, *label, value)
    for match in _PRICE_LABEL.finditer(view):
        if any(start <= starts[match.start()] < end for start, end, *_ in collector.items):
            continue
        index = match.end()
        if index < len(view) and view[index] in "\"'" and match.start() and view[match.start() - 1] == view[index]:
            index += 1
        while index < len(view) and view[index] in " \t":
            index += 1
        explicit = index < len(view) and view[index] in ":=为是"
        if explicit:
            index += 1
            while index < len(view) and view[index] in " \t":
                index += 1
        if index < len(view) and view[index] in "\"'`":
            start = starts[index]
            value, end = _text_literal(source, start)
            collector.add(start, end, "internal_price", match[0], value)
            continue
        number = _AMOUNT.match(view, index)
        if not number:
            if explicit:
                raise ProtectionError("unsupported_price_value")
            continue  # An instruction such as '内部底价不得外发' is not a value.
        if not _numeric_boundary(view, number.start(), number.end()):
            raise ProtectionError("unsupported_price_value")
        start, end = starts[number.start()], ends[number.end() - 1]
        collector.add(start, end, "internal_price", match[0], source[start:end])


def mask_protected_fields(
    text: str,
    *,
    format: str = "auto",
    limits: ProtectionLimits = _DEFAULT_LIMITS,
) -> MaskedText:
    """Mask only explicit_labels_v1 source fields, or raise a code-only error.

    auto treats a leading '{' or '[' (after whitespace) as JSON and NEVER falls
    back to text on a parse failure. Explicit json also accepts a JSON scalar;
    text supports the documented line/sentence syntax. A caller must not accept
    a model's proposed source hash, field list, or masking result as authority.
    """
    _limits(limits)
    _text(text, limits)
    if not isinstance(format, str) or format not in {"auto", "text", "json"}:
        raise ProtectionError("invalid_format")
    if format == "auto":
        parsed_format = "json" if text.lstrip().startswith(("{", "[")) else "text"
    else:
        parsed_format = format
    collector = _Collector(text, limits)
    if parsed_format == "json":
        _JSONParser(text, collector).parse()
    else:
        _plain_text(text, collector)
    return collector.finish(parsed_format)
