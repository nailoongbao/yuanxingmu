"""One explicitly supported email policy; never rewrite arbitrary policy text."""
from __future__ import annotations

import re

from .config import ConfigurationError


_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,127}")
_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def _tool_identifier(value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ConfigurationError(
            "This policy template requires tool names of 1-128 ASCII letters, digits or underscores, starting with a letter"
        )
    return value


def _domain(value: str) -> str:
    if not isinstance(value, str):
        raise ConfigurationError("The allowed email domain must be a literal ASCII domain")
    value = value.lower()
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ConfigurationError("The allowed email domain must be a literal ASCII domain")
    return value


def email_policy(
    source_tool: str = "get_inbox",
    sink_tool: str = "send_email",
    allowed_domain: str = "ourcompany.com",
) -> str:
    """Render the tested ToolCall-bound policy with safely quoted literal names/domain."""
    source_tool = _tool_identifier(source_tool)
    sink_tool = _tool_identifier(sink_tool)
    domain = _domain(allowed_domain)
    # This DSL retains regex backslashes; JSON quoting would escape them a second time.
    recipient_pattern = r"(?i)^[^@\s]+@" + re.escape(domain) + "$"
    return (
        'raise "External email to unknown address" if:\n'
        "    (call: ToolCall) -> (call2: ToolCall)\n"
        f"    call is tool:{source_tool}\n"
        f"    call2 is tool:{sink_tool}\n"
        f"    not (call2 is tool:{sink_tool}({{\n"
        f'      to: "{recipient_pattern}"\n'
        "    }))\n"
    )


def require_template_policy(
    text: str,
    source_tool: str = "get_inbox",
    sink_tool: str = "send_email",
    allowed_domain: str = "ourcompany.com",
) -> str:
    """Accept the complete known template, allowing only CRLF/LF line-ending variation."""
    expected = email_policy(source_tool, sink_tool, allowed_domain)
    if not isinstance(text, str) or text.replace("\r\n", "\n") != expected:
        raise ConfigurationError(
            "The complete source policy must exactly match the supported email-domain template; unknown rules require manual review"
        )
    return expected
