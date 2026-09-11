"""One approved plain-text message through a host-owned, certificate-checked account.

The agent may propose only recipient, subject and body. Account selection and
authorization belong to the caller. An SMTP acknowledgement means the server
accepted the message, not that it reached an inbox. Persist an attempt before
calling: Message-ID is stable for a request ID, but SMTP does not deduplicate it.
This module never retries an SMTP transaction or exposes server exception text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import format_datetime
import hashlib
import ipaddress
import json
import re
import smtplib
import ssl
import unicodedata


MAX_SUBJECT_CHARACTERS = 200
MAX_BODY_BYTES = 64 * 1024
SMTP_TIMEOUT_SECONDS = 30
_LOCAL = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*\Z")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_REQUEST_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


def _address(value: str) -> str:
    if type(value) is not str or not value.isascii() or len(value) > 254 or value.count("@") != 1:
        raise ValueError("invalid_mail_address")
    local, domain = value.split("@")
    labels = domain.split(".")
    if (not 1 <= len(local) <= 64 or not _LOCAL.fullmatch(local)
            or len(domain) > 253 or len(labels) < 2
            or any(not _LABEL.fullmatch(label) for label in labels)):
        raise ValueError("invalid_mail_address")
    return local + "@" + domain.lower()


def _has_controls(value: str, *, body: bool = False) -> bool:
    return any(
        (unicodedata.category(character) in {"Cc", "Cf", "Cs"}
         and not (body and character in "\n\t"))
        or (not body and character in "\u2028\u2029")
        for character in value
    )


def validate_draft(value: dict) -> dict[str, str]:
    """Return canonical fields; reject lists, display names and hidden headers.

    Preserve the local part of the address and the visible subject/body. Lower
    case the address domain and normalize CRLF body lines to LF. Body LF and TAB
    are allowed; other controls, invisible formatting and lone CR are rejected.
    """
    if type(value) is not dict or set(value) != {"recipient", "subject", "body"}:
        raise ValueError("invalid_mail_draft_keys")
    recipient = _address(value["recipient"])
    subject, body = value["subject"], value["body"]
    if (type(subject) is not str or len(subject) > MAX_SUBJECT_CHARACTERS
            or _has_controls(subject)):
        raise ValueError("invalid_mail_subject")
    if type(body) is not str:
        raise ValueError("invalid_mail_body")
    body = body.replace("\r\n", "\n")
    if _has_controls(body, body=True) or len(body.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValueError("invalid_mail_body")
    return {"recipient": recipient, "subject": subject, "body": body}


def draft_digest(value: dict) -> str:
    canonical = validate_draft(value)
    encoded = json.dumps(canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class MailAccount:
    """Trusted host configuration. There is deliberately no plaintext/TLS switch."""

    host: str
    port: int
    username: str = field(repr=False)
    password: str = field(repr=False)
    from_address: str = field(repr=False)

    def __post_init__(self):
        if (type(self.host) is not str or not self.host.isascii()
                or not 1 <= len(self.host) <= 253 or "%" in self.host):
            raise ValueError("invalid_mail_account_host")
        try:
            host = str(ipaddress.ip_address(self.host))
        except ValueError:
            if any(not _LABEL.fullmatch(label) for label in self.host.split(".")):
                raise ValueError("invalid_mail_account_host") from None
            host = self.host.lower()
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("invalid_mail_account_port")
        for value, maximum in ((self.username, 1024), (self.password, 16384)):
            if type(value) is not str or not 1 <= len(value) <= maximum or _has_controls(value):
                raise ValueError("invalid_mail_account_credentials")
        object.__setattr__(self, "host", host)
        object.__setattr__(self, "from_address", _address(self.from_address))


def _message(account: MailAccount, draft: dict, request_id: str) -> bytes:
    if type(request_id) is not str or not _REQUEST_ID.fullmatch(request_id):
        raise ValueError("invalid_mail_request_id")
    message = EmailMessage(policy=SMTP)
    message["From"] = account.from_address
    message["To"] = draft["recipient"]
    message["Subject"] = draft["subject"]
    message["Date"] = format_datetime(datetime.now(timezone.utc))
    identifier = hashlib.sha256(request_id.encode("ascii")).hexdigest()
    message["Message-ID"] = "<yxm." + identifier + "@yuanxingmu.invalid>"
    # Bytes content preserves the exact approved UTF-8 body, including whether
    # it has a final newline. MIME base64 cannot introduce additional headers.
    message.set_content(draft["body"].encode("utf-8"), maintype="text", subtype="plain",
                        cte="base64", params={"charset": "utf-8"})
    return message.as_bytes()


def send_email(account: MailAccount, draft: dict, request_id: str) -> dict[str, str]:
    """Attempt one SMTP submission and return only a sanitized outcome.

    not_started is returned only for failures before constructing SMTP_SSL. Any
    later failure is unconfirmed, even when no DATA is known to have been sent.
    A lost response after DATA must never cause an automatic retry. Cancellation
    via BaseException propagates: the caller's durable attempt must remain
    unconfirmed. No state inside this transport establishes send-once authority.
    """
    try:
        if type(account) is not MailAccount:
            raise ValueError("invalid_mail_account")
        canonical = validate_draft(draft)
        payload = _message(account, canonical, request_id)
        context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("mail_certificate_verification_required")
    except Exception:
        return {"outcome": "not_started"}

    client = None
    try:
        client = smtplib.SMTP_SSL(account.host, account.port, timeout=SMTP_TIMEOUT_SECONDS, context=context)
        client.set_debuglevel(0)
        client.login(account.username, account.password)
        refused = client.sendmail(account.from_address, [canonical["recipient"]], payload)
        return {"outcome": "acknowledged" if type(refused) is dict and not refused else "unconfirmed"}
    except Exception:
        return {"outcome": "unconfirmed"}
    finally:
        if client is not None:
            try:
                # A failure while closing cannot undo an already received DATA
                # acknowledgement. Closing does not submit another transaction.
                client.close()
            except Exception:
                pass
