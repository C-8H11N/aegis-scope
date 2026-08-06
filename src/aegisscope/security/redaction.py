"""Conservative redaction for evidence written by the runner."""

from __future__ import annotations

import re
from collections.abc import Mapping

SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
    "x-api-key",
}

TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.I | re.S)),
    ("bearer_token", re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{12,}", re.I)),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("api_key", re.compile(r"(?i)\b(api[_-]?key|secret|token)\b\s*[:=]\s*['\"]?[A-Za-z0-9._~+/=-]{12,}")),
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)),
    ("phone", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("cn_id", re.compile(r"(?<!\d)\d{17}[0-9Xx](?!\d)")),
    ("payment_card", re.compile(r"(?<!\d)(?:\d[ -]?){15,18}\d(?!\d)")),
)


def redact_headers(headers: Mapping[str, str]) -> tuple[dict[str, str], list[str]]:
    redacted: dict[str, str] = {}
    hits: list[str] = []
    for name, value in headers.items():
        if name.lower() in SENSITIVE_HEADER_NAMES:
            redacted[name] = "<REDACTED>"
            hits.append(f"header:{name.lower()}")
        else:
            redacted[name] = value
    return redacted, sorted(set(hits))


def redact_text(text: str) -> tuple[str, list[str]]:
    redacted = text
    hits: list[str] = []
    for label, pattern in TEXT_PATTERNS:
        redacted, count = pattern.subn(f"<REDACTED:{label}>", redacted)
        if count:
            hits.append(label)
    return redacted, sorted(set(hits))
