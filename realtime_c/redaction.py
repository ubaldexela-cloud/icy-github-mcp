"""Shared redaction for logs and tool text.

The marker is the lowercase string ``[redacted]``. Matching runs on the
full string, and only then is the result sliced. ``handler.py`` is not
imported and is not modified.
"""

from __future__ import annotations

import logging
import re
from typing import Any

REDACTED_MARKER = "[redacted]"

# Longer tokens first so github_pat_ is not partially matched as something else.
_SECRET_RE = re.compile(
    r"(?:"
    r"github_pat_[A-Za-z0-9_]+"
    r"|ghp_[A-Za-z0-9]+"
    r"|gho_[A-Za-z0-9]+"
    r"|ghu_[A-Za-z0-9]+"
    r"|ghs_[A-Za-z0-9]+"
    r"|ghr_[A-Za-z0-9]+"
    r"|sk-[A-Za-z0-9_\-]+"
    r"|A(?:KIA|SIA)[0-9A-Z]{16}"
    r"|(?i:authorization\s*:\s*(?:bearer|token|basic)\s+\S+)"
    r"|(?<![A-Za-z0-9])Bearer\s+\S+"
    r"|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    r"|[a-zA-Z][a-zA-Z0-9+.\-]{0,32}://[^/\s:@]{1,256}:[^/\s@]{1,256}@"
    r"|grant_hmac_key=[^&\s]+"
    r"|client_secret=[^&\s]+"
    r")",
    re.DOTALL,
)

_TRIGGER_SNIPPETS = (
    "ghp_",
    "github_pat_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "sk-",
    "AKIA",
    "ASIA",
    "Bearer ",
    "authorization:",
    "Authorization:",
    "-----BEGIN",
    "://",
    "grant_hmac_key=",
    "client_secret=",
)


def _has_trigger(value: str) -> bool:
    return any(snippet in value for snippet in _TRIGGER_SNIPPETS)


def redact_text(value: object, max_len: int | None = 500) -> str:
    """Replace secret-shaped substrings, then optionally slice."""
    text = _SECRET_RE.sub(REDACTED_MARKER, str(value))
    if max_len is None:
        return text
    return text[:max_len]


def redact_structure(value: Any, max_len: int | None = 500) -> Any:
    """Redact nested text. Numbers, bools, and short trigger-free strings stay."""
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        if len(value) <= 64 and not _has_trigger(value):
            return value
        return redact_text(value, max_len=max_len)
    if isinstance(value, dict):
        cleaned: dict[Any, Any] = {}
        for key, item in value.items():
            new_key = key
            if isinstance(key, str) and (len(key) > 64 or _has_trigger(key)):
                new_key = redact_text(key, max_len=max_len)
            cleaned[new_key] = redact_structure(item, max_len=max_len)
        return cleaned
    if isinstance(value, tuple):
        return tuple(redact_structure(item, max_len=max_len) for item in value)
    if isinstance(value, list):
        return [redact_structure(item, max_len=max_len) for item in value]
    return redact_text(str(value), max_len=max_len)


def is_forbidden_git_segment(part: str) -> bool:
    """True for ``.git`` / ``.github`` after trailing dot and space strip."""
    return part.rstrip(". ").casefold() in {".git", ".github"}


class RedactingLogFilter(logging.Filter):
    """Rewrite a log record's message and arguments before they are emitted."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact_text(record.msg)
        elif record.msg is not None:
            record.msg = redact_structure(record.msg)
        if record.args:
            record.args = redact_structure(record.args)
        return True
