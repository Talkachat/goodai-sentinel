"""Redact secrets and PII from audit records before they are written.

The monitor sees command lines, file paths and agent targets — which can contain
API keys, tokens, passwords, private keys, emails, and card-like numbers. Writing
those verbatim to the audit log would itself be a data leak. This module scrubs a
record (recursively) so the log keeps its forensic value without storing the secret.

Applied centrally in AuditLog.write, so no code path can bypass it.
"""
from __future__ import annotations
import re

_PLACEHOLDER = "«redacted»"

# Order matters: more specific patterns first.
_PATTERNS: list[tuple[re.Pattern, str]] = [
    # private key blocks
    (re.compile(r"-----BEGIN [^-]+ PRIVATE KEY-----.*?-----END [^-]+ PRIVATE KEY-----", re.S), "«private-key»"),
    # common cloud / vendor tokens
    (re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,})"), "«token»"),          # GitHub
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"), "«token»"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "«aws-key»"),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "«api-key»"),                 # OpenAI-style
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"), "«slack-token»"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{3,}"), "«jwt»"),  # JWT
    # key=value / flag secrets:  --password X, token: X, "api_key":"X", PASSWORD=X
    (re.compile(r"(?i)(\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|auth|bearer|credential)s?\b"
                r"[\"']?\s*[:=]\s*[\"']?)([^\s\"',;]{4,})"), r"\1«redacted»"),
    (re.compile(r"(?i)(--?(password|token|secret|api[-_]?key|auth)[= ])([^\s]{4,})"), r"\1«redacted»"),
    # emails (PII)
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "«email»"),
    # card-like 13-19 digit runs (PII) — keep last 4
    (re.compile(r"\b(?:\d[ -]?){12,18}(\d{4})\b"), r"«card»\1"),
]

_SENSITIVE_KEYS = re.compile(r"(?i)(pass(word|wd)?|secret|token|api[_-]?key|access[_-]?key|"
                             r"auth|bearer|credential|private[_-]?key|ssn|card)")


def redact_text(s: str) -> str:
    for rx, repl in _PATTERNS:
        s = rx.sub(repl, s)
    return s


def redact(obj):
    """Recursively redact strings inside dicts/lists. Keys that are themselves the name
    of a secret get their whole value replaced."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and _SENSITIVE_KEYS.search(k) and isinstance(v, (str, int, float)):
                out[k] = _PLACEHOLDER
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj
