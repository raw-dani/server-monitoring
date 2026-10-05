"""Secret redaction used by logging, the subprocess wrapper, reports, and findings."""

from __future__ import annotations

import re
from typing import Any, Iterable, Optional

REDACTED = "[REDACTED]"

_KEY_NAMES = (
    r"pass(?:word|wd)?|pwd|secret|token|api[_-]?key|apikey|auth(?:orization)?|cookie|session(?:id)?|"
    r"salt|private[_-]?key|credential|bearer|signature|"
    r"(?:AUTH|LOGGED_IN|SECURE_AUTH|NONCE)_(?:KEY|SALT)|DB_PASSWORD|DB_USER"
)

_PATTERNS = [
    # Authorization: Bearer xxx / Token token=xxx
    (re.compile(r"(?i)\b(bearer|token token=)\s*[\"']?([A-Za-z0-9._~+/=-]{6,})"), r"\1 " + REDACTED),
    # key=value / key: value / "key": "value"
    (
        re.compile(
            r"(?i)(?P<k>(?<![A-Za-z])[\"']?(?:" + _KEY_NAMES + r")[\"']?\s*[:=]\s*)"
            r"(?P<v>\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
        ),
        lambda m: m.group("k") + REDACTED,
    ),
    # --password xxx style CLI flags
    (
        re.compile(r"(?i)(--(?:password|passwd|token|secret|api-key|apikey))(\s+|=)(\S+)"),
        lambda m: m.group(1) + m.group(2) + REDACTED,
    ),
    # PEM private keys
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
        REDACTED,
    ),
    # unix password hashes ($6$salt$hash) and bcrypt
    (re.compile(r"\$(?:1|2[aby]?|5|6|y|7)\$[A-Za-z0-9./$]{8,}"), REDACTED),
    # URL credentials  scheme://user:pass@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@"), lambda m: m.group(1) + m.group(2) + ":" + REDACTED + "@"),
]

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def redact(text: Any, extra_secrets: Optional[Iterable[str]] = None) -> str:
    """Return ``text`` with known secret shapes and explicitly supplied secret values removed."""
    s = text if isinstance(text, str) else str(text)
    for secret in extra_secrets or ():
        if secret and len(secret) >= 4:
            s = s.replace(secret, REDACTED)
    for pattern, repl in _PATTERNS:
        s = pattern.sub(repl, s)  # type: ignore[call-overload]
    return s


def sanitize_excerpt(text: Any, max_len: int = 200) -> str:
    """Prepare untrusted text (log lines, file names) for storage: strip control chars, redact, bound length."""
    s = redact(text)
    s = _CONTROL.sub("?", s.replace("\r", " ").replace("\n", " "))
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return s


def redact_mapping(data: Any, secret_keys: Optional[Iterable[str]] = None) -> Any:
    """Recursively redact a nested mapping/list for display (e.g. ``config show --redacted``)."""
    keys = {k.lower() for k in (secret_keys or ())}
    sensitive = re.compile(r"(?i)(" + _KEY_NAMES + r")")
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            ks = str(k)
            if ks.lower().endswith("_file") or ks.lower().endswith("_path"):
                out[k] = v  # file *paths* are not secrets; contents are never read here
            elif ks.lower() in keys or (sensitive.search(ks) and isinstance(v, (str, int, float)) and v != ""):
                out[k] = REDACTED
            else:
                out[k] = redact_mapping(v, secret_keys)
        return out
    if isinstance(data, list):
        return [redact_mapping(v, secret_keys) for v in data]
    if isinstance(data, str):
        return redact(data)
    return data


def mask_ip(ip: str) -> str:
    """Aggregate an address for reports: IPv4 -> /24, IPv6 -> /48."""
    if ":" in ip:
        parts = ip.split(":")
        return ":".join(parts[:3]) + "::/48"
    octets = ip.split(".")
    if len(octets) == 4:
        return ".".join(octets[:3]) + ".0/24"
    return "unknown"


def mask_email(email: str) -> str:
    if "@" not in email:
        return REDACTED
    local, _, domain = email.partition("@")
    return (local[:1] or "?") + "***@" + domain
