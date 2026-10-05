"""Path validation helpers: approved roots, symlink-escape prevention, name validation."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable, List, Optional

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_UNIT_RE = re.compile(r"^[A-Za-z0-9:_.@\\-]{1,128}$")
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")
_SLUG_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def is_valid_domain(name: str) -> bool:
    return bool(name) and bool(_DOMAIN_RE.match(name.lower()))


def is_valid_unit_name(name: str) -> bool:
    return bool(_UNIT_RE.match(name))


def is_valid_username(name: str) -> bool:
    return bool(_USER_RE.match(name))


def is_valid_slug(name: str) -> bool:
    return bool(_SLUG_RE.match(name)) and name not in (".", "..")


def normalize_domain(name: str) -> Optional[str]:
    n = name.strip().lower().rstrip(".")
    if n.startswith("*."):
        return None
    return n if is_valid_domain(n) else None


def real(path: str) -> str:
    return os.path.realpath(path)


def is_within(path: str, roots: Iterable[str]) -> bool:
    """True if the *resolved* path lies inside one of the resolved roots (defeats symlink escapes and ``..``)."""
    try:
        resolved = Path(real(path))
    except (OSError, ValueError):
        return False
    for root in roots:
        try:
            rr = Path(real(root))
        except (OSError, ValueError):
            continue
        if resolved == rr or rr in resolved.parents:
            return True
    return False


def safe_absolute(path: str) -> Optional[str]:
    """Return ``path`` if it is a clean absolute path without NUL bytes or parent traversal."""
    if not path or "\x00" in path:
        return None
    if not os.path.isabs(path):
        return None
    if ".." in Path(path).parts:
        return None
    return path


def matches_exclusion(rel_path: str, patterns: Iterable[str]) -> bool:
    """Exclusion by path component or by relative-path prefix (patterns use forward slashes)."""
    rel = rel_path.replace(os.sep, "/").strip("/")
    parts = rel.split("/")
    for pat in patterns:
        p = pat.strip("/")
        if not p:
            continue
        if "/" in p:
            if rel == p or rel.startswith(p + "/") or ("/" + p + "/") in ("/" + rel + "/"):
                return True
        elif p in parts:
            return True
    return False


def existing(paths: Iterable[str]) -> List[str]:
    return [p for p in paths if os.path.exists(p)]
