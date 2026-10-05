"""Bounded filesystem helpers."""

from __future__ import annotations

import os
import time
from typing import Tuple


def bounded_dir_size(path: str, max_entries: int = 200000, max_seconds: float = 20.0) -> Tuple[int, bool, int]:
    """Sum file sizes under ``path`` without following symlinks. Returns ``(bytes, complete, entries)``.

    The scan stops when either bound is exceeded and reports ``complete=False``; callers must not treat an
    incomplete size as authoritative.
    """
    deadline = time.monotonic() + max_seconds
    total = 0
    entries = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                for entry in it:
                    entries += 1
                    if entries > max_entries or time.monotonic() > deadline:
                        return total, False, entries
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                    except OSError:
                        continue
        except OSError:
            continue
    return total, True, entries
