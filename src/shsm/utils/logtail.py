"""Incremental log reading with rotation/truncation handling."""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from shsm.core.timeutils import to_iso
from shsm.database.connection import Database

log = logging.getLogger(__name__)

HEAD_BYTES = 256


@dataclass
class TailResult:
    lines: List[str] = field(default_factory=list)
    status: str = "ok"  # ok | first_seen | rotated | truncated | missing | unreadable
    bytes_read: int = 0
    more_available: bool = False
    error: Optional[str] = None


def _head_hash(fh) -> str:
    fh.seek(0)
    return hashlib.sha1(fh.read(HEAD_BYTES), usedforsecurity=False).hexdigest()  # noqa: S324 - identity only


class LogTailer:
    """Persist (device, inode, offset, head hash) per log file in SQLite and read only new, complete lines."""

    def __init__(self, db: Database):
        self.db = db

    def _load(self, path: str):
        return self.db.query_one("SELECT * FROM log_cursors WHERE path=?", (path,))

    def _save(self, path: str, st: os.stat_result, offset: int, head: str, now: datetime) -> None:
        self.db.execute(
            "INSERT INTO log_cursors (path, device, inode, offset, head_hash, size, updated_at) VALUES (?,?,?,?,?,?,?) "
            "ON CONFLICT(path) DO UPDATE SET device=excluded.device, inode=excluded.inode, offset=excluded.offset, "
            "head_hash=excluded.head_hash, size=excluded.size, updated_at=excluded.updated_at",
            (path, st.st_dev, st.st_ino, offset, head, st.st_size, to_iso(now)),
        )

    def read_new(self, path: str, now: datetime, max_bytes: int = 20 * 1024 * 1024,
                 start_at_end_on_first_seen: bool = True, max_lines: int = 500000) -> TailResult:
        """Return new complete lines since the last call.

        * first sight: start at end of file (old history is never re-read) unless told otherwise;
        * inode/device change or different file head: treated as rotation, read from the start;
        * size smaller than the stored offset: treated as truncation, read from the start;
        * only complete (newline-terminated) lines are consumed so partial writes are never half-parsed;
        * at most ``max_bytes`` are processed per call.
        """
        try:
            fh = open(path, "rb")  # noqa: SIM115 - closed in finally
        except FileNotFoundError:
            return TailResult(status="missing", error="file not found")
        except OSError as exc:
            return TailResult(status="unreadable", error=exc.strerror or str(exc))
        try:
            st = os.fstat(fh.fileno())
            cur = self._load(path)
            head = _head_hash(fh)
            status = "ok"
            if cur is None:
                if start_at_end_on_first_seen:
                    self._save(path, st, st.st_size, head, now)
                    return TailResult(status="first_seen")
                offset, status = 0, "first_seen"
            else:
                offset = int(cur["offset"])
                same_file = cur["inode"] == st.st_ino and cur["device"] == st.st_dev
                if not same_file:
                    offset, status = 0, "rotated"
                elif st.st_size < offset:
                    offset, status = 0, "truncated"
                elif cur["head_hash"] != head and st.st_size >= HEAD_BYTES and offset >= HEAD_BYTES:
                    # same inode, different content at the head => copytruncate-style rotation
                    offset, status = 0, "rotated"

            fh.seek(offset)
            data = fh.read(max_bytes)
            more = (offset + len(data)) < st.st_size
            last_nl = data.rfind(b"\n")
            if last_nl == -1:
                # no complete line: only advance if we hit the byte budget with a single giant line
                consumed = len(data) if (len(data) >= max_bytes) else 0
                chunk = b"" if consumed == 0 else data
            else:
                consumed = last_nl + 1
                chunk = data[:consumed]
            text = chunk.decode("utf-8", errors="replace")
            lines = text.splitlines()
            if len(lines) > max_lines:
                # honour the line budget: only consume the bytes of the lines we return
                lines = lines[:max_lines]
                consumed = len(("\n".join(lines) + "\n").encode("utf-8", errors="replace"))
                more = True
            self._save(path, st, offset + consumed, head, now)
            return TailResult(lines=lines, status=status, bytes_read=consumed, more_available=more)
        except OSError as exc:
            return TailResult(status="unreadable", error=exc.strerror or str(exc))
        finally:
            fh.close()
