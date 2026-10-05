"""File-integrity baseline and event storage."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from shsm.core.timeutils import to_iso
from shsm.database.connection import Database


class IntegrityRepo:
    def __init__(self, db: Database):
        self.db = db

    def baseline(self) -> Dict[str, Dict[str, Any]]:
        return {r["path"]: dict(r) for r in self.db.query("SELECT * FROM integrity_baseline")}

    def baseline_count(self) -> int:
        return int(self.db.scalar("SELECT COUNT(*) FROM integrity_baseline", default=0))

    def baseline_created(self) -> Optional[str]:
        return self.db.scalar("SELECT MIN(created_at) FROM integrity_baseline")

    def baseline_updated(self) -> Optional[str]:
        return self.db.scalar("SELECT MAX(updated_at) FROM integrity_baseline")

    def upsert_baseline(self, rec: Dict[str, Any], now: datetime) -> None:
        ts = to_iso(now)
        self.db.execute(
            "INSERT INTO integrity_baseline (path, file_type, sha256, size, uid, gid, mode, mtime, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET file_type=excluded.file_type, sha256=excluded.sha256, "
            "size=excluded.size, uid=excluded.uid, gid=excluded.gid, mode=excluded.mode, mtime=excluded.mtime, updated_at=excluded.updated_at",
            (rec["path"], rec["file_type"], rec.get("sha256"), rec.get("size"), rec.get("uid"), rec.get("gid"),
             rec.get("mode"), rec.get("mtime"), ts, ts))

    def delete_baseline(self, path: str) -> None:
        self.db.execute("DELETE FROM integrity_baseline WHERE path=?", (path,))

    def open_events(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM integrity_events WHERE status='OPEN' ORDER BY detected_at, path")]

    def find_open_event(self, path: str, change_type: str) -> Optional[Dict[str, Any]]:
        row = self.db.query_one(
            "SELECT * FROM integrity_events WHERE path=? AND change_type=? AND status='OPEN' ORDER BY id DESC LIMIT 1", (path, change_type))
        return dict(row) if row else None

    def add_event(self, path: str, change_type: str, severity: str, old: Any, new: Any, now: datetime) -> int:
        ts = to_iso(now)
        cur = self.db.execute(
            "INSERT INTO integrity_events (path, change_type, severity, old_json, new_json, detected_at, last_seen_at) "
            "VALUES (?,?,?,?,?,?,?)", (path, change_type, severity, json.dumps(old, default=str), json.dumps(new, default=str), ts, ts))
        return int(cur.lastrowid or 0)

    def touch_event(self, event_id: int, new: Any, now: datetime) -> None:
        self.db.execute("UPDATE integrity_events SET last_seen_at=?, new_json=? WHERE id=?",
                        (to_iso(now), json.dumps(new, default=str), event_id))

    def close_event(self, event_id: int, status: str, now: datetime) -> None:
        self.db.execute("UPDATE integrity_events SET status=?, resolved_at=? WHERE id=?", (status, to_iso(now), event_id))

    def events_in_period(self, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM integrity_events WHERE detected_at<? AND (resolved_at IS NULL OR resolved_at>=?) ORDER BY detected_at",
            (to_iso(end), to_iso(start)))]

    def purge(self, before: datetime) -> int:
        return self.db.execute(
            "DELETE FROM integrity_events WHERE status!='OPEN' AND COALESCE(resolved_at, detected_at)<?", (to_iso(before),)).rowcount
