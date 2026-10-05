"""Operational tables: scan runs, key/value state, log cursors, audit log, server info, score snapshots, heartbeats."""

from __future__ import annotations

import json
import os
import platform
import socket
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from shsm.core.timeutils import to_iso
from shsm.database.connection import Database


class RunsRepo:
    def __init__(self, db: Database):
        self.db = db

    # ---- scan runs
    def start(self, job: str, profile: str, now: datetime) -> int:
        cur = self.db.execute(
            "INSERT INTO scan_runs (job, profile, started_at, status, pid) VALUES (?,?,?,?,?)",
            (job, profile, to_iso(now), "RUNNING", os.getpid()),
        )
        return int(cur.lastrowid or 0)

    def finish(self, run_id: int, now: datetime, status: str, complete: bool, exit_code: int,
               summary: Dict[str, Any], errors: List[str], tool_versions: Dict[str, str], duration: float) -> None:
        self.db.execute(
            "UPDATE scan_runs SET finished_at=?, status=?, complete=?, exit_code=?, summary_json=?, errors_json=?, "
            "tool_versions_json=?, duration_seconds=? WHERE id=?",
            (to_iso(now), status, 1 if complete else 0, exit_code, json.dumps(summary, default=str),
             json.dumps(errors[:50]), json.dumps(tool_versions), duration, run_id),
        )

    def mark_interrupted(self, now: datetime, alive_pids: Optional[set] = None) -> int:
        """Mark RUNNING rows whose process is gone as INTERRUPTED (never as clean)."""
        n = 0
        for r in self.db.query("SELECT id, pid FROM scan_runs WHERE status='RUNNING'"):
            if r["pid"] == os.getpid():
                continue
            alive = _pid_alive(r["pid"]) if alive_pids is None else r["pid"] in alive_pids
            if not alive:
                self.db.execute(
                    "UPDATE scan_runs SET status='INTERRUPTED', complete=0, finished_at=? WHERE id=?", (to_iso(now), r["id"])
                )
                n += 1
        return n

    def last(self, job: str, only_success: bool = False) -> Optional[Dict[str, Any]]:
        sql = "SELECT * FROM scan_runs WHERE job=?"
        if only_success:
            sql += " AND status IN ('SUCCESS','PARTIAL') AND finished_at IS NOT NULL"
        row = self.db.query_one(sql + " ORDER BY started_at DESC, id DESC LIMIT 1", (job,))
        return dict(row) if row else None

    def last_success_time(self, job: str, complete_only: bool = False) -> Optional[str]:
        sql = "SELECT finished_at FROM scan_runs WHERE job=? AND status IN ('SUCCESS'%s) AND finished_at IS NOT NULL"
        sql = sql % ("" if complete_only else ",'PARTIAL'")
        row = self.db.query_one(sql + " ORDER BY finished_at DESC LIMIT 1", (job,))
        return row["finished_at"] if row else None

    def recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,))]

    def jobs(self) -> List[str]:
        return [r["job"] for r in self.db.query("SELECT DISTINCT job FROM scan_runs")]

    def purge(self, before: datetime) -> int:
        return self.db.execute("DELETE FROM scan_runs WHERE started_at<? AND status!='RUNNING'", (to_iso(before),)).rowcount

    # ---- kv state
    def kv_get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        row = self.db.query_one("SELECT value FROM state_kv WHERE key=?", (key,))
        return row["value"] if row else default

    def kv_set(self, key: str, value: str, now: datetime) -> None:
        self.db.execute(
            "INSERT INTO state_kv (key, value, updated_at) VALUES (?,?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, to_iso(now)),
        )

    def kv_get_json(self, key: str, default: Any = None) -> Any:
        raw = self.kv_get(key)
        if raw is None:
            return default
        try:
            return json.loads(raw)
        except ValueError:
            return default

    def kv_set_json(self, key: str, value: Any, now: datetime) -> None:
        self.kv_set(key, json.dumps(value, default=str), now)

    def kv_updated(self, key: str) -> Optional[str]:
        row = self.db.query_one("SELECT updated_at FROM state_kv WHERE key=?", (key,))
        return row["updated_at"] if row else None

    # ---- audit log
    def audit(self, actor: str, action: str, target: str, details: Dict[str, Any], now: datetime) -> None:
        self.db.execute(
            "INSERT INTO audit_log (ts, actor, action, target, details_json) VALUES (?,?,?,?,?)",
            (to_iso(now), actor, action, target, json.dumps(details, default=str)),
        )

    def audit_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    # ---- server info
    def ensure_server_info(self, now: datetime, cpu_count: Optional[int] = None, mem_total: Optional[int] = None) -> Dict[str, Any]:
        row = self.db.query_one("SELECT * FROM server_info WHERE id=1")
        hostname = socket.gethostname()
        os_release = _os_release()
        kernel = platform.release()
        if row is None:
            self.db.execute(
                "INSERT INTO server_info (id, server_id, hostname, os_release, kernel, cpu_count, memory_total_bytes, first_seen, updated_at) "
                "VALUES (1,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex, hostname, os_release, kernel, cpu_count, mem_total, to_iso(now), to_iso(now)),
            )
        else:
            self.db.execute(
                "UPDATE server_info SET hostname=?, os_release=?, kernel=?, cpu_count=COALESCE(?,cpu_count), "
                "memory_total_bytes=COALESCE(?,memory_total_bytes), updated_at=? WHERE id=1",
                (hostname, os_release, kernel, cpu_count, mem_total, to_iso(now)),
            )
        return dict(self.db.query_one("SELECT * FROM server_info WHERE id=1"))  # type: ignore[arg-type]

    def server_info(self) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM server_info WHERE id=1")
        return dict(row) if row else None

    # ---- score snapshots
    def add_snapshot(self, now: datetime, health: Optional[float], health_cov: float, security: Optional[float],
                     security_cov: float, details: Dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO score_snapshots (ts, health_score, health_coverage, security_score, security_coverage, details_json) "
            "VALUES (?,?,?,?,?,?)",
            (to_iso(now), health, health_cov, security, security_cov, json.dumps(details, default=str)),
        )

    def last_snapshot_time(self) -> Optional[str]:
        return self.db.scalar("SELECT MAX(ts) FROM score_snapshots")

    def snapshots(self, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM score_snapshots WHERE ts>=? AND ts<? ORDER BY ts", (to_iso(start), to_iso(end)))]

    def purge_snapshots(self, before: datetime) -> int:
        return self.db.execute("DELETE FROM score_snapshots WHERE ts<?", (to_iso(before),)).rowcount

    # ---- heartbeats
    def add_heartbeat(self, now: datetime, provider: str, status: str, http_status: Optional[int], attempts: int,
                      error: Optional[str], summary: Dict[str, Any]) -> None:
        self.db.execute(
            "INSERT INTO external_heartbeats (sent_at, provider, status, http_status, attempts, error, payload_summary_json) "
            "VALUES (?,?,?,?,?,?,?)",
            (to_iso(now), provider, status, http_status, attempts, error, json.dumps(summary, default=str)),
        )

    def last_heartbeat(self) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM external_heartbeats ORDER BY id DESC LIMIT 1")
        return dict(row) if row else None

    def purge_heartbeats(self, before: datetime) -> int:
        return self.db.execute("DELETE FROM external_heartbeats WHERE sent_at<?", (to_iso(before),)).rowcount

    def purge_audit(self, before: datetime) -> int:
        return self.db.execute("DELETE FROM audit_log WHERE ts<?", (to_iso(before),)).rowcount


def _pid_alive(pid: Optional[int]) -> bool:
    if not pid:
        return False
    try:
        import psutil

        return psutil.pid_exists(int(pid))
    except Exception:
        return False


def _os_release() -> str:
    try:
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return platform.platform()
