"""Alert state, alert deliveries, reports, and report deliveries."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from shsm.core.timeutils import to_iso
from shsm.database.connection import Database


class AlertsRepo:
    def __init__(self, db: Database):
        self.db = db

    def get(self, fingerprint: str) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM alerts WHERE fingerprint=?", (fingerprint,))
        return dict(row) if row else None

    def active(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM alerts WHERE state='ACTIVE' ORDER BY first_alerted_at")]

    def all(self, limit: int = 200) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM alerts ORDER BY last_notified_at DESC LIMIT ?", (limit,))]

    def activate(self, fingerprint: str, finding_id: Optional[int], severity: str, category: str, title: str,
                 now: datetime) -> None:
        ts = to_iso(now)
        self.db.execute(
            "INSERT INTO alerts (fingerprint, finding_id, severity, category, title, state, first_alerted_at, last_notified_at) "
            "VALUES (?,?,?,?,?,'ACTIVE',?,?) ON CONFLICT(fingerprint) DO UPDATE SET finding_id=excluded.finding_id, "
            "severity=excluded.severity, title=excluded.title, state='ACTIVE', last_notified_at=excluded.last_notified_at, "
            "notify_count=alerts.notify_count+1, escalation_level=0, recovered_at=NULL",
            (fingerprint, finding_id, severity, category, title, ts, ts))

    def touch(self, fingerprint: str, now: datetime, escalation_level: Optional[int] = None) -> None:
        if escalation_level is None:
            self.db.execute("UPDATE alerts SET last_notified_at=?, notify_count=notify_count+1 WHERE fingerprint=?",
                            (to_iso(now), fingerprint))
        else:
            self.db.execute(
                "UPDATE alerts SET last_notified_at=?, notify_count=notify_count+1, escalation_level=? WHERE fingerprint=?",
                (to_iso(now), escalation_level, fingerprint))

    def recover(self, fingerprint: str, now: datetime) -> None:
        self.db.execute("UPDATE alerts SET state='RECOVERED', recovered_at=? WHERE fingerprint=?", (to_iso(now), fingerprint))

    def add_delivery(self, now: datetime, kind: str, subject: str, recipients: Sequence[str], status: str,
                     attempts: int, error: Optional[str], fingerprints: Sequence[str]) -> int:
        cur = self.db.execute(
            "INSERT INTO alert_deliveries (created_at, kind, subject, recipients, status, attempts, error, fingerprints_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (to_iso(now), kind, subject[:300], ",".join(recipients), status, attempts, error, json.dumps(list(fingerprints))))
        return int(cur.lastrowid or 0)

    def deliveries(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM alert_deliveries ORDER BY id DESC LIMIT ?", (limit,))]

    def deliveries_in_period(self, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM alert_deliveries WHERE created_at>=? AND created_at<? ORDER BY id", (to_iso(start), to_iso(end)))]

    def purge(self, before: datetime) -> int:
        n = self.db.execute("DELETE FROM alert_deliveries WHERE created_at<?", (to_iso(before),)).rowcount
        n += self.db.execute("DELETE FROM alerts WHERE state='RECOVERED' AND recovered_at<?", (to_iso(before),)).rowcount
        return n


class ReportsRepo:
    def __init__(self, db: Database):
        self.db = db

    def add(self, kind: str, start: datetime, end: datetime, now: datetime, html_path: Optional[str],
            pdf_path: Optional[str], summary: Dict[str, Any]) -> int:
        cur = self.db.execute(
            "INSERT INTO reports (kind, period_start, period_end, generated_at, html_path, pdf_path, status, summary_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (kind, to_iso(start), to_iso(end), to_iso(now), html_path, pdf_path, "GENERATED", json.dumps(summary, default=str)))
        return int(cur.lastrowid or 0)

    def add_delivery(self, report_id: int, now: datetime, recipients: Sequence[str], status: str, attempts: int,
                     error: Optional[str]) -> None:
        self.db.execute(
            "INSERT INTO report_deliveries (report_id, created_at, recipients, status, attempts, error) VALUES (?,?,?,?,?,?)",
            (report_id, to_iso(now), ",".join(recipients), status, attempts, error))
        if status == "SENT":
            self.db.execute("UPDATE reports SET status='SENT' WHERE id=?", (report_id,))

    def already_sent(self, kind: str, start: datetime) -> bool:
        return bool(self.db.scalar(
            "SELECT COUNT(*) FROM reports WHERE kind=? AND period_start=? AND status='SENT'", (kind, to_iso(start)), default=0))

    def list(self, limit: int = 50) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM reports ORDER BY id DESC LIMIT ?", (limit,))]

    def purge(self, before: datetime) -> List[str]:
        """Delete old report rows and return file paths that should be removed from disk."""
        rows = self.db.query("SELECT id, html_path, pdf_path FROM reports WHERE generated_at<?", (to_iso(before),))
        paths: List[str] = []
        for r in rows:
            paths += [p for p in (r["html_path"], r["pdf_path"]) if p]
            self.db.execute("DELETE FROM reports WHERE id=?", (r["id"],))
        return paths
