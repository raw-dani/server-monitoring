"""Findings lifecycle and per-check latest results."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from shsm.core.components import component_for
from shsm.core.findings import (
    CheckResult,
    FindingCandidate,
    FindingStatus,
    Severity,
)
from shsm.core.timeutils import to_iso
from shsm.database.connection import Database

_SEV_SQL = "CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END"


class FindingsRepo:
    def __init__(self, db: Database):
        self.db = db

    def upsert(self, cand: FindingCandidate, now: datetime) -> Tuple[int, str]:
        """Insert or refresh a finding. Returns (id, event) where event is NEW | REOPENED | UPDATED."""
        ts = to_iso(now)
        fp = cand.fingerprint
        row = self.db.query_one("SELECT id, status, severity FROM findings WHERE fingerprint=?", (fp,))
        details = json.dumps(cand.details, default=str, sort_keys=True)
        if row is None:
            cur = self.db.execute(
                "INSERT INTO findings (uid, fingerprint, category, check_id, component, asset, severity, confidence, "
                "status, title, evidence, recommendation, source, first_seen, last_seen, details_json, status_changed_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (uuid.uuid4().hex[:12], fp, cand.category, cand.check_id, component_for(cand.check_id), cand.asset,
                 cand.severity.value, cand.confidence.value, FindingStatus.OPEN.value, cand.title, cand.evidence,
                 cand.recommendation, cand.source, ts, ts, details, ts),
            )
            return int(cur.lastrowid or 0), "NEW"
        event = "UPDATED"
        status = row["status"]
        if status == FindingStatus.RESOLVED.value:
            self.db.execute(
                "UPDATE findings SET status='OPEN', resolved_at=NULL, reopen_count=reopen_count+1, status_changed_at=? WHERE id=?",
                (ts, row["id"]),
            )
            event = "REOPENED"
        self.db.execute(
            "UPDATE findings SET severity=?, confidence=?, title=?, evidence=?, recommendation=?, source=?, "
            "last_seen=?, occurrences=occurrences+1, details_json=?, component=? WHERE id=?",
            (cand.severity.value, cand.confidence.value, cand.title, cand.evidence, cand.recommendation, cand.source,
             ts, details, component_for(cand.check_id), row["id"]),
        )
        return int(row["id"]), event

    def record_run(self, candidates: Sequence[FindingCandidate], scopes: Sequence[str], now: datetime,
                   pairs: Iterable[Tuple[str, str]] = ()) -> Dict[str, List[int]]:
        """Persist candidates and resolve findings that were not seen again.

        A finding is auto-resolved only if (a) its check_id falls in an explicitly fully-evaluated scope prefix, or
        (b) a *conclusive* check result for the same (check_id, asset) was produced in this run. Unknown/error
        results therefore never resolve anything.
        """
        out: Dict[str, List[int]] = {"NEW": [], "REOPENED": [], "UPDATED": [], "RESOLVED": []}
        seen: Set[str] = set()
        with self.db.transaction():
            for cand in candidates:
                fid, event = self.upsert(cand, now)
                out[event].append(fid)
                seen.add(cand.fingerprint)
            out["RESOLVED"] = self.resolve_missing(scopes, seen, now)
            out["RESOLVED"] += self.resolve_pairs(pairs, seen, now)
        return out

    def resolve_pairs(self, pairs: Iterable[Tuple[str, str]], seen: Set[str], now: datetime) -> List[int]:
        resolved: List[int] = []
        ts = to_iso(now)
        for check_id, asset in set(pairs):
            for r in self.db.query(
                "SELECT id, fingerprint FROM findings WHERE status IN ('OPEN','ACKNOWLEDGED','SUPPRESSED') "
                "AND check_id=? AND asset=?", (check_id, asset)):
                if r["fingerprint"] in seen:
                    continue
                self.db.execute(
                    "UPDATE findings SET status='RESOLVED', resolved_at=?, status_changed_at=? WHERE id=?",
                    (ts, ts, r["id"]))
                resolved.append(int(r["id"]))
        return resolved

    def resolve_missing(self, prefixes: Iterable[str], seen: Set[str], now: datetime) -> List[int]:
        resolved: List[int] = []
        ts = to_iso(now)
        for prefix in prefixes:
            rows = self.db.query(
                "SELECT id, fingerprint FROM findings WHERE status IN ('OPEN','ACKNOWLEDGED','SUPPRESSED') "
                "AND check_id LIKE ? ESCAPE '\\'",
                (prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",),
            )
            for r in rows:
                if r["fingerprint"] in seen:
                    continue
                self.db.execute(
                    "UPDATE findings SET status='RESOLVED', resolved_at=?, status_changed_at=? WHERE id=?",
                    (ts, ts, r["id"]),
                )
                resolved.append(int(r["id"]))
        return resolved

    # ------------------------------------------------------------------ queries
    def list(self, statuses: Optional[Sequence[str]] = None, min_severity: Optional[Severity] = None,
             category: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM findings WHERE 1=1"
        params: List[Any] = []
        if statuses:
            placeholders = ",".join("?" * len(statuses))
            sql += f" AND status IN ({placeholders})"
            params += list(statuses)
        if min_severity:
            sql += f" AND {_SEV_SQL} >= ?"
            params.append(min_severity.rank)
        if category:
            sql += " AND category=?"
            params.append(category)
        sql += f" ORDER BY {_SEV_SQL} DESC, last_seen DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.db.query(sql, params)]

    def get(self, ident: str) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM findings WHERE uid=? OR fingerprint=?", (ident, ident))
        return dict(row) if row else None

    def by_id(self, fid: int) -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM findings WHERE id=?", (fid,))
        return dict(row) if row else None

    def set_status(self, ident: str, status: FindingStatus, note: str, now: datetime) -> bool:
        row = self.get(ident)
        if not row:
            return False
        self.db.execute(
            "UPDATE findings SET status=?, status_note=?, status_changed_at=?, resolved_at=? WHERE id=?",
            (status.value, note, to_iso(now), to_iso(now) if status == FindingStatus.RESOLVED else None, row["id"]),
        )
        return True

    def open_counts(self) -> Dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for r in self.db.query(
            "SELECT severity, COUNT(*) AS n FROM findings WHERE status IN ('OPEN','ACKNOWLEDGED') GROUP BY severity"
        ):
            out[r["severity"]] = r["n"]
        return out

    def in_period(self, start: datetime, end: datetime) -> List[Dict[str, Any]]:
        """Findings first seen, still open, or resolved during [start, end)."""
        s, e = to_iso(start), to_iso(end)
        rows = self.db.query(
            f"SELECT * FROM findings WHERE first_seen < ? AND (resolved_at IS NULL OR resolved_at >= ?) "
            f"ORDER BY {_SEV_SQL} DESC, first_seen",
            (e, s),
        )
        return [dict(r) for r in rows]

    def purge(self, before: datetime) -> int:
        """Delete only RESOLVED findings older than the retention window; open findings are always preserved."""
        return self.db.execute(
            "DELETE FROM findings WHERE status='RESOLVED' AND resolved_at < ?", (to_iso(before),)
        ).rowcount


class CheckRepo:
    def __init__(self, db: Database):
        self.db = db

    def upsert_many(self, results: Sequence[CheckResult], now: datetime) -> None:
        ts = to_iso(now)
        with self.db.transaction():
            for r in results:
                success = ts if r.status.conclusive else None
                self.db.execute(
                    "INSERT INTO check_results (check_id, asset, category, status, summary, details_json, source, checked_at, last_success_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(check_id, asset) DO UPDATE SET category=excluded.category, "
                    "status=excluded.status, summary=excluded.summary, details_json=excluded.details_json, "
                    "source=excluded.source, checked_at=excluded.checked_at, "
                    "last_success_at=COALESCE(excluded.last_success_at, check_results.last_success_at)",
                    (r.check_id, r.asset, r.category, r.status.value, r.summary,
                     json.dumps(r.details, default=str, sort_keys=True), r.source, ts, success),
                )

    def drop_stale(self, prefixes: Iterable[str], keep: Set[Tuple[str, str]]) -> int:
        """Remove rows within evaluated scopes that this run did not produce (e.g. a removed domain)."""
        removed = 0
        for prefix in prefixes:
            like = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            for r in self.db.query("SELECT check_id, asset FROM check_results WHERE check_id LIKE ? ESCAPE '\\'", (like,)):
                if (r["check_id"], r["asset"]) not in keep:
                    self.db.execute("DELETE FROM check_results WHERE check_id=? AND asset=?", (r["check_id"], r["asset"]))
                    removed += 1
        return removed

    def all(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query("SELECT * FROM check_results ORDER BY check_id, asset")]

    def get(self, check_id: str, asset: str = "") -> Optional[Dict[str, Any]]:
        row = self.db.query_one("SELECT * FROM check_results WHERE check_id=? AND asset=?", (check_id, asset))
        return dict(row) if row else None

    def by_prefix(self, prefix: str) -> List[Dict[str, Any]]:
        return [dict(r) for r in self.db.query(
            "SELECT * FROM check_results WHERE check_id LIKE ? ESCAPE '\\' ORDER BY check_id, asset",
            (prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",),
        )]

    def counts_by_status(self) -> Dict[str, int]:
        return {r["status"]: r["n"] for r in self.db.query("SELECT status, COUNT(*) AS n FROM check_results GROUP BY status")}
