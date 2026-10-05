"""Metric samples, rollups, and retention for metrics."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from shsm.core.findings import Metric
from shsm.core.timeutils import UTC, from_iso, get_tz, to_iso
from shsm.database.connection import Database


class MetricsRepo:
    def __init__(self, db: Database):
        self.db = db

    def insert(self, ts: datetime, metrics: Iterable[Metric]) -> int:
        rows = [(to_iso(ts), m.name, m.asset, m.value) for m in metrics]
        if rows:
            with self.db.transaction():
                self.db.executemany("INSERT INTO metric_samples (ts, metric, asset, value) VALUES (?,?,?,?)", rows)
        return len(rows)

    def latest(self, metric: str, asset: str = "") -> Optional[Tuple[str, float]]:
        row = self.db.query_one(
            "SELECT ts, value FROM metric_samples WHERE metric=? AND asset=? ORDER BY ts DESC, id DESC LIMIT 1",
            (metric, asset),
        )
        return (row["ts"], row["value"]) if row else None

    def window_values(self, metric: str, since: datetime, asset: str = "") -> List[float]:
        rows = self.db.query(
            "SELECT value FROM metric_samples WHERE metric=? AND asset=? AND ts>=? ORDER BY ts",
            (metric, asset, to_iso(since)),
        )
        return [r["value"] for r in rows]

    def series(self, metric: str, since: datetime, until: Optional[datetime] = None, asset: str = "") -> List[Tuple[str, float]]:
        until_iso = to_iso(until) if until else "9999-12-31T23:59:59Z"
        rows = self.db.query(
            "SELECT ts, value FROM metric_samples WHERE metric=? AND asset=? AND ts>=? AND ts<? ORDER BY ts",
            (metric, asset, to_iso(since), until_iso),
        )
        return [(r["ts"], r["value"]) for r in rows]

    def value_at_or_before(self, metric: str, when: datetime, asset: str = "") -> Optional[Tuple[str, float]]:
        row = self.db.query_one(
            "SELECT ts, value FROM metric_samples WHERE metric=? AND asset=? AND ts<=? ORDER BY ts DESC LIMIT 1",
            (metric, asset, to_iso(when)),
        )
        return (row["ts"], row["value"]) if row else None

    def assets(self, metric: str) -> List[str]:
        return [r["asset"] for r in self.db.query("SELECT DISTINCT asset FROM metric_samples WHERE metric=?", (metric,))]

    # ------------------------------------------------------------------ rollups
    def rollup_hourly(self, now: datetime) -> int:
        """Aggregate raw samples from completed hours into hourly rollups (idempotent)."""
        hour_start = now.astimezone(UTC).replace(minute=0, second=0, microsecond=0)
        cutoff = to_iso(hour_start)
        with self.db.transaction():
            cur = self.db.execute(
                "INSERT OR REPLACE INTO metric_rollups_hourly (metric, asset, bucket_start, samples, avg, min, max) "
                "SELECT metric, asset, substr(ts,1,13)||':00:00Z', COUNT(*), AVG(value), MIN(value), MAX(value) "
                "FROM metric_samples WHERE ts < ? AND ts >= COALESCE((SELECT MAX(bucket_start) FROM metric_rollups_hourly), '0000') "
                "GROUP BY metric, asset, substr(ts,1,13)",
                (cutoff,),
            )
        return cur.rowcount

    def rollup_daily(self, now: datetime) -> int:
        """Aggregate completed UTC days from hourly rollups into daily rollups."""
        today = to_iso(now.astimezone(UTC).replace(hour=0, minute=0, second=0, microsecond=0))
        with self.db.transaction():
            cur = self.db.execute(
                "INSERT OR REPLACE INTO metric_rollups_daily (metric, asset, bucket_start, samples, avg, min, max) "
                "SELECT metric, asset, substr(bucket_start,1,10)||'T00:00:00Z', SUM(samples), "
                "SUM(avg*samples)/SUM(samples), MIN(min), MAX(max) "
                "FROM metric_rollups_hourly WHERE bucket_start < ? "
                "GROUP BY metric, asset, substr(bucket_start,1,10)",
                (today,),
            )
        return cur.rowcount

    def period_daily(self, metric: str, start: datetime, end: datetime, tz_name: str, asset: str = "") -> List[Dict[str, object]]:
        """Daily avg/min/max in the local timezone for [start, end), from hourly rollups plus current-hour raw data."""
        self.rollup_hourly(datetime.now(tz=UTC))
        rows = self.db.query(
            "SELECT bucket_start, samples, avg, min, max FROM metric_rollups_hourly "
            "WHERE metric=? AND asset=? AND bucket_start>=? AND bucket_start<? ORDER BY bucket_start",
            (metric, asset, to_iso(start), to_iso(end)),
        )
        tz = get_tz(tz_name)
        days: Dict[str, Dict[str, float]] = {}
        for r in rows:
            local_day = from_iso(r["bucket_start"]).astimezone(tz).strftime("%Y-%m-%d")
            d = days.setdefault(local_day, {"n": 0, "sum": 0.0, "min": float("inf"), "max": float("-inf")})
            d["n"] += r["samples"]
            d["sum"] += r["avg"] * r["samples"]
            d["min"] = min(d["min"], r["min"])
            d["max"] = max(d["max"], r["max"])
        return [
            {"day": day, "avg": d["sum"] / d["n"], "min": d["min"], "max": d["max"], "samples": int(d["n"])}
            for day, d in sorted(days.items()) if d["n"]
        ]

    def period_stats(self, metric: str, start: datetime, end: datetime, asset: str = "") -> Optional[Dict[str, float]]:
        row = self.db.query_one(
            "SELECT SUM(samples) AS n, SUM(avg*samples)/SUM(samples) AS avg, MIN(min) AS min, MAX(max) AS max "
            "FROM metric_rollups_hourly WHERE metric=? AND asset=? AND bucket_start>=? AND bucket_start<?",
            (metric, asset, to_iso(start), to_iso(end)),
        )
        if not row or not row["n"]:
            return None
        return {"avg": row["avg"], "min": row["min"], "max": row["max"], "samples": row["n"]}

    # ---------------------------------------------------------------- retention
    def purge(self, now: datetime, raw_days: int, hourly_days: int, daily_months: int) -> Dict[str, int]:
        raw_cut = to_iso(now - timedelta(days=raw_days))
        hourly_cut = to_iso(now - timedelta(days=hourly_days))
        daily_cut = to_iso(now - timedelta(days=daily_months * 31))
        out = {}
        with self.db.transaction():
            out["raw"] = self.db.execute("DELETE FROM metric_samples WHERE ts<?", (raw_cut,)).rowcount
            out["hourly"] = self.db.execute("DELETE FROM metric_rollups_hourly WHERE bucket_start<?", (hourly_cut,)).rowcount
            out["daily"] = self.db.execute("DELETE FROM metric_rollups_daily WHERE bucket_start<?", (daily_cut,)).rowcount
        return out
