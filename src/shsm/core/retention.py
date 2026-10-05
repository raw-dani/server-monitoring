"""Data retention, metric rollups, and SQLite snapshot backups."""

from __future__ import annotations

import os
from datetime import timedelta
from typing import Any, Dict

from shsm.core.context import Context


def run_retention_and_rollups(ctx: Context) -> Dict[str, Any]:
    now = ctx.now()
    r_cfg = ctx.config.section("retention")

    # 1. Hourly and Daily rollups
    hourly_rolls = ctx.metrics.rollup_hourly(now)
    daily_rolls = ctx.metrics.rollup_daily(now)

    # 2. Metric samples purge
    raw_days = int(r_cfg.get("raw_metrics_days", 30))
    hourly_days = int(r_cfg.get("hourly_rollup_days", 90))
    daily_months = int(r_cfg.get("daily_rollup_months", 12))

    purged_metrics = ctx.metrics.purge(now, raw_days, hourly_days, daily_months)

    # 3. Purge findings (only RESOLVED findings older than findings_days; open findings are preserved)
    findings_days = int(r_cfg.get("findings_days", 365))
    purged_findings = ctx.findings.purge(now - timedelta(days=findings_days))

    # 4. Purge old scan runs
    scan_days = int(r_cfg.get("scan_runs_days", 365))
    purged_runs = ctx.runs.purge(now - timedelta(days=scan_days))

    # 5. Purge old alerts & deliveries
    purged_alerts = ctx.alerts.purge(now - timedelta(days=findings_days))

    # 6. Purge old reports & delete corresponding files
    report_days = int(r_cfg.get("reports_days", 365))
    deleted_report_files = ctx.reports.purge(now - timedelta(days=report_days))
    for fpath in deleted_report_files:
        try:
            if os.path.isfile(fpath):
                os.remove(fpath)
        except OSError:
            pass

    # 7. Purge integrity history
    integ_days = int(r_cfg.get("integrity_days", 180))
    purged_integrity = ctx.integrity.purge(now - timedelta(days=integ_days))

    return {
        "hourly_rollups_created": hourly_rolls,
        "daily_rollups_created": daily_rolls,
        "purged_metrics": purged_metrics,
        "purged_findings": purged_findings,
        "purged_runs": purged_runs,
        "purged_alerts": purged_alerts,
        "deleted_report_files": len(deleted_report_files),
        "purged_integrity": purged_integrity,
    }


def perform_database_backup(ctx: Context) -> str:
    """Create a consistent online SQLite backup using the SQLite backup API."""
    now = ctx.now()
    backup_dir = ctx.config.backup_dir
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)

    timestamp_str = now.strftime("%Y%m%d_%H%M%S")
    dest_path = os.path.join(backup_dir, f"shsm_monitoring_{timestamp_str}.db")

    saved_path = ctx.db.backup_to(dest_path)

    # Rotate old backups
    keep_count = int(ctx.config.get("retention.backup_keep", 14))
    existing = sorted(
        [
            os.path.join(backup_dir, f)
            for f in os.listdir(backup_dir)
            if f.startswith("shsm_monitoring_") and f.endswith(".db")
        ],
        key=os.path.getmtime,
    )

    if len(existing) > keep_count:
        for old in existing[:-keep_count]:
            try:
                os.remove(old)
            except OSError:
                pass

    return saved_path
