"""Single definition of every scheduled job; used by the systemd generator, doctor, and staleness checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

UNIT_PREFIX = "shsm-"


@dataclass(frozen=True)
class JobDef:
    name: str  # also the runner job name and the unit suffix: shsm-<name>.service / .timer
    argv: List[str]  # arguments passed to the shsm executable
    calendar: str  # systemd OnCalendar expression (timezone suffix optional)
    description: str
    root: bool = False  # needs root (privileged reads, secrets, setuid for WP-CLI)
    heavy: bool = False  # shares the global heavy-scan lock and is niced
    max_age_seconds: int = 900  # last successful run older than this => stale
    timeout_seconds: int = 600  # systemd TimeoutStartSec
    random_delay: int = 0


def build_jobs(schedule: Optional[Dict[str, Any]] = None) -> List[JobDef]:
    s = schedule or {}
    tz = s.get("timezone", "Asia/Jakarta")
    weekday = str(s.get("weekly_day", "monday")).capitalize()[:3]
    wtime = s.get("weekly_time", "07:00")
    mday = int(s.get("monthly_day", 1))
    mtime = s.get("monthly_time", "07:00")
    return [
        JobDef("health", ["collect", "health"], "*-*-* *:*:00", "CPU/RAM/swap/disk/network/process metrics",
               max_age_seconds=600, timeout_seconds=120),
        JobDef("services", ["collect", "services"], "*-*-* *:*:30", "systemd service monitoring",
               max_age_seconds=600, timeout_seconds=120),
        JobDef("databases", ["collect", "databases"], "*-*-* *:0/5:00", "MariaDB and Redis checks", root=True,
               max_age_seconds=1800, timeout_seconds=180),
        JobDef("openlitespeed", ["collect", "openlitespeed"], "*-*-* *:2/5:00", "OpenLiteSpeed log parsing",
               root=True, max_age_seconds=1800, timeout_seconds=300),
        JobDef("websites-check", ["websites", "check", "--no-ssl"], "*-*-* *:1/10:00", "Website DNS/HTTP checks",
               max_age_seconds=3600, timeout_seconds=600),
        JobDef("websites-ssl", ["websites", "check", "--ssl-only"], "*-*-* 00/6:15:00", "TLS certificate expiry checks",
               max_age_seconds=43200, timeout_seconds=900, random_delay=120),
        JobDef("websites-discover", ["websites", "discover"], "*-*-* 00/6:05:00", "CyberPanel website discovery",
               root=True, max_age_seconds=43200, timeout_seconds=300),
        JobDef("wordpress-discover", ["wordpress", "discover"], "*-*-* 00/6:10:00", "WordPress installation discovery",
               root=True, max_age_seconds=43200, timeout_seconds=600),
        JobDef("wordpress-audit", ["wordpress", "audit"], "*-*-* 03:30:00", "WordPress core/plugin/theme/user audit",
               root=True, heavy=True, max_age_seconds=2 * 86400, timeout_seconds=7200, random_delay=300),
        JobDef("audit-logs", ["security", "audit", "--scope", "logs"], "*-*-* *:3/10:00",
               "SSH authentication log aggregation and Fail2Ban log summary", root=True,
               max_age_seconds=3600, timeout_seconds=300),
        JobDef("audit-host", ["security", "audit", "--scope", "host"], "*-*-* *:17:00",
               "SSH config, firewall, Fail2Ban, listening ports, patches", root=True,
               max_age_seconds=7200, timeout_seconds=600),
        JobDef("integrity", ["integrity", "check"], "*-*-* 00/8:20:00", "Incremental file integrity check",
               root=True, max_age_seconds=86400, timeout_seconds=1800, random_delay=120),
        JobDef("scan-quick", ["security", "scan", "--profile", "quick", "--only", "heuristic,clamav"],
               "*-*-* 04:00:00", "Daily heuristic + ClamAV quick scan", root=True, heavy=True,
               max_age_seconds=2 * 86400, timeout_seconds=7200),
        JobDef("scan-full", ["security", "scan", "--profile", "full", "--only", "heuristic,clamav"],
               "Sun *-*-* 02:00:00", "Weekly heuristic + ClamAV full scan (low-traffic window)", root=True,
               heavy=True, max_age_seconds=9 * 86400, timeout_seconds=4 * 3600),
        JobDef("lynis", ["security", "scan", "--only", "lynis"], "Sat *-*-* 03:00:00", "Weekly Lynis audit",
               root=True, heavy=True, max_age_seconds=9 * 86400, timeout_seconds=3600),
        JobDef("rootkit", ["security", "scan", "--profile", "full", "--only", "rootkit"], "Sat *-*-* 04:00:00",
               "Weekly rkhunter/chkrootkit scan", root=True, heavy=True, max_age_seconds=9 * 86400,
               timeout_seconds=5400),
        JobDef("heartbeat", ["external", "send"], "*-*-* *:0/5:45", "External heartbeat", root=True,
               max_age_seconds=1200, timeout_seconds=120),
        JobDef("report-weekly", ["report", "weekly", "--send"], f"{weekday} *-*-* {wtime}:00 {tz}",
               "Weekly HTML/PDF report", root=True, max_age_seconds=9 * 86400, timeout_seconds=900),
        JobDef("report-monthly", ["report", "monthly", "--send"], f"*-*-{mday:02d} {mtime}:00 {tz}",
               "Monthly HTML/PDF report", root=True, max_age_seconds=35 * 86400, timeout_seconds=900),
        JobDef("retention", ["retention", "run"], "*-*-* 05:30:00", "Rollups and retention", root=True,
               max_age_seconds=2 * 86400, timeout_seconds=1800),
        JobDef("db-backup", ["database", "backup"], "*-*-* 05:00:00", "SQLite backup", root=True,
               max_age_seconds=2 * 86400, timeout_seconds=900),
    ]


JOBS = build_jobs()
JOBS_BY_NAME = {j.name: j for j in JOBS}
HEAVY_LOCK = "heavy"
