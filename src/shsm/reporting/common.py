"""Shared data assembly and formatting helpers for daily, weekly, and monthly reports."""

from __future__ import annotations

import socket
from datetime import datetime
from typing import Any, Dict, List, Optional

from shsm.core.context import Context
from shsm.core.timeutils import format_local
from shsm.reporting.scoring import compute_scores

_SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _safe_latest(ctx: Context, metric: str, asset: str = "") -> Optional[float]:
    res = ctx.metrics.latest(metric, asset)
    return float(res[1]) if res else None


def assemble_metrics_summary(ctx: Context, start: datetime, end: datetime) -> Dict[str, Optional[float]]:
    """Gather CPU, Load, RAM, and root Disk averages/peaks for [start, end)."""
    cpu_stats = ctx.metrics.period_stats("cpu.percent", start, end)
    load_stats = ctx.metrics.period_stats("cpu.load1", start, end)
    mem_stats = ctx.metrics.period_stats("memory.available_percent", start, end)
    disk_stats = ctx.metrics.period_stats("disk.used_percent", start, end, asset="/")

    cpu_avg = cpu_stats["avg"] if cpu_stats else _safe_latest(ctx, "cpu.percent")
    cpu_peak = cpu_stats["max"] if cpu_stats else _safe_latest(ctx, "cpu.percent")
    load_avg = load_stats["avg"] if load_stats else _safe_latest(ctx, "cpu.load1")
    load_peak = load_stats["max"] if load_stats else _safe_latest(ctx, "cpu.load1")
    mem_avg_avail = mem_stats["avg"] if mem_stats else _safe_latest(ctx, "memory.available_percent")
    mem_min_avail = mem_stats["min"] if mem_stats else _safe_latest(ctx, "memory.available_percent")
    disk_avg = disk_stats["avg"] if disk_stats else _safe_latest(ctx, "disk.used_percent", "/")
    disk_peak = disk_stats["max"] if disk_stats else _safe_latest(ctx, "disk.used_percent", "/")

    return {
        "cpu_avg": round(cpu_avg, 1) if cpu_avg is not None else None,
        "cpu_peak": round(cpu_peak, 1) if cpu_peak is not None else None,
        "load_avg": round(load_avg, 2) if load_avg is not None else None,
        "load_peak": round(load_peak, 2) if load_peak is not None else None,
        "mem_avg_avail": round(mem_avg_avail, 1) if mem_avg_avail is not None else None,
        "mem_min_avail": round(mem_min_avail, 1) if mem_min_avail is not None else None,
        "disk_avg": round(disk_avg, 1) if disk_avg is not None else None,
        "disk_peak": round(disk_peak, 1) if disk_peak is not None else None,
    }


def assemble_websites_summary(
    ctx: Context,
    start: datetime,
    end: datetime,
    use_period_uptime: bool = False,
) -> List[Dict[str, Any]]:
    """Build website availability and SSL summary rows for active domains."""
    ssl_certs = ctx.inventory.latest_ssl()
    ssl_map = {c["domain"]: c.get("days_remaining") for c in ssl_certs}
    websites_list: List[Dict[str, Any]] = []

    for site in ctx.inventory.active_websites():
        dom = site["domain"]
        ws_id = site["id"]
        if use_period_uptime:
            uptime_data = ctx.inventory.uptime(ws_id, "https", start, end)
            uptime_pct = float(uptime_data.get("uptime_percent", 100.0)) if uptime_data else 100.0
            avg_ms = uptime_data.get("avg_ms") if uptime_data else None
            websites_list.append({
                "domain": dom,
                "status_code": f"{uptime_pct:.1f}% uptime",
                "uptime_percent": round(uptime_pct, 1),
                "ok": uptime_pct >= 95.0,
                "response_ms": avg_ms,
                "ssl_days": ssl_map.get(dom),
            })
        else:
            last_check = ctx.db.query_one(
                "SELECT status_code, response_ms, ok FROM website_checks WHERE website_id=? ORDER BY id DESC LIMIT 1",
                (ws_id,),
            )
            websites_list.append({
                "domain": dom,
                "status_code": last_check["status_code"] if last_check else "-",
                "ok": bool(last_check["ok"]) if last_check else None,
                "response_ms": last_check["response_ms"] if last_check else None,
                "ssl_days": ssl_map.get(dom),
            })
    return websites_list


def build_action_items(
    open_findings: List[Dict[str, Any]],
    websites: List[Dict[str, Any]],
    metrics_summary: Dict[str, Optional[float]],
) -> List[Dict[str, str]]:
    """Extract top prioritized plain-language action items for rapid admin triage."""
    items: List[Dict[str, str]] = []
    sorted_f = sorted(
        open_findings,
        key=lambda f: _SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 0),
        reverse=True,
    )
    for f in sorted_f[:3]:
        sev = str(f.get("severity", "INFO")).upper()
        title = str(f.get("title", "Temuan server"))
        rec = str(f.get("recommendation") or "Tinjau dan selesaikan temuan terkait.")
        items.append({"priority": sev, "title": title, "action": rec})

    # Add proactive SSL or Disk reminders if not already covered
    if len(items) < 3:
        for w in websites:
            days = w.get("ssl_days")
            if days is not None and days <= 14:
                sev = "CRITICAL" if days <= 7 else "HIGH"
                msg = (
                    f"Sertifikat SSL {w['domain']} sudah kadaluarsa."
                    if days <= 0
                    else f"Sertifikat SSL {w['domain']} tersisa {days:.0f} hari."
                )
                items.append({
                    "priority": sev,
                    "title": msg,
                    "action": "Perbarui SSL via CyberPanel / certbot / acme.sh sebelum browser memblokir akses.",
                })
                if len(items) >= 3:
                    break

    if len(items) < 3:
        disk_peak = metrics_summary.get("disk_peak")
        if disk_peak is not None and disk_peak >= 80.0:
            items.append({
                "priority": "CRITICAL" if disk_peak >= 90.0 else "MEDIUM",
                "title": f"Kapasitas disk root mencapai {disk_peak:.1f}%",
                "action": "Bersihkan log lama (/usr/local/lsws/logs, journalctl --vacuum-time=7d) atau arsipkan backup.",
            })

    return items


def assemble_report_data(
    ctx: Context,
    kind: str,
    title: str,
    period_str: str,
    start: datetime,
    end: datetime,
    use_period_uptime: bool = False,
) -> Dict[str, Any]:
    """Assemble full validated report payload shared by daily, weekly, and monthly generators."""
    tz = ctx.tz
    now = ctx.now()
    hostname = socket.gethostname()

    scores = compute_scores(ctx)
    open_findings = ctx.findings.list(statuses=["OPEN", "ACKNOWLEDGED"], limit=50)
    open_findings.sort(
        key=lambda f: _SEV_ORDER.get(str(f.get("severity", "INFO")).upper(), 0),
        reverse=True,
    )

    period_findings = ctx.findings.in_period(start, end)
    mitigated_findings = [f for f in period_findings if f.get("status") == "RESOLVED"]

    services = ctx.inventory.latest_services()
    websites_list = assemble_websites_summary(ctx, start, end, use_period_uptime=use_period_uptime)
    metrics_summary = assemble_metrics_summary(ctx, start, end)
    action_items = build_action_items(open_findings, websites_list, metrics_summary)

    return {
        "kind": kind,
        "title": title,
        "hostname": hostname,
        "period": period_str,
        "generated_at": format_local(now, tz, "%Y-%m-%d %H:%M:%S %Z"),
        "health_score": scores["health_score"],
        "health_coverage": scores["health_coverage"],
        "security_score": scores["security_score"],
        "security_coverage": scores["security_coverage"],
        "components": scores["components"],
        "findings": open_findings,
        "mitigated_findings": mitigated_findings[:15],
        "resolved_findings_count": len(mitigated_findings),
        "action_items": action_items,
        "services": services,
        "websites": websites_list,
        "metrics_summary": metrics_summary,
    }
