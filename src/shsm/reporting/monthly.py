"""Monthly reporting: monthly rollups, month-over-month comparisons, HTML/PDF generation, and delivery."""

from __future__ import annotations

import os
import socket
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from shsm.core.context import Context
from shsm.core.timeutils import format_local, monthly_period
from shsm.notifications.smtp import SMTPTransport
from shsm.reporting.html import render_html_report
from shsm.reporting.pdf import generate_pdf_report
from shsm.reporting.scoring import compute_scores


def assemble_monthly_data(ctx: Context, start: datetime, end: datetime) -> Dict[str, Any]:
    tz = ctx.tz
    now = ctx.now()
    hostname = socket.gethostname()

    scores = compute_scores(ctx)
    open_findings = ctx.findings.list(statuses=["OPEN", "ACKNOWLEDGED"], limit=50)
    resolved_in_period = ctx.findings.list(statuses=["RESOLVED"], limit=50)
    services = ctx.inventory.latest_services()
    ssl_certs = ctx.inventory.latest_ssl()
    ssl_map = {c["domain"]: c.get("days_remaining") for c in ssl_certs}

    # Website uptime in period
    websites_list = []
    for site in ctx.inventory.active_websites():
        dom = site["domain"]
        ws_id = site["id"]
        uptime_data = ctx.inventory.uptime(ws_id, "https", start, end)
        uptime_pct = uptime_data.get("uptime_percent", 100.0) if uptime_data else 100.0
        avg_ms = uptime_data.get("avg_ms") if uptime_data else None

        websites_list.append({
            "domain": dom,
            "status_code": f"{uptime_pct:.1f}% uptime",
            "response_ms": avg_ms,
            "ssl_days": ssl_map.get(dom),
        })

    # Metric averages over the month
    cpu_stats = ctx.metrics.period_stats("cpu.percent", start, end)
    mem_stats = ctx.metrics.period_stats("memory.available_percent", start, end)
    disk_stats = ctx.metrics.period_stats("disk.used_percent", start, end)

    period_str = f"{format_local(start, tz, '%Y-%m-%d')} to {format_local(end, tz, '%Y-%m-%d')} ({tz})"
    gen_time_str = format_local(now, tz, "%Y-%m-%d %H:%M:%S %Z")

    return {
        "kind": "monthly",
        "title": "Server Health & Security Monthly Report",
        "hostname": hostname,
        "period": period_str,
        "generated_at": gen_time_str,
        "health_score": scores["health_score"],
        "health_coverage": scores["health_coverage"],
        "security_score": scores["security_score"],
        "security_coverage": scores["security_coverage"],
        "components": scores["components"],
        "findings": open_findings,
        "resolved_findings_count": len(resolved_in_period),
        "services": services,
        "websites": websites_list,
        "metrics_summary": {
            "cpu_avg": cpu_stats.get("avg") if cpu_stats else None,
            "cpu_peak": cpu_stats.get("max") if cpu_stats else None,
            "mem_avg_avail": mem_stats.get("avg") if mem_stats else None,
            "disk_avg": disk_stats.get("avg") if disk_stats else None,
        },
    }


def generate_monthly_report(
    ctx: Context,
    send_email: bool = False,
    override_start: Optional[datetime] = None,
    override_end: Optional[datetime] = None,
) -> Tuple[str, str, Optional[int]]:
    """Generate monthly HTML & PDF report. Returns (html_path, pdf_path, report_id)."""
    now = ctx.now()
    if override_start and override_end:
        start, end = override_start, override_end
    else:
        start, end = monthly_period(now, ctx.tz)

    data = assemble_monthly_data(ctx, start, end)

    report_dir = ctx.config.report_dir / "monthly"
    os.makedirs(report_dir, exist_ok=True)

    date_tag = start.strftime("%Y-%m")
    html_path = str(report_dir / f"shsm_monthly_{date_tag}.html")
    pdf_path = str(report_dir / f"shsm_monthly_{date_tag}.pdf")

    html_content = render_html_report(data)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    generate_pdf_report(data, pdf_path)

    report_id = ctx.reports.add("monthly", start, end, now, html_path, pdf_path, data)

    if send_email:
        hostname = socket.gethostname()
        subject = f"[MONTHLY][{hostname}] Server Health & Security Report - {date_tag}"
        transport = SMTPTransport(ctx)
        recipients = list(ctx.config.get("email.recipients", ["rohmataliwardani@gmail.com"]))
        ok, attempts, err = transport.send_email(
            subject=subject,
            html_body=html_content,
            recipients=recipients,
            pdf_attachment_path=pdf_path,
        )
        status_str = "SENT" if ok else "FAILED"
        ctx.reports.add_delivery(report_id, now, recipients, status_str, attempts, err)

    return html_path, pdf_path, report_id
