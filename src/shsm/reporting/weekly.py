"""Weekly reporting: period aggregation, HTML/PDF artifact generation, and delivery."""

from __future__ import annotations

import os
import socket
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from shsm.core.context import Context
from shsm.core.timeutils import format_local, weekly_period
from shsm.notifications.smtp import SMTPTransport
from shsm.reporting.html import render_html_report
from shsm.reporting.pdf import generate_pdf_report
from shsm.reporting.scoring import compute_scores


def assemble_weekly_data(ctx: Context, start: datetime, end: datetime) -> Dict[str, Any]:
    tz = ctx.tz
    now = ctx.now()
    hostname = socket.gethostname()

    scores = compute_scores(ctx)
    open_findings = ctx.findings.list(statuses=["OPEN", "ACKNOWLEDGED"], limit=50)
    services = ctx.inventory.latest_services()
    ssl_certs = ctx.inventory.latest_ssl()
    ssl_map = {c["domain"]: c.get("days_remaining") for c in ssl_certs}

    websites_list = []
    for site in ctx.inventory.active_websites():
        dom = site["domain"]
        ws_id = site["id"]
        last_check = ctx.db.query_one(
            "SELECT status_code, response_ms, ok FROM website_checks WHERE website_id=? ORDER BY id DESC LIMIT 1",
            (ws_id,),
        )
        websites_list.append({
            "domain": dom,
            "status_code": last_check["status_code"] if last_check else "-",
            "response_ms": last_check["response_ms"] if last_check else None,
            "ssl_days": ssl_map.get(dom),
        })

    period_str = f"{format_local(start, tz, '%Y-%m-%d')} to {format_local(end, tz, '%Y-%m-%d')} ({tz})"
    gen_time_str = format_local(now, tz, "%Y-%m-%d %H:%M:%S %Z")

    return {
        "kind": "weekly",
        "title": "Server Health & Security Weekly Report",
        "hostname": hostname,
        "period": period_str,
        "generated_at": gen_time_str,
        "health_score": scores["health_score"],
        "health_coverage": scores["health_coverage"],
        "security_score": scores["security_score"],
        "security_coverage": scores["security_coverage"],
        "components": scores["components"],
        "findings": open_findings,
        "services": services,
        "websites": websites_list,
    }


def generate_weekly_report(
    ctx: Context,
    send_email: bool = False,
    override_start: Optional[datetime] = None,
    override_end: Optional[datetime] = None,
) -> Tuple[str, str, Optional[int]]:
    """Generate weekly HTML & PDF report. Returns (html_path, pdf_path, report_id)."""
    now = ctx.now()
    if override_start and override_end:
        start, end = override_start, override_end
    else:
        start, end = weekly_period(now, ctx.tz)

    data = assemble_weekly_data(ctx, start, end)

    report_dir = ctx.config.report_dir / "weekly"
    os.makedirs(report_dir, exist_ok=True)

    date_tag = start.strftime("%Y-%m-%d")
    html_path = str(report_dir / f"shsm_weekly_{date_tag}.html")
    pdf_path = str(report_dir / f"shsm_weekly_{date_tag}.pdf")

    html_content = render_html_report(data)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_content)

    generate_pdf_report(data, pdf_path)

    report_id = ctx.reports.add("weekly", start, end, now, html_path, pdf_path, data)

    if send_email:
        hostname = socket.gethostname()
        subject = f"[WEEKLY][{hostname}] Server Health & Security Report - {date_tag}"
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
