"""Monthly reporting: monthly rollups, month-over-month comparisons, HTML/PDF generation, and delivery."""

from __future__ import annotations

import os
import socket
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from shsm.core.context import Context
from shsm.core.timeutils import format_local, monthly_period
from shsm.notifications.smtp import SMTPTransport
from shsm.reporting.common import assemble_report_data
from shsm.reporting.html import render_html_report
from shsm.reporting.pdf import generate_pdf_report


def assemble_monthly_data(ctx: Context, start: datetime, end: datetime) -> Dict[str, Any]:
    period_str = f"{format_local(start, ctx.tz, '%Y-%m-%d')} to {format_local(end, ctx.tz, '%Y-%m-%d')} ({ctx.tz})"
    return assemble_report_data(
        ctx,
        kind="monthly",
        title="Server Health & Security Monthly Report",
        period_str=period_str,
        start=start,
        end=end,
        use_period_uptime=True,
    )


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
        recipients = (
            list(ctx.config.get("email.monthly_recipients", []))
            or list(ctx.config.get("email.report_recipients", []))
            or list(ctx.config.get("email.recipients", ["rohmataliwardani@gmail.com"]))
        )
        ok, attempts, err = transport.send_email(
            subject=subject,
            html_body=html_content,
            recipients=recipients,
            pdf_attachment_path=pdf_path,
        )
        status_str = "SENT" if ok else "FAILED"
        ctx.reports.add_delivery(report_id, now, recipients, status_str, attempts, err)

    return html_path, pdf_path, report_id
