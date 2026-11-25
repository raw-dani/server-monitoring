"""Integration tests for report generation (HTML and ReportLab PDF)."""

import os

from shsm.core.timeutils import utcnow, weekly_period
from shsm.reporting.html import render_html_report
from shsm.reporting.pdf import generate_pdf_report


def test_html_report_rendering(sample_config):
    now = utcnow()
    start_dt, end_dt = weekly_period(now, "Asia/Jakarta")

    report_data = {
        "kind": "weekly",
        "title": "Weekly Health & Security Report",
        "hostname": sample_config.get("general.server_name"),
        "period": f"{start_dt.strftime('%Y-%m-%d')} to {end_dt.strftime('%Y-%m-%d')}",
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "health_score": 96.5,
        "health_coverage": 100.0,
        "security_score": 92.0,
        "security_coverage": 95.0,
        "components": {
            "cpu": {"label": "CPU & Load", "score": 98.0, "coverage": 100.0, "open_findings": 0},
            "memory": {"label": "Memory & Swap", "score": 95.0, "coverage": 100.0, "open_findings": 0},
        },
        "findings": [
            {
                "title": "SSH Root Login Active",
                "severity": "HIGH",
                "asset": "/etc/ssh/sshd_config",
                "status": "OPEN",
                "first_seen": "2026-10-01T00:00:00Z",
            }
        ],
        "services": [
            {"unit": "lshttpd.service", "active": True, "description": "OpenLiteSpeed"}
        ],
        "websites": [
            {"domain": "example.com", "status_code": 200, "response_time_ms": 120}
        ],
    }

    html_content = render_html_report(report_data)
    assert "<html" in html_content.lower()
    assert sample_config.get("general.server_name") in html_content
    assert "96.5" in html_content
    assert "SSH Root Login Active" in html_content


def test_pdf_report_generation(temp_dir, sample_config):
    now = utcnow()
    start_dt, end_dt = weekly_period(now, "Asia/Jakarta")

    report_data = {
        "kind": "weekly",
        "title": "Weekly Health & Security Report",
        "hostname": sample_config.get("general.server_name"),
        "period": f"{start_dt.strftime('%Y-%m-%d')} to {end_dt.strftime('%Y-%m-%d')}",
        "generated_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "health_score": 95.0,
        "health_coverage": 100.0,
        "security_score": 90.0,
        "security_coverage": 95.0,
        "components": {
            "cpu": {"label": "CPU & Load", "score": 98.0, "coverage": 100.0, "open_findings": 0},
            "memory": {"label": "Memory & Swap", "score": 95.0, "coverage": 100.0, "open_findings": 0},
            "disk": {"label": "Disk & Inodes", "score": 92.0, "coverage": 100.0, "open_findings": 0},
        },
        "findings": [
            {
                "title": "SSH Root Login Active",
                "severity": "HIGH",
                "asset": "/etc/ssh/sshd_config",
                "status": "OPEN",
                "first_seen": "2026-10-01T00:00:00Z",
            }
        ],
        "services": [
            {"unit": "lshttpd.service", "active": True, "description": "OpenLiteSpeed"}
        ],
        "websites": [
            {"domain": "example.com", "status_code": 200, "response_time_ms": 120}
        ],
    }

    out_pdf = os.path.join(temp_dir, "weekly_report.pdf")
    res_path = generate_pdf_report(report_data, output_path=out_pdf)

    assert os.path.exists(res_path)
    assert os.path.getsize(res_path) > 1000  # ReportLab PDF must have content
    with open(res_path, "rb") as f:
        header = f.read(4)
        assert header == b"%PDF"


def test_report_email_recipient_routing(test_db, sample_config, monkeypatch):
    from unittest.mock import MagicMock

    from shsm.core.context import Context
    from shsm.notifications.smtp import SMTPTransport
    from shsm.reporting.monthly import generate_monthly_report
    from shsm.reporting.weekly import generate_weekly_report

    mock_send = MagicMock(return_value=(True, 1, None))
    monkeypatch.setattr(SMTPTransport, "send_email", mock_send)

    cfg_data = sample_config.data
    cfg_data["email"]["recipients"] = ["security-alert@example.com"]
    cfg_data["email"]["weekly_recipients"] = ["weekly-team@example.com"]
    cfg_data["email"]["monthly_recipients"] = ["monthly-team@example.com"]

    ctx = Context(sample_config, test_db)

    # Weekly report email
    generate_weekly_report(ctx, send_email=True)
    assert mock_send.call_count == 1
    call_kwargs = mock_send.call_args[1]
    assert call_kwargs["recipients"] == ["weekly-team@example.com"]
    assert "security-alert@example.com" not in call_kwargs["recipients"]

    # Monthly report email
    mock_send.reset_mock()
    generate_monthly_report(ctx, send_email=True)
    assert mock_send.call_count == 1
    call_kwargs = mock_send.call_args[1]
    assert call_kwargs["recipients"] == ["monthly-team@example.com"]
    assert "security-alert@example.com" not in call_kwargs["recipients"]


def test_pdf_escapes_xml_and_html_renders_metrics_and_website_states(temp_dir):
    report_data = {
        "kind": "daily",
        "title": "Daily <Health> & Security",
        "hostname": "host&01",
        "period": "2026-11-25",
        "generated_at": "2026-11-25 11:00:00 WIB",
        "health_score": 85.0,
        "health_coverage": 100.0,
        "security_score": 80.0,
        "security_coverage": 100.0,
        "metrics_summary": {
            "cpu_avg": 22.5,
            "cpu_peak": 78.4,
            "load_avg": 1.25,
            "load_peak": 3.40,
            "mem_avg_avail": 48.0,
            "mem_min_avail": 31.2,
            "disk_avg": 55.0,
            "disk_peak": 56.0,
        },
        "action_items": [
            {"priority": "HIGH", "title": "Fix <Files> & query?a=1&b=2", "action": "Run shsm block-scanners"}
        ],
        "mitigated_findings": [
            {"title": "L7 flood auto-blocked", "asset": "185.218.86.7", "status_note": "CSF blocked"}
        ],
        "resolved_findings_count": 1,
        "findings": [
            {
                "title": "Probe <script> & ?x=1&y=2",
                "severity": "HIGH",
                "asset": "/var/www/<tag>&1",
                "status": "OPEN",
                "evidence": "GET /wp-login.php?a=1&b=2 <bad>",
                "recommendation": "Check <Files> & block IP",
            }
        ],
        "websites": [
            {"domain": "down.example.com", "status_code": "0.0% uptime", "response_ms": 0, "ssl_days": -2},
            {"domain": "protected.example.com", "status_code": 403, "ok": True, "response_ms": 45, "ssl_days": 60},
        ],
    }

    html_out = render_html_report(report_data)
    assert "22.5% / 78.4%" in html_out
    assert "Prioritas Tindakan" in html_out
    assert "Aktivitas Pertahanan Aktif" in html_out
    assert "KADALUARSA" in html_out
    assert "0.0% uptime (<span class='badge badge-crit'>KENDALA</span>)" in html_out
    assert "403 (<span class='badge badge-pass'>ONLINE</span>)" in html_out

    out_pdf = os.path.join(temp_dir, "escaped_report.pdf")
    pdf_path = generate_pdf_report(report_data, out_pdf)
    assert os.path.exists(pdf_path)
    assert os.path.getsize(pdf_path) > 1000


def test_daily_assembly_populates_raw_metrics_fallback(test_db, sample_config):
    from shsm.core.context import Context
    from shsm.core.findings import Metric
    from shsm.core.timeutils import daily_period
    from shsm.reporting.daily import assemble_daily_data

    ctx = Context(sample_config, test_db)
    now = ctx.now()
    ctx.metrics.insert(now, [
        Metric("cpu.percent", 35.0),
        Metric("cpu.load1", 1.5),
        Metric("memory.available_percent", 60.0),
        Metric("disk.used_percent", 42.0, asset="/"),
    ])
    start, end = daily_period(now, ctx.tz)
    data = assemble_daily_data(ctx, start, end)
    ms = data["metrics_summary"]
    assert ms["cpu_avg"] == 35.0
    assert ms["load_avg"] == 1.5
    assert ms["mem_avg_avail"] == 60.0
    assert ms["disk_avg"] == 42.0
