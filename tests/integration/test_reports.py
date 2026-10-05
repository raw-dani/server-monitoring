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
