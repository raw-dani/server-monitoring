"""Unit tests for daily report, digest mode, and instant root login alerts."""

import datetime
from unittest.mock import MagicMock, patch

from shsm.core.context import Context
from shsm.core.findings import FindingCandidate, Severity, Confidence
from shsm.notifications.alerts import AlertManager
from shsm.reporting.daily import generate_daily_report, assemble_daily_data
from shsm.security.ssh import parse_auth_lines, collect as collect_ssh


def test_ssh_root_login_detected():
    lines = [
        "Oct 30 08:12:00 host sshd[1234]: Accepted publickey for root from 203.0.113.5 port 54321 ssh2",
        "Oct 30 08:15:00 host sshd[1235]: Failed password for invalid user admin from 198.51.100.2 port 43210 ssh2",
    ]
    data = parse_auth_lines(lines)
    assert data["failed_attempts"] == 1
    assert "203.0.113.5" in data["root_logins"]


def test_ssh_collector_flags_root_login(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    sample_lines = [
        "Oct 30 08:12:00 host sshd[1234]: Accepted publickey for root from 1.2.3.4 port 54321 ssh2"
    ]
    with patch("os.path.isfile", return_value=True), \
         patch.object(ctx.tailer, "read_new") as mock_tail:
        mock_res = MagicMock()
        mock_res.lines = sample_lines
        mock_tail.return_value = mock_res

        out = collect_ssh(ctx)
        findings = [f for f in out.findings if f.check_id == "ssh.root_login"]
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "1.2.3.4" in findings[0].asset


def test_alert_manager_digest_mode_suppression(test_db, sample_config):
    sample_config.data["alerts"]["digest_mode"] = True
    sample_config.data["alerts"]["instant_check_ids"] = ["ssh.root_login"]
    ctx = Context(sample_config, test_db)
    mgr = AlertManager(ctx)

    # 1. Scanner finding (should be suppressed in digest_mode)
    scanner_cand = FindingCandidate(
        check_id="openlitespeed.scanner_404_flood",
        category="security",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        title="Scanner 404 flood detected",
        evidence="100 404s",
        recommendation="Ban IP",
        asset="45.138.12.16",
        source="ols",
        key="45.138.12.16",
    )

    with patch.object(mgr.transport, "send_email", return_value=(True, 1, None)) as mock_send:
        res = mgr.process_findings([scanner_cand], [])
        assert res["alerts_dispatched"] == 0
        assert mock_send.call_count == 0

    # 2. Root login finding (should NOT be suppressed, must send immediate email)
    root_cand = FindingCandidate(
        check_id="ssh.root_login",
        category="security",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        title="SSH root login detected from 1.2.3.4",
        evidence="Accepted root login",
        recommendation="Verify root access",
        asset="1.2.3.4",
        source="ssh_audit",
        key="root_login_1.2.3.4",
    )

    with patch.object(mgr.transport, "send_email", return_value=(True, 1, None)) as mock_send:
        res = mgr.process_findings([root_cand], [])
        assert res["alerts_dispatched"] == 1
        assert mock_send.call_count == 1
        call_args = mock_send.call_args[0]
        assert "server monitoring alert" in call_args[0].lower()


def test_generate_daily_report(test_db, sample_config, tmp_path):
    sample_config.data["paths"]["report_dir"] = str(tmp_path / "reports")
    ctx = Context(sample_config, test_db)

    with patch.object(ctx.reports, "add", return_value=123):
        html_p, pdf_p, r_id = generate_daily_report(ctx, send_email=False)
        assert r_id == 123
        assert html_p.endswith(".html")
        assert pdf_p.endswith(".pdf")
