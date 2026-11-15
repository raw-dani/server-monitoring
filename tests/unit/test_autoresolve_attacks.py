"""Test auto-mitigation resolution for OpenLiteSpeed exploit and 404 scanner findings."""

from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from shsm.collectors.openlitespeed import collect
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, FindingStatus, Severity


def test_exploit_auto_blocked_resolves_finding(test_db, sample_config):
    sample_config.data["openlitespeed"]["access_log"] = "/dummy/access.log"
    sample_config.data["security"]["fail2ban_auto_block"] = True
    ctx = Context(sample_config, test_db)

    # Mock access log lines returning a suspicious request
    log_lines = ['102.244.97.185 - - [02/Nov/2026:08:00:00 +0700] "GET /wp-content/uploads/shell.php HTTP/1.1" 404 123 "-" "curl"']

    with patch.object(ctx.tailer, "read_new") as mock_tail, \
         patch("shsm.security.fail2ban.ban_ip", return_value=(True, "banned in jail")) as mock_ban, \
         patch("os.path.exists", return_value=True):

        res_mock = MagicMock()
        res_mock.lines = log_lines
        mock_tail.return_value = res_mock

        out = collect(ctx)
        findings = [f for f in out.findings if f.check_id == "openlitespeed.exploit_attempts"]
        assert len(findings) == 1
        f = findings[0]
        # Should be marked as RESOLVED and downgraded severity since defense succeeded
        assert f.initial_status == FindingStatus.RESOLVED
        assert f.severity == Severity.LOW
        assert "Auto-Blocked" in f.title

        # Check status should be PASS because it's mitigated
        checks = [c for c in out.checks if c.check_id == "openlitespeed.exploit_attempts"]
        assert len(checks) == 1
        assert checks[0].status == CheckStatus.PASS

        # Record run and verify it is saved into DB as RESOLVED
        now = datetime.now(timezone.utc)
        events = ctx.findings.record_run(out.findings, out.scopes, now)
        saved = ctx.findings.get(f.fingerprint)
        assert saved is not None
        assert saved["status"] == "RESOLVED"
        assert "Fail2Ban" in saved["status_note"]


def test_scanner_404_auto_dropped_resolves_finding(test_db, sample_config):
    sample_config.data["openlitespeed"]["access_log"] = "/dummy/access.log"
    sample_config.data["security"]["scanner_404_threshold"] = 5
    sample_config.data["security"]["scanner_404_auto_block"] = True
    ctx = Context(sample_config, test_db)

    # 6 404 requests from same IP to exceed threshold
    log_lines = [
        f'45.138.12.16 - - [02/Nov/2026:08:00:0{i} +0700] "GET /nonexistent-{i} HTTP/1.1" 404 123 "-" "bot"'
        for i in range(6)
    ]

    with patch.object(ctx.tailer, "read_new") as mock_tail, \
         patch("shsm.security.blocked.ban_ip_unified", return_value=(True, "added iptables DROP rule")) as mock_drop, \
         patch("os.path.exists", return_value=True):

        res_mock = MagicMock()
        res_mock.lines = log_lines
        mock_tail.return_value = res_mock

        out = collect(ctx)
        findings = [f for f in out.findings if f.check_id == "openlitespeed.scanner_404_flood"]
        assert len(findings) == 1
        f = findings[0]
        assert f.initial_status == FindingStatus.RESOLVED
        assert f.severity == Severity.LOW
        assert "Auto-Dropped" in f.title

        checks = [c for c in out.checks if c.check_id == "openlitespeed.scanner_404_flood"]
        assert len(checks) == 1
        assert checks[0].status == CheckStatus.PASS

        now = datetime.now(timezone.utc)
        events = ctx.findings.record_run(out.findings, out.scopes, now)
        saved = ctx.findings.get(f.fingerprint)
        assert saved is not None
        assert saved["status"] == "RESOLVED"
        assert "iptables" in saved["status_note"]
