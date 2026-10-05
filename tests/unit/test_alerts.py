"""Unit tests for Alert dispatching, cooldowns, and deduplication."""

from shsm.core.context import Context
from shsm.core.findings import Confidence, FindingCandidate, Severity
from shsm.notifications.alerts import AlertManager


def test_alert_manager_cooldown(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    manager = AlertManager(ctx)

    f = FindingCandidate(
        check_id="disk.usage",
        category="health",
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        title="Disk Space Low",
        evidence="Disk space usage is 92%",
        recommendation="Free disk space or clean old logs",
        asset="/var",
    )

    # First check: should record alert and trigger dispatch attempt
    manager.process_findings([f], resolved_finding_ids=[])
    # The active alert should now be recorded in ctx.alerts
    alert_record = ctx.alerts.get(f.fingerprint)
    assert alert_record is not None

    # Immediate second check: cooldown should prevent re-alerting
    res2 = manager.process_findings([f], resolved_finding_ids=[])
    assert res2.get("sent", 0) == 0


def test_alert_manager_suppresses_low_severities(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    manager = AlertManager(ctx)

    f = FindingCandidate(
        check_id="ssh.info",
        category="security",
        severity=Severity.INFO,
        confidence=Confidence.LOW,
        title="Informational notice",
        evidence="Just FYI",
        recommendation="No action needed",
        asset="system",
    )
    # INFO findings should not activate an alert when alerts.min_severity is CRITICAL
    manager.process_findings([f], resolved_finding_ids=[])
    alert_record = ctx.alerts.get(f.fingerprint)
    assert alert_record is None


def test_email_presets_resolution():
    from shsm.notifications.smtp import EMAIL_PRESETS

    assert "brevo" in EMAIL_PRESETS
    assert EMAIL_PRESETS["brevo"]["smtp_host"] == "smtp-relay.brevo.com"
    assert EMAIL_PRESETS["brevo"]["smtp_port"] == 587

    assert "mailtrap" in EMAIL_PRESETS
    assert EMAIL_PRESETS["mailtrap"]["smtp_host"] == "live.smtp.mailtrap.io"

    assert "mailtrap_sandbox" in EMAIL_PRESETS
    assert EMAIL_PRESETS["mailtrap_sandbox"]["smtp_host"] == "sandbox.smtp.mailtrap.io"
    assert EMAIL_PRESETS["mailtrap_sandbox"]["smtp_port"] == 2525

    assert "sendgrid" in EMAIL_PRESETS
    assert EMAIL_PRESETS["sendgrid"]["smtp_host"] == "smtp.sendgrid.net"
    assert EMAIL_PRESETS["sendgrid"]["username"] == "apikey"

    assert "local" in EMAIL_PRESETS
    assert EMAIL_PRESETS["local"]["security"] == "none"

