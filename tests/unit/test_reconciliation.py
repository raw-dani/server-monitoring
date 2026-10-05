"""Unit tests for finding deduplication and auto-reconciliation."""

from datetime import datetime, timezone

from shsm.core.findings import Confidence, FindingCandidate, Severity
from shsm.database.repositories.findings import FindingsRepo


def test_finding_deduplication(test_db):
    repo = FindingsRepo(test_db)
    now = datetime.now(timezone.utc)

    f1 = FindingCandidate(
        check_id="ssh.root_login",
        category="security",
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        title="SSH Root Login Enabled",
        evidence="PermitRootLogin is set to yes",
        recommendation="Set PermitRootLogin to no in /etc/ssh/sshd_config",
        asset="/etc/ssh/sshd_config",
    )

    # First upsert
    fid1, event1 = repo.upsert(f1, now)
    assert event1 == "NEW"

    # Second upsert of identical candidate
    fid2, event2 = repo.upsert(f1, now)
    assert event2 == "UPDATED"
    assert fid1 == fid2


def test_finding_auto_reconciliation(test_db):
    repo = FindingsRepo(test_db)
    now = datetime.now(timezone.utc)

    f1 = FindingCandidate(
        check_id="disk.usage",
        category="health",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        title="Disk Space High",
        evidence="Usage at 85%",
        recommendation="Clean temporary files",
        asset="/var",
    )
    repo.upsert(f1, now)

    # Verify finding is OPEN
    open_findings = repo.list(statuses=["OPEN"])
    assert len(open_findings) == 1
    assert open_findings[0]["fingerprint"] == f1.fingerprint

    # Now, run completes for disk scope with no open candidates (candidate resolved)
    result = repo.record_run(candidates=[], scopes=["disk"], now=now)
    assert len(result["RESOLVED"]) == 1
    assert result["RESOLVED"][0] == 1

    # Open findings should now be 0
    open_after = repo.list(statuses=["OPEN"])
    assert len(open_after) == 0
