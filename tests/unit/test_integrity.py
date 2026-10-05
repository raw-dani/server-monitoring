"""Unit and integration tests for integrity checking with smart account diffing."""

import os

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, Severity
from shsm.security import integrity


def test_integrity_smart_account_diffing(temp_dir, test_db, sample_config):
    # Setup test etc directory with passwd
    etc_dir = os.path.join(temp_dir, "etc")
    os.makedirs(etc_dir, exist_ok=True)
    passwd_path = os.path.join(etc_dir, "passwd")

    with open(passwd_path, "w") as f:
        f.write("root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n")

    # Configure monitored paths
    sample_config.data["integrity"]["paths"] = [passwd_path]
    sample_config.data["integrity"]["critical_paths"] = [passwd_path]
    ctx = Context(sample_config, test_db)

    # 1. Build initial baseline
    count = integrity.build_or_update_baseline(ctx)
    assert count == 1

    # Check baseline initial state
    out = integrity.check(ctx)
    check_status = next(c for c in out.checks if c.check_id == "integrity.files")
    assert check_status.status == CheckStatus.PASS
    assert len(out.findings) == 0

    # 2. Add benign system service account (e.g. clamav)
    with open(passwd_path, "a") as f:
        f.write("clamav:x:122:131:ClamAV:/var/lib/clamav:/bin/false\n")

    out_benign = integrity.check(ctx)
    # The check itself must stay PASS so Health/Security scores are not penalized!
    check_status_benign = next(c for c in out_benign.checks if c.check_id == "integrity.files")
    assert check_status_benign.status == CheckStatus.PASS

    # Finding must be classified as INFO, not CRITICAL!
    acc_findings = [f for f in out_benign.findings if f.check_id == "integrity.accounts"]
    assert len(acc_findings) == 1
    assert acc_findings[0].severity == Severity.INFO
    assert "clamav" in acc_findings[0].title

    # 3. Add dangerous backdoor UID 0 account
    with open(passwd_path, "a") as f:
        f.write("toor:x:0:0:Backdoor:/root:/bin/bash\n")

    out_crit = integrity.check(ctx)
    # Check must now be CRITICAL!
    check_status_crit = next(c for c in out_crit.checks if c.check_id == "integrity.files")
    assert check_status_crit.status == CheckStatus.CRITICAL

    crit_findings = [f for f in out_crit.findings if f.severity == Severity.CRITICAL]
    assert len(crit_findings) >= 1
    assert any("UID: 0" in f.title for f in crit_findings)

    # 4. Admin updates baseline to approve changes
    updated = integrity.build_or_update_baseline(ctx)
    assert updated == 1

    # Check must return to PASS with 0 open events
    out_clean = integrity.check(ctx)
    check_status_clean = next(c for c in out_clean.checks if c.check_id == "integrity.files")
    assert check_status_clean.status == CheckStatus.PASS
