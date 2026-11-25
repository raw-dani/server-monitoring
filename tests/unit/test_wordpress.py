"""Unit tests for WordPress security audit and WP-CLI execution."""

from unittest.mock import MagicMock, patch

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, Severity
from shsm.reporting.scoring import calculate_component_score
from shsm.security.wordpress import audit_all, run_wp_cli, scan_wp_entry_points


def test_run_wp_cli_safe_owner_without_is_safe_owner_flag():
    ctx = MagicMock()
    ctx.runner.which.return_value = "/usr/local/bin/wp"
    ctx.config.get.return_value = 100

    site = {
        "domain": "example.com",
        "doc_root": "/home/user1/public_html",
        "owner": "user1",
    }

    # Should not reject as unsafe when owner is not root
    ctx.runner.run.return_value = MagicMock(ok=True, stdout="6.4.3", stderr="")
    ok, stdout, stderr = run_wp_cli(ctx, site, ["core", "version"])
    assert ok is True
    assert stdout == "6.4.3"


def test_run_wp_cli_rejects_root_owner():
    ctx = MagicMock()
    ctx.runner.which.return_value = "/usr/local/bin/wp"

    site = {
        "domain": "root-site.com",
        "doc_root": "/var/www/html",
        "owner": "root",
        "is_safe_owner": False,
    }

    ok, stdout, stderr = run_wp_cli(ctx, site, ["core", "version"])
    assert ok is False
    assert "refusing to run wp-cli as user 'root'" in stderr


def test_scan_wp_entry_points_detects_wp_config_mu_plugins_and_htaccess(tmp_path):
    doc_root = tmp_path / "public_html"
    mu_dir = doc_root / "wp-content" / "mu-plugins"
    mu_dir.mkdir(parents=True)

    (doc_root / "wp-config.php").write_text("<?php eval(base64_decode('aGVsbG8=')); ?>", encoding="utf-8")
    (mu_dir / "backdoor.php").write_text("<?php system($_POST['cmd']); ?>", encoding="utf-8")
    (doc_root / ".htaccess").write_text("php_value auto_prepend_file /tmp/evil.php\n", encoding="utf-8")

    hits = scan_wp_entry_points(str(doc_root))
    types = {h["type"] for h in hits}
    assert "obfuscated_eval" in types
    assert "php2shell_stager" in types
    assert "htaccess_php_injection" in types


def test_audit_all_emits_full_wordpress_coverage_and_flags_injection(tmp_path, test_db, sample_config):
    doc_root = tmp_path / "site" / "public_html"
    (doc_root / "wp-content").mkdir(parents=True)
    (doc_root / "wp-config.php").write_text("<?php eval(gzinflate(base64_decode('abc'))); ?>", encoding="utf-8")

    ctx = Context(sample_config, test_db)
    site_row = {
        "id": 1,
        "domain": "wp-test.com",
        "doc_root": str(doc_root),
        "owner": "wpuser",
        "is_safe_owner": True,
    }

    def fake_wp(_ctx, _site, args, timeout=None):
        if args[:2] == ["core", "version"]:
            return True, "6.7.1\n", ""
        if args[:2] == ["core", "check-update"]:
            return True, "[]", ""
        if args[:2] == ["core", "verify-checksums"]:
            return True, "Success: WordPress installation verifies against checksums.", ""
        if args[:2] == ["plugin", "list"]:
            return True, '[{"name":"litespeed-cache","version":"6.5","status":"active","update":"none","update_version":""}]', ""
        if args[:2] == ["user", "list"]:
            return True, '[{"ID":"1","user_login":"admin","user_email":"a@wp-test.com"}]', ""
        return True, "", ""

    with patch.object(ctx.inventory, "active_wordpress_sites", return_value=[site_row]), \
         patch.object(ctx.inventory, "replace_plugins"), \
         patch.object(ctx.inventory, "replace_themes"), \
         patch.object(ctx.inventory, "add_wp_audit"), \
         patch("shsm.security.wordpress._find_wp_cli", return_value="/usr/local/bin/wp"), \
         patch("shsm.security.wordpress.run_wp_cli", side_effect=fake_wp):
        out = audit_all(ctx)

    check_map = {c.check_id: c for c in out.checks}
    # All 5 EXPECTED_CHECKS["wordpress"] must be present
    for expected_id in ("wordpress.discovery", "wordpress.core", "wordpress.checksums", "wordpress.plugins", "wordpress.users"):
        assert expected_id in check_map

    # Even though wp core verify-checksums passed, wp-config.php injection triggers CRITICAL
    assert check_map["wordpress.checksums"].status == CheckStatus.CRITICAL
    crit_findings = [f for f in out.findings if f.check_id == "wordpress.checksums"]
    assert len(crit_findings) == 1
    assert crit_findings[0].severity == Severity.CRITICAL

    # Verify 100% coverage in scoring engine when checks are stored
    now = ctx.now()
    ctx.checks.upsert_many(out.checks, now)
    _score, cov, _det = calculate_component_score("wordpress", ctx.checks.all(), [], now)
    assert cov == 100.0

