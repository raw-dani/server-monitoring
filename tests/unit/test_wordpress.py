"""Unit tests for WordPress security audit and WP-CLI execution."""

from unittest.mock import MagicMock
from shsm.security.wordpress import run_wp_cli


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

