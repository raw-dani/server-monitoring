import sys
from unittest.mock import MagicMock

from shsm.security.fail2ban import ban_ip, unban_ip, is_valid_ip, get_active_jails


def test_is_valid_ip():
    assert is_valid_ip("20.194.17.163") is True
    assert is_valid_ip("81.71.147.6") is True
    assert is_valid_ip("2001:db8::1") is True
    assert is_valid_ip("not-an-ip") is False
    assert is_valid_ip("999.999.999.999") is False
    assert is_valid_ip("192.168.1.1; rm -rf /") is False


def test_ban_ip_rejects_whitelist_and_private():
    ctx = MagicMock()
    ctx.config.get.return_value = ["127.0.0.1", "::1"]

    # Localhost
    ok, msg = ban_ip(ctx, "127.0.0.1")
    assert ok is False
    assert "whitelist" in msg

    # Private IP
    ok, msg = ban_ip(ctx, "192.168.1.50")
    assert ok is False
    assert "private" in msg

    # Invalid IP
    ok, msg = ban_ip(ctx, "invalid-host")
    assert ok is False
    assert "Invalid IP" in msg


def test_ban_ip_auto_selects_ols_scanner():
    ctx = MagicMock()
    ctx.config.get.return_value = ["127.0.0.1"]
    ctx.runner.which.return_value = "/usr/bin/fail2ban-client"

    # Mock fail2ban status showing ols-scanner and sshd
    status_res = MagicMock()
    status_res.ok = True
    status_res.stdout = "Number of jail:\t2\nJail list:\tsshd, ols-scanner\n"

    # Mock ban command result
    ban_res = MagicMock()
    ban_res.ok = True
    ban_res.stdout = "1"

    def run_side_effect(cmd, timeout=None):
        if "status" in cmd:
            return status_res
        if "set" in cmd and "ols-scanner" in cmd and "banip" in cmd:
            return ban_res
        return MagicMock(ok=False)

    ctx.runner.run.side_effect = run_side_effect

    ok, msg = ban_ip(ctx, "20.194.17.163")
    assert ok is True
    assert "ols-scanner" in msg
    assert "20.194.17.163" in msg


def test_unban_ip_success():
    ctx = MagicMock()
    ctx.runner.which.return_value = "/usr/bin/fail2ban-client"

    unban_res = MagicMock()
    unban_res.ok = True
    ctx.runner.run.return_value = unban_res

    ok, msg = unban_ip(ctx, "20.194.17.163", jail="ols-scanner")
    assert ok is True
    assert "Successfully unbanned" in msg
