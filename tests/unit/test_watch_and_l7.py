"""Unit tests for real-time adaptive watch daemon, CyberPanel multi-vhost L7 parsing, CSF/ipset, and Cloudflare protection."""

import os
import time
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from shsm.cli import main
from shsm.collectors.openlitespeed import (
    discover_active_access_logs,
    find_l7_offenders,
    parse_access_lines,
)
from shsm.core.context import Context
from shsm.core.findings import CheckStatus
from shsm.reporting.scoring import calculate_component_score
from shsm.security.blocked import (
    ban_ip_unified,
    get_firewalld_blocked,
    get_ufw_blocked,
    is_protected_ip,
    unban_ip_unified,
)
from shsm.security.ols_anti_ddos import parse_ols_tuning_and_ddos
from shsm.security.ols_anti_ddos import scan as scan_ols_ddos
from shsm.security.watch import WatchState, run_watch_tick


def test_parse_cyberpanel_quoted_log_and_l7_metrics():
    lines = [
        '"185.218.86.7 - - [19/Nov/2026:13:53:06 +0700] "GET /.env HTTP/1.1" 404 711 "-" "Mozilla/5.0""',
        '"54.162.165.144 - - [19/Nov/2026:13:51:19 +0700] "GET /2017/06/17/post/ HTTP/2" 200 38881 "-" "RiverBot/1.0 (+https://river.ai/bot)""',
        '"111.225.214.173 - - [19/Nov/2026:13:50:28 +0700] "GET /wp-json/wp/v2/posts/23292 HTTP/2" 401 141 "-" "Mozilla/5.0""',
        '"203.0.113.77 - - [19/Nov/2026:13:50:29 +0700] "GET /wp-content/uploads/a.webp HTTP/2" 200 1234 "-" "Mozilla/5.0""',
    ]
    res = parse_access_lines(lines)
    assert res["ip_404_counts"]["185.218.86.7"] == 1
    assert res["ip_bad_bot_counts"]["54.162.165.144"] == 1
    assert res["ip_auth_err_counts"]["111.225.214.173"] == 1
    assert res["ip_high_cost_counts"]["111.225.214.173"] == 1
    # Static .webp must NOT increment dynamic burst count
    assert "203.0.113.77" not in res["ip_dynamic_counts"]


def test_find_l7_offenders_ignores_static_assets_and_detects_floods(test_db, sample_config):
    sample_config.data["security"]["l7_burst_threshold"] = 20
    sample_config.data["security"]["l7_high_cost_threshold"] = 5
    sample_config.data["security"]["l7_auth_error_threshold"] = 5
    ctx = Context(sample_config, test_db)

    lines = []
    # Real human loading 50 static images/CSS must NOT trigger burst
    for i in range(50):
        lines.append(f'"203.0.113.10 - - [19/Nov/2026:13:50:00 +0700] "GET /wp-content/img-{i}.webp HTTP/2" 200 500 "-" "Chrome""')
    # Attacker hitting /wp-json/ returning 401
    for i in range(6):
        lines.append(f'"198.51.100.44 - - [19/Nov/2026:13:50:00 +0700] "GET /wp-json/wp/v2/posts/{i} HTTP/2" 401 141 "-" "bot""')
    # Bad bot RiverBot scraping 4 pages (200 OK)
    for i in range(4):
        lines.append(f'"54.162.165.144 - - [19/Nov/2026:13:50:00 +0700] "GET /article-{i}/ HTTP/2" 200 9000 "-" "RiverBot/1.0""')

    parsed = parse_access_lines(lines)
    offenders = find_l7_offenders(ctx, parsed)
    assert "203.0.113.10" not in offenders
    assert "198.51.100.44" in offenders
    assert "54.162.165.144" in offenders


def test_discover_active_access_logs_skips_dormant_logs(tmp_path, test_db, sample_config):
    active_log = tmp_path / "active.access_log"
    dormant_log = tmp_path / "dormant.access_log"
    active_log.write_text("line\n", encoding="utf-8")
    dormant_log.write_text("old\n", encoding="utf-8")

    # Set dormant_log mtime to 2 hours ago
    old_ts = time.time() - 7200
    os.utime(dormant_log, (old_ts, old_ts))

    sample_config.data["openlitespeed"]["access_log"] = str(tmp_path / "missing_global.log")
    sample_config.data["openlitespeed"]["vhost_log_globs"] = [str(tmp_path / "*.access_log")]
    sample_config.data["openlitespeed"]["vhost_active_window_seconds"] = 300
    ctx = Context(sample_config, test_db)

    found = discover_active_access_logs(ctx)
    assert str(active_log) in found
    assert str(dormant_log) not in found


def test_cloudflare_ip_protection(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    prot_cf, reason = is_protected_ip(ctx, "104.16.12.34")
    assert prot_cf is True
    assert "Cloudflare" in reason

    ok, msg = ban_ip_unified(ctx, "104.16.12.34", use_iptables=True)
    assert ok is False
    assert "protected" in msg.lower()


def test_cidr_whitelist_protection(test_db, sample_config):
    sample_config.data["security"]["ip_whitelist"] = ["127.0.0.1", "182.253.122.0/24"]
    ctx = Context(sample_config, test_db)
    prot, reason = is_protected_ip(ctx, "182.253.122.2")
    assert prot is True
    assert "182.253.122.0/24" in reason


def test_ban_prefers_csf_then_ipset(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    ctx.runner = MagicMock()
    ctx.runner.which.side_effect = lambda name: f"/usr/sbin/{name}" if "csf" in name else None
    ctx.runner.run.return_value = MagicMock(ok=True, stdout="csf ok", stderr="")

    ok, msg = ban_ip_unified(ctx, "185.218.86.7", use_iptables=True, ttl_seconds=1800, reason="Scanner")
    assert ok is True
    assert "CSF blocked" in msg
    called_cmd = ctx.runner.run.call_args[0][0]
    assert "-td" in called_cmd
    assert "185.218.86.7" in called_cmd

    # Now disable CSF and test ipset O(1) path
    ctx2 = Context(sample_config, test_db)
    ctx2.runner = MagicMock()
    ctx2.runner.which.side_effect = lambda name: f"/usr/sbin/{name}" if ("ipset" in name or "iptables" in name) else None
    ctx2.runner.run.return_value = MagicMock(ok=True, stdout="ok", stderr="")

    ok2, msg2 = ban_ip_unified(ctx2, "185.218.86.7", use_iptables=True, ttl_seconds=3600)
    assert ok2 is True
    assert "ipset" in msg2

    # Unban checks ipset + iptables cleanup
    ok_u, msgs_u = unban_ip_unified(ctx2, "185.218.86.7")
    assert ok_u is True
    assert any("ipset" in m for m in msgs_u)


def test_parse_ols_nested_block_and_lsphp_maxconns(tmp_path, test_db, sample_config):
    conf = tmp_path / "httpd_config.conf"
    conf.write_text("""
tuning  {
  perClientConnLimit  {
    staticReqPerSec         30
    dynReqPerSec            5
    softLimit               60
    hardLimit               100
    gracePeriod             10
    banPeriod               180
  }
}
extprocessor lsphp81 {
  type                    lsapi
  maxConns                50
}
""", encoding="utf-8")
    parsed = parse_ols_tuning_and_ddos(str(conf))
    assert parsed["found"] is True
    assert parsed["per_client_conn_limit"] == 100
    assert parsed["dyn_req_per_sec"] == 5
    assert parsed["ban_period"] == 180
    assert parsed["max_php_conns"] == 50

    sample_config.data["openlitespeed"]["config_file"] = str(conf)
    ctx = Context(sample_config, test_db)
    with patch("os.cpu_count", return_value=4):
        out = scan_ols_ddos(ctx)
        checks = {c.check_id: c for c in out.checks}
        assert checks["security.ols_anti_ddos"].status == CheckStatus.WARNING
        assert "maxConns" in checks["security.ols_anti_ddos"].summary


def test_watch_tick_realtime_seek_and_cooldown(tmp_path, test_db, sample_config):
    log_p = tmp_path / "site.access_log"
    log_p.write_text('"203.0.113.1 - - [19/Nov/2026:10:00:00 +0700] "GET / HTTP/2" 200 100 "-" "Mozilla""\n', encoding="utf-8")

    sample_config.data["openlitespeed"]["access_log"] = str(tmp_path / "missing.log")
    sample_config.data["openlitespeed"]["vhost_log_globs"] = [str(tmp_path / "*.access_log")]
    sample_config.data["security"]["l7_watch_burst_threshold"] = 5
    sample_config.data["security"]["scanner_404_threshold"] = 5
    ctx = Context(sample_config, test_db)
    state = WatchState()

    with patch("shsm.security.watch.analyze_tcp_connections", return_value=(5, 0, {}, [])), \
         patch("shsm.security.watch.ban_ip_unified", return_value=(True, "CSF blocked")) as mock_ban, \
         patch("shsm.security.watch._get_load_per_cpu", return_value=0.5):

        # Tick 1: initializes cursor at EOF (ignores historical lines)
        res1 = run_watch_tick(ctx, state)
        assert res1["banned_ips"] == []
        mock_ban.assert_not_called()

        # Append burst attack lines
        with open(log_p, "a", encoding="utf-8") as fh:
            for i in range(6):
                fh.write(f'"198.51.100.77 - - [19/Nov/2026:10:00:05 +0700] "GET /p-{i} HTTP/2" 404 100 "-" "curl""\n')

        # Tick 2: reads only appended bytes and bans immediately
        res2 = run_watch_tick(ctx, state)
        assert "198.51.100.77" in res2["banned_ips"]
        assert mock_ban.call_count == 1

        # Append more lines from same IP: cooldown cache skips duplicate subprocess ban!
        with open(log_p, "a", encoding="utf-8") as fh:
            for i in range(6):
                fh.write(f'"198.51.100.77 - - [19/Nov/2026:10:00:10 +0700] "GET /x-{i} HTTP/2" 404 100 "-" "curl""\n')

        res3 = run_watch_tick(ctx, state)
        assert res3["banned_ips"] == []
        assert mock_ban.call_count == 1


def test_watch_emergency_circuit_breaker(test_db, sample_config):
    sample_config.data["security"]["emergency_circuit_breaker"] = True
    sample_config.data["security"]["emergency_load_per_cpu"] = 5.0
    sample_config.data["openlitespeed"]["scan_vhost_logs"] = False
    sample_config.data["openlitespeed"]["access_log"] = "/nonexistent/access.log"
    ctx = Context(sample_config, test_db)
    state = WatchState()

    with patch("shsm.security.watch.analyze_tcp_connections", return_value=(10, 0, {}, [])), \
         patch("shsm.security.watch._get_load_per_cpu", return_value=6.5), \
         patch("shsm.security.watch._run_with_sudo_fallback", return_value=MagicMock(ok=True)) as mock_kill:
        r1 = run_watch_tick(ctx, state)
        r2 = run_watch_tick(ctx, state)
        assert r1["breaker_triggered"] is False
        assert r2["breaker_triggered"] is False
        mock_kill.assert_not_called()

        r3 = run_watch_tick(ctx, state)
        assert r3["breaker_triggered"] is True
        mock_kill.assert_called_once()


def test_cli_watch_once_dry_run():
    runner = CliRunner()
    with patch("shsm.security.watch.run_watch_tick", return_value={
        "load_per_cpu": 0.25,
        "banned_ips": [],
        "actions": [],
        "breaker_triggered": False,
        "next_sleep": 10,
        "logs_watched": 2,
    }):
        res = runner.invoke(main, ["watch", "--once", "--dry-run"])
        assert res.exit_code == 0
        assert "Watch tick done" in res.output


def test_ufw_and_firewalld_ban_list_unban(test_db, sample_config):
    # UFW backend
    ctx_ufw = Context(sample_config, test_db)
    ctx_ufw.runner = MagicMock()
    ctx_ufw.runner.which.side_effect = lambda name: "/usr/sbin/ufw" if "ufw" in name else None

    def ufw_run(cmd, timeout=None):
        if "status" in cmd:
            return MagicMock(ok=True, stdout="Status: active\nAnywhere DENY 185.218.86.7\n", stderr="")
        if "delete" in cmd:
            return MagicMock(ok=True, stdout="Rule deleted\n", stderr="")
        return MagicMock(ok=True, stdout="Rule inserted\n", stderr="")

    ctx_ufw.runner.run.side_effect = ufw_run
    ok_b, msg_b = ban_ip_unified(ctx_ufw, "185.218.86.7", use_iptables=True, reason="Test UFW")
    assert ok_b is True
    assert "UFW" in msg_b
    ufw_list = get_ufw_blocked(ctx_ufw)
    assert len(ufw_list) == 1 and ufw_list[0]["target"] == "185.218.86.7"
    ok_u, msgs_u = unban_ip_unified(ctx_ufw, "185.218.86.7")
    assert ok_u is True and any("UFW:" in m for m in msgs_u)

    # Firewalld backend
    ctx_fwd = Context(sample_config, test_db)
    ctx_fwd.runner = MagicMock()
    ctx_fwd.runner.which.side_effect = lambda name: "/usr/bin/firewall-cmd" if "firewall-cmd" in name else None

    def fwd_run(cmd, timeout=None):
        if "--state" in cmd:
            return MagicMock(ok=True, stdout="running\n", stderr="")
        if "--list-rich-rules" in cmd:
            return MagicMock(ok=True, stdout='rule family="ipv4" source address="185.218.86.7" drop\n', stderr="")
        return MagicMock(ok=True, stdout="success\n", stderr="")

    ctx_fwd.runner.run.side_effect = fwd_run
    ok_f, msg_f = ban_ip_unified(ctx_fwd, "185.218.86.7", use_iptables=True, ttl_seconds=600)
    assert ok_f is True and "Firewalld" in msg_f
    fwd_list = get_firewalld_blocked(ctx_fwd)
    assert len(fwd_list) == 1 and fwd_list[0]["target"] == "185.218.86.7"
    ok_fu, msgs_fu = unban_ip_unified(ctx_fwd, "185.218.86.7")
    assert ok_fu is True and any("Firewalld:" in m for m in msgs_fu)


def test_scoring_not_applicable_optional_fail2ban_keeps_full_coverage():
    from datetime import datetime, timezone

    from shsm.core.timeutils import to_iso
    now = datetime.now(timezone.utc)
    iso_now = to_iso(now)
    checks = [
        {"check_id": "firewall.status", "status": CheckStatus.PASS.value, "checked_at": iso_now},
        {"check_id": "firewall.ports", "status": CheckStatus.PASS.value, "checked_at": iso_now},
        {"check_id": "fail2ban.status", "status": CheckStatus.NOT_APPLICABLE.value, "checked_at": iso_now},
        {"check_id": "network.outbound", "status": CheckStatus.PASS.value, "checked_at": iso_now},
    ]
    score, cov, _details = calculate_component_score("firewall_network", checks, [], now)
    assert score == 100.0
    assert cov == 100.0
