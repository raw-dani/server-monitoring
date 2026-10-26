"""Unit tests for DDoS detector and OpenLiteSpeed anti-DDoS auditor."""

import os
import tempfile
from unittest.mock import MagicMock, patch

from shsm.collectors.ddos import analyze_tcp_connections, collect as collect_ddos
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, Severity
from shsm.security.ols_anti_ddos import parse_ols_tuning_and_ddos, scan as scan_ols_ddos


def test_analyze_tcp_connections_clean(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    # Mock normal connections
    conn1 = MagicMock()
    conn1.status = "ESTABLISHED"
    conn1.laddr.port = 443
    conn1.raddr.ip = "203.0.113.10"

    conn2 = MagicMock()
    conn2.status = "ESTABLISHED"
    conn2.laddr.port = 80
    conn2.raddr.ip = "203.0.113.11"

    with patch("psutil.net_connections", return_value=[conn1, conn2]):
        total, syn_cnt, ip_cnt, violators = analyze_tcp_connections(ctx)
        assert total == 2
        assert syn_cnt == 0
        assert len(violators) == 0


def test_analyze_tcp_connections_flooder_detected(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    # Generate 60 connections from a single IP to trigger WARNING (>50)
    conns = []
    for _ in range(60):
        c = MagicMock()
        c.status = "ESTABLISHED"
        c.laddr.port = 443
        c.raddr.ip = "198.51.100.99"
        conns.append(c)

    # Add 120 SYN_RECV conns across system to trigger SYN flood
    for _ in range(120):
        c = MagicMock()
        c.status = "SYN_RECV"
        c.laddr.port = 443
        c.raddr.ip = "198.51.100.100"
        conns.append(c)

    with patch("psutil.net_connections", return_value=conns):
        total, syn_cnt, ip_cnt, violators = analyze_tcp_connections(ctx)
        assert syn_cnt == 120
        assert len(violators) >= 1
        assert violators[0]["ip"] == "198.51.100.100" or violators[0]["ip"] == "198.51.100.99"


def test_collect_ddos_clean(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    with patch("shsm.collectors.ddos.analyze_tcp_connections", return_value=(10, 0, {"1.1.1.1": 2}, [])):
        out = collect_ddos(ctx)
        checks = {c.check_id: c for c in out.checks}
        assert checks["ddos.conns"].status == CheckStatus.PASS
        assert checks["ddos.syn_flood"].status == CheckStatus.PASS
        assert len(out.findings) == 0


def test_collect_ddos_critical(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    violators = [{
        "ip": "203.0.113.55",
        "masked_ip": "203.0.113.xxx",
        "connections": 200,
        "level": "CRITICAL",
    }]
    with patch("shsm.collectors.ddos.analyze_tcp_connections", return_value=(250, 400, {"203.0.113.55": 200}, violators)):
        out = collect_ddos(ctx)
        checks = {c.check_id: c for c in out.checks}
        assert checks["ddos.conns"].status == CheckStatus.CRITICAL
        assert checks["ddos.syn_flood"].status == CheckStatus.CRITICAL
        assert len(out.findings) == 2


def test_parse_ols_tuning_and_ddos():
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write("""
        tuning {
            perClientConnLimit  80
            gracePeriod         30
            banPeriod           60
        }
        reCaptcha {
            enabled             1
        }
        """)
        f.flush()
        res = parse_ols_tuning_and_ddos(f.name)
        assert res["found"] is True
        assert res["per_client_conn_limit"] == 80
        assert res["grace_period"] == 30
        assert res["ban_period"] == 60
        assert res["recaptcha_enabled"] is True
    os.unlink(f.name)


def test_scan_ols_ddos_pass(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    good_parsed = {
        "found": True,
        "per_client_conn_limit": 80,
        "grace_period": 30,
        "ban_period": 60,
        "recaptcha_enabled": True,
        "anti_ddos_enabled": True,
    }
    with patch("shsm.security.ols_anti_ddos.parse_ols_tuning_and_ddos", return_value=good_parsed):
        out = scan_ols_ddos(ctx)
        checks = {c.check_id: c for c in out.checks}
        assert checks["security.ols_anti_ddos"].status == CheckStatus.PASS
        assert len(out.findings) == 0


def test_scan_ols_ddos_unlimited(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    weak_parsed = {
        "found": True,
        "per_client_conn_limit": 0,  # Unlimited
        "grace_period": 0,
        "ban_period": 0,
        "recaptcha_enabled": False,
        "anti_ddos_enabled": False,
    }
    with patch("shsm.security.ols_anti_ddos.parse_ols_tuning_and_ddos", return_value=weak_parsed):
        out = scan_ols_ddos(ctx)
        checks = {c.check_id: c for c in out.checks}
        assert checks["security.ols_anti_ddos"].status == CheckStatus.WARNING
        assert len(out.findings) == 1
        assert out.findings[0].severity == Severity.HIGH
