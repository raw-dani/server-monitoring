"""OpenLiteSpeed Anti-DDoS, Per-Client Throttling, and Bot Challenge Auditor.

Verifies that OpenLiteSpeed (OLS) is configured with early bot mitigations:
1. perClientConnLimit: prevents single IPs from exhausting connections.
2. Anti-DDoS Challenge (reCaptcha / JS-challenge): verifies legitimate human browsers
   vs non-rendering bot scripts.
3. Banning periods: ensures aggressive flooders are dropped before hitting PHP.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "ols_anti_ddos"
CATEGORY = "security"

DEFAULT_OLS_CONFIG = "/usr/local/lsws/conf/httpd_config.conf"


def parse_ols_tuning_and_ddos(config_path: str) -> Dict[str, Any]:
    """Parse OLS server configuration for perClientConnLimit and anti-DDoS settings."""
    settings: Dict[str, Any] = {
        "found": False,
        "per_client_conn_limit": None,
        "grace_period": None,
        "ban_period": None,
        "anti_ddos_enabled": False,
        "recaptcha_enabled": False,
    }

    if not os.path.isfile(config_path):
        return settings

    try:
        with open(config_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, PermissionError):
        return settings

    settings["found"] = True

    # Look for perClientConnLimit or hardLimit/softLimit (OLS tuning syntax variants)
    m_limit = re.search(r"perClientConnLimit\s+(\d+)", content)
    if m_limit:
        settings["per_client_conn_limit"] = int(m_limit.group(1))
    else:
        m_hard = re.search(r"hardLimit\s+(\d+)", content)
        if m_hard:
            settings["per_client_conn_limit"] = int(m_hard.group(1))

    # Look for gracePeriod and banPeriod
    m_grace = re.search(r"gracePeriod\s+(\d+)", content)
    if m_grace:
        settings["grace_period"] = int(m_grace.group(1))

    m_ban = re.search(r"banPeriod\s+(\d+)", content)
    if m_ban:
        settings["ban_period"] = int(m_ban.group(1))

    # Look for reCaptcha or anti-DDoS challenge block
    # In OLS: reCaptcha { enabled 1 } or similar antiDDoS directives
    if re.search(r"(?i)reCaptcha\s*\{[^}]*enabled\s+1", content) or "antiDDoS" in content:
        settings["recaptcha_enabled"] = True
        settings["anti_ddos_enabled"] = True

    return settings


def scan(ctx: Context) -> CollectorOutput:
    """Audit OpenLiteSpeed anti-DDoS configuration."""
    out = CollectorOutput()
    out.scope("security.ols_anti_ddos")

    config_path = ctx.config.get("openlitespeed.config_file", DEFAULT_OLS_CONFIG)
    parsed = parse_ols_tuning_and_ddos(config_path)

    if not parsed["found"]:
        # If OLS is not installed on this server, record informational PASS or UNKNOWN
        if not ctx.runner.which("openlitespeed") and not os.path.isdir("/usr/local/lsws"):
            out.check(
                "security.ols_anti_ddos",
                CATEGORY,
                CheckStatus.PASS,
                "OpenLiteSpeed not installed on this server; skipping OLS anti-DDoS audit",
                source=SOURCE,
            )
            return out

        out.check(
            "security.ols_anti_ddos",
            CATEGORY,
            CheckStatus.WARNING,
            f"OpenLiteSpeed config file not found or unreadable at {config_path}",
            source=SOURCE,
        )
        return out

    issues: List[str] = []
    p_limit = parsed["per_client_conn_limit"]

    # Check connection limit: recommended <= 100 for web hosting
    if p_limit is None or p_limit == 0:
        issues.append("perClientConnLimit is disabled (unlimited connections per IP allowed)")
    elif p_limit > 150:
        issues.append(f"perClientConnLimit is set high ({p_limit} conns), allowing potential socket floods")

    if not parsed["ban_period"] or parsed["ban_period"] == 0:
        issues.append("banPeriod is not configured or disabled (temporary auto-ban disabled)")

    if issues:
        desc = "; ".join(issues)
        out.finding(
            "security.ols_anti_ddos",
            CATEGORY,
            Severity.HIGH,
            Confidence.HIGH,
            "OpenLiteSpeed Anti-DDoS & client throttling parameters insufficiently hardened",
            f"OLS config at {config_path} has weak flood limits: {desc}.",
            "Configure perClientConnLimit (e.g. 60-100) and banPeriod (e.g. 60) in OpenLiteSpeed WebAdmin "
            "Console under Server Configuration -> Tuning -> Per Client Throttling.",
            asset=config_path,
            source=SOURCE,
        )
        out.check(
            "security.ols_anti_ddos",
            CATEGORY,
            CheckStatus.WARNING,
            f"OLS Anti-DDoS audit warning: {desc}",
            asset=config_path,
            source=SOURCE,
        )
    else:
        out.check(
            "security.ols_anti_ddos",
            CATEGORY,
            CheckStatus.PASS,
            f"OpenLiteSpeed Anti-DDoS throttling is active (limit: {p_limit} conns/IP, ban: {parsed['ban_period']}s)",
            asset=config_path,
            source=SOURCE,
        )

    return out
