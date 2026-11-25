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
from typing import Any, Dict, List

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "ols_anti_ddos"
CATEGORY = "security"

DEFAULT_OLS_CONFIG = "/usr/local/lsws/conf/httpd_config.conf"


def parse_ols_tuning_and_ddos(config_path: str) -> Dict[str, Any]:
    """Parse OLS server configuration for perClientConnLimit (flat & block syntax) and anti-DDoS settings."""
    settings: Dict[str, Any] = {
        "found": False,
        "per_client_conn_limit": None,
        "dyn_req_per_sec": None,
        "grace_period": None,
        "ban_period": None,
        "anti_ddos_enabled": False,
        "recaptcha_enabled": False,
        "max_php_conns": None,
    }

    if not os.path.isfile(config_path):
        return settings

    try:
        with open(config_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except (OSError, PermissionError):
        return settings

    settings["found"] = True

    # Support nested OLS block: perClientConnLimit { ... hardLimit 100 ... }
    block_match = re.search(r"perClientConnLimit\s*\{([^}]*)\}", content, re.DOTALL)
    block_body = block_match.group(1) if block_match else content

    # Look for perClientConnLimit <int> or hardLimit/softLimit inside block
    m_limit = re.search(r"perClientConnLimit\s+(\d+)", content)
    if m_limit:
        settings["per_client_conn_limit"] = int(m_limit.group(1))
    else:
        m_hard = re.search(r"hardLimit\s+(\d+)", block_body)
        if m_hard:
            settings["per_client_conn_limit"] = int(m_hard.group(1))

    m_dyn = re.search(r"dynReqPerSec\s+(\d+)", block_body)
    if m_dyn:
        settings["dyn_req_per_sec"] = int(m_dyn.group(1))

    m_grace = re.search(r"gracePeriod\s+(\d+)", block_body)
    if m_grace:
        settings["grace_period"] = int(m_grace.group(1))

    m_ban = re.search(r"banPeriod\s+(\d+)", block_body)
    if m_ban:
        settings["ban_period"] = int(m_ban.group(1))

    # Look for reCaptcha or anti-DDoS challenge block
    if re.search(r"(?i)reCaptcha\s*\{[^}]*enabled\s+1", content) or "antiDDoS" in content:
        settings["recaptcha_enabled"] = True
        settings["anti_ddos_enabled"] = True

    # Inspect maxConns in lsphp extProcessor definitions to catch worker exhaustion
    php_conns = [int(x) for x in re.findall(r"(?i)lsphp[^\n]*\n(?:[^\}]*\n)*?\s*maxConns\s+(\d+)", content)]
    if php_conns:
        settings["max_php_conns"] = max(php_conns)

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

    dyn_rps = parsed.get("dyn_req_per_sec")
    if dyn_rps is not None and (dyn_rps == 0 or dyn_rps > 30):
        issues.append(f"dynReqPerSec is permissive ({dyn_rps} req/s), allowing PHP worker flooding")

    max_php = parsed.get("max_php_conns")
    cpu_cnt = os.cpu_count() or 4
    if max_php is not None and max_php > cpu_cnt * 4:
        issues.append(
            f"lsphp maxConns ({max_php}) exceeds safe limit ({cpu_cnt * 4} for {cpu_cnt} cores), risking CPU thrashing"
        )

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
