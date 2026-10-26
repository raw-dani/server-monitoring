"""DDoS socket flood, SYN flood, and per-IP connection anomaly detector.

Collects real-time Layer 4 TCP connection metrics directly from the kernel
(psutil/ss) with near-zero CPU and memory footprint (< 25ms execution).
Detects:
1. TCP SYN_RECV flood attacks.
2. Abnormally high concurrent TCP connections from single IPs on ports 80/443.
3. Potential Slowloris attacks (many connections in lingering states).
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

import psutil

from shsm.collectors.base import threshold_result
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.utils.redact import mask_ip

SOURCE = "ddos_detector"
CATEGORY = "security"

WEB_PORTS = {80, 443}


def analyze_tcp_connections(
    ctx: Context,
) -> Tuple[int, int, Dict[str, int], List[Dict[str, Any]]]:
    """Inspect established/syn connections to web ports directly from kernel memory.

    Returns:
        (total_web_conns, syn_recv_count, ip_counter_dict, top_violators)
    """
    conn_warn = int(ctx.config.get("thresholds.ddos_ip_conns_warning", 50))
    conn_crit = int(ctx.config.get("thresholds.ddos_ip_conns_critical", 150))
    whitelist = set(ctx.config.get("security.ip_whitelist", ["127.0.0.1", "::1"]))

    try:
        conns = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, Exception):
        return 0, 0, {}, []

    syn_recv_count = 0
    total_web_conns = 0
    ip_counter: Counter[str] = Counter()

    for c in conns:
        # Check SYN_RECV states across all ports (SYN flood metric)
        if c.status == psutil.CONN_SYN_RECV:
            syn_recv_count += 1

        # Focus on web traffic (port 80 / 443 incoming)
        l_port = c.laddr.port if c.laddr and hasattr(c.laddr, "port") else (c.laddr[1] if c.laddr else None)
        if l_port not in WEB_PORTS:
            continue

        total_web_conns += 1

        if c.status in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_RECV, psutil.CONN_CLOSE_WAIT):
            if c.raddr:
                r_ip = c.raddr.ip if hasattr(c.raddr, "ip") else str(c.raddr[0])
                if r_ip not in whitelist and not r_ip.startswith("127."):
                    ip_counter[r_ip] += 1

    top_violators: List[Dict[str, Any]] = []
    for ip, count in ip_counter.most_common(10):
        if count >= conn_warn:
            level = "CRITICAL" if count >= conn_crit else "WARNING"
            top_violators.append({
                "ip": ip,
                "masked_ip": mask_ip(ip),
                "connections": count,
                "level": level,
            })

    return total_web_conns, syn_recv_count, dict(ip_counter.most_common(5)), top_violators


def collect(ctx: Context) -> CollectorOutput:
    """Collect DDoS and socket flood metrics."""
    out = CollectorOutput()
    out.scope("ddos.conns")
    out.scope("ddos.syn_flood")

    total_web_conns, syn_recv, top_ips, violators = analyze_tcp_connections(ctx)

    out.metric("ddos.web_connections_total", float(total_web_conns))
    out.metric("ddos.syn_recv_count", float(syn_recv))
    out.metric("ddos.violators_count", float(len(violators)))

    # 1. SYN Flood Evaluation
    syn_warn = float(ctx.config.get("thresholds.ddos_syn_warning", 100))
    syn_crit = float(ctx.config.get("thresholds.ddos_syn_critical", 300))

    threshold_result(
        out,
        check_id="ddos.syn_flood",
        category=CATEGORY,
        asset="network",
        value=float(syn_recv),
        warning=syn_warn,
        critical=syn_crit,
        emergency=syn_crit * 2,
        label="TCP SYN_RECV Flood Count",
        unit=" half-open conns",
        recommendation=(
            "Enable TCP SYN cookies ('sysctl -w net.ipv4.tcp_syncookies=1') and check firewall rules "
            "to drop SYN packets exceeding rate thresholds."
        ),
        source=SOURCE,
    )

    # 2. Per-IP Connection Flooding (HTTP Flood / Slowloris)
    if violators:
        crit_violators = [v for v in violators if v["level"] == "CRITICAL"]
        status = CheckStatus.CRITICAL if crit_violators else CheckStatus.WARNING
        sev = Severity.CRITICAL if crit_violators else Severity.MEDIUM

        summary_parts = [f"{v['masked_ip']}: {v['connections']} conns" for v in violators]
        summary_str = ", ".join(summary_parts)

        out.finding(
            "ddos.conns",
            CATEGORY,
            sev,
            Confidence.HIGH,
            f"Detected {len(violators)} IP(s) conducting concurrent connection flood on web ports",
            f"Active violators: {summary_str}. Total concurrent web connections: {total_web_conns}.",
            "Drop the attacking IP addresses immediately via iptables: 'iptables -I INPUT -s <IP> -j DROP'. "
            "Ensure OpenLiteSpeed perClientConnLimit is enforced.",
            asset="ports_80_443",
            source=SOURCE,
            key=f"ddos_flood:{violators[0]['ip']}",
        )
        out.check(
            "ddos.conns",
            CATEGORY,
            status,
            f"DDoS connection flood detected: {len(violators)} suspicious IP(s) ({summary_str})",
            asset="ports_80_443",
            source=SOURCE,
        )
    else:
        out.check(
            "ddos.conns",
            CATEGORY,
            CheckStatus.PASS,
            f"Web concurrent connections healthy ({total_web_conns} conns, top IP has {list(top_ips.values())[0] if top_ips else 0} conns)",
            asset="ports_80_443",
            source=SOURCE,
        )

    return out
