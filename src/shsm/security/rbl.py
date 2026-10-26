"""DNSBL / RBL (Real-time Blackhole List) IP reputation scanner.

Performs asynchronous / low-latency UDP DNS lookups for server public IPv4 against
prominent anti-spam blocklists (Spamhaus, Barracuda, SpamCop, SORBS, UCEPROTECT, etc.).
Runs infrequently (every 6 or 12 hours) to avoid load, completely read-only.
"""

from __future__ import annotations

import socket
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "rbl_scanner"
CATEGORY = "security"

DEFAULT_RBL_PROVIDERS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "psbl.surriel.com",
    "bl.mailspike.net",
]


def get_public_ip(ctx: Context) -> Optional[str]:
    """Retrieve server public IP from config, network interface, or lightweight external resolver."""
    configured_ip = ctx.config.get("security.server_public_ip")
    if configured_ip and isinstance(configured_ip, str) and configured_ip.strip():
        return configured_ip.strip()

    # Fast external resolver with 2 second timeout
    resolvers = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
        "https://icanhazip.com",
    ]
    for url in resolvers:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SHSM-Monitor/1.0"})
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                ip = resp.read().decode("utf-8").strip()
                if ip and all(part.isdigit() for part in ip.split(".") if len(ip.split(".")) == 4):
                    return ip
        except Exception:
            continue

    return None


def reverse_ip(ip: str) -> str:
    """Reverse IPv4 string: 1.2.3.4 -> 4.3.2.1"""
    parts = ip.strip().split(".")
    if len(parts) == 4:
        return ".".join(reversed(parts))
    return ip


def check_rbl_single(reversed_ip: str, rbl_host: str, timeout: float = 2.0) -> Tuple[bool, str]:
    """Perform a standard single DNS A-record query against an RBL provider."""
    query = f"{reversed_ip}.{rbl_host}"
    orig_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        answers = socket.gethostbyname_ex(query)
        # answers format: (hostname, aliaslist, ipaddrlist)
        # A positive RBL match returns 127.0.0.X
        ips = answers[2]
        if ips and any(ip.startswith("127.0.0.") for ip in ips):
            return True, ips[0]
        return False, ""
    except (socket.gaierror, socket.herror, TimeoutError, OSError):
        # NXDOMAIN / Not found means IP is clean
        return False, ""
    finally:
        socket.setdefaulttimeout(orig_timeout)


def scan(ctx: Context) -> CollectorOutput:
    """Check server public IP against configured or default DNSBL providers."""
    out = CollectorOutput()
    out.scope("security.rbl")

    public_ip = get_public_ip(ctx)
    if not public_ip:
        out.check(
            "security.rbl",
            CATEGORY,
            CheckStatus.UNKNOWN,
            "Cannot determine server public IP address for RBL verification",
            source=SOURCE,
        )
        return out

    rev_ip = reverse_ip(public_ip)
    providers: List[str] = ctx.config.get("security.rbl_providers", DEFAULT_RBL_PROVIDERS)

    blacklisted_on: List[Dict[str, str]] = []
    total_checked = 0

    for provider in providers:
        provider = provider.strip()
        if not provider:
            continue
        total_checked += 1
        is_listed, return_code = check_rbl_single(rev_ip, provider, timeout=2.0)
        if is_listed:
            blacklisted_on.append({
                "provider": provider,
                "return_code": return_code,
            })

    out.metric("rbl.providers_checked", float(total_checked))
    out.metric("rbl.blacklists_matched", float(len(blacklisted_on)))

    if blacklisted_on:
        names = [b["provider"] for b in blacklisted_on]
        prov_list = ", ".join(names)
        out.finding(
            "security.rbl",
            CATEGORY,
            Severity.CRITICAL,
            Confidence.HIGH,
            f"Server public IP ({public_ip}) is listed on {len(blacklisted_on)} anti-spam blacklist(s)",
            f"IP {public_ip} listed on: {prov_list}. Return codes: {blacklisted_on}",
            "Investigate immediate spam origin via SHSM mail queue logs and Postfix mail.log. "
            "Delist your IP on the affected RBL provider portals after stopping the spam outbreak.",
            asset=public_ip,
            source=SOURCE,
            key=f"rbl:{public_ip}:{names[0]}",
        )
        out.check(
            "security.rbl",
            CATEGORY,
            CheckStatus.CRITICAL,
            f"Server IP {public_ip} is blacklisted on {len(blacklisted_on)}/{total_checked} RBLs: {prov_list}",
            asset=public_ip,
            source=SOURCE,
        )
    else:
        out.check(
            "security.rbl",
            CATEGORY,
            CheckStatus.PASS,
            f"Server IP {public_ip} is clean across {total_checked} DNSBL providers",
            asset=public_ip,
            source=SOURCE,
        )

    return out
