"""TLS/SSL certificate expiry and validity monitoring."""

from __future__ import annotations

import concurrent.futures
import datetime
import socket
import ssl
from typing import Any, Dict, List

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.core.timeutils import UTC, to_iso

SOURCE = "tls_socket"
CATEGORY = "websites"


def inspect_certificate(domain: str, port: int = 443, timeout: float = 10.0) -> Dict[str, Any]:
    """Connect using TLS and extract certificate dates and validity."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as s:
                cert = s.getpeercert()
                if not cert:
                    return {
                        "domain": domain,
                        "port": port,
                        "valid": False,
                        "error": "No certificate presented by server",
                    }

                # Date format in python ssl getpeercert: 'May 10 12:00:00 2026 GMT'
                fmt = "%b %d %H:%M:%S %Y %Z"
                not_before_str = cert.get("notBefore")
                not_after_str = cert.get("notAfter")

                not_before = datetime.datetime.strptime(str(not_before_str), fmt).replace(tzinfo=UTC) if not_before_str else None
                not_after = datetime.datetime.strptime(str(not_after_str), fmt).replace(tzinfo=UTC) if not_after_str else None

                now = datetime.datetime.now(tz=UTC)
                if not_after:
                    days_remaining = (not_after - now).total_seconds() / 86400.0
                else:
                    days_remaining = None

                is_expired = days_remaining is not None and days_remaining <= 0

                return {
                    "domain": domain,
                    "port": port,
                    "not_before": to_iso(not_before) if not_before else None,
                    "not_after": to_iso(not_after) if not_after else None,
                    "days_remaining": days_remaining,
                    "valid": not is_expired,
                    "error": "Certificate has expired" if is_expired else None,
                }
    except ssl.SSLCertVerificationError as exc:
        return {
            "domain": domain,
            "port": port,
            "valid": False,
            "days_remaining": 0.0,
            "error": f"Certificate verification failed: {exc.verify_message}",
        }
    except Exception as exc:
        return {
            "domain": domain,
            "port": port,
            "valid": False,
            "days_remaining": None,
            "error": str(exc),
        }


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    now = ctx.now()

    websites = ctx.inventory.active_websites()
    if not websites:
        out.check("ssl.certificate", CATEGORY, CheckStatus.NOT_APPLICABLE, "No websites to check SSL for", source=SOURCE)
        return out

    max_workers = int(ctx.config.get("websites.max_workers", 4))
    timeout = float(ctx.config.get("websites.timeout_seconds", 10))

    t_warn = ctx.threshold("ssl_warning_days")
    t_high = ctx.threshold("ssl_high_days")
    t_crit = ctx.threshold("ssl_critical_days")

    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(inspect_certificate, site["domain"], 443, timeout): site["domain"]
            for site in websites
        }
        for f in concurrent.futures.as_completed(futures):
            try:
                results.append(f.result())
            except Exception as exc:
                dom = futures[f]
                out.error(f"ssl check error for {dom}: {exc}")

    for r in results:
        domain = r["domain"]
        port = r.get("port", 443)
        days = r.get("days_remaining")
        valid = r.get("valid")
        err = r.get("error")

        ctx.inventory.add_ssl(domain, port, now, r.get("not_before"), r.get("not_after"), days, valid, err)

        if days is not None:
            out.metric("ssl.days_remaining", days, asset=domain)

        if not valid or (days is not None and days <= 0):
            out.check(
                "ssl.certificate",
                CATEGORY,
                CheckStatus.CRITICAL,
                f"SSL certificate for {domain} is invalid or expired ({err})",
                asset=domain,
                source=SOURCE,
            )
            out.finding(
                "ssl.certificate",
                CATEGORY,
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                f"SSL certificate for {domain} is expired or invalid",
                f"TLS connection to {domain}:{port} failed certificate validation: {err}.",
                "Renew the Let's Encrypt SSL certificate in CyberPanel immediately (Websites -> Issue SSL).",
                asset=domain,
                source=SOURCE,
                key=domain,
            )
        elif days is not None:
            if days <= t_crit:
                out.check(
                    "ssl.certificate",
                    CATEGORY,
                    CheckStatus.CRITICAL,
                    f"SSL certificate for {domain} expires in {days:.1f} days (critical)",
                    asset=domain,
                    source=SOURCE,
                )
                out.finding(
                    "ssl.certificate",
                    CATEGORY,
                    Severity.CRITICAL,
                    Confidence.CONFIRMED,
                    f"SSL certificate for {domain} expires in {days:.1f} days",
                    f"Certificate for {domain} will expire on {r.get('not_after')} ({days:.1f} days remaining).",
                    "Verify why automatic renewal in CyberPanel has not executed and issue certificate manually.",
                    asset=domain,
                    source=SOURCE,
                    key=domain,
                )
            elif days <= t_high:
                out.check(
                    "ssl.certificate",
                    CATEGORY,
                    CheckStatus.WARNING,
                    f"SSL certificate for {domain} expires in {days:.1f} days (high priority)",
                    asset=domain,
                    source=SOURCE,
                )
                out.finding(
                    "ssl.certificate",
                    CATEGORY,
                    Severity.HIGH,
                    Confidence.HIGH,
                    f"SSL certificate for {domain} expires in {days:.1f} days",
                    f"Certificate for {domain} has only {days:.1f} days remaining.",
                    "Ensure CyberPanel certbot/acme cron is functioning properly.",
                    asset=domain,
                    source=SOURCE,
                    key=domain,
                )
            elif days <= t_warn:
                out.check(
                    "ssl.certificate",
                    CATEGORY,
                    CheckStatus.WARNING,
                    f"SSL certificate for {domain} expires in {days:.1f} days",
                    asset=domain,
                    source=SOURCE,
                )
                out.finding(
                    "ssl.certificate",
                    CATEGORY,
                    Severity.MEDIUM,
                    Confidence.HIGH,
                    f"SSL certificate for {domain} expiring soon ({days:.1f} days)",
                    f"Certificate for {domain} has {days:.1f} days remaining before expiration.",
                    "Monitor for automated renewal over the next few days.",
                    asset=domain,
                    source=SOURCE,
                    key=domain,
                )
            else:
                out.check(
                    "ssl.certificate",
                    CATEGORY,
                    CheckStatus.PASS,
                    f"SSL certificate for {domain} valid ({days:.0f} days remaining)",
                    asset=domain,
                    source=SOURCE,
                )
        else:
            out.check(
                "ssl.certificate",
                CATEGORY,
                CheckStatus.UNKNOWN,
                f"Could not determine certificate expiry for {domain}: {err}",
                asset=domain,
                source=SOURCE,
            )

    return out
