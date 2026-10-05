"""Website availability, DNS resolution, HTTP/HTTPS response times, and redirect checking."""

from __future__ import annotations

import concurrent.futures
import json
import socket
import time
from typing import Any, Dict, List, Tuple

import requests

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "http_client"
CATEGORY = "websites"


def _check_dns(domain: str) -> Tuple[bool, List[str], str]:
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({str(item[4][0]) for item in infos if item[4]})
        return True, ips, ""
    except Exception as exc:
        return False, [], str(exc)


def _check_http(
    domain: str,
    scheme: str,
    timeout: float,
    user_agent: str,
    expected_statuses: List[int],
    max_redirects: int = 5,
) -> Dict[str, Any]:
    url = f"{scheme}://{domain}/"
    headers = {"User-Agent": user_agent}
    start = time.monotonic()
    try:
        session = requests.Session()
        session.max_redirects = max_redirects
        resp = session.get(url, headers=headers, timeout=timeout, allow_redirects=True, verify=False)
        duration_ms = (time.monotonic() - start) * 1000.0

        chain = [r.url for r in resp.history] + [resp.url]
        code = resp.status_code

        # Check HTTPS redirect behavior
        https_redirect = False
        if scheme == "http" and resp.history:
            https_redirect = any(u.startswith("https://") for u in chain)

        is_ok = code in expected_statuses

        return {
            "ok": is_ok,
            "status_code": code,
            "response_ms": duration_ms,
            "chain": chain,
            "https_redirect": https_redirect,
            "error": None if is_ok else f"Unexpected status code {code} (expected {expected_statuses})",
        }
    except requests.exceptions.Timeout:
        duration_ms = (time.monotonic() - start) * 1000.0
        return {
            "ok": False,
            "status_code": None,
            "response_ms": duration_ms,
            "chain": [],
            "https_redirect": False,
            "error": f"Connection timed out after {timeout}s",
        }
    except requests.exceptions.SSLError as exc:
        duration_ms = (time.monotonic() - start) * 1000.0
        return {
            "ok": False,
            "status_code": None,
            "response_ms": duration_ms,
            "chain": [],
            "https_redirect": False,
            "error": f"TLS/SSL handshake error: {exc}",
        }
    except Exception as exc:
        duration_ms = (time.monotonic() - start) * 1000.0
        return {
            "ok": False,
            "status_code": None,
            "response_ms": duration_ms,
            "chain": [],
            "https_redirect": False,
            "error": f"Request failed: {exc}",
        }


def check_single_website(
    site: Dict[str, Any],
    timeout: float,
    user_agent: str,
    default_expected: List[int],
) -> Dict[str, Any]:
    domain = site["domain"]
    dns_ok, ips, dns_err = _check_dns(domain)

    exp_json = site.get("expected_status_json")
    if exp_json:
        try:
            expected = json.loads(exp_json)
        except Exception:
            expected = default_expected
    else:
        expected = site.get("expected_status") or default_expected

    http_res = _check_http(domain, "http", timeout, user_agent, expected)
    https_res = _check_http(domain, "https", timeout, user_agent, expected)

    return {
        "site": site,
        "dns_ok": dns_ok,
        "ips": ips,
        "dns_err": dns_err,
        "http": http_res,
        "https": https_res,
    }


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    now = ctx.now()

    websites = ctx.inventory.active_websites()
    if not websites:
        out.check("website.http", CATEGORY, CheckStatus.NOT_APPLICABLE, "No websites registered or discovered", source=SOURCE)
        return out

    max_workers = int(ctx.config.get("websites.max_workers", 4))
    timeout = float(ctx.config.get("websites.timeout_seconds", 10))
    user_agent = str(ctx.config.get("websites.user_agent", "SHSM-Monitor/1.0"))
    default_expected = list(ctx.config.get("websites.default_expected_status", [200]))
    fail_threshold = int(ctx.threshold("website_failures_before_critical"))
    resp_warn = float(ctx.threshold("website_response_warning_seconds")) * 1000.0
    resp_crit = float(ctx.threshold("website_response_critical_seconds")) * 1000.0

    results: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(check_single_website, s, timeout, user_agent, default_expected)
            for s in websites
        ]
        for f in concurrent.futures.as_completed(futures):
            try:
                results.append(f.result())
            except Exception as exc:
                out.error(f"website check failed: {exc}")

    for r in results:
        site = r["site"]
        domain = site["domain"]
        ws_id = site["id"]

        # Record DNS
        dns_ok = r["dns_ok"]
        ips_str = ",".join(r["ips"])

        # Record HTTP check
        http_data = r["http"]
        ctx.inventory.add_website_check(
            ws_id,
            now,
            "http",
            dns_ok,
            ips_str,
            http_data["status_code"],
            http_data["response_ms"],
            http_data["chain"],
            http_data["https_redirect"],
            http_data["ok"],
            http_data["error"],
        )

        # Record HTTPS check
        https_data = r["https"]
        ctx.inventory.add_website_check(
            ws_id,
            now,
            "https",
            dns_ok,
            ips_str,
            https_data["status_code"],
            https_data["response_ms"],
            https_data["chain"],
            https_data["https_redirect"],
            https_data["ok"],
            https_data["error"],
        )

        # Evaluate HTTPS availability as the primary user-facing test
        primary = https_data if (https_data["status_code"] or not http_data["ok"]) else http_data
        out.metric("website.response_ms", primary["response_ms"], asset=domain)

        if not dns_ok:
            out.check(
                "website.dns",
                CATEGORY,
                CheckStatus.CRITICAL,
                f"DNS resolution failed for {domain}: {r['dns_err']}",
                asset=domain,
                source=SOURCE,
            )
            out.finding(
                "website.dns",
                CATEGORY,
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                f"DNS resolution failure for domain {domain}",
                f"Could not resolve A/AAAA records for {domain}. Error: {r['dns_err']}.",
                "Check domain registrar nameserver configuration and Cloudflare/DNS zone records.",
                asset=domain,
                source=SOURCE,
                key=domain,
            )
            continue

        if not primary["ok"]:
            # Check recent failure history before raising CRITICAL alert (spec deduplication rule)
            recent_results = ctx.inventory.recent_check_results(ws_id, "https", fail_threshold)
            failures = [f for f in recent_results if not f]

            is_confirmed_outage = len(failures) >= fail_threshold
            status = CheckStatus.CRITICAL if is_confirmed_outage else CheckStatus.WARNING
            summary = f"Outage on {domain}: {primary['error']}"

            out.check("website.http", CATEGORY, status, summary, asset=domain, source=SOURCE)
            out.finding(
                "website.http",
                CATEGORY,
                Severity.CRITICAL if is_confirmed_outage else Severity.HIGH,
                Confidence.CONFIRMED if is_confirmed_outage else Confidence.MEDIUM,
                f"Website outage or error on {domain}",
                f"Health check failed for {domain}. Error: {primary['error']}. Status: {primary['status_code']}.",
                "Verify OpenLiteSpeed vhost configuration, document root permissions, and application index files.",
                asset=domain,
                source=SOURCE,
                key=domain,
            )
        else:
            # Latency check
            ms = primary["response_ms"]
            if ms >= resp_crit:
                out.check(
                    "website.http",
                    CATEGORY,
                    CheckStatus.WARNING,
                    f"{domain} response time very high ({ms:.0f}ms)",
                    asset=domain,
                    source=SOURCE,
                )
            elif ms >= resp_warn:
                out.check(
                    "website.http",
                    CATEGORY,
                    CheckStatus.WARNING,
                    f"{domain} response time elevated ({ms:.0f}ms)",
                    asset=domain,
                    source=SOURCE,
                )
            else:
                out.check(
                    "website.http",
                    CATEGORY,
                    CheckStatus.PASS,
                    f"{domain} OK ({primary['status_code']}, {ms:.0f}ms)",
                    asset=domain,
                    source=SOURCE,
                )

    return out
