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
    retries: int = 2,
) -> Dict[str, Any]:
    if not expected_statuses:
        expected_statuses = [200, 201, 204, 301, 302, 307, 308, 401, 403]

    url = f"{scheme}://{domain}/"
    headers = {
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }
    start = time.monotonic()
    last_err_type = "unknown"
    last_err_msg = ""

    for attempt in range(retries + 1):
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
                "error_type": None if is_ok else "http_status",
                "error": None if is_ok else f"Unexpected status code {code} (expected {expected_statuses})",
            }
        except requests.exceptions.Timeout as exc:
            last_err_type = "timeout"
            last_err_msg = f"Connection timed out after {timeout}s"
            continue
        except requests.exceptions.SSLError as exc:
            # Check if this SSLError is actually a handshake timeout
            err_text = str(exc).lower()
            if "timed out" in err_text or "timeout" in err_text:
                last_err_type = "timeout"
                last_err_msg = f"TLS handshake timed out after {timeout}s"
                continue
            last_err_type = "ssl"
            last_err_msg = f"TLS/SSL handshake error: {exc}"
            break
        except requests.exceptions.ConnectionError as exc:
            err_text = str(exc).lower()
            if "timed out" in err_text or "timeout" in err_text:
                last_err_type = "timeout"
                last_err_msg = f"Connection timed out after {timeout}s"
                continue
            last_err_type = "connection"
            last_err_msg = f"Connection error: {exc}"
            break
        except Exception as exc:
            last_err_type = "generic"
            last_err_msg = f"Request failed: {exc}"
            break

    duration_ms = (time.monotonic() - start) * 1000.0
    return {
        "ok": False,
        "status_code": None,
        "response_ms": duration_ms,
        "chain": [],
        "https_redirect": False,
        "error_type": last_err_type,
        "error": last_err_msg,
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
    expected: List[int] = []
    if exp_json:
        try:
            parsed = json.loads(exp_json)
            if isinstance(parsed, list):
                expected = [int(x) for x in parsed if isinstance(x, (int, str)) and str(x).isdigit()]
        except Exception:
            expected = []
    if not expected:
        raw_exp = site.get("expected_status")
        if isinstance(raw_exp, list):
            expected = [int(x) for x in raw_exp if isinstance(x, (int, str)) and str(x).isdigit()]
    if not expected:
        expected = list(default_expected) if default_expected else [200, 201, 204, 301, 302, 307, 308, 401, 403]

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

    out.scope("website.http")
    out.scope("website.dns")

    max_workers = int(ctx.config.get("websites.max_workers", 4))
    timeout = float(ctx.config.get("websites.timeout_seconds", 10))
    user_agent = str(ctx.config.get("websites.user_agent", "SHSM-Monitor/1.0"))
    default_expected = list(
        ctx.config.get(
            "websites.default_expected_status",
            [200, 201, 204, 301, 302, 307, 308, 401, 403],
        )
    )
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
            err_type = primary.get("error_type")

            if err_type == "timeout":
                # Network or probe timeout: distinguish from hard server error (4xx/5xx)
                status = CheckStatus.WARNING
                summary = f"Website check timed out for {domain}: {primary['error']}"
                finding_sev = Severity.HIGH if is_confirmed_outage else Severity.MEDIUM
                finding_conf = Confidence.HIGH if is_confirmed_outage else Confidence.LOW
                finding_title = f"Website probe timed out for {domain}"
                finding_rec = "Check network latency, probe firewall rules, or OpenLiteSpeed per-client connection limits. The site may still be accessible to external browsers."
            else:
                status = CheckStatus.CRITICAL if is_confirmed_outage else CheckStatus.WARNING
                summary = f"Outage on {domain}: {primary['error']}"
                finding_sev = Severity.CRITICAL if is_confirmed_outage else Severity.HIGH
                finding_conf = Confidence.CONFIRMED if is_confirmed_outage else Confidence.MEDIUM
                finding_title = f"Website outage or error on {domain}"
                finding_rec = "Verify OpenLiteSpeed vhost configuration, document root permissions, and application index files."

            out.check("website.http", CATEGORY, status, summary, asset=domain, source=SOURCE)
            out.finding(
                "website.http",
                CATEGORY,
                finding_sev,
                finding_conf,
                finding_title,
                f"Health check failed for {domain}. Error: {primary['error']}. Status: {primary['status_code']}.",
                finding_rec,
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
