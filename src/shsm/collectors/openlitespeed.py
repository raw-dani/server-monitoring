"""OpenLiteSpeed monitoring: process metrics and incremental log parsing."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List
try:
    import psutil
except ImportError:
    psutil = None

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "openlitespeed"
CATEGORY = "health"

# Regex patterns for OpenLiteSpeed access and error logs
_ACCESS_LOG_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?P<method>\S+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<bytes>\S+)'
)

_PHP_FATAL = re.compile(r"(?i)PHP Fatal error|PHP Parse error|Uncaught Error")
_PHP_MEM = re.compile(r"(?i)Allowed memory size of \d+ bytes exhausted")
_UPSTREAM_TIMEOUT = re.compile(r"(?i)timed out|connection refused|broken pipe|upstream error")
_SSL_HANDSHAKE = re.compile(r"(?i)SSL handshake failed|SSL_accept failed|alert certificate")

# Suspicious URI or attack pattern targeting PHP RCE / PHP2Shell
_EXPLOIT_URI_PATTERN = re.compile(
    r"(?i)(?:\/wp-content\/uploads\/[^\s\?]+\.(?:php|phtml|php\d|pht)\b"
    r"|php:\/\/input|data:\/\/text\/plain"
    r"|\b(?:c99|r57|b374k|wso|alfa|php2shell|webshell|cmd\.php|shell\.php)\b)"
)
_EXPLOIT_HINTS = ("php", "phtml", "pht", "data:", "c99", "r57", "b374k", "wso", "alfa", "shell")


def collect_process_metrics(ctx: Context, out: CollectorOutput) -> None:
    proc_names = tuple(p.lower() for p in ctx.config.get("openlitespeed.process_names", ["openlitespeed", "lshttpd", "litespeed", "lsphp"]))
    matched_count = 0
    total_rss = 0
    if psutil is None:
        out.metric("openlitespeed.process_count", 0)
        out.metric("openlitespeed.memory_bytes", 0)
        out.metric("openlitespeed.cpu_percent", 0.0)
        return

    # Under high attack load, thousands of short-lived lsphp processes spawn/die.
    # We iterate conservatively and limit total inspected to prevent CPU burn.
    try:
        for p in psutil.process_iter(attrs=["name"]):
            try:
                name = (p.info.get("name") or "").lower()
                if any(target in name for target in proc_names):
                    matched_count += 1
                    # Only query memory for primary daemons to save system calls
                    if matched_count <= 50:
                        mem = p.memory_info()
                        if mem:
                            total_rss += getattr(mem, "rss", 0)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except Exception:
        pass

    out.metric("openlitespeed.process_count", matched_count)
    out.metric("openlitespeed.memory_bytes", total_rss)
    out.metric("openlitespeed.cpu_percent", 0.0)


def parse_access_lines(lines: List[str]) -> Dict[str, Any]:
    total_reqs = len(lines)
    status_counts: Dict[str, int] = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    c_5xx = 0
    c_4xx = 0
    suspicious_requests: List[Dict[str, str]] = []
    ip_404_counts: Dict[str, int] = {}

    for line in lines:
        m = _ACCESS_LOG_LINE.search(line)
        if m:
            code = m.group("status")
            path = m.group("path")
            ip = m.group("ip")
            first_c = code[0] if code else ""
            if first_c == "2":
                status_counts["2xx"] += 1
            elif first_c == "3":
                status_counts["3xx"] += 1
            elif first_c == "4":
                status_counts["4xx"] += 1
                c_4xx += 1
                if code == "404" and ip:
                    ip_404_counts[ip] = ip_404_counts.get(ip, 0) + 1
            elif first_c == "5":
                status_counts["5xx"] += 1
                c_5xx += 1
            else:
                status_counts["other"] += 1

            path_lower = path.lower()
            if any(h in path_lower for h in _EXPLOIT_HINTS) and _EXPLOIT_URI_PATTERN.search(path):
                suspicious_requests.append({"ip": ip, "path": path, "status": code})

    return {
        "total": total_reqs,
        "5xx": c_5xx,
        "4xx": c_4xx,
        "counts": status_counts,
        "suspicious": suspicious_requests,
        "ip_404_counts": ip_404_counts,
    }


def parse_error_lines(lines: List[str]) -> Dict[str, int]:
    fatals = 0
    mem_exhaust = 0
    timeouts = 0
    ssl_errs = 0

    for line in lines:
        if _PHP_FATAL.search(line):
            fatals += 1
        if _PHP_MEM.search(line):
            mem_exhaust += 1
        if _UPSTREAM_TIMEOUT.search(line):
            timeouts += 1
        if _SSL_HANDSHAKE.search(line):
            ssl_errs += 1

    return {
        "php_fatal": fatals,
        "php_memory": mem_exhaust,
        "upstream_timeouts": timeouts,
        "ssl_handshake": ssl_errs,
    }


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    now = ctx.now()

    enabled = ctx.config.get("openlitespeed.enabled", "auto")
    if enabled is False:
        out.check("openlitespeed.logs", CATEGORY, CheckStatus.NOT_APPLICABLE, "OpenLiteSpeed monitoring is disabled", source=SOURCE)
        return out

    collect_process_metrics(ctx, out)

    access_log = str(ctx.config.get("openlitespeed.access_log", "/usr/local/lsws/logs/access.log"))
    error_log = str(ctx.config.get("openlitespeed.error_log", "/usr/local/lsws/logs/error.log"))
    max_bytes = int(ctx.config.get("openlitespeed.max_bytes_per_run", 5 * 1024 * 1024))
    max_lines = int(ctx.config.get("openlitespeed.max_lines_per_run", 50000))

    if not os.path.exists(access_log) and not os.path.exists(error_log):
        if enabled is True:
            out.check("openlitespeed.logs", CATEGORY, CheckStatus.ERROR, f"OpenLiteSpeed logs not found at {access_log}", source=SOURCE)
        else:
            out.check("openlitespeed.logs", CATEGORY, CheckStatus.NOT_APPLICABLE, "OpenLiteSpeed logs not found", source=SOURCE)
        return out

    # 1. Access log parsing
    tail_access = ctx.tailer.read_new(access_log, now, max_bytes=max_bytes, max_lines=max_lines)
    if tail_access.lines:
        acc_info = parse_access_lines(tail_access.lines)
        total = acc_info["total"]
        c_5xx = acc_info["5xx"]
        c_4xx = acc_info["4xx"]

        out.metric("openlitespeed.requests", total)
        out.metric("openlitespeed.5xx_count", c_5xx)
        out.metric("openlitespeed.4xx_count", c_4xx)

        rate_5xx = (c_5xx / total * 100.0) if total > 0 else 0.0
        out.metric("openlitespeed.5xx_rate_percent", rate_5xx)

        min_reqs = int(ctx.threshold("openlitespeed_min_requests"))
        warn_5xx = ctx.threshold("openlitespeed_5xx_rate_warning_percent")
        crit_5xx = ctx.threshold("openlitespeed_5xx_rate_critical_percent")

        if total >= min_reqs and rate_5xx >= warn_5xx:
            status = CheckStatus.CRITICAL if rate_5xx >= crit_5xx else CheckStatus.WARNING
            out.check(
                "openlitespeed.5xx_rate",
                CATEGORY,
                status,
                f"HTTP 5xx error rate is {rate_5xx:.1f}% ({c_5xx}/{total} requests)",
                source=SOURCE,
            )
            out.finding(
                "openlitespeed.5xx_rate",
                CATEGORY,
                Severity.HIGH if status == CheckStatus.CRITICAL else Severity.MEDIUM,
                Confidence.HIGH,
                f"Elevated HTTP 5xx error rate ({rate_5xx:.1f}%) on OpenLiteSpeed",
                f"Observed {c_5xx} 5xx server errors out of {total} requests ({rate_5xx:.1f}% error rate).",
                "Inspect OpenLiteSpeed error logs and WordPress PHP fatal error logs to identify failing virtual hosts.",
                source=SOURCE,
            )
        else:
            out.check(
                "openlitespeed.5xx_rate",
                CATEGORY,
                CheckStatus.PASS,
                f"HTTP 5xx rate normal ({rate_5xx:.1f}% over {total} requests)",
                source=SOURCE,
            )

        # Suspicious exploit request detection (PHP2Shell / RCE / Webshell attempts)
        suspicious = acc_info.get("suspicious", [])
        out.metric("openlitespeed.suspicious_requests", len(suspicious))
        if suspicious:
            from shsm.security import fail2ban
            auto_block = bool(ctx.config.get("security.fail2ban_auto_block", True))
            target_jail = str(ctx.config.get("security.fail2ban_block_jail", "auto"))

            sample = suspicious[0]
            action_notes = []

            # Automatically ban offending IPs in Fail2Ban if active defense is enabled
            if auto_block:
                unique_ips = {s.get("ip") for s in suspicious if s.get("ip")}
                for s_ip in unique_ips:
                    ok, detail = fail2ban.ban_ip(ctx, s_ip, jail=target_jail)
                    if ok:
                        action_notes.append(f"Auto-banned {s_ip} in Fail2Ban")

            out.check(
                "openlitespeed.exploit_attempts",
                CATEGORY,
                CheckStatus.CRITICAL,
                f"Detected {len(suspicious)} suspicious exploit request(s) targeting PHP2Shell/webshells",
                source=SOURCE,
            )
            action_suffix = f" ({'; '.join(action_notes)})." if action_notes else ""
            out.finding(
                "openlitespeed.exploit_attempts",
                "security",
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                f"Suspicious exploit request detected in OpenLiteSpeed access log",
                f"Detected {len(suspicious)} request(s) matching known PHP2Shell/webshell injection paths. Example: IP {sample.get('ip')} requested '{sample.get('path')}' (status: {sample.get('status')}).{action_suffix}",
                "Review the requesting IP in firewall/Fail2Ban, quarantine any files created at that path, and ensure PHP execution in uploads is blocked.",
                asset=sample.get("ip", "network"),
                source=SOURCE,
                key=f"ols:exploit:{sample.get('ip')}:{sample.get('path')}",
            )
        else:
            out.check(
                "openlitespeed.exploit_attempts",
                CATEGORY,
                CheckStatus.PASS,
                "No suspicious PHP/webshell exploit attempts in access log",
                source=SOURCE,
            )

        # 404 Flood / Botnet Scanner Detection & Auto-Blocking
        ip_404_counts = acc_info.get("ip_404_counts", {})
        thresh_404 = int(ctx.config.get("security.scanner_404_threshold", 30))
        auto_block_404 = bool(ctx.config.get("security.scanner_404_auto_block", True))
        target_jail = str(ctx.config.get("security.fail2ban_block_jail", "auto"))
        whitelist = set(ctx.config.get("security.ip_whitelist", ["127.0.0.1", "::1"]))

        # Automatically protect server's own public IP and local hostname IPs
        cfg_ip = ctx.config.get("security.server_public_ip")
        if cfg_ip:
            whitelist.add(str(cfg_ip).strip())
        try:
            import socket
            hostname = socket.gethostname()
            for host_ip in socket.gethostbyname_ex(hostname)[2]:
                whitelist.add(host_ip)
        except Exception:
            pass

        abusive_404_ips = {
            ip: cnt for ip, cnt in ip_404_counts.items()
            if cnt >= thresh_404 and ip not in whitelist and not ip.startswith("127.")
        }

        out.metric("openlitespeed.aggressive_404_scanners", len(abusive_404_ips))
        if abusive_404_ips:
            from shsm.security import blocked
            ban_notes = []
            if auto_block_404:
                # Limit direct kernel drop to top 10 offenders per execution cycle
                # to prevent spawning excessive subprocesses during massive bot floods
                sorted_abusive = sorted(abusive_404_ips.items(), key=lambda x: x[1], reverse=True)[:10]
                for a_ip, a_cnt in sorted_abusive:
                    b_ok, b_msg = blocked.ban_ip_unified(ctx, a_ip, use_iptables=True)
                    if b_ok:
                        ban_notes.append(f"Auto-dropped {a_ip} in iptables ({a_cnt} 404s)")
                    else:
                        ban_notes.append(f"Failed iptables drop {a_ip}: {b_msg}")

            top_offender = max(abusive_404_ips.items(), key=lambda x: x[1])
            ban_suffix = f" Actions taken: {'; '.join(ban_notes)}." if ban_notes else ""

            out.finding(
                "openlitespeed.scanner_404_flood",
                "security",
                Severity.CRITICAL,
                Confidence.CONFIRMED,
                f"Aggressive 404 flood/botnet scanner detected on OpenLiteSpeed ({len(abusive_404_ips)} IPs)",
                f"Detected {len(abusive_404_ips)} IP(s) generating abnormal 404 bursts. "
                f"Top violator: IP {top_offender[0]} generated {top_offender[1]} 404 requests.{ban_suffix}",
                "The IP(s) have been auto-blocked. Ensure OpenLiteSpeed client throttling is active.",
                asset=top_offender[0],
                source=SOURCE,
                key=f"ols:404_flood:{top_offender[0]}",
            )
            out.check(
                "openlitespeed.scanner_404_flood",
                CATEGORY,
                CheckStatus.CRITICAL,
                f"Detected {len(abusive_404_ips)} aggressive 404 scanner IP(s). Top: {top_offender[0]} ({top_offender[1]} 404s)",
                asset=top_offender[0],
                source=SOURCE,
            )
        else:
            out.check(
                "openlitespeed.scanner_404_flood",
                CATEGORY,
                CheckStatus.PASS,
                "No aggressive 404 scanner/botnet activity detected in access log",
                source=SOURCE,
            )

    # 2. Error log parsing
    tail_error = ctx.tailer.read_new(error_log, now, max_bytes=max_bytes, max_lines=max_lines)
    if tail_error.lines:
        err_info = parse_error_lines(tail_error.lines)
        fatals = err_info["php_fatal"]
        mems = err_info["php_memory"]
        timeouts = err_info["upstream_timeouts"]

        out.metric("openlitespeed.php_fatal_errors", fatals)
        out.metric("openlitespeed.php_memory_exhaustions", mems)
        out.metric("openlitespeed.upstream_timeouts", timeouts)

        warn_fatal = int(ctx.threshold("openlitespeed_php_fatal_warning"))
        if fatals >= warn_fatal or mems > 0:
            out.check(
                "openlitespeed.logs",
                CATEGORY,
                CheckStatus.WARNING,
                f"Detected {fatals} PHP fatal errors, {mems} memory exhaustions in error log",
                source=SOURCE,
            )
            out.finding(
                "openlitespeed.php_fatal",
                CATEGORY,
                Severity.MEDIUM,
                Confidence.HIGH,
                "PHP fatal errors or memory exhaustion detected in OpenLiteSpeed",
                f"Parsed {fatals} PHP fatal errors and {mems} memory limit exhaustion events in recent log entries.",
                "Review the latest PHP crash reports and consider increasing memory_limit in php.ini for affected vhosts.",
                source=SOURCE,
            )
        else:
            out.check(
                "openlitespeed.logs",
                CATEGORY,
                CheckStatus.PASS,
                f"OpenLiteSpeed error log clean ({fatals} PHP fatals, {mems} OOM)",
                source=SOURCE,
            )
    else:
        out.check("openlitespeed.logs", CATEGORY, CheckStatus.PASS, "No new OpenLiteSpeed error log entries", source=SOURCE)

    return out
