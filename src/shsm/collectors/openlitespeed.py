"""OpenLiteSpeed monitoring: process metrics and incremental log parsing."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List

import psutil

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


def collect_process_metrics(ctx: Context, out: CollectorOutput) -> None:
    proc_names = ctx.config.get("openlitespeed.process_names", ["openlitespeed", "lshttpd", "litespeed", "lsphp"])
    matched_procs: List[psutil.Process] = []

    for p in psutil.process_iter():
        try:
            name = p.name().lower()
            if any(target in name for target in proc_names):
                matched_procs.append(p)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    total_rss = 0
    total_cpu = 0.0
    for p in matched_procs:
        try:
            total_rss += p.memory_info().rss
            total_cpu += p.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    out.metric("openlitespeed.process_count", len(matched_procs))
    out.metric("openlitespeed.memory_bytes", total_rss)
    out.metric("openlitespeed.cpu_percent", total_cpu)


def parse_access_lines(lines: List[str]) -> Dict[str, Any]:
    total_reqs = len(lines)
    status_counts: Dict[str, int] = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "other": 0}
    c_5xx = 0
    c_4xx = 0

    for line in lines:
        m = _ACCESS_LOG_LINE.search(line)
        if m:
            code = m.group("status")
            if code.startswith("2"):
                status_counts["2xx"] += 1
            elif code.startswith("3"):
                status_counts["3xx"] += 1
            elif code.startswith("4"):
                status_counts["4xx"] += 1
                c_4xx += 1
            elif code.startswith("5"):
                status_counts["5xx"] += 1
                c_5xx += 1
            else:
                status_counts["other"] += 1

    return {
        "total": total_reqs,
        "5xx": c_5xx,
        "4xx": c_4xx,
        "counts": status_counts,
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
    max_bytes = int(ctx.config.get("openlitespeed.max_bytes_per_run", 20 * 1024 * 1024))
    max_lines = int(ctx.config.get("openlitespeed.max_lines_per_run", 400000))

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
