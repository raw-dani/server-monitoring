"""RAM, swap, and OOM events."""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, Dict, List, Optional

import psutil

from shsm.collectors.base import human_bytes, threshold_result
from shsm.collectors.process import format_top, top_by
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "psutil"
CATEGORY = "health"
_OOM_LINE = re.compile(r"out of memory|oom-kill|oom_reaper|killed process", re.I)
_VICTIM = re.compile(r"Killed process \d+ \(([^)]{1,32})\)")


def parse_oom_lines(text: str) -> Dict[str, Any]:
    events = [ln for ln in text.splitlines() if _OOM_LINE.search(ln)]
    victims = sorted({m.group(1) for ln in events for m in [_VICTIM.search(ln)] if m})
    killed = len([ln for ln in events if "killed process" in ln.lower()])
    return {"lines": len(events), "kills": killed, "victims": victims}


def collect(ctx: Context, process_rows: Optional[List[Dict[str, Any]]] = None) -> CollectorOutput:
    out = CollectorOutput()
    t = ctx.threshold
    vm = psutil.virtual_memory()
    total = float(vm.total)
    avail_pct = vm.available / total * 100 if total else 0.0
    out.metric("memory.total_bytes", total)
    out.metric("memory.available_bytes", vm.available)
    out.metric("memory.available_percent", avail_pct)
    out.metric("memory.used_percent", 100.0 - avail_pct)
    out.metric("memory.cached_bytes", getattr(vm, "cached", None))
    out.metric("memory.buffers_bytes", getattr(vm, "buffers", None))
    out.meta["memory_total"] = int(total)

    n = int(ctx.config.get("monitoring.top_processes", 5))
    extra = ""
    if process_rows:
        extra = "Top memory consumers: " + format_top(top_by(process_rows, "rss", n), "rss") + "."
    threshold_result(
        out, check_id="memory.available", category=CATEGORY, asset="", value=avail_pct,
        warning=t("memory_available_warning_percent"), critical=t("memory_available_critical_percent"),
        emergency=t("memory_available_emergency_percent"), label="Available memory (MemAvailable)", unit="%",
        recommendation="Reduce PHP/LSAPI worker counts, check for memory leaks, or add RAM. Page cache is reclaimable and "
        "is already excluded from this figure.", source=SOURCE, higher_is_worse=False, evidence_extra=extra,
        details={"available": human_bytes(vm.available), "total": human_bytes(total)})

    # ---- swap
    sw = psutil.swap_memory()
    out.metric("swap.total_bytes", sw.total)
    out.metric("swap.used_bytes", sw.used)
    if sw.total > 0:
        out.metric("swap.used_percent", sw.percent)
        threshold_result(
            out, check_id="swap.usage", category=CATEGORY, asset="", value=sw.percent, warning=t("swap_warning"),
            critical=t("swap_critical"), emergency=t("swap_emergency"), label="Swap used", unit="%",
            recommendation="Sustained swap use indicates memory pressure; find the largest consumers and reduce them.",
            source=SOURCE, details={"used": human_bytes(sw.used), "total": human_bytes(sw.total)})
        _swap_activity(ctx, out, sw)
    else:
        out.check("swap.usage", CATEGORY, CheckStatus.NOT_APPLICABLE, "no swap configured", source=SOURCE)

    # ---- OOM events
    _oom(ctx, out)
    return out


def _swap_activity(ctx: Context, out: CollectorOutput, sw) -> None:
    for name, value in (("swap.sin_bytes", sw.sin), ("swap.sout_bytes", sw.sout)):
        prev = ctx.metrics.latest(name)
        out.metric(name, value)
        if prev and value >= prev[1]:
            from shsm.core.timeutils import from_iso

            dt = (ctx.now() - from_iso(prev[0])).total_seconds()
            if dt > 0:
                out.metric(name.replace("_bytes", "_bytes_per_s"), (value - prev[1]) / dt)


def _oom(ctx: Context, out: CollectorOutput) -> None:
    minutes = int(ctx.config.get("monitoring.oom_lookback_minutes", 15))
    since = f"{minutes} minutes ago"
    res = ctx.runner.run(["journalctl", "-k", "--no-pager", "-q", "-o", "short-iso", "--since", since], timeout=20)
    if not res.ran:
        out.check("memory.oom", CATEGORY, CheckStatus.UNKNOWN, f"cannot read kernel log: {res.describe()}", source="journalctl")
        out.error(f"memory.oom: journalctl unavailable ({res.describe()})")
        return
    if res.returncode != 0 and not res.stdout.strip():
        out.check("memory.oom", CATEGORY, CheckStatus.UNKNOWN, "journalctl returned an error: " + res.stderr.strip()[:120],
                  source="journalctl")
        return
    info = parse_oom_lines(res.stdout)
    out.metric("memory.oom_events", info["lines"])
    if info["lines"]:
        victims = ", ".join(info["victims"]) or "unknown process"
        out.check("memory.oom", CATEGORY, CheckStatus.CRITICAL, f"{info['kills']} OOM kill(s) in the last {minutes} min",
                  source="journalctl", victims=info["victims"])
        out.finding(
            "memory.oom", CATEGORY, Severity.HIGH, Confidence.CONFIRMED, "Kernel OOM killer was invoked",
            f"{info['kills']} process kill(s) by the OOM killer in the last {minutes} minutes. Victims: {victims}.",
            "Check memory consumers, PHP/MariaDB memory settings, and swap. Repeated OOM kills can take down MariaDB or "
            "OpenLiteSpeed.", source="journalctl")
    else:
        out.check("memory.oom", CATEGORY, CheckStatus.PASS, f"no OOM events in the last {minutes} min", source="journalctl")


__all__ = ["collect", "parse_oom_lines", "timedelta"]
