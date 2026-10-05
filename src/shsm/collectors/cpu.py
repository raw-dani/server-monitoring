"""CPU, load, steal and iowait with rolling-window (sustained) evaluation."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Dict, List, Optional

import psutil

from shsm.collectors.base import sustained_level, threshold_result
from shsm.collectors.process import ProcessSampler, format_top, top_by
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput

SOURCE = "psutil"
CATEGORY = "health"


def measure(sampler: Optional[ProcessSampler] = None, interval: float = 1.0) -> Dict[str, Any]:
    """Take one CPU measurement over ``interval`` seconds."""
    psutil.cpu_percent(None, percpu=True)  # prime per-core counters
    if sampler:
        sampler.prime()
    times = psutil.cpu_times_percent(interval=interval)
    per_core = psutil.cpu_percent(None, percpu=True)
    idle = getattr(times, "idle", 0.0)
    iowait = getattr(times, "iowait", 0.0)
    steal = getattr(times, "steal", 0.0)
    try:
        load = psutil.getloadavg()
    except (AttributeError, OSError):
        load = (0.0, 0.0, 0.0)
    return {
        "percent": max(0.0, min(100.0, 100.0 - idle - iowait)),
        "iowait": iowait,
        "steal": steal,
        "per_core": per_core,
        "load": load,
        "count": psutil.cpu_count(logical=True) or 1,
        "has_iowait": hasattr(times, "iowait"),
        "has_steal": hasattr(times, "steal"),
    }


def _window(ctx: Context, metric: str, current: float) -> List[float]:
    minutes = int(ctx.config.get("monitoring.cpu_window_minutes", 5))
    since = ctx.now() - timedelta(minutes=minutes)
    return ctx.metrics.window_values(metric, since) + [current]


def evaluate(ctx: Context, m: Dict[str, Any], top_text: str = "") -> CollectorOutput:
    out = CollectorOutput()
    min_samples = int(ctx.config.get("monitoring.cpu_min_samples", 3))
    minutes = int(ctx.config.get("monitoring.cpu_window_minutes", 5))
    count = m["count"]
    out.metric("cpu.percent", m["percent"])
    out.metric("cpu.iowait", m["iowait"] if m["has_iowait"] else None)
    out.metric("cpu.steal", m["steal"] if m["has_steal"] else None)
    out.metric("cpu.load1", m["load"][0])
    out.metric("cpu.load5", m["load"][1])
    out.metric("cpu.load15", m["load"][2])
    out.metric("cpu.load_per_cpu", m["load"][1] / count)
    out.metric("cpu.count", count)
    out.metric("cpu.core_max", max(m["per_core"]) if m["per_core"] else None)

    t = ctx.threshold
    # --- sustained CPU usage
    values = _window(ctx, "cpu.percent", m["percent"])
    level, mean, n = sustained_level(values, min_samples, t("cpu_warning"), t("cpu_critical"), t("cpu_emergency"))
    if level is None:
        out.check("cpu.usage", CATEGORY, CheckStatus.UNKNOWN,
                  f"only {n} sample(s) in the {minutes}-minute window (need {min_samples}); current {m['percent']:.1f}%",
                  source=SOURCE)
    else:
        threshold_result(
            out, check_id="cpu.usage", category=CATEGORY, asset="", value=mean, warning=t("cpu_warning"),
            critical=t("cpu_critical"), emergency=t("cpu_emergency"), label=f"CPU usage ({minutes}-min average)",
            unit="%", recommendation="Review the busiest processes and recent traffic; look for runaway PHP workers, "
            "cron jobs, or abusive crawlers.", source=SOURCE, level=level,
            evidence_extra=f"Top processes: {top_text}." if top_text else "",
            details={"samples": n, "current": round(m["percent"], 1)})
    # --- load average relative to CPU count
    lpc = m["load"][1] / count
    threshold_result(
        out, check_id="cpu.load", category=CATEGORY, asset="", value=lpc, warning=t("load_per_cpu_warning"),
        critical=t("load_per_cpu_critical"), emergency=t("load_per_cpu_emergency"),
        label="Load per CPU (5-min)", unit="", recommendation="High load with low CPU usually means I/O wait or "
        "blocked processes; check disk latency, MariaDB, and PHP workers.", source=SOURCE,
        details={"load5": m["load"][1], "cpus": count})
    # --- steal / iowait are separate findings
    for key, check_id, label, rec, ok in (
        ("steal", "cpu.steal", "CPU steal", "The hypervisor is withholding CPU; contact the VPS provider or move the "
         "workload.", m["has_steal"]),
        ("iowait", "cpu.iowait", "CPU iowait", "Processes are waiting on storage; check disk saturation, swap activity, "
         "and heavy scans/backups.", m["has_iowait"]),
    ):
        if not ok:
            out.check(check_id, CATEGORY, CheckStatus.NOT_APPLICABLE, f"{label} not reported on this platform",
                      source=SOURCE)
            continue
        vals = _window(ctx, f"cpu.{key}", m[key])
        lvl, avg, cnt = sustained_level(vals, min_samples, t(f"cpu_{key}_warning"), t(f"cpu_{key}_critical"),
                                        t(f"cpu_{key}_emergency"))
        if lvl is None:
            out.check(check_id, CATEGORY, CheckStatus.UNKNOWN, f"only {cnt} sample(s) in window", source=SOURCE)
        else:
            threshold_result(out, check_id=check_id, category=CATEGORY, asset="", value=avg,
                             warning=t(f"cpu_{key}_warning"), critical=t(f"cpu_{key}_critical"),
                             emergency=t(f"cpu_{key}_emergency"), label=f"{label} ({minutes}-min average)", unit="%",
                             recommendation=rec, source=SOURCE, level=lvl, details={"samples": cnt})
    return out


def collect(ctx: Context, sampler: Optional[ProcessSampler] = None, interval: float = 1.0) -> CollectorOutput:
    sampler = sampler or ProcessSampler()
    m = measure(sampler, interval)
    rows = sampler.snapshot()
    n = int(ctx.config.get("monitoring.top_processes", 5))
    top_text = format_top(top_by(rows, "cpu", n), "cpu") if rows else ""
    out = evaluate(ctx, m, top_text)
    out.meta["process_rows"] = rows
    out.meta["cpu_count"] = m["count"]
    return out
