"""Disk capacity, inodes, I/O indicators, growth, and bounded directory sizing."""

from __future__ import annotations

import os
from datetime import timedelta
from typing import Any, List

import psutil

from shsm.collectors.base import human_bytes, threshold_result
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity
from shsm.core.timeutils import from_iso, to_iso
from shsm.utils.fs import bounded_dir_size

SOURCE = "psutil/statvfs"
CATEGORY = "health"


def relevant_partitions(ctx: Context) -> List[Any]:
    ignore_fs = set(ctx.config.get("monitoring.disk_ignore_fstypes", []))
    ignore_mp = tuple(ctx.config.get("monitoring.disk_ignore_mountpoints", []))
    seen = set()
    result = []
    for part in psutil.disk_partitions(all=False):
        if part.fstype in ignore_fs or "loop" in part.device:
            continue
        if any(part.mountpoint == m or part.mountpoint.startswith(m.rstrip("/") + "/") for m in ignore_mp):
            continue
        key = (part.device, part.mountpoint)
        if key in seen:
            continue
        seen.add(key)
        result.append(part)
    return result


def collect(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()
    t = ctx.threshold
    parts = relevant_partitions(ctx)
    if not parts:
        out.check("disk.usage", CATEGORY, CheckStatus.UNKNOWN, "no filesystems discovered", source=SOURCE)
        out.error("disk.usage: no filesystems discovered")
    for part in parts:
        mp = part.mountpoint
        try:
            usage = psutil.disk_usage(mp)
        except (PermissionError, OSError) as exc:
            out.check("disk.usage", CATEGORY, CheckStatus.UNKNOWN, f"cannot stat: {exc}", asset=mp, source=SOURCE)
            out.error(f"disk.usage {mp}: {exc}")
            continue
        out.metric("disk.used_percent", usage.percent, mp)
        out.metric("disk.used_bytes", usage.used, mp)
        out.metric("disk.free_bytes", usage.free, mp)
        out.metric("disk.total_bytes", usage.total, mp)
        threshold_result(
            out, check_id="disk.usage", category=CATEGORY, asset=mp, value=usage.percent,
            warning=t("disk_warning_percent"), critical=t("disk_critical_percent"), emergency=t("disk_emergency_percent"),
            label="Disk usage", unit="%", recommendation="Free space: rotate/compress logs, remove old backups, review the "
            "largest directories (see 'shsm status'), or expand the volume. Do not delete website files without a backup.",
            source=SOURCE, details={"free": human_bytes(usage.free), "total": human_bytes(usage.total), "fstype": part.fstype})
        _inodes(ctx, out, mp, part.fstype)
        _growth(ctx, out, mp, usage)
    _io(ctx, out)
    _directories(ctx, out)
    return out


def _inodes(ctx: Context, out: CollectorOutput, mp: str, fstype: str) -> None:
    t = ctx.threshold
    if not hasattr(os, "statvfs"):
        out.check("inode.usage", CATEGORY, CheckStatus.NOT_APPLICABLE, "inode statistics not available on this platform",
                  asset=mp, source=SOURCE)
        return
    try:
        st = os.statvfs(mp)
    except OSError as exc:
        out.check("inode.usage", CATEGORY, CheckStatus.UNKNOWN, f"cannot statvfs: {exc}", asset=mp, source=SOURCE)
        out.error(f"inode.usage {mp}: {exc}")
        return
    if st.f_files == 0:
        out.check("inode.usage", CATEGORY, CheckStatus.NOT_APPLICABLE, f"{fstype} allocates inodes dynamically", asset=mp,
                  source=SOURCE)
        return
    pct = (st.f_files - st.f_ffree) / st.f_files * 100.0
    out.metric("inode.used_percent", pct, mp)
    threshold_result(
        out, check_id="inode.usage", category=CATEGORY, asset=mp, value=pct, warning=t("inode_warning_percent"),
        critical=t("inode_critical_percent"), emergency=t("inode_emergency_percent"), label="Inode usage", unit="%",
        recommendation="Look for directories with huge file counts (cache, session, mail queue, backup fragments) and clean "
        "them up.", source=SOURCE, details={"inodes_total": st.f_files, "inodes_free": st.f_ffree})


def growth_percent_per_day(current_used: float, previous_used: float, elapsed_seconds: float, total: float) -> float:
    if elapsed_seconds <= 0 or total <= 0:
        return 0.0
    return (current_used - previous_used) / total * 100.0 * (86400.0 / elapsed_seconds)


def _growth(ctx: Context, out: CollectorOutput, mp: str, usage) -> None:
    target = ctx.now() - timedelta(hours=24)
    prev = ctx.metrics.value_at_or_before("disk.used_bytes", target, mp)
    if not prev:
        return
    elapsed = (ctx.now() - from_iso(prev[0])).total_seconds()
    if elapsed < 6 * 3600 or elapsed > 72 * 3600:
        return  # not comparable
    rate = growth_percent_per_day(usage.used, prev[1], elapsed, usage.total)
    out.metric("disk.growth_percent_per_day", rate, mp)
    limit = ctx.threshold("disk_growth_warning_percent_per_day")
    if rate >= limit:
        out.check("disk.growth", CATEGORY, CheckStatus.WARNING, f"{rate:.1f}% of capacity per day", asset=mp, source=SOURCE)
        days_left = (usage.free / usage.total * 100.0) / rate if rate > 0 else None
        out.finding("disk.growth", CATEGORY, Severity.MEDIUM, Confidence.MEDIUM, f"Rapid disk growth on {mp}",
                    f"Used space grew {rate:.1f}% of capacity per day (limit {limit}%)."
                    + (f" At this rate the disk fills in about {days_left:.0f} day(s)." if days_left else ""),
                    "Find the growing directory (logs, backups, caches) and fix the source or add capacity.",
                    asset=mp, source=SOURCE)
    else:
        out.check("disk.growth", CATEGORY, CheckStatus.PASS, f"{rate:.1f}% of capacity per day", asset=mp, source=SOURCE)


def _io(ctx: Context, out: CollectorOutput) -> None:
    try:
        io = psutil.disk_io_counters()
    except Exception:
        io = None
    if not io:
        return
    now = ctx.now()
    counters = {"disk.io_read_bytes": io.read_bytes, "disk.io_write_bytes": io.write_bytes,
                "disk.io_read_count": io.read_count, "disk.io_write_count": io.write_count}
    busy = getattr(io, "busy_time", None)
    if busy is not None:
        counters["disk.io_busy_ms"] = busy
    for name, value in counters.items():
        out.metric(name, value)
        prev = ctx.metrics.latest(name)
        if prev and value >= prev[1]:
            dt = (now - from_iso(prev[0])).total_seconds()
            if dt > 0:
                rate = (value - prev[1]) / dt
                if name == "disk.io_busy_ms":
                    out.metric("disk.io_busy_percent", min(100.0, rate / 10.0))
                else:
                    out.metric(name + "_per_s", rate)


def _directories(ctx: Context, out: CollectorOutput) -> None:
    targets: List[str] = list(ctx.config.get("monitoring.directory_size_targets", []))
    if not targets:
        return
    interval = int(ctx.config.get("monitoring.directory_scan_interval_seconds", 3600))
    last = ctx.runs.kv_get("disk.dirscan.last")
    if last and (ctx.now() - from_iso(last)).total_seconds() < interval:
        return
    max_entries = int(ctx.config.get("monitoring.directory_scan_max_entries", 200000))
    max_seconds = float(ctx.config.get("monitoring.directory_scan_max_seconds", 20))
    limit_mb = ctx.threshold("log_growth_warning_mb_per_day")
    for path in targets:
        if not os.path.isdir(path):
            continue
        size, complete, entries = bounded_dir_size(path, max_entries, max_seconds)
        if not complete:
            out.check("logs.growth", CATEGORY, CheckStatus.UNKNOWN,
                      f"directory scan of {path} hit its bound after {entries} entries", asset=path, source="scandir")
            out.complete = False
            continue
        out.metric("dir.size_bytes", size, path)
        prev = ctx.metrics.value_at_or_before("dir.size_bytes", ctx.now() - timedelta(hours=24), path)
        status, summary = CheckStatus.PASS, f"{human_bytes(size)}"
        if prev:
            elapsed = (ctx.now() - from_iso(prev[0])).total_seconds()
            if 6 * 3600 <= elapsed <= 72 * 3600:
                growth_mb = (size - prev[1]) / 1048576.0 * (86400.0 / elapsed)
                summary += f", {growth_mb:+.0f} MiB/day"
                if growth_mb >= limit_mb:
                    status = CheckStatus.WARNING
                    out.finding("logs.growth", CATEGORY, Severity.MEDIUM, Confidence.MEDIUM,
                                f"Abnormal growth of {path}",
                                f"{path} grew about {growth_mb:.0f} MiB/day (limit {limit_mb:.0f} MiB/day); now {human_bytes(size)}.",
                                "Identify the noisy log/file, fix the underlying error flood, and confirm logrotate works.",
                                asset=path, source="scandir")
        out.check("logs.growth", CATEGORY, status, summary, asset=path, source="scandir")
    out.meta["dirscan_ran"] = True
    ctx.runs.kv_set("disk.dirscan.last", to_iso(ctx.now()), ctx.now())


__all__: List[str] = ["collect", "growth_percent_per_day", "relevant_partitions"]
