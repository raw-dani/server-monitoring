"""Process inspection: top consumers, zombies, and unexpected privileged executables."""

from __future__ import annotations

import os
from typing import Any, Dict, List

import psutil

from shsm.collectors.base import threshold_result
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "psutil"
SUSPICIOUS_EXE_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/")


_USER_CACHE: Dict[int, str] = {}


class ProcessSampler:
    """Prime per-process CPU counters, then report the top consumers after a measurement interval."""

    def __init__(self) -> None:
        self.procs: List[psutil.Process] = []
        self._primed: bool = False

    def prime(self) -> None:
        self.procs = []
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
                self.procs.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self._primed = True

    def snapshot(self) -> List[Dict[str, Any]]:
        rows = []
        for p in self.procs:
            try:
                with p.oneshot():
                    pid = p.pid
                    try:
                        name = p.name()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        name = f"proc_{pid}"
                    user = _safe_user(p)
                    try:
                        cpu_val = p.cpu_percent(None)
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        cpu_val = 0.0
                    try:
                        rss_val = p.memory_info().rss
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        rss_val = 0
                    try:
                        status_val = p.status()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        status_val = "unknown"

                    rows.append({
                        "pid": pid,
                        "name": name,
                        "user": user,
                        "cpu": cpu_val,
                        "rss": rss_val,
                        "status": status_val,
                    })
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
        return rows


def _safe_user(p: psutil.Process) -> str:
    try:
        uids = p.uids()
        uid = uids.real
        if uid in _USER_CACHE:
            return _USER_CACHE[uid]
        uname = p.username()
        _USER_CACHE[uid] = uname
        return uname
    except (psutil.AccessDenied, KeyError, psutil.NoSuchProcess, AttributeError):
        return "?"


def top_by(rows: List[Dict[str, Any]], key: str, n: int) -> List[Dict[str, Any]]:
    return sorted(rows, key=lambda r: r.get(key, 0.0) if r.get(key) is not None else 0.0, reverse=True)[:n]


def format_top(rows: List[Dict[str, Any]], key: str) -> str:
    if key == "cpu":
        # Only report processes with real, measurable CPU consumption (>= 0.5%)
        # Exclude shsm/python from self-reporting as a culprit if its CPU is minimal (< 5.0%)
        meaningful = [
            r for r in rows
            if (r.get("cpu") or 0.0) >= 0.5
            and not (r.get("name") in ("shsm", "python", "python3") and (r.get("cpu") or 0.0) < 5.0)
        ]
        if not meaningful:
            if len(rows) <= 3:
                return "insufficient privileges to inspect all user processes (/proc restricted; check 'top' via SSH)"
            return "none active during 1s sample (likely short-lived PHP/cron bursts)"
        return ", ".join(f"{r['name']}[{r['pid']}] {r['cpu']:.0f}%" for r in meaningful)
    # Memory: only report processes with actual RSS usage
    meaningful_mem = [r for r in rows if (r.get("rss") or 0) > 1048576]
    if not meaningful_mem:
        return "none reported"
    return ", ".join(f"{r['name']}[{r['pid']}] {r['rss'] / 1048576:.0f} MiB" for r in meaningful_mem)


def collect_processes(ctx: Context, rows: List[Dict[str, Any]]) -> CollectorOutput:
    """Zombie count and top consumers from an already-taken snapshot (no extra process walk)."""
    out = CollectorOutput()
    n = int(ctx.config.get("monitoring.top_processes", 5))
    zombies = [r for r in rows if r["status"] == psutil.STATUS_ZOMBIE]
    out.metric("process.count", len(rows))
    out.metric("process.zombies", len(zombies))
    warn = ctx.threshold("zombie_warning")
    if len(zombies) >= warn:
        out.check("process.zombies", "health", CheckStatus.WARNING, f"{len(zombies)} zombie processes", source=SOURCE)
        out.finding("process.zombies", "health", Severity.LOW, Confidence.HIGH, "Many zombie processes",
                    f"{len(zombies)} zombie processes (threshold {warn:.0f}).",
                    "Identify the parent process that is not reaping children and restart it during a maintenance window.",
                    source=SOURCE)
    else:
        out.check("process.zombies", "health", CheckStatus.PASS, f"{len(zombies)} zombie processes", source=SOURCE)
    out.scope("process.zombies")
    out.meta["top_cpu"] = [
        {k: r[k] for k in ("pid", "name", "user", "cpu")} for r in top_by(rows, "cpu", n)]
    out.meta["top_memory"] = [
        {k: r[k] for k in ("pid", "name", "user", "rss")} for r in top_by(rows, "rss", n)]
    return out


def collect_privileged(ctx: Context) -> CollectorOutput:
    """Flag root-owned processes running from temp locations or from a deleted binary (needs root to be conclusive)."""
    out = CollectorOutput()
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        out.check("process.privileged", "security", CheckStatus.UNKNOWN,
                  "requires root to inspect other users' process executables", source=SOURCE)
        out.complete = False
        return out
    inspected = denied = 0
    for p in psutil.process_iter():
        try:
            if p.uids().effective != 0:
                continue
            exe = p.exe()
            inspected += 1
        except (psutil.AccessDenied, psutil.ZombieProcess):
            denied += 1
            continue
        except psutil.NoSuchProcess:
            continue
        except OSError:
            continue
        try:
            name = p.name()
            pid = p.pid
        except psutil.NoSuchProcess:
            continue
        reasons = []
        if exe.endswith(" (deleted)"):
            reasons.append("binary was deleted while the process is running")
        if exe.startswith(SUSPICIOUS_EXE_PREFIXES):
            reasons.append(f"runs from temporary location {os.path.dirname(exe)}")
        if reasons:
            out.finding(
                "process.privileged", "security", Severity.HIGH, Confidence.MEDIUM,
                f"Privileged process from unexpected location: {name}",
                f"root process {name}[{pid}] exe={os.path.dirname(exe)}/…: {'; '.join(reasons)}.",
                "Investigate the process (ls -l /proc/<pid>/exe, lsof -p <pid>). Kernel-updated packages can cause deleted "
                "binaries legitimately; temp-directory execution as root rarely is.",
                asset=name, source=SOURCE, key=f"{name}:{exe}")
    if denied and not inspected:
        out.check("process.privileged", "security", CheckStatus.UNKNOWN, "all process inspections were denied",
                  source=SOURCE)
        out.complete = False
        return out
    flagged = len([f for f in out.findings if f.check_id == "process.privileged"])
    out.check("process.privileged", "security", CheckStatus.WARNING if flagged else CheckStatus.PASS,
              f"{inspected} root processes inspected, {flagged} flagged", source=SOURCE)
    out.scope("process.privileged")
    return out


__all__ = ["ProcessSampler", "collect_processes", "collect_privileged", "threshold_result"]
