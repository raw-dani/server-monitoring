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


class ProcessSampler:
    """Prime per-process CPU counters, then report the top consumers after a measurement interval."""

    def __init__(self) -> None:
        self.procs: List[psutil.Process] = []

    def prime(self) -> None:
        self.procs = []
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
                self.procs.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def snapshot(self) -> List[Dict[str, Any]]:
        rows = []
        for p in self.procs:
            try:
                with p.oneshot():
                    rows.append({
                        "pid": p.pid,
                        "name": p.name(),
                        "user": _safe_user(p),
                        "cpu": p.cpu_percent(None),
                        "rss": p.memory_info().rss,
                        "status": p.status(),
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return rows


def _safe_user(p: psutil.Process) -> str:
    try:
        return p.username()
    except (psutil.AccessDenied, KeyError, psutil.NoSuchProcess):
        return "?"


def top_by(rows: List[Dict[str, Any]], key: str, n: int) -> List[Dict[str, Any]]:
    return sorted(rows, key=lambda r: r[key], reverse=True)[:n]


def format_top(rows: List[Dict[str, Any]], key: str) -> str:
    if key == "cpu":
        return ", ".join(f"{r['name']}[{r['pid']}] {r['cpu']:.0f}%" for r in rows)
    return ", ".join(f"{r['name']}[{r['pid']}] {r['rss'] / 1048576:.0f} MiB" for r in rows)


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
