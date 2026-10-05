"""Rootkit scanner integration (rkhunter and chkrootkit)."""

from __future__ import annotations

import re
from typing import Any, List, Tuple

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "rootkit_scanner"
CATEGORY = "malware_integrity"

_RKH_WARNING = re.compile(r"\[\s*WARNING\s*\]")
_CHK_INFECTED = re.compile(r"(?i)\bINFECTED\b")


def _run_with_sudo_fallback(
    ctx: Context, cmd: List[str], timeout: float = 60, ok_returncodes: Tuple[int, ...] = (0,)
) -> Any:
    res = ctx.runner.run(cmd, timeout=timeout, ok_returncodes=ok_returncodes)
    if res.ran and res.ok:
        return res
    if ctx.runner.which("sudo"):
        res_sudo = ctx.runner.run(["sudo"] + cmd, timeout=timeout, ok_returncodes=ok_returncodes)
        if res_sudo.ran and res_sudo.ok:
            return res_sudo
    return res


def run_rkhunter(ctx: Context, timeout: float) -> Tuple[bool, List[str], str]:
    rkh = ctx.runner.which("rkhunter")
    if not rkh:
        return False, [], "rkhunter not installed"

    # --check: required check mode, --cronjob: non-interactive, --rwo: report warnings only, --sk: skip keypress
    res = _run_with_sudo_fallback(
        ctx, [rkh, "--check", "--cronjob", "--rwo", "--sk"], timeout=timeout, ok_returncodes=(0, 1)
    )
    if not res.ran:
        return False, [], f"rkhunter failed: {res.describe()}"

    # Only accept lines matching actual [ WARNING ] pattern to avoid capturing option errors or summaries
    warnings = [line.strip() for line in res.stdout.splitlines() if _RKH_WARNING.search(line)]
    return True, warnings, ""


def run_chkrootkit(ctx: Context, timeout: float) -> Tuple[bool, List[str], str]:
    chk = ctx.runner.which("chkrootkit")
    if not chk:
        return False, [], "chkrootkit not installed"

    res = _run_with_sudo_fallback(ctx, [chk, "-q"], timeout=timeout, ok_returncodes=(0, 1))
    if not res.ran:
        return False, [], f"chkrootkit failed: {res.describe()}"

    warnings = []
    for line in res.stdout.splitlines():
        if _CHK_INFECTED.search(line):
            warnings.append(line.strip())
    return True, warnings, ""


def scan(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()

    enabled = ctx.config.get("scanning.rootkit.enabled", True)
    if not enabled:
        out.check("rootkit.scan", CATEGORY, CheckStatus.NOT_APPLICABLE, "Rootkit scanning is disabled in configuration", source=SOURCE)
        return out

    timeout = float(ctx.config.get("scanning.rootkit.timeout_seconds", 3600))
    tools = ctx.config.get("scanning.rootkit.tools", ["rkhunter", "chkrootkit"])

    ran_any = False
    all_warnings: List[str] = []

    if "rkhunter" in tools:
        ok, rkh_warns, err = run_rkhunter(ctx, timeout)
        if ok:
            ran_any = True
            all_warnings.extend(rkh_warns)

    if "chkrootkit" in tools:
        ok, chk_warns, err = run_chkrootkit(ctx, timeout)
        if ok:
            ran_any = True
            all_warnings.extend(chk_warns)

    if not ran_any:
        out.check("rootkit.scan", CATEGORY, CheckStatus.NOT_APPLICABLE, "Neither rkhunter nor chkrootkit is installed", source=SOURCE)
        return out

    out.metric("rootkit.warnings_count", len(all_warnings))
    out.scope("rootkit.warning")

    if all_warnings:
        for w in all_warnings[:10]:
            out.finding(
                "rootkit.warning",
                CATEGORY,
                Severity.CRITICAL,
                Confidence.MEDIUM,
                f"Possible rootkit or system file anomaly: {w[:80]}",
                f"Rootkit check warned: {w}. Note: package updates may cause benign checksum mismatches.",
                "Review the warned binary or kernel module. If packages were recently updated, run 'rkhunter --propupd'.",
                source=SOURCE,
                key=w[:64],
            )
        out.check(
            "rootkit.scan",
            CATEGORY,
            CheckStatus.WARNING,
            f"Rootkit scan flagged {len(all_warnings)} warning(s)",
            source=SOURCE,
        )
    else:
        # Per specification rule: clean tool result does NOT guarantee absence of rootkits
        out.check(
            "rootkit.scan",
            CATEGORY,
            CheckStatus.PASS,
            "Rootkit scanner finished without detections (advisory check; does not prove absolute absence)",
            source=SOURCE,
        )

    return out
