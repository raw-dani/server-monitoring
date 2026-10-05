"""Lynis host security auditing integration."""

from __future__ import annotations

import os
import re
from typing import Any, Dict

from shsm.core.context import Context
from shsm.core.findings import CheckStatus, CollectorOutput, Confidence, Severity

SOURCE = "lynis"
CATEGORY = "system_integrity"

_WARNING_LINE = re.compile(r"^Warning:\s*(.+)$", re.M)
_SUGGESTION_LINE = re.compile(r"^Suggestion:\s*(.+)$", re.M)
_HARDENING_INDEX = re.compile(r"Hardening index\s*:\s*(\d+)")


def parse_lynis_report(report_path: str) -> Dict[str, Any]:
    """Parse lynis-report.dat key-value format if generated."""
    data: Dict[str, Any] = {"warnings": [], "suggestions": [], "hardening_index": None}
    if not os.path.isfile(report_path) or not os.access(report_path, os.R_OK):
        return data

    try:
        with open(report_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k == "warning[]":
                        data["warnings"].append(v)
                    elif k == "suggestion[]":
                        data["suggestions"].append(v)
                    elif k == "hardening_index":
                        try:
                            data["hardening_index"] = int(v)
                        except ValueError:
                            pass
    except OSError:
        pass
    return data


def scan(ctx: Context) -> CollectorOutput:
    out = CollectorOutput()

    enabled = ctx.config.get("scanning.lynis.enabled", True)
    if not enabled:
        out.check("lynis.audit", CATEGORY, CheckStatus.NOT_APPLICABLE, "Lynis auditing is disabled in configuration", source=SOURCE)
        return out

    lynis_bin = ctx.runner.which("lynis")
    if not lynis_bin:
        out.check("lynis.audit", CATEGORY, CheckStatus.NOT_APPLICABLE, "Lynis is not installed", source=SOURCE)
        return out

    timeout = float(ctx.config.get("scanning.lynis.timeout_seconds", 1800))
    report_file = str(ctx.config.get("scanning.lynis.report_file", "/var/log/lynis-report.dat"))

    # Execute lynis in non-interactive audit mode
    res = ctx.runner.run(
        [lynis_bin, "audit", "system", "--quick", "--cronjob", f"--report-file={report_file}"],
        timeout=timeout,
        ok_returncodes=(0, 64, 65, 66),  # Lynis return codes: 0 clean, 64-66 warnings/suggestions
    )

    if not res.ran:
        out.check("lynis.audit", CATEGORY, CheckStatus.ERROR, f"Lynis audit execution failed: {res.describe()}", source=SOURCE)
        out.error(f"lynis.audit: {res.describe()}")
        return out

    # Parse report file or stdout
    report_data = parse_lynis_report(report_file)
    warnings = report_data.get("warnings", [])
    suggestions = report_data.get("suggestions", [])
    hardening_index = report_data.get("hardening_index")

    if hardening_index is None:
        m = _HARDENING_INDEX.search(res.stdout)
        if m:
            hardening_index = int(m.group(1))

    if hardening_index is not None:
        out.metric("lynis.hardening_index", float(hardening_index))

    # Add findings for warnings
    for w in warnings[:20]:
        out.finding(
            "lynis.warning",
            CATEGORY,
            Severity.MEDIUM,
            Confidence.HIGH,
            f"Lynis security warning: {w[:80]}",
            f"Lynis host audit flagged: {w}",
            "Review Lynis recommendation and apply recommended configuration hardening.",
            source=SOURCE,
            key=w[:64],
        )

    out.metric("lynis.warnings_count", len(warnings))
    out.metric("lynis.suggestions_count", len(suggestions))

    h_str = f"Hardening index: {hardening_index}" if hardening_index else ""
    if warnings:
        out.check(
            "lynis.audit",
            CATEGORY,
            CheckStatus.WARNING,
            f"Lynis completed with {len(warnings)} warnings and {len(suggestions)} suggestions. {h_str}".strip(),
            source=SOURCE,
        )
    else:
        out.check(
            "lynis.audit",
            CATEGORY,
            CheckStatus.PASS,
            f"Lynis audit completed cleanly ({len(suggestions)} suggestions). {h_str}".strip(),
            source=SOURCE,
        )

    return out
