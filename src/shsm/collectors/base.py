"""Shared helpers for collectors."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from shsm.core.findings import (
    LEVEL_NAME,
    LEVEL_SEVERITY,
    LEVEL_STATUS,
    CheckStatus,
    CollectorOutput,
    Confidence,
    Severity,
    classify,
)


def sustained_level(values: Sequence[float], min_samples: int, warning: float, critical: float,
                    emergency: Optional[float] = None, higher_is_worse: bool = True):
    """Evaluate a rolling window. Returns ``(level, mean, sample_count)``; level is None if too few samples.

    The window mean (not a single sample) is classified, so one spike never raises an alert.
    """
    n = len(values)
    if n < min_samples:
        return None, (sum(values) / n if n else 0.0), n
    mean = sum(values) / n
    return classify(mean, warning, critical, emergency, higher_is_worse), mean, n


def threshold_result(
    out: CollectorOutput,
    *,
    check_id: str,
    category: str,
    asset: str,
    value: float,
    warning: float,
    critical: float,
    emergency: Optional[float],
    label: str,
    unit: str,
    recommendation: str,
    source: str,
    higher_is_worse: bool = True,
    evidence_extra: str = "",
    details: Optional[Dict[str, Any]] = None,
    level: Optional[int] = None,
) -> int:
    """Create a check result (+ finding if a threshold is crossed). Returns the threshold level 0..3."""
    if level is None:
        level = classify(value, warning, critical, emergency, higher_is_worse)
    where = f" on {asset}" if asset else ""
    summary = f"{label}{where}: {value:.1f}{unit} ({LEVEL_NAME[level]})"
    det = {"value": round(value, 3), "warning": warning, "critical": critical, "emergency": emergency}
    det.update(details or {})
    out.check(check_id, category, LEVEL_STATUS[level], summary, asset=asset, source=source, **det)
    if level > 0:
        limit = (warning, critical, emergency if emergency is not None else critical)[level - 1]
        cmp = ">=" if higher_is_worse else "<="
        evidence = f"{label}{where} is {value:.1f}{unit} ({cmp} {limit}{unit} {LEVEL_NAME[level]} threshold)."
        if evidence_extra:
            evidence += " " + evidence_extra
        out.finding(
            check_id, category, LEVEL_SEVERITY[level], Confidence.HIGH, f"{label} {LEVEL_NAME[level]}{where}",
            evidence, recommendation, asset=asset, source=source,
        )
    return level


def unknown_check(out: CollectorOutput, check_id: str, category: str, reason: str, asset: str = "",
                  source: str = "", status: CheckStatus = CheckStatus.UNKNOWN) -> None:
    out.check(check_id, category, status, reason, asset=asset, source=source)
    out.error(f"{check_id}: {reason}")


def human_bytes(n: float) -> str:
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(n) < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} TiB"


def join_limited(items: Sequence[str], limit: int = 5) -> str:
    items = list(items)
    if len(items) <= limit:
        return ", ".join(items)
    return ", ".join(items[:limit]) + f" (+{len(items) - limit} more)"


SEVERITY_BY_STATUS: Dict[CheckStatus, Severity] = {
    CheckStatus.WARNING: Severity.MEDIUM,
    CheckStatus.CRITICAL: Severity.HIGH,
}

__all__: List[str] = [
    "sustained_level", "threshold_result", "unknown_check", "human_bytes", "join_limited",
]
