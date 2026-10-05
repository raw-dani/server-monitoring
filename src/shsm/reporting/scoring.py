"""Deterministic health and security scoring with coverage indicators."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from shsm.core.components import (
    COMPONENTS,
    EXPECTED_CHECKS,
    HEALTH,
    SECURITY,
    component_for,
    stale_after,
)
from shsm.core.context import Context
from shsm.core.findings import CheckStatus, Severity
from shsm.core.timeutils import from_iso


def calculate_component_score(
    component: str,
    check_results: List[Dict[str, Any]],
    open_findings: List[Dict[str, Any]],
    now_dt,
) -> Tuple[float, float, Dict[str, Any]]:
    """Return (score_0_to_100, coverage_0_to_100, details) for a single component.

    Coverage: fraction of expected checks that have a fresh, conclusive result.
    Score: 100 minus severity penalty deductions for open findings and failed checks.
    """
    expected = EXPECTED_CHECKS.get(component, [])
    comp_checks = [c for c in check_results if component_for(c["check_id"]) == component]
    comp_findings = [f for f in open_findings if (f.get("component") == component or component_for(f["check_id"]) == component)]

    # Evaluate freshness and check results
    check_by_id: Dict[str, List[Dict[str, Any]]] = {}
    for c in comp_checks:
        check_by_id.setdefault(c["check_id"], []).append(c)

    conclusive_expected = 0
    for exp_id in expected:
        matches = check_by_id.get(exp_id, [])
        if matches:
            # Check if any match is conclusive and not stale
            fresh_and_conclusive = False
            for m in matches:
                st = m.get("status")
                chk_time = from_iso(m["checked_at"]) if m.get("checked_at") else None
                max_stale = stale_after(exp_id)
                if chk_time and (now_dt - chk_time).total_seconds() <= max_stale:
                    if st in (CheckStatus.PASS.value, CheckStatus.WARNING.value, CheckStatus.CRITICAL.value):
                        fresh_and_conclusive = True
                        break
            if fresh_and_conclusive:
                conclusive_expected += 1

    coverage_pct = (conclusive_expected / len(expected) * 100.0) if expected else 100.0

    # Score calculation from 100 with deductions
    score = 100.0
    deductions: Dict[str, float] = {}

    for f in comp_findings:
        sev = f.get("severity", Severity.INFO.value)
        if sev == Severity.CRITICAL.value:
            penalty = 40.0
        elif sev == Severity.HIGH.value:
            penalty = 20.0
        elif sev == Severity.MEDIUM.value:
            penalty = 10.0
        elif sev == Severity.LOW.value:
            penalty = 3.0
        else:
            penalty = 0.0

        key = f"finding_{f['check_id']}_{sev}"
        # Bound duplicate penalties per check
        deductions[key] = max(deductions.get(key, 0.0), penalty)

    # Check for direct CRITICAL / WARNING check status without finding
    for c in comp_checks:
        st = c.get("status")
        if st == CheckStatus.CRITICAL.value:
            deductions[f"check_{c['check_id']}_crit"] = 30.0
        elif st == CheckStatus.WARNING.value:
            deductions[f"check_{c['check_id']}_warn"] = 10.0

    total_penalty = sum(deductions.values())
    final_score = max(0.0, score - total_penalty)

    return final_score, coverage_pct, {
        "score": round(final_score, 1),
        "coverage": round(coverage_pct, 1),
        "open_findings": len(comp_findings),
        "conclusive_checks": conclusive_expected,
        "expected_checks": len(expected),
    }


def compute_scores(ctx: Context) -> Dict[str, Any]:
    now = ctx.now()
    check_results = ctx.checks.all()
    open_findings = ctx.findings.list(statuses=["OPEN", "ACKNOWLEDGED"])

    health_weighted_sum = 0.0
    health_weight_total = 0.0
    health_cov_weighted_sum = 0.0

    security_weighted_sum = 0.0
    security_weight_total = 0.0
    security_cov_weighted_sum = 0.0

    components_breakdown: Dict[str, Any] = {}

    for comp, (kind, weight, label) in COMPONENTS.items():
        score, cov, details = calculate_component_score(comp, check_results, open_findings, now)
        details["label"] = label
        details["weight"] = weight
        components_breakdown[comp] = details

        if kind == HEALTH:
            health_weighted_sum += score * weight
            health_cov_weighted_sum += cov * weight
            health_weight_total += weight
        elif kind == SECURITY:
            security_weighted_sum += score * weight
            security_cov_weighted_sum += cov * weight
            security_weight_total += weight

    health_score = health_weighted_sum / health_weight_total if health_weight_total else 100.0
    health_cov = health_cov_weighted_sum / health_weight_total if health_weight_total else 100.0

    security_score = security_weighted_sum / security_weight_total if security_weight_total else 100.0
    security_cov = security_cov_weighted_sum / security_weight_total if security_weight_total else 100.0

    snapshot = {
        "health_score": round(health_score, 1),
        "health_coverage": round(health_cov, 1),
        "security_score": round(security_score, 1),
        "security_coverage": round(security_cov, 1),
        "components": components_breakdown,
    }

    # Save to score snapshots
    ctx.runs.add_snapshot(now, health_score, health_cov, security_score, security_cov, snapshot)

    return snapshot
