"""Unit tests for Health & Security scoring engine."""

from datetime import datetime, timezone

from shsm.core.context import Context
from shsm.core.findings import Severity
from shsm.reporting.scoring import calculate_component_score, compute_scores


def test_perfect_component_score():
    now_dt = datetime.now(timezone.utc)
    score, coverage, details = calculate_component_score(
        component="cpu",
        check_results=[],
        open_findings=[],
        now_dt=now_dt,
    )
    assert score == 100.0
    assert details["open_findings"] == 0


def test_deduction_for_critical_finding():
    now_dt = datetime.now(timezone.utc)
    open_findings = [
        {
            "check_id": "cpu.usage",
            "component": "cpu",
            "severity": Severity.CRITICAL.value,
        }
    ]
    score, coverage, details = calculate_component_score(
        component="cpu",
        check_results=[],
        open_findings=open_findings,
        now_dt=now_dt,
    )
    # Critical finding deducts 40 points
    assert score == 60.0
    assert details["open_findings"] == 1


def test_compute_scores_context(test_db, sample_config):
    ctx = Context(sample_config, test_db)
    snapshot = compute_scores(ctx)
    assert "health_score" in snapshot
    assert "security_score" in snapshot
    assert snapshot["health_score"] >= 0.0
    assert snapshot["security_score"] >= 0.0
