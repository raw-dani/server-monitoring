"""Structured results shared by every collector and scanner."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence

from shsm.utils.redact import redact, sanitize_excerpt


class CheckStatus(str, Enum):
    PASS = "PASS"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"

    @property
    def conclusive(self) -> bool:
        return self in (CheckStatus.PASS, CheckStatus.WARNING, CheckStatus.CRITICAL)


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER.index(self)


class Confidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"

    @property
    def rank(self) -> int:
        return CONFIDENCE_ORDER.index(self)


class FindingStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
CONFIDENCE_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.CONFIRMED]

# Maps the threshold level classification (0 ok, 1 warning, 2 critical, 3 emergency) to outputs.
LEVEL_STATUS = {
    0: CheckStatus.PASS,
    1: CheckStatus.WARNING,
    2: CheckStatus.CRITICAL,
    3: CheckStatus.CRITICAL,
}
LEVEL_SEVERITY = {1: Severity.MEDIUM, 2: Severity.HIGH, 3: Severity.CRITICAL}
LEVEL_NAME = {0: "ok", 1: "warning", 2: "critical", 3: "emergency"}


def classify(value: float, warning: float, critical: float, emergency: Optional[float] = None,
             higher_is_worse: bool = True) -> int:
    """Return threshold level 0..3 for ``value``."""
    levels = [warning, critical] + ([emergency] if emergency is not None else [])
    level = 0
    for i, limit in enumerate(levels, start=1):
        bad = value >= limit if higher_is_worse else value <= limit
        if bad:
            level = i
    return level


def make_fingerprint(*parts: Any) -> str:
    raw = "\x1f".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]


@dataclass
class CheckResult:
    check_id: str
    category: str
    status: CheckStatus
    summary: str = ""
    asset: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    source: str = ""

    def __post_init__(self) -> None:
        self.summary = sanitize_excerpt(self.summary, 300)


@dataclass
class Metric:
    name: str
    value: float
    asset: str = ""


@dataclass
class FindingCandidate:
    check_id: str
    category: str
    severity: Severity
    confidence: Confidence
    title: str
    evidence: str
    recommendation: str
    asset: str = ""
    source: str = ""
    key: str = ""  # extra identity component (e.g. file path, port)
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.title = sanitize_excerpt(self.title, 200)
        self.evidence = redact(self.evidence)[:2000]
        self.recommendation = redact(self.recommendation)[:1000]

    @property
    def fingerprint(self) -> str:
        return make_fingerprint(self.check_id, self.asset, self.key)


@dataclass
class CollectorOutput:
    """Everything a collector/scanner returns; persisted by the runner."""

    checks: List[CheckResult] = field(default_factory=list)
    metrics: List[Metric] = field(default_factory=list)
    findings: List[FindingCandidate] = field(default_factory=list)
    scopes: List[str] = field(default_factory=list)  # check_id prefixes that were fully evaluated
    complete: bool = True
    errors: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict)
    tool_versions: Dict[str, str] = field(default_factory=dict)

    def check(self, check_id: str, category: str, status: CheckStatus, summary: str = "",
              asset: str = "", source: str = "", **details: Any) -> CheckResult:
        res = CheckResult(check_id, category, status, summary, asset, details, source)
        self.checks.append(res)
        return res

    def metric(self, name: str, value: Optional[float], asset: str = "") -> None:
        if value is not None:
            self.metrics.append(Metric(name, float(value), asset))

    def finding(self, check_id: str, category: str, severity: Severity, confidence: Confidence,
                title: str, evidence: str, recommendation: str, asset: str = "", source: str = "",
                key: str = "", **details: Any) -> FindingCandidate:
        cand = FindingCandidate(check_id, category, severity, confidence, title, evidence,
                                recommendation, asset, source, key, details)
        self.findings.append(cand)
        return cand

    def scope(self, *prefixes: str) -> None:
        for p in prefixes:
            if p not in self.scopes:
                self.scopes.append(p)

    def error(self, message: str) -> None:
        self.errors.append(sanitize_excerpt(message, 300))

    def merge(self, other: CollectorOutput) -> None:
        self.checks += other.checks
        self.metrics += other.metrics
        self.findings += other.findings
        for s in other.scopes:
            self.scope(s)
        self.complete = self.complete and other.complete
        self.errors += other.errors
        self.meta.update(other.meta)
        self.tool_versions.update(other.tool_versions)

    @property
    def worst_status(self) -> CheckStatus:
        order = [CheckStatus.CRITICAL, CheckStatus.ERROR, CheckStatus.WARNING, CheckStatus.UNKNOWN, CheckStatus.PASS]
        present = {c.status for c in self.checks}
        for s in order:
            if s in present:
                return s
        return CheckStatus.NOT_APPLICABLE


def severity_max(severities: Sequence[Severity]) -> Severity:
    return max(severities, key=lambda s: s.rank) if severities else Severity.INFO
