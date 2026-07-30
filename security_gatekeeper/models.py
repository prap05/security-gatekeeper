"""Typed, tool-neutral security finding models."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Source(StrEnum):
    SAST = "sast"
    SCA = "sca"
    DAST = "dast"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


SEVERITY_CVSS: dict[Severity, float] = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 8.0,
    Severity.MEDIUM: 5.5,
    Severity.LOW: 2.5,
    Severity.INFO: 0.0,
    Severity.UNKNOWN: 0.0,
}


@dataclass(slots=True)
class Location:
    """A code location or HTTP endpoint where a finding was observed."""

    resource: str
    line: int | None = None
    method: str | None = None


@dataclass(slots=True)
class Finding:
    """Normalized security finding, independent of the scanner that emitted it."""

    source: Source
    scanner_id: str
    title: str
    severity: Severity
    description: str = ""
    location: Location | None = None
    cves: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    owasp_categories: tuple[str, ...] = ()
    cvss: float | None = None
    epss: float | None = None
    epss_percentile: float | None = None
    remediation: str = ""
    references: tuple[str, ...] = ()
    evidence: str = ""
    correlated_sources: set[Source] = field(default_factory=set)
    related_ids: list[str] = field(default_factory=list)
    fingerprint: str = ""
    risk_score: float = 0.0

    def __post_init__(self) -> None:
        self.correlated_sources.add(self.source)
        if self.cvss is None:
            self.cvss = SEVERITY_CVSS[self.severity]

    @property
    def display_location(self) -> str:
        if self.location is None:
            return "Repository-wide"
        suffix = f":{self.location.line}" if self.location.line else ""
        return f"{self.location.resource}{suffix}"

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["source"] = self.source.value
        result["severity"] = self.severity.value
        result["correlated_sources"] = sorted(source.value for source in self.correlated_sources)
        return result


@dataclass(slots=True)
class GateResult:
    threshold: float
    passed: bool
    findings: list[Finding]
    blocked: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "passed": self.passed,
            "finding_count": len(self.findings),
            "blocked_count": len(self.blocked),
            "blocked": [finding.to_dict() for finding in self.blocked],
        }

