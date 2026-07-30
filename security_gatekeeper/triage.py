"""Finding correlation, EPSS enrichment, and transparent risk scoring."""

from __future__ import annotations

import hashlib
import re
from collections import defaultdict
from collections.abc import Iterable
from pathlib import PurePosixPath

from .models import Finding, Severity

_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]+")


def _normalize(value: str) -> str:
    return _NON_ALPHANUMERIC.sub("-", value.lower()).strip("-")


def _resource_key(finding: Finding) -> str:
    if finding.location is None:
        return "repository"
    resource = finding.location.resource.split("?", maxsplit=1)[0].rstrip("/")
    # Source findings include full paths; only retain a stable, useful file identity.
    if "/" not in resource and "\\" not in resource:
        return resource.lower()
    return str(PurePosixPath(resource.replace("\\", "/"))).lower()


def correlation_key(finding: Finding) -> str:
    """Return a conservative key: CVEs first, then CWE/title plus the affected resource.

    Location is deliberately part of non-CVE keys. Two generic alerts such as
    "missing security header" on different endpoints must remain separate.
    """
    if finding.cves:
        return f"cve:{sorted(finding.cves)[0].lower()}"
    resource = _resource_key(finding)
    if finding.cwes:
        return f"cwe:{sorted(finding.cwes)[0].lower()}:{resource}"
    return f"title:{_normalize(finding.title)}:{resource}"


def stable_fingerprint(finding: Finding) -> str:
    identity = "|".join((correlation_key(finding), finding.scanner_id.lower()))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    """Merge genuinely overlapping scanner results while retaining every source ID."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[correlation_key(finding)].append(finding)

    merged: list[Finding] = []
    for key, group in groups.items():
        # Choose the most severe observation as the canonical record. This keeps
        # context from a dynamic scanner when it reports a higher impact.
        primary = max(group, key=lambda item: (item.cvss or 0.0, item.severity.value))
        primary.related_ids = sorted({item.scanner_id for item in group})
        primary.correlated_sources = {source for item in group for source in item.correlated_sources}
        primary.cves = tuple(sorted({cve for item in group for cve in item.cves}))
        primary.cwes = tuple(sorted({cwe for item in group for cwe in item.cwes}))
        primary.owasp_categories = tuple(
            sorted({category for item in group for category in item.owasp_categories})
        )
        primary.references = tuple(sorted({url for item in group for url in item.references}))
        primary.fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
        merged.append(primary)
    return sorted(merged, key=lambda item: (item.risk_score, item.title), reverse=True)


def score(finding: Finding) -> float:
    """Score 0-100 using impact (CVSS), exploit likelihood (EPSS), and corroboration.

    Formula: 65% CVSS, 30% EPSS probability, +5 points for each independent
    corroborating source after the first (capped at 10). It is intentionally
    simple enough to defend in a risk-review conversation.
    """
    cvss_component = max(0.0, min(finding.cvss or 0.0, 10.0)) * 6.5
    epss_component = max(0.0, min(finding.epss or 0.0, 1.0)) * 30.0
    corroboration = min(max(len(finding.correlated_sources) - 1, 0) * 5.0, 10.0)
    return round(min(cvss_component + epss_component + corroboration, 100.0), 1)


def apply_risk_scores(findings: Iterable[Finding]) -> list[Finding]:
    scored = list(findings)
    for finding in scored:
        finding.risk_score = score(finding)
        if not finding.fingerprint:
            finding.fingerprint = stable_fingerprint(finding)
    return sorted(scored, key=lambda item: item.risk_score, reverse=True)


def severity_for_risk(score_value: float) -> Severity:
    if score_value >= 80:
        return Severity.CRITICAL
    if score_value >= 60:
        return Severity.HIGH
    if score_value >= 35:
        return Severity.MEDIUM
    if score_value > 0:
        return Severity.LOW
    return Severity.INFO

