"""Portable JSON and Markdown evidence reports for engineers and auditors."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from .models import Finding


def write_json(path: Path, findings: list[Finding]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"schema_version": "1.0", "findings": [finding.to_dict() for finding in findings]}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def read_json(path: Path) -> list[Finding]:
    from .models import Location, Source, Severity

    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for raw in payload.get("findings", []):
        location_data = raw.get("location")
        location = Location(**location_data) if location_data else None
        raw["source"] = Source(raw["source"])
        raw["severity"] = Severity(raw["severity"])
        raw["location"] = location
        raw["cves"] = tuple(raw.get("cves", []))
        raw["cwes"] = tuple(raw.get("cwes", []))
        raw["owasp_categories"] = tuple(raw.get("owasp_categories", []))
        raw["references"] = tuple(raw.get("references", []))
        raw["correlated_sources"] = {Source(value) for value in raw.get("correlated_sources", [])}
        findings.append(Finding(**raw))
    return findings


def write_markdown(path: Path, findings: list[Finding], threshold: float) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    by_source = Counter(source.value for finding in findings for source in finding.correlated_sources)
    blocked = [finding for finding in findings if finding.risk_score >= threshold]
    lines = [
        "# Security Gatekeeper report",
        "",
        f"**Decision:** {'FAIL' if blocked else 'PASS'} - threshold: `{threshold:.1f}/100`",
        "",
        f"Normalized findings: **{len(findings)}** | Blocking findings: **{len(blocked)}**",
        "",
        "## Coverage",
        "",
        "| Source | Correlated findings |",
        "|---|---:|",
    ]
    lines.extend(f"| {source.upper()} | {count} |" for source, count in sorted(by_source.items()))
    lines.extend(
        [
            "",
            "## Prioritized findings",
            "",
            "| Risk | Sources | Finding | Location | CVEs |",
            "|---:|---|---|---|---|",
        ]
    )
    for finding in findings:
        sources = ", ".join(sorted(source.upper() for source in finding.correlated_sources))
        cves = ", ".join(finding.cves) or "-"
        lines.append(
            f"| {finding.risk_score:.1f} | {sources} | {finding.title} | "
            f"{finding.display_location} | {cves} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
