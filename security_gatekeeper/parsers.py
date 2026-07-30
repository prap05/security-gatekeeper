"""Defensive parsers for Semgrep, OWASP Dependency-Check, and OWASP ZAP JSON reports."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .models import Finding, Location, Severity, Source

_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_PATTERN = re.compile(r"CWE-\d+", re.IGNORECASE)


def _load(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"Report not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in report: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return payload


def _severity(value: object) -> Severity:
    normalized = str(value or "unknown").lower()
    if "critical" in normalized:
        return Severity.CRITICAL
    if "high" in normalized or normalized == "error":
        return Severity.HIGH
    if "medium" in normalized or "moderate" in normalized or normalized == "warning":
        return Severity.MEDIUM
    if "low" in normalized:
        return Severity.LOW
    if "info" in normalized or "informational" in normalized:
        return Severity.INFO
    return Severity.UNKNOWN


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value if item)
    return ()


def _matches(pattern: re.Pattern[str], *values: object) -> tuple[str, ...]:
    text = " ".join(str(value) for value in values if value)
    return tuple(sorted({match.upper() for match in pattern.findall(text)}))


def _cvss_from_dependency(vulnerability: dict[str, Any]) -> float | None:
    for field in ("cvssv4", "cvssv3", "cvssv2"):
        metric = vulnerability.get(field)
        if isinstance(metric, dict):
            score = metric.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def parse_semgrep(path: Path) -> list[Finding]:
    """Parse Semgrep CE JSON output (``semgrep scan --json``)."""
    report = _load(path)
    findings: list[Finding] = []
    for result in report.get("results", []):
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        path_value = str(result.get("path", "Repository-wide"))
        references = _strings(metadata.get("references"))
        combined = (metadata, extra.get("message"), result.get("check_id"))
        findings.append(
            Finding(
                source=Source.SAST,
                scanner_id=str(result.get("check_id", "semgrep.unknown")),
                title=str(metadata.get("shortlink") or result.get("check_id", "Semgrep finding")),
                severity=_severity(extra.get("severity")),
                description=str(extra.get("message", "")),
                location=Location(resource=path_value, line=start.get("line") if isinstance(start.get("line"), int) else None),
                cves=_matches(_CVE_PATTERN, *combined),
                cwes=_matches(_CWE_PATTERN, *combined),
                owasp_categories=_strings(metadata.get("owasp")),
                remediation=str(metadata.get("fix", "")),
                references=references,
                evidence=str(extra.get("lines", "")),
            )
        )
    return findings


def parse_dependency_check(path: Path) -> list[Finding]:
    """Parse OWASP Dependency-Check JSON reports without assuming one schema version."""
    report = _load(path)
    findings: list[Finding] = []
    for dependency in report.get("dependencies", []):
        if not isinstance(dependency, dict):
            continue
        package = str(dependency.get("fileName") or dependency.get("filePath") or "dependency")
        for vulnerability in dependency.get("vulnerabilities", []) or []:
            if not isinstance(vulnerability, dict):
                continue
            name = str(vulnerability.get("name", "Unknown dependency CVE")).upper()
            description = str(vulnerability.get("description", ""))
            references: list[str] = []
            for reference in vulnerability.get("references", []) or []:
                if isinstance(reference, dict) and reference.get("url"):
                    references.append(str(reference["url"]))
            findings.append(
                Finding(
                    source=Source.SCA,
                    scanner_id=name,
                    title=f"{name} in {package}",
                    severity=_severity(vulnerability.get("severity")),
                    description=description,
                    location=Location(resource=package),
                    cves=_matches(_CVE_PATTERN, name, description),
                    cwes=_matches(_CWE_PATTERN, vulnerability.get("cwes"), description),
                    cvss=_cvss_from_dependency(vulnerability),
                    remediation="Upgrade or replace the affected dependency after validating compatibility.",
                    references=tuple(references),
                    evidence=str(dependency.get("packages") or dependency.get("filePath") or package),
                )
            )
    return findings


def parse_zap(path: Path) -> list[Finding]:
    """Parse ZAP baseline JSON output, preserving endpoint evidence for human triage."""
    report = _load(path)
    findings: list[Finding] = []
    risk_by_code = {"3": Severity.HIGH, "2": Severity.MEDIUM, "1": Severity.LOW, "0": Severity.INFO}
    for site in report.get("site", []):
        if not isinstance(site, dict):
            continue
        for alert in site.get("alerts", []):
            if not isinstance(alert, dict):
                continue
            instances = alert.get("instances") if isinstance(alert.get("instances"), list) else []
            instance = instances[0] if instances and isinstance(instances[0], dict) else {}
            risk = risk_by_code.get(str(alert.get("riskcode", "")), _severity(alert.get("riskdesc")))
            cwe_value = alert.get("cweid")
            cwes = (f"CWE-{cwe_value}",) if str(cwe_value).isdigit() and str(cwe_value) != "0" else ()
            findings.append(
                Finding(
                    source=Source.DAST,
                    scanner_id=str(alert.get("pluginid") or alert.get("alertRef") or "zap.unknown"),
                    title=str(alert.get("alert", "ZAP alert")),
                    severity=risk,
                    description=str(alert.get("desc", "")),
                    location=Location(
                        resource=str(instance.get("uri") or site.get("@name") or "web target"),
                        method=str(instance.get("method")) if instance.get("method") else None,
                    ),
                    cwes=cwes,
                    remediation=str(alert.get("solution", "")),
                    references=_strings(alert.get("reference")),
                    evidence=str(instance.get("evidence", "")),
                )
            )
    return findings


def parse_reports(
    semgrep: Path | None = None,
    dependency_check: Path | None = None,
    zap: Path | None = None,
) -> list[Finding]:
    """Load any supplied scanner reports into one normalized finding list."""
    parsed: list[Finding] = []
    for report, parser in ((semgrep, parse_semgrep), (dependency_check, parse_dependency_check), (zap, parse_zap)):
        if report is not None:
            parsed.extend(parser(report))
    return parsed
