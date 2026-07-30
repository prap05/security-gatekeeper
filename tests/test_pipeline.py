from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from security_gatekeeper.models import Finding, Location, Severity, Source
from security_gatekeeper.parsers import parse_reports
from security_gatekeeper.reporting import read_json, write_json
from security_gatekeeper.triage import apply_risk_scores, deduplicate


FIXTURES = Path(__file__).parent / "fixtures"


class PipelineTests(unittest.TestCase):
    def test_parses_all_three_scanner_formats(self) -> None:
        findings = parse_reports(
            FIXTURES / "semgrep.json",
            FIXTURES / "dependency-check.json",
            FIXTURES / "zap.json",
        )
        self.assertEqual(len(findings), 3)
        self.assertEqual({finding.source for finding in findings}, {Source.SAST, Source.SCA, Source.DAST})
        self.assertIn("CVE-2021-33503", findings[1].cves)

    def test_cve_deduplication_preserves_source_provenance(self) -> None:
        first = Finding(
            source=Source.SCA,
            scanner_id="CVE-2025-0001",
            title="CVE-2025-0001 in demo-package",
            severity=Severity.HIGH,
            cves=("CVE-2025-0001",),
        )
        second = Finding(
            source=Source.SAST,
            scanner_id="custom.vulnerable.dependency",
            title="Known vulnerable dependency is used",
            severity=Severity.MEDIUM,
            cves=("CVE-2025-0001",),
        )
        merged = deduplicate([first, second])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].correlated_sources, {Source.SAST, Source.SCA})
        self.assertEqual(len(merged[0].related_ids), 2)

    def test_risk_formula_weights_exploit_probability_and_corroboration(self) -> None:
        finding = Finding(
            source=Source.SCA,
            scanner_id="CVE-2025-0001",
            title="Dependency CVE",
            severity=Severity.HIGH,
            cvss=8.0,
            epss=0.5,
            cves=("CVE-2025-0001",),
        )
        finding.correlated_sources.add(Source.DAST)
        scored = apply_risk_scores([finding])
        # 0.65 * 80 + 0.30 * 50 + 5 corroboration = 72
        self.assertEqual(scored[0].risk_score, 72.0)

    def test_normalized_report_round_trip(self) -> None:
        finding = Finding(
            source=Source.SAST,
            scanner_id="rule.id",
            title="Example",
            severity=Severity.MEDIUM,
            location=Location(resource="src/main.py", line=10),
            cwes=("CWE-79",),
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            report = Path(temp_dir) / "gatekeeper.json"
            write_json(report, apply_risk_scores([finding]))
            restored = read_json(report)
        self.assertEqual(restored[0].display_location, "src/main.py:10")
        self.assertEqual(restored[0].source, Source.SAST)


if __name__ == "__main__":
    unittest.main()
