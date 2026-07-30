"""Idempotent GitHub Issue synchronization using the standard-library HTTP client."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from .models import Finding


@dataclass(frozen=True, slots=True)
class GitHubConfig:
    repository: str
    token: str

    @classmethod
    def from_environment(cls) -> "GitHubConfig":
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        token = os.environ.get("GITHUB_TOKEN", "")
        if not repository or not token:
            raise ValueError("GITHUB_REPOSITORY and GITHUB_TOKEN are required to create issues.")
        return cls(repository=repository, token=token)


class GitHubIssues:
    api_base = "https://api.github.com"
    label = "security-gatekeeper"

    def __init__(self, config: GitHubConfig) -> None:
        self.config = config

    def _request(self, method: str, endpoint: str, payload: dict[str, object] | None = None) -> object:
        data = json.dumps(payload).encode("utf-8") if payload else None
        request = Request(
            f"{self.api_base}{endpoint}",
            method=method,
            data=data,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.config.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Content-Type": "application/json",
            },
        )
        try:
            with urlopen(request, timeout=12) as response:  # nosec B310 - GitHub fixed HTTPS API
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API {method} {endpoint} failed: {exc.code} {detail}") from exc

    @staticmethod
    def marker(finding: Finding) -> str:
        return f"<!-- gatekeeper:fingerprint={finding.fingerprint} -->"

    def _existing_markers(self) -> set[str]:
        endpoint = f"/repos/{self.config.repository}/issues?state=open&labels={self.label}&per_page=100"
        issues = self._request("GET", endpoint)
        if not isinstance(issues, list):
            return set()
        return {self.marker_from_body(str(issue.get("body", ""))) for issue in issues if isinstance(issue, dict)} - {""}

    def _ensure_labels(self) -> None:
        """Create the two workflow labels once, if this repository does not have them."""
        endpoint = f"/repos/{self.config.repository}/labels?per_page=100"
        existing = self._request("GET", endpoint)
        labels = existing if isinstance(existing, list) else []
        names = {
            str(label.get("name", ""))
            for label in labels
            if isinstance(label, dict)
        }
        for name, color in ((self.label, "B60205"), ("security", "D93F0B")):
            if name not in names:
                self._request("POST", f"/repos/{self.config.repository}/labels", {"name": name, "color": color})

    @staticmethod
    def marker_from_body(body: str) -> str:
        prefix = "<!-- gatekeeper:fingerprint="
        start = body.find(prefix)
        end = body.find(" -->", start)
        return body[start : end + 4] if start >= 0 and end >= 0 else ""

    def _body(self, finding: Finding) -> str:
        sources = ", ".join(sorted(source.upper() for source in finding.correlated_sources))
        cves = ", ".join(finding.cves) or "None"
        cwes = ", ".join(finding.cwes) or "None"
        references = "\n".join(f"- {reference}" for reference in finding.references) or "- None provided"
        return "\n".join(
            [
                self.marker(finding),
                "## Security Gatekeeper finding",
                "",
                f"**Risk score:** {finding.risk_score:.1f}/100",
                f"**Sources:** {sources}",
                f"**Location:** `{finding.display_location}`",
                f"**CVEs:** {cves}",
                f"**CWEs:** {cwes}",
                "",
                "### Why this matters",
                finding.description or "Scanner-reported security issue requiring triage.",
                "",
                "### Recommended remediation",
                finding.remediation or "Validate the finding, remediate, and re-run the pipeline.",
                "",
                "### References",
                references,
                "",
                "_Created automatically by Security Gatekeeper. Close after remediation is verified._",
            ]
        )

    def create_for(self, findings: list[Finding], minimum_risk: float, dry_run: bool = False) -> int:
        """Create one issue per unique blocking finding; returns the number created."""
        eligible = [finding for finding in findings if finding.risk_score >= minimum_risk]
        if not dry_run:
            self._ensure_labels()
        existing = self._existing_markers() if not dry_run else set()
        created = 0
        for finding in eligible:
            if self.marker(finding) in existing:
                continue
            if not dry_run:
                title = f"[Security] {finding.title} ({finding.risk_score:.1f}/100)"
                self._request(
                    "POST",
                    f"/repos/{self.config.repository}/issues",
                    {"title": title[:240], "body": self._body(finding), "labels": [self.label, "security"]},
                )
            created += 1
        return created
