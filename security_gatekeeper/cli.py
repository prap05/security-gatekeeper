"""Command line interface for producing evidence and enforcing security policy."""

from __future__ import annotations

import argparse
from pathlib import Path

from .epss import EpssClient
from .github_issues import GitHubConfig, GitHubIssues
from .parsers import parse_reports
from .reporting import read_json, write_json, write_markdown
from .triage import apply_risk_scores, deduplicate


def _path(value: str) -> Path:
    return Path(value).expanduser()


def _normalize(args: argparse.Namespace) -> int:
    findings = parse_reports(args.semgrep, args.dependency_check, args.zap)
    findings = deduplicate(findings)
    if not args.offline:
        EpssClient(args.cache).enrich(findings)
    findings = apply_risk_scores(findings)
    write_json(args.output, findings)
    write_markdown(args.markdown, findings, args.threshold)
    print(f"Normalized {len(findings)} findings -> {args.output}")
    return 0


def _gate(args: argparse.Namespace) -> int:
    findings = read_json(args.report)
    blocked = [finding for finding in findings if finding.risk_score >= args.threshold]
    if args.issue_mode == "create":
        created = GitHubIssues(GitHubConfig.from_environment()).create_for(
            findings, args.issue_threshold, dry_run=args.dry_run
        )
        print(f"GitHub issues {'would be ' if args.dry_run else ''}created: {created}")
    if blocked:
        print(f"FAIL: {len(blocked)} finding(s) meet or exceed {args.threshold:.1f}/100")
        for finding in blocked:
            print(f"  - {finding.risk_score:>5.1f} {finding.title} [{finding.fingerprint}]")
        return 1
    print(f"PASS: no findings meet or exceed {args.threshold:.1f}/100")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gatekeeper", description="Risk-based SAST + SCA + DAST finding triage."
    )
    commands = parser.add_subparsers(dest="command", required=True)

    normalize = commands.add_parser("normalize", help="Parse reports, correlate findings, and write evidence.")
    normalize.add_argument("--semgrep", type=_path, help="Semgrep JSON report")
    normalize.add_argument("--dependency-check", type=_path, help="Dependency-Check JSON report")
    normalize.add_argument("--zap", type=_path, help="ZAP baseline JSON report")
    normalize.add_argument("--output", type=_path, default=Path("reports/gatekeeper.json"))
    normalize.add_argument("--markdown", type=_path, default=Path("reports/gatekeeper.md"))
    normalize.add_argument("--cache", type=_path, default=Path(".gatekeeper/epss-cache.json"))
    normalize.add_argument("--threshold", type=float, default=70.0)
    normalize.add_argument("--offline", action="store_true", help="Do not call the public EPSS API.")
    normalize.set_defaults(handler=_normalize)

    gate = commands.add_parser("gate", help="Enforce the risk threshold and optionally create GitHub issues.")
    gate.add_argument("--report", type=_path, default=Path("reports/gatekeeper.json"))
    gate.add_argument("--threshold", type=float, default=70.0)
    gate.add_argument("--issue-mode", choices=("off", "create"), default="off")
    gate.add_argument("--issue-threshold", type=float, default=45.0)
    gate.add_argument("--dry-run", action="store_true", help="Preview issue creation without using GitHub.")
    gate.set_defaults(handler=_gate)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    raise SystemExit(args.handler(args))


if __name__ == "__main__":
    main()
