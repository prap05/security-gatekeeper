# Security Gatekeeper

Security Gatekeeper is a Python-first AppSec pipeline that turns three noisy scanner reports into an actionable risk decision.

It demonstrates the exact workflow a security engineer follows in a real DevSecOps team:

```text
Semgrep (SAST) ─┐
Dependency-Check (SCA) ─┼─> normalize + deduplicate ─> CVSS + EPSS risk score
OWASP ZAP (DAST) ───────┘              │                         │
                                      evidence report       GitHub issue + CI gate
```

## Why this project matters

Most portfolio projects only run a scanner. This project handles the harder operational problems:

- Correlates overlapping findings conservatively and keeps source provenance.
- Combines CVSS impact with EPSS exploit probability, rather than treating every high-CVSS CVE equally.
- Produces JSON and Markdown evidence suitable for developers, risk review, or audit collection.
- Opens idempotent GitHub issues, using a stable fingerprint so repeat pipeline runs do not create duplicates.
- Fails CI only when a transparent, configurable risk policy is breached.
- Runs DAST only against a deliberately configured staging URL, never a production default.

## Architecture

| Layer | Tool / responsibility | Output |
|---|---|---|
| SAST | Semgrep Community Edition | Source-code patterns and CWE/OWASP context |
| SCA | OWASP Dependency-Check | Known vulnerable dependencies and CVSS |
| DAST | OWASP ZAP baseline | Passive web findings and endpoint evidence |
| Triage | Python standard library | Normalized, deduplicated finding records |
| Prioritization | CVSS + FIRST EPSS | A 0-100 explainable risk score |
| Workflow | GitHub Actions + REST API | Evidence artifact, issues, pass/fail gate |

## Risk policy

The score is deliberately explainable in an interview:

```text
risk = min(100, 0.65 × (CVSS × 10) + 0.30 × (EPSS × 100) + corroboration)
```

`corroboration` adds 5 points per independent source after the first, capped at 10. The default build threshold is **70/100**. The default issue threshold is **45/100**, so medium-risk items are tracked without automatically blocking delivery.

EPSS is fetched from FIRST's public API only for CVE-backed findings and cached in `.gatekeeper/epss-cache.json`. If the service is unavailable, the build stays deterministic: the finding is still scored from CVSS and source correlation.

## Quick start

Prerequisite: Python 3.12+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

Run the supplied safe report fixtures locally without calling EPSS:

```powershell
gatekeeper normalize `
  --semgrep tests/fixtures/semgrep.json `
  --dependency-check tests/fixtures/dependency-check.json `
  --zap tests/fixtures/zap.json `
  --offline

gatekeeper gate --report reports/gatekeeper.json --threshold 70
```

## GitHub Actions setup

The workflow is at [`.github/workflows/security-gatekeeper.yml`](.github/workflows/security-gatekeeper.yml). Push this repository to GitHub and enable Actions.

1. Create a non-production, authorized staging target, then set the repository variable `DAST_TARGET_URL`. Without it, ZAP is safely skipped.
2. Optionally configure an `NVD_API_KEY` in the Dependency-Check command for faster NVD updates on a real project.
3. Add the `security-gatekeeper` and `security` labels to the repository, or allow the workflow to create them.
4. Tune `RISK_THRESHOLD` and `ISSUE_THRESHOLD` to match the team’s risk appetite.
5. Before a production rollout, pin container images and third-party GitHub Actions to immutable digests/SHAs and manage updates with Dependabot or Renovate.

The workflow uploads `reports/` on every run. Issue creation is suppressed for forked pull requests, preventing untrusted PR code from receiving write-token privileges.

## Project structure

```text
security_gatekeeper/
  parsers.py          # Semgrep, Dependency-Check, and ZAP adapters
  triage.py           # correlation and risk policy
  epss.py             # cached FIRST EPSS client
  github_issues.py    # idempotent GitHub issue writer
  reporting.py        # JSON + Markdown evidence
  cli.py              # normalize and gate commands
tests/fixtures/       # safe scanner-output fixtures
.github/workflows/    # CI orchestration
docs/                 # interview and security-design notes
```

## Interview-ready explanation

Start with: “I built Security Gatekeeper because scanning alone creates noise. It orchestrates code, dependency, and web scanning, normalizes their output, and prioritizes the vulnerabilities most likely to matter.”

Then explain the lifecycle:

1. **Detect:** Semgrep checks code, Dependency-Check checks third-party components, and ZAP baselines a staging application.
2. **Triage:** Python adapters map each vendor format to one finding model. The correlator merges only shared CVEs or matching CWE/title plus resource, avoiding over-deduplication.
3. **Prioritize:** CVSS measures impact; EPSS estimates exploit likelihood. A verified result from more than one source is a useful corroboration signal.
4. **Remediate:** qualifying findings become idempotent GitHub issues with location, evidence, references, and remediation guidance.
5. **Prevent:** the quality gate blocks merges above the agreed risk threshold and retains evidence as a workflow artifact.

For likely interview questions and trade-offs, see [docs/interview-guide.md](docs/interview-guide.md).

## Responsible use

Use ZAP only against systems you own or have explicit permission to test. Configure a disposable staging environment; do not scan production from this sample pipeline.

## References

- [Semgrep CI configuration](https://semgrep.dev/docs/semgrep-ci/sample-ci-configs)
- [Semgrep Community Edition](https://semgrep.dev/products/community-edition/)
- [OWASP ZAP documentation](https://www.zaproxy.org/docs/)
- [FIRST EPSS API](https://www.first.org/epss/api)
- [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
