# Security Gatekeeper: interview guide

## 30-second project pitch

“Security Gatekeeper is a Python DevSecOps pipeline that combines Semgrep for SAST, OWASP Dependency-Check for SCA, and OWASP ZAP baseline for DAST. Instead of treating every alert as equal, I normalize the reports, deduplicate only defensible overlaps, enrich CVEs with EPSS, calculate a transparent risk score, create idempotent GitHub issues, and fail the build when the team’s threshold is exceeded.”

## Questions I expect and how I would answer

### Why combine CVSS and EPSS?

CVSS expresses technical impact if a vulnerability is exploited; it does not predict whether attackers are likely to exploit it. EPSS is an exploit-probability estimate. Combining both helps the team prioritize a high-impact issue that is likely to be exploited ahead of an equally severe but less likely issue. EPSS is only one input—asset exposure, business criticality, and compensating controls belong in a mature risk process too.

### How do you avoid duplicate findings?

I use a conservative hierarchy. The strongest correlation is a shared CVE. If there is no CVE, I require the same CWE or normalized title **and** the same affected resource. I preserve the originating scanner IDs and all sources in the merged record. This reduces noise without incorrectly hiding separate vulnerabilities on different endpoints.

### Why does ZAP run only against staging?

Even baseline scans send traffic and could affect availability or logs. CI should have an explicit, authorized `DAST_TARGET_URL` variable pointing to a disposable staging environment. Production scanning needs its own approved change, authentication design, rate limit, and monitoring plan.

### What happens if a scanner or EPSS is unavailable?

The workflow preserves scanner artifacts and the pipeline still produces a report from successful tools. The EPSS client fails closed on enrichment—meaning it does not invent a value—and scores from CVSS plus corroboration. For a production program, I would separately alert on scanner health and define whether an unavailable mandatory control should fail closed.

### How is issue creation safe to rerun?

Every normalized finding receives a stable fingerprint. The GitHub issue body contains an invisible marker with that fingerprint. Before creating an issue, the client lists open Security Gatekeeper issues and skips an existing matching marker. This makes the integration idempotent.

### What would you add next?

I would add authenticated ZAP contexts, repository-specific Semgrep rules, lockfile-aware SCA, SBOM generation, a false-positive/suppression workflow with expiry dates, Slack/Teams notifications, and a risk register export that maps evidence to ISO 27001 or NIST controls.

## OWASP Top 10 mapping

| Project signal | Example OWASP concern | How the pipeline helps |
|---|---|---|
| Semgrep injection rules | Injection | Pinpoints code locations for review |
| Dependency CVEs | Vulnerable and outdated components | Finds risky third-party components |
| ZAP headers/cookies | Security misconfiguration | Tests a running staging service |
| Semgrep authz rules + ZAP endpoints | Broken access control | Supports guided review and dynamic validation |
| ZAP CSP / XSS alerts | Injection / XSS | Records endpoint evidence and remediation |

## Be honest about the boundaries

This is a triage and policy project, not a claim that scanners prove exploitability. A security engineer validates context, tests safely, documents evidence, agrees remediation with developers, and verifies the fix. That distinction demonstrates mature AppSec thinking.
