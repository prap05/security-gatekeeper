# Production hardening checklist

This project is intentionally runnable as a student portfolio. Before using it to enforce policy in a real organization, complete the following controls.

## CI supply chain

- Pin every GitHub Action to a full commit SHA and every scanner image to an immutable digest. Keep those pins current through Dependabot/Renovate and a reviewed update process.
- Protect the default branch and require review for workflow changes.
- Keep `GITHUB_TOKEN` permissions at the workflow minimum. Put issue creation in a separate, protected workflow if untrusted internal contributors can alter CI configuration.
- Use a GitHub App or fine-grained token only if the default token cannot provide the required scope.

## Scanning reliability

- Use an NVD API key and a persistent Dependency-Check data cache to avoid rate limits.
- Define a scanner-health SLO. The sample tolerates individual operational failures so it can still produce evidence; a production risk policy may require a failed mandatory scanner to block the release.
- Pin Semgrep rules, maintain organization-specific rules, and review false positives with an expiry date rather than permanent blanket exclusions.
- Produce and retain SBOMs (CycloneDX or SPDX) and add reachability analysis where tooling supports it.

## DAST safety

- Use a separately owned staging environment with synthetic data and a written authorization record.
- Configure authentication contexts, rate limits, allowed paths, and an explicit scope file. Baseline scans are passive; active scans need an additional change approval.
- Treat ZAP evidence as a lead for validation, not automatic proof of exploitability.

## Risk governance

- Add asset criticality, internet exposure, compensating controls, and remediation SLA to the risk decision.
- Map evidence to your control framework (for example NIST SSDF, ISO 27001, or SOC 2) and retain decisions in a risk register.
- Periodically review the `70` gate threshold against false-positive rate, incident learnings, and the organization’s risk appetite.
