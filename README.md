# NoBreach AppSec Rulesmith

Custom Application Security Testing Rules, Vulnerability Detection & Secure
Code Validation Platform — built as an 8-week internship project for the No
Breach Training Hub Cybersecurity Team.

## What This Is

A local, controlled AppSec platform that helps analysts move beyond generic
scanning by creating **reusable, explainable, testable** security detection
rules. It combines:

- Intentionally vulnerable demo web/API applications
- A custom DAST (dynamic) rule engine
- A custom SAST (static) rule pack
- Evidence collection for every finding
- OWASP Top 10 / OWASP API Top 10 / CWE mapping
- Secure fixes and a before/after remediation validation workflow
- A reusable knowledge base and developer security checklist
- A sample technical AppSec assessment report

## Vulnerability Focus

Eleven curated, non-overlapping vulnerability classes — see
[`docs/vulnerability-list.md`](docs/vulnerability-list.md) for the full
rationale:

1. Broken Object Level Authorization (IDOR)
2. Broken Access Control (missing admin authorization)
3. Mass Assignment (Broken Object Property Level Authorization)
4. Server-Side Request Forgery (SSRF)
5. Insecure JWT Handling
6. NoSQL Injection (simulated)
7. Server-Side Template Injection (SSTI)
8. Insecure File Upload
9. Missing / Misconfigured Security Headers
10. XML External Entity Injection (XXE)
11. Insecure Deserialization



## Status

✅ Week 1 — Architecture & Rule Design

✅ Week 2 — Vulnerable web & API demo application (11 routes implemented, verified)

✅ Week 3 — Custom DAST rule engine (9 rules across 6 vulnerability classes, verified)

✅ Week 4 — Advanced AppSec rules (2 new rules: file upload, XXE — DAST now covers 9/11 vulnerabilities)

✅ Week 5 — SAST rule pack (3 Semgrep rules, insecure JWT handling + insecure deserialization, verified)

✅ Week 6 — Secure fixes & remediation validation (all 11 vulnerabilities fixed in apps/secure-api/, 100% remediation rate confirmed)

✅ Week 7 — Knowledge base, developer checklist, OWASP/CWE mappings, before/after comparison, sample AppSec report

🚧 Week 8 — Final testing, documentation, demo (next up)

## Quick Start

```bash
git clone <repo-url>
cd Appsec-Rulesmith-NoBreach-Intenrship
docker compose up -d
curl http://localhost:8080/health
```

See [`docs/vulnerable-routes.md`](docs/vulnerable-routes.md) for every
endpoint and how to trigger each vulnerability, and
[`docs/setup.md`](docs/setup.md) for full setup instructions.

## Running the DAST Engine

```bash
python dast/runner.py --rules rules/dast/ --target http://localhost:8080
```

Logs in automatically as the test accounts declared by each rule, runs
all 11 rules (as of Week 4), prints a severity-sorted summary to the
terminal, and saves full JSON results to `dast/results/`. See
[`docs/dast-engine.md`](docs/dast-engine.md) for how it works and how to
add new rules.

## Running the SAST Rule Pack

```bash
python sast/run_semgrep.py --rules rules/sast/semgrep/ --target apps/vulnerable-api/
```

Runs Semgrep with the project's custom rules, normalizes each match into
the same finding schema the DAST engine produces, prints a summary, and
saves full JSON results to `sast/results/`. Covers the two vulnerabilities
DAST can't reach: insecure JWT handling and insecure deserialization. See
[`docs/sast-engine.md`](docs/sast-engine.md) for details.

## Running the Remediation Validator

```bash
python remediation/validate.py
```

Requires both `vulnerable-api` (port 8080) and `secure-api` (port 8081)
to be running. Re-runs every DAST and SAST rule against both, compares
results per rule, and reports which vulnerabilities are fixed, still
open, or regressed. See [`docs/secure-fixes.md`](docs/secure-fixes.md)
for what each fix does and why.

## Knowledge Base & Developer Resources

The `knowledge_base/` directory contains reusable AppSec documentation
built from the findings and evidence collected across Weeks 3–6:

- [`knowledge_base/vulnerabilities.yml`](knowledge_base/vulnerabilities.yml) — full KB entry for each of the 11 vulnerabilities: description, business/technical impact, detection logic, remediation steps, secure coding recommendation, and OWASP/CWE mapping
- [`knowledge_base/recommendations.yml`](knowledge_base/recommendations.yml) — reusable remediation patterns with wrong-vs-right Python code snippets for each vulnerability class
- [`knowledge_base/secure-coding-checklist.md`](knowledge_base/secure-coding-checklist.md) — 15-section pre-deployment checklist for developers and code reviewers

## Sample AppSec Report

A complete sample technical assessment report is available in both formats:

- [`reports/sample_appsec_report.md`](reports/sample_appsec_report.md) — Markdown version
- [`reports/sample_appsec_report.html`](reports/sample_appsec_report.html) — Styled HTML version, ready for client presentation

## Repository Layout

See [`docs/architecture.md`](docs/architecture.md) for the full breakdown of
each component and how the pieces fit together.

## Roadmap

| Week | Focus |
|------|-------|
| 1 | Architecture, rule design, repo scaffolding |
| 2 | Vulnerable web & API demo applications |
| 3 | Custom DAST rule engine |
| 4 | Advanced AppSec rules |
| 5 | SAST rule pack |
| 6 | Secure fixes & remediation validation |
| 7 | Knowledge base, checklist, sample report |
| 8 | Final testing, documentation, demo |

## License / Usage

Internal No Breach training project. Not for use against systems you do not
own or have explicit written authorization to test.
