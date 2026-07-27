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

🚧 Week 4 — Advanced AppSec rules (next up)

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
all 9 rules, prints a severity-sorted summary to the terminal, and saves
full JSON results to `dast/results/`. See
[`docs/dast-engine.md`](docs/dast-engine.md) for how it works and how to
add new rules.

## Repository Layout

See [`docs/architecture.md`](docs/architecture.md) for the full breakdown of
each component and how the pieces fit together. Folders for the demo apps,
rule engine, and reports will be added as they're built, starting Week 2 —
this repo intentionally doesn't scaffold empty directories ahead of time.

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
