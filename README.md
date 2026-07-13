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

Eight curated, non-overlapping vulnerability classes — see
[`docs/vulnerability-list.md`](docs/vulnerability-list.md) for the full
rationale:

1. Broken Object Level Authorization (IDOR)
2. Broken Access Control (missing admin authorization)
3. Server-Side Request Forgery (SSRF)
4. Mass Assignment (Broken Object Property Level Authorization)
5. Insecure JWT Handling
6. NoSQL Injection
7. Insecure File Upload
8. Missing / Misconfigured Security Headers

🚧 Week 1 — Architecture & Rule Design (in progress)

## Quick Start

> Full instructions in [`docs/setup.md`](docs/setup.md). This section will
> be updated as the demo applications come online in Week 2.

```bash
git clone <repo-url>
cd nobreach-appsec-rulesmith
docker compose up -d
```

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
