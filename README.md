# NoBreach AppSec Rulesmith

Custom Application Security Testing Rules, Vulnerability Detection, Automated Remediation Validation & Central AppSec Dashboard — built as an 8-week internship project for the No Breach Training Hub Cybersecurity Team.

---

## What This Is

A local, controlled AppSec platform that helps security analysts and developers move beyond black-box scanners by creating **reusable, explainable, and testable** detection rules. It combines:

- **Intentionally Vulnerable & Secure Demo APIs** (14 distinct vulnerability classes in Python/Flask)
- **Declarative DAST Rule Engine** (14 custom YAML rules evaluating HTTP response indicators, status codes, and security headers)
- **SAST Rule Pack** (3 Semgrep custom rules detecting dangerous code patterns and cryptographic flaws)
- **Differential Remediation Validator** (automated before-vs-after regression testing confirming a 100% fix rate)
- **Interactive Web Dashboard** (Executive charts, live scan launcher, findings inspector, and rule pack browser on port 5050)
- **Dynamic Security Assessment Report Generator** (automated HTML & Markdown audit reports with one-click export)
- **AppSec Knowledge Base & Developer Checklist** (CWE, OWASP Top 10, OWASP API Top 10 mappings, and remediation guides)

---

## Vulnerability Catalog (14 Classes)

Fourteen curated, non-overlapping vulnerability classes covering the OWASP Top 10 and OWASP API Security Top 10 — see [`docs/vulnerability-list.md`](docs/vulnerability-list.md) for full details:

1. **Broken Object Level Authorization (IDOR)** — `GET /profile/2` (`CWE-639` / `API1:2023`)
2. **Broken Access Control (Missing Admin Authorization)** — `GET /admin/users` (`CWE-862` / `A01:2021`)
3. **Mass Assignment (Broken Object Property Level Authorization)** — `PUT /profile/1` (`CWE-915` / `API3:2023`)
4. **Server-Side Request Forgery (SSRF)** — `POST /webhook/preview` (`CWE-918` / `A10:2021`)
5. **Insecure JWT Handling (Hardcoded Secret & Alg 'none')** — `POST /auth/login` (`CWE-798`, `CWE-347` / `A02:2021`)
6. **NoSQL Injection (Filter Expression Evaluation)** — `POST /search` (`CWE-943` / `A03:2021`)
7. **Server-Side Template Injection (SSTI)** — `POST /render` (`CWE-1336` / `A03:2021`)
8. **Insecure File Upload (Arbitrary Extension & Content-Type)** — `POST /upload` (`CWE-434` / `A04:2021`)
9. **Missing / Misconfigured Security Headers (CSP, HSTS, X-Content-Type)** — `GET /health` (`CWE-1021` / `A05:2021`)
10. **XML External Entity Injection (XXE)** — `POST /xml/parse` (`CWE-611` / `A05:2021`)
11. **Insecure Deserialization (Python Pickle RCE)** — `POST /import/contacts` (`CWE-502` / `A08:2021`)
12. **OS Command Injection** — `POST /system/ping` (`CWE-78` / `A03:2021`)
13. **Path / Directory Traversal** — `GET /files/download` (`CWE-22` / `A01:2021`)
14. **CORS Misconfiguration (Dynamic Origin Reflection)** — `GET /cors/data` (`CWE-942` / `A05:2021` / `API8:2023`)

---

## Architecture & Project Layout

```text
nobreach-appsec-rulesmith/
├── apps/
│   ├── vulnerable-api/       # Vulnerable target API (Port 8080)
│   ├── secure-api/           # Remediated secure target API (Port 8081)
│   └── internal-service/     # Internal HTTPBin service for SSRF testing
├── rules/
│   ├── dast/                 # 14 Declarative YAML DAST rules (NB-APPSEC-001..014)
│   └── sast/semgrep/         # 3 Custom Semgrep SAST rules
├── dast/                     # DAST Engine: runner, auth manager, normalizer, safety checks
├── sast/                     # SAST Engine: Semgrep execution & output normalization
├── remediation/              # Remediation validator & differential comparison reports
├── dashboard/                # Central Flask Web Dashboard (Port 5050)
├── reports/                  # Dynamic Report Generator & audit-ready HTML/MD reports
├── knowledge_base/           # KB entries, remediation patterns, and secure coding checklist
├── mappings/                 # CWE, OWASP Top 10 2021, and OWASP API 2023 taxonomy mappings
└── docs/                     # Architecture, route guides, rule format, and setup docs
```

---

## Quick Start with Docker

Start the full environment (Vulnerable API, Secure API, Internal Service, and Web Dashboard):

```bash
git clone <repo-url>
cd nobreach-appsec-rulesmith-AI
docker compose up -d --build
```

### Active Services:
- **Web Dashboard**: [http://localhost:5050](http://localhost:5050)
- **Vulnerable API**: `http://localhost:8080`
- **Secure API**: `http://localhost:8081`
- **Internal Service (SSRF Target)**: `http://internal-service:80` (Internal Docker network)

---

## Interactive Web Dashboard (`http://localhost:5050`)

The web dashboard provides an executive and operational interface for the platform:

- **Executive Overview (`/`)**: Severity breakdown doughnut chart, OWASP Top 10 radar coverage map, and key security KPIs.
- **Scan Console (`/scan`)**: Target switcher (`:8080` vs `:8081`) with real-time DAST and SAST scanning and animated results tables.
- **Findings Inspector (`/findings`)**: Interactive finding cards with severity/source filters, HTTP evidence viewer, and remediation guidance.
- **Remediation Tracker (`/remediation`)**: Live Before/After scorecard tracking all 17 detection checks with a 100% verification meter.
- **Rule Pack Browser (`/rules`)**: Catalog of all 14 DAST + 3 SAST rules with an embedded YAML syntax viewer.
- **1-Click Report Export**: Download fresh, styled HTML or Markdown assessment reports directly from the top navigation bar.

---

## Running CLI Tools

### 1. DAST Rule Engine
```bash
python dast/runner.py --rules rules/dast/ --target http://localhost:8080
```
*Dispatches 14 DAST rules against the target, handles automated JWT authentication for protected routes, records HTTP evidence, normalizes findings against OWASP/CWE mappings, and saves JSON output to `dast/results/`.*

### 2. SAST Rule Pack (Semgrep)
```bash
python sast/run_semgrep.py --rules rules/sast/semgrep/ --target apps/vulnerable-api/
```
*Executes custom Semgrep rules against the source tree, flags insecure patterns (hardcoded secrets, algorithmic flaws, unsafe pickle deserialization), and normalizes output to standard finding schema in `sast/results/`.*

### 3. Remediation Validator
```bash
python remediation/validate.py
```
*Performs differential testing across both live Docker targets and source repositories, producing a rule-by-rule status scorecard (`FIXED`, `OPEN`, `REGRESSION`) with a 100% verified remediation rate.*

### 4. Dynamic Report Generator
```bash
python reports/generator.py --format all
```
*Compiles the latest DAST, SAST, and Remediation results into standalone, printable HTML and Markdown assessment reports stored in `reports/`.*

---

## Knowledge Base & Developer Resources

- [`knowledge_base/vulnerabilities.yml`](knowledge_base/vulnerabilities.yml) — Technical descriptions, business impacts, detection mechanics, and taxonomy mappings for all 14 vulnerabilities.
- [`knowledge_base/recommendations.yml`](knowledge_base/recommendations.yml) — Reusable remediation patterns with before-and-after Python code snippets.
- [`knowledge_base/secure-coding-checklist.md`](knowledge_base/secure-coding-checklist.md) — 15-section secure development checklist for developers and code reviewers.
- [`reports/sample_appsec_report.html`](reports/sample_appsec_report.html) — Ready-to-present HTML technical security assessment report.

---

## Internship Roadmap Summary

| Phase | Description | Status |
|---|---|---|
| **Week 1** | Architecture, taxonomy mappings, and rule schema design | ✅ Complete |
| **Week 2** | Vulnerable API baseline implementation (blueprints & routes) | ✅ Complete |
| **Week 3** | Custom DAST rule engine, auth manager & safety guards | ✅ Complete |
| **Week 4** | Advanced DAST rules (File Upload, XXE, Command Injection, Path Traversal, CORS) | ✅ Complete |
| **Week 5** | SAST rule pack (Semgrep rules & unified schema normalization) | ✅ Complete |
| **Week 6** | Remediated Secure API (`apps/secure-api/`) & differential validation engine | ✅ Complete |
| **Week 7** | AppSec Knowledge Base, recommendations, and checklist | ✅ Complete |
| **Week 8** | Interactive Web Dashboard, Dynamic Report Generator & documentation | ✅ Complete |

---

## License & Usage

Developed as an internal training and demonstration platform for the **No Breach Training Hub Cybersecurity Team**. Designed for controlled lab environments and educational AppSec research.
