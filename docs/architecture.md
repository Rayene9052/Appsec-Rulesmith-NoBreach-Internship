# Architecture

## 1. Purpose of This Document

This document defines the technical architecture of NoBreach AppSec Rulesmith. It serves as the comprehensive architectural reference for the entire platform, outlining component boundaries, data flow, rule formats, and design principles.

---

## 2. High-Level Architecture

```text
                         ┌────────────────────────────────────────┐
                         │       Docker Compose Environment       │
                         │  - vulnerable-api (Port 8080)          │
                         │  - secure-api (Port 8081)              │
                         │  - internal-service (HTTPBin)          │
                         │  - dashboard (Port 5050)               │
                         └───────────────────┬────────────────────┘
                                             │ HTTP / Volume Mounts
                     ┌───────────────────────┴───────────────────────┐
                     │                                               │
            ┌────────▼────────┐                            ┌─────────▼────────┐
            │ DAST Rule Engine│                            │  SAST Rule Pack  │
            │ (dast/*.py)     │                            │ (rules/sast/*)   │
            │ 14 YAML Rules   │                            │ 3 Semgrep Rules  │
            └────────┬────────┘                            └─────────┬────────┘
                     │                                               │
                     └───────────────────────┬───────────────────────┘
                                             │
                                 ┌───────────▼────────────┐
                                 │   Evidence Collector   │
                                 │ (dast/evidence_        │
                                 │  collector.py)         │
                                 └───────────┬────────────┘
                                             │
                                 ┌───────────▼────────────┐
                                 │  Normalizer & Mapper   │
                                 │  (OWASP Top 10, OWASP  │
                                 │   API Top 10, CWE)     │
                                 └───────────┬────────────┘
                                             │
                    ┌────────────────────────┼────────────────────────┐
                    │                        │                        │
          ┌─────────▼───────┐      ┌─────────▼───────┐      ┌─────────▼────────┐
          │ Knowledge Base  │      │   Remediation   │      │ Report Generator │
          │(knowledge_base/)│      │   Validator     │      │ (reports/)       │
          │ KB, REC & Check │      │ (remediation/)  │      │ HTML + Markdown  │
          └─────────────────┘      └─────────┬───────┘      └─────────┬────────┘
                                             │                        │
                                 ┌───────────▼────────────────────────▼┐
                                 │     Interactive Web Dashboard       │
                                 │    (dashboard/ — Port 5050)         │
                                 │  Charts, Scan, Findings, Rem, Export│
                                 └─────────────────────────────────────┘
```

---

## 3. Component Responsibilities

### 3.1 Demo Applications (`apps/`)
- **`apps/vulnerable-api/`** — Flask application running on port **8080** intentionally exposing 14 curated vulnerability classes.
- **`apps/secure-api/`** — Hardened counterpart running on port **8081** implementing secure coding patterns for all 14 vulnerabilities.
- **`internal-service`** — Isolated HTTPBin container on the internal Docker network used for safe SSRF exploitation and verification.

### 3.2 DAST Rule Engine (`dast/`)
- `rule_engine.py` — Schema validator and YAML rule loader for `rules/dast/*.yml`.
- `runner.py` — HTTP test execution driver supporting indicator checks, status checks, header checks, and multipart file uploads.
- `auth.py` — Automated token management and multi-user login resolver for protected routes.
- `target_safety.py` — Safety guard enforcing that requests strictly target authorized local environments.
- `evidence_collector.py` — Records structured evidence and summary output.
- `normalizer.py` — Maps findings to OWASP Top 10, OWASP API Top 10, and CWE taxonomies.

### 3.3 SAST Rule Pack (`sast/`, `rules/sast/`)
- Custom Semgrep rules (`rules/sast/semgrep/*.yml`) scanning the source tree for dangerous patterns:
  - Hardcoded JWT secrets (`CWE-798`)
  - JWT algorithm 'none' acceptance (`CWE-347`)
  - Insecure Python Pickle deserialization (`CWE-502`)
- `sast/run_semgrep.py` normalizes static findings into the unified JSON finding schema.

### 3.4 Remediation Validator (`remediation/`)
- `remediation/validate.py` executes all DAST and SAST rules against both the vulnerable and secure targets.
- Performs differential analysis to produce verified Before-vs-After scorecards (`FIXED`, `OPEN`, `REGRESSION`) confirming a **100% remediation rate**.

### 3.5 Dynamic Report Generator (`reports/`)
- `reports/generator.py` compiles findings, metrics, and remediation evidence into publication-ready HTML and Markdown audit reports.

### 3.6 Interactive Web Dashboard (`dashboard/`)
- Central Flask application running on **port 5050**.
- Visualizes executive KPIs (Severity doughnut chart, OWASP radar chart).
- Features live scan triggers, an interactive findings inspector, before-vs-after status trackers, and 1-click report downloads.

---

## 4. Data Flow (Core Workflow)

1. **Deployment:** Target APIs and Dashboard start in Docker via `docker compose up -d`.
2. **DAST Execution:** The DAST engine runs 14 declarative YAML rules against `http://localhost:8080`, recording live HTTP response evidence.
3. **SAST Execution:** Semgrep executes custom static rules against the source repository, identifying code-level flaws.
4. **Normalization:** Findings from DAST and SAST are normalized into standard schema with CWE and OWASP mappings.
5. **Remediation Testing:** The validator re-executes all rules against `http://localhost:8081` and `apps/secure-api/` to verify mitigations.
6. **Reporting & UI:** The dashboard and dynamic report generator present verified findings, risk matrices, and remediation metrics.

---

## 5. Design Principles

- **Declarative Security Rules:** Security checks are defined as human-readable YAML files rather than hardcoded scripts.
- **Unified Finding Schema:** DAST and SAST findings share an identical schema so downstream reporting and dashboards operate seamlessly.
- **Strict Target Safety:** Automated safeguards prevent outbound testing against unauthorized hosts.
- **Verified Remediation:** A finding is only considered remediated when automated test re-execution confirms the flaw is blocked.

---

## 6. Progress & Milestone Summary

| Phase | Milestone |
|---|---|
| **Week 1** | Architecture, rule format specification, and taxonomy mapping |
| **Week 2** | Vulnerable API baseline implementation (blueprints & test fixtures) |
| **Week 3** | Custom DAST rule engine, automated auth manager & safety guards |
| **Week 4** | Advanced DAST rules (File Upload, XXE, Command Injection, Path Traversal, CORS) |
| **Week 5** | SAST rule pack (Semgrep rules & unified schema normalization) |
| **Week 6** | Remediated Secure API (`apps/secure-api/`) & differential validation engine |
| **Week 7** | AppSec Knowledge Base, recommendations, and developer checklist |
| **Week 8** | Interactive Web Dashboard, Dynamic Report Generator, and audit documentation |