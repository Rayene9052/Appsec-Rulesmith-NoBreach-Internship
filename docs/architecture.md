# Architecture

## 1. Purpose of This Document

This document defines the technical architecture of NoBreach AppSec
Rulesmith as designed in Week 1. It is the reference point for all
subsequent weeks — later work should extend this design rather than
improvise around it.

## 2. High-Level Architecture

```
                         ┌────────────────────────┐
                         │   Vulnerable Demo Apps  │
                         │  (Node/Express, Flask/  │
                         │  FastAPI)               │
                         └───────────┬─────────────┘
                                     │ HTTP
                     ┌───────────────┴───────────────┐
                     │                                │
            ┌────────▼────────┐             ┌─────────▼────────┐
            │  DAST Rule Engine │             │  SAST Rule Pack  │
            │  (dast/*.py)      │             │  (rules/sast/*)  │
            │  loads rules/dast │             │  Semgrep/Bandit/ │
            │  runs HTTP checks │             │  ESLint          │
            └────────┬──────────┘             └─────────┬────────┘
                     │                                    │
                     └───────────────┬────────────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  Evidence Collector      │
                         │  (dast/evidence_         │
                         │   collector.py)          │
                         └───────────┬──────────────┘
                                     │
                         ┌───────────▼────────────┐
                         │  Normalizer + Mapper     │
                         │  (OWASP Top 10, OWASP    │
                         │   API Top 10, CWE)       │
                         └───────────┬──────────────┘
                                     │
                    ┌────────────────┼─────────────────┐
                    │                │                  │
          ┌─────────▼───────┐ ┌──────▼───────┐ ┌────────▼────────┐
          │ Knowledge Base    │ │ Remediation   │ │ Report Generator │
          │ (knowledge_base/) │ │ Validation    │ │ (reports/)       │
          │                   │ │ (remediation/)│ │ md/html/json     │
          └───────────────────┘ └───────────────┘ └──────────────────┘
                                                            │
                                                  ┌─────────▼─────────┐
                                                  │ Optional Dashboard │
                                                  │ (dashboard/)       │
                                                  └────────────────────┘
```

## 3. Component Responsibilities

### 3.1 Vulnerable Demo Applications (`apps/`)
Local-only Docker services that intentionally implement the eleven
vulnerability classes defined in
[`docs/vulnerability-list.md`](vulnerability-list.md): IDOR, missing admin
authorization, mass assignment, SSRF, insecure JWT handling, NoSQL
injection, SSTI, insecure file upload, missing security headers, XXE, and
insecure deserialization. Each vulnerable feature gets a paired secure
implementation in `apps/secure-api/` from Week 6 onward, so the DAST
engine can run the same rule against both and prove the fix works.

### 3.2 DAST Rule Engine (`dast/`)
- `rule_engine.py` — loads and validates rule files from `rules/dast/*.yml`.
- `runner.py` — executes each rule as an HTTP request against a configured
  target (local demo app only) and captures the response.
- `evidence_collector.py` — turns a rule result into a structured evidence
  record (see evidence schema in `docs/rule-format.md`).
- `normalizer.py` — standardizes findings into one internal schema
  regardless of whether they came from DAST or SAST, so downstream reporting
  doesn't need to know the source.
- `results/` — raw JSON output per run, gitignored except for a checked-in
  sample.

Primary DAST targets: IDOR, missing admin authorization, SSRF, mass
assignment, missing headers, and (partially) NoSQL injection.

### 3.3 Rule Library (`rules/`)
- `rules/dast/*.yml` — dynamic check definitions (see rule format doc).
- `rules/sast/{semgrep,bandit,eslint}/` — static rule packs per tool.

Primary SAST targets: insecure JWT handling, insecure file upload
validation, and (partially) NoSQL injection query construction.

### 3.4 Mappings (`mappings/`)
Static YAML lookup tables (`owasp-top10.yml`, `owasp-api-top10.yml`,
`cwe.yml`) that the normalizer consults to attach a recognized security
category to every finding.

### 3.5 Knowledge Base & Remediation (`knowledge_base/`, `remediation/`)
Human-readable reference material and the before/after comparison workflow
that proves a fix closed a finding.

### 3.6 Reporting (`reports/`)
Generates the final technical AppSec assessment report from normalized
findings, in Markdown/HTML/JSON.

### 3.7 Optional Dashboard (`dashboard/`)
Stretch goal. A thin read-only view over the same JSON output the report
generator consumes — no new data model.

## 4. Data Flow (Core Workflow)

1. Demo app launched locally via `docker compose up -d`.
2. DAST rule engine loads `rules/dast/*.yml` and runs each rule against the
   target defined in its config.
3. Each rule result is passed to the evidence collector, producing a
   structured JSON evidence record.
4. SAST tools run separately against the source code and emit findings in
   the same normalized schema.
5. The normalizer merges DAST + SAST findings and attaches OWASP/CWE
   mapping.
6. Secure fix is applied in `apps/secure-api/`.
7. The same rule is re-run against the secure version; results are compared
   and the finding is marked fixed/still-vulnerable in `remediation/`.
8. The report generator turns the final finding set into a technical AppSec
   report.

## 5. Design Principles

- **Rules over one-off scripts.** Every check is a declarative rule file, not
  hardcoded logic, so No Breach can add checks later without touching the
  engine.
- **One normalized finding schema.** DAST and SAST findings converge on the
  same shape before reporting, so the report generator and dashboard don't
  need source-specific logic.
- **Local-only targets.** The engine's HTTP client only accepts targets that
  match an explicit local allowlist (`localhost`, `127.0.0.1`, or the
  Docker Compose service network) — see `docs/ethical-rules.md`. This is
  especially important for the SSRF rule, which by nature involves the demo
  app making outbound requests; those requests must also be constrained to
  the local network.
- **Reusability first.** Rules, mappings, and knowledge base entries are
  designed as standalone artifacts other No Breach engagements can import.
- **No empty scaffolding.** Directories (`apps/`, `dast/`, `rules/`, etc.)
  are created when the first real file lands in them, not pre-created as
  placeholders — keeps the repo honest about what's actually built.

## 6. Environments

| Environment | Purpose |
|---|---|
| Local Docker Compose | Runs vulnerable + secure demo apps for DAST |
| Local filesystem | Runs SAST tools against demo app source |
| CI (stretch goal, Week 8+) | Optional GitHub Actions run of SAST + DAST on PRs |


## 7. Progress by Week

| Week | Delivered |
|---|---|
| 1 | Architecture, rule format, vulnerability list, OWASP/CWE mapping |
| 2 | Vulnerable demo app, all 11 vulnerabilities implemented and manually verified |
| 3 | DAST engine + 9 rules across 7 vulnerabilities, verified against a live target |
| 4 | Multipart upload support added to the engine; 2 new DAST rules (file upload, XXE), bringing DAST coverage to 9 of 11 vulnerabilities |