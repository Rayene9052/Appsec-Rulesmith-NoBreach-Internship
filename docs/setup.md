# Setup Documentation

## 1. Prerequisites

- Docker & Docker Compose
- Python 3.11+
- Git

Both demo backends (`apps/vulnerable-api/`, `apps/secure-api/`) and the central Web Dashboard (`dashboard/`) are built with Python and Flask, providing a fully containerized, reproducible AppSec test environment.

---

## 2. Repository Setup

```bash
git clone <repo-url>
cd nobreach-appsec-rulesmith-AI
```

---

## 3. Python Environment (Optional for local CLI runs)

```bash
python -m venv .venv
# Linux / macOS:
source .venv/bin/activate
# Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

This installs `requests`, `pyyaml`, and `semgrep` — everything the local DAST engine, SAST rule pack, remediation validator, and dynamic report generator need.

---

## 4. Running the Full Platform (Docker Compose)

```bash
docker compose up -d --build
```

Brings up four services:
- **`nobreach-dashboard`** — Central Web Dashboard on **`http://localhost:5050`**
- **`nobreach-vulnerable-api`** — Intentionally vulnerable target API on **`http://localhost:8080`**
- **`nobreach-secure-api`** — Remediated secure counterpart API on **`http://localhost:8081`**
- **`nobreach-internal-service`** — Isolated `httpbin` service for SSRF testing

Verify health:
```bash
curl http://localhost:8080/health
curl http://localhost:8081/health
curl http://localhost:5050/
```

---

## 5. Web Dashboard Interface

Open your browser at **[http://localhost:5050](http://localhost:5050)** to access:
- **Executive Overview** (`/`): Charts & KPI metrics.
- **Scan Console** (`/scan`): 1-click live DAST/SAST scan execution against either target.
- **Findings Inspector** (`/findings`): Filterable vulnerability catalog with HTTP evidence.
- **Remediation Tracker** (`/remediation`): Before-vs-after status comparisons.
- **Rule Pack Browser** (`/rules`): Interactive catalog of all 14 DAST + 3 SAST rules.
- **Export Audit Reports**: Download live assessment reports in HTML or Markdown.

---

## 6. Running CLI Tools

### Running the DAST Rule Engine
```bash
# Scan vulnerable target (14 findings detected):
python dast/runner.py --rules rules/dast/ --target http://localhost:8080

# Scan secure target (0 findings detected - clean):
python dast/runner.py --rules rules/dast/ --target http://localhost:8081
```

### Running the SAST Rule Pack (Semgrep)
```bash
# Scan vulnerable source (3 findings detected):
python sast/run_semgrep.py --rules rules/sast/semgrep/ --target apps/vulnerable-api/

# Scan secure source (0 findings detected - clean):
python sast/run_semgrep.py --rules rules/sast/semgrep/ --target apps/secure-api/
```

### Running the Full Remediation Validator
```bash
python remediation/validate.py
```
*Compares DAST + SAST results across both targets, verifying a 100% remediation rate.*

### Generating Dynamic Assessment Reports
```bash
python reports/generator.py --format all
```
*Compiles the latest findings and remediation metrics into standalone HTML and Markdown reports in `reports/`.*
