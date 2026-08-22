# Setup Documentation

## 1. Prerequisites

- Docker & Docker Compose
- Python 3.11+
- Git

Both demo backends (`apps/vulnerable-api/`, `apps/secure-api/`) are
Flask (Python) — chosen because several target vulnerabilities (XXE,
SSTI, insecure deserialization) are Python-library-specific. No Node.js
or frontend component exists in this project.

## 2. Repository Setup

```bash
git clone <repo-url>
cd Appsec-Rulesmith-NoBreach-Intenrship
```

## 3. Python Environment (for DAST engine, SAST tooling, remediation validator)

```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

This installs `requests`, `pyyaml`, and `semgrep` — everything the DAST
engine, SAST rule pack, and remediation validator need. This is separate
from each app's own `requirements.txt` (Flask, PyJWT, lxml, Jinja2),
which is installed inside its own Docker container, not in this venv.

## 4. Running the Demo Applications

```bash
docker compose up -d
```

Brings up three containers:
- `vulnerable-api` — Flask, port **8080**
- `secure-api` — Flask, the Week 6 fixed counterpart, port **8081**
- `internal-service` — an isolated `httpbin` container, not published to
  the host, used as a safe local target for the SSRF demo route and its
  fix

```bash
curl http://localhost:8080/health
curl http://localhost:8081/health
```

## 5. Running the DAST Engine

```bash
python dast/runner.py --rules rules/dast/ --target http://localhost:8080
python dast/runner.py --rules rules/dast/ --target http://localhost:8081
```

Logs in automatically as the test accounts declared by each rule, runs
all 11 rules, prints a severity-sorted summary, and saves JSON to
`dast/results/`. Run against port 8080 (vulnerable) it should flag most
rules; run against port 8081 (secure) it should flag none. See
[`docs/dast-engine.md`](dast-engine.md).

## 6. Running the SAST Rule Pack

```bash
python sast/run_semgrep.py --rules rules/sast/semgrep/ --target apps/vulnerable-api/
python sast/run_semgrep.py --rules rules/sast/semgrep/ --target apps/secure-api/
```

Run against `apps/vulnerable-api/` this reports 3 findings; run against
`apps/secure-api/` it should report 0. See
[`docs/sast-engine.md`](sast-engine.md).

## 7. Running the Remediation Validator

```bash
python remediation/validate.py
```

Requires both `vulnerable-api` and `secure-api` to be running (step 4).
Re-runs every DAST and SAST rule against both targets, compares results
per-rule, prints a fixed/still-open/regression summary, and saves a full
JSON comparison to `remediation/reports/`. See
[`docs/secure-fixes.md`](secure-fixes.md) for what each fix does and
why.

## 8. Network / Target Safety

All tooling in this project must only target `localhost`/`127.0.0.1` or
the Docker Compose internal network. This applies to the DAST engine's
own requests, to the SSRF demo feature's outbound requests (and its
Week 6 fix, which blocks anything outside that boundary), and to the XXE
demo feature's external entity resolution. See
[`docs/ethical-rules.md`](ethical-rules.md) — the DAST engine validates
the target host against an allowlist before sending any request
(`dast/target_safety.py`).

## 9. Directory Reference

See [`docs/architecture.md`](architecture.md) for what each component is
responsible for.
