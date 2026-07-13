# Setup Documentation (Week 1)

This document covers environment setup for the project. It will be expanded
in Week 2 once the vulnerable demo applications exist.

## 1. Prerequisites

- Docker & Docker Compose
- Python 3.11+
- Node.js 20+
- Git

## 2. Repository Setup

```bash
git clone <repo-url>
cd nobreach-appsec-rulesmith
```

## 3. Python Environment (for DAST engine, SAST tooling)

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` will be populated starting Week 2 with, at minimum:
`requests`, `pyyaml`, `semgrep`, `bandit`, `pyjwt`.

## 4. Node Environment (for demo frontend / ESLint security rules)

```bash
cd apps/vulnerable-frontend
npm install
```

## 5. Running the Demo Applications

Not yet available — vulnerable demo apps are a Week 2 deliverable. Once
live, the expected command is:

```bash
docker compose up -d
```

This will bring up:
- `vulnerable-api` (Node/Express or Flask/FastAPI — decision pending, see
  `docs/architecture.md`)
- `secure-api` (patched counterpart, added incrementally from Week 6)

## 6. Running Rules (Week 3+ preview)

Once the DAST engine exists:

```bash
python dast/runner.py --rules rules/dast/ --target http://localhost:8080
```

Once SAST tooling is wired up:

```bash
semgrep --config rules/sast/semgrep/ apps/vulnerable-api/
bandit -r apps/vulnerable-api/ -c rules/sast/bandit/config.yml
```

## 7. Network / Target Safety

All tooling in this project must only target `localhost`/`127.0.0.1` or the
Docker Compose internal network. This applies both to the DAST engine's own
requests and to the SSRF demo feature's outbound requests. See
[`docs/ethical-rules.md`](ethical-rules.md) for the enforced policy — the
DAST engine will validate the target host against an allowlist before
sending any request (implemented Week 3).

## 8. Directory Reference

See [`docs/architecture.md`](architecture.md) for what each component is
responsible for. Directories for apps, the rule engine, and rules are added
as they're built starting Week 2, rather than pre-scaffolded now.
