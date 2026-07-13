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
`requests`, `pyyaml`, `semgrep`, `bandit`, `pyjwt`, `lxml`, `jinja2`.

`lxml` and `jinja2` back the intentionally vulnerable XXE and SSTI demo
endpoints respectively — both are also used, configured securely, in
`apps/secure-api/` from Week 6 onward.

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

SAST is the primary detection method for insecure deserialization
(`pickle`/`yaml.load` usage) and one of two methods for XXE (parser
configuration), so `semgrep`/`bandit` runs matter for this project beyond
just style checks.

## 7. Network / Target Safety

All tooling in this project must only target `localhost`/`127.0.0.1` or the
Docker Compose internal network. This applies to the DAST engine's own
requests, to the SSRF demo feature's outbound requests, and to the XXE demo
feature's external entity resolution — the vulnerable XML parser must only
be able to reach local, sandboxed test files, never the real filesystem or
network.

## 8. Directory Reference

See [`docs/architecture.md`](architecture.md) for what each component is
responsible for. Directories for apps, the rule engine, and rules are added
as they're built starting Week 2, rather than pre-scaffolded now.