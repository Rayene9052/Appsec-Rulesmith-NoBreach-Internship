# DAST Engine (Week 3)

The custom dynamic testing engine that automates what was previously done
by hand with `curl` in Week 2. This document covers the module layout, how
a scan runs end to end, and how to add a new rule.

## Module Layout

| File | Responsibility |
|---|---|
| `dast/runner.py` | CLI entry point. Orchestrates a full scan run. |
| `dast/rule_engine.py` | Loads and validates `rules/dast/*.yml`. |
| `dast/auth.py` | Logs in as test accounts (`dast/accounts.yml`), caches tokens per run. |
| `dast/target_safety.py` | Enforces the local-only target allowlist from `docs/ethical-rules.md`. |
| `dast/normalizer.py` | Loads `mappings/*.yml`, attaches OWASP/CWE tags, builds the normalized finding. |
| `dast/evidence_collector.py` | Saves JSON results, prints the terminal summary. |
| `dast/accounts.yml` | Test account credentials for automatic login. |

## How a Scan Runs

1. `runner.py` validates the `--target` against the allowlist in
   `target_safety.py` before doing anything else — a target outside
   `localhost`/`127.0.0.1`/the Docker Compose service names is refused
   immediately.
2. `rule_engine.load_rules()` loads every `*.yml` file in `rules/dast/`
   and validates each rule's structure (required fields, valid
   `check_type`, valid `severity`, valid `method`).
3. For each rule, `runner.run_rule()`:
   - Resolves auth via `AuthManager.get_token()` if the rule declares
     `auth: <account_key>`. The first rule that needs a given account
     triggers a real login; every rule after that reuses the cached
     token.
   - Sends the HTTP request the rule describes.
   - Evaluates the response against the rule's `check_type`.
4. `normalizer.normalize()` turns the raw pass/fail result into the
   finding schema from `docs/rule-format.md`, attaching `owasp`,
   `owasp_api`, and `cwe` straight from the rule (the mapping files in
   `mappings/` are loaded so the normalizer can validate against them,
   and future report-generation code can look up category descriptions).
5. `evidence_collector.save_results()` writes all findings to
   `dast/results/scan_<timestamp>.json`.
6. `evidence_collector.print_summary()` prints a severity-sorted, ANSI-free
   readable summary to the terminal.

## Check Types Implemented

| check_type | Vulnerable when... |
|---|---|
| `response_indicator` | `expected_indicator` string is found in the response body |
| `status_code` | Response status does **not** match `expected_status` (used for rules where a specific status is the secure/expected outcome) |
| `header_present` | `expected_indicator` header is **missing** from the response |
| `header_absent` | `expected_indicator` header is **missing** from the response (used for hardening headers — same direction as above, kept as a distinct name per the schema in `docs/rule-format.md`) |
| `cookie_flag_missing` | Named cookie is present but missing `expected_flag` (defaults to `Secure`) |

## Current Rule Coverage (9 rules, 6 vulnerability classes)

| Rule ID | Vulnerability | File |
|---|---|---|
| NB-APPSEC-001 | IDOR | `rules/dast/access-control.yml` |
| NB-APPSEC-002 | Broken Access Control | `rules/dast/access-control.yml` |
| NB-APPSEC-003 | Mass Assignment | `rules/dast/mass-assignment.yml` |
| NB-APPSEC-004 | SSRF | `rules/dast/ssrf.yml` |
| NB-APPSEC-005 | NoSQL Injection | `rules/dast/nosql-injection.yml` |
| NB-APPSEC-006 | SSTI | `rules/dast/ssti.yml` |
| NB-APPSEC-007 | Missing CSP header | `rules/dast/headers.yml` |
| NB-APPSEC-008 | Missing HSTS header | `rules/dast/headers.yml` |
| NB-APPSEC-009 | Missing X-Content-Type-Options header | `rules/dast/headers.yml` |

Not yet covered by DAST (SAST-only or deferred to Week 4/5): Insecure JWT
Handling, Insecure File Upload, XXE, Insecure Deserialization. See
`docs/vulnerability-list.md` for the full detection-method breakdown.

## Verified Against a Live Target

This engine was run against the actual `apps/vulnerable-api/` Flask app
(outside Docker, direct `python app.py`) and correctly flagged 8 of 9
rules as vulnerable. The 9th (SSRF) correctly reported clean in that test
because `internal-service` wasn't running — when run against the real
`docker compose up -d` stack, that rule fires as vulnerable too, matching
the manual `curl` test from Week 2.

## Adding a New Rule

1. Pick or create a file in `rules/dast/` — group by category, e.g. a new
   injection rule can go in a new `rules/dast/injection.yml` or alongside
   an existing category file as a new list item.
2. Follow the schema in `docs/rule-format.md`. At minimum: `id`, `name`,
   `category`, `severity`, `method`, `path`, `check_type`, plus whatever
   `check_type` requires (`expected_indicator` or `expected_status`).
3. If the rule needs to be authenticated, add `auth: <account_key>` where
   `<account_key>` is a key in `dast/accounts.yml`.
4. Run `python dast/runner.py --rules rules/dast/ --target
   http://localhost:8080` — a malformed rule fails fast with a validation
   error naming the file and field.

## Known Limitations (Week 1 open items now resolved, new ones noted)

- `expected_status` does not yet support ranges (e.g. `2xx`) — every rule
  using `status_code` today checks an exact status.
- Multi-step rules (e.g. "log in, then chain three requests together")
  are not supported — every rule is a single request/response check.
  This was flagged as an open question in `docs/rule-format.md` and is
  still deferred; none of the current 9 rules need it.
- `cookie_flag_missing` is implemented but not yet used by any rule —
  no current vulnerability targets a cookie flag directly.
