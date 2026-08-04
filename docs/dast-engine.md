# DAST Engine

Custom dynamic testing engine that automates what was first done by hand
with `curl` in Week 2, extended in Week 4 with multipart request support.

## Module Layout

| File | Responsibility |
|---|---|
| `dast/runner.py` | CLI entry point. Orchestrates a full scan run; builds JSON, text, and (as of Week 4) multipart requests. |
| `dast/rule_engine.py` | Loads and validates `rules/dast/*.yml`. |
| `dast/auth.py` | Logs in as test accounts (`dast/accounts.yml`), caches tokens per run. |
| `dast/target_safety.py` | Enforces the local-only target allowlist. |
| `dast/normalizer.py` | Loads `mappings/*.yml`, attaches OWASP/CWE tags, builds the normalized finding. |
| `dast/evidence_collector.py` | Saves JSON results, prints the terminal summary. |
| `dast/accounts.yml` | Test account credentials for automatic login. |

## How a Scan Runs

1. `runner.py` validates `--target` against the allowlist before doing
   anything else.
2. `rule_engine.load_rules()` loads and validates every `*.yml` in
   `rules/dast/`.
3. For each rule, `runner.run_rule()` resolves auth if needed, builds the
   request (JSON body, raw text/XML body, or — new in Week 4 — a
   multipart file upload if the rule sets `multipart: true`), sends it,
   and evaluates the response against the rule's `check_type`.
4. `normalizer.normalize()` builds the standard finding, attaching
   `owasp`, `owasp_api`, `cwe` from the rule.
5. `evidence_collector.save_results()` writes all findings to
   `dast/results/scan_<timestamp>.json`.
6. `evidence_collector.print_summary()` prints a severity-sorted summary.

## Check Types

| check_type | Vulnerable when... |
|---|---|
| `response_indicator` | `expected_indicator` string is found in the response body |
| `status_code` | Response status does not match `expected_status` |
| `header_present` | `expected_indicator` header is missing |
| `header_absent` | `expected_indicator` header is missing (hardening headers) |
| `cookie_flag_missing` | Named cookie is present but missing `expected_flag` |

## Rule Coverage (11 rules, 9 vulnerability classes, as of Week 4)

| Rule ID | Vulnerability | File | Added |
|---|---|---|---|
| NB-APPSEC-001 | IDOR | `rules/dast/access-control.yml` | Week 3 |
| NB-APPSEC-002 | Broken Access Control | `rules/dast/access-control.yml` | Week 3 |
| NB-APPSEC-003 | Mass Assignment | `rules/dast/mass-assignment.yml` | Week 3 |
| NB-APPSEC-004 | SSRF | `rules/dast/ssrf.yml` | Week 3 |
| NB-APPSEC-005 | NoSQL Injection | `rules/dast/nosql-injection.yml` | Week 3 |
| NB-APPSEC-006 | SSTI | `rules/dast/ssti.yml` | Week 3 |
| NB-APPSEC-007 | Missing CSP header | `rules/dast/headers.yml` | Week 3 |
| NB-APPSEC-008 | Missing HSTS header | `rules/dast/headers.yml` | Week 3 |
| NB-APPSEC-009 | Missing X-Content-Type-Options header | `rules/dast/headers.yml` | Week 3 |
| NB-APPSEC-010 | Insecure File Upload | `rules/dast/file-upload.yml` | Week 4 |
| NB-APPSEC-011 | XXE | `rules/dast/xxe.yml` | Week 4 |

Not covered by DAST (SAST-only, Week 5): Insecure JWT Handling, Insecure
Deserialization.

## Week 4 Addition: Multipart File Upload Rules

The engine previously only sent JSON or raw-text bodies. NB-APPSEC-010
needed to send an actual `multipart/form-data` file upload, so
`runner.py` gained support for a new rule shape:

```yaml
multipart: true
file_field: file
file_name: malicious.py
file_content: "print('this should never be accepted')"
file_content_type: text/x-python
```

When `multipart` is set, `body` is ignored and the engine builds the
request with `requests`' `files=` parameter instead, letting `requests`
set its own multipart `Content-Type` boundary.

## Week 4 Addition: XXE Rule Design Note

NB-APPSEC-011 targets `/etc/os-release` rather than `/etc/hostname` (used
in the manual Week 2 test) and checks for the `PRETTY_NAME` key, which is
a standard field present in virtually every Linux distribution's
`os-release` file — this makes the rule portable across environments
(any Debian/Ubuntu/Alpine-based container) instead of depending on an
unpredictable per-container hostname string.

## Verified Against a Live Target

All 11 rules were tested against a running `apps/vulnerable-api/`
instance. In an environment without `internal-service` running (i.e.
outside the full `docker compose` stack), 10 of 11 rules correctly flag
vulnerable and the SSRF rule correctly reports clean, since its target
genuinely isn't reachable — this was also true in Week 3 testing and
confirmed not to be an engine bug. Against the real Docker Compose stack
(where `internal-service` is reachable), all 11 rules — including SSRF —
flag as vulnerable, matching every result already proven by hand.

## Known Limitations

- `expected_status` does not support ranges (e.g. `2xx`).
- Multi-step rules (e.g. chained requests) are not supported.
- `cookie_flag_missing` is implemented but not yet used by any rule.
