# Rule Format (Draft)

Defines the schema for DAST rules (`rules/dast/*.yml`), SAST rule metadata
(`rules/sast/**`), and the evidence JSON both produce. This is a **draft** —
expect refinement once the engine is built in Week 3, but the shape below is
the baseline every rule should follow starting now.

## 1. DAST Rule Schema (YAML)

```yaml
id: NB-APPSEC-001                # unique, prefixed NB-APPSEC-<3 digits>
name: Missing Content-Security-Policy Header
category: Security Misconfiguration   # see docs/vulnerability-list.md categories
severity: Medium                 # Info | Low | Medium | High | Critical
method: GET
path: /
headers:                         # optional, request headers to send
  Accept: application/json
body: null                       # optional, request payload
check_type: header_absent        # response_indicator | status_code | header_present | header_absent | cookie_flag_missing
expected_indicator: "Content-Security-Policy"   # meaning depends on check_type
owasp: A05:2021
owasp_api: null
cwe: CWE-1021
recommendation: >
  Set a Content-Security-Policy header to reduce the impact of injected
  scripts and restrict allowed content sources.
```

### `check_type` values (Week 1 draft — extend as needed)

| check_type | meaning |
|---|---|
| `response_indicator` | Response body contains/lacks `expected_indicator` |
| `status_code` | Response status matches `expected_status` |
| `header_present` | A named response header exists |
| `header_absent` | A named response header is missing (e.g. security headers) |
| `cookie_flag_missing` | A named cookie lacks a flag (`Secure`, `HttpOnly`, `SameSite`) |

### Example: IDOR check (object-level authorization)

```yaml
id: NB-APPSEC-002
name: Broken Object Level Authorization on Order Endpoint
category: Access Control
severity: High
method: GET
path: /api/orders/{id}
auth: user_a_token               # authenticate as user A
check_type: response_indicator
expected_indicator: "user_b_order_id"  # requesting user B's order ID succeeds
owasp_api: API1:2023
cwe: CWE-639
recommendation: >
  Verify the authenticated user owns the requested object before returning
  it, instead of relying solely on a guessable/sequential ID.
```

## 2. SAST Rule Metadata Schema

SAST rules live in the native format of their tool (Semgrep YAML, Bandit
config, ESLint rule config), but every rule must carry this metadata block
so it normalizes the same way as a DAST finding:

```yaml
id: nb-jwt-alg-none-accepted
message: JWT verification accepts "alg: none" or does not pin an algorithm.
severity: ERROR               # INFO | WARNING | ERROR (mapped to Info–Critical downstream)
category: cryptographic-failures
owasp: A02:2021
cwe: CWE-347                  # Improper Verification of Cryptographic Signature
recommendation: Explicitly pin the accepted JWT algorithm(s) and reject "none".
```

## 3. Normalized Finding / Evidence Schema (JSON)

Both DAST and SAST results are converted to this shape before mapping,
remediation tracking, and reporting:

```json
{
  "rule_id": "NB-APPSEC-002",
  "source": "dast",
  "title": "Broken Object Level Authorization on Order Endpoint",
  "endpoint": "/api/orders/{id}",
  "method": "GET",
  "status_code": 200,
  "severity": "High",
  "category": "access-control",
  "owasp": null,
  "owasp_api": "API1:2023",
  "cwe": "CWE-639",
  "evidence": "User A retrieved User B's order by incrementing the order ID.",
  "recommendation": "Verify object ownership server-side before returning data.",
  "timestamp": "2026-07-13T10:00:00Z",
  "remediation_status": "open"
}
```

`source` is `"dast"` or `"sast"`. `remediation_status` starts as `"open"`
and moves to `"fixed"` or `"still_vulnerable"` once the remediation
validation workflow (Week 6) re-runs the rule against the secure version.

## 4. Naming Conventions

- DAST rule IDs: `NB-APPSEC-###` (3-digit, sequential).
- SAST rule IDs: `nb-<kebab-case-description>`.
- Rule filenames match their category: `rules/dast/access-control.yml`,
  `rules/dast/ssrf.yml`, `rules/dast/headers.yml`, etc. — multiple rules of
  the same category can live in one file as a YAML list.

## 5. Versioning

Each rule file should carry a top-level `version:` once the engine is live,
so historical scans can record which rule version produced a finding. Not
required for Week 1 drafts, but noted here so Week 3 doesn't skip it.

## 6. Open Items for Week 3

- Confirm whether `expected_status` needs to support ranges (e.g. `2xx`).
- Decide how the `auth` field in a rule (e.g. `auth: user_a_token`) maps to
  actual demo-app test accounts once the auth flow is built in Week 2.
- Decide whether multi-step rules (login → then check) are in scope for
  core, or deferred to Advanced scope.
