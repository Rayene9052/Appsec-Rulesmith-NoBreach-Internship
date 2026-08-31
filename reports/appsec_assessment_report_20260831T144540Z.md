# Application Security Assessment Report

---

**Organisation:** No Breach Training Hub
**Application:** NoBreach Demo API (nobreach-appsec-rulesmith)
**Assessment Type:** Automated DAST + SAST | Controlled Lab Environment
**Assessment Date:** 2026-08-31
**Assessor:** NoBreach AppSec Rulesmith Platform
**Report Version:** 2.0
**Classification:** Internal — Training Use Only

---

## Executive Summary

The NoBreach AppSec Rulesmith platform performed an automated application security
assessment of the intentionally vulnerable demo API (`apps/vulnerable-api/`).
The assessment combined dynamic testing (DAST) against a live Docker target and
static analysis (SAST) against the Python source code.

**14 distinct vulnerability classes** were detected across the demo application.
All findings were subsequently remediated in `apps/secure-api/` and validated by re-running
the full DAST and SAST rule sets, achieving a **100.0% remediation rate**.

### Finding Summary by Severity

| Severity | Count |
|---|---|
| Critical | 4 |
| High | 6 |
| Medium | 3 |
| Low | 1 |
| **Total** | **14** |

### OWASP Top 10 Coverage

| OWASP Category | Findings |
|---|---|
| A01:2021 | 4 |
| A03:2021 | 3 |
| A04:2021 | 1 |
| A05:2021 | 5 |
| A10:2021 | 1 |

---

## Assessment Methodology

1. **Dynamic Testing (DAST):** Declarative YAML rules loaded by `dast/runner.py` sent crafted HTTP requests to the live target API container (`http://localhost:8080`). Each rule checks a specific vulnerability class by evaluating response codes, headers, and body content.

2. **Static Analysis (SAST):** Semgrep rules from `rules/sast/semgrep/` were executed against the Python source tree (`apps/vulnerable-api/`) to detect insecure code patterns without running the application.

3. **Evidence Collection:** Every finding was recorded with its rule ID, title, endpoint, severity, HTTP evidence, CWE mapping, and remediation recommendation.

4. **Remediation Validation:** After security patches were applied to `apps/secure-api/`, the full rule set was re-executed against the secure target to confirm that vulnerabilities were verifiably eliminated rather than merely assumed fixed.

---

## Detailed Findings

### #1 — [CRITICAL] Broken Access Control on Admin Endpoint

- **Rule ID:** `NB-APPSEC-002`
- **Source:** DAST
- **Severity:** Critical
- **Target / Location:** `/admin/users`
- **CWE:** CWE-862
- **OWASP:** A01:2021

**Evidence:**
> Response contained "password", indicating the check condition was met.

**Remediation Recommendation:**
Require a valid admin-role token before returning this endpoint's data. Returning sensitive fields like passwords with no authentication at all is a critical finding.

---

### #2 — [CRITICAL] Server-Side Template Injection via Render Endpoint

- **Rule ID:** `NB-APPSEC-006`
- **Source:** DAST
- **Severity:** Critical
- **Target / Location:** `/render`
- **CWE:** CWE-1336
- **OWASP:** A03:2021

**Evidence:**
> Response contained "Hello, 49!", indicating the check condition was met.

**Remediation Recommendation:**
Never splice user input directly into template source. Pass user data in as template *context/data* instead, so it is rendered as a literal value rather than compiled as template syntax.

---

### #3 — [CRITICAL] XML External Entity Injection via XML Parser

- **Rule ID:** `NB-APPSEC-011`
- **Source:** DAST
- **Severity:** Critical
- **Target / Location:** `/xml/parse`
- **CWE:** CWE-611
- **OWASP:** A05:2021

**Evidence:**
> Response contained "PRETTY_NAME", indicating the check condition was met.

**Remediation Recommendation:**
Disable external entity resolution and external DTD loading in the XML parser configuration (e.g. resolve_entities=False in lxml, or use a hardened parser such as defusedxml), instead of trusting entity declarations found in client-supplied XML.

---

### #4 — [CRITICAL] OS Command Injection via System Ping Endpoint

- **Rule ID:** `NB-APPSEC-012`
- **Source:** DAST
- **Severity:** Critical
- **Target / Location:** `/system/ping`
- **CWE:** CWE-78
- **OWASP:** A03:2021

**Evidence:**
> Response contained "NB_CMD_INJECTION_SUCCESS", indicating the check condition was met.

**Remediation Recommendation:**
Never concatenate user input directly into shell commands or execute subprocesses with shell=True. Use parameterized APIs that accept arguments as a list, and validate inputs against a strict allowlist (e.g. valid IP addresses).

---

### #5 — [HIGH] Broken Object Level Authorization on Profile Endpoint (IDOR)

- **Rule ID:** `NB-APPSEC-001`
- **Source:** DAST
- **Severity:** High
- **Target / Location:** `/profile/2`
- **CWE:** CWE-639
- **OWASP:** A01:2021 | **API Top 10:** API1:2023

**Evidence:**
> Response contained "bob@example.com", indicating the check condition was met.

**Remediation Recommendation:**
Verify the authenticated user's ID matches the requested user_id before returning profile data, instead of only checking that a token is present and valid.

---

### #6 — [HIGH] Mass Assignment via Profile Update

- **Rule ID:** `NB-APPSEC-003`
- **Source:** DAST
- **Severity:** High
- **Target / Location:** `/profile/1`
- **CWE:** CWE-915
- **OWASP:** A01:2021 | **API Top 10:** API3:2023

**Evidence:**
> Response contained ""role": "admin"", indicating the check condition was met.

**Remediation Recommendation:**
Apply an explicit allowlist of fields a client is permitted to update (e.g. email, display name) instead of merging the entire request body into the stored record.

---

### #7 — [HIGH] Server-Side Request Forgery via Webhook Preview

- **Rule ID:** `NB-APPSEC-004`
- **Source:** DAST
- **Severity:** High
- **Target / Location:** `/webhook/preview`
- **CWE:** CWE-918
- **OWASP:** A10:2021

**Evidence:**
> Response contained "origin", indicating the check condition was met.

**Remediation Recommendation:**
Restrict outbound requests to an explicit allowlist of external hosts, block requests to private/internal IP ranges, and never let a client fully control the target URL of a server-side request.

---

### #8 — [HIGH] NoSQL Injection via Search Filter

- **Rule ID:** `NB-APPSEC-005`
- **Source:** DAST
- **Severity:** High
- **Target / Location:** `/search`
- **CWE:** CWE-943
- **OWASP:** A03:2021

**Evidence:**
> Response contained "admin@nobreach.local", indicating the check condition was met.

**Remediation Recommendation:**
Never evaluate user-controlled input as code or as part of a query expression. Compare filter values as literal strings, or use a parameterized query API if a real database is introduced.

---

### #9 — [HIGH] Insecure File Upload Accepts Arbitrary File Type

- **Rule ID:** `NB-APPSEC-010`
- **Source:** DAST
- **Severity:** High
- **Target / Location:** `/upload`
- **CWE:** CWE-434
- **OWASP:** A04:2021

**Evidence:**
> Response contained "saved_to", indicating the check condition was met.

**Remediation Recommendation:**
Enforce an explicit file extension and content-type allowlist, validate actual file content (magic bytes) rather than trusting the client-supplied filename or Content-Type header, and store uploads outside the web root with randomized, non-attacker-controlled filenames.

---

### #10 — [HIGH] Path Traversal via File Download Endpoint

- **Rule ID:** `NB-APPSEC-013`
- **Source:** DAST
- **Severity:** High
- **Target / Location:** `/files/download?filename=../../../../etc/passwd`
- **CWE:** CWE-22
- **OWASP:** A01:2021

**Evidence:**
> Response contained "root:", indicating the check condition was met.

**Remediation Recommendation:**
Strip directory traversal sequences using secure filename sanitization, resolve canonical absolute paths, and verify the resulting path is strictly confined within the intended root storage directory boundary.

---

### #11 — [MEDIUM] Missing Content-Security-Policy Header

- **Rule ID:** `NB-APPSEC-007`
- **Source:** DAST
- **Severity:** Medium
- **Target / Location:** `/health`
- **CWE:** CWE-1021
- **OWASP:** A05:2021

**Evidence:**
> Response is missing the "Content-Security-Policy" security header.

**Remediation Recommendation:**
Set a Content-Security-Policy header on all responses to reduce the impact of injected scripts and restrict allowed content sources.

---

### #12 — [MEDIUM] Missing Strict-Transport-Security Header

- **Rule ID:** `NB-APPSEC-008`
- **Source:** DAST
- **Severity:** Medium
- **Target / Location:** `/health`
- **CWE:** CWE-1021
- **OWASP:** A05:2021

**Evidence:**
> Response is missing the "Strict-Transport-Security" security header.

**Remediation Recommendation:**
Set a Strict-Transport-Security header to enforce HTTPS once the application is deployed behind TLS.

---

### #13 — [MEDIUM] Overly Permissive CORS with Dynamic Origin Reflection

- **Rule ID:** `NB-APPSEC-014`
- **Source:** DAST
- **Severity:** Medium
- **Target / Location:** `/cors/data`
- **CWE:** CWE-942
- **OWASP:** A05:2021 | **API Top 10:** API8:2023

**Evidence:**
> Header "Access-Control-Allow-Origin" contains "https://evil-attacker.com" (actual: "https://evil-attacker.com").

**Remediation Recommendation:**
Avoid dynamically reflecting untrusted Origin headers. Enforce an explicit allowlist of trusted origins, and avoid setting Access-Control-Allow-Credentials to true for untrusted or wildcard origins.

---

### #14 — [LOW] Missing X-Content-Type-Options Header

- **Rule ID:** `NB-APPSEC-009`
- **Source:** DAST
- **Severity:** Low
- **Target / Location:** `/health`
- **CWE:** CWE-1021
- **OWASP:** A05:2021

**Evidence:**
> Response is missing the "X-Content-Type-Options" security header.

**Remediation Recommendation:**
Set "X-Content-Type-Options: nosniff" on all responses to prevent browsers from MIME-sniffing responses away from their declared content type.

---

## Remediation Validation Summary

| # | Rule ID | Finding Title | Type | Status |
|---|---|---|---|---|
| 1 | `NB-APPSEC-001` | Broken Object Level Authorization on Profile Endpoint (IDOR) | DAST | ✅ Fixed |
| 2 | `NB-APPSEC-002` | Broken Access Control on Admin Endpoint | DAST | ✅ Fixed |
| 3 | `NB-APPSEC-003` | Mass Assignment via Profile Update | DAST | ✅ Fixed |
| 4 | `NB-APPSEC-004` | Server-Side Request Forgery via Webhook Preview | DAST | ✅ Fixed |
| 5 | `NB-APPSEC-005` | NoSQL Injection via Search Filter | DAST | ✅ Fixed |
| 6 | `NB-APPSEC-006` | Server-Side Template Injection via Render Endpoint | DAST | ✅ Fixed |
| 7 | `NB-APPSEC-007` | Missing Content-Security-Policy Header | DAST | ✅ Fixed |
| 8 | `NB-APPSEC-008` | Missing Strict-Transport-Security Header | DAST | ✅ Fixed |
| 9 | `NB-APPSEC-009` | Missing X-Content-Type-Options Header | DAST | ✅ Fixed |
| 10 | `NB-APPSEC-010` | Insecure File Upload Accepts Arbitrary File Type | DAST | ✅ Fixed |
| 11 | `NB-APPSEC-011` | XML External Entity Injection via XML Parser | DAST | ✅ Fixed |
| 12 | `NB-APPSEC-012` | OS Command Injection via System Ping Endpoint | DAST | ✅ Fixed |
| 13 | `NB-APPSEC-013` | Path Traversal via File Download Endpoint | DAST | ✅ Fixed |
| 14 | `NB-APPSEC-014` | Overly Permissive CORS with Dynamic Origin Reflection | DAST | ✅ Fixed |
| 15 | `nb-insecure-deserialization-pickle` | Semgrep SAST Rule | SAST | ✅ Fixed |
| 16 | `nb-jwt-alg-none-accepted` | Semgrep SAST Rule | SAST | ✅ Fixed |
| 17 | `nb-jwt-hardcoded-secret` | Semgrep SAST Rule | SAST | ✅ Fixed |

**Automated validation result: 17 / 17 rules confirmed fixed. Remediation rate: 100.0%.**

---

## Secure Coding Recommendations

1. **Input Validation & Sanitization:** Apply strict regex validation and type constraints on all parameters before use.
2. **Safe Execution APIs:** Never use `shell=True` or `eval()`. Use subprocess list arguments and parameterized queries.
3. **Path Traversal Defenses:** Sanitize filenames with `secure_filename()` and verify canonical paths remain within directory boundaries.
4. **Strict CORS Policies:** Avoid wildcard (`*`) or reflected `Origin` headers with credentials enabled. Use explicit allowlists.
5. **Defense-in-Depth Headers:** Deploy `Content-Security-Policy`, `Strict-Transport-Security`, and `X-Content-Type-Options: nosniff` on all API responses.

---

## References

- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/
- CWE Top 25 Most Dangerous Software Weaknesses: https://cwe.mitre.org/top25/
- NoBreach Knowledge Base: `knowledge_base/vulnerabilities.yml`

---

*This report was generated dynamically by the NoBreach AppSec Rulesmith platform.*
