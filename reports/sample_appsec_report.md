# Application Security Assessment Report

---

**Organisation:** No Breach Training Hub
**Application:** NoBreach Demo API (nobreach-appsec-rulesmith)
**Assessment Type:** Automated DAST + SAST | Controlled Lab Environment
**Assessment Date:** 2026-08-22
**Assessor:** NoBreach AppSec Rulesmith Platform
**Report Version:** 1.0
**Classification:** Internal — Training Use Only

---

## Executive Summary

The NoBreach AppSec Rulesmith platform performed an automated application security
assessment of the intentionally vulnerable demo API (`apps/vulnerable-api/`).
The assessment combined dynamic testing (DAST) against a live Docker target and
static analysis (SAST) against the Python source code.

**Eleven (11) distinct vulnerability classes** were detected across the demo application.
All 11 were subsequently remediated in `apps/secure-api/` and validated by re-running
the full DAST and SAST rule sets, achieving a **100% remediation rate**.

### Finding Summary by Severity

| Severity | Count |
|---|---|
| Critical | 4 |
| High | 5 |
| Medium | 2 |
| **Total** | **11** |

### OWASP Top 10 Coverage

| OWASP Category | Findings |
|---|---|
| A01:2021 Broken Access Control | 3 |
| A02:2021 Cryptographic Failures | 1 |
| A03:2021 Injection | 2 |
| A04:2021 Insecure Design | 1 |
| A05:2021 Security Misconfiguration | 2 |
| A08:2021 Software and Data Integrity Failures | 1 |
| A10:2021 SSRF | 1 |

---

## Assessment Methodology

The assessment followed the NoBreach AppSec Rulesmith workflow:

1. **Dynamic testing (DAST):** Custom YAML rules loaded by `dast/runner.py` sent crafted HTTP requests to the live vulnerable API container (`http://localhost:8080`). Each rule checks a specific vulnerability class by evaluating response codes, headers, and body content.

2. **Static analysis (SAST):** Semgrep rules from `rules/sast/semgrep/` were executed against the Python source tree (`apps/vulnerable-api/`) to detect insecure code patterns without running the application.

3. **Evidence collection:** Every finding was recorded with its rule ID, title, endpoint, severity, HTTP evidence, and recommendation.

4. **Remediation validation:** After fixes were applied to `apps/secure-api/`, the full rule set was re-run against the secure target. A finding is marked "Fixed" only when its rule produces no positive result against the secure version.

**Scope:** Local Docker Compose environment only. No external, client, or production systems were tested.

---

## Detailed Findings

---

### Finding 1 — Broken Object Level Authorization (IDOR)

| Field | Value |
|---|---|
| **Rule ID** | NB-APPSEC-001 |
| **Severity** | High |
| **Endpoint** | `GET /profile/<user_id>` |
| **OWASP Top 10** | A01:2021 — Broken Access Control |
| **OWASP API** | API1:2023 — Broken Object Level Authorization |
| **CWE** | CWE-639 |
| **Detection** | DAST |
| **Status** | Fixed |

**Description:**
The profile endpoint authenticated the caller but did not verify that the
authenticated identity matched the requested user ID. Any authenticated user
could retrieve any other user's profile by substituting a different ID in the URL.

**Evidence:**
```
Request:  GET /profile/2
          Authorization: Bearer <alice_token>
Response: 200 OK
          {"id": 2, "username": "bob", "email": "bob@example.com", "role": "user"}
```
Alice's token was used to successfully retrieve Bob's profile.

**Risk:**
Complete loss of data confidentiality for all user records. Attackers can enumerate
and exfiltrate all user data including email addresses, roles, and any sensitive
profile fields.

**Remediation:**
Enforce ownership check: compare `token["user_id"]` with the requested `user_id`
before serving data. Grant access only to the owner or an admin role.

```python
# Secure implementation
if token["user_id"] != user_id and token.get("role") != "admin":
    return {"error": "forbidden"}, 403
```

---

### Finding 2 — Broken Access Control (Missing Admin Authorization)

| Field | Value |
|---|---|
| **Rule ID** | NB-APPSEC-002 |
| **Severity** | Critical |
| **Endpoint** | `GET /admin/users` |
| **OWASP Top 10** | A01:2021 — Broken Access Control |
| **OWASP API** | API5:2023 — Broken Function Level Authorization |
| **CWE** | CWE-862 |
| **Detection** | DAST |
| **Status** | Fixed |

**Description:**
The admin endpoint listing all user accounts had no authentication or
authorisation check. Any unauthenticated HTTP client that discovered the URL
received a full dump of all user records.

**Evidence:**
```
Request:  GET /admin/users
          (no Authorization header)
Response: 200 OK
          [{"id":1,"username":"alice","role":"user"}, {"id":2,"username":"bob",...}]
```

**Risk:**
Complete exposure of all user data without any credentials. An attacker can
harvest all usernames, emails, and role assignments in a single unauthenticated request.

**Remediation:**
Require a valid token with `role == "admin"` before returning any data.
Apply the check at the blueprint level so future admin routes inherit it automatically.

---

### Finding 3 — Mass Assignment

| Field | Value |
|---|---|
| **Rule ID** | NB-APPSEC-003 |
| **Severity** | High |
| **Endpoint** | `PUT /profile/<user_id>` |
| **OWASP Top 10** | A01:2021 — Broken Access Control |
| **OWASP API** | API3:2023 — Broken Object Property Level Authorization |
| **CWE** | CWE-915 |
| **Detection** | DAST |
| **Status** | Fixed |

**Description:**
The profile update endpoint merged the entire request body into the stored user
object without filtering which fields are client-writable. Sending `{"role": "admin"}`
in the request body successfully elevated the caller's role to administrator.

**Evidence:**
```
Request:  PUT /profile/1
          Authorization: Bearer <alice_token>
          {"role": "admin"}
Response: 200 OK
          {"id":1,"username":"alice","role":"admin"}  ← role changed
```

**Risk:**
Any authenticated user can self-escalate to administrator, override billing status,
corrupt audit fields, or modify any other system-controlled attribute.

**Remediation:**
Define `UPDATABLE_FIELDS = {"email"}` and filter the request body before applying:
```python
update = {k: v for k, v in body.items() if k in UPDATABLE_FIELDS}
```

---

### Finding 4 — Server-Side Request Forgery (SSRF)

| Field | Value |
|---|---|
| **Rule ID** | NB-APPSEC-004 |
| **Severity** | High |
| **Endpoint** | `POST /webhook/preview` |
| **OWASP Top 10** | A10:2021 — SSRF |
| **OWASP API** | API7:2023 — SSRF |
| **CWE** | CWE-918 |
| **Detection** | DAST |
| **Status** | Fixed |

**Description:**
The webhook preview endpoint fetched any URL supplied by the client with no
destination validation. The Docker internal network was reachable, allowing the
attacker to reach the `internal-service` container and exfiltrate its content.

**Evidence:**
```
Request:  POST /webhook/preview
          {"url": "http://internal-service/"}
Response: 200 OK
          {"content": "<!DOCTYPE html>...httpbin/..."}  ← internal service response
```

**Risk:**
The server becomes a proxy to internal infrastructure. Attackers can reach cloud
metadata endpoints (169.254.169.254), internal databases, admin panels, or any
service visible from the server's network position — bypassing all firewall rules.

**Remediation:**
Validate scheme (https only), resolve hostname to IP, and reject RFC1918/loopback/
link-local addresses before making any outbound request.

---

### Finding 5 — Insecure JWT Handling

| Field | Value |
|---|---|
| **Rule ID** | nb-jwt-alg-none-accepted, nb-jwt-hardcoded-secret |
| **Severity** | Critical |
| **Location** | `apps/vulnerable-api/auth_routes.py` |
| **OWASP Top 10** | A02:2021 — Cryptographic Failures |
| **OWASP API** | API2:2023 — Broken Authentication |
| **CWE** | CWE-347, CWE-798 |
| **Detection** | SAST |
| **Status** | Fixed |

**Description (1 — alg:none):**
`jwt.decode()` was called with `algorithms=["HS256", "none"]`. The `none` algorithm
instructs PyJWT to skip signature verification entirely. An attacker can forge a
token with arbitrary claims and have it accepted without knowing the secret.

**Description (2 — hardcoded secret):**
The signing secret was hardcoded as the literal string `"secret123"`. Anyone with
access to the source code can sign arbitrary tokens, and the secret is committed
to version control.

**SAST Evidence:**
```
File: apps/vulnerable-api/auth_routes.py
Line 12: SECRET = "secret123"                          ← nb-jwt-hardcoded-secret
Line 31: jwt.decode(token, SECRET,
           algorithms=["HS256", "none"])               ← nb-jwt-alg-none-accepted
```

**Remediation:**
```python
SECRET = os.environ.get("JWT_SECRET") or secrets.token_hex(32)
jwt.decode(token, SECRET, algorithms=["HS256"])  # "none" removed
```

---

### Finding 6 — NoSQL Injection (Simulated)

| Field | Value |
|---|---|
| **Rule ID** | NB-APPSEC-005 |
| **Severity** | High |
| **Endpoint** | `POST /search` |
| **OWASP Top 10** | A03:2021 — Injection |
| **OWASP API** | API8:2023 — Security Misconfiguration |
| **CWE** | CWE-943 |
| **Detection** | DAST |
| **Status** | Fixed |

**Description:**
The search endpoint used Python's `eval()` to evaluate a dynamically constructed
expression that included unsanitised user input. An injection payload caused the
condition to always evaluate to `True`, returning all user records.

**Evidence:**
```
Request:  POST /search
          {"username": "x' or True or 'x"}
Response: 200 OK
          [{"id":1,"username":"alice",...}, {"id":2,"username":"bob",...}]
          ← all users returned, not zero
```

**Remediation:**
Remove `eval()` entirely. Use plain string equality: `u["username"] == filter`.

---

### Finding 7 — Server-Side Template Injection (SSTI)

| Field | Value |
|---|---|
| **Rule ID** | NB-APPSEC-006 |
| **Severity** | Critical |
| **Endpoint** | `POST /render` |
| **OWASP Top 10** | A03:2021 — Injection |
| **CWE** | CWE-1336 |
| **Detection** | DAST |
| **Status** | Fixed |

**Description:**
The render endpoint built the Jinja2 template source from an f-string containing
user input. Template syntax in the input was compiled and executed by the engine.
The standard Jinja2 sandbox escape chain can escalate this to full RCE.

**Evidence:**
```
Request:  POST /render
          {"name": "{{7*7}}"}
Response: 200 OK
          {"message": "Hello, 49!"}  ← expression evaluated
```

**Remediation:**
Use a fixed template literal and pass user input as render data only:
```python
TMPL = Template("Hello, {{ name }}!")
return TMPL.render(name=name)
```

---

### Finding 8 — Insecure File Upload

| Field | Value |
|---|---|
| **Rule ID** | NB-APPSEC-010 |
| **Severity** | High |
| **Endpoint** | `POST /upload` |
| **OWASP Top 10** | A04:2021 — Insecure Design |
| **CWE** | CWE-434 |
| **Detection** | DAST |
| **Status** | Fixed |

**Description:**
The upload endpoint accepted any file type, stored the client-supplied filename
directly (path traversal risk), and applied no size limit. Uploading a web shell
was accepted without restriction.

**Evidence:**
```
Request:  POST /upload  (multipart, file: shell.php, content: <?php system($_GET['cmd']); ?>)
Response: 200 OK
          {"filename": "shell.php", "size": 34}
```

**Remediation:**
Extension allowlist + UUID filename + 2 MB size cap.

---

### Finding 9 — Missing Security Headers

| Field | Value |
|---|---|
| **Rule IDs** | NB-APPSEC-007, NB-APPSEC-008, NB-APPSEC-009 |
| **Severity** | Medium |
| **Scope** | All endpoints |
| **OWASP Top 10** | A05:2021 — Security Misconfiguration |
| **CWE** | CWE-1021, CWE-693 |
| **Detection** | DAST |
| **Status** | Fixed |

**Description:**
Three security headers were absent from all responses: `Content-Security-Policy`,
`Strict-Transport-Security`, and `X-Content-Type-Options`. Their absence removes
browser-enforced protections against XSS, SSL stripping, and MIME-type sniffing.

**Evidence:**
```
GET /health HTTP/1.1
Response headers:
  Content-Type: application/json
  ← No Content-Security-Policy
  ← No Strict-Transport-Security
  ← No X-Content-Type-Options
```

**Remediation:**
Add a single `@app.after_request` hook setting all three headers.

---

### Finding 10 — XML External Entity Injection (XXE)

| Field | Value |
|---|---|
| **Rule ID** | NB-APPSEC-011 |
| **Severity** | High |
| **Endpoint** | `POST /xml/parse` |
| **OWASP Top 10** | A05:2021 — Security Misconfiguration |
| **CWE** | CWE-611 |
| **Detection** | DAST |
| **Status** | Fixed |

**Description:**
The XML parser was configured with `resolve_entities=True`, enabling external
entity references in submitted XML. A crafted `<!ENTITY>` declaration referencing
`file:///etc/os-release` caused the file's contents to appear in the parsed output.

**Evidence:**
```
Request:  POST /xml/parse
          <?xml version="1.0"?>
          <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/os-release">]>
          <root>&xxe;</root>
Response: 200 OK
          {"parsed_text": "NAME=\"Debian GNU/Linux\"\nVERSION_ID=\"12\"..."}
          ← file contents returned
```

**Remediation:**
```python
parser = etree.XMLParser(resolve_entities=False)
```

---

### Finding 11 — Insecure Deserialization

| Field | Value |
|---|---|
| **Rule ID** | nb-insecure-deserialization-pickle |
| **Severity** | Critical |
| **Location** | `apps/vulnerable-api/import_routes.py` |
| **OWASP Top 10** | A08:2021 — Software and Data Integrity Failures |
| **CWE** | CWE-502 |
| **Detection** | SAST |
| **Status** | Fixed |

**Description:**
The import endpoint decoded a base64 blob supplied by the client and passed it
directly to `pickle.loads()`. Python's pickle format executes arbitrary code during
deserialization. A crafted pickle payload reliably achieves remote code execution.

**SAST Evidence:**
```
File: apps/vulnerable-api/import_routes.py
Line 18: obj = pickle.loads(base64.b64decode(body["data"]))
         ← nb-insecure-deserialization-pickle
```

**Remediation:**
Replace `pickle.loads()` with `json.loads()`. JSON cannot execute code during parsing.

---

## Remediation Summary

| # | Finding | Severity | Rule(s) | Status |
|---|---|---|---|---|
| 1 | IDOR | High | NB-APPSEC-001 | ✅ Fixed |
| 2 | Missing Admin AuthZ | Critical | NB-APPSEC-002 | ✅ Fixed |
| 3 | Mass Assignment | High | NB-APPSEC-003 | ✅ Fixed |
| 4 | SSRF | High | NB-APPSEC-004 | ✅ Fixed |
| 5 | Insecure JWT | Critical | nb-jwt-* (×2) | ✅ Fixed |
| 6 | NoSQL Injection | High | NB-APPSEC-005 | ✅ Fixed |
| 7 | SSTI | Critical | NB-APPSEC-006 | ✅ Fixed |
| 8 | Insecure File Upload | High | NB-APPSEC-010 | ✅ Fixed |
| 9 | Missing Headers | Medium | NB-APPSEC-007/008/009 | ✅ Fixed |
| 10 | XXE | High | NB-APPSEC-011 | ✅ Fixed |
| 11 | Insecure Deserialization | Critical | nb-insecure-deserialization-pickle | ✅ Fixed |

**Automated validation result: 14 / 14 rules confirmed fixed. Remediation rate: 100%.**
*(Evidence in `remediation/reports/remediation_report_20260822T112239Z.json`)*

---

## Recommendations

### Immediate (pre-production)

1. **Authentication and authorization** — implement `require_auth()` as a decorator applied at blueprint level. No route should be less protected than the data it returns.
2. **JWT secrets** — inject via environment variable in every deployment. Rotate any secrets that were ever committed to version control.
3. **Insecure deserialization** — audit the entire codebase for `pickle.loads()` and `eval()` on untrusted data and replace before any external exposure.
4. **SSTI** — audit every `Template()` and `from_string()` call to confirm no user input reaches the template source.

### Short-term (next sprint)

5. **Security headers** — add the `@app.after_request` hook to all Flask applications in the organisation as a standard baseline.
6. **File upload** — enforce extension allowlist, UUID rename, and size cap on every upload endpoint.
7. **XML parsing** — standardise on `defusedxml` for all XML processing across the codebase.
8. **SSRF** — add a shared `validate_url()` utility function to the internal library so all outbound request code uses the same validated path.

### Ongoing

9. Run the NoBreach AppSec Rulesmith DAST and SAST rules in CI on every pull request to catch regressions.
10. Integrate `pip-audit` into the CI pipeline for dependency vulnerability scanning.
11. Review this checklist (`knowledge_base/secure-coding-checklist.md`) before every deployment.

---

## References

- OWASP Top 10 2021: https://owasp.org/Top10/
- OWASP API Security Top 10 2023: https://owasp.org/API-Security/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- CWE Top 25: https://cwe.mitre.org/top25/
- NoBreach Knowledge Base: `knowledge_base/vulnerabilities.yml`
- NoBreach Recommendations: `knowledge_base/recommendations.yml`
- NoBreach Developer Checklist: `knowledge_base/secure-coding-checklist.md`

---

*This report was generated by the NoBreach AppSec Rulesmith platform for training
and demonstration purposes. All testing was performed in a controlled, local
Docker Compose environment. No external, client, or production systems were tested
or affected.*
