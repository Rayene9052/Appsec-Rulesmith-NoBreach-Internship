# Remediation — Before / After Comparison

**Week 7 Deliverable** | No Breach Training Hub

This document provides a structured before-and-after comparison for each of the
11 vulnerabilities implemented and fixed in the NoBreach AppSec Rulesmith platform.
It is designed to be used in developer training sessions, code review walkthroughs,
and as supporting material for AppSec assessment reports.

The "After" column reflects the implementation in `apps/secure-api/`. Every fix
was validated by re-running the full DAST and SAST rule set against the secure
target and confirming 0 open findings (see `remediation/reports/` for timestamped
evidence).

---

## 1. Broken Object Level Authorization (IDOR)

| | Vulnerable (`apps/vulnerable-api/`) | Secure (`apps/secure-api/`) |
|---|---|---|
| **File** | `profile_routes.py` | `profile_routes.py` |
| **Root Cause** | Token presence checked; token identity never compared to requested `user_id` | Token decoded; `token["user_id"] == user_id` enforced before data is returned |
| **Attack** | Authenticated as user 1, request `GET /profile/2` → returns user 2's data | Same request → `{"error": "forbidden"}`, HTTP 403 |
| **DAST Rule** | NB-APPSEC-001: vulnerable (200, other user's data returned) | NB-APPSEC-001: clean (403 returned) |
| **Principle** | — | Verify ownership, not just authentication |

```python
# BEFORE — authenticates but never checks ownership
def get_profile(user_id):
    token = decode_token(...)  # valid token confirmed
    user = get_user(user_id)   # any user_id returned, no comparison
    return user

# AFTER — ownership enforced
def get_profile(user_id):
    token = decode_token(...)
    if token["user_id"] != user_id and token.get("role") != "admin":
        return {"error": "forbidden"}, 403
    return get_user(user_id)
```

---

## 2. Broken Access Control — Missing Admin Authorization

| | Vulnerable | Secure |
|---|---|---|
| **File** | `admin_routes.py` | `admin_routes.py` |
| **Root Cause** | No authentication check whatsoever on `/admin/users` | Requires valid token with `role == "admin"` |
| **Attack** | `curl /admin/users` (no token) → full user list returned, HTTP 200 | Same request → HTTP 401 |
| **DAST Rule** | NB-APPSEC-002: vulnerable | NB-APPSEC-002: clean |
| **Principle** | — | All privileged routes must authenticate and authorise |

```python
# BEFORE — no protection at all
@app.route("/admin/users")
def admin_users():
    return list_all_users()  # reachable by anyone

# AFTER — role check enforced
@app.route("/admin/users")
@require_auth(roles=["admin"])
def admin_users():
    return list_all_users()
```

---

## 3. Mass Assignment

| | Vulnerable | Secure |
|---|---|---|
| **File** | `profile_routes.py` | `profile_routes.py` |
| **Root Cause** | `user.update(request.get_json())` — entire body merged without filtering | `UPDATABLE_FIELDS = {"email"}` allowlist applied before any update |
| **Attack** | `PUT /profile/1` with `{"role": "admin"}` → role changed to admin | Same request → role unchanged, extra fields silently dropped |
| **DAST Rule** | NB-APPSEC-003: vulnerable | NB-APPSEC-003: clean |
| **Principle** | — | Explicit allowlist; deny-by-default for all other fields |

```python
# BEFORE — full body merged
user.update(request.get_json())

# AFTER — allowlist enforced
UPDATABLE_FIELDS = {"email"}
update = {k: v for k, v in body.items() if k in UPDATABLE_FIELDS}
user.update(update)
```

---

## 4. Server-Side Request Forgery (SSRF)

| | Vulnerable | Secure |
|---|---|---|
| **File** | `webhook_routes.py` | `webhook_routes.py` |
| **Root Cause** | `requests.get(url)` called with no destination validation | Scheme check + IP resolution + private-range rejection before any request |
| **Attack** | `POST /webhook/preview {"url": "http://internal-service/"}` → internal response returned | Same request → `{"error": "blocked: non-public address"}`, HTTP 400 |
| **DAST Rule** | NB-APPSEC-004: vulnerable | NB-APPSEC-004: clean |
| **Principle** | — | Resolve, validate, then request — never request then validate |

```python
# BEFORE — no validation
resp = requests.get(url)
return resp.text

# AFTER — full validation before fetch
blocked, reason = _is_blocked_target(url)
if blocked:
    return {"error": f"blocked: {reason}"}, 400
resp = requests.get(url, timeout=5)
return resp.text
```

---

## 5. Insecure JWT Handling

| | Vulnerable | Secure |
|---|---|---|
| **File** | `auth_routes.py` | `auth_routes.py` |
| **Root Cause** | Hardcoded secret `"secret123"`; `algorithms=["HS256", "none"]` accepted | Secret from env var or `secrets.token_hex(32)`; `algorithms=["HS256"]` only |
| **Attack (1)** | Forge token with `alg:none` → accepted and trusted | `alg:none` token → rejected by PyJWT, HTTP 401 |
| **Attack (2)** | Brute-force or source-read the secret → forge any token | Randomly generated secret; no literal in source |
| **SAST Rules** | `nb-jwt-alg-none-accepted`, `nb-jwt-hardcoded-secret`: flagged | Both rules: clean |
| **Principle** | — | Explicit algorithm list; secrets from environment |

```python
# BEFORE
SECRET = "secret123"
jwt.decode(token, SECRET, algorithms=["HS256", "none"])

# AFTER
SECRET = os.environ.get("JWT_SECRET") or secrets.token_hex(32)
jwt.decode(token, SECRET, algorithms=["HS256"])
```

---

## 6. NoSQL Injection (Simulated)

| | Vulnerable | Secure |
|---|---|---|
| **File** | `search_routes.py` | `search_routes.py` |
| **Root Cause** | `eval(f"'{filter}' == username", ...)` — user input embedded in executed expression | Plain string equality: `u["username"] == filter` |
| **Attack** | `{"username": "x' or True or 'x"}` → all users returned | Same payload → `[]` (no match, literal string comparison) |
| **DAST Rule** | NB-APPSEC-005: vulnerable | NB-APPSEC-005: clean |
| **Principle** | — | Eliminate eval(); use data comparisons, not code evaluation |

```python
# BEFORE — eval on user input
results = [u for u in USERS
           if eval(f"'{username_filter}' == username",
                   {"username": u["username"]})]

# AFTER — plain equality
if not isinstance(username_filter, str):
    return []
results = [u for u in USERS if u["username"] == username_filter]
```

---

## 7. Server-Side Template Injection (SSTI)

| | Vulnerable | Secure |
|---|---|---|
| **File** | `render_routes.py` | `render_routes.py` |
| **Root Cause** | `Template(f"Hello, {name}!")` — user value embedded in template source | `Template("Hello, {{ name }}!")` fixed; user input passed as render variable only |
| **Attack** | `{"name": "{{7*7}}"}` → response contains `"Hello, 49!"` | Same payload → `"Hello, {{7*7}}!"` (literal, not evaluated) |
| **DAST Rule** | NB-APPSEC-006: vulnerable | NB-APPSEC-006: clean |
| **Principle** | — | Template source is developer-controlled; data is user-controlled |

```python
# BEFORE — user input becomes template source
tmpl = Template(f"Hello, {name}!")
return tmpl.render()

# AFTER — fixed template, user input as data only
GREETING = Template("Hello, {{ name }}!")
return GREETING.render(name=name)
```

---

## 8. Insecure File Upload

| | Vulnerable | Secure |
|---|---|---|
| **File** | `upload_routes.py` | `upload_routes.py` |
| **Root Cause** | No extension check; client filename used as storage path; no size limit | Extension allowlist; UUID filename; 2 MB size cap |
| **Attack** | Upload `shell.php` → accepted, stored, potentially executable | Upload `shell.php` → HTTP 400, `"file type '.php' is not allowed"` |
| **DAST Rule** | NB-APPSEC-010: vulnerable | NB-APPSEC-010: clean |
| **Principle** | — | Reject, rename, limit — in that order |

```python
# BEFORE — accepts anything, trusts client filename
path = os.path.join(UPLOAD_DIR, file.filename)
file.save(path)

# AFTER — allowlist + UUID rename + size cap
ALLOWED = {".jpg", ".jpeg", ".png", ".pdf", ".txt"}
ext = os.path.splitext(file.filename)[1].lower()
if ext not in ALLOWED:
    return {"error": f"file type '{ext}' is not allowed"}, 400
data = file.read()
if len(data) > 2 * 1024 * 1024:
    return {"error": "file too large"}, 413
safe = f"{uuid.uuid4()}{ext}"
open(os.path.join(UPLOAD_DIR, safe), "wb").write(data)
```

---

## 9. Missing Security Headers

| | Vulnerable | Secure |
|---|---|---|
| **File** | `app.py` | `app.py` |
| **Root Cause** | No security headers set on any response | `@app.after_request` hook adds 4 headers to every response |
| **Attack Surface** | XSS, MIME sniffing, clickjacking, SSL stripping | Mitigated by browser enforcement of CSP, HSTS, nosniff, frame deny |
| **DAST Rules** | NB-APPSEC-007/008/009: all vulnerable | All three: clean |
| **Principle** | — | Centralised hook; all routes covered automatically |

```python
# BEFORE — no headers
# (nothing)

# AFTER — after_request hook
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response
```

---

## 10. XML External Entity Injection (XXE)

| | Vulnerable | Secure |
|---|---|---|
| **File** | `xml_routes.py` | `xml_routes.py` |
| **Root Cause** | `XMLParser(resolve_entities=True, no_network=False)` — external entities resolved | `XMLParser(resolve_entities=False)` — entities left as literal text |
| **Attack** | `<!ENTITY xxe SYSTEM "file:///etc/os-release">` + `&xxe;` → file contents in response | Same payload → `"&xxe;"` returned literally |
| **DAST Rule** | NB-APPSEC-011: vulnerable | NB-APPSEC-011: clean |
| **Principle** | — | Always construct XML parsers with entity resolution disabled |

```python
# BEFORE
parser = etree.XMLParser(resolve_entities=True, no_network=False)

# AFTER
parser = etree.XMLParser(resolve_entities=False)
```

---

## 11. Insecure Deserialization

| | Vulnerable | Secure |
|---|---|---|
| **File** | `import_routes.py` | `import_routes.py` |
| **Root Cause** | `pickle.loads(base64.b64decode(data))` — arbitrary code runs during deserialization | `json.loads(data)` — data-only format, no code execution |
| **Attack** | Pickle payload with `__reduce__` executing `os.system("id")` → RCE | Same payload fails JSON parsing, HTTP 400 returned |
| **SAST Rule** | `nb-insecure-deserialization-pickle`: flagged | Rule: clean |
| **Principle** | — | Never deserialise untrusted binary objects; use data-only formats |

```python
# BEFORE
import pickle, base64
obj = pickle.loads(base64.b64decode(body["data"]))

# AFTER
import json
obj = json.loads(body["data"])
if not isinstance(obj, dict):
    return {"error": "payload must be a JSON object"}, 400
```

---

## Summary Table

| # | Vulnerability | Rule(s) | Before Status | After Status | Fix Complexity |
|---|---|---|---|---|---|
| 1 | IDOR | NB-APPSEC-001 | Vulnerable | Fixed | Low |
| 2 | Broken Admin AuthZ | NB-APPSEC-002 | Vulnerable | Fixed | Low |
| 3 | Mass Assignment | NB-APPSEC-003 | Vulnerable | Fixed | Low |
| 4 | SSRF | NB-APPSEC-004 | Vulnerable | Fixed | Medium |
| 5 | Insecure JWT | nb-jwt-* (×2) | Vulnerable | Fixed | Low |
| 6 | NoSQL Injection | NB-APPSEC-005 | Vulnerable | Fixed | Low |
| 7 | SSTI | NB-APPSEC-006 | Vulnerable | Fixed | Low |
| 8 | Insecure File Upload | NB-APPSEC-010 | Vulnerable | Fixed | Low |
| 9 | Missing Headers | NB-APPSEC-007/008/009 | Vulnerable | Fixed | Low |
| 10 | XXE | NB-APPSEC-011 | Vulnerable | Fixed | Low |
| 11 | Insecure Deserialization | nb-insecure-deserialization-pickle | Vulnerable | Fixed | Low |

**Remediation rate: 14 / 14 rules confirmed fixed (100%)**
See `remediation/reports/` for automated validation evidence.
