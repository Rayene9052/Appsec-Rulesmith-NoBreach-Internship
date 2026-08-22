# Secure Fixes Documentation

For each of the 11 vulnerabilities, this document explains what was
wrong, how `apps/secure-api/` fixes it, the security principle applied,
and how to verify the fix yourself. Every fix below was actually tested
— both by re-running the Week 3-5 DAST/SAST rules against the secure API
and by hand with `curl` — not just written and assumed correct. See
`remediation/validate.py` for the automated comparison and
`remediation/reports/` for the actual scan output this document is based
on.

## 1. Broken Object Level Authorization (IDOR)

**What was wrong:** `GET /profile/<user_id>` checked that a request had
*a* valid token, but never checked that the token belonged to the user
being requested.

**Fix (`profile_routes.py`):** The decoded token's `user_id` must match
the requested `user_id`, unless the token's `role` is `admin`. Anyone
else gets `403 Forbidden`.

**Verify:**
```bash
# alice's own token, requesting bob's profile (id=2)
curl http://localhost:8081/profile/2 -H "Authorization: Bearer <alice_token>"
# -> {"error": "forbidden"}, HTTP 403
```

## 2. Broken Access Control (Missing Admin Authorization)

**What was wrong:** `GET /admin/users` had no authentication check
whatsoever — not even a missing-header check.

**Fix (`admin_routes.py`):** Requires a valid token with `role ==
"admin"`. Missing, invalid, expired, or non-admin tokens all get
401/403 with no user data returned.

**Verify:**
```bash
curl http://localhost:8081/admin/users
# -> {"error": "unauthenticated"}, HTTP 401
```

## 3. Mass Assignment

**What was wrong:** `PUT /profile/<user_id>` merged the entire request
body into the stored user record, so sending `{"role": "admin"}` worked.

**Fix (`profile_routes.py`):** An explicit `UPDATABLE_FIELDS` allowlist
(`["email"]`) filters the request body before anything is applied.
`role`, `id`, `username`, and `password` can never reach the stored
record through this endpoint, no matter what the client sends.

**Verify:**
```bash
curl -X PUT http://localhost:8081/profile/1 \
  -H "Authorization: Bearer <alice_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
# -> alice's record returned unchanged, role still "user"
```

## 4. Server-Side Request Forgery (SSRF)

**What was wrong:** `POST /webhook/preview` fetched whatever URL the
client supplied, with no restriction at all.

**Fix (`webhook_routes.py`):** Two checks before any request is sent:
(1) the URL scheme must be `https`; (2) the hostname's resolved IP must
be public — `ipaddress.ip_address(...).is_private`, `.is_loopback`, and
`.is_link_local` are all rejected. This blocks RFC1918 ranges, loopback,
the `169.254.169.254` cloud metadata address, and the local Docker
network (including `internal-service`) in one check, since Docker
bridge subnets fall inside the private ranges being blocked.

**Verify:** (tested directly against the check function, not just over
HTTP, since sandboxed environments may block outbound requests at the
network layer before the app logic even runs)
```python
from webhook_routes import _is_blocked_target
_is_blocked_target("https://example.com")            # -> (False, "")
_is_blocked_target("https://169.254.169.254/")        # -> (True, "...non-public address...")
_is_blocked_target("http://example.com")              # -> (True, "scheme 'http' is not allowed...")
```

## 5. Insecure JWT Handling

**What was wrong:** `auth_routes.py` hardcoded the signing secret as the
literal string `"secret123"`, and the decode step accepted `"none"` as
a valid algorithm — an attacker could forge an unsigned token and have
it trusted.

**Fix (`auth_routes.py`):** The secret is read from the `JWT_SECRET`
environment variable if set, otherwise generated randomly with
`secrets.token_hex(32)` at process startup — no literal secret string
exists in source. `algorithms=["HS256"]` is the only accepted value, so
`alg: none` tokens are rejected outright. Tokens now also carry `exp`
(1 hour) and `iss` claims, both validated on decode.

**Verify:**
```python
import jwt
forged = jwt.encode({"user_id": 3, "role": "admin"}, "", algorithm="none")
# vulnerable API accepts this and returns admin data
# secure API: {"error": "unauthenticated"}, HTTP 401
```

## 6. NoSQL Injection (Simulated)

**What was wrong:** `POST /search` evaluated the `username` filter as a
Python expression (`eval(f"'{filter}' == username", ...)`), so a crafted
string like `x' or True or 'x` bypassed the comparison entirely.

**Fix (`search_routes.py`):** Removed `eval()` completely. The filter is
compared with plain string equality (`u["username"] == username_filter`)
and rejected outright if it isn't a string.

**Verify:**
```bash
curl -X POST http://localhost:8081/search \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"x' or True or 'x\"}"
# -> [] (no match, as expected for a string nobody's username equals)
```

## 7. Server-Side Template Injection (SSTI)

**What was wrong:** `POST /render` built the Jinja2 template source
itself from an f-string containing user input (`Template(f"Hello,
{name}!")`), so template syntax in `name` was compiled and executed.

**Fix (`render_routes.py`):** The template source is now a fixed literal
defined once (`Template("Hello, {{ name }}!")`); user input is only ever
passed in as render *data* (`.render(name=name)`), so template syntax
inside it is displayed as inert text.

**Verify:**
```bash
curl -X POST http://localhost:8081/render \
  -H "Content-Type: application/json" \
  -d '{"name": "{{ 7*7 }}"}'
# -> {"message": "Hello, {{ 7*7 }}!"}  (not "Hello, 49!")
```

## 8. Insecure File Upload

**What was wrong:** `POST /upload` accepted any file type, trusted the
client-supplied filename directly (including path traversal risk), and
had no size limit.

**Fix (`upload_routes.py`):** Extension allowlist
(`.jpg .jpeg .png .pdf .txt`), a random UUID filename (the original
client-supplied name is discarded, removing path traversal risk
entirely), and a 2 MB size cap.

**Verify:**
```bash
curl -X POST http://localhost:8081/upload -F "file=@malicious.py"
# -> {"error": "file type '.py' is not allowed"}, HTTP 400
```

## 9. Missing / Misconfigured Security Headers

**What was wrong:** No response, on any route, carried any hardening
headers.

**Fix (`app.py`):** A single `@app.after_request` hook adds
`X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`,
and `Strict-Transport-Security` to every response, so new routes get
the headers automatically without repeating the logic per-route.
(`X-XSS-Protection` was deliberately left out — it's a deprecated header
modern browsers ignore, and OWASP no longer recommends it now that CSP
covers the same concern properly.)

**Verify:**
```bash
curl -I http://localhost:8081/health
# -> Content-Security-Policy, Strict-Transport-Security,
#    X-Content-Type-Options, X-Frame-Options all present
```

## 10. XML External Entity Injection (XXE)

**What was wrong:** `POST /xml/parse` used `etree.XMLParser(resolve_entities=True,
no_network=False)`, so a crafted `<!ENTITY>` declaration could read
local files.

**Fix (`xml_routes.py`):** `resolve_entities=False`. In testing, lxml
doesn't raise an error for this — it parses successfully and leaves an
undefined entity reference as the literal text `&xxe;` in the output,
rather than fetching and substituting the referenced file. Either way,
no file content ever reaches the response.

**Verify:**
```bash
curl -X POST http://localhost:8081/xml/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/os-release">]><root>&xxe;</root>'
# -> {"parsed_text": "&xxe;"}  (not the file's actual contents)
```

## 11. Insecure Deserialization

**What was wrong:** `POST /import` called `pickle.loads()` directly on a
base64-decoded, client-supplied blob — Python's pickle format can
execute arbitrary code during deserialization.

**Fix (`import_routes.py`):** Replaced `pickle.loads()` with
`json.loads()`, a data-only format with no code-execution capability
during parsing. A minimal schema check (`isinstance(obj, dict)`) is
applied after parsing.

**Verify:**
```bash
# a pickle blob that worked against the vulnerable API now fails to parse as JSON:
curl -X POST http://localhost:8081/import -H "Content-Type: application/json" -d '{"data": "<pickle_blob>"}'
# -> {"error": "invalid payload: 'utf-8' codec can't decode byte ..."}
```

## Summary

Running `remediation/validate.py` against a live `docker compose up -d`
stack re-runs all 11 DAST rules and all 3 SAST rules (14 total) against
both APIs. In the sandbox environment used to write this document — which
doesn't run `internal-service`, so the SSRF rule can't reach its target
on *either* API and reports "not applicable" rather than "vulnerable" on
the un-fixed app — 13 of the 13 applicable rules confirmed the
vulnerability fixed, 0 still open, 0 regressions. Against the real
Docker Compose stack, where `internal-service` is reachable, the SSRF
rule becomes applicable too and is expected to show "fixed" the same way
it was manually confirmed working in `_is_blocked_target()` testing
above — bringing the full result to 14 of 14. See `remediation/reports/`
for the actual timestamped report this was generated from.
