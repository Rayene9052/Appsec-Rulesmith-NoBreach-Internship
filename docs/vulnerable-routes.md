# Vulnerable Routes Reference

Documents every intentionally vulnerable endpoint in `apps/vulnerable-api/`
— the Week 2 deliverable. This is the reference the DAST rules (Week 3-4)
and knowledge base (Week 7) will be written against, so treat it as the
source of truth for exact request/response shape.

Base URL once running: `http://localhost:8080`

## Test accounts

| username | password | role |
|---|---|---|
| alice | alice123 | user |
| bob | bob123 | user |
| admin | admin123 | admin |

## 1. `POST /auth/login`

Issues a JWT. Not vulnerable by itself, but the token it issues is signed
with a hardcoded weak secret and the verifier (`auth_routes.decode_token`)
also accepts `alg: none`.

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "alice123"}'
```

**Vulnerability:** Insecure JWT Handling — `A02:2021` / `CWE-347`.

## 2. `GET /profile/<user_id>` — IDOR

Returns a user's profile. Checks that *a* valid token was sent, but never
checks that the token's `user_id` matches the requested `user_id`.

```bash
# Log in as alice (user_id 1), then request bob's profile (user_id 2)
curl http://localhost:8080/profile/2 -H "Authorization: Bearer <alice_token>"
```

**Vulnerability:** Broken Object Level Authorization (IDOR) — `API1:2023`
/ `A01:2021` / `CWE-639`.

## 3. `PUT /profile/<user_id>` — Mass Assignment

Updates a profile by merging the request body directly into the stored
record, with no allowlist of updatable fields.

```bash
curl -X PUT http://localhost:8080/profile/1 \
  -H "Authorization: Bearer <alice_token>" \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

**Vulnerability:** Mass Assignment / Broken Object Property Level
Authorization — `API3:2023` / `A01:2021` / `CWE-915`.

## 4. `GET /admin/users` — Broken Access Control

No authentication check at all — not even a missing/invalid-token check.

```bash
curl http://localhost:8080/admin/users
```

**Vulnerability:** Broken Access Control — `A01:2021` / `CWE-862`.

## 5. `POST /upload` — Insecure File Upload

No file type, content, or size validation, and the client-supplied
filename is trusted as-is.

```bash
curl -X POST http://localhost:8080/upload \
  -F "file=@malicious.py"
```

**Vulnerability:** Insecure File Upload — `A04:2021` / `CWE-434`.

## 6. `POST /search` — NoSQL Injection (simulated)

Evaluates the `username` filter as a Python expression rather than
comparing it as a literal string — analogous to an unsanitized MongoDB
`$where` clause.

```bash
curl -X POST http://localhost:8080/search \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"x' or True or 'x\"}"
```

This returns every user regardless of the actual username, because the
crafted string makes the evaluated expression `'x' or True or 'x' ==
username` short-circuit to a truthy value before `username` is ever
compared.

**Vulnerability:** NoSQL Injection — `A03:2021` / `CWE-943`.

## 7. `POST /webhook/preview` — SSRF

Fetches any URL supplied by the client with no allowlist. In this repo,
point it at the isolated `internal-service` container (see
`docker-compose.yml`) rather than any real address.

```bash
curl -X POST http://localhost:8080/webhook/preview \
  -H "Content-Type: application/json" \
  -d '{"url": "http://internal-service/get"}'
```

**Vulnerability:** Server-Side Request Forgery — `A10:2021` / `CWE-918`.

## 8. `POST /import` — Insecure Deserialization

Loads a base64-encoded pickle blob with `pickle.loads()`. Only ever send
test payloads generated locally against this demo app — pickle
deserialization can execute arbitrary code.

```bash
python3 -c "
import pickle, base64
print(base64.b64encode(pickle.dumps({'hello': 'world'})).decode())
" # then POST the output as {"data": "<output>"}
```

**Vulnerability:** Insecure Deserialization — `A08:2021` / `CWE-502`.

## 9. `POST /xml/parse` — XXE

Parses XML with entity resolution enabled.

```bash
curl -X POST http://localhost:8080/xml/parse \
  -H "Content-Type: application/xml" \
  --data-binary @sample-payloads/xxe-local-file.xml
```

**Vulnerability:** XML External Entity Injection — `A05:2021` / `CWE-611`.

## 10. `POST /render` — SSTI

Splices the `name` field into a Jinja2 template source string instead of
passing it as render data.

```bash
curl -X POST http://localhost:8080/render \
  -H "Content-Type: application/json" \
  -d '{"name": "{{ 7*7 }}"}'
```

**Vulnerability:** Server-Side Template Injection — `A03:2021` /
`CWE-1336`.

## 11. Missing / Misconfigured Security Headers (global)

Not a single route — every response from every endpoint, including
`GET /health`, lacks `Content-Security-Policy`, `Strict-Transport-Security`,
`X-Content-Type-Options`, and similar hardening headers. Verify with:

```bash
curl -I http://localhost:8080/health
```

**Vulnerability:** Missing / Misconfigured Security Headers — `A05:2021`
/ `CWE-1021`.

## Not yet wired to auth

`admin_routes.py` and `search_routes.py` don't check authentication at
all (that's the point of #4, and #6 doesn't require login by design).
Every other route above requires a valid `Authorization: Bearer <token>`
header from `/auth/login`, but — per vulnerability #1/#2 — a forged or
mismatched token still gets through.
