# NoBreach AppSec Rulesmith — Developer Security Checklist

**Version:** 1.0 | **Week 7 Deliverable** | **No Breach Training Hub**

Use this checklist before every deployment and during code review. Each item
links to the corresponding knowledge base entry (`knowledge_base/vulnerabilities.yml`)
and recommendation (`knowledge_base/recommendations.yml`) where applicable.

---

## 1. Authentication

- [ ] All state-changing endpoints require a valid, server-side-validated token or session.
- [ ] Tokens are validated with an explicit algorithm list — `algorithms=["HS256"]`; `alg:none` is rejected.
- [ ] JWT signing secrets are read from environment variables, not hardcoded in source code.
- [ ] Secrets are at least 256 bits of cryptographically random entropy (`secrets.token_hex(32)`).
- [ ] Tokens carry an `exp` claim and expiry is validated on every decode.
- [ ] Login endpoints implement rate limiting and account lockout after repeated failures.
- [ ] Passwords are hashed with bcrypt, argon2, or scrypt — never MD5, SHA-1, or unsalted SHA-256.
- [ ] Password reset tokens are single-use, short-lived, and tied to the requesting user.

**KB refs:** KB-005 | **Rec refs:** REC-011

---

## 2. Authorization

- [ ] Every resource endpoint verifies that the authenticated caller owns (or is permitted to access) the specific object — not just that *a* valid token is present.
- [ ] Admin-only routes enforce a role check in addition to authentication.
- [ ] Authorization middleware is applied at the route group / blueprint level, not ad-hoc per handler.
- [ ] Returning 403 Forbidden (not 404) when access is denied, to avoid leaking object existence.
- [ ] Write endpoints (PUT, PATCH, DELETE) apply the same ownership check as read endpoints.

**KB refs:** KB-001, KB-002 | **Rec refs:** REC-001, REC-003

---

## 3. Input Validation and Injection Prevention

- [ ] All user-supplied values are type-checked before use (reject integers where a string is expected, etc.).
- [ ] `eval()`, `exec()`, and `compile()` are not called with any data derived from user input.
- [ ] SQL queries use parameterised statements exclusively — no string concatenation into query templates.
- [ ] MongoDB/NoSQL queries validate that no `$`-prefixed operator keys appear in client-supplied filter objects.
- [ ] XML input is parsed with external entities disabled (`resolve_entities=False` or `defusedxml`).
- [ ] HTML output is escaped or rendered through a template engine with autoescape enabled.

**KB refs:** KB-006, KB-010 | **Rec refs:** REC-005, REC-009

---

## 4. Template and Rendering Security

- [ ] Template source strings are fixed literals — never built from user input via f-strings or concatenation.
- [ ] User input is passed only as render variables, never as part of the template source.
- [ ] Jinja2 / template engine autoescape is enabled for HTML output contexts.
- [ ] If user-editable templates are a product requirement, a sandboxed template environment is used.

**KB refs:** KB-007 | **Rec refs:** REC-006

---

## 5. Mass Assignment and Data Integrity

- [ ] Every write endpoint defines an explicit `UPDATABLE_FIELDS` allowlist.
- [ ] Request body is filtered through the allowlist before being applied to the stored object.
- [ ] `role`, `id`, `password`, `is_admin`, and all system fields are excluded from every write allowlist.
- [ ] Schema validation (pydantic, marshmallow, jsonschema) is applied to all incoming JSON bodies.

**KB refs:** KB-003 | **Rec refs:** REC-002

---

## 6. File Upload Security

- [ ] An explicit extension allowlist is enforced (`.jpg`, `.jpeg`, `.png`, `.pdf`, `.txt` or tighter).
- [ ] The client-supplied filename is discarded; a server-generated UUID is used as the storage filename.
- [ ] A maximum file size is enforced before writing to disk.
- [ ] Uploaded files are stored outside the web root or in object storage — not in a publicly-served directory.
- [ ] MIME type is verified against magic bytes (not just the `Content-Type` header or file extension) if the file type matters for processing.

**KB refs:** KB-008 | **Rec refs:** REC-007

---

## 7. Serialisation and Deserialization

- [ ] `pickle.loads()` is never called on client-supplied data.
- [ ] All data interchange with external clients uses a data-only format: JSON, TOML, or msgpack.
- [ ] A schema check (type assertions, required-key presence) is applied after deserialisation before any field is used.
- [ ] Internal pickle use (caching, ML models) is isolated from external-facing endpoints and payloads are HMAC-signed.

**KB refs:** KB-011 | **Rec refs:** REC-010

---

## 8. Request Forgery Prevention (SSRF)

- [ ] Any endpoint that makes outbound HTTP requests validates the target URL before sending.
- [ ] Only `https://` scheme is permitted; `http`, `file`, `ftp`, `gopher` are rejected.
- [ ] The target hostname is resolved to an IP and the IP is checked against RFC1918, loopback, and link-local ranges.
- [ ] Redirects are not followed automatically without re-validating the redirect destination.
- [ ] An egress allowlist (firewall rule or outbound proxy) is in place to complement the application-level check.

**KB refs:** KB-004 | **Rec refs:** REC-004

---

## 9. Security Headers

- [ ] `Content-Security-Policy` is set on all responses (minimum: `default-src 'self'`).
- [ ] `Strict-Transport-Security` is set with `max-age` ≥ 1 year once HTTPS is confirmed stable.
- [ ] `X-Content-Type-Options: nosniff` is set on all responses.
- [ ] `X-Frame-Options: DENY` is set (or CSP `frame-ancestors 'none'` for modern browsers).
- [ ] Headers are set in a single framework-level `after_request` hook, not per-route.
- [ ] `X-XSS-Protection` is NOT set (deprecated; CSP replaces it).
- [ ] `Server` and `X-Powered-By` response headers are suppressed to avoid information disclosure.

**KB refs:** KB-009 | **Rec refs:** REC-008

---

## 10. Session and Cookie Management

- [ ] Session cookies carry the `HttpOnly` flag (prevents JavaScript access).
- [ ] Session cookies carry the `Secure` flag (transmitted over HTTPS only).
- [ ] Session cookies carry `SameSite=Strict` or `SameSite=Lax` (mitigates CSRF).
- [ ] Session tokens are invalidated server-side on logout; client-side cookie deletion alone is not sufficient.
- [ ] Session IDs are regenerated after privilege escalation (e.g. after login).

---

## 11. API Security

- [ ] All API endpoints that accept data enforce a maximum request body size.
- [ ] Pagination and result-count limits are enforced on all list endpoints.
- [ ] API versioning is in place so breaking security changes can be deployed without affecting legacy consumers.
- [ ] Sensitive fields (`password_hash`, `secret`, internal IDs) are never included in API responses.
- [ ] Error responses use generic messages — they do not expose stack traces, file paths, or internal field names.

---

## 12. Secrets Management

- [ ] No secrets (API keys, passwords, JWT secrets, database credentials) appear in source code.
- [ ] No secrets are committed to version control — `.gitignore` covers all `.env` and config files.
- [ ] Secrets are injected via environment variables, a secrets manager (Vault, AWS Secrets Manager), or a CI/CD secrets store.
- [ ] Secrets are rotated after any suspected exposure.
- [ ] Logs do not contain secrets, tokens, or raw passwords.

**KB refs:** KB-005 | **Rec refs:** REC-011

---

## 13. Dependency and Supply Chain Security

- [ ] `requirements.txt` or `package.json` specifies pinned versions.
- [ ] A dependency scanner (pip-audit, npm audit, Dependabot) runs in CI on every pull request.
- [ ] Known-vulnerable transitive dependencies are tracked and updated promptly.
- [ ] Docker base images are pinned to digest hashes, not floating tags.
- [ ] Third-party packages are reviewed before introduction (check for typosquatting, abandoned maintainers).

---

## 14. Logging and Error Handling

- [ ] All authentication failures are logged with IP address and timestamp.
- [ ] All authorisation failures are logged.
- [ ] Logs do not contain passwords, tokens, PII, or secret values.
- [ ] Unhandled exceptions return a generic 500 response — stack traces are never sent to clients.
- [ ] A log aggregation and alerting system is in place to detect repeated failures.

---

## 15. Infrastructure and Configuration

- [ ] Debug mode is disabled in all production and staging environments.
- [ ] CORS is configured to an explicit allowlist of origins — `Access-Control-Allow-Origin: *` is not acceptable for APIs that handle credentials.
- [ ] TLS 1.2 is the minimum version; TLS 1.0 and 1.1 are disabled.
- [ ] Docker containers run as a non-root user.
- [ ] Container images are scanned for known CVEs in CI before deployment.
- [ ] Environment-specific configuration (development vs. production) is managed via environment variables, not code branches.

---

## Pre-Deployment Sign-Off

| Area | Reviewer | Status | Date |
|---|---|---|---|
| Authentication | | ☐ Pass / ☐ Fail | |
| Authorization | | ☐ Pass / ☐ Fail | |
| Input Validation | | ☐ Pass / ☐ Fail | |
| File Upload | | ☐ Pass / ☐ Fail | |
| Serialisation | | ☐ Pass / ☐ Fail | |
| Security Headers | | ☐ Pass / ☐ Fail | |
| Secrets Management | | ☐ Pass / ☐ Fail | |
| Dependencies | | ☐ Pass / ☐ Fail | |
| DAST Scan Passed | | ☐ Yes / ☐ No | |
| SAST Scan Passed | | ☐ Yes / ☐ No | |

---

*This checklist is a living document. Update it when new vulnerability classes are added to the NoBreach AppSec Rulesmith rule library.*

*Reference: `knowledge_base/vulnerabilities.yml` | `knowledge_base/recommendations.yml`*
