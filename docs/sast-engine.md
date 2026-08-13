# SAST Rule Pack (Week 5)

Static analysis coverage for the two vulnerabilities the DAST engine
can't reliably reach dynamically: insecure JWT handling and insecure
deserialization. Both are code-level issues — the flaw is in *how* the
code is written, not in observable HTTP behavior — so Semgrep scans the
source directly instead of sending requests.

## Module Layout

| File | Responsibility |
|---|---|
| `sast/run_semgrep.py` | CLI entry point. Runs Semgrep, normalizes its output into the standard finding schema. |
| `rules/sast/semgrep/insecure-jwt.yml` | Two rules: JWT algorithm allowlist containing `"none"`, and a hardcoded JWT signing secret. |
| `rules/sast/semgrep/insecure-deserialization.yml` | One rule: any `pickle.loads()` call. |

## Why Semgrep

Semgrep rules are YAML, matching the declarative philosophy already used
for DAST rules in this project (see `docs/rule-format.md`) — no custom
AST-walking code needed, and rules stay readable by someone who isn't a
Python tooling expert.

## How a Scan Runs

1. `run_semgrep.py` calls `semgrep --config <rules_dir> <target> --json`
   as a subprocess.
2. Each match in Semgrep's JSON output is normalized: the rule id is
   extracted from Semgrep's `check_id` (which prefixes it with the rule
   file's path), the finding's title is taken from the first sentence of
   the rule's `message`, and the actual matched source lines are read
   directly from disk using the reported line range — not from Semgrep's
   own `extra.lines` field, which returned the literal string
   `"requires login"` in testing rather than real code (a Community
   Edition/registry-gated feature in this Semgrep version), so the
   runner reads the file itself instead of trusting that field.
3. Custom fields (`category`, `owasp`, `owasp_api`, `cwe`,
   `recommendation`) are pulled from each rule's `metadata` block.
4. Every match becomes a finding with `"source": "sast"` and
   `"vulnerable": true` — unlike DAST, a static rule only reports
   matches, so there's no "checked and found clean" result to record per
   rule the way `not_applicable` works for DAST.
5. Results are saved to `sast/results/sast_scan_<timestamp>.json` and a
   summary is printed to the terminal.

## Rule Coverage (3 rules, 2 vulnerability classes)

| Rule ID | Vulnerability | Detects |
|---|---|---|
| `nb-jwt-alg-none-accepted` | Insecure JWT Handling | Any list literal assignment containing `"none"` as an accepted algorithm |
| `nb-jwt-hardcoded-secret` | Insecure JWT Handling | A JWT-secret-looking variable assigned a hardcoded string literal |
| `nb-insecure-deserialization-pickle` | Insecure Deserialization | Any `pickle.loads(...)` call |

Combined with the Week 3/4 DAST rules, all 11 vulnerabilities from
`docs/vulnerability-list.md` now have at least one automated detection
rule.

## A Design Note on the JWT Algorithm Rule

The vulnerable code doesn't pass a literal algorithm list at the
`jwt.decode()` call site — it references a module-level variable:

```python
JWT_ALGORITHMS = ["HS256", "none"]
...
jwt.decode(token, JWT_SECRET, algorithms=JWT_ALGORITHMS, ...)
```

An early version of the rule tried to match the pattern at the
`jwt.decode()` call itself (`algorithms=[..., "none", ...]`), expecting
Semgrep's constant propagation to resolve the variable — it didn't, and
the rule silently found nothing. The rule was rewritten to match the
list *definition* directly (`$VAR = [..., "none", ...]`) instead, which
correctly flags the root cause regardless of how many places later
reference that variable, and was confirmed working in testing.

## Verification

Every rule was tested two ways before being considered done, not just
written and assumed correct:

1. **Positive test** — run against the actual `apps/vulnerable-api/`
   source. All 3 rules fired on the expected lines
   (`auth_routes.py:10`, `auth_routes.py:14`, `import_routes.py:26`).
2. **Negative test** — run against hand-written secure equivalents (a
   JWT decode using `os.environ.get()` for the secret and `["HS256"]`
   only for algorithms; a deserialization function using `json.loads()`
   instead of `pickle.loads()`). Zero findings — confirming the rules
   detect the actual insecure pattern rather than firing on any related
   code.

## Known Limitations

- The hardcoded-secret rule (`nb-jwt-hardcoded-secret`) uses a regex on
  variable naming (anything containing `SECRET` near `JWT`/`TOKEN`), so
  it won't catch a hardcoded secret stored under an unrelated variable
  name. A more thorough version would need Semgrep's secret-detection
  rule pack or an entropy-based check, which is out of scope here.
- SAST findings don't currently get re-run against `apps/secure-api/`
  the way DAST rules will in Week 6 — that wiring is part of the Week 6
  remediation validation workflow, not yet built.
