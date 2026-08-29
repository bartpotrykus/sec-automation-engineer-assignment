# Security Findings

## Method & scope

| Scan type | Tool | Target | Report |
| --------- | ---- | ------ | ------ |
| SAST | Semgrep (`p/python`, `p/javascript`, `p/nodejsscan`, `p/secrets`, `p/security-audit`) | `app/`, `notify/src/` | [reports/sast.semgrep.json](../reports/sast.semgrep.json) |
| SCA / dependencies | Trivy `fs` (vuln) | `requirements.txt`, `notify/package-lock.json` | [reports/sca.trivy.json](../reports/sca.trivy.json) |
| Container image | Trivy `image` | Docker image | ⏳ Task 4 → [reports/container.trivy.json](../reports/container.trivy.json) |
| IaC | Trivy `config` | `terraform/` | ⏳ Task 4 → [reports/iac.trivy.json](../reports/iac.trivy.json) |

Container and IaC scans require artifacts produced in Task 4; this file is updated when they run.
All four run in CI ([.github/workflows/ci.yml](../.github/workflows/ci.yml)).

**Why severity is contextual here.** VulnTracker is an inventory of an organisation's *known,
unremediated* vulnerabilities and who owns them. That makes it unusually high-value: a
confidentiality breach hands an attacker a pre-prioritised map of where the company is exploitable;
an integrity breach lets an attacker mark real findings "resolved" to hide them; downtime blinds the
security team. Severities below reflect exploitability **and** this business context, not raw CVSS.

Tool corroboration is noted, but severity is my own assessment — in two places I diverge from the
tool (F7 up-contextualised, F12 down-graded after verification).

## Prioritised findings

| # | Finding | Location | Source | Severity | In |
| - | ------- | -------- | ------ | -------- | -- |
| F1 | Hardcoded JWT signing key → forge a token for any user | [config.py:3](../app/config.py#L3) | Manual | **Critical** | Starter |
| F2 | SQL injection via f-string into `text()` (UNION-able) | [database.py:20-29](../app/database.py#L20-L29) | Semgrep + manual | **Critical** | Starter |
| F3 | Broken object-level auth (IDOR) — read any scan by ID | [main.py `get_scan`](../app/main.py) | Manual | **High** | Starter |
| F4 | Search returns all users' scans (no owner filter) | [database.py:20-29](../app/database.py#L20-L29) | Manual | **High** | Starter |
| F5 | SSRF + unauthenticated webhook registration, leaks service key | [dispatcher.js:7](../notify/src/dispatcher.js#L7), [index.js:14](../notify/src/index.js#L14) | Semgrep + manual | **High** | Starter (notify) |
| F6 | Exception handler returns traceback/internals; logs full URL | [main.py:41-52](../app/main.py#L41-L52) | Manual | **High** | Starter |
| F7 | `python-jose` 3.3.0 — CVE-2024-33663 (alg confusion), -33664 (DoS) | [requirements.txt:4](../requirements.txt#L4) | Trivy | **High** | Starter |
| F8 | `cryptography` 38.0.1 — 11 CVEs incl. Bleichenbacher timing oracle | [requirements.txt:7](../requirements.txt#L7) | Trivy | **High** | Starter |
| F9 | `axios` 0.21.1 — SSRF + credential-leak + ReDoS (15 HIGH CVEs) | [notify/package.json](../notify/package.json) | Trivy | **High** | Starter (notify) |
| F10 | Plaintext credentials logged on every login attempt (+ log injection) | [main.py:146-158](../app/main.py#L146-L158) | Semgrep + manual | **Medium** | Starter |
| F11 | CORS reflects arbitrary Origin with `Allow-Credentials: true` | [main.py:29-38](../app/main.py#L29-L38) | Manual | **Medium** | Starter |
| F12 | JWT decode allows `alg: "none"` (latent, not exploitable here) | [auth.py:38](../app/auth.py#L38) | Semgrep + manual | **Medium** | Starter |
| F13 | `python-multipart` 0.0.6 — path traversal / DoS CVEs | [requirements.txt:6](../requirements.txt#L6) | Trivy | **Medium** | Starter |
| F14 | `express`/`path-to-regexp`/`body-parser` — ReDoS & input handling | [notify/package.json](../notify/package.json) | Trivy | **Medium** | Starter (notify) |
| F15 | No rate limiting / lockout on `/auth/login` and public `/share/{token}` | [main.py](../app/main.py) | Manual | **Medium** | Starter + **new** |
| F16 | Other hardcoded secrets: DB creds, `ADMIN_API_KEY`, notify `SERVICE_KEY` | [config.py:8-14](../app/config.py#L8-L14), [config.js:6](../notify/src/config.js#L6) | Manual | **Medium** | Starter |
| F17 | notify leaks `err.stack` to clients; `GET /webhooks` lists all endpoints | [index.js:36-48](../notify/src/index.js#L36-L48), [77-80](../notify/src/index.js#L77-L80) | Manual | **Low** | Starter (notify) |
| F18 | `pytest` 7.4.3 CVE-2025-71176 — test-only, not shipped | [requirements.txt:10](../requirements.txt#L10) | Trivy | **Low** | Starter |

**SCA totals (Trivy, unique CVEs):** `requirements.txt` — 1 critical / 11 high / 9 medium / 7 low.
`notify/package-lock.json` — 15 high / 15 medium / 7 low.

## Rationale for the top findings

**F1 — Hardcoded JWT signing key (Critical).** `SECRET_KEY` is committed in `config.py`. HS256 is
symmetric, so the value that *signs* tokens also *verifies* them — anyone who reads the repo can mint
a valid token for any username (verified: `jwt.encode({"sub":"alice"}, "<committed key>")` is
accepted). *Impact:* complete authentication bypass and impersonation of any account, including
whoever owns the most sensitive findings. This is the single most damaging issue and undermines every
per-user control below it.

**F2 — SQL injection (Critical).** `search_scans_by_query` builds SQL by f-string interpolation and
runs it through `text()` (Semgrep `avoid-sqlalchemy-text`). The query is UNION-able against the
`users` table, so an authenticated attacker (registration is open) can exfiltrate every user's
`hashed_password`. *Impact:* full database read — the entire vulnerability inventory plus credential
hashes for offline cracking.

**F3 / F4 — Broken access control (High).** `get_scan` filters only by `id`, and
`search_scans_by_query` filters by nothing — both ignore `owner_id` (contrast `update_scan`/`delete_scan`,
which are scoped). Any authenticated user reads any other tenant's findings by ID or by search.
*Impact:* cross-tenant disclosure of exactly which systems are exploitable. This is the pattern the
Task 1 share endpoint deliberately avoids (it enforces ownership on creation).

**F5 — SSRF & key exfiltration in notify (High).** `POST /webhooks` is unauthenticated and stores any
`url`; `dispatcher.js` then POSTs event data to that URL (Semgrep `node_ssrf`) **with the hardcoded
`X-Service-Key` header attached**. *Impact:* an attacker registers `http://169.254.169.254/…` to reach
cloud metadata / internal services, and simultaneously receives the internal service key on every
dispatch. The "internal network only" comment in the code is the sole compensating control, and it is
an assumption, not an enforced boundary. Per the agreed scope this is documented, not fixed (notify is
out of the change set), and it compounds with F9 (axios' own SSRF CVEs).

**F6 — Verbose error handler (High).** The global handler returns `str(exc)`, the exception type, the
**full traceback**, and the request path in the HTTP response body, and logs `request.url`. *Impact:*
internal paths, SQL fragments, and library versions are handed to any client — reconnaissance gold on a
security tool. It also creates a **cross-feature leak**: a share link's `?password=` sits in
`request.url`, so any 500 on `/share` would log (and the body would echo) the share password — a direct
interaction with the Task 1 feature.

**F7 — python-jose 3.3.0 (High, contextualised).** Trivy flags CVE-2024-33663 as *critical*. I rate the
finding **High**, not critical, because that CVE is an algorithm-confusion issue centred on *asymmetric*
keys, and this app uses HS256 symmetric signing — so the direct exploit path is narrow. It still
warrants upgrade: CVE-2024-33664 (decode DoS) does apply, and staying on an EOL-ish jose is poor
hygiene for an auth-critical library. This is the kind of tool-output-vs-reality gap the review should
surface rather than parrot.

**F8 / F9 — Vulnerable crypto & HTTP libraries (High).** `cryptography` 38.0.1 ships known-vulnerable
OpenSSL (Bleichenbacher timing oracle, null-deref DoS); `axios` 0.21.1 carries SSRF and proxy-credential
leakage CVEs that directly amplify F5. Exploitability varies by usage, but both are load-bearing
dependencies and the fix is a version bump.

## Coverage & interpretation notes

- **Automated secret scanning missed every hardcoded secret.** Both Trivy's secret scanner and
  Semgrep's `p/secrets` pack returned no hits on `SECRET_KEY`, `ADMIN_API_KEY`, `DB_PASSWORD`, or
  `SERVICE_KEY` — they don't match known vendor key formats. F1/F16 are therefore *manual* findings.
  Lesson: signature-based secret scanners are necessary but not sufficient; manual review and
  code-review gates still matter.
- **F12 down-graded after verification.** `alg: "none"` is real (Semgrep `jwt-python-none-alg`), but I
  tested it against this exact code path: python-jose 3.3.0 refuses the `none` path whenever a key is
  supplied, and `decode_token` always supplies one — so it is **not** exploitable today. It stays as a
  Medium latent footgun (a library swap or an empty-key refactor turns it into a full bypass) and is
  fixed as defense-in-depth.
- **F13 exposure is limited by usage.** `python-multipart`'s path-traversal CVE needs multipart form
  handling; this app's endpoints are JSON, so runtime exposure is low today — but the dependency is
  present and should be bumped.
- **Dependency noise vs. signal.** Trivy reports 65 unique CVEs across both ecosystems; most collapse
  into a handful of package upgrades (axios, cryptography, python-multipart, python-jose). The
  remediation plan tracks these as package-level actions rather than per-CVE.

## New-feature (Task 1) assessment

The Shared Report Link feature was built to *avoid* the patterns above: opaque 256-bit tokens,
ownership enforced on creation (no F3-style IDOR), bcrypt-hashed share passwords, server-side expiry,
and a curated response model that omits `owner_id`/`remediation_notes`. It introduces **no new
critical/high finding**. Its two residuals are tracked as F15 (no brute-force throttling on the public
endpoint — fixed in Task 3) and the brief-mandated password-in-query exposure, which is only dangerous
in combination with F6.
