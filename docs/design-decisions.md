# Design Decisions

High-level record of what was built, the decisions behind each feature, the arguments
for and against, the resulting effect, and potential improvements. Detailed technical
walkthroughs live in [technical-notes.md](technical-notes.md).

| Task | Status |
| ---- | ------ |
| 1 — Shared Report Link | ✅ Implemented |
| 2 — Security analysis (scans + findings) | ✅ All four scans + findings.md |
| 3 — Remediation | ✅ 13 findings fixed; deferrals documented |
| 4 — Containerisation & deployment | ✅ Dockerfile + Terraform |
| 5 — Executive summary | ⏳ Planned |

---

## Task 1 — Shared Report Link

### Overview
Lets an authenticated user mint a shareable link to a single scan for an external
stakeholder (auditor, customer). Links **expire after 24 hours** and support
**optional password protection**.

- `POST /scans/{scan_id}/share` (Bearer) → `{ "share_url": "..." }`
- `GET /share/{token}` (public) → curated scan view; requires `?password=` if protected

### Key decisions

**1. Stateful, opaque token (DB row) rather than a self-describing/signed token.**
- *For:* single source of truth; expiry, password, and revocation are server-side columns
  we can change or invalidate at any time; the token leaks zero metadata.
- *Against:* requires a DB lookup and a table (a stateless signed token needs neither).
- *Effect:* the token is a meaningless 256-bit random string; everything meaningful about
  the link lives in `shared_reports`. The alternative — a signed stateless token
  (`itsdangerous`/HMAC over `scan_id:expiry`) — is documented as viable but rejected here
  because it cannot be revoked before expiry and complicates password handling.

**2. Token = `secrets.token_urlsafe(32)` (~256 bits of entropy).**
- *For:* `secrets` is the correct CSPRNG primitive for security tokens; enumeration is
  computationally infeasible, so `GET /share/{token}` needs no per-token rate limiting to
  resist guessing.
- *Against:* none material. (`uuid4` would also work but is the wrong idiom, and `uuid1`
  would have been guessable — it encodes timestamp + MAC.)

**3. Ownership enforced on share creation.**
- *For:* prevents the IDOR pattern present elsewhere in the starter code — a user must not
  be able to share a scan they do not own.
- *Effect:* non-owners receive `404` (not `403`), so they cannot even confirm a scan ID
  exists.

**4. Share password hashed with bcrypt (reusing `auth.get_password_hash`).**
- *For:* the share password is a credential; it is stored hashed exactly like user
  passwords, never in plaintext. Verification is constant-time via bcrypt.
- *Against:* bcrypt's 72-byte input limit applies (acceptable for a share password).

**5. 24-hour expiry stored as `expires_at` and checked server-side.**
- *For:* authoritative and easy to reason about; no client-trusted timestamps.
- *Effect:* TTL is config-driven (`SHARE_LINK_TTL_HOURS`).

**6. Curated public projection — `SharedScanView` omits `owner_id` and
`remediation_notes`.**
- *For:* an external auditor needs the finding, not internal ownership or the internal
  remediation playbook. Enforced by a FastAPI `response_model`, so it is structural, not a
  manual field-picking that can drift.
- *Effect:* least-privilege data exposure by default (per the agreed decision to exclude
  internal remediation detail).

**7. Share URL host: configurable `PUBLIC_BASE_URL`, else the request's base URL.**
- *For:* using the raw request `Host` header lets an attacker poison the generated link
  (host-header injection). An explicit configured base URL removes that in production.
- *Against:* one more config value. Falls back to request base URL for the prototype, as
  the brief permits.

**8. Error signaling designed to minimise oracles.**
- Unknown token and expired token both return an identical `404` — the endpoint does not
  reveal whether a token ever existed.
- A valid-but-password-protected link returns `401` on missing/wrong password. This does
  confirm the token is valid, but given 256-bit tokens that is not a usable oracle, and it
  keeps the UX honest for legitimate users who mistype the password.

### Residual risks (carried into findings.md / remediation-plan.md)
- **Password travels as a query parameter** (mandated by the brief). Query strings leak to
  server/proxy access logs, browser history, and `Referer` headers. This interacts with a
  **starter-code bug**: the global exception handler logs `request.url`, which would
  capture the password on any 500. Documented; the cleaner alternative is a POST body or a
  request header.
- **No brute-force throttling on `GET /share/{token}`.** Token guessing is infeasible, but
  *password* guessing against a known link is not throttled. Planned as the Task 3
  hardening applied to this feature (rate limiting), giving a visible remediation in the
  code written here.

### Potential improvements
- Rate limiting / lockout on the public endpoint (Task 3).
- Explicit revocation endpoint (`DELETE /share/{token}`) and a `revoked` flag.
- Alembic migrations (the prototype relies on `create_all`; a new table is fine, but schema
  changes to existing tables would need migrations).
- One-time-view or view-count-limited links for higher-sensitivity reports.

---

## Task 2 — Security Analysis

### Overview
Ran the runnable scan categories now and wired them into CI; container and IaC scans depend on
Task 4 artifacts and are added there. Full prioritised results in [findings.md](findings.md).

- **SAST** — Semgrep (via Docker) over `app/` + `notify/src`: 5 findings.
- **SCA** — Trivy `fs` over `requirements.txt` + `notify/package-lock.json`: 65 unique CVEs.
- **CI** — `sast` + `sca` jobs added to [ci.yml](../.github/workflows/ci.yml) with severity gates.

### Key decisions

**1. Consolidate on Trivy for SCA (and later container + IaC).**
- *For:* one engine covers dependencies, OS packages, and IaC misconfig; single JSON shape; fewer
  tools to install, pin, and defend. Covers both ecosystems (`pip` + `npm`) in one pass.
- *Against:* a dedicated SCA tool (e.g. `pip-audit`, `npm audit`) can have deeper per-ecosystem
  advisory data; Trivy is a generalist.
- *Effect:* chosen deliberately (per agreed scope) over a grype + Docker Scout split.

**2. Semgrep for SAST (not Bandit).**
- *For:* multi-language — it scanned the Python API *and* the Node service in one run, catching the
  `notify` SSRF that a Python-only tool (Bandit) would miss; taint/security rulesets flag JWT `none`,
  raw-SQL, and credential logging out of the box.
- *Against:* Semgrep has no native Windows support, so it runs via Docker locally (Bandit would run
  natively). Acceptable — CI runs it on Linux anyway.

**3. CI gates are scoped to code we own; reports cover everything.**
- *Decision:* the uploaded report scans the whole repo (app + notify), but the *failing gate* only
  blocks on criticals in `app/` and `requirements.txt`.
- *For:* a gate must stop *our* regressions without going permanently red over `notify`, which is
  out of scope for fixes (per the brief) yet legitimately full of findings. Blocking on it would
  either force scope-violating changes or a blanket ignore-file.
- *Against:* a stricter org might gate the whole monorepo. Trade-off is documented, and the notify
  findings remain visible in `findings.md` as accepted/tracked risk.
- *Effect:* CI is red today on the two app criticals (SQLi, JWT `none`) and goes green once Task 3
  fixes them — the gate is doing its job, not being bypassed.

**4. Severity is my assessment, not the tool's.**
- Two deliberate divergences: **F7** (`python-jose`) — Trivy says *critical*, I rate *high* because
  the alg-confusion CVE targets asymmetric keys and this app uses HS256; **F12** (`alg:"none"`) —
  down-graded to *medium latent* after I verified python-jose 3.3.0 does not actually honour it here.
- *Why it matters:* the brief grades interpretation over tool output; parroting a scanner's severity
  would be the wrong answer.

### Effect
Real, reproducible evidence backs the manual review, and CI now enforces it. The most security-relevant
result is corroboration: Semgrep independently flagged the SQLi, JWT `none`, credential logging, and
notify SSRF; Trivy surfaced the vulnerable auth/crypto libraries that compound them.

### Potential improvements
- SARIF upload to GitHub code scanning for inline PR annotations.
- Pin exact Semgrep version in CI for full reproducibility.

---

## Task 4 — Containerisation & Deployment

### Overview
A production Dockerfile for the API and a Terraform (Kubernetes/AKS) deployment. Building these also
unblocked the container and IaC scans in Task 2.

### Dockerfile decisions

**1. Multi-stage, digest-pinned slim base.**
- *For:* the builder installs dependencies into a venv; the runtime copies only that venv + app code,
  so no build toolchain ships in the final image. `python:3.11-slim` is pinned by digest
  (`sha256:1042b6…`) for an immutable, reproducible base.
- *Against:* digest pins need periodic bumps — automatable with Dependabot/Renovate.

**2. Non-root + read-only-friendly layout.**
- Runs as uid 10001; app code is copied root-owned (read-only to the runtime user). The prototype's
  SQLite file is redirected to a dedicated `/data` volume so the container root filesystem can be
  read-only under Kubernetes.
- *Trade-off:* SQLite-on-a-volume is a prototype crutch; production points `DATABASE_URL` at a managed
  database.

**3. Stdlib HEALTHCHECK.** Probes `/health` with `urllib` rather than adding `curl` — one fewer package
(and one fewer CVE surface) in the image.

**4. No embedded secrets.** `SECRET_KEY`/`DATABASE_URL` are injected at runtime; the insecure config
fallbacks remain only until Task 3 removes them (F1).

### Terraform decisions

**Kubernetes provider targeting AKS.**
- *For:* directly expresses the required controls (security contexts, resource limits, network policy)
  and fits the Azure-heavy role. Secrets come from **Azure Key Vault** via the Secrets Store CSI driver
  with a workload identity — no secret values in the repo, manifests, or Terraform state.
- *Against:* applying needs cluster add-ons (CSI driver + workload identity); documented in the README.
- **Hardened by construction:** runAsNonRoot, readOnlyRootFilesystem, drop `ALL` capabilities, no
  privilege escalation, seccomp `RuntimeDefault`, SA-token automount off, `ClusterIP` + `NetworkPolicy`
  (ingress only from the ingress controller on 8000).

### IaC scanner pivot — Trivy → Checkov
- *Decision:* use **Checkov** for the IaC scan, even though Trivy handles SCA + container.
- *Why:* Trivy's Terraform scanner does not cover the `kubernetes` provider — verified with a control
  test (0 findings on a deliberately insecure pod). A clean Trivy result would have been meaningless.
- *Effect:* a real IaC gate. After hardening: **0 failed / 3 justified skips**. The "consolidate on
  Trivy" goal still holds everywhere Trivy is actually competent — this is using the right tool for one
  domain, not tool sprawl.

### Potential improvements
- Distroless base to shed the unfixable OS CVEs (F19).
- App reads secrets from the CSI file mount instead of env vars (clears CKV_K8S_35 / F20).
- Automated base-image digest bumps.

---

## Task 3 — Remediation

### Overview
Fixed 13 findings in code (≥3 critical/high, one — F15 — in the Task 1 feature). Deferrals are
documented in [remediation-plan.md](remediation-plan.md). All four CI gates go green as a result.

### Key decisions

**1. `SECRET_KEY`: env-sourced with an ephemeral dev fallback (not hard-fail).**
- *For:* removes the committed secret (the actual vulnerability) while letting the app boot in dev/test
  without extra provisioning; logs a warning.
- *Against:* a per-process ephemeral key invalidates tokens across restarts/workers — a hard-fail
  ("refuse to start without SECRET_KEY") is stricter. Chosen the pragmatic option and documented the
  production expectation (always set it); the deployment injects it from Key Vault.

**2. SQL injection: parameterise *and* scope by owner.**
- Fixing F2 (injection) and F4 (missing owner filter) together — the raw query had both flaws. Kept a
  bound `text()` query rather than switching to the ORM to avoid a circular import (`database` →
  `models`), which is a smaller, lower-risk change.

**3. CORS: explicit allowlist via `CORSMiddleware`.**
- Replaced the origin-reflecting custom middleware. Empty allowlist by default (same-origin only);
  real origins come from `CORS_ALLOW_ORIGINS`. No more `reflect-origin + allow-credentials`.

**4. Rate-limiting `/share` (F15, the Task 1 fix): in-memory per-token throttle.**
- *For:* a minimal, dependency-free control that blunts password brute force on a public endpoint.
- *Against:* per-process only — it does not hold across replicas. Documented; production should use a
  shared store (Redis) or a gateway/WAF. Deliberately not over-built.

**5. Dependency bumps to the lowest version that clears the gate.**
- `python-jose` 3.5.0, `cryptography` 50.0.1, `python-multipart` 0.0.32. `cryptography` needed 50.0.1
  specifically (49.0.0 still carried one HIGH). Verified by re-scanning the manifest and re-running the
  full test suite (21 passing) against the new libraries.

**6. `alg:"none"` removed despite being non-exploitable here** — defense-in-depth, per the F12 analysis:
it becomes a full auth bypass under a library swap or an empty-key refactor, and costs nothing to drop.

### Effect
SAST app/ ERROR findings 5 → 0; SCA `requirements.txt` CRITICAL/HIGH → 0; the two auth criticals (F1
forge-any-token, F2 dump-hashes) and the BOLA reads (F3/F4) are closed. The notify findings remain
(out of scope) but no longer share a class with anything in `app/`.

### Potential improvements
- Hard-fail on missing `SECRET_KEY` in a `prod` profile.
- Distributed rate-limiting for `/share` and login.
- Split `requirements-dev.txt` so pytest (F18) never ships in the image.
