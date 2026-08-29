# Remediation Plan

What was fixed in Task 3, and for everything deferred: the residual risk, the effort to remediate, and
any compensating controls. Finding IDs refer to [findings.md](findings.md).

## Fixed in code (see git diff on `claude-main`)

| # | Finding | Fix |
| - | ------- | --- |
| F1 | Hardcoded JWT `SECRET_KEY` | Removed; sourced from env, ephemeral dev fallback with warning, no committed secret |
| F2 | SQL injection in search | Parameterised (bound `:q`) — no interpolation |
| F3 | IDOR in `get_scan` | Query scoped by `owner_id` |
| F4 | Search leaked other users' scans | Search scoped by `owner_id` |
| F6 | Verbose exception handler | Generic 500 body; logs path only (not the query string) |
| F7 | `python-jose` 3.3.0 | Bumped to 3.5.0 |
| F8 | `cryptography` 38.0.1 | Bumped to 50.0.1 |
| F10 | Credentials logged at login | Passwords no longer logged; `%r` prevents log injection |
| F11 | CORS reflected any origin + credentials | Explicit allowlist via `CORSMiddleware` |
| F12 | JWT `alg:"none"` accepted | Removed `"none"` from the decode allow-list |
| F13 | `python-multipart` 0.0.6 | Bumped to 0.0.32 |
| F15 | No throttling on `/share` (new feature) | Per-token rate limit on password attempts |
| F16 | Dead hardcoded secrets in `config.py` | `DB_USER`/`DB_PASSWORD`/`ADMIN_API_KEY` deleted (unused) |

Three+ critical/high fixed, at least one (F15) in the Task 1 code. CI SAST + SCA gates go green as a
result.

> Note: `reports/*.json` are the point-in-time Task 2 analysis (they justify findings.md). The fixes
> above are visible in the git diff; CI regenerates fresh reports on every run.

## Deferred — with rationale

### D1. notify service issues (F5 SSRF + key exfil, F9 axios CVEs, F14 express/path-to-regexp ReDoS, F17 stack disclosure, F16 `SERVICE_KEY`)
- **Why deferred:** the brief scopes changes to `app/` ("notify — no changes required"). Fixing it is
  out of the agreed change set; it is documented here instead.
- **Residual risk:** *High.* Unauthenticated webhook registration + SSRF can reach cloud metadata
  (`169.254.169.254`) and internal services, and leaks the hardcoded `SERVICE_KEY` to any attacker-
  registered URL; axios/express carry their own SSRF/ReDoS CVEs; error responses disclose stack traces.
- **Effort:** ~1 day. Authenticate `POST /webhooks`; validate/allowlist destination URLs and block
  link-local/private ranges; move `SERVICE_KEY` to env; `npm update` axios/express/path-to-regexp;
  stop returning `err.stack`.
- **Compensating controls:** the Terraform `NetworkPolicy` limits egress (DNS + 443 only), which blunts
  SSRF to internal HTTP services; the service is intended for internal-network reachability only.

### D2. `pytest` 7.4.3 CVE (F18)
- **Residual risk:** *Low.* Test-only dependency; not on any runtime code path. It is, however,
  currently installed into the image via `requirements.txt`.
- **Effort:** *Low.* Split a `requirements-dev.txt` (pytest, pytest-asyncio) out of the runtime
  requirements and bump pytest; the production image then omits it entirely.
- **Compensating controls:** not reachable at runtime; image runs as non-root with a read-only FS.

### D3. Base-image OS CVEs (F19)
- **Residual risk:** *Low.* The critical/high OS packages (`perl-base`, `ncurses`, `gzip`) are pulled in
  by Debian, never invoked by the app, and many have no upstream fix.
- **Effort:** *Low–Medium.* Move to a distroless / Chainguard base and rebuild; re-scan.
- **Compensating controls:** non-root uid 10001, read-only root filesystem, dropped capabilities,
  minimal invoked surface; CI gates on image secrets/misconfig (0) rather than unfixable OS CVEs.

### D4. K8s secrets as env vars, not files (F20 / CKV_K8S_35)
- **Residual risk:** *Low.* Env vars are readable via `/proc` to same-uid processes and can surface in
  crash dumps; here the container runs a single process and the secret originates in Key Vault.
- **Effort:** *Low.* Have the app read secrets from the CSI file mount (`/mnt/secrets-store`) instead of
  env; drop the `secretObjects` env sync.
- **Compensating controls:** secrets are Key Vault-sourced (never hardcoded), delivered by the CSI
  driver, and the K8s Secret is RBAC-restricted to the namespace.
