# Technical Notes

Detailed, per-task technical record of features and actions taken. High-level rationale
lives in [design-decisions.md](design-decisions.md).

---

## Task 1 — Shared Report Link

### Files changed
| File | Change |
| ---- | ------ |
| [app/models.py](../app/models.py) | New `SharedReport` model (`shared_reports` table) |
| [app/config.py](../app/config.py) | `SHARE_LINK_TTL_HOURS`, `PUBLIC_BASE_URL` (env-sourced) |
| [app/main.py](../app/main.py) | `ShareCreate` / `ShareResponse` / `SharedScanView` schemas, `_share_base_url` helper, `POST /scans/{scan_id}/share`, `GET /share/{token}` |
| [tests/test_api.py](../tests/test_api.py) | 7 tests covering the feature |

### Data model — `shared_reports`
| Column | Type | Notes |
| ------ | ---- | ----- |
| `id` | int PK | |
| `token` | str(64), unique, indexed | `secrets.token_urlsafe(32)` |
| `scan_id` | FK → `scan_results.id` | the shared scan |
| `password_hash` | str(200), nullable | bcrypt hash; `NULL` ⇒ public link |
| `created_by` | FK → `users.id` | audit trail of who shared it |
| `created_at` | datetime | |
| `expires_at` | datetime | `created_at + SHARE_LINK_TTL_HOURS` |

Table is created via the app's existing `Base.metadata.create_all` — no migration needed
for a brand-new table.

### `POST /scans/{scan_id}/share`
1. Authenticate via Bearer (`get_current_user`).
2. Load the scan filtered by **both** `id` and `owner_id == current_user.id`.
   Missing ⇒ `404` (ownership + existence check in one query; no IDOR, no ID probing).
3. Generate `token = secrets.token_urlsafe(32)`.
4. If a `password` is supplied, store `bcrypt(password)`; else `NULL`.
5. Persist the row with `expires_at = utcnow() + 24h`.
6. Return `{"share_url": "<base>/share/<token>"}` where `<base>` is `PUBLIC_BASE_URL` if
   set, otherwise `request.base_url`.

### `GET /share/{token}` (public, no auth)
1. Look up the token.
2. **Unknown or expired ⇒ identical `404`** (`"Share link not found or has expired"`) — no
   existence oracle.
3. If `password_hash` is set: require `?password=` and verify with bcrypt; missing/wrong ⇒
   `401`.
4. Load the underlying scan; if it was deleted since sharing ⇒ `404`.
5. Serialize through `SharedScanView` (`response_model`), which **structurally drops**
   `owner_id` and `remediation_notes`.

### Error matrix
| Condition | Status | Body detail |
| --------- | ------ | ----------- |
| Not authenticated (POST) | 401/403 | bearer required |
| Share a scan you don't own | 404 | `Scan not found` |
| Unknown token (GET) | 404 | `Share link not found or has expired` |
| Expired token (GET) | 404 | `Share link not found or has expired` |
| Password required, missing/wrong | 401 | `Invalid or missing password` |
| Valid, no password | 200 | curated scan view |
| Valid, correct password | 200 | curated scan view |
| Underlying scan deleted | 404 | `Share link not found or has expired` |

### Security properties
- **Unguessable tokens:** 256-bit CSPRNG output ⇒ enumeration infeasible.
- **No IDOR:** creation requires ownership; the public read is scoped to exactly one scan.
- **Credential hygiene:** share passwords hashed (bcrypt), never stored or logged in clear.
- **Least data exposure:** public view excludes ownership and internal remediation notes.
- **No metadata leak in the token:** all state (expiry, protection, owner) is server-side.
- **Link-poisoning resistance:** `PUBLIC_BASE_URL` avoids trusting the `Host` header.

### Known gaps (tracked for later tasks)
- Password-in-query-string exposure (brief-mandated) → findings.md.
- No rate limiting on the public endpoint → Task 3 hardening (this feature's remediation).

### Test coverage ([tests/test_api.py](../tests/test_api.py))
`test_share_scan_requires_auth`, `test_share_scan_creates_link`,
`test_share_scan_non_owner_blocked`, `test_view_shared_scan_excludes_internal_fields`,
`test_view_shared_scan_unknown_token`, `test_password_protected_share`,
`test_expired_share_returns_404`. Full suite: **17 passed**.

### Manual example
```bash
# 1. Authenticate
TOKEN=$(curl -s localhost:8000/auth/login -H 'content-type: application/json' \
  -d '{"username":"alice","password":"pw"}' | jq -r .access_token)

# 2. Create a password-protected share for scan 1
curl -s -X POST localhost:8000/scans/1/share -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"password":"s3cret"}'
# -> {"share_url":"http://localhost:8000/share/xoq...<43 chars>"}

# 3. View it (public)
curl -s 'localhost:8000/share/xoq...?password=s3cret'
```

---

## Task 2 — Security Analysis

### Tools and exact commands
| Category | Tool | Command (as run) | Report |
| -------- | ---- | ---------------- | ------ |
| SAST | Semgrep (Docker) | `semgrep --config p/python --config p/javascript --config p/nodejsscan --config p/secrets --config p/security-audit --json -o reports/sast.semgrep.json app notify/src` | [sast.semgrep.json](../reports/sast.semgrep.json) |
| SCA | Trivy 0.74.0 | `trivy fs --scanners vuln --format json -o reports/sca.trivy.json --skip-dirs .venv --skip-dirs notify/node_modules .` | [sca.trivy.json](../reports/sca.trivy.json) |
| Secrets (supporting) | Trivy `--scanners secret` | run ad-hoc; **0 hits** (see note) | not retained |
| Container | Trivy `image` | `trivy image --format json -o reports/container.trivy.json vulntracker-api:local` | [container.trivy.json](../reports/container.trivy.json) |
| IaC | **Checkov** | `checkov -d terraform --compact -o json > reports/iac.checkov.json` | [iac.checkov.json](../reports/iac.checkov.json) |

Semgrep runs via the `semgrep/semgrep` Docker image because it has no native Windows build; it scanned
9 git-tracked source files with 431 rules.

### What the tools caught
- **Semgrep (5):** `jwt-python-none-alg` (auth.py:38), `avoid-sqlalchemy-text` (database.py:28),
  `python-logger-credential-disclosure` ×2 (login), `node_ssrf` (dispatcher.js:7).
- **Trivy SCA (65 unique CVEs):** `requirements.txt` = 1 critical / 11 high / 9 medium / 7 low;
  `notify/package-lock.json` = 15 high / 15 medium / 7 low. Key packages: `python-jose`, `cryptography`,
  `python-multipart` (Python); `axios`, `express`, `path-to-regexp`, `body-parser` (npm).

### CI wiring ([ci.yml](../.github/workflows/ci.yml))
Two new jobs, each = **report artifact + gate**:
- `sast`: install Semgrep → produce `sast.semgrep.json` (uploaded) → gate fails if any `ERROR`-severity
  finding has a path under `app/`. Verified locally: 2 such findings today (auth.py:38, database.py:28),
  both fixed in Task 3 → gate turns green. The notify `node_ssrf` ERROR is intentionally excluded from
  the gate (out-of-scope service) but present in the report.
- `sca`: install Trivy 0.74.0 → produce `sca.trivy.json` (uploaded, whole repo) → gate runs
  `trivy fs --severity CRITICAL,HIGH --exit-code 1 requirements.txt`, so only the app's Python deps
  block the build (cleared by dependency bumps in Task 3). notify's npm CVEs are reported, not gated.

**Gate-scoping rationale:** a security gate should block *our* regressions, not sit permanently red on
a service the brief tells us not to change. Scoping the failing check to `app/` + `requirements.txt`
keeps the gate meaningful and green-able, while the full-repo report preserves visibility of every
finding. See F5/F9/F14/F17 in findings.md for the notify items that are tracked but not gated.

### Interpretation notes
- **Secret scanners found nothing.** Trivy's secret scanner and Semgrep's `p/secrets` pack both
  returned 0 on the four hardcoded secrets — they don't match known vendor formats. F1/F16 are manual.
- **`alg:"none"` verified non-exploitable** in python-jose 3.3.0 (a key is always passed to
  `jwt.decode`), so F12 is a *latent* medium, not a critical — see the auth.py analysis in Task 3.
- **CVE severity ≠ finding severity:** F7 (`python-jose`) was contextualised down from Trivy's critical
  because the app uses symmetric HS256, not the asymmetric keys the CVE targets.

---

## Task 4 — Containerisation & Deployment

### Dockerfile ([Dockerfile](../Dockerfile))
Multi-stage build:
1. **builder** — `python:3.11-slim` pinned by digest (`sha256:1042b6…`); creates a venv and
   `pip install`s `requirements.txt` (own layer, cache-friendly).
2. **runtime** — same digest-pinned base; creates user/group `appuser` (uid/gid 10001); copies the
   venv and `app/`; sets `DATABASE_URL=sqlite:////data/vulntracker.db` on a writable `/data` volume so
   the app code stays read-only; `HEALTHCHECK` uses `urllib` (no `curl`); `USER appuser`; `CMD uvicorn`.

**Verified locally:** image builds; `docker run -p 8000:8000` → `GET /health` = 200;
`docker exec … id` = `uid=10001(appuser)`; `docker inspect … Health.Status` = `healthy`.

### Container scan ([container.trivy.json](../reports/container.trivy.json))
`trivy image` on the built image: OS (debian) 3 critical / 11 high — almost entirely `perl-base`,
`ncurses`, `gzip` (unused, many with no fix); Python layer mirrors the SCA findings (F7/F8/F13);
**0 secrets, 0 misconfigurations**. Interpretation in findings.md (F19).

### Terraform ([terraform/](../terraform/))
| Resource | Security properties |
| -------- | ------------------- |
| `kubernetes_deployment_v1` | pod + container securityContext (runAsNonRoot uid 10001, readOnlyRootFilesystem, drop ALL caps, no privilege escalation, seccomp RuntimeDefault); CPU/mem requests+limits; liveness/readiness on `/health`; SA-token automount off; env from CSI-synced Secret; `emptyDir` for `/data` + `/tmp` |
| `SecretProviderClass` (CSI) | pulls `SECRET-KEY` / `DATABASE-URL` from Azure Key Vault via workload identity; syncs to a K8s Secret — no secret values in repo/manifests/state |
| `kubernetes_service_v1` | `ClusterIP` (no direct external exposure) |
| `kubernetes_network_policy_v1` | ingress only from the ingress-controller namespace on 8000; egress limited to DNS + 443 |
| `kubernetes_service_account_v1` | workload-identity annotated; automount disabled |

### IaC scan — Trivy vs Checkov ([iac.checkov.json](../reports/iac.checkov.json))
**Control test:** `trivy config` on a deliberately insecure `kubernetes_pod` (privileged, hostNetwork,
hostPID, root) → **0 misconfigurations**. This proves Trivy's Terraform scanner does not cover the
`kubernetes` provider, so it was replaced by **Checkov** for IaC only.

Checkov result after hardening: **28 passed, 0 failed, 3 skipped** (+1 secrets false-positive skipped):
| Check | Disposition |
| ----- | ----------- |
| CKV_K8S_15 (imagePullPolicy) | **fixed** → `Always` |
| CKV_K8S_14 / CKV_K8S_43 (tag/digest) | **enforced** via `var.image` `@sha256:` validation; skipped (Checkov can't resolve the variable) |
| CKV_K8S_35 (secrets as env) | **accepted** — Key Vault CSI sourced, env for app compat; file-based consumption is future work |
| CKV_SECRET_6 | **false positive** on `secretProviderClass` name; inline-suppressed |

### CI ([ci.yml](../.github/workflows/ci.yml))
Added `container-scan` (docker build → `trivy image` → upload → gate on secrets/misconfig only, since
OS CVEs are unfixable) and `iac-scan` (`checkov -d terraform` → upload → gate on any unjustified
misconfiguration). Both gates are green today.
