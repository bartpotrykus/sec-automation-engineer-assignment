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
