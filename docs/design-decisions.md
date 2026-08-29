# Design Decisions

High-level record of what was built, the decisions behind each feature, the arguments
for and against, the resulting effect, and potential improvements. Detailed technical
walkthroughs live in [technical-notes.md](technical-notes.md).

| Task | Status |
| ---- | ------ |
| 1 — Shared Report Link | ✅ Implemented |
| 2 — Security analysis (scans + findings) | ⏳ Planned |
| 3 — Remediation | ⏳ Planned |
| 4 — Containerisation & deployment | ⏳ Planned |
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
