import logging
import os
import secrets

logger = logging.getLogger(__name__)

# 12-factor: everything comes from the environment (containers/K8s inject via a
# secret store). No hardcoded credentials remain in this file.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vulntracker.db")

# JWT signing key (F1). No hardcoded default. Required in production; for local
# dev/test we generate an ephemeral key so the app still boots — but that key is
# per-process, so tokens won't survive a restart or span multiple workers.
# ALWAYS set SECRET_KEY in production.
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(64)
    logger.warning("SECRET_KEY not set — using an ephemeral key; set SECRET_KEY in production.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

NOTIFY_SERVICE_URL = os.environ.get("NOTIFY_SERVICE_URL", "http://localhost:3001")

# Shared report links (Task 1)
SHARE_LINK_TTL_HOURS = 24
# Set PUBLIC_BASE_URL in production to the externally reachable base URL to avoid
# Host-header-based poisoning of generated share links.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL")

# Brute-force throttling for password-protected share links (F15).
SHARE_MAX_ATTEMPTS = int(os.environ.get("SHARE_MAX_ATTEMPTS", "10"))
SHARE_WINDOW_SECONDS = int(os.environ.get("SHARE_WINDOW_SECONDS", "900"))

# CORS allowlist (F11) — explicit origins only; never reflect arbitrary origins.
# Comma-separated, e.g. "https://app.example.com,https://admin.example.com".
CORS_ALLOW_ORIGINS = [o.strip() for o in os.environ.get("CORS_ALLOW_ORIGINS", "").split(",") if o.strip()]
