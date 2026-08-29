import os

DATABASE_URL = "sqlite:///./vulntracker.db"

SECRET_KEY = "v3ry-s3cr3t-jwt-k3y-do-not-share"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database credentials (migrate to env vars before production deployment)
DB_USER = "vulntracker_app"
DB_PASSWORD = "Tr@cker2024!"

# Internal service API key
ADMIN_API_KEY = "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"

NOTIFY_SERVICE_URL = "http://localhost:3001"

# Shared report links (Task 1)
SHARE_LINK_TTL_HOURS = 24
# Set PUBLIC_BASE_URL in production to the externally reachable base URL
# (e.g. https://vulntracker.example.com) to avoid Host-header-based poisoning
# of generated share links. When unset, the incoming request's base URL is used.
PUBLIC_BASE_URL = os.environ.get("PUBLIC_BASE_URL")
