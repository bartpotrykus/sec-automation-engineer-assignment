# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Builder — install dependencies into an isolated virtualenv
# ---------------------------------------------------------------------------
FROM python@sha256:1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install deps first (own layer) so source changes don't invalidate the cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------------------
# Runtime — minimal, non-root, no build toolchain
# ---------------------------------------------------------------------------
FROM python@sha256:1042b61448fef4ba92d16a8c7eb4996d027568ce64792a7877fd88511e0af7c6 AS runtime

# Unprivileged user/group (fixed high UID/GID for K8s runAsNonRoot)
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin appuser

# Dedicated writable dir for the prototype's SQLite file, so the app code in
# /app can stay read-only (and the root filesystem read-only in K8s — mount a
# volume at /data). Production would point DATABASE_URL at a managed database.
RUN mkdir -p /data && chown appuser:appuser /data

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DATABASE_URL="sqlite:////data/vulntracker.db"

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app
# The app uses bare imports and must run from inside its own directory.
# Code is copied root-owned → read-only to the unprivileged runtime user.
COPY app/ /app/
VOLUME ["/data"]

USER appuser
EXPOSE 8000

# No curl in the slim image — use the stdlib to probe the app's own endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

# Secrets (SECRET_KEY, DATABASE_URL, ...) are injected at runtime via env /
# secret store — never baked into the image.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
