import logging
import secrets
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import (
    CORS_ALLOW_ORIGINS,
    NOTIFY_SERVICE_URL,
    PUBLIC_BASE_URL,
    SHARE_LINK_TTL_HOURS,
    SHARE_MAX_ATTEMPTS,
    SHARE_WINDOW_SECONDS,
)
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


# CORS (F11): explicit allowlist only — never reflect arbitrary origins. An empty
# allowlist permits no cross-origin requests (same-origin only).
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ALLOW_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    # F6: record full detail server-side (path only — never the query string, so
    # a share link's ?password= is never logged) and return a generic body so
    # tracebacks and internals are not disclosed to clients.
    logger.error("Unhandled exception on %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ShareCreate(BaseModel):
    password: Optional[str] = None


class ShareResponse(BaseModel):
    share_url: str


class SharedScanView(BaseModel):
    """Curated public projection of a scan — intentionally omits owner_id and
    internal remediation_notes so external stakeholders see only report data."""
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _share_base_url(request: Request) -> str:
    # Prefer an explicitly configured public URL to avoid Host-header poisoning
    # of generated share links; fall back to the request's own base URL.
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/")
    return str(request.base_url).rstrip("/")


def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


# In-memory brute-force throttle for password-protected share links (F15).
# Per-process only; production should use a shared store (Redis) or a gateway/WAF.
_share_attempts: dict = defaultdict(list)


def _enforce_share_rate_limit(token: str) -> None:
    now = time.monotonic()
    recent = [t for t in _share_attempts[token] if now - t < SHARE_WINDOW_SECONDS]
    _share_attempts[token] = recent
    if len(recent) >= SHARE_MAX_ATTEMPTS:
        raise HTTPException(status_code=429, detail="Too many attempts; try again later")


def _record_share_attempt(token: str) -> None:
    _share_attempts[token].append(time.monotonic())


def _clear_share_attempts(token: str) -> None:
    _share_attempts.pop(token, None)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    # F10: never log passwords; %r escapes control chars to prevent log injection.
    logger.info("Login attempt for user %r", payload.username)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("Failed login for user %r", payload.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    results = search_scans_by_query(db, q, current_user.id)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # F3: scope by owner so a user cannot read another tenant's scan by ID (BOLA).
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


@app.post("/scans/{scan_id}/share", response_model=ShareResponse, status_code=201)
def share_scan(
    scan_id: int,
    payload: ShareCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        # 404 (not 403) so a non-owner cannot probe which scan IDs exist.
        raise HTTPException(status_code=404, detail="Scan not found")

    share = models.SharedReport(
        token=secrets.token_urlsafe(32),
        scan_id=scan.id,
        password_hash=get_password_hash(payload.password) if payload.password else None,
        created_by=current_user.id,
        expires_at=datetime.utcnow() + timedelta(hours=SHARE_LINK_TTL_HOURS),
    )
    db.add(share)
    db.commit()

    return {"share_url": f"{_share_base_url(request)}/share/{share.token}"}


# ---------------------------------------------------------------------------
# Shared report links (public)
# ---------------------------------------------------------------------------

@app.get("/share/{token}", response_model=SharedScanView)
def view_shared_scan(
    token: str,
    password: Optional[str] = None,
    db: Session = Depends(get_db),
):
    share = db.query(models.SharedReport).filter(
        models.SharedReport.token == token
    ).first()

    # Uniform 404 for unknown *or* expired tokens so the endpoint is not an
    # oracle revealing which tokens exist.
    if not share or share.expires_at < datetime.utcnow():
        raise HTTPException(status_code=404, detail="Share link not found or has expired")

    if share.password_hash:
        _enforce_share_rate_limit(share.token)
        if not password or not verify_password(password, share.password_hash):
            _record_share_attempt(share.token)
            raise HTTPException(status_code=401, detail="Invalid or missing password")
        _clear_share_attempts(share.token)

    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == share.scan_id
    ).first()
    if not scan:
        # Underlying scan was deleted after the link was created.
        raise HTTPException(status_code=404, detail="Share link not found or has expired")

    return scan


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}
