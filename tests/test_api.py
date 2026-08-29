import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
os.environ.setdefault("SHARE_MAX_ATTEMPTS", "3")  # keep the F15 rate-limit test fast

from datetime import datetime, timedelta  # noqa: E402

import models  # noqa: E402,F401
from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["results"][0]["title"] == "SQL Injection via login"


def test_search_scoped_to_owner():
    # F4: search must not leak another user's scans
    owner = register_and_login("owner2", "owner2@example.com", "pw")
    client.post("/scans", json={
        "title": "secret finding", "severity": "high", "affected_component": "x",
    }, headers=auth_headers(owner))
    other = register_and_login("mallory2", "mallory2@example.com", "pw")
    resp = client.get("/scans/search?q=secret", headers=auth_headers(other))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_search_injection_is_neutralised():
    # F2: an injection payload must not error nor bypass owner scoping to dump rows.
    # Against the old raw-SQL code this returns the victim's row; the fix returns none.
    victim = register_and_login("victim", "victim@example.com", "pw")
    client.post("/scans", json={
        "title": "victim finding", "severity": "high", "affected_component": "x",
    }, headers=auth_headers(victim))
    attacker = register_and_login("attacker", "attacker@example.com", "pw")
    resp = client.get("/scans/search?q=' OR '1'='1", headers=auth_headers(attacker))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Task 1 — Shared report links
# ---------------------------------------------------------------------------

def _create_scan(token, **overrides):
    body = {
        "title": "Shareable finding",
        "description": "internal description",
        "severity": "high",
        "affected_component": "svc",
        "remediation_notes": "apply patch X",
    }
    body.update(overrides)
    return client.post("/scans", json=body, headers=auth_headers(token)).json()["id"]


def _token_from_url(share_url):
    return share_url.rsplit("/", 1)[-1]


def test_share_scan_requires_auth():
    resp = client.post("/scans/1/share", json={})
    assert resp.status_code in (401, 403)


def test_share_scan_creates_link():
    token = register_and_login()
    scan_id = _create_scan(token)
    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 201
    assert "/share/" in resp.json()["share_url"]


def test_share_scan_non_owner_blocked():
    owner = register_and_login("owner", "owner@example.com", "pw")
    scan_id = _create_scan(owner)
    other = register_and_login("mallory", "mallory@example.com", "pw")
    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(other))
    assert resp.status_code == 404


def test_view_shared_scan_excludes_internal_fields():
    token = register_and_login()
    scan_id = _create_scan(token)
    share_url = client.post(
        f"/scans/{scan_id}/share", json={}, headers=auth_headers(token)
    ).json()["share_url"]
    resp = client.get(f"/share/{_token_from_url(share_url)}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["title"] == "Shareable finding"
    assert "remediation_notes" not in body
    assert "owner_id" not in body


def test_view_shared_scan_unknown_token():
    assert client.get("/share/does-not-exist").status_code == 404


def test_password_protected_share():
    token = register_and_login()
    scan_id = _create_scan(token)
    share_url = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "s3cret"},
        headers=auth_headers(token),
    ).json()["share_url"]
    share_token = _token_from_url(share_url)

    assert client.get(f"/share/{share_token}").status_code == 401
    assert client.get(f"/share/{share_token}?password=wrong").status_code == 401
    ok = client.get(f"/share/{share_token}?password=s3cret")
    assert ok.status_code == 200
    assert ok.json()["title"] == "Shareable finding"


def test_expired_share_returns_404():
    token = register_and_login()
    scan_id = _create_scan(token)
    share_url = client.post(
        f"/scans/{scan_id}/share", json={}, headers=auth_headers(token)
    ).json()["share_url"]
    share_token = _token_from_url(share_url)

    db = TestingSessionLocal()
    share = db.query(models.SharedReport).filter(
        models.SharedReport.token == share_token
    ).first()
    share.expires_at = datetime.utcnow() - timedelta(hours=1)
    db.commit()
    db.close()

    assert client.get(f"/share/{share_token}").status_code == 404


def test_get_scan_non_owner_blocked():
    # F3: BOLA — a non-owner must not read a scan by ID
    owner = register_and_login("owner3", "owner3@example.com", "pw")
    scan_id = _create_scan(owner)
    other = register_and_login("mallory3", "mallory3@example.com", "pw")
    assert client.get(f"/scans/{scan_id}", headers=auth_headers(other)).status_code == 404
    assert client.get(f"/scans/{scan_id}", headers=auth_headers(owner)).status_code == 200


def test_share_password_rate_limited():
    # F15: password-protected links throttle brute force (SHARE_MAX_ATTEMPTS=3 in tests)
    token = register_and_login()
    scan_id = _create_scan(token)
    share_url = client.post(
        f"/scans/{scan_id}/share", json={"password": "s3cret"}, headers=auth_headers(token)
    ).json()["share_url"]
    t = _token_from_url(share_url)

    for _ in range(3):
        assert client.get(f"/share/{t}?password=wrong").status_code == 401
    # further attempts are throttled — even with the correct password
    assert client.get(f"/share/{t}?password=wrong").status_code == 429
    assert client.get(f"/share/{t}?password=s3cret").status_code == 429
