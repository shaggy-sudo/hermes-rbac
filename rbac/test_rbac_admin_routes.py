"""Standalone smoke test for rbac_admin.register_rbac_admin().

Builds a dummy FastAPI app, registers the routes, and asserts every expected
(method, path) pair exists. Also exercises the admin gate end-to-end with a
fake session via TestClient (admin allowed via HERMES_ADMIN_EMAILS, non-admin
and anonymous get 403).

Run:  python3 rbac/test_rbac_admin_routes.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Make the repo importable regardless of cwd.
REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

# Point HERMES_HOME at a scratch dir and set an admin allowlist BEFORE import.
import tempfile

SCRATCH = tempfile.mkdtemp(prefix="rbac-admin-test-")
os.environ["HERMES_HOME"] = SCRATCH
os.environ["HERMES_ADMIN_EMAILS"] = "boss@acme.com"

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from hermes_cli.dashboard_auth.rbac_admin import register_rbac_admin  # noqa: E402

EXPECTED = {
    ("GET", "/api/rbac/roles"),
    ("GET", "/api/rbac/identities"),
    ("POST", "/api/rbac/assign-role"),
    ("POST", "/api/rbac/permissions"),
    ("GET", "/api/rbac/shared/files"),
    ("POST", "/api/rbac/shared/upload"),
    ("DELETE", "/api/rbac/shared/file"),
    ("GET", "/api/rbac/shared/memory"),
    ("PUT", "/api/rbac/shared/memory"),
    ("GET", "/rbac"),
}


def test_routes_registered():
    app = FastAPI()
    register_rbac_admin(app)
    found = set()
    for r in app.routes:
        for m in getattr(r, "methods", set()) or set():
            found.add((m, r.path))
    missing = EXPECTED - found
    assert not missing, f"missing routes: {sorted(missing)}"
    print(f"[ok] all {len(EXPECTED)} routes registered")


class _FakeSession:
    def __init__(self, email):
        self.email = email


def _app_with_session(email):
    app = FastAPI()

    @app.middleware("http")
    async def attach(request: Request, call_next):
        request.state.session = _FakeSession(email) if email else None
        return await call_next(request)

    register_rbac_admin(app)
    return app


def test_admin_gate():
    # Anonymous -> 403
    anon = TestClient(_app_with_session(None))
    assert anon.get("/api/rbac/roles").status_code == 403
    assert anon.get("/rbac").status_code == 403

    # Non-admin -> 403
    nonadmin = TestClient(_app_with_session("intern@acme.com"))
    assert nonadmin.get("/api/rbac/roles").status_code == 403

    # Admin -> 200 and sees the seeded roles + can flow through writes.
    admin = TestClient(_app_with_session("boss@acme.com"))
    r = admin.get("/api/rbac/roles")
    assert r.status_code == 200, r.text
    names = {x["name"] for x in r.json()["roles"]}
    assert {"admin", "developer", "viewer"} <= names, names

    # Page renders for admin.
    assert admin.get("/rbac").status_code == 200

    # assign-role writes the override file and is reflected in /roles members.
    assert admin.post("/api/rbac/assign-role", json={"email": "dev@acme.com", "role": "developer"}).status_code == 200
    assert (Path(SCRATCH) / "rbac" / "role-overrides.json").exists()

    # Unknown role rejected.
    assert admin.post("/api/rbac/assign-role", json={"email": "x@acme.com", "role": "nope"}).status_code == 404

    # permissions: set viewer to read-only, confirm it surfaces in /roles.
    assert admin.post("/api/rbac/permissions", json={"role": "viewer", "shared_access": "ro"}).status_code == 200
    viewer = next(x for x in admin.get("/api/rbac/roles").json()["roles"] if x["name"] == "viewer")
    assert viewer["shared_access"] == "ro", viewer

    # shared files: empty dir, then upload, list, read memory, delete.
    assert admin.get("/api/rbac/shared/files", params={"role": "developer"}).json()["entries"] == []
    import base64
    payload = base64.b64encode(b"hello shared").decode()
    assert admin.post("/api/rbac/shared/upload",
                      json={"role": "developer", "path": "notes.txt", "content": payload}).status_code == 200
    names = {e["name"] for e in admin.get("/api/rbac/shared/files", params={"role": "developer"}).json()["entries"]}
    assert "notes.txt" in names, names

    # path traversal is refused.
    assert admin.post("/api/rbac/shared/upload",
                      json={"role": "developer", "path": "../escape.txt", "content": payload}).status_code == 400

    # memory put/get round-trips.
    assert admin.put("/api/rbac/shared/memory",
                     json={"role": "developer", "text": "# Dev memory\n"}).status_code == 200
    assert admin.get("/api/rbac/shared/memory", params={"role": "developer"}).json()["text"] == "# Dev memory\n"

    # delete the uploaded file.
    assert admin.request("DELETE", "/api/rbac/shared/file",
                         params={"role": "developer", "path": "notes.txt"}).status_code == 200
    print("[ok] admin gate + CRUD flows pass")


if __name__ == "__main__":
    test_routes_registered()
    test_admin_gate()
    print("\nALL TESTS PASSED")
