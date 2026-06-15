"""Shared Management — an ADMIN-ONLY dashboard surface for the RBAC layer.

Adds a self-contained admin console (HTML at ``/rbac``) backed by a small JSON
API under ``/api/rbac/*`` for:

  1. Roles & members      — roles from ``rbac/roles.yaml`` + members derived from
                            the captured Google identities + each member's
                            *effective* role; assign/override a user's role.
  2. Captured identities  — the raw records under
                            ``<HERMES_HOME>/rbac/identities/*.json``.
  3. Shared volume files  — browse / upload / delete files under
                            ``<HERMES_HOME>/shared/<role>`` (path-traversal
                            confined to that role's directory).
  4. Shared role memory   — read / edit ``<HERMES_HOME>/shared/<role>/MEMORY.md``.
  5. Permissions          — per-role read-write vs read-only flag for the shared
                            volume, persisted to a side JSON
                            (``<HERMES_HOME>/rbac/shared-access.json``) so the
                            committed ``roles.yaml`` stays untouched. The flag
                            also honours a ``shared_access: rw|ro`` key if one is
                            present in ``roles.yaml`` (side JSON wins).

Every handler enforces admin: it reads ``request.state.session`` (may be None),
extracts ``.email`` and requires :func:`rbac_map.is_admin`. Non-admins (and
unauthenticated requests) get a 403.

Self-contained: stdlib + PyYAML + FastAPI only. The HTML/CSS/JS is inline and
needs no build step (vanilla ``fetch()``). Register from ``web_server.py`` with
``register_rbac_admin(app)``.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # FastAPI is always present in the dashboard; keep imports defensive.
    from fastapi import HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
except Exception:  # pragma: no cover - exercised only without fastapi installed
    HTTPException = Request = HTMLResponse = JSONResponse = None  # type: ignore

import yaml

from hermes_cli.dashboard_auth import rbac_map

try:
    from hermes_constants import get_hermes_home
except Exception:  # pragma: no cover - fallback mirrors the constant's default
    def get_hermes_home() -> Path:  # type: ignore[misc]
        env = os.environ.get("HERMES_HOME", "").strip()
        return Path(env) if env else (Path.home() / ".hermes")


# Cap inline uploads so a single base64 blob can't exhaust memory.
_MAX_UPLOAD_BYTES = 25 * 1024 * 1024
# Cap MEMORY.md so the editor textarea stays sane.
_MAX_MEMORY_BYTES = 1 * 1024 * 1024


# --------------------------------------------------------------------------- #
# Paths                                                                        #
# --------------------------------------------------------------------------- #


def _home() -> Path:
    return Path(get_hermes_home())


def _roles_yaml_path() -> Path:
    """Locate ``roles.yaml``. The repo ships it at ``rbac/roles.yaml`` next to
    the install dir; on deployed boxes it lives under the install dir. Prefer
    ``HERMES_INSTALL_DIR`` (same env the auto-provision path uses), then fall
    back to the package-relative copy used in dev."""
    install = os.environ.get("HERMES_INSTALL_DIR", "/opt/hermes")
    candidates = [
        Path(install) / "rbac" / "roles.yaml",
        # dev checkout: <repo>/rbac/roles.yaml (this file is at
        # <repo>/hermes_cli/dashboard_auth/rbac_admin.py)
        Path(__file__).resolve().parents[2] / "rbac" / "roles.yaml",
        _home() / "rbac" / "roles.yaml",
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[0]


def _identities_dir() -> Path:
    return _home() / "rbac" / "identities"


def _overrides_path() -> Path:
    return _home() / "rbac" / "role-overrides.json"


def _shared_access_path() -> Path:
    return _home() / "rbac" / "shared-access.json"


def _shared_root() -> Path:
    return _home() / "shared"


def _role_dir(role: str) -> Path:
    """Resolved shared directory for ``role``. ``role`` is validated to a plain
    segment first so it can't itself escape ``<home>/shared``."""
    safe = _safe_role(role)
    return (_shared_root() / safe).resolve()


# --------------------------------------------------------------------------- #
# Validation / IO helpers                                                      #
# --------------------------------------------------------------------------- #


def _safe_role(role: Any) -> str:
    r = str(role or "").strip()
    if not r or r in (".", "..") or "/" in r or "\\" in r or "\0" in r:
        raise HTTPException(status_code=400, detail="Invalid role")
    return r


def _known_roles() -> List[str]:
    return list(_load_roles_yaml().keys())


def _require_known_role(role: str) -> str:
    r = _safe_role(role)
    if r not in _known_roles():
        raise HTTPException(status_code=404, detail=f"Unknown role: {r}")
    return r


def _load_roles_yaml() -> Dict[str, Any]:
    path = _roles_yaml_path()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        return {}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Could not read roles.yaml: {exc}")
    roles = data.get("roles") if isinstance(data, dict) else None
    return roles if isinstance(roles, dict) else {}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except Exception:  # noqa: BLE001 - corrupt side file shouldn't 500 the page
        return None


def _load_overrides() -> Dict[str, str]:
    data = _load_json(_overrides_path())
    if not isinstance(data, dict):
        return {}
    return {str(k).strip().lower(): str(v).strip() for k, v in data.items() if v}


def _load_shared_access() -> Dict[str, str]:
    data = _load_json(_shared_access_path())
    if not isinstance(data, dict):
        return {}
    out: Dict[str, str] = {}
    for k, v in data.items():
        val = str(v).strip().lower()
        if val in ("rw", "ro"):
            out[str(k).strip()] = val
    return out


def _effective_role(email: str, overrides: Dict[str, str]) -> str:
    """Effective role for a member: admin allowlist wins, then an override,
    then the rbac_map default. Mirrors the patched ``role_for_email`` so the
    console shows what the system will actually enforce."""
    e = email.strip().lower()
    if rbac_map.is_admin(e):
        return "admin"
    if e in overrides:
        return overrides[e]
    return rbac_map.role_for_email(e)


def _shared_access_for(role: str, yaml_roles: Dict[str, Any], side: Dict[str, str]) -> str:
    """rw|ro for a role's shared volume. Side JSON wins; else the yaml
    ``shared_access`` key; else default rw."""
    if role in side:
        return side[role]
    spec = yaml_roles.get(role) or {}
    val = str(spec.get("shared_access", "")).strip().lower() if isinstance(spec, dict) else ""
    return val if val in ("rw", "ro") else "rw"


def _members_by_role(overrides: Dict[str, str]) -> Dict[str, List[str]]:
    """email lists keyed by effective role, derived from captured identities."""
    out: Dict[str, List[str]] = {}
    for rec in _iter_identities():
        email = (rec.get("email") or "").strip()
        if not email:
            continue
        role = _effective_role(email, overrides)
        out.setdefault(role, [])
        if email not in out[role]:
            out[role].append(email)
    for v in out.values():
        v.sort()
    return out


def _iter_identities() -> List[Dict[str, Any]]:
    d = _identities_dir()
    records: List[Dict[str, Any]] = []
    if not d.is_dir():
        return records
    for f in sorted(d.glob("*.json")):
        rec = _load_json(f)
        if isinstance(rec, dict):
            records.append(rec)
    return records


def _resolve_under_role(role: str, rel_path: str) -> Path:
    """Resolve ``rel_path`` under the role's shared dir, refusing traversal.

    Returns the resolved absolute path. The role dir itself need not exist yet
    (callers that write will create it); confinement is enforced by comparing
    resolved prefixes against the resolved role dir."""
    role_dir = _role_dir(role)
    raw = str(rel_path or "").strip().lstrip("/\\")
    if "\0" in raw:
        raise HTTPException(status_code=400, detail="Invalid path")
    # Reject explicit parent refs up front for a clear error; the prefix check
    # below is the actual security boundary.
    parts = [p for p in raw.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise HTTPException(status_code=400, detail="Path cannot contain '..'")
    candidate = (role_dir / Path(*parts)).resolve() if parts else role_dir
    if candidate != role_dir and role_dir not in candidate.parents:
        raise HTTPException(status_code=403, detail="Path outside the role's shared space")
    return candidate


# --------------------------------------------------------------------------- #
# Admin gate                                                                   #
# --------------------------------------------------------------------------- #


def _require_admin(request: "Request") -> str:
    session = getattr(request.state, "session", None)
    email = (getattr(session, "email", "") or "").strip() if session is not None else ""
    if email and rbac_map.is_admin(email):
        return email
    # Router model: per-user containers run --insecure (no in-container
    # session). The trusted router spawns the ADMIN's container with
    # HERMES_RBAC_ADMIN_EMAIL set, vouching for an authenticated admin. Only
    # the router sets container env (users never can), so honoring it does not
    # weaken the gate.
    # Trust the router's vouch directly: it sets HERMES_RBAC_ADMIN_EMAIL only
    # for a Google-authenticated admin, and the per-user container has no
    # HERMES_ADMIN_EMAILS list of its own to re-check against.
    vouched = os.environ.get("HERMES_RBAC_ADMIN_EMAIL", "").strip()
    if vouched:
        return vouched
    raise HTTPException(status_code=403, detail="Admin only")


# --------------------------------------------------------------------------- #
# Registration                                                                 #
# --------------------------------------------------------------------------- #


def register_rbac_admin(app) -> None:
    """Attach the Shared Management routes to ``app``. Idempotent-ish: safe to
    call once during dashboard startup right after ``app = FastAPI(...)``."""

    @app.get("/api/rbac/roles")
    async def rbac_roles(request: Request):  # noqa: ANN001
        _require_admin(request)
        yaml_roles = _load_roles_yaml()
        overrides = _load_overrides()
        side = _load_shared_access()
        members = _members_by_role(overrides)
        roles_out: List[Dict[str, Any]] = []
        for name, spec in yaml_roles.items():
            spec = spec if isinstance(spec, dict) else {}
            roles_out.append(
                {
                    "name": name,
                    "toolsets": spec.get("toolsets", []),
                    "backend": spec.get("backend", ""),
                    "shared_skills": spec.get("shared_skills", []),
                    "description": spec.get("description", ""),
                    "shared_access": _shared_access_for(name, yaml_roles, side),
                    "members": members.get(name, []),
                }
            )
        return {"roles": roles_out}

    @app.get("/api/rbac/identities")
    async def rbac_identities(request: Request):  # noqa: ANN001
        _require_admin(request)
        overrides = _load_overrides()
        out = []
        for rec in _iter_identities():
            email = (rec.get("email") or "").strip()
            out.append(
                {
                    "sub": rec.get("sub"),
                    "email": email,
                    "name": rec.get("name"),
                    "picture": rec.get("picture"),
                    "hd": rec.get("hd"),
                    "email_verified": rec.get("email_verified"),
                    "granted_scopes": rec.get("granted_scopes"),
                    "first_seen": rec.get("first_seen"),
                    "last_login": rec.get("last_login"),
                    "login_count": rec.get("login_count"),
                    "effective_role": _effective_role(email, overrides) if email else None,
                }
            )
        return {"identities": out}

    @app.post("/api/rbac/assign-role")
    async def rbac_assign_role(request: Request):  # noqa: ANN001
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body must be JSON")
        email = str((body or {}).get("email", "")).strip().lower()
        role = str((body or {}).get("role", "")).strip()
        if not email:
            raise HTTPException(status_code=400, detail="email is required")
        role = _require_known_role(role)
        overrides = _load_overrides()
        overrides[email] = role
        path = _overrides_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(overrides, indent=2, sort_keys=True), encoding="utf-8")
        return {"ok": True, "email": email, "role": role, "overrides": overrides}

    @app.post("/api/rbac/permissions")
    async def rbac_permissions(request: Request):  # noqa: ANN001
        """Set a role's shared-volume access flag (rw|ro) in the side JSON."""
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body must be JSON")
        role = _require_known_role(str((body or {}).get("role", "")))
        access = str((body or {}).get("shared_access", "")).strip().lower()
        if access not in ("rw", "ro"):
            raise HTTPException(status_code=400, detail="shared_access must be 'rw' or 'ro'")
        side = _load_shared_access()
        side[role] = access
        path = _shared_access_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(side, indent=2, sort_keys=True), encoding="utf-8")
        return {"ok": True, "role": role, "shared_access": access, "shared_access_map": side}

    @app.get("/api/rbac/shared/files")
    async def rbac_shared_files(request: Request, role: str, path: str = ""):  # noqa: ANN001
        _require_admin(request)
        role = _require_known_role(role)
        target = _resolve_under_role(role, path)
        if not target.exists():
            # Empty/uninitialised shared dir is a normal state, not an error.
            return {"role": role, "path": path, "entries": []}
        if not target.is_dir():
            raise HTTPException(status_code=400, detail="Path is not a directory")
        entries = []
        for child in sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            try:
                st = child.stat()
                entries.append(
                    {
                        "name": child.name,
                        "is_dir": child.is_dir(),
                        "size": st.st_size if child.is_file() else None,
                        "mtime": int(st.st_mtime),
                    }
                )
            except OSError:
                continue
        return {"role": role, "path": path, "entries": entries}

    @app.post("/api/rbac/shared/upload")
    async def rbac_shared_upload(request: Request):  # noqa: ANN001
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body must be JSON")
        role = _require_known_role(str((body or {}).get("role", "")))
        rel = str((body or {}).get("path", "")).strip()
        if not rel:
            raise HTTPException(status_code=400, detail="path is required")
        raw_content = (body or {}).get("content", "")
        # Accept either bare base64 or a data: URL.
        content = str(raw_content)
        if content.startswith("data:"):
            _, _, content = content.partition(",")
        try:
            data = base64.b64decode(content, validate=False)
        except Exception:
            raise HTTPException(status_code=400, detail="content must be base64")
        if len(data) > _MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File too large")
        target = _resolve_under_role(role, rel)
        if target == _role_dir(role):
            raise HTTPException(status_code=400, detail="path must name a file")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return {"ok": True, "role": role, "path": rel, "size": len(data)}

    @app.delete("/api/rbac/shared/file")
    async def rbac_shared_delete(request: Request, role: str, path: str):  # noqa: ANN001
        _require_admin(request)
        role = _require_known_role(role)
        target = _resolve_under_role(role, path)
        if target == _role_dir(role):
            raise HTTPException(status_code=400, detail="Refusing to delete the role root")
        if not target.exists():
            raise HTTPException(status_code=404, detail="Not found")
        try:
            if target.is_dir():
                import shutil

                shutil.rmtree(target)
            else:
                target.unlink()
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"Could not delete: {exc}")
        return {"ok": True, "role": role, "path": path}

    @app.get("/api/rbac/shared/memory")
    async def rbac_shared_memory_get(request: Request, role: str):  # noqa: ANN001
        _require_admin(request)
        role = _require_known_role(role)
        mem = _resolve_under_role(role, "MEMORY.md")
        text = ""
        if mem.exists() and mem.is_file():
            try:
                text = mem.read_text(encoding="utf-8")
            except Exception as exc:  # noqa: BLE001
                raise HTTPException(status_code=500, detail=f"Could not read MEMORY.md: {exc}")
        return {"role": role, "exists": mem.exists(), "text": text}

    @app.put("/api/rbac/shared/memory")
    async def rbac_shared_memory_put(request: Request):  # noqa: ANN001
        _require_admin(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body must be JSON")
        role = _require_known_role(str((body or {}).get("role", "")))
        text = (body or {}).get("text", "")
        if not isinstance(text, str):
            raise HTTPException(status_code=400, detail="text must be a string")
        if len(text.encode("utf-8")) > _MAX_MEMORY_BYTES:
            raise HTTPException(status_code=413, detail="MEMORY.md too large")
        mem = _resolve_under_role(role, "MEMORY.md")
        mem.parent.mkdir(parents=True, exist_ok=True)
        mem.write_text(text, encoding="utf-8")
        return {"ok": True, "role": role, "bytes": len(text.encode("utf-8"))}

    @app.get("/rbac")
    async def rbac_admin_page(request: Request):  # noqa: ANN001
        _require_admin(request)
        return HTMLResponse(_PAGE_HTML)


# --------------------------------------------------------------------------- #
# Self-contained admin page (inline CSS/JS, vanilla fetch, dark theme)         #
# --------------------------------------------------------------------------- #

_PAGE_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Shared Management — Hermes RBAC</title>
<style>
  :root {
    --bg:#0e1116; --panel:#161b22; --panel2:#1c2230; --border:#2a313c;
    --text:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --danger:#f85149;
    --ok:#3fb950; --warn:#d29922;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
    font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  header { padding:16px 24px; border-bottom:1px solid var(--border);
    display:flex; align-items:center; gap:12px; }
  header h1 { font-size:16px; margin:0; font-weight:600; }
  header .sub { color:var(--muted); font-size:12px; }
  nav { display:flex; gap:4px; padding:0 24px; border-bottom:1px solid var(--border);
    background:var(--panel); }
  nav button { background:none; border:none; color:var(--muted); padding:12px 14px;
    cursor:pointer; font-size:13px; border-bottom:2px solid transparent; }
  nav button:hover { color:var(--text); }
  nav button.active { color:var(--text); border-bottom-color:var(--accent); }
  main { padding:24px; max-width:1100px; }
  .tab { display:none; }
  .tab.active { display:block; }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:8px;
    padding:16px; margin-bottom:16px; }
  .card h2 { margin:0 0 4px; font-size:14px; }
  .card .desc { color:var(--muted); font-size:12px; margin-bottom:10px; }
  .row { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--border);
    vertical-align:top; }
  th { color:var(--muted); font-weight:600; font-size:12px; }
  code,.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px; }
  .tag { display:inline-block; background:var(--panel2); border:1px solid var(--border);
    border-radius:12px; padding:1px 8px; font-size:11px; margin:1px 2px; }
  .pill { border-radius:10px; padding:1px 8px; font-size:11px; font-weight:600; }
  .pill.rw { background:rgba(63,185,80,.15); color:var(--ok); }
  .pill.ro { background:rgba(210,153,34,.15); color:var(--warn); }
  button.btn, select, input, textarea {
    background:var(--panel2); color:var(--text); border:1px solid var(--border);
    border-radius:6px; padding:6px 10px; font-size:13px; }
  button.btn { cursor:pointer; }
  button.btn:hover { border-color:var(--accent); }
  button.btn.primary { background:var(--accent); color:#0d1117; border-color:var(--accent); font-weight:600; }
  button.btn.danger { color:var(--danger); }
  button.btn.danger:hover { border-color:var(--danger); }
  textarea { width:100%; min-height:340px; resize:vertical; font-family:ui-monospace,Menlo,Consolas,monospace; }
  .muted { color:var(--muted); }
  .crumbs { font-size:12px; margin-bottom:10px; }
  .crumbs a { color:var(--accent); cursor:pointer; text-decoration:none; }
  .toast { position:fixed; bottom:20px; right:20px; background:var(--panel2);
    border:1px solid var(--border); padding:10px 14px; border-radius:8px; font-size:13px;
    opacity:0; transform:translateY(8px); transition:.2s; pointer-events:none; max-width:380px; }
  .toast.show { opacity:1; transform:none; }
  .toast.err { border-color:var(--danger); color:var(--danger); }
  .toast.ok { border-color:var(--ok); }
  .avatar { width:22px; height:22px; border-radius:50%; vertical-align:middle; margin-right:6px; }
  .spacer { flex:1; }
  .small { font-size:11px; }
</style>
</head>
<body>
<header>
  <h1>Shared Management</h1>
  <span class="sub">Hermes RBAC · admin only</span>
</header>
<nav>
  <button data-tab="roles" class="active">Roles &amp; Members</button>
  <button data-tab="identities">Identities</button>
  <button data-tab="files">Shared Files</button>
  <button data-tab="memory">Shared Memory</button>
  <button data-tab="perms">Permissions</button>
</nav>
<main>
  <section id="tab-roles" class="tab active">
    <div class="card">
      <h2>Roles &amp; Members</h2>
      <div class="desc">Roles from <code>roles.yaml</code>, members from captured identities,
        and each user's effective role. Assign an override below.</div>
      <div id="roles-body" class="muted">Loading…</div>
    </div>
    <div class="card">
      <h2>Assign / override a role</h2>
      <div class="row">
        <input id="assign-email" placeholder="user@company.com" style="min-width:260px"/>
        <select id="assign-role"></select>
        <button class="btn primary" id="assign-go">Assign</button>
      </div>
      <div class="desc" style="margin-top:8px">Writes <code>rbac/role-overrides.json</code>.
        The admin allowlist always wins for admins.</div>
    </div>
  </section>

  <section id="tab-identities" class="tab">
    <div class="card">
      <h2>Captured Google identities</h2>
      <div class="desc">From <code>&lt;HERMES_HOME&gt;/rbac/identities/*.json</code>.</div>
      <div id="ident-body" class="muted">Loading…</div>
    </div>
  </section>

  <section id="tab-files" class="tab">
    <div class="card">
      <h2>Shared volume files</h2>
      <div class="row">
        <label class="small muted">Role</label>
        <select id="files-role"></select>
        <span class="spacer"></span>
        <input type="file" id="files-upload-input"/>
        <button class="btn" id="files-upload-go">Upload here</button>
      </div>
      <div class="crumbs" id="files-crumbs"></div>
      <div id="files-body" class="muted">Pick a role…</div>
    </div>
  </section>

  <section id="tab-memory" class="tab">
    <div class="card">
      <h2>Shared role memory — MEMORY.md</h2>
      <div class="row">
        <label class="small muted">Role</label>
        <select id="mem-role"></select>
        <button class="btn" id="mem-reload">Reload</button>
        <span class="spacer"></span>
        <button class="btn primary" id="mem-save">Save</button>
      </div>
      <div class="desc" id="mem-status"></div>
      <textarea id="mem-text" placeholder="# Shared memory for this role…"></textarea>
    </div>
  </section>

  <section id="tab-perms" class="tab">
    <div class="card">
      <h2>Shared-volume permissions</h2>
      <div class="desc">Per-role read-write vs read-only flag for the shared volume.
        Stored in <code>rbac/shared-access.json</code> (leaves <code>roles.yaml</code> untouched).</div>
      <div id="perms-body" class="muted">Loading…</div>
    </div>
  </section>
</main>
<div id="toast" class="toast"></div>

<script>
const $ = (s, r=document) => r.querySelector(s);
const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));
let ROLES = [];

function toast(msg, kind) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show ' + (kind || '');
  clearTimeout(t._t);
  t._t = setTimeout(() => { t.className = 'toast ' + (kind || ''); }, 3200);
}
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function fmtTime(epoch) {
  if (!epoch) return '—';
  try { return new Date(epoch * 1000).toLocaleString(); } catch(e) { return String(epoch); }
}
function fmtSize(n) {
  if (n == null) return '';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n/1024).toFixed(1) + ' KB';
  return (n/1048576).toFixed(1) + ' MB';
}
async function api(method, url, body) {
  const opts = { method, headers: {} };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(url, opts);
  let data = null;
  try { data = await r.json(); } catch(e) {}
  if (!r.ok) { throw new Error((data && data.detail) || (r.status + ' ' + r.statusText)); }
  return data;
}

// ---- tabs ----
$$('nav button').forEach(b => b.onclick = () => {
  $$('nav button').forEach(x => x.classList.remove('active'));
  $$('.tab').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  $('#tab-' + b.dataset.tab).classList.add('active');
  if (b.dataset.tab === 'identities') loadIdentities();
  if (b.dataset.tab === 'files') loadFiles();
  if (b.dataset.tab === 'perms') loadPerms();
  if (b.dataset.tab === 'memory') loadMemory();
});

// ---- roles & members ----
async function loadRoles() {
  try {
    const d = await api('GET', '/api/rbac/roles');
    ROLES = d.roles || [];
    populateRoleSelects();
    renderRoles();
  } catch(e) { toast('Roles: ' + e.message, 'err'); $('#roles-body').textContent = e.message; }
}
function populateRoleSelects() {
  const opts = ROLES.map(r => `<option value="${esc(r.name)}">${esc(r.name)}</option>`).join('');
  ['#assign-role', '#files-role', '#mem-role'].forEach(sel => {
    const el = $(sel); if (el) el.innerHTML = opts;
  });
}
function renderRoles() {
  let h = '<table><thead><tr><th>Role</th><th>Backend</th><th>Toolsets</th>' +
          '<th>Shared skills</th><th>Access</th><th>Members</th></tr></thead><tbody>';
  for (const r of ROLES) {
    const toolsets = (r.toolsets || []).map(t => `<span class="tag">${esc(t)}</span>`).join(' ');
    const skills = (r.shared_skills || []).map(t => `<span class="tag">${esc(t)}</span>`).join(' ');
    const members = (r.members || []).length
      ? r.members.map(m => `<div class="mono small">${esc(m)}</div>`).join('')
      : '<span class="muted small">none</span>';
    h += `<tr><td><b>${esc(r.name)}</b><div class="muted small">${esc(r.description||'')}</div></td>` +
         `<td><code>${esc(r.backend)}</code></td><td>${toolsets}</td><td>${skills}</td>` +
         `<td><span class="pill ${esc(r.shared_access)}">${esc(r.shared_access)}</span></td>` +
         `<td>${members}</td></tr>`;
  }
  h += '</tbody></table>';
  $('#roles-body').innerHTML = h;
}
$('#assign-go').onclick = async () => {
  const email = $('#assign-email').value.trim();
  const role = $('#assign-role').value;
  if (!email) { toast('Enter an email', 'err'); return; }
  try {
    await api('POST', '/api/rbac/assign-role', { email, role });
    toast('Assigned ' + email + ' → ' + role, 'ok');
    $('#assign-email').value = '';
    loadRoles();
  } catch(e) { toast('Assign: ' + e.message, 'err'); }
};

// ---- identities ----
async function loadIdentities() {
  try {
    const d = await api('GET', '/api/rbac/identities');
    const recs = d.identities || [];
    if (!recs.length) { $('#ident-body').textContent = 'No identities captured yet.'; return; }
    let h = '<table><thead><tr><th>User</th><th>Email</th><th>Domain</th>' +
            '<th>Effective role</th><th>Logins</th><th>First seen</th><th>Last login</th></tr></thead><tbody>';
    for (const r of recs) {
      const pic = r.picture ? `<img class="avatar" src="${esc(r.picture)}" referrerpolicy="no-referrer"/>` : '';
      h += `<tr><td>${pic}${esc(r.name||'')}</td><td class="mono">${esc(r.email||'')}` +
           (r.email_verified ? '' : ' <span class="pill ro">unverified</span>') + `</td>` +
           `<td>${esc(r.hd||'—')}</td><td><span class="tag">${esc(r.effective_role||'?')}</span></td>` +
           `<td>${esc(r.login_count==null?'—':r.login_count)}</td>` +
           `<td class="small muted">${fmtTime(r.first_seen)}</td>` +
           `<td class="small muted">${fmtTime(r.last_login)}</td></tr>`;
    }
    h += '</tbody></table>';
    $('#ident-body').innerHTML = h;
  } catch(e) { toast('Identities: ' + e.message, 'err'); $('#ident-body').textContent = e.message; }
}

// ---- shared files ----
let filesState = { role: null, path: '' };
function currentFilesRole() { return $('#files-role').value; }
$('#files-role').onchange = () => { filesState.path=''; loadFiles(); };
async function loadFiles() {
  const role = currentFilesRole();
  if (!role) { $('#files-body').textContent = 'Pick a role…'; return; }
  filesState.role = role;
  try {
    const d = await api('GET', `/api/rbac/shared/files?role=${encodeURIComponent(role)}&path=${encodeURIComponent(filesState.path)}`);
    renderCrumbs();
    const e = d.entries || [];
    if (!e.length) { $('#files-body').innerHTML = '<span class="muted">Empty directory.</span>'; return; }
    let h = '<table><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>';
    for (const it of e) {
      const name = it.is_dir
        ? `<a href="#" data-dir="${esc(it.name)}">📁 ${esc(it.name)}/</a>`
        : `📄 ${esc(it.name)}`;
      h += `<tr><td>${name}</td><td class="small muted">${it.is_dir?'':fmtSize(it.size)}</td>` +
           `<td class="small muted">${fmtTime(it.mtime)}</td>` +
           `<td><button class="btn danger small" data-del="${esc(it.name)}">delete</button></td></tr>`;
    }
    h += '</tbody></table>';
    $('#files-body').innerHTML = h;
    $$('#files-body a[data-dir]').forEach(a => a.onclick = ev => {
      ev.preventDefault();
      filesState.path = (filesState.path ? filesState.path + '/' : '') + a.dataset.dir;
      loadFiles();
    });
    $$('#files-body button[data-del]').forEach(b => b.onclick = () => delFile(b.dataset.del));
  } catch(e) { toast('Files: ' + e.message, 'err'); $('#files-body').textContent = e.message; }
}
function renderCrumbs() {
  const parts = filesState.path ? filesState.path.split('/') : [];
  let acc = '';
  let h = `<a data-go="">${esc(filesState.role)}</a>`;
  parts.forEach((p, i) => {
    acc = acc ? acc + '/' + p : p;
    h += ` / <a data-go="${esc(acc)}">${esc(p)}</a>`;
  });
  $('#files-crumbs').innerHTML = h;
  $$('#files-crumbs a').forEach(a => a.onclick = ev => {
    ev.preventDefault(); filesState.path = a.dataset.go; loadFiles();
  });
}
async function delFile(name) {
  if (!confirm('Delete "' + name + '"?')) return;
  const rel = (filesState.path ? filesState.path + '/' : '') + name;
  try {
    await api('DELETE', `/api/rbac/shared/file?role=${encodeURIComponent(filesState.role)}&path=${encodeURIComponent(rel)}`);
    toast('Deleted ' + name, 'ok'); loadFiles();
  } catch(e) { toast('Delete: ' + e.message, 'err'); }
}
$('#files-upload-go').onclick = () => {
  const inp = $('#files-upload-input');
  const f = inp.files && inp.files[0];
  if (!f) { toast('Choose a file first', 'err'); return; }
  const reader = new FileReader();
  reader.onload = async () => {
    const b64 = String(reader.result).split(',')[1] || '';
    const rel = (filesState.path ? filesState.path + '/' : '') + f.name;
    try {
      await api('POST', '/api/rbac/shared/upload', { role: filesState.role, path: rel, content: b64 });
      toast('Uploaded ' + f.name, 'ok'); inp.value=''; loadFiles();
    } catch(e) { toast('Upload: ' + e.message, 'err'); }
  };
  reader.readAsDataURL(f);
};

// ---- shared memory ----
$('#mem-role').onchange = loadMemory;
$('#mem-reload').onclick = loadMemory;
async function loadMemory() {
  const role = $('#mem-role').value;
  if (!role) return;
  try {
    const d = await api('GET', `/api/rbac/shared/memory?role=${encodeURIComponent(role)}`);
    $('#mem-text').value = d.text || '';
    $('#mem-status').textContent = d.exists ? 'Loaded MEMORY.md for ' + role : 'No MEMORY.md yet for ' + role + ' (saving creates it).';
  } catch(e) { toast('Memory: ' + e.message, 'err'); }
}
$('#mem-save').onclick = async () => {
  const role = $('#mem-role').value;
  try {
    await api('PUT', '/api/rbac/shared/memory', { role, text: $('#mem-text').value });
    toast('Saved MEMORY.md for ' + role, 'ok');
    $('#mem-status').textContent = 'Saved MEMORY.md for ' + role;
  } catch(e) { toast('Save: ' + e.message, 'err'); }
};

// ---- permissions ----
async function loadPerms() {
  if (!ROLES.length) { try { await loadRoles(); } catch(e){} }
  let h = '<table><thead><tr><th>Role</th><th>Shared volume access</th><th></th></tr></thead><tbody>';
  for (const r of ROLES) {
    h += `<tr><td><b>${esc(r.name)}</b></td>` +
         `<td><select data-perm-role="${esc(r.name)}">` +
         `<option value="rw"${r.shared_access==='rw'?' selected':''}>read-write (rw)</option>` +
         `<option value="ro"${r.shared_access==='ro'?' selected':''}>read-only (ro)</option>` +
         `</select></td>` +
         `<td><button class="btn primary small" data-perm-save="${esc(r.name)}">Save</button></td></tr>`;
  }
  h += '</tbody></table>';
  $('#perms-body').innerHTML = h;
  $$('#perms-body button[data-perm-save]').forEach(b => b.onclick = async () => {
    const role = b.dataset.permSave;
    const sel = $(`select[data-perm-role="${role}"]`);
    try {
      await api('POST', '/api/rbac/permissions', { role, shared_access: sel.value });
      toast(role + ' → ' + sel.value, 'ok');
      loadRoles();
    } catch(e) { toast('Permissions: ' + e.message, 'err'); }
  });
}

loadRoles();
</script>
</body>
</html>
"""
