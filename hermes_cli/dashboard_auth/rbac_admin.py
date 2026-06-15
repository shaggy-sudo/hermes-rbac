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
    from fastapi.responses import HTMLResponse, JSONResponse, Response
except Exception:  # pragma: no cover - exercised only without fastapi installed
    HTTPException = Request = HTMLResponse = JSONResponse = Response = None  # type: ignore

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
# Reject the request body early (before buffering/parsing) when its declared
# Content-Length exceeds this. base64 inflates by ~4/3 and JSON adds quoting,
# so allow some headroom over _MAX_UPLOAD_BYTES.
_MAX_BODY_BYTES = 34 * 1024 * 1024
# Cap MEMORY.md so the editor textarea stays sane.
_MAX_MEMORY_BYTES = 1 * 1024 * 1024
# Cap inline file downloads/views so a single read can't exhaust memory.
_MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024

# Terminal execution backends accepted when creating/editing a role.
_KNOWN_BACKENDS = ("docker", "local")
# Built-in roles that must always exist; refuse to delete them.
_BUILTIN_ROLES = ("admin", "viewer")


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


def _coerce_role_spec(body: Dict[str, Any], base: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Validate + normalise a role spec from a request body. ``base`` (the
    existing spec on edit) supplies defaults for omitted keys. Returns a plain
    dict safe to write into roles.yaml's ``roles`` map."""
    base = dict(base) if isinstance(base, dict) else {}
    out: Dict[str, Any] = dict(base)

    if "toolsets" in body:
        ts = body.get("toolsets")
        if not isinstance(ts, list) or any(not isinstance(t, str) for t in ts):
            raise HTTPException(status_code=400, detail="toolsets must be a list of strings")
        out["toolsets"] = [t.strip() for t in ts if str(t).strip()]
    elif "toolsets" not in out:
        out["toolsets"] = []

    if "backend" in body:
        backend = str(body.get("backend", "")).strip().lower()
        if backend not in _KNOWN_BACKENDS:
            raise HTTPException(
                status_code=400,
                detail=f"backend must be one of: {', '.join(_KNOWN_BACKENDS)}",
            )
        out["backend"] = backend
    elif "backend" not in out:
        out["backend"] = "docker"

    if "shared_skills" in body:
        ss = body.get("shared_skills")
        if not isinstance(ss, list) or any(not isinstance(s, str) for s in ss):
            raise HTTPException(status_code=400, detail="shared_skills must be a list of strings")
        out["shared_skills"] = [s.strip() for s in ss if str(s).strip()]
    elif "shared_skills" not in out:
        out["shared_skills"] = []

    if "description" in body:
        out["description"] = str(body.get("description", "") or "")

    if "shared_access" in body:
        sa = str(body.get("shared_access", "")).strip().lower()
        if sa not in ("rw", "ro"):
            raise HTTPException(status_code=400, detail="shared_access must be 'rw' or 'ro'")
        out["shared_access"] = sa

    return out


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


def _load_roles_document() -> Dict[str, Any]:
    """Load the whole roles.yaml document (not just the ``roles`` map) so a
    write can mutate the roles dict in place and re-dump the rest. Note: a full
    YAML round-trip with PyYAML does not preserve comments — acceptable here."""
    path = _roles_yaml_path()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except FileNotFoundError:
        data = {}
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Could not read roles.yaml: {exc}")
    if not isinstance(data, dict):
        data = {}
    if not isinstance(data.get("roles"), dict):
        data["roles"] = {}
    return data


def _write_roles_document(doc: Dict[str, Any]) -> None:
    """Persist the full roles.yaml document. PyYAML drops comments on a
    round-trip; the output stays valid YAML with stable key order."""
    path = _roles_yaml_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.write_text(
            yaml.safe_dump(doc, sort_keys=False, default_flow_style=False, allow_unicode=True),
            encoding="utf-8",
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Could not write roles.yaml: {exc}")


def _guard_body_size(request: "Request") -> None:
    """Reject an oversized request body up front using the declared
    Content-Length, before ``request.json()`` buffers and parses it. This is a
    cheap DoS guard for the base64-in-JSON upload and the MEMORY.md PUT."""
    raw = request.headers.get("content-length", "")
    try:
        length = int(raw)
    except (TypeError, ValueError):
        return
    if length > _MAX_BODY_BYTES:
        raise HTTPException(status_code=413, detail="Request body too large")


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


def _admin_emails() -> frozenset:
    """All emails treated as admin when computing effective roles. Inside a
    per-user admin container ``HERMES_ADMIN_EMAILS`` is empty, so the logged-in
    admin's own vouched email (``HERMES_RBAC_ADMIN_EMAIL``, set only by the
    trusted router) must also count — otherwise the console wouldn't show the
    admin as 'admin' even though the gate already trusts them."""
    out = set()
    for var in ("HERMES_ADMIN_EMAILS", "HERMES_RBAC_ADMIN_EMAIL"):
        for e in os.environ.get(var, "").split(","):
            e = e.strip().lower()
            if e:
                out.add(e)
    return frozenset(out)


def _is_admin_email(email: str) -> bool:
    """Admin check that matches the gate: the env allowlist or the vouched
    router email. ``rbac_map.is_admin`` alone misses the vouched admin in a
    per-user container where ``HERMES_ADMIN_EMAILS`` is empty."""
    e = email.strip().lower()
    return rbac_map.is_admin(e) or e in _admin_emails()


def _effective_role(email: str, overrides: Dict[str, str]) -> str:
    """Effective role for a member: admin allowlist wins, then an override,
    then the rbac_map default. Mirrors the patched ``role_for_email`` so the
    console shows what the system will actually enforce."""
    e = email.strip().lower()
    if _is_admin_email(e):
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


def _members_by_role(overrides: Dict[str, str]) -> Dict[str, List[Dict[str, Any]]]:
    """Member records keyed by effective role, derived from captured
    identities. Each record is ``{"email", "by_override"}`` so the UI can mark
    which members are pinned by an explicit override vs the default mapping."""
    out: Dict[str, List[Dict[str, Any]]] = {}
    seen: Dict[str, set] = {}
    for rec in _iter_identities():
        email = (rec.get("email") or "").strip()
        if not email:
            continue
        role = _effective_role(email, overrides)
        out.setdefault(role, [])
        seen.setdefault(role, set())
        if email.lower() in seen[role]:
            continue
        seen[role].add(email.lower())
        out[role].append(
            {"email": email, "by_override": email.strip().lower() in overrides}
        )
    for v in out.values():
        v.sort(key=lambda m: m["email"].lower())
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


def _require_csrf(request: "Request") -> None:
    """Require a non-simple custom header on mutating requests. A cross-site
    form/img/navigation cannot set ``X-Requested-With`` without a CORS
    preflight, so requiring it blocks drive-by CSRF. Defense in depth: the
    admin gate already authenticates the caller. The page's ``api()`` helper
    always sends this header."""
    if (request.headers.get("x-requested-with", "") or "").strip().lower() != "fetch":
        raise HTTPException(status_code=403, detail="Missing X-Requested-With: fetch")


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
                    "builtin": name in _BUILTIN_ROLES,
                }
            )
        return {"roles": roles_out, "overrides": overrides}

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

    def _save_overrides(overrides: Dict[str, str]) -> None:
        path = _overrides_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(overrides, indent=2, sort_keys=True), encoding="utf-8")

    @app.post("/api/rbac/assign-role")
    async def rbac_assign_role(request: Request):  # noqa: ANN001
        _require_admin(request)
        _require_csrf(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body must be JSON")
        email = str((body or {}).get("email", "")).strip().lower()
        role = str((body or {}).get("role", "")).strip()
        if not email:
            raise HTTPException(status_code=400, detail="email is required")
        overrides = _load_overrides()
        if not role:
            # Empty role clears the override and reverts to the default mapping.
            overrides.pop(email, None)
            _save_overrides(overrides)
            return {"ok": True, "email": email, "role": None, "cleared": True, "overrides": overrides}
        role = _require_known_role(role)
        overrides[email] = role
        _save_overrides(overrides)
        return {"ok": True, "email": email, "role": role, "overrides": overrides}

    @app.delete("/api/rbac/assign-role")
    async def rbac_assign_role_delete(request: Request, email: str):  # noqa: ANN001
        _require_admin(request)
        _require_csrf(request)
        e = str(email or "").strip().lower()
        if not e:
            raise HTTPException(status_code=400, detail="email is required")
        overrides = _load_overrides()
        existed = e in overrides
        overrides.pop(e, None)
        _save_overrides(overrides)
        return {"ok": True, "email": e, "cleared": existed, "overrides": overrides}

    @app.post("/api/rbac/permissions")
    async def rbac_permissions(request: Request):  # noqa: ANN001
        """Set a role's shared-volume access flag (rw|ro) in the side JSON."""
        _require_admin(request)
        _require_csrf(request)
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

    @app.post("/api/rbac/roles")
    async def rbac_role_create(request: Request):  # noqa: ANN001
        """Create a new role in roles.yaml. Comments in the file are not
        preserved on the YAML round-trip (acceptable for this console)."""
        _require_admin(request)
        _require_csrf(request)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body must be JSON")
        body = body or {}
        name = _safe_role(body.get("name", ""))
        doc = _load_roles_document()
        if name in doc["roles"]:
            raise HTTPException(status_code=409, detail=f"Role already exists: {name}")
        doc["roles"][name] = _coerce_role_spec(body)
        _write_roles_document(doc)
        return {"ok": True, "role": name}

    @app.put("/api/rbac/roles/{name}")
    async def rbac_role_update(request: Request, name: str):  # noqa: ANN001
        _require_admin(request)
        _require_csrf(request)
        name = _safe_role(name)
        try:
            body = await request.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Body must be JSON")
        doc = _load_roles_document()
        if name not in doc["roles"]:
            raise HTTPException(status_code=404, detail=f"Unknown role: {name}")
        existing = doc["roles"][name]
        existing = existing if isinstance(existing, dict) else {}
        doc["roles"][name] = _coerce_role_spec(body or {}, base=existing)
        _write_roles_document(doc)
        return {"ok": True, "role": name}

    @app.delete("/api/rbac/roles/{name}")
    async def rbac_role_delete(request: Request, name: str):  # noqa: ANN001
        _require_admin(request)
        _require_csrf(request)
        name = _safe_role(name)
        if name in _BUILTIN_ROLES:
            raise HTTPException(status_code=400, detail=f"Refusing to delete built-in role: {name}")
        doc = _load_roles_document()
        if name not in doc["roles"]:
            raise HTTPException(status_code=404, detail=f"Unknown role: {name}")
        # Refuse to orphan members: a role with anyone effectively assigned
        # (default or override) must be emptied first.
        members = _members_by_role(_load_overrides()).get(name, [])
        if members:
            raise HTTPException(
                status_code=409,
                detail=f"Role has {len(members)} member(s); reassign them first",
            )
        del doc["roles"][name]
        _write_roles_document(doc)
        # Drop any stale side-channel access flag for the removed role.
        side = _load_shared_access()
        if name in side:
            del side[name]
            sp = _shared_access_path()
            sp.parent.mkdir(parents=True, exist_ok=True)
            sp.write_text(json.dumps(side, indent=2, sort_keys=True), encoding="utf-8")
        return {"ok": True, "role": name, "deleted": True}

    @app.get("/api/rbac/shared/files")
    async def rbac_shared_files(request: Request, role: str, path: str = ""):  # noqa: ANN001
        _require_admin(request)
        role = _require_known_role(role)
        target = _resolve_under_role(role, path)
        if not target.exists():
            # Distinguish "no shared volume yet" (role root missing) from an
            # existing-but-empty subdirectory so the UI can show a clearer
            # empty state. ``exists`` reflects the role's shared root.
            return {
                "role": role,
                "path": path,
                "entries": [],
                "exists": _role_dir(role).exists(),
            }
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
        return {"role": role, "path": path, "entries": entries, "exists": True}

    @app.get("/api/rbac/shared/download")
    async def rbac_shared_download(request: Request, role: str, path: str):  # noqa: ANN001
        """Download a single file under a role's shared dir. Confined by
        ``_resolve_under_role``; bounded by ``_MAX_DOWNLOAD_BYTES``."""
        _require_admin(request)
        role = _require_known_role(role)
        target = _resolve_under_role(role, path)
        if target == _role_dir(role):
            raise HTTPException(status_code=400, detail="path must name a file")
        if not target.exists() or not target.is_file():
            raise HTTPException(status_code=404, detail="Not found")
        try:
            size = target.stat().st_size
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"Could not stat file: {exc}")
        if size > _MAX_DOWNLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File too large to download")
        try:
            data = target.read_bytes()
        except OSError as exc:
            raise HTTPException(status_code=500, detail=f"Could not read file: {exc}")
        # Quote the filename to keep the Content-Disposition header well-formed
        # and strip anything that could inject header characters.
        fname = target.name.replace('"', "").replace("\r", "").replace("\n", "")
        return Response(
            content=data,
            media_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{fname}"'},
        )

    @app.post("/api/rbac/shared/upload")
    async def rbac_shared_upload(request: Request):  # noqa: ANN001
        _require_admin(request)
        _require_csrf(request)
        _guard_body_size(request)
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
        _require_csrf(request)
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
        _require_csrf(request)
        _guard_body_size(request)
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
  .count { color:var(--muted); font-size:12px; font-weight:400; }
  .pill.def { background:rgba(139,148,158,.15); color:var(--muted); }
  .pill.ovr { background:rgba(88,166,255,.15); color:var(--accent); }
  button.btn:disabled, select:disabled, input:disabled, textarea:disabled {
    opacity:.55; cursor:not-allowed; }
  button.btn.spin { position:relative; color:transparent !important; }
  button.btn.spin::after { content:""; position:absolute; inset:0; margin:auto;
    width:12px; height:12px; border:2px solid currentColor; border-top-color:transparent;
    border-radius:50%; animation:sp .6s linear infinite; color:var(--text); }
  @keyframes sp { to { transform:rotate(360deg); } }
  .errpanel { border:1px solid var(--danger); background:rgba(248,81,73,.08);
    border-radius:8px; padding:12px 14px; color:var(--text); }
  .errpanel .msg { color:var(--danger); margin-bottom:8px; word-break:break-word; }
  .modal-bg { position:fixed; inset:0; background:rgba(0,0,0,.6); display:none;
    align-items:center; justify-content:center; z-index:50; }
  .modal-bg.show { display:flex; }
  .modal { background:var(--panel); border:1px solid var(--border); border-radius:8px;
    padding:16px; width:min(820px,92vw); max-height:86vh; overflow:auto; }
  .modal h3 { margin:0 0 10px; font-size:14px; }
  .modal pre { background:var(--bg); border:1px solid var(--border); border-radius:6px;
    padding:12px; overflow:auto; max-height:60vh; font-size:12px;
    font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; white-space:pre-wrap;
    word-break:break-word; }
  .modal .actions { display:flex; gap:8px; justify-content:flex-end; margin-top:12px; }
  .field { display:flex; flex-direction:column; gap:4px; margin-bottom:10px; }
  .field label { color:var(--muted); font-size:12px; }
  .grid2 { display:grid; grid-template-columns:1fr 1fr; gap:10px; }
  .actrow { display:flex; gap:4px; flex-wrap:wrap; }
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
      <h2>Roles &amp; Members <span class="count" id="roles-count"></span></h2>
      <div class="desc">Roles from <code>roles.yaml</code>, members from captured identities,
        and each user's effective role. <span class="pill ovr">by override</span> vs
        <span class="pill def">by default</span>.</div>
      <div id="roles-body" class="muted">Loading…</div>
    </div>
    <div class="card">
      <h2>Add role</h2>
      <div class="grid2">
        <div class="field"><label>Name</label>
          <input id="role-new-name" placeholder="analyst"/></div>
        <div class="field"><label>Backend</label>
          <select id="role-new-backend"><option value="docker">docker</option><option value="local">local</option></select></div>
        <div class="field"><label>Toolsets (comma-separated)</label>
          <input id="role-new-toolsets" placeholder="web, vision, skills"/></div>
        <div class="field"><label>Shared skills (comma-separated)</label>
          <input id="role-new-skills" placeholder="common"/></div>
        <div class="field"><label>Shared access</label>
          <select id="role-new-access"><option value="rw">read-write (rw)</option><option value="ro">read-only (ro)</option></select></div>
        <div class="field"><label>Description</label>
          <input id="role-new-desc" placeholder="optional"/></div>
      </div>
      <div class="row"><button class="btn primary" id="role-new-go">Create role</button></div>
      <div class="desc" style="margin-top:8px">Writes <code>roles.yaml</code>
        (comments are not preserved on save).</div>
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
      <div id="overrides-body" style="margin-top:12px"></div>
    </div>
  </section>

  <section id="tab-identities" class="tab">
    <div class="card">
      <h2>Captured Google identities <span class="count" id="ident-count"></span></h2>
      <div class="desc">From <code>&lt;HERMES_HOME&gt;/rbac/identities/*.json</code>.</div>
      <div class="row" style="margin-bottom:10px">
        <input id="ident-search" placeholder="Filter by name, email, domain…" style="min-width:280px"/>
      </div>
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
<div id="modal-bg" class="modal-bg">
  <div class="modal">
    <h3 id="modal-title"></h3>
    <div id="modal-content"></div>
    <div class="actions"><button class="btn" id="modal-close">Close</button></div>
  </div>
</div>
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
  // Always send X-Requested-With: a cross-site form/img cannot set it, so the
  // server can require it as a CSRF guard on top of the admin gate.
  const opts = { method, headers: { 'X-Requested-With': 'fetch' } };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  const r = await fetch(url, opts);
  let data = null;
  try { data = await r.json(); } catch(e) {}
  if (!r.ok) { throw new Error((data && data.detail) || (r.status + ' ' + r.statusText)); }
  return data;
}
// Render a styled error panel with a Retry button into a target element.
function showError(sel, message, onRetry) {
  const el = $(sel); if (!el) return;
  el.classList.remove('muted');
  el.innerHTML = '<div class="errpanel"><div class="msg">' + esc(message) +
    '</div><button class="btn" id="' + sel.replace(/[^a-z0-9]/gi,'') + '-retry">Retry</button></div>';
  const rb = el.querySelector('button'); if (rb && onRetry) rb.onclick = onRetry;
}
// Disable a button + show a spinner while an async action runs.
async function busy(btn, fn) {
  if (!btn) return fn();
  const wasDisabled = btn.disabled;
  btn.disabled = true; btn.classList.add('spin');
  try { return await fn(); }
  finally { btn.classList.remove('spin'); btn.disabled = wasDisabled; }
}
// ---- modal ----
function openModal(title, html) {
  $('#modal-title').textContent = title;
  $('#modal-content').innerHTML = html;
  $('#modal-bg').classList.add('show');
}
function closeModal() { $('#modal-bg').classList.remove('show'); $('#modal-content').innerHTML = ''; }
$('#modal-close').onclick = closeModal;
$('#modal-bg').onclick = ev => { if (ev.target === $('#modal-bg')) closeModal(); };

// ---- tabs (with location.hash deep-linking) ----
const TAB_LOADERS = {
  roles: () => loadRoles(),
  identities: () => loadIdentities(),
  files: () => loadFiles(),
  memory: () => loadMemory(),
  perms: () => loadPerms(),
};
function showTab(name, push) {
  if (!TAB_LOADERS[name]) name = 'roles';
  $$('nav button').forEach(x => x.classList.toggle('active', x.dataset.tab === name));
  $$('.tab').forEach(x => x.classList.remove('active'));
  const sec = $('#tab-' + name); if (sec) sec.classList.add('active');
  if (push && location.hash !== '#' + name) location.hash = name;
  TAB_LOADERS[name]();
}
$$('nav button').forEach(b => b.onclick = () => showTab(b.dataset.tab, true));
window.addEventListener('hashchange', () => showTab((location.hash || '').replace(/^#/, ''), false));

// ---- roles & members ----
let OVERRIDES = {};
async function loadRoles() {
  try {
    const d = await api('GET', '/api/rbac/roles');
    ROLES = d.roles || [];
    OVERRIDES = d.overrides || {};
    populateRoleSelects();
    renderRoles();
    renderOverrides();
  } catch(e) {
    toast('Roles: ' + e.message, 'err');
    showError('#roles-body', 'Could not load roles: ' + e.message, loadRoles);
  }
}
function populateRoleSelects() {
  const opts = ROLES.map(r => `<option value="${esc(r.name)}">${esc(r.name)}</option>`).join('');
  ['#assign-role', '#files-role', '#mem-role'].forEach(sel => {
    const el = $(sel); if (el) el.innerHTML = opts;
  });
}
function renderRoles() {
  const totalMembers = ROLES.reduce((n, r) => n + (r.members || []).length, 0);
  $('#roles-count').textContent = ROLES.length + ' roles · ' + totalMembers + ' members';
  let h = '<table><thead><tr><th>Role</th><th>Backend</th><th>Toolsets</th>' +
          '<th>Shared skills</th><th>Access</th><th>Members</th><th></th></tr></thead><tbody>';
  for (const r of ROLES) {
    const toolsets = (r.toolsets || []).map(t => `<span class="tag">${esc(t)}</span>`).join(' ');
    const skills = (r.shared_skills || []).map(t => `<span class="tag">${esc(t)}</span>`).join(' ');
    const members = (r.members || []).length
      ? r.members.map(m => `<div class="mono small">${esc(m.email)} ` +
          `<span class="pill ${m.by_override?'ovr':'def'}">${m.by_override?'override':'default'}</span></div>`).join('')
      : '<span class="muted small">none</span>';
    const delBtn = r.builtin
      ? ''
      : `<button class="btn danger small" data-role-del="${esc(r.name)}">Delete</button>`;
    h += `<tr><td><b>${esc(r.name)}</b>${r.builtin?' <span class="pill def">built-in</span>':''}` +
         `<div class="muted small">${esc(r.description||'')}</div></td>` +
         `<td><code>${esc(r.backend)}</code></td><td>${toolsets}</td><td>${skills}</td>` +
         `<td><span class="pill ${esc(r.shared_access)}">${esc(r.shared_access)}</span></td>` +
         `<td>${members}</td>` +
         `<td><div class="actrow"><button class="btn small" data-role-edit="${esc(r.name)}">Edit</button>${delBtn}</div></td></tr>`;
  }
  h += '</tbody></table>';
  $('#roles-body').innerHTML = h;
  $$('#roles-body button[data-role-edit]').forEach(b => b.onclick = () => openRoleEditor(b.dataset.roleEdit));
  $$('#roles-body button[data-role-del]').forEach(b => b.onclick = () => deleteRole(b.dataset.roleDel));
}
function renderOverrides() {
  const keys = Object.keys(OVERRIDES);
  if (!keys.length) { $('#overrides-body').innerHTML = '<span class="muted small">No active overrides.</span>'; return; }
  keys.sort();
  let h = '<div class="small muted" style="margin-bottom:4px">Active overrides (' + keys.length + ')</div>' +
          '<table><thead><tr><th>Email</th><th>Role</th><th></th></tr></thead><tbody>';
  for (const email of keys) {
    h += `<tr><td class="mono">${esc(email)}</td><td><span class="tag">${esc(OVERRIDES[email])}</span></td>` +
         `<td><button class="btn small danger" data-ovr-del="${esc(email)}">Remove</button></td></tr>`;
  }
  h += '</tbody></table>';
  $('#overrides-body').innerHTML = h;
  $$('#overrides-body button[data-ovr-del]').forEach(b => b.onclick = () => removeOverride(b.dataset.ovrDel, b));
}
async function removeOverride(email, btn) {
  const prev = OVERRIDES[email] || '?';
  if (!confirm('Remove override for ' + email + ' (currently ' + prev + ')? Reverts to default role.')) return;
  await busy(btn, async () => {
    try {
      await api('DELETE', '/api/rbac/assign-role?email=' + encodeURIComponent(email));
      toast('Removed override for ' + email + ' (was ' + prev + ')', 'ok');
      loadRoles();
    } catch(e) { toast('Remove: ' + e.message, 'err'); }
  });
}
function csvToList(s) { return String(s||'').split(',').map(x => x.trim()).filter(Boolean); }
$('#role-new-go').onclick = () => busy($('#role-new-go'), async () => {
  const name = $('#role-new-name').value.trim();
  if (!name) { toast('Enter a role name', 'err'); return; }
  const body = {
    name,
    backend: $('#role-new-backend').value,
    toolsets: csvToList($('#role-new-toolsets').value),
    shared_skills: csvToList($('#role-new-skills').value),
    shared_access: $('#role-new-access').value,
    description: $('#role-new-desc').value.trim(),
  };
  try {
    await api('POST', '/api/rbac/roles', body);
    toast('Created role ' + name, 'ok');
    ['#role-new-name','#role-new-toolsets','#role-new-skills','#role-new-desc'].forEach(s => $(s).value='');
    loadRoles();
  } catch(e) { toast('Create role: ' + e.message, 'err'); }
});
function openRoleEditor(name) {
  const r = ROLES.find(x => x.name === name); if (!r) return;
  const html =
    `<div class="field"><label>Backend</label>` +
    `<select id="re-backend"><option value="docker"${r.backend==='docker'?' selected':''}>docker</option>` +
    `<option value="local"${r.backend==='local'?' selected':''}>local</option></select></div>` +
    `<div class="field"><label>Toolsets (comma-separated)</label>` +
    `<input id="re-toolsets" value="${esc((r.toolsets||[]).join(', '))}"/></div>` +
    `<div class="field"><label>Shared skills (comma-separated)</label>` +
    `<input id="re-skills" value="${esc((r.shared_skills||[]).join(', '))}"/></div>` +
    `<div class="field"><label>Shared access</label>` +
    `<select id="re-access"><option value="rw"${r.shared_access==='rw'?' selected':''}>read-write (rw)</option>` +
    `<option value="ro"${r.shared_access==='ro'?' selected':''}>read-only (ro)</option></select></div>` +
    `<div class="field"><label>Description</label>` +
    `<input id="re-desc" value="${esc(r.description||'')}"/></div>` +
    `<div class="actions"><button class="btn primary" id="re-save">Save</button></div>`;
  openModal('Edit role: ' + name, html);
  $('#re-save').onclick = () => busy($('#re-save'), async () => {
    const body = {
      backend: $('#re-backend').value,
      toolsets: csvToList($('#re-toolsets').value),
      shared_skills: csvToList($('#re-skills').value),
      shared_access: $('#re-access').value,
      description: $('#re-desc').value.trim(),
    };
    try {
      await api('PUT', '/api/rbac/roles/' + encodeURIComponent(name), body);
      toast('Saved role ' + name, 'ok'); closeModal(); loadRoles();
    } catch(e) { toast('Save role: ' + e.message, 'err'); }
  });
}
async function deleteRole(name) {
  if (!confirm('Delete role "' + name + '"? This rewrites roles.yaml.')) return;
  try {
    await api('DELETE', '/api/rbac/roles/' + encodeURIComponent(name));
    toast('Deleted role ' + name, 'ok'); loadRoles();
  } catch(e) { toast('Delete role: ' + e.message, 'err'); }
}
$('#assign-go').onclick = () => busy($('#assign-go'), async () => {
  const email = $('#assign-email').value.trim();
  const role = $('#assign-role').value;
  if (!email) { toast('Enter an email', 'err'); return; }
  const prev = OVERRIDES[email.toLowerCase()];
  const prevTxt = prev ? ' (was overridden to ' + prev + ')' : '';
  if (!confirm('Assign ' + email + ' → ' + role + prevTxt + '?')) return;
  try {
    await api('POST', '/api/rbac/assign-role', { email, role });
    toast('Assigned ' + email + ' → ' + role, 'ok');
    $('#assign-email').value = '';
    loadRoles();
  } catch(e) { toast('Assign: ' + e.message, 'err'); }
});

// ---- identities ----
let IDENTITIES = [];
$('#ident-search').oninput = renderIdentities;
async function loadIdentities() {
  try {
    const d = await api('GET', '/api/rbac/identities');
    IDENTITIES = d.identities || [];
    renderIdentities();
  } catch(e) {
    toast('Identities: ' + e.message, 'err');
    showError('#ident-body', 'Could not load identities: ' + e.message, loadIdentities);
  }
}
function renderIdentities() {
  const q = $('#ident-search').value.trim().toLowerCase();
  const recs = q
    ? IDENTITIES.filter(r => [r.name, r.email, r.hd, r.effective_role]
        .some(v => String(v||'').toLowerCase().includes(q)))
    : IDENTITIES;
  $('#ident-count').textContent = q
    ? recs.length + ' of ' + IDENTITIES.length
    : IDENTITIES.length + ' total';
  if (!IDENTITIES.length) { $('#ident-body').classList.add('muted'); $('#ident-body').textContent = 'No identities captured yet.'; return; }
  if (!recs.length) { $('#ident-body').classList.add('muted'); $('#ident-body').textContent = 'No identities match.'; return; }
  $('#ident-body').classList.remove('muted');
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
}

// ---- shared files ----
let filesState = { role: null, path: '' };
function currentFilesRole() { return $('#files-role').value; }
$('#files-role').onchange = () => { filesState.path=''; loadFiles(); };
// Extensions safe to preview inline as text.
const TEXT_EXT = ['txt','md','markdown','json','yaml','yml','csv','log','ini','cfg','conf','toml','xml','html','css','js','ts','py','sh','env'];
const VIEW_MAX = 512 * 1024;
function isTextName(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return TEXT_EXT.includes(ext);
}
async function loadFiles() {
  const role = currentFilesRole();
  if (!role) { $('#files-body').classList.add('muted'); $('#files-body').textContent = 'Pick a role…'; return; }
  filesState.role = role;
  try {
    const d = await api('GET', `/api/rbac/shared/files?role=${encodeURIComponent(role)}&path=${encodeURIComponent(filesState.path)}`);
    renderCrumbs();
    const e = d.entries || [];
    $('#files-body').classList.remove('muted');
    if (!e.length) {
      // Distinguish "no shared volume yet" from an existing-but-empty dir.
      if (d.exists === false && !filesState.path) {
        $('#files-body').innerHTML = '<span class="muted">No shared volume yet for this role — upload a file to create it.</span>';
      } else {
        $('#files-body').innerHTML = '<span class="muted">Empty directory.</span>';
      }
      return;
    }
    let h = '<table><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th></th></tr></thead><tbody>';
    for (const it of e) {
      const name = it.is_dir
        ? `<a href="#" data-dir="${esc(it.name)}">📁 ${esc(it.name)}/</a>`
        : `📄 ${esc(it.name)}`;
      let actions = '';
      if (!it.is_dir) {
        actions += `<button class="btn small" data-dl="${esc(it.name)}">download</button>`;
        if (isTextName(it.name) && (it.size == null || it.size <= VIEW_MAX)) {
          actions += `<button class="btn small" data-view="${esc(it.name)}">view</button>`;
        }
      }
      actions += `<button class="btn danger small" data-del="${esc(it.name)}">delete</button>`;
      h += `<tr><td>${name}</td><td class="small muted">${it.is_dir?'':fmtSize(it.size)}</td>` +
           `<td class="small muted">${fmtTime(it.mtime)}</td>` +
           `<td><div class="actrow">${actions}</div></td></tr>`;
    }
    h += '</tbody></table>';
    $('#files-body').innerHTML = h;
    $$('#files-body a[data-dir]').forEach(a => a.onclick = ev => {
      ev.preventDefault();
      filesState.path = (filesState.path ? filesState.path + '/' : '') + a.dataset.dir;
      loadFiles();
    });
    $$('#files-body button[data-del]').forEach(b => b.onclick = () => delFile(b.dataset.del));
    $$('#files-body button[data-dl]').forEach(b => b.onclick = () => downloadFile(b.dataset.dl));
    $$('#files-body button[data-view]').forEach(b => b.onclick = () => viewFile(b.dataset.view, b));
  } catch(e) {
    toast('Files: ' + e.message, 'err');
    showError('#files-body', 'Could not list files: ' + e.message, loadFiles);
  }
}
function fileRel(name) { return (filesState.path ? filesState.path + '/' : '') + name; }
function downloadFile(name) {
  const url = `/api/rbac/shared/download?role=${encodeURIComponent(filesState.role)}&path=${encodeURIComponent(fileRel(name))}`;
  // Browser navigation can't send X-Requested-With; download is a GET (no CSRF guard).
  const a = document.createElement('a');
  a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
}
async function viewFile(name, btn) {
  await busy(btn, async () => {
    const url = `/api/rbac/shared/download?role=${encodeURIComponent(filesState.role)}&path=${encodeURIComponent(fileRel(name))}`;
    try {
      const r = await fetch(url, { headers: { 'X-Requested-With': 'fetch' } });
      if (!r.ok) {
        let detail = r.status + ' ' + r.statusText;
        try { const j = await r.json(); if (j && j.detail) detail = j.detail; } catch(e) {}
        throw new Error(detail);
      }
      const text = await r.text();
      openModal(name, '<pre>' + esc(text) + '</pre>');
    } catch(e) { toast('View: ' + e.message, 'err'); }
  });
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
  if (!filesState.role) { toast('Pick a role first', 'err'); return; }
  busy($('#files-upload-go'), () => new Promise(resolve => {
    const reader = new FileReader();
    reader.onload = async () => {
      const b64 = String(reader.result).split(',')[1] || '';
      const rel = (filesState.path ? filesState.path + '/' : '') + f.name;
      try {
        await api('POST', '/api/rbac/shared/upload', { role: filesState.role, path: rel, content: b64 });
        toast('Uploaded ' + f.name, 'ok'); inp.value=''; loadFiles();
      } catch(e) { toast('Upload: ' + e.message, 'err'); }
      finally { resolve(); }
    };
    reader.onerror = () => { toast('Could not read file', 'err'); resolve(); };
    reader.readAsDataURL(f);
  }));
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
  } catch(e) { toast('Memory: ' + e.message, 'err'); $('#mem-status').textContent = 'Could not load: ' + e.message; }
}
$('#mem-save').onclick = () => busy($('#mem-save'), async () => {
  const role = $('#mem-role').value;
  try {
    await api('PUT', '/api/rbac/shared/memory', { role, text: $('#mem-text').value });
    toast('Saved MEMORY.md for ' + role, 'ok');
    $('#mem-status').textContent = 'Saved MEMORY.md for ' + role;
  } catch(e) { toast('Save: ' + e.message, 'err'); }
});

// ---- permissions ----
async function loadPerms() {
  if (!ROLES.length) {
    try { await loadRoles(); }
    catch(e) { showError('#perms-body', 'Could not load roles: ' + e.message, loadPerms); return; }
  }
  $('#perms-body').classList.remove('muted');
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
  $$('#perms-body button[data-perm-save]').forEach(b => b.onclick = () => busy(b, async () => {
    const role = b.dataset.permSave;
    const sel = $(`select[data-perm-role="${role}"]`);
    const prev = (ROLES.find(x => x.name === role) || {}).shared_access || '?';
    if (sel.value !== prev && !confirm('Change ' + role + ' shared access: ' + prev + ' → ' + sel.value + '?')) {
      sel.value = prev; return;
    }
    try {
      await api('POST', '/api/rbac/permissions', { role, shared_access: sel.value });
      toast(role + ': ' + prev + ' → ' + sel.value, 'ok');
      loadRoles();
    } catch(e) { toast('Permissions: ' + e.message, 'err'); }
  }));
}

// ---- boot: restore tab from location.hash ----
showTab((location.hash || '').replace(/^#/, '') || 'roles', false);
</script>
</body>
</html>
"""
