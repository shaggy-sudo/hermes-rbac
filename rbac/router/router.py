"""RBAC router — the front door for the per-user-container model.

Flow:
  browser ─▶ router (Google gate) ─▶ per-user dashboard container ─▶ proxied back

The router is the ONLY trusted component with docker access. Each authenticated
Google user is routed to their OWN dashboard container, which mounts ONLY their
profile (as /opt/data) + their role's /shared. Because the chat PTY (and its `!`
shell escape) then runs inside that container, it physically cannot see
/opt/data of other users — the isolation the shared-dashboard model could not
provide.

Trust boundary: docker.sock lives HERE, not in a container where a user has a
shell. Per-user dashboards run --insecure on an internal network, reachable
only via this router.

Env:
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   OAuth web client
  GOOGLE_ALLOWED_DOMAIN / GOOGLE_ALLOWED_EMAILS   team restriction (optional)
  HERMES_ADMIN_EMAILS                       admins (get full-data container)
  ROUTER_PUBLIC_URL                         public base URL, e.g. https://host/
  ROUTER_SECRET                             cookie-signing secret — REQUIRED,
                                            >=32 chars; the router refuses to
                                            start with a blank/default/short
                                            value (openssl rand -hex 32). Also
                                            derives the stable per-user
                                            dashboard session token.
  HERMES_HOST_DATA                          HOST path of ~/.hermes (for -v src)
  HERMES_IMAGE                              per-user container image
  HERMES_NET                                docker network shared with users
  OPENROUTER_API_KEY / HERMES_DEFAULT_MODEL forwarded into user containers

Per-user containers additionally receive (set ONLY by this router, so they
cannot be forged by users):
  HERMES_RBAC_USER_EMAIL / HERMES_RBAC_USER_ROLE / HERMES_RBAC_IS_ADMIN
                                            verified identity → /api/auth/me
  HERMES_RBAC_ADMIN_EMAIL                   admin vouch (admins only) → /rbac
  HERMES_DASHBOARD_SESSION_TOKEN            stable --insecure SPA token
                                            (survives respawns)

Reads <HERMES_HOST_DATA>/rbac/shared-access.json (role -> "rw"|"ro") to decide
whether a role's /shared mount is read-only.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
from urllib.parse import urlsplit

import httpx
import jwt
import websockets
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket

from hermes_cli.dashboard_auth import rbac_map

# The Google provider does the OAuth dance; we reuse it verbatim.
import importlib.util as _ilu

_spec = _ilu.spec_from_file_location(
    "google_provider", "/opt/hermes/plugins/dashboard_auth/google/__init__.py"
)
_gp = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_gp)

PUBLIC_URL = os.environ.get("ROUTER_PUBLIC_URL", "").rstrip("/")

# Fail closed: a forgeable cookie secret means anyone can mint a session for any
# email (including an admin) and bypass the Google gate entirely. Reject empty,
# the known insecure defaults, and anything too short to be a real secret.
_raw_secret = os.environ.get("ROUTER_SECRET", "")
if (
    not _raw_secret
    or _raw_secret in {"dev-insecure-secret-change-me", "change-me-please"}
    or len(_raw_secret) < 32
):
    raise RuntimeError(
        "ROUTER_SECRET is missing, default, or too short. Set it to at least 32 "
        "random characters, e.g. `openssl rand -hex 32`."
    )
SECRET = _raw_secret
HOST_DATA = os.environ.get("HERMES_HOST_DATA", "")  # host path of ~/.hermes
IMAGE = os.environ.get("HERMES_IMAGE", "hermes-agent")
NET = os.environ.get("HERMES_NET", "hermes-rbac-net")
PORT = 9119
COOKIE = "rbac_router_session"
PKCE_COOKIE = "rbac_router_pkce"
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length",
}
# Client-supplied forwarding headers are never trusted: the router sets them
# itself from the real connection so downstream audit IPs and prefix-based
# redirects cannot be poisoned.
FORWARDED_HEADERS = {
    "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-prefix",
}

_PUBLIC = urlsplit(PUBLIC_URL) if PUBLIC_URL else None
PUBLIC_SCHEME = (_PUBLIC.scheme if _PUBLIC and _PUBLIC.scheme else "http")
PUBLIC_HOST = (_PUBLIC.netloc if _PUBLIC else "")
IS_HTTPS = PUBLIC_SCHEME == "https"

# Serialise first-login provisioning per email so concurrent requests for the
# same user don't race to spawn duplicate containers.
_spawn_locks: dict[str, asyncio.Lock] = {}


def _spawn_lock(email: str) -> asyncio.Lock:
    lock = _spawn_locks.get(email)
    if lock is None:
        lock = asyncio.Lock()
        _spawn_locks[email] = lock
    return lock


def _provider():
    return _gp.GoogleDashboardAuthProvider(
        client_id=os.environ["GOOGLE_CLIENT_ID"],
        client_secret=os.environ["GOOGLE_CLIENT_SECRET"],
        allowed_domain=os.environ.get("GOOGLE_ALLOWED_DOMAIN", ""),
        allowed_emails=tuple(
            e for e in os.environ.get("GOOGLE_ALLOWED_EMAILS", "").split(",") if e.strip()
        ),
    )


# ---------------------------------------------------------------------------
# Session cookie (PyJWT-signed; itsdangerous isn't in the image)
# ---------------------------------------------------------------------------

def _issue_cookie(email: str) -> str:
    return jwt.encode(
        {"email": email, "iat": int(time.time()), "exp": int(time.time()) + 86400},
        SECRET, algorithm="HS256",
    )


def _read_cookie(request: Request) -> str | None:
    tok = request.cookies.get(COOKIE)
    if not tok:
        return None
    try:
        return jwt.decode(tok, SECRET, algorithms=["HS256"]).get("email")
    except jwt.InvalidTokenError:
        return None


# ---------------------------------------------------------------------------
# Per-user container lifecycle (docker CLI over the mounted socket)
# ---------------------------------------------------------------------------

def _session_token_for(email: str) -> str:
    """Stable per-user dashboard session token (the --insecure SPA token).

    Derived from ROUTER_SECRET so it survives container respawns/restarts —
    keeping already-open browser tabs authenticated — yet stays unguessable
    without the secret."""
    return hmac.new(SECRET.encode(), email.encode(), hashlib.sha256).hexdigest()


def _slug(email: str) -> str:
    return rbac_map.profile_for_email(email)  # u-<slug>, validated


def _container_name(email: str) -> str:
    return f"hermes-{_slug(email)}"


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=check, timeout=120
    )


def _running(name: str) -> bool:
    r = _docker("ps", "--filter", f"name=^{name}$", "--format", "{{.Names}}", check=False)
    return name in r.stdout.split()


class ContainerNotReady(Exception):
    """Raised when a user's dashboard container failed to spawn or never became
    ready, so callers can serve a friendly retry page instead of proxying into
    an opaque connection error."""


def _shared_access(role: str) -> str:
    """Effective bind mode for a role's /shared mount: "rw" (default) or "ro".

    Read from {HOST_DATA}/rbac/shared-access.json, a small JSON map of
    role -> "rw"|"ro". Kept self-contained on purpose. Note: the docker bind
    mode is fixed when the container is created, so after toggling a role to
    "ro" the admin must respawn (docker rm -f) that role's containers."""
    try:
        with open(f"{HOST_DATA}/rbac/shared-access.json", encoding="utf-8") as fh:
            access = json.load(fh)
        if isinstance(access, dict) and str(access.get(role, "rw")).lower() == "ro":
            return "ro"
    except FileNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001 — malformed config must not open access
        print(f"[router] shared-access.json unreadable, defaulting rw: {exc}", file=sys.stderr)
    return "rw"


def ensure_container(email: str) -> str:
    """Provision the user's profile (once) and ensure their dashboard container
    is running with ONLY their profile + role-shared mounted. Returns the
    container name (reachable by the router at http://<name>:9119). Raises
    ContainerNotReady if the spawn or readiness poll fails."""
    name = _container_name(email)
    if _running(name):
        return name

    profile = _slug(email)
    role = rbac_map.role_for_email(email)
    admin = rbac_map.is_admin(email)

    # 1) Provision the profile on the shared data volume (idempotent). Forward
    #    the LLM key + model so the user's profile can actually run.
    _OPENROUTER = os.environ.get("OPENROUTER_API_KEY", "")
    _MODEL = os.environ.get("HERMES_DEFAULT_MODEL", "openrouter/owl-alpha")
    _docker(
        "run", "--rm",
        "-e", "HERMES_RBAC_TERMINAL_BACKEND=local",
        "-e", f"OPENROUTER_API_KEY={_OPENROUTER}",
        "-e", f"HERMES_DEFAULT_MODEL={_MODEL}",
        "-v", f"{HOST_DATA}:/opt/data",
        IMAGE, "bash", "/opt/hermes/rbac/provision-user.sh", email, role,
        check=False,
    )

    # 2) Remove any stopped container with the same name, then spawn fresh.
    _docker("rm", "-f", name, check=False)

    # Vouch the Google-verified identity into the container so its --insecure
    # dashboard can report who the user is (role/admin) to the SPA — the
    # container has no session of its own. Only the router sets container env,
    # so this can't be forged by the user. Drives /api/auth/me + the SPA's
    # role badge and role-filtered nav.
    identity_env = [
        "-e", f"HERMES_RBAC_USER_EMAIL={email}",
        "-e", f"HERMES_RBAC_USER_ROLE={role}",
        "-e", f"HERMES_RBAC_IS_ADMIN={'1' if admin else '0'}",
        # Pin the dashboard's --insecure session token to a value that is
        # STABLE across container respawns (derived from ROUTER_SECRET + email,
        # unguessable without the secret). Otherwise every respawn/restart mints
        # a fresh random token and the user's already-open SPA tab keeps sending
        # the old one → /api/* 401 → infinite spinners until a hard refresh.
        "-e", f"HERMES_DASHBOARD_SESSION_TOKEN={_session_token_for(email)}",
    ]

    admin_env: list[str] = []
    if admin:
        # Admins get the full data volume (machine-level management) + a vouch
        # so the Shared Management admin UI (/rbac) recognises them despite the
        # container running --insecure with no in-container session.
        mounts = ["-v", f"{HOST_DATA}:/opt/data"]
        admin_env = ["-e", f"HERMES_RBAC_ADMIN_EMAIL={email}"]
    else:
        # Non-admins: ONLY their profile (as /opt/data) + their role's /shared.
        # The /shared mount is read-only when the role's effective access is
        # "ro" so a same-role tenant cannot poison shared context (e.g.
        # /shared/MEMORY.md) for everyone. Bind mode is fixed at creation, so
        # the admin must respawn (docker rm -f) these containers after toggling.
        shared = f"{HOST_DATA}/shared/{role}:/shared"
        if _shared_access(role) == "ro":
            shared += ":ro"
        mounts = [
            "-v", f"{HOST_DATA}/profiles/{profile}:/opt/data",
            "-v", shared,
        ]

    run = _docker(
        "run", "-d", "--name", name, "--network", NET, "--restart", "unless-stopped",
        "-e", "HERMES_UID=10000", "-e", "HERMES_GID=10000",
        "-e", f"OPENROUTER_API_KEY={_OPENROUTER}",
        *identity_env,
        *admin_env,
        *mounts,
        IMAGE, "dashboard", "--host", "0.0.0.0", "--no-open", "--insecure",
        "--port", str(PORT),
        check=False,
    )
    if run.returncode != 0:
        print(f"[router] docker run failed for {name}: {run.stderr.strip()}", file=sys.stderr)
        raise ContainerNotReady(name)

    # Give it a moment to bind, and confirm it actually became ready.
    base = f"http://{name}:{PORT}"
    for _ in range(30):
        try:
            httpx.get(f"{base}/api/status", timeout=2)
            return name
        except Exception:
            time.sleep(1)
    print(f"[router] container {name} never became ready", file=sys.stderr)
    raise ContainerNotReady(name)


# ---------------------------------------------------------------------------
# Branded pages (self-contained, dark theme matching rbac_admin.py palette)
# ---------------------------------------------------------------------------

def _page(title: str, body: str, status_code: int = 200) -> HTMLResponse:
    html = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
  html,body{{height:100%;margin:0}}
  body{{background:#0e1116;color:#c9d1d9;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
        display:flex;align-items:center;justify-content:center}}
  .panel{{background:#161b22;border:1px solid #21262d;border-radius:12px;padding:40px;max-width:380px;
          width:100%;text-align:center;box-sizing:border-box}}
  h1{{font-size:20px;margin:0 0 8px}}
  p{{color:#8b949e;margin:0 0 24px}}
  a.btn{{display:inline-block;background:#58a6ff;color:#0e1116;font-weight:600;text-decoration:none;
         padding:11px 20px;border-radius:8px}}
  a.btn:hover{{filter:brightness(1.08)}}
  a.alt{{display:inline-block;margin-top:18px;color:#58a6ff;text-decoration:none;font-size:13px}}
</style></head>
<body><div class="panel">{body}</div></body></html>"""
    return HTMLResponse(html, status_code=status_code)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

async def login(request: Request):
    return _page(
        "Hermes Agent",
        '<h1>Hermes Agent</h1>'
        '<p>Sign in to access your workspace.</p>'
        '<a class="btn" href="/auth/start">Continue with Google</a>',
    )


async def start_login(request: Request):
    ls = _provider().start_login(redirect_uri=f"{PUBLIC_URL}/auth/callback")
    resp = RedirectResponse(ls.redirect_url, status_code=302)
    resp.set_cookie(
        PKCE_COOKIE, ls.cookie_payload["hermes_session_pkce"],
        # SameSite must be Lax (not Strict): /auth/callback is reached via a
        # cross-site top-level redirect from accounts.google.com, and Strict
        # would withhold the cookie there, breaking every login. Lax still
        # blocks cross-site subresource sends.
        httponly=True, secure=IS_HTTPS, samesite="lax", max_age=600, path="/auth",
    )
    return resp


async def callback(request: Request):
    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    pkce = request.cookies.get(PKCE_COOKIE, "")
    parts = dict(seg.split("=", 1) for seg in pkce.split(";") if "=" in seg)
    if not code or parts.get("state") != state:
        print("[router] callback rejected: invalid or missing state", file=sys.stderr)
        return _page(
            "Sign-in failed",
            '<h1>Sign-in failed</h1>'
            '<p>Please try again.</p>'
            '<a class="btn" href="/login">Try a different account</a>',
            status_code=400,
        )
    try:
        session = _provider().complete_login(
            code=code, state=state, code_verifier=parts.get("verifier", ""),
            redirect_uri=f"{PUBLIC_URL}/auth/callback",
        )
    except Exception as exc:  # noqa: BLE001
        # Never leak the raw exception (denied domain, token errors) to the body.
        print(f"[router] callback complete_login failed: {exc}", file=sys.stderr)
        return _page(
            "Access restricted",
            '<h1>Access restricted</h1>'
            "<p>This workspace is restricted &mdash; your account isn't authorized. "
            "Contact your admin.</p>"
            '<a class="btn" href="/login">Try a different account</a>',
            status_code=403,
        )
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(
        COOKIE, _issue_cookie(session.email),
        # SameSite=Lax (not Strict): the post-OAuth landing on "/" is the tail
        # of a cross-site redirect chain from accounts.google.com, and Strict
        # withholds the cookie on that navigation → the dashboard bounces back
        # to /login forever. Lax sends it on top-level navigations (the login
        # landing) while still blocking cross-site subresource/POST CSRF.
        httponly=True, secure=IS_HTTPS, samesite="lax", max_age=86400,
    )
    resp.delete_cookie(PKCE_COOKIE, path="/auth")
    return resp


async def logout(request: Request):
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(COOKIE)
    return resp


# ---------------------------------------------------------------------------
# Reverse proxy (HTTP + WebSocket) to the user's container
# ---------------------------------------------------------------------------

async def _ensure_container_async(email: str) -> str:
    """Run the blocking docker/subprocess provisioning off the event loop, with
    a per-email lock so concurrent first-login requests don't race to spawn."""
    async with _spawn_lock(email):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, ensure_container, email)


def _starting_page() -> HTMLResponse:
    return _page(
        "Workspace starting",
        '<h1>Workspace starting</h1>'
        '<p>Your workspace is still starting or failed to start. Please retry in a moment.</p>'
        '<a class="btn" href="/">Retry</a>',
        status_code=502,
    )


async def proxy_http(request: Request):
    email = _read_cookie(request)
    if not email:
        return RedirectResponse("/login", status_code=302)
    try:
        name = await _ensure_container_async(email)
    except ContainerNotReady:
        return _starting_page()
    url = f"http://{name}:{PORT}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in HOP_BY_HOP and k.lower() not in FORWARDED_HEADERS
    }
    headers["host"] = f"{name}:{PORT}"
    # Set forwarding headers ourselves from the real connection — never trust
    # client-supplied X-Forwarded-* (audit IP / prefix-redirect poisoning).
    headers["x-forwarded-for"] = request.client.host if request.client else ""
    headers["x-forwarded-proto"] = PUBLIC_SCHEME
    body = await request.body()
    async with httpx.AsyncClient(timeout=None) as client:
        upstream = await client.request(
            request.method, url, headers=headers, content=body,
            follow_redirects=False,
        )
    out_headers = {
        k: v for k, v in upstream.headers.items() if k.lower() not in HOP_BY_HOP
    }
    return Response(
        content=upstream.content, status_code=upstream.status_code, headers=out_headers,
    )


async def proxy_ws(ws: WebSocket):
    # Origin check: a cookie alone would let any cross-site page open a WS to
    # the victim's PTY shell. Require the Origin to match our public host.
    origin = ws.headers.get("origin")
    if PUBLIC_HOST and origin:
        if urlsplit(origin).netloc != PUBLIC_HOST:
            await ws.close(code=4403)
            return
    elif origin:
        # No configured public host to compare against — reject browser origins.
        await ws.close(code=4403)
        return
    # Cookie auth for the WS handshake.
    tok = ws.cookies.get(COOKIE)
    email = None
    if tok:
        try:
            email = jwt.decode(tok, SECRET, algorithms=["HS256"]).get("email")
        except jwt.InvalidTokenError:
            email = None
    if not email:
        await ws.close(code=4401)
        return
    try:
        name = await _ensure_container_async(email)
    except ContainerNotReady:
        await ws.close(code=4503)
        return
    path = ws.url.path
    if ws.url.query:
        path += f"?{ws.url.query}"
    upstream_url = f"ws://{name}:{PORT}{path}"
    await ws.accept()
    try:
        async with websockets.connect(upstream_url, open_timeout=20, max_size=None) as up:
            async def c2u():
                while True:
                    msg = await ws.receive()
                    if msg["type"] == "websocket.disconnect":
                        await up.close()
                        return
                    if msg.get("text") is not None:
                        await up.send(msg["text"])
                    elif msg.get("bytes") is not None:
                        await up.send(msg["bytes"])

            async def u2c():
                async for message in up:
                    if isinstance(message, bytes):
                        await ws.send_bytes(message)
                    else:
                        await ws.send_text(message)

            await asyncio.gather(c2u(), u2c())
    except Exception:
        pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass


app = Starlette(routes=[
    Route("/login", login),
    Route("/auth/start", start_login),
    Route("/auth/callback", callback),
    Route("/logout", logout),
    WebSocketRoute("/{path:path}", proxy_ws),
    Route("/{path:path}", proxy_http, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
])
