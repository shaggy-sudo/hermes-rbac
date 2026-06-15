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
  ROUTER_PUBLIC_URL                         e.g. https://xxx.ngrok-free.app
  ROUTER_SECRET                             cookie-signing secret
  HERMES_HOST_DATA                          HOST path of ~/.hermes (for -v src)
  HERMES_IMAGE                              per-user container image
  HERMES_NET                                docker network shared with users
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import time

import httpx
import jwt
import websockets
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
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
SECRET = os.environ.get("ROUTER_SECRET") or "dev-insecure-secret-change-me"
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


def ensure_container(email: str) -> str:
    """Provision the user's profile (once) and ensure their dashboard container
    is running with ONLY their profile + role-shared mounted. Returns the
    container name (reachable by the router at http://<name>:9119)."""
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

    admin_env: list[str] = []
    if admin:
        # Admins get the full data volume (machine-level management) + a vouch
        # so the Shared Management admin UI (/rbac) recognises them despite the
        # container running --insecure with no in-container session.
        mounts = ["-v", f"{HOST_DATA}:/opt/data"]
        admin_env = ["-e", f"HERMES_RBAC_ADMIN_EMAIL={email}"]
    else:
        # Non-admins: ONLY their profile (as /opt/data) + their role's /shared.
        mounts = [
            "-v", f"{HOST_DATA}/profiles/{profile}:/opt/data",
            "-v", f"{HOST_DATA}/shared/{role}:/shared",
        ]

    _docker(
        "run", "-d", "--name", name, "--network", NET, "--restart", "unless-stopped",
        "-e", "HERMES_UID=10000", "-e", "HERMES_GID=10000",
        "-e", f"OPENROUTER_API_KEY={_OPENROUTER}",
        *admin_env,
        *mounts,
        IMAGE, "dashboard", "--host", "0.0.0.0", "--no-open", "--insecure",
        "--port", str(PORT),
    )
    # Give it a moment to bind.
    base = f"http://{name}:{PORT}"
    for _ in range(30):
        try:
            httpx.get(f"{base}/api/status", timeout=2)
            break
        except Exception:
            time.sleep(1)
    return name


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

async def login(request: Request):
    ls = _provider().start_login(redirect_uri=f"{PUBLIC_URL}/auth/callback")
    resp = RedirectResponse(ls.redirect_url, status_code=302)
    resp.set_cookie(
        PKCE_COOKIE, ls.cookie_payload["hermes_session_pkce"],
        httponly=True, secure=PUBLIC_URL.startswith("https"), samesite="lax", max_age=600,
    )
    return resp


async def callback(request: Request):
    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    pkce = request.cookies.get(PKCE_COOKIE, "")
    parts = dict(seg.split("=", 1) for seg in pkce.split(";") if "=" in seg)
    if not code or parts.get("state") != state:
        return JSONResponse({"error": "invalid_state"}, status_code=400)
    try:
        session = _provider().complete_login(
            code=code, state=state, code_verifier=parts.get("verifier", ""),
            redirect_uri=f"{PUBLIC_URL}/auth/callback",
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)
    resp = RedirectResponse("/", status_code=302)
    resp.set_cookie(
        COOKIE, _issue_cookie(session.email),
        httponly=True, secure=PUBLIC_URL.startswith("https"), samesite="lax", max_age=86400,
    )
    resp.delete_cookie(PKCE_COOKIE)
    return resp


async def logout(request: Request):
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie(COOKIE)
    return resp


# ---------------------------------------------------------------------------
# Reverse proxy (HTTP + WebSocket) to the user's container
# ---------------------------------------------------------------------------

async def proxy_http(request: Request):
    email = _read_cookie(request)
    if not email:
        return RedirectResponse("/login", status_code=302)
    name = ensure_container(email)
    url = f"http://{name}:{PORT}{request.url.path}"
    if request.url.query:
        url += f"?{request.url.query}"
    headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP_BY_HOP}
    headers["host"] = f"{name}:{PORT}"
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
    name = ensure_container(email)
    path = ws.url.path
    if ws.url.query:
        path += f"?{ws.url.query}"
    upstream_url = f"ws://{name}:{PORT}{path}"
    await ws.accept()
    try:
        async with websockets.connect(upstream_url, open_timeout=20, max_size=None) as up:
            import asyncio

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
    Route("/auth/callback", callback),
    Route("/logout", logout),
    WebSocketRoute("/{path:path}", proxy_ws),
    Route("/{path:path}", proxy_http, methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]),
])
