# Google auth gate + per-user FS

A Google login that meets the user **before** the Hermes web UI, then pins each
user to their own profile (private filesystem) wired to their role's shared
space (shared filesystem).

## Pieces

| Piece | Where | What it does |
|-------|-------|--------------|
| `GoogleDashboardAuthProvider` | `plugins/dashboard_auth/google/` | OAuth2 (auth-code + PKCE, confidential client) against Google. Verifies the `id_token` against Google JWKS. Restricts login to your team via `GOOGLE_ALLOWED_DOMAIN` / `GOOGLE_ALLOWED_EMAILS`. Persists **all** captured identity fields for later RBAC tuning. |
| Profile lock | `hermes_cli/dashboard_auth/rbac_map.py` + patched `web_server.py` / `middleware.py` | After login, a non-admin user is pinned to `u-<email-slug>`; any `?profile=other` is overridden. Admins (`HERMES_ADMIN_EMAILS`) keep the machine-level switcher. |
| Provisioning | `rbac/provision-user.sh` (auto-run on first login) | Creates the user's profile (private FS) and wires the role's shared FS (`/shared`) + shared skills. |
| Identity store | `<HERMES_HOME>/rbac/identities/<sub>.json` | Full id_token claims + `/userinfo` + granted scopes + login count/timestamps. Where `hd` (domain) and any future Workspace group/role claims land. |

## Two-tier filesystem

- **Private (per-user):** the user's own profile `HERMES_HOME` (memory, skills,
  sessions) + own container home (`terminal.home_mode: profile`, docker backend).
- **Shared (per-role):** `<HERMES_HOME>/shared/<role>` mounted into every
  same-role user's container at `/shared`, plus the role's read-only
  `shared-skills` bundles via `skills.external_dirs`.

## Google Cloud Console setup (corporate / Workspace)

1. APIs & Services → Credentials → **Create Credentials → OAuth client ID**.
2. Application type: **Web application**.
3. **Authorized redirect URIs** → add `<dashboard-base-url>/auth/callback`.
   - Google requires the redirect URI to be **HTTPS** unless the host is
     `localhost`/`127.0.0.1`. Options:
     - **Dev:** tunnel to localhost — `ssh -L 9119:localhost:9119 …` (or Docker
       Desktop's `http://127.0.0.1:9119`) and register
       `http://localhost:9119/auth/callback`.
     - **OrbStack/HTTPS:** use the OrbStack HTTPS domain
       `https://hermes-dashboard.orb.local/auth/callback` (valid cert, no port).
     - **Prod:** put the dashboard behind an HTTPS reverse proxy and register
       that public `https://…/auth/callback`.
4. Copy the **Client ID** and **Client secret**.
5. Because it's a corporate Workspace, set `GOOGLE_ALLOWED_DOMAIN=<yourco.com>`
   so only company accounts can log in (the `hd` claim is verified server-side).

## Enable it

In `.env`:

```
GOOGLE_CLIENT_ID=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=...
GOOGLE_ALLOWED_DOMAIN=yourco.com
HERMES_ADMIN_EMAILS=you@yourco.com
HERMES_DEFAULT_ROLE=viewer
ROUTER_SECRET=$(openssl rand -hex 32)
HERMES_HOST_DATA=/abs/path/to/~/.hermes
HERMES_DASHBOARD_PUBLIC_URL=https://your-public-url
```

**Production (router):** bring up the router; it serves the gate and spawns a
per-user container on first login.

```bash
docker network create hermes-rbac-net   # once
HERMES_UID=$(id -u) HERMES_GID=$(id -g) \
  docker compose -f docker-compose.yml -f docker-compose.router.yml up -d router
```

Register `<public-url>/auth/callback` as an Authorized redirect URI, open the
public URL → branded `/login` → **Continue with Google** → company account →
you land in your own container scoped to your profile.

**Legacy (standalone dashboard):** the machine-level admin dashboard in
`docker-compose.mac.yml` can run gated instead — switch its `command` from the
`--insecure` line to the gated line and recreate the `dashboard` service. This
is superseded by the router for end users.

## Roles from Workspace (future)

Standard OIDC has no `role`/`groups` claim. To drive roles from Workspace
groups, either (a) configure Google to emit a custom `groups` claim, or (b)
query the Admin SDK Directory API with a service account. Either way the data
will appear in the identity store, and `rbac_map.role_for_email()` can then map
group → role instead of the current admin-allowlist + default-viewer scheme.

## Verified vs. needs-your-creds

Verified headlessly: plugin registers & is advertised (`/api/auth/providers` →
`google`), gate engages (`/` → 302 `/login`, `/api/profiles` → 401), profile
lock overrides `?profile=`, per-user provisioning builds the two-tier FS,
identity persistence writes the full record.

Needs your Google OAuth client + a browser: the actual Google consent + token
exchange, and the live per-user redirect end-to-end.

## Production front door: the router

In production the **router** (`rbac/router/router.py`), not the standalone
dashboard, serves the gate. It reuses `GoogleDashboardAuthProvider`, then
reverse-proxies to the user's own container. Operational notes:

- **`ROUTER_SECRET`** signs the session cookie and **must** be ≥32 chars — the
  router refuses to start otherwise (`openssl rand -hex 32`). A weak/default
  secret would let anyone forge a cookie for any email. `docker-compose.router.yml`
  uses a `:?` guard so the value is required.
- **Cookies** (session + PKCE) are `SameSite=Lax`, `HttpOnly`, and `Secure` over
  HTTPS. Lax (not Strict) is required: the post-OAuth landing on `/` is the tail
  of a cross-site redirect from Google, and Strict would withhold the cookie
  there → an endless `/login` loop.
- **Branded UX**: `/login` renders a branded "Continue with Google" page;
  denied-domain / failed sign-in render friendly HTML (never raw JSON or
  exception text).
- **Stable SPA token**: the router pins each container's `--insecure` session
  token to `hmac(ROUTER_SECRET, email)` so container respawns/restarts don't
  invalidate an already-open browser tab.

## WebSocket enforcement (closed)

The `/chat` PTY and the gateway/event WebSockets authenticate via a minted
ticket rather than the HTTP auth middleware. The ticket now carries the verified
email, and the handlers re-apply the per-user lock for the socket's lifetime
(`_ws_rbac_lock`), so a pinned user can no longer pass `?profile=<other>` on
`/api/pty` or drive another tenant's gateway; pub/sub channels are namespaced
per tenant. (REST API, skills, config, env, sessions, memory, logs, and cron
were already enforced.)
