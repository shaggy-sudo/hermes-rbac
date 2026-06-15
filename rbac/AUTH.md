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
```

Then in `docker-compose.mac.yml`, switch the dashboard `command` from the
`--insecure` line (MODE 1) to the gated line (MODE 2), and recreate:

```bash
HERMES_UID=$(id -u) HERMES_GID=$(id -g) \
  docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d dashboard
```

Visit the dashboard → it redirects to `/login` → **Log in with Google** →
company account → you land scoped to your own profile.

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

## Known remaining item

The `/chat` tab WebSocket authenticates via a minted ticket, not the HTTP auth
middleware, so the request-scoped profile lock isn't set on that path yet. For
full enforcement on the chat terminal, set the lock during WS ticket validation
(the REST API, skills, config, and cron endpoints are already enforced).
