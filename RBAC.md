# Hermes RBAC fork

A fork of [NousResearch/hermes-agent](https://github.com/NousResearch/hermes-agent)
adding **team role-based access control**: corporate Google login in front of the
web UI, and per-user isolation of filesystem, memory, and skills.

> Role = access control, not persona. Each authenticated user gets their own
> isolated container; roles define what tools, shared files, and shared memory
> they get.

## Architecture (per-user container + router)

```
browser ─▶ cloudflare tunnel ─▶ router (Google gate, docker.sock)
                                   │ spawns / proxies to
                                   ▼
                         per-user dashboard container
                         mounts ONLY: <data>/profiles/<user> as /opt/data
                                      <data>/shared/<role>   as /shared
```

The router (`rbac/router/router.py`) is the only trusted component with docker
access. Each user's chat/agent runs in their own container, so even the chat
PTY `!`-shell can't reach other users' data — the isolation a shared dashboard
could not provide.

### Two-tier model
| Tier | Private (per-user) | Shared (per-role) |
|------|--------------------|-------------------|
| Files | profile `/opt/data` | `/shared` volume |
| Memory | profile `MEMORY.md` | `/shared/MEMORY.md` (injected via hook) |
| Skills | profile `skills/` | `rbac/shared-skills/<bundle>` (read-only) |

## Security & isolation guarantees

A non-admin request runs under a request-scoped **profile lock** (set from the
authenticated email). Every data surface confines to the locked profile + the
role's `/shared`:

| Surface | Confinement |
|---------|-------------|
| Files (`/api/fs/*`, `/api/files`) | own profile home + role `/shared` only |
| Env / secrets (`/api/env*`) | own profile `.env`; reveal/write never reach another profile |
| Config / skills / toolsets / memory | resolved through the lock even when `?profile=` is omitted |
| Sessions (`/api/sessions*`, `/api/profiles/sessions`) | only the locked profile's `state.db` |
| Logs, media, cron | scoped to the locked profile |
| Chat / agent (`/api/pty`, `/api/ws`, `/api/pub`, `/api/events`) | WS ticket carries the verified email; the lock is re-applied for the socket lifetime, so `?profile=<other>` cannot escape, and pub/sub channels are namespaced per tenant |
| Profile lifecycle (create/rename/delete/set-active) | **admin-only** (403 under a lock) |

Admins (allowlist `HERMES_ADMIN_EMAILS`) and the loopback/`--insecure`
single-operator mode run **unlocked** — unrestricted, as before.

Operational hard requirements:
- **`ROUTER_SECRET`** must be a high-entropy value (≥32 chars); the router
  *refuses to start* otherwise (`openssl rand -hex 32`). A weak/default secret
  would let anyone forge a session cookie for any email.
- **Shared `rw`/`ro`** per role is enforced at the mount: `ro` roles get
  `/shared` mounted read-only. The flag lives in
  `<HERMES_HOME>/rbac/shared-access.json` (managed from the `/rbac` console);
  bind mode is fixed at container creation, so toggling it requires respawning
  the affected role's containers.

Regression coverage: `rbac/test_rbac_endpoint_confinement.py` (locked vs
unlocked endpoint behavior), `rbac/test_rbac_admin_routes.py` (admin gate +
CRUD + CSRF), and `tests/hermes_cli/test_dashboard_auth_ws_auth.py` (WS ticket
email propagation + channel namespacing).

## Docs
- **[rbac/README.md](rbac/README.md)** — RBAC model, roles, provisioning
- **[rbac/AUTH.md](rbac/AUTH.md)** — Google OAuth gate setup (Cloud Console, redirect URI)
- **[rbac/SYNC.md](rbac/SYNC.md)** — keeping this fork in sync with upstream Hermes
- **[rbac/hooks/README.md](rbac/hooks/README.md)** — shared role-memory hook
- **[rbac/CHANGELOG.md](rbac/CHANGELOG.md)** — RBAC layer change history (hardening pass)

## Quick start (macOS / OrbStack)
```bash
# 1. build
docker build -t hermes-agent .

# 2. config: copy .env (gitignored) with GOOGLE_CLIENT_ID/SECRET, OPENROUTER_API_KEY,
#    HERMES_ADMIN_EMAILS, HERMES_HOST_DATA=<host path of ~/.hermes>, ROUTER_SECRET

# 3. network + router
docker network create hermes-rbac-net
HERMES_UID=$(id -u) HERMES_GID=$(id -g) \
  docker compose -f docker-compose.yml -f docker-compose.router.yml up -d router

# 4. public URL (stable) via cloudflare named tunnel
cloudflared tunnel run --url http://hermes-router.orb.local:9200 hermes-rbac
```
Register `<public-url>/auth/callback` as an Authorized redirect URI in the
Google OAuth client, then open the public URL and log in.

## Key files
| Path | What |
|------|------|
| `rbac/router/router.py` | Google gate + per-user container spawn + reverse proxy |
| `rbac/roles.yaml` | role → toolsets / backend / shared_skills |
| `rbac/provision-user.sh` | create a user profile (private FS + role shared) |
| `hermes_cli/dashboard_auth/google/` | Google `DashboardAuthProvider` plugin |
| `hermes_cli/dashboard_auth/rbac_map.py` | email→profile/role, profile lock |
| `hermes_cli/dashboard_auth/rbac_admin.py` | Shared Management admin UI (`/rbac`) |
| `hermes_cli/dashboard_auth/rbac_admin.py` | `/rbac` admin console (roles CRUD, members, shared files/memory, permissions) |
| `<HERMES_HOME>/rbac/shared-access.json` | per-role `rw`/`ro` shared-volume flag (managed in the console) |
| `docker-compose.router.yml` | router service (the production front door) |
| `docker-compose.mac.yml` | legacy machine-level dashboard (admin) |

MIT-licensed, same as upstream Hermes Agent.
