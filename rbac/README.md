# Hermes RBAC layer

Role-based isolation of **context (memory)**, **skills**, **files**, and
**execution environment** built on top of Hermes' native **profiles**, with a
corporate Google login in front and per-user isolation enforced by a trusted
router.

## Core idea: role = profile, user = container

A Hermes *profile* is a separate `HERMES_HOME` directory with its own
`config.yaml`, `.env`, `SOUL.md`, **memory**, sessions, **skills**, cron jobs,
state DB, and gateway. We build two things on top:

- **role → permissions** (`roles.yaml`): which toolsets, shared skills, and
  shared-volume access a role gets.
- **user → their own profile + container**: each authenticated Google user is
  routed to their **own** dashboard container that mounts ONLY their private
  profile (`/opt/data`) and their role's shared volume (`/shared`).

So memory, skills, files, and sessions are isolated *natively* by the profile
dir, and the per-user container makes that isolation a hard boundary (see
[Why a container per user](#why-a-container-per-user)).

## Architecture (production): router + per-user container

```
browser ─▶ cloudflare tunnel ─▶ router (Google gate, docker.sock, TRUSTED)
                                   │ spawns / reverse-proxies to
                                   ▼
                          per-user dashboard container
                          mounts ONLY:
                            <data>/profiles/<user>  as /opt/data  (private)
                            <data>/shared/<role>    as /shared    (role-shared)
```

- **Router** (`rbac/router/router.py`) is the only component with docker access.
  It runs the Google OAuth gate (`/login` → `/auth/start` → `/auth/callback`),
  issues a signed session cookie, and reverse-proxies HTTP + WebSocket to the
  user's container, spawning it on first use (`ensure_container`).
- **Per-user containers** (`hermes-u-<slug>`) run the dashboard `--insecure` on
  an internal network, reachable only through the router. A non-admin mounts
  only their own profile + role `/shared`; an admin mounts the full data volume
  and is vouched as admin via `HERMES_RBAC_ADMIN_EMAIL`.

### Why a container per user

A shared dashboard with a per-request "profile lock" still exposes the chat PTY
(`!`-shell escape) and any un-pinned endpoint to the host/other profiles. Giving
each user their own container means the only data on disk inside it is theirs —
the mount *is* the boundary. The in-process lock (below) is still enforced as
defense-in-depth and protects the legacy single-dashboard mode + the admin
container.

## Permission model

`rbac/roles.yaml` is the single source of truth. Each role declares its allowed
toolsets, shared skill bundles, execution backend, and (optionally) shared
volume access.

```yaml
roles:
  admin:
    toolsets: [hermes-cli]           # full per-container toolset
    backend: docker
    shared_skills: [common]
  developer:
    toolsets: [terminal, file, web, vision, skills, todo, cronjob]
    backend: docker
    shared_skills: [common, coding]
  viewer:
    toolsets: [web, vision, skills, todo]  # no terminal/file → read-only
    backend: docker
    shared_skills: [common]
```

Enforcement points (where a role's limits actually bite):

- **Toolset gating** → `platform_toolsets` in the profile's `config.yaml`
  (written by `provision-user.sh`). Removing `terminal`/`file` from `viewer`
  stops it running shell commands or writing files.
- **Container mount** → the router mounts only the user's profile + role
  `/shared`; other tenants' data is simply not present.
- **Shared `rw`/`ro`** → per role, persisted in
  `<HERMES_HOME>/rbac/shared-access.json` (managed from the `/rbac` console).
  When a role is `ro`, the router mounts `/shared` read-only so a same-role
  tenant cannot poison shared context (e.g. `/shared/MEMORY.md`). Bind mode is
  fixed at container creation, so respawn the role's containers after toggling.
- **Request lock** (`rbac_map.py`) → a non-admin request/WS is pinned to its own
  profile; `enforce()` overrides any `?profile=other`, and the file/env/config/
  skills/sessions/memory/logs/cron endpoints resolve through it. Admins and the
  loopback/`--insecure` single-operator mode run unlocked.

See [../RBAC.md](../RBAC.md#security--isolation-guarantees) for the full
endpoint-by-endpoint guarantee table and [CHANGELOG.md](CHANGELOG.md) for the
hardening history.

## Identity, roles, and the admin console

- **Identity → profile/role** (`rbac_map.py`): `profile_for_email()` → `u-<slug>`,
  `role_for_email()` (admin allowlist > `role-overrides.json` > `HERMES_DEFAULT_ROLE`/viewer),
  `is_admin()` (`HERMES_ADMIN_EMAILS`).
- **Identity store**: `<HERMES_HOME>/rbac/identities/<sub>.json` — full id_token
  claims, `hd` (domain), granted scopes, login counts. Where future Workspace
  group→role mapping will read from.
- **Shared Management console** (`/rbac`, admin-only): roles CRUD (writes
  `roles.yaml`), members + role overrides, captured identities, shared-file
  browse/upload/download/view/delete, shared `MEMORY.md` editor, and the
  per-role `rw`/`ro` flag. Backed by `/api/rbac/*` (admin-gated + CSRF header).
- The router vouches each user's identity (`HERMES_RBAC_USER_EMAIL/ROLE/IS_ADMIN`)
  into their container so the SPA's `/api/auth/me` can show their role and
  filter the nav even though the container has no in-container session.

## Two-tier model

| Tier | Private (per-user) | Shared (per-role) |
|------|--------------------|-------------------|
| Files | profile `/opt/data` | `/shared` volume (`rw` or `ro`) |
| Memory | profile `MEMORY.md` | `/shared/MEMORY.md` (injected via `pre_llm_call` hook) |
| Skills | profile `skills/` | `rbac/shared-skills/<bundle>` (read-only via `external_dirs`) |

## Layout

```
rbac/
  roles.yaml                  # role → permissions (source of truth)
  provision-user.sh           # create a user profile (auto-run on first login)
  init-role.sh                # materialize a ROLE profile (legacy one-bot-per-role path)
  router/router.py            # Google gate + per-user container spawn + proxy
  hooks/inject-shared-memory.sh  # pre_llm_call hook: inject /shared/MEMORY.md
  shared-skills/              # read-only skill bundles mounted into roles
    common/  coding/
  shared-access.json          # (runtime, under HERMES_HOME) per-role rw|ro
  identities/<sub>.json       # (runtime, under HERMES_HOME) captured Google identities
  test_rbac_admin_routes.py        # admin console gate + CRUD + CSRF
  test_rbac_endpoint_confinement.py  # locked-vs-unlocked endpoint confinement
```

## Quick start

See [../RBAC.md](../RBAC.md#quick-start-macos--orbstack) for the router quick
start, and [AUTH.md](AUTH.md) for the Google OAuth client setup.

### Legacy: one bot per role / standalone dashboard

Before the router, isolation relied on one gateway bot per role-profile and the
`docker` terminal backend (each role a separate container `HOME`/venv).
`init-role.sh <role>` still materializes a role-profile for that model, and
`docker-compose.mac.yml` runs the machine-level admin dashboard. The router
model supersedes this for end users; the standalone dashboard remains as the
admin/machine-management surface.
