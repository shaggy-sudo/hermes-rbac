# RBAC layer changelog

History of the RBAC fork's own changes (on top of upstream
`NousResearch/hermes-agent`). Newest first.

## 2026-06-15/16 — Hardening pass

A multi-agent audit reviewed every HTTP/WebSocket endpoint and method,
adversarially verified the findings, and a follow-up pass fixed them. All
changes were unit-tested and live-verified on the router deployment.

### Isolation (cross-tenant gaps closed)
- `web_server._profile_scope` now routes an omitted `?profile=` through
  `enforce()`, so a locked (non-admin) user can no longer reach the **default
  profile's `.env`/secrets, config, skills, or toolsets** by dropping the
  param. One chokepoint closed the whole class.
- WebSocket handlers (`/api/pty`, `/api/ws`, `/api/pub`, `/api/events`) now
  re-apply the per-user lock from the ticket's verified email for the socket
  lifetime (`_ws_rbac_lock`), so `?profile=<other>` can't escape and pub/sub
  channels are namespaced per tenant. The WS ticket carries the email
  (`ws_tickets.mint_ticket(email=…)`); lock application is shared with the HTTP
  middleware via `rbac_map.lock_tokens_for_email`.
- `/api/profiles/sessions`, `/api/memory*`, `/api/logs`, `/api/media`,
  `/api/sessions/{id}/latest-descendant`, and cron `?profile=all` now honor the
  lock instead of reading the default/all profiles.
- Profile lifecycle (`create`/`rename`/`delete`/`set-active`) is admin-only
  under a lock (403).

### Router (`rbac/router/router.py`)
- **Fail closed** without a ≥32-char `ROUTER_SECRET`; compose uses a `:?` guard.
- Mounts `/shared` **read-only** when the role's `shared-access.json` is `ro`.
- Strips client `X-Forwarded-*`, validates the WebSocket `Origin`, and sets
  `SameSite=Lax` + `Secure` (HTTPS) cookies.
- Branded `/login` + `/auth/start` and friendly HTML error pages (no raw JSON).
- Spawn-failure handling (`ContainerNotReady`), per-email async lock, and
  off-event-loop docker calls.
- Vouches identity into each container (`HERMES_RBAC_USER_EMAIL/ROLE/IS_ADMIN`)
  so `/api/auth/me` works without an in-container session.
- Pins a **stable** per-user dashboard token (`hmac(ROUTER_SECRET, email)`) so
  container respawns don't invalidate open browser tabs.

### Admin console (`rbac_admin.py`)
- Role CRUD (writes `roles.yaml`), shared-file download/view, override removal,
  vouch-aware effective roles, request-size pre-check, CSRF header requirement,
  destructive-action confirms, tab deep-links, identity search, empty states.

### SPA (`web/src`)
- Role/admin badge in the auth widget, role-filtered nav (non-admins lose infra
  pages), a "Shared Management" link to `/rbac` for admins, shared-vs-private
  file badges, and friendlier API error messages (`useAuthMe` hook).

### Provisioning (`provision-user.sh`)
- Enforces the `ro` shared mount from `shared-access.json`; `chmod 600` on the
  profile `.env`.

### Tests
- `rbac/test_rbac_endpoint_confinement.py` (locked-vs-unlocked confinement),
  WS-ticket-email tests in `tests/hermes_cli/test_dashboard_auth_ws_auth.py`,
  and CSRF coverage in `rbac/test_rbac_admin_routes.py`.

### Follow-ups (not done)
- `OPENROUTER_API_KEY` is present in every container's env + profile `.env`, so
  any user with a shell in their own container can read it. A proper fix is an
  LLM egress proxy on the router that holds the key and meters per user
  (deferred — larger change).

### Notes
- In the per-user-container production model each container is `--insecure`
  (no in-container lock) → isolation is the **per-user mount**. The lock-based
  confinement protects the legacy single gated dashboard + the admin container
  (full mount) and is defense-in-depth; it is covered by the confinement tests.
- After any redeploy, an already-open tab should be **hard-refreshed once**
  (Cmd/Ctrl+Shift+R) to pick up the current bundle.
