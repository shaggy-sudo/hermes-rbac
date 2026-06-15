# Hermes RBAC layer

Role-based isolation of **context (memory)**, **skills**, and **execution
environment (venv/tools)** built on top of Hermes' native **profiles**.

## Core idea: role = profile

A Hermes *profile* is a separate `HERMES_HOME` directory with its own
`config.yaml`, `.env`, `SOUL.md`, **memory**, sessions, **skills**, cron jobs,
state DB, and gateway. We map **one role → one profile**. That gives us, for
free:

| Requirement            | How profiles deliver it                                              |
|------------------------|----------------------------------------------------------------------|
| Context per role       | Memory / sessions / `state.db` are per-`HERMES_HOME` → isolated.     |
| Skills per role        | Each profile has its own `skills/`; shared skills via `external_dirs`.|
| venv / tools per role  | `terminal.home_mode: profile` + `terminal.backend: docker` → each role gets its own container `HOME`, packages, and CLI creds. |

So memory and skills are isolated *natively* — no external store (e.g. Cognee)
required for that part.

## What profiles do NOT give you (the layer we add)

1. **Enforcement, not just separation.** On the `local` terminal backend the
   agent still sees the whole host filesystem. To make a role a real boundary,
   every role-profile must run on a **container** backend (`docker`). `init-role.sh`
   sets this by default.
2. **Identity → role mapping.** A profile is selected by `-p <name>`, not by
   *who* is messaging. Two supported models:
   - **One bot per role** (native, simplest): each role-profile has its own
     gateway bot token. A user talks to the bot for their role. Cross-role
     access is impossible because the bots are separate processes with separate
     `HERMES_HOME`.
   - **Router gateway** (future): one front bot authenticates the sender and
     dispatches to the right profile. Not built yet; tracked in `TODO`.

## Permission model

`rbac/roles.yaml` is the single source of truth. Each role declares its allowed
toolsets, shared skill bundles, and execution backend. `init-role.sh` reads it
and materializes a profile.

```yaml
roles:
  admin:
    toolsets: [hermes-cli]          # everything
    backend: docker
    shared_skills: [common]
  developer:
    toolsets: [terminal, file, web, skills, todo]
    backend: docker
    shared_skills: [common, coding]
  viewer:
    toolsets: [web, vision, skills]  # no terminal → read-only
    backend: docker
    shared_skills: [common]
```

Key enforcement points (where a role's limits actually bite):

- **Toolset gating** → `platform_toolsets` in the profile's `config.yaml`.
  Removing `terminal` from `viewer` means it cannot run shell commands at all —
  this is what stops a low-privilege role from escaping skill/memory limits via
  a raw shell.
- **Execution isolation** → `terminal.backend: docker` + `home_mode: profile`
  per role: separate container, separate venv, separate `~/.ssh`/`~/.gitconfig`.
- **Skill scope** → per-profile `skills/` + read-only `skills.external_dirs`
  pointing at `rbac/shared-skills/<bundle>`.

## Layout

```
rbac/
  roles.yaml             # role → permissions (source of truth)
  init-role.sh           # materialize a role as a Hermes profile
  shared-skills/         # read-only skill bundles mounted into roles
    common/
    coding/
```

## Quick start (after the image is built)

```bash
# 1. bring up the stack (Mac)
HERMES_UID=$(id -u) HERMES_GID=$(id -g) \
  docker compose -f docker-compose.yml -f docker-compose.mac.yml up -d

# 2. create role-profiles from roles.yaml (run inside the container)
docker exec hermes bash /opt/hermes/rbac/init-role.sh developer
docker exec hermes bash /opt/hermes/rbac/init-role.sh viewer

# 3. give each role its bot token + provider key
docker exec hermes hermes -p developer setup

# 4. start a role's gateway (supervised by s6)
docker exec hermes hermes -p developer gateway start
```

The web dashboard manages every role-profile via its profile switcher (config,
keys, skills, model). URL depends on your Docker runtime:
- **OrbStack**: http://hermes-dashboard.orb.local:9119
- **Docker Desktop**: http://127.0.0.1:9119
