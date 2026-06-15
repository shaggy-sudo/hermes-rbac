---
name: team-conventions
description: "Shared team conventions available to every role (read-only)."
version: 1.0.0
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [team, conventions, rbac, shared]
    related_skills: []
---

# Team Conventions

This is a **shared** skill bundle mounted read-only into every role-profile via
`skills.external_dirs`. Edit it once here (`rbac/shared-skills/common/`) and all
roles see the change. Roles cannot modify it — skill creation always writes to
the role's own `skills/`.

## What belongs here

- Team-wide norms (tone, languages, escalation paths).
- Pointers to shared infra that every role may reference.

## What does NOT belong here

- Role-specific procedures → put those in the role's own profile `skills/`.
- Secrets → those live in each profile's `.env`, never in a skill.
