# RBAC shell hooks

Drop-in Hermes shell hooks for the role-based access control layer.

## `inject-shared-memory.sh` — SHARED (per-role) memory tier

A `pre_llm_call` shell hook that injects the role-shared team-memory file into
the agent's LLM context on every turn. It implements the **shared** tier of the
two-tier memory model:

- **private (per-user):** Hermes's own `MEMORY.md` / `USER.md` under
  `HERMES_HOME` — already isolated per user by the profile mount.
- **shared (per-role):** `/shared/MEMORY.md` — the role's shared volume, mounted
  read-write into every same-role user's container at `/shared`. All users of a
  role see the same team facts.

### How it works

On each turn Hermes fires the `pre_llm_call` event and pipes a JSON payload to
the hook on stdin. The hook:

1. Reads `/shared/MEMORY.md` (override with `RBAC_SHARED_MEMORY`).
2. If the file is missing, unreadable, or empty/whitespace-only, prints `{}`
   (a silent no-op — nothing is injected).
3. Otherwise prints `{"context": "<labeled shared team memory>"}`. Hermes
   appends that text to the current turn's user message (ephemeral; the system
   prompt and prompt cache are untouched, and nothing is persisted).

The injected block is prefixed with a header that labels it as role-wide shared
team memory and tells the model not to write to the file.

### Wire protocol

`pre_llm_call` sends `tool_name` / `tool_input` as `null`; the hook ignores the
payload entirely (it just drains stdin). Output is a single JSON object on
stdout. See `website/docs/user-guide/features/hooks.md` ("Shell Hooks" → "JSON
wire protocol") for the full schema.

### Dependencies

Pure POSIX `sh`. JSON is built with Python for correct escaping — it prefers the
in-container interpreter at `/opt/hermes/.venv/bin/python` and falls back to any
`python3` on `PATH`. With no Python available it degrades to `{}`.

### Manual test

```sh
mkdir -p /tmp/shared
printf '# Team Memory\n- deploy to eu-west-1\n' > /tmp/shared/MEMORY.md
printf '{"hook_event_name":"pre_llm_call"}' \
  | RBAC_SHARED_MEMORY=/tmp/shared/MEMORY.md ./inject-shared-memory.sh \
  | python3 -m json.tool
```

Or, inside a provisioned container: `hermes hooks test pre_llm_call`.

### Integration

This hook is wired into each user profile's `config.yaml` by
`rbac/provision-user.sh` under the `hooks.pre_llm_call` block, pointing at the
absolute in-container path `/opt/hermes/rbac/hooks/inject-shared-memory.sh`.
Because the gateway is non-interactive, the profile config also sets
`hooks_auto_accept: true` so the hook registers without a TTY consent prompt
(equivalently, set `HERMES_ACCEPT_HOOKS=1` in the container environment).
