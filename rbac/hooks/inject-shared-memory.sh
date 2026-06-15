#!/bin/sh
#
# inject-shared-memory.sh — Hermes pre_llm_call shell hook (RBAC SHARED tier)
#
# Injects the role-shared team memory file (/shared/MEMORY.md) into the next
# LLM call as ephemeral context, labeled as shared team memory. Each user keeps
# their own private MEMORY.md under HERMES_HOME; this adds the per-role tier
# common to everyone in the same role (the shared volume mounted at /shared).
#
# Wire protocol (see website/docs/user-guide/features/hooks.md):
#   - stdin : JSON payload for the pre_llm_call event (ignored here).
#   - stdout: {"context": "..."} to inject, or {} for a silent no-op.
#
# Robustness: missing or empty/whitespace-only file -> emit {} (no injection).
# Malformed JSON / non-zero exit / timeout are caught by Hermes and never abort
# the agent loop, but we still aim to always print exactly one valid JSON object.

set -u

SHARED_MEMORY="${RBAC_SHARED_MEMORY:-/shared/MEMORY.md}"

# Drain stdin so the writer never blocks on a full pipe; payload is unused.
cat - >/dev/null 2>&1 || true

# No file -> silent no-op.
if [ ! -f "$SHARED_MEMORY" ] || [ ! -r "$SHARED_MEMORY" ]; then
    printf '{}\n'
    exit 0
fi

# Prefer the in-container venv python for correct JSON escaping; fall back to
# any python3 on PATH. If neither exists, degrade to a safe no-op.
PY=""
if [ -x /opt/hermes/.venv/bin/python ]; then
    PY=/opt/hermes/.venv/bin/python
elif command -v python3 >/dev/null 2>&1; then
    PY=python3
fi

if [ -z "$PY" ]; then
    printf '{}\n'
    exit 0
fi

SHARED_MEMORY="$SHARED_MEMORY" "$PY" - <<'PY'
import json, os, sys

path = os.environ["SHARED_MEMORY"]
try:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        content = fh.read()
except OSError:
    sys.stdout.write("{}\n")
    sys.exit(0)

# Empty or whitespace-only -> no injection.
if not content.strip():
    sys.stdout.write("{}\n")
    sys.exit(0)

header = (
    "Shared team memory (role-wide, from /shared/MEMORY.md). "
    "These facts are shared by all users of your role; treat them as "
    "authoritative team context. Do not write to this file."
)
context = header + "\n\n" + content.strip()
sys.stdout.write(json.dumps({"context": context}) + "\n")
PY
