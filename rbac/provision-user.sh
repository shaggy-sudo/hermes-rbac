#!/usr/bin/env bash
#
# provision-user.sh <email> [role] — create a per-user profile (private FS)
# wired to its role's shared space (shared FS). Idempotent.
#
#   docker exec hermes bash /opt/hermes/rbac/provision-user.sh alice@acme.com developer
#
# Two-tier filesystem result for the user's profile:
#   private (per-user) : the profile's own HERMES_HOME (memory/skills/sessions)
#                        + own docker container home (home_mode=profile).
#   shared (per-role)  : role shared-skills mounted read-only via external_dirs,
#                        and a shared role volume mounted into the container at
#                        /shared (read-write, common to all same-role users).
set -euo pipefail

EMAIL="${1:?usage: provision-user.sh <email> [role]}"
RBAC_DIR="$(cd "$(dirname "$0")" && pwd)"
ROLES_YAML="$RBAC_DIR/roles.yaml"
PY="${HERMES_PYTHON:-python3}"
HOME_ROOT="${HERMES_HOME:-/opt/data}"

# Derive profile id + role exactly like the Python RBAC map (u-<slug>),
# and resolve the role's settings from roles.yaml.
read -r PROFILE ROLE TOOLSETS BACKEND SHARED < <("$PY" - "$ROLES_YAML" "$EMAIL" "${2:-}" <<'PY'
import sys, re, hashlib, yaml
roles_yaml, email, role_arg = sys.argv[1], sys.argv[2].strip().lower(), sys.argv[3].strip()
slug = re.sub(r"[^a-z0-9]+", "-", email).strip("-") or "user"
prof = f"u-{slug}"
if len(prof) > 64 or prof.endswith("-"):
    prof = f"u-{slug[:50].rstrip('-')}-{hashlib.sha256(email.encode()).hexdigest()[:8]}"
roles = yaml.safe_load(open(roles_yaml))["roles"]
role = role_arg or "viewer"
r = roles.get(role) or roles["viewer"]
print(prof, role, ",".join(r.get("toolsets", ["safe"])), r.get("backend", "docker"),
      " ".join(r.get("shared_skills", [])))
PY
)

# In the per-user-container (router) model the container itself is the
# sandbox, so the terminal runs LOCALLY inside it. Override via env.
BACKEND="${HERMES_RBAC_TERMINAL_BACKEND:-$BACKEND}"

echo ">> provisioning user=$EMAIL -> profile=$PROFILE role=$ROLE backend=$BACKEND"

if ! hermes profile list 2>/dev/null | grep -qw "$PROFILE"; then
    hermes profile create "$PROFILE" --description "User $EMAIL (role: $ROLE)"
fi

# Shared role volume on the host/data side, mounted into the user's container.
SHARED_HOST="$HOME_ROOT/shared/$ROLE"
mkdir -p "$SHARED_HOST"

PROFILE_HOME="$HOME_ROOT/profiles/$PROFILE"
CONFIG="$PROFILE_HOME/config.yaml"

MODEL="${HERMES_DEFAULT_MODEL:-openrouter/owl-alpha}"

RBAC_DIR="$RBAC_DIR" ROLE="$ROLE" TOOLSETS="$TOOLSETS" BACKEND="$BACKEND" \
SHARED="$SHARED" SHARED_HOST="$SHARED_HOST" CONFIG="$CONFIG" MODEL="$MODEL" "$PY" - <<'PY'
import os, yaml, pathlib
cfg_path = pathlib.Path(os.environ["CONFIG"])
cfg = yaml.safe_load(cfg_path.read_text()) if cfg_path.exists() else {}
cfg = cfg or {}

toolsets = os.environ["TOOLSETS"].split(",")
platforms = ["cli", "telegram", "discord", "whatsapp", "slack", "signal"]
cfg["platform_toolsets"] = {p: list(toolsets) for p in platforms}

term = cfg.setdefault("terminal", {})
term["backend"] = os.environ["BACKEND"]
term["home_mode"] = "profile"
if os.environ["BACKEND"] == "docker":
    term.setdefault("docker_image", "nikolaik/python-nodejs:python3.11-nodejs20")
    term["container_persistent"] = True
    # Mount the shared role volume into the user's container at /shared.
    extra = term.get("docker_extra_args", []) or []
    mount = ["-v", f"{os.environ['SHARED_HOST']}:/shared"]
    if mount[1] not in extra:
        extra += mount
    term["docker_extra_args"] = extra

# Role shared-skills, read-only, on top of the user's own private skills/.
rbac_dir = os.environ["RBAC_DIR"]
shared = os.environ["SHARED"].split() if os.environ["SHARED"].strip() else []
cfg.setdefault("skills", {})["external_dirs"] = [
    f"{rbac_dir}/shared-skills/{b}" for b in shared
]

# LLM model/provider so the auto-provisioned profile can actually run.
model = cfg.setdefault("model", {})
model["default"] = os.environ["MODEL"]
model["provider"] = "openrouter"

# SHARED memory tier: inject /shared/MEMORY.md into every LLM turn via a
# pre_llm_call shell hook. pre_llm_call is not a tool event, so no matcher.
hooks = cfg.setdefault("hooks", {})
pre = hooks.setdefault("pre_llm_call", [])
hook_cmd = "/opt/hermes/rbac/hooks/inject-shared-memory.sh"
if not any(isinstance(h, dict) and h.get("command") == hook_cmd for h in pre):
    pre.append({"command": hook_cmd, "timeout": 10})
# Non-interactive (gateway/dashboard) runs need consent pre-granted to register.
cfg["hooks_auto_accept"] = True

cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))
print(f"   private FS : {cfg_path.parent}")
print(f"   shared FS  : {os.environ['SHARED_HOST']} -> /shared (role {os.environ['ROLE']})")
print(f"   toolsets   : {toolsets}")
PY

# Seed the LLM key into the profile .env so the user's container can run.
if [ -n "${OPENROUTER_API_KEY:-}" ]; then
    touch "$PROFILE_HOME/.env"
    grep -v '^OPENROUTER_API_KEY=' "$PROFILE_HOME/.env" > "$PROFILE_HOME/.env.tmp" 2>/dev/null || true
    mv "$PROFILE_HOME/.env.tmp" "$PROFILE_HOME/.env"
    printf 'OPENROUTER_API_KEY=%s\n' "$OPENROUTER_API_KEY" >> "$PROFILE_HOME/.env"
    echo "   seeded OPENROUTER_API_KEY into profile .env"
fi

echo ">> user '$EMAIL' provisioned. Profile '$PROFILE' ready."
