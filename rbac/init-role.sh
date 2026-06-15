#!/usr/bin/env bash
#
# init-role.sh <role> — materialize a role from roles.yaml as a Hermes profile
# with isolated memory, skills, and execution venv.
#
# Run inside the container:
#   docker exec hermes bash /opt/hermes/rbac/init-role.sh developer
#
# Idempotent: re-running re-applies config without wiping memory/sessions.
set -euo pipefail

ROLE="${1:?usage: init-role.sh <role>}"
RBAC_DIR="$(cd "$(dirname "$0")" && pwd)"
ROLES_YAML="$RBAC_DIR/roles.yaml"
PY="${HERMES_PYTHON:-python3}"

[ -f "$ROLES_YAML" ] || { echo "missing $ROLES_YAML" >&2; exit 1; }

# Pull the role's settings out of roles.yaml as shell-eval lines.
eval "$("$PY" - "$ROLES_YAML" "$ROLE" <<'PY'
import sys, yaml, shlex
roles = yaml.safe_load(open(sys.argv[1]))["roles"]
r = roles.get(sys.argv[2])
if r is None:
    sys.exit(f"unknown role: {sys.argv[2]} (have: {', '.join(roles)})")
print("DESC=" + shlex.quote(r.get("description", "")))
print("BACKEND=" + shlex.quote(r.get("backend", "docker")))
print("TOOLSETS=" + shlex.quote(",".join(r.get("toolsets", ["safe"]))))
print("SHARED=" + shlex.quote(" ".join(r.get("shared_skills", []))))
PY
)"

echo ">> role=$ROLE backend=$BACKEND toolsets=$TOOLSETS shared_skills=[$SHARED]"

# 1. Create the profile if it doesn't exist (gives it isolated home).
if ! hermes profile list 2>/dev/null | grep -qw "$ROLE"; then
    hermes profile create "$ROLE" --description "$DESC"
fi

PROFILE_HOME="${HERMES_HOME:-/opt/data}/profiles/$ROLE"
CONFIG="$PROFILE_HOME/config.yaml"

# 2. Patch the profile's config.yaml: toolset gating + isolated execution +
#    read-only shared skill bundles. Done in Python for safe YAML merging.
RBAC_DIR="$RBAC_DIR" ROLE="$ROLE" BACKEND="$BACKEND" TOOLSETS="$TOOLSETS" \
SHARED="$SHARED" CONFIG="$CONFIG" "$PY" - <<'PY'
import os, yaml, pathlib

cfg_path = pathlib.Path(os.environ["CONFIG"])
cfg = {}
if cfg_path.exists():
    cfg = yaml.safe_load(cfg_path.read_text()) or {}

toolsets = os.environ["TOOLSETS"].split(",")
backend = os.environ["BACKEND"]
rbac_dir = os.environ["RBAC_DIR"]
shared = os.environ["SHARED"].split() if os.environ["SHARED"].strip() else []

# Toolset gating — applies to every messaging platform + cli.
platforms = ["cli", "telegram", "discord", "whatsapp", "slack", "signal"]
cfg["platform_toolsets"] = {p: list(toolsets) for p in platforms}

# Execution isolation: own container + own HOME (venv, ssh, gitconfig per role).
term = cfg.setdefault("terminal", {})
term["backend"] = backend
term["home_mode"] = "profile"
if backend == "docker":
    term.setdefault("docker_image", "nikolaik/python-nodejs:python3.11-nodejs20")
    term.setdefault("container_persistent", True)  # role keeps its venv across sessions

# Read-only shared skill bundles, in addition to the profile's own skills/.
ext = [f"{rbac_dir}/shared-skills/{b}" for b in shared]
cfg.setdefault("skills", {})["external_dirs"] = ext

cfg_path.parent.mkdir(parents=True, exist_ok=True)
cfg_path.write_text(yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True))
print(f"   wrote {cfg_path}")
print(f"   platform_toolsets -> {toolsets}")
print(f"   terminal.backend  -> {backend} (home_mode=profile)")
print(f"   skills.external_dirs -> {ext}")
PY

echo ">> role '$ROLE' ready. Next: hermes -p $ROLE setup   (provider key + bot token)"
