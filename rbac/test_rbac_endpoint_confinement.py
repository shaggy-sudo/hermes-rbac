"""RBAC confinement tests for the dashboard's per-user lock.

Asserts that when a per-user profile lock is active (a non-admin request), the
data endpoints confine to the locked profile and the machine-level profile
lifecycle ops 403 — and that with NO lock (admin / loopback) the same paths
keep their unrestricted behavior.

The endpoints take a request-scoped lock from
``hermes_cli.dashboard_auth.rbac_map.get_lock``; each endpoint imports it
locally at call time, so monkeypatching the module attribute simulates a
locked / unlocked context without standing up the full OAuth gate.

Run:  python3 rbac/test_rbac_endpoint_confinement.py
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

# A scratch HERMES_HOME with a second "tenant" profile so the locked-profile
# resolution has a real on-disk dir to land on. Set BEFORE importing the server.
SCRATCH = Path(tempfile.mkdtemp(prefix="rbac-confine-test-"))
os.environ["HERMES_HOME"] = str(SCRATCH)
os.environ.setdefault("HERMES_RBAC_AUTOPROVISION", "0")

from hermes_cli import web_server  # noqa: E402
from hermes_cli.dashboard_auth import rbac_map  # noqa: E402
from fastapi import HTTPException  # noqa: E402

LOCKED = "u-tenant"


def _seed_profiles() -> None:
    """Create the default + the locked tenant's profile dirs + state.dbs."""
    from hermes_cli import profiles as profiles_mod
    from hermes_state import SessionDB

    # default home already exists (== HERMES_HOME); seed a state.db with a row.
    default_home = profiles_mod.get_profile_dir("default")
    default_home.mkdir(parents=True, exist_ok=True)
    db = SessionDB(db_path=default_home / "state.db")
    db.close()

    # The locked tenant profile lives under the profiles root.
    tenant_home = profiles_mod.get_profile_dir(LOCKED)
    tenant_home.mkdir(parents=True, exist_ok=True)
    (tenant_home / "memories").mkdir(parents=True, exist_ok=True)
    (tenant_home / "logs").mkdir(parents=True, exist_ok=True)
    db = SessionDB(db_path=tenant_home / "state.db")
    db.close()


class _Lock:
    """Context-manager swapping rbac_map.get_lock for the test."""

    def __init__(self, value):
        self.value = value
        self._orig = None

    def __enter__(self):
        self._orig = rbac_map.get_lock
        rbac_map.get_lock = lambda: self.value
        return self

    def __exit__(self, *exc):
        rbac_map.get_lock = self._orig


def _run(coro):
    return asyncio.run(coro)


# Seed at import so the profile dirs/state.dbs exist under BOTH pytest (which
# never reaches the __main__ block) and the standalone runner. Idempotent.
_seed_profiles()


def test_profiles_sessions_confined_when_locked():
    from hermes_cli import profiles as profiles_mod

    # Unlocked: ?profile=all enumerates every profile (default + tenant).
    with _Lock(None):
        out = _run(web_server.get_profiles_sessions(profile="all"))
    unlocked_profiles = set(out["profile_totals"].keys())
    assert LOCKED in unlocked_profiles, unlocked_profiles
    assert "default" in unlocked_profiles, unlocked_profiles

    # Locked: ?profile=all must collapse to ONLY the locked tenant.
    with _Lock(LOCKED):
        out = _run(web_server.get_profiles_sessions(profile="all"))
    locked_profiles = set(out["profile_totals"].keys())
    assert locked_profiles <= {LOCKED}, locked_profiles
    assert "default" not in locked_profiles, locked_profiles
    print("[ok] /api/profiles/sessions confined to locked profile")


def test_profile_lifecycle_admin_only_when_locked():
    from hermes_cli.web_server import (
        create_profile_endpoint,
        delete_profile_endpoint,
        rename_profile_endpoint,
        set_active_profile_endpoint,
        ProfileCreate,
        ProfileRename,
        ProfileActiveUpdate,
    )

    with _Lock(LOCKED):
        for call in (
            create_profile_endpoint(ProfileCreate(name="evil")),
            delete_profile_endpoint("default"),
            rename_profile_endpoint("default", ProfileRename(new_name="x")),
            set_active_profile_endpoint(ProfileActiveUpdate(name="default")),
        ):
            try:
                _run(call)
            except HTTPException as e:
                assert e.status_code == 403, e.status_code
            else:
                raise AssertionError("expected 403 for locked profile op")
    print("[ok] profile create/delete/rename/set-active 403 when locked")


def test_memory_reset_confined_when_locked():
    from hermes_cli import profiles as profiles_mod
    from hermes_cli.web_server import reset_memory, MemoryReset

    default_home = profiles_mod.get_profile_dir("default")
    tenant_home = profiles_mod.get_profile_dir(LOCKED)
    (default_home / "memories").mkdir(parents=True, exist_ok=True)
    default_mem = default_home / "memories" / "MEMORY.md"
    tenant_mem = tenant_home / "memories" / "MEMORY.md"
    default_mem.write_text("DEFAULT SECRET", encoding="utf-8")
    tenant_mem.write_text("tenant data", encoding="utf-8")

    # Locked reset must wipe ONLY the tenant's file, never the default's.
    with _Lock(LOCKED):
        _run(reset_memory(MemoryReset(target="memory")))
    assert default_mem.exists(), "locked reset wiped the DEFAULT profile memory"
    assert not tenant_mem.exists(), "locked reset did not wipe the tenant memory"
    print("[ok] /api/memory/reset confined to locked profile")


def test_logs_dir_confined_when_locked():
    from hermes_cli import profiles as profiles_mod

    tenant_home = profiles_mod.get_profile_dir(LOCKED)
    default_home = profiles_mod.get_profile_dir("default")
    (default_home / "logs").mkdir(parents=True, exist_ok=True)
    (default_home / "logs" / "agent.log").write_text("DEFAULT PROMPTS", encoding="utf-8")
    (tenant_home / "logs" / "agent.log").write_text("tenant line\n", encoding="utf-8")

    with _Lock(LOCKED):
        out = _run(web_server.get_logs(file="agent", lines=10))
    joined = "\n".join(out["lines"])
    assert "DEFAULT PROMPTS" not in joined, joined
    assert "tenant line" in joined, joined
    print("[ok] /api/logs confined to locked profile")


def test_no_lock_paths_unrestricted():
    # With no lock, _profile_scope("") resolves to the live home (default),
    # and profile lifecycle ops do NOT 403 at the guard (a real op may still
    # 404 on a missing profile, which is fine — we only assert the guard).
    with _Lock(None):
        # The admin-only guard must NOT fire.
        web_server._require_no_lock_for_profile_admin()  # no raise
        # enforce passes through unchanged when unlocked.
        assert rbac_map.enforce("") == ""
        assert rbac_map.enforce("default") == "default"
    print("[ok] no-lock path stays unrestricted")


if __name__ == "__main__":
    _seed_profiles()
    test_profiles_sessions_confined_when_locked()
    test_profile_lifecycle_admin_only_when_locked()
    test_memory_reset_confined_when_locked()
    test_logs_dir_confined_when_locked()
    test_no_lock_paths_unrestricted()
    print("\nALL TESTS PASSED")
