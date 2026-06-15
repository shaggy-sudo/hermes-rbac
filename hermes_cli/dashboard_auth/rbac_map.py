"""RBAC mapping: authenticated email -> per-user profile + role, and a
request-scoped "profile lock" the dashboard honors so a logged-in user can
only reach their own profile's data (their private filesystem).

Two-tier filesystem model:
  * private (per-user)  -> the user's own profile = ``u-<slug>`` (own
    HERMES_HOME: memory, skills, sessions; own container FS on docker backend).
  * shared (per-role)   -> the role's shared-skills bundle + a shared role
    volume mounted into every same-role user's container (wired by the
    provisioning layer, not here).

Admins (``HERMES_ADMIN_EMAILS``) are NOT locked: they keep the machine-level
profile switcher and can manage every profile. Everyone else is pinned.

This module is import-light (stdlib + a contextvar) so middleware can import
it on the hot path without pulling heavy deps.
"""

from __future__ import annotations

import hashlib
import os
import re
from contextvars import ContextVar
from typing import Optional

# Request-scoped lock. None = no lock (admin / loopback / unauthenticated
# pre-session). Set by the auth middleware once a Session is verified, reset
# after the response. ContextVar gives per-request isolation under asyncio.
_locked_profile: ContextVar[Optional[str]] = ContextVar("hermes_locked_profile", default=None)

# Extra filesystem roots a locked user may also reach beyond their own profile
# home — i.e. their role's SHARED space. Lets the FS browser show shared
# resources without exposing other tenants. Empty when unlocked.
_shared_roots: ContextVar[tuple] = ContextVar("hermes_shared_roots", default=())

_DEFAULT_ROLE = "viewer"
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def _admin_emails() -> frozenset[str]:
    raw = os.environ.get("HERMES_ADMIN_EMAILS", "")
    return frozenset(e.strip().lower() for e in raw.split(",") if e.strip())


def is_admin(email: str) -> bool:
    return email.strip().lower() in _admin_emails()


def profile_for_email(email: str) -> str:
    """Deterministic, validation-safe per-user profile id from an email.

    Produces ``u-<slug>`` matching ``^[a-z0-9][a-z0-9_-]{0,63}$``. Long or
    exotic emails are truncated and disambiguated with a short hash so two
    distinct emails never collide on the same profile.
    """
    e = email.strip().lower()
    slug = _NON_ALNUM.sub("-", e).strip("-") or "user"
    candidate = f"u-{slug}"
    if len(candidate) <= 64 and not candidate.endswith("-"):
        return candidate
    digest = hashlib.sha256(e.encode()).hexdigest()[:8]
    head = slug[:50].rstrip("-")
    return f"u-{head}-{digest}"


def shared_dirs_for_role(role: str) -> tuple:
    """Filesystem roots shared across all users of ``role`` — the role's
    shared volume under ``<HERMES_HOME>/shared/<role>``. A locked user is
    allowed to browse these in addition to their own profile home (two-tier
    FS: private + shared)."""
    try:
        from hermes_constants import get_hermes_home

        return (str((get_hermes_home() / "shared" / role).resolve()),)
    except Exception:
        return ()


def role_for_email(email: str) -> str:
    """Role assigned to a user. Admins -> ``admin`` (allowlist always wins);
    then an explicit override from ``<HERMES_HOME>/rbac/role-overrides.json``
    (written by the Shared Management admin console); else the configured
    default (``viewer``)."""
    e = email.strip().lower()
    if is_admin(e):
        return "admin"
    try:
        import json
        from hermes_constants import get_hermes_home

        overrides_path = get_hermes_home() / "rbac" / "role-overrides.json"
        data = json.loads(overrides_path.read_text(encoding="utf-8"))
        role = str(data.get(e, "")).strip()
        if role:
            return role
    except Exception:
        pass  # missing/corrupt overrides file -> fall through to default
    return os.environ.get("HERMES_DEFAULT_ROLE", _DEFAULT_ROLE).strip() or _DEFAULT_ROLE


# ---- request-scoped lock -------------------------------------------------


def set_lock(profile: Optional[str]):
    """Set the locked profile for the current request context. Returns a token
    for :func:`reset_lock`. Pass ``None`` to explicitly clear (admins)."""
    return _locked_profile.set(profile)


def get_lock() -> Optional[str]:
    """Return the locked profile for this request, or None if unlocked."""
    return _locked_profile.get()


def reset_lock(token) -> None:
    try:
        _locked_profile.reset(token)
    except Exception:
        # Token from a different context (shouldn't happen on the request
        # path); fall back to clearing.
        _locked_profile.set(None)


def set_shared_roots(roots: tuple):
    return _shared_roots.set(tuple(roots or ()))


def get_shared_roots() -> tuple:
    return _shared_roots.get()


def reset_shared_roots(token) -> None:
    try:
        _shared_roots.reset(token)
    except Exception:
        _shared_roots.set(())


def fs_roots() -> tuple:
    """All filesystem roots the current (locked) user may browse: their own
    profile home + their role's shared dirs. Returns () when unlocked (admin /
    loopback) — callers treat () as "no confinement"."""
    locked = get_lock()
    if not locked:
        return ()
    roots = []
    try:
        from hermes_cli import profiles as profiles_mod

        roots.append(str(profiles_mod.get_profile_dir(locked).resolve()))
    except Exception:
        pass
    roots.extend(get_shared_roots())
    return tuple(roots)


def ensure_user_profile(email: str) -> None:
    """Lazily provision the user's per-user profile on first login.

    Guarded by existence so it runs at most once per user. Delegates the
    actual creation + two-tier FS wiring to ``rbac/provision-user.sh`` so the
    profile-creation logic lives in one place. Best-effort: a failure here is
    logged and swallowed so the request can still surface a clean error rather
    than a 500 from the middleware. Disable with ``HERMES_RBAC_AUTOPROVISION=0``.
    """
    if os.environ.get("HERMES_RBAC_AUTOPROVISION", "1").strip() in ("0", "false", "no"):
        return
    profile = profile_for_email(email)
    try:
        from hermes_cli import profiles as profiles_mod

        if profiles_mod.profile_exists(profile):
            return
    except Exception:
        pass  # fall through to the script, which is itself idempotent

    import subprocess

    script = os.path.join(
        os.environ.get("HERMES_INSTALL_DIR", "/opt/hermes"),
        "rbac",
        "provision-user.sh",
    )
    if not os.path.exists(script):
        return
    try:
        subprocess.run(
            ["bash", script, email, role_for_email(email)],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except Exception as exc:  # noqa: BLE001 — provisioning is best-effort
        import logging

        logging.getLogger(__name__).warning(
            "RBAC auto-provision failed for %s: %s", email, exc
        )


def enforce(requested: Optional[str]) -> Optional[str]:
    """Resolution chokepoint helper. When a lock is active, the requested
    profile is overridden with the locked one (a pinned user cannot escape
    to another profile by passing ``?profile=other``). When unlocked, the
    requested value passes through unchanged."""
    locked = get_lock()
    if locked:
        return locked
    return requested
