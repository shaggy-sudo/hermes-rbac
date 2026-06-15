/**
 * AuthWidget — sidebar "Logged in as …" affordance for the dashboard
 * OAuth gate (Phase 7 of .hermes/plans/2026-05-21-dashboard-oauth-auth.md).
 *
 * Renders nothing in loopback / --insecure mode. In gated mode, fetches
 * /api/auth/me on mount and surfaces:
 *
 *   - the human identity: ``display_name`` and/or ``email`` as populated by
 *     the provider (the Google provider supplies both). The truncated
 *     ``user_id`` is only used as a last-resort fallback when neither claim
 *     is present.
 *   - the caller's RBAC role as a pill ("Viewer", "Developer", …), plus an
 *     "Admin" pill for infra/console admins (``is_admin``), so the user can
 *     see who they are in RBAC terms.
 *   - a logout button that POSTs /auth/logout and full-page-navigates to
 *     /login (the dashboard becomes inaccessible again)
 *
 * Failure modes:
 *   - 401 from /api/auth/me means we're not gated (or the gate is on but
 *     we have no cookie — in that case the gate's middleware would have
 *     redirected us before App.tsx renders, so we won't see this). The
 *     widget renders nothing.
 *   - Network error: shows a minimal "auth status unavailable" message
 *     so the user knows the widget tried.
 */

import { api } from "@/lib/api";
import { useAuthMe } from "@/hooks/useAuthMe";
import { cn } from "@/lib/utils";
import { LogOut } from "lucide-react";

interface AuthWidgetProps {
  className?: string;
}

/** Truncate ``user_id`` to fit a small UI without revealing the full
 *  opaque identifier. 14 chars is enough to disambiguate users in a
 *  small org and short enough to fit a single sidebar row. Only used as a
 *  last resort when the provider supplied no display_name/email. */
function truncateUserId(id: string): string {
  if (id.length <= 14) return id;
  return `${id.slice(0, 14)}…`;
}

/** Title-case an RBAC role slug for display ("viewer" → "Viewer"). */
function formatRole(role: string): string {
  return role.charAt(0).toUpperCase() + role.slice(1);
}

export function AuthWidget({ className }: AuthWidgetProps) {
  const { me, hidden, error } = useAuthMe();

  if (hidden) return null;

  if (error) {
    return (
      <div
        className={cn(
          "px-5 py-2 text-[0.65rem] tracking-[0.05em] text-muted-foreground/70",
          className,
        )}
      >
        {error}
      </div>
    );
  }

  if (!me) {
    // Loading. Reserve the row height so the sidebar doesn't flicker
    // when the data arrives.
    return (
      <div
        className={cn(
          "h-9 px-5 py-2 text-[0.65rem] text-muted-foreground/40",
          className,
        )}
        aria-busy="true"
      >
        …
      </div>
    );
  }

  const handleLogout = () => {
    void api.logout();
  };

  // Prefer display_name → email → truncated user_id. Providers like Google
  // populate display_name + email; the user_id fallback is the last resort
  // for providers that emit neither.
  const label = me.display_name || me.email || truncateUserId(me.user_id);
  // Show the email as a secondary line only when it adds information beyond
  // the primary label (i.e. when display_name is what we're showing).
  const subLabel = me.display_name && me.email ? me.email : null;
  const roleLabel = me.role ? formatRole(me.role) : null;

  return (
    <div
      className={cn(
        "flex shrink-0 items-center justify-between gap-2",
        "px-5 py-2",
        "border-t border-current/10",
        "text-[0.65rem] tracking-[0.05em]",
        className,
      )}
      role="status"
      aria-label={`Logged in as ${label}${roleLabel ? `, role ${roleLabel}` : ""}`}
    >
      <div className="flex min-w-0 flex-col gap-0.5">
        <span className="truncate font-mono text-foreground/90" title={me.email || me.user_id}>
          {label}
        </span>
        {subLabel ? (
          <span className="truncate text-muted-foreground/70" title={subLabel}>
            {subLabel}
          </span>
        ) : null}
        <span className="mt-0.5 flex flex-wrap items-center gap-1">
          {roleLabel ? (
            <span
              className="rounded-sm border border-current/20 bg-current/5 px-1.5 py-px font-mondwest text-display uppercase tracking-[0.08em] text-text-secondary"
              title={`RBAC role: ${roleLabel}`}
            >
              {roleLabel}
            </span>
          ) : null}
          {me.is_admin ? (
            <span
              className="rounded-sm border border-amber-500/40 bg-amber-500/10 px-1.5 py-px font-mondwest text-display uppercase tracking-[0.08em] text-amber-300"
              title="Infrastructure / console admin"
            >
              Admin
            </span>
          ) : null}
          <span className="truncate text-muted-foreground/60">via {me.provider}</span>
        </span>
      </div>
      <button
        type="button"
        onClick={handleLogout}
        className={cn(
          "shrink-0 rounded p-1.5 text-muted-foreground/70",
          "transition-colors hover:bg-current/10 hover:text-foreground",
          "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-current/40",
        )}
        aria-label="Log out"
        title="Log out"
      >
        <LogOut className="h-3.5 w-3.5" />
      </button>
    </div>
  );
}
