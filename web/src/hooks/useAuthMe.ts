import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { AuthMeResponse } from "@/lib/api";

/** Resolution states for the dashboard auth-gate identity probe. */
export interface AuthMeState {
  /** The verified session, or null while loading / when not gated. */
  me: AuthMeResponse | null;
  /** True until the probe resolves (success or failure). */
  loading: boolean;
  /** True when the gate isn't engaged in this process (a plain 401/403 from
   *  /api/auth/me) — consumers like AuthWidget render nothing. */
  hidden: boolean;
  /** Set on a network/other failure so consumers can show a degraded state. */
  error: string | null;
}

/**
 * Fetch the dashboard auth-gate identity (``GET /api/auth/me``) once on mount.
 *
 * Shared by the AuthWidget (to show "who am I") and the app shell (to gate
 * admin-only navigation by role/is_admin), so the SPA makes a single probe.
 *
 * In loopback / --insecure mode the endpoint 401s by design; that surfaces as
 * ``hidden: true`` (not an error) — the same self-hide signal the ProfileSwitcher
 * relies on for non-applicable surfaces.
 */
export function useAuthMe(): AuthMeState {
  const [me, setMe] = useState<AuthMeResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [hidden, setHidden] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getAuthMe()
      .then((data) => {
        if (cancelled) return;
        setMe(data);
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        // A plain 401/403 from /api/auth/me means the gate isn't engaged in
        // this process (loopback mode) — hide rather than error. fetchJSON
        // throws an Error with the status code as a prefix.
        const msg = err instanceof Error ? err.message : String(err);
        if (msg.startsWith("401:") || msg.startsWith("403:")) {
          setHidden(true);
          return;
        }
        setError("auth status unavailable");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return { me, loading, hidden, error };
}
