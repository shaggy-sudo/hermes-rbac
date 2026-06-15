"""GoogleDashboardAuthProvider — Google OAuth (authorization-code + PKCE).

A dashboard auth gate that meets the user *before* the Hermes web UI. Modeled
on the bundled ``nous`` provider but pointed at Google's OAuth endpoints and a
confidential (client_secret) web client.

Identity model:
  Google returns an ``id_token`` (an RS256 JWT) carrying the user's verified
  ``email`` / ``sub`` / ``exp``. We store that id_token as the Session's
  ``access_token`` so ``verify_session`` can validate it statelessly against
  Google's JWKS on every request (no per-request call to Google). The opaque
  Google access_token is not needed by the dashboard, so we don't keep it.

Configuration (env wins; all optional ones default to "no restriction"):
  GOOGLE_CLIENT_ID       — OAuth web client id            (required)
  GOOGLE_CLIENT_SECRET   — OAuth web client secret         (required)
  GOOGLE_ALLOWED_DOMAIN  — restrict to a Workspace hd, e.g. "yourco.com"
  GOOGLE_ALLOWED_EMAILS  — comma-separated explicit allowlist

The RBAC layer (middleware profile-lock + provisioning) consumes
``Session.email`` downstream to scope the user to their own profile. This
provider only authenticates; it does not assign roles.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import urllib.parse
from typing import Any, Dict, Optional

import httpx

from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    InvalidCodeError,
    LoginStart,
    ProviderError,
    RefreshExpiredError,
    Session,
)

logger = logging.getLogger(__name__)

# Google OAuth/OIDC well-known endpoints.
_AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_TOKEN_URL = "https://oauth2.googleapis.com/token"
_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
# Google emits either form as the id_token issuer.
_ISSUERS = ("https://accounts.google.com", "accounts.google.com")
_SCOPE = "openid email profile"
_TOKEN_ENDPOINT_TIMEOUT_SEC = 10.0
_JWKS_CACHE_SECONDS = 300

# Operator-friendly skip reason read by the gate's fail-closed branch.
LAST_SKIP_REASON: str = ""


def _b64url_no_pad(raw: bytes) -> str:
    """Base64url-encode without ``=`` padding (RFC 7636 §4)."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class GoogleDashboardAuthProvider(DashboardAuthProvider):
    """Google OAuth via authorization-code + PKCE (S256), confidential client."""

    name = "google"
    display_name = "Google"

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        allowed_domain: str = "",
        allowed_emails: tuple[str, ...] = (),
    ) -> None:
        if not client_id or not client_secret:
            raise ValueError("client_id and client_secret are both required")
        self._client_id = client_id
        self._client_secret = client_secret
        self._allowed_domain = allowed_domain.strip().lower()
        self._allowed_emails = frozenset(e.strip().lower() for e in allowed_emails if e.strip())
        self._jwks_client: Any = None

    # ---- public API (DashboardAuthProvider) -------------------------------

    def start_login(self, *, redirect_uri: str) -> LoginStart:
        self._validate_redirect_uri(redirect_uri)

        code_verifier = _b64url_no_pad(secrets.token_bytes(64))
        code_challenge = _b64url_no_pad(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        )
        state = _b64url_no_pad(secrets.token_bytes(32))

        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "scope": _SCOPE,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            # offline + consent are what make Google return a refresh_token.
            "access_type": "offline",
            "prompt": "consent select_account",
            "include_granted_scopes": "true",
        }
        # Hosted-domain hint (Workspace). Not a security control on its own —
        # we still verify the hd/email claim in complete_login — but it scopes
        # the account chooser to the team's domain.
        if self._allowed_domain:
            params["hd"] = self._allowed_domain

        redirect_url = f"{_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"
        cookie_payload = {
            "hermes_session_pkce": f"state={state};verifier={code_verifier}",
        }
        return LoginStart(redirect_url=redirect_url, cookie_payload=cookie_payload)

    def complete_login(
        self,
        *,
        code: str,
        state: str,
        code_verifier: str,
        redirect_uri: str,
    ) -> Session:
        _ = state  # state is validated by the auth-route layer before this call
        try:
            response = httpx.post(
                _TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "code_verifier": code_verifier,
                },
                headers={"Accept": "application/json"},
                timeout=_TOKEN_ENDPOINT_TIMEOUT_SEC,
            )
        except httpx.RequestError as exc:
            raise ProviderError(f"Google token endpoint unreachable: {exc}") from exc
        return self._token_response_to_session(response, bad_request_exc=InvalidCodeError)

    def refresh_session(self, *, refresh_token: str) -> Session:
        if not refresh_token:
            raise RefreshExpiredError("no refresh token present in session")
        try:
            response = httpx.post(
                _TOKEN_URL,
                data={
                    "grant_type": "refresh_token",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "refresh_token": refresh_token,
                },
                headers={"Accept": "application/json"},
                timeout=_TOKEN_ENDPOINT_TIMEOUT_SEC,
            )
        except httpx.RequestError as exc:
            raise ProviderError(f"Google token endpoint unreachable: {exc}") from exc
        # Google does not return refresh_token on the refresh grant, so carry
        # the existing one forward.
        return self._token_response_to_session(
            response, bad_request_exc=RefreshExpiredError, carry_refresh_token=refresh_token
        )

    def verify_session(self, *, access_token: str) -> Optional[Session]:
        # ``access_token`` here is the stored Google id_token (a JWT).
        try:
            claims = self._verify_jwt(access_token)
        except InvalidCodeError:
            return None  # expired/invalid → middleware tries refresh then login
        except ProviderError:
            raise  # JWKS unreachable → middleware emits 503
        return self._session_from_claims(access_token, "", claims)

    def revoke_session(self, *, refresh_token: str) -> None:
        # Best-effort: revoke the refresh token at Google's revocation endpoint.
        # Must never raise.
        if not refresh_token:
            return None
        try:
            httpx.post(
                "https://oauth2.googleapis.com/revoke",
                data={"token": refresh_token},
                timeout=_TOKEN_ENDPOINT_TIMEOUT_SEC,
            )
        except Exception as exc:  # noqa: BLE001 — logout is best-effort
            logger.debug("google revoke best-effort failed: %s", exc)
        return None

    # ---- internals --------------------------------------------------------

    def _validate_redirect_uri(self, redirect_uri: str) -> None:
        parsed = urllib.parse.urlparse(redirect_uri)
        if parsed.scheme not in ("https", "http"):
            raise ProviderError(f"redirect_uri must be http(s), got {redirect_uri!r}")
        if not parsed.path or not parsed.path.endswith("/auth/callback"):
            raise ProviderError(
                f"redirect_uri path must end with '/auth/callback', got {redirect_uri!r}"
            )

    def _parse_json_body(self, response: httpx.Response) -> Dict[str, Any]:
        ctype = response.headers.get("content-type", "")
        if not ctype.startswith("application/json"):
            return {}
        try:
            body = response.json()
        except ValueError:
            return {}
        return body if isinstance(body, dict) else {}

    def _token_response_to_session(
        self,
        response: httpx.Response,
        *,
        bad_request_exc: type[Exception],
        carry_refresh_token: str = "",
    ) -> Session:
        if response.status_code == 400:
            body = self._parse_json_body(response)
            error_code = body.get("error", "invalid_request")
            raise bad_request_exc(f"Google rejected token request: {error_code}")
        if response.status_code != 200:
            raise ProviderError(
                f"Google token endpoint returned {response.status_code}: "
                f"{response.text[:200]!r}"
            )
        payload = self._parse_json_body(response)
        # The identity is in the id_token (JWT), not the opaque access_token.
        id_token = payload.get("id_token")
        if not id_token or not isinstance(id_token, str):
            raise ProviderError("Google token response missing id_token")
        claims = self._verify_jwt(id_token)
        refresh_token = payload.get("refresh_token") or carry_refresh_token or ""
        if not isinstance(refresh_token, str):
            refresh_token = carry_refresh_token or ""
        # Capture EVERYTHING Google gives us (id_token claims + /userinfo) and
        # persist it for later RBAC tuning / debugging. Best-effort; never
        # blocks login. The Session dataclass is fixed, so the full record
        # lives in a side store keyed by the Google subject id.
        userinfo = self._fetch_userinfo(payload.get("access_token"))
        self._persist_identity(claims=claims, userinfo=userinfo, token_payload=payload)
        return self._session_from_claims(id_token, refresh_token, claims)

    def _fetch_userinfo(self, access_token: Optional[str]) -> Dict[str, Any]:
        """Pull the full Google profile from the userinfo endpoint. The
        id_token carries the verified core claims; userinfo can add fields
        like ``picture``, ``locale``, ``given_name``/``family_name`` and any
        extra scopes granted. Best-effort: returns {} on any failure."""
        if not access_token or not isinstance(access_token, str):
            return {}
        try:
            r = httpx.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=_TOKEN_ENDPOINT_TIMEOUT_SEC,
            )
            if r.status_code == 200:
                body = r.json()
                return body if isinstance(body, dict) else {}
        except Exception as exc:  # noqa: BLE001 — diagnostics only
            logger.debug("google userinfo fetch failed: %s", exc)
        return {}

    def _persist_identity(
        self,
        *,
        claims: Dict[str, Any],
        userinfo: Dict[str, Any],
        token_payload: Dict[str, Any],
    ) -> None:
        """Write the full captured identity to
        ``<HERMES_HOME>/rbac/identities/<sub>.json`` for later debugging and
        role mapping. Merges id_token claims + userinfo; records which OAuth
        scopes were granted and a login timestamp. Never raises."""
        try:
            import json
            import time
            from pathlib import Path

            from hermes_constants import get_hermes_home

            sub = str(claims.get("sub", "")) or "unknown"
            safe_sub = "".join(c if c.isalnum() or c in "-_" else "_" for c in sub)
            dest_dir = Path(get_hermes_home()) / "rbac" / "identities"
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / f"{safe_sub}.json"

            prior = {}
            if dest.exists():
                try:
                    prior = json.loads(dest.read_text()) or {}
                except Exception:
                    prior = {}

            # Everything we know, with id_token claims as the trusted base and
            # userinfo merged on top for the extra (non-security) fields.
            merged = {**userinfo, **claims}
            record = {
                "sub": sub,
                "email": merged.get("email"),
                "email_verified": merged.get("email_verified"),
                "name": merged.get("name"),
                "given_name": merged.get("given_name"),
                "family_name": merged.get("family_name"),
                "picture": merged.get("picture"),
                "locale": merged.get("locale"),
                "hd": merged.get("hd"),  # Workspace hosted domain
                "id_token_claims": claims,
                "userinfo": userinfo,
                "granted_scopes": token_payload.get("scope"),
                "first_seen": prior.get("first_seen"),
                # Note: integer epoch; clock import is local to keep best-effort.
                "last_login": int(time.time()),
                "login_count": int(prior.get("login_count", 0)) + 1,
            }
            if not record["first_seen"]:
                record["first_seen"] = record["last_login"]
            dest.write_text(json.dumps(record, indent=2, ensure_ascii=False, sort_keys=True))
            logger.info("dashboard-auth-google: persisted identity for %s", merged.get("email"))
        except Exception as exc:  # noqa: BLE001 — persistence is best-effort
            logger.debug("google identity persist failed: %s", exc)

    def _get_jwks_client(self) -> Any:
        if self._jwks_client is None:
            from jwt import PyJWKClient

            self._jwks_client = PyJWKClient(
                _JWKS_URL, cache_keys=True, lifespan=_JWKS_CACHE_SECONDS
            )
        return self._jwks_client

    def _verify_jwt(self, id_token: str) -> Dict[str, Any]:
        import jwt

        try:
            signing_key = self._get_jwks_client().get_signing_key_from_jwt(id_token)
        except jwt.PyJWKClientError as exc:
            raise ProviderError(f"JWKS lookup failed: {exc}") from exc
        except Exception as exc:  # pragma: no cover - defensive
            raise ProviderError(f"JWKS lookup failed: {exc!r}") from exc

        try:
            claims = jwt.decode(
                id_token,
                signing_key.key,
                algorithms=["RS256"],
                audience=self._client_id,
                issuer=list(_ISSUERS),
                options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidCodeError(f"id_token expired: {exc}") from exc
        except jwt.InvalidTokenError as exc:
            raise ProviderError(f"id_token verification failed: {exc}") from exc

        self._enforce_allowlist(claims)
        return claims

    def _enforce_allowlist(self, claims: Dict[str, Any]) -> None:
        """RBAC gate: reject accounts outside the configured team.

        Google verifies the email, but ANY Google account could complete the
        flow. ``GOOGLE_ALLOWED_DOMAIN`` / ``GOOGLE_ALLOWED_EMAILS`` restrict
        login to the team. With neither set, any verified Google account is
        accepted (suitable only for trials).
        """
        email = str(claims.get("email", "")).lower()
        email_verified = bool(claims.get("email_verified", False))
        if (self._allowed_domain or self._allowed_emails) and not email_verified:
            raise InvalidCodeError("Google account email is not verified")
        if self._allowed_emails and email in self._allowed_emails:
            return
        if self._allowed_domain:
            hd = str(claims.get("hd", "")).lower()
            if hd == self._allowed_domain or email.endswith("@" + self._allowed_domain):
                return
        if not self._allowed_domain and not self._allowed_emails:
            return  # no restriction configured
        raise InvalidCodeError(f"account {email!r} is not allowed on this dashboard")

    def _session_from_claims(
        self, access_token: str, refresh_token: str, claims: Dict[str, Any]
    ) -> Session:
        user_id = str(claims.get("sub", ""))
        if not user_id:
            raise ProviderError("id_token missing 'sub' (user_id) claim")
        email = str(claims.get("email", ""))
        return Session(
            user_id=user_id,
            email=email,
            display_name=str(claims.get("name") or email or user_id),
            org_id=str(claims.get("hd") or ""),
            provider=self.name,
            expires_at=int(claims["exp"]),
            access_token=access_token,
            refresh_token=refresh_token,
        )


# ---------------------------------------------------------------------------
# Plugin entry point
# ---------------------------------------------------------------------------


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def register(ctx) -> None:
    """Plugin entry — registers the Google provider when configured.

    Activates only when GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are both
    set. Loopback / ``--insecure`` operators leave them unset, so this is a
    no-op for them.
    """
    global LAST_SKIP_REASON
    LAST_SKIP_REASON = ""

    client_id = _env("GOOGLE_CLIENT_ID")
    client_secret = _env("GOOGLE_CLIENT_SECRET")
    if not client_id or not client_secret:
        LAST_SKIP_REASON = (
            "GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET are not both set. Create "
            "an OAuth 2.0 Web application client in Google Cloud Console, add "
            "the dashboard's <base>/auth/callback as an Authorized redirect "
            "URI, and set both env vars — or pass --insecure to skip the gate."
        )
        logger.debug("dashboard-auth-google: %s", LAST_SKIP_REASON)
        return

    allowed_domain = _env("GOOGLE_ALLOWED_DOMAIN")
    allowed_emails = tuple(
        e for e in _env("GOOGLE_ALLOWED_EMAILS").split(",") if e.strip()
    )
    try:
        provider = GoogleDashboardAuthProvider(
            client_id=client_id,
            client_secret=client_secret,
            allowed_domain=allowed_domain,
            allowed_emails=allowed_emails,
        )
    except ValueError as exc:
        LAST_SKIP_REASON = f"GoogleDashboardAuthProvider construction failed: {exc}"
        logger.warning("dashboard-auth-google: %s", LAST_SKIP_REASON)
        return

    ctx.register_dashboard_auth_provider(provider)
    logger.info(
        "dashboard-auth-google: registered (client_id=%s, domain=%s, emails=%d)",
        client_id,
        allowed_domain or "(any)",
        len(allowed_emails),
    )
