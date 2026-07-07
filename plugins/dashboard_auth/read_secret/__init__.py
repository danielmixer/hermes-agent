"""ReadSecretProvider — shared-bearer-secret auth for read-only API access.

Service-to-service counterpart to the drain plugin, for callers (e.g. Hermes
Workspace) that need to read /api/sessions without an interactive login.

Configuration
-------------
    HERMES_DASHBOARD_READ_SECRET   # >=256-bit url-safe-base64 shared secret

Optional config.yaml knobs (under dashboard.read_auth):
    scope: read            # capability label on the principal (default: "read")
    min_secret_chars: 43   # entropy floor (default 43 ~= 256 bits)

When HERMES_DASHBOARD_READ_SECRET is unset the plugin is a no-op.
"""
from __future__ import annotations

import hmac
import logging
import math
import os
from collections import Counter
from typing import Optional

from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    LoginStart,
    Session,
    TokenPrincipal,
)

logger = logging.getLogger(__name__)

# 43 url-safe-base64 chars ~= 256 bits; mirrors the drain plugin's bar.
_DEFAULT_MIN_SECRET_CHARS = 43
_MIN_DISTINCT_CHARS = 16
_MIN_SHANNON_BITS = 128.0

SESSION_ROUTE_PATH = "/api/sessions/{session_id}"
READ_ROUTE_PATH = "/api/sessions"
MESSAGES_ROUTE_PATH = "/api/sessions/{session_id}/messages"
SKILLS_ROUTE_PATH = "/api/skills"

LAST_SKIP_REASON: str = ""


def _shannon_bits(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    per_char = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return per_char * n


def _assess_secret_strength(secret: str, *, min_chars: int = _DEFAULT_MIN_SECRET_CHARS) -> Optional[str]:
    if not secret:
        return "secret is empty"
    if len(secret) < min_chars:
        return (
            f"secret too short: {len(secret)} chars (need >= {min_chars}; "
            "use a >=256-bit value, e.g. `python -c \"import secrets; "
            "print(secrets.token_urlsafe(32))\"`)"
        )
    distinct = len(set(secret))
    if distinct < _MIN_DISTINCT_CHARS:
        return (
            f"secret has only {distinct} distinct characters (need >= "
            f"{_MIN_DISTINCT_CHARS}); looks structured/low-entropy"
        )
    bits = _shannon_bits(secret)
    if bits < _MIN_SHANNON_BITS:
        return (
            f"secret entropy too low: {bits:.0f} bits (need >= "
            f"{_MIN_SHANNON_BITS:.0f}); looks structured/repeated"
        )
    return None


class ReadSecretProvider(DashboardAuthProvider):
    """Non-interactive shared-bearer-secret provider for read-only API access."""

    name = "read-secret"
    display_name = "Workspace Reader (service credential)"
    supports_token = True
    supports_session = False

    def __init__(self, *, secret: str, scope: str = "read") -> None:
        reason = _assess_secret_strength(secret)
        if reason is not None:
            raise ValueError(f"read secret rejected: {reason}")
        self._secret = secret
        self._scope = scope or "read"

    def verify_token(self, *, token: str) -> Optional[TokenPrincipal]:
        if not token:
            return None
        if hmac.compare_digest(token.encode("utf-8"), self._secret.encode("utf-8")):
            return TokenPrincipal(
                principal="workspace-reader",
                provider=self.name,
                scopes=(self._scope,),
            )
        return None

    def start_login(self, *, redirect_uri: str) -> LoginStart:
        raise NotImplementedError("ReadSecretProvider is a non-interactive service credential.")

    def complete_login(self, *, code: str, state: str, code_verifier: str, redirect_uri: str) -> Session:
        raise NotImplementedError("ReadSecretProvider is a non-interactive service credential.")

    def verify_session(self, *, access_token: str) -> Optional[Session]:
        return None

    def refresh_session(self, *, refresh_token: str) -> Session:
        raise NotImplementedError("ReadSecretProvider is a non-interactive service credential.")

    def revoke_session(self, *, refresh_token: str) -> None:
        return None


def _load_config_read_auth_section() -> dict:
    try:
        from hermes_cli.config import cfg_get, load_config
        cfg = load_config()
    except Exception as exc:
        logger.debug("dashboard-auth-read: load_config() raised %s; falling back to env-only", exc)
        return {}
    section = cfg_get(cfg, "dashboard", "read_auth", default=None)
    return section if isinstance(section, dict) else {}


def register(ctx) -> None:
    """Plugin entry — registers ReadSecretProvider when a strong secret is set."""
    global LAST_SKIP_REASON
    LAST_SKIP_REASON = ""

    secret = os.environ.get("HERMES_DASHBOARD_READ_SECRET", "").strip()
    if not secret:
        LAST_SKIP_REASON = (
            "HERMES_DASHBOARD_READ_SECRET is not set. Set a >=256-bit secret "
            "(e.g. `python -c \"import secrets; print(secrets.token_urlsafe(32))\"`) "
            "to enable bearer-token access for Workspace; leave it unset to disable."
        )
        logger.debug("dashboard-auth-read: %s", LAST_SKIP_REASON)
        return

    section = _load_config_read_auth_section()
    scope = str(section.get("scope", "read") or "read").strip() or "read"
    try:
        min_chars = int(section.get("min_secret_chars", _DEFAULT_MIN_SECRET_CHARS))
    except (TypeError, ValueError):
        min_chars = _DEFAULT_MIN_SECRET_CHARS

    reason = _assess_secret_strength(secret, min_chars=min_chars)
    if reason is not None:
        LAST_SKIP_REASON = f"HERMES_DASHBOARD_READ_SECRET rejected — {reason}. Endpoint stays disabled."
        logger.warning("dashboard-auth-read: %s", LAST_SKIP_REASON)
        return

    try:
        provider = ReadSecretProvider(secret=secret, scope=scope)
    except ValueError as exc:
        LAST_SKIP_REASON = f"ReadSecretProvider construction failed: {exc}"
        logger.warning("dashboard-auth-read: %s", LAST_SKIP_REASON)
        return

    ctx.register_dashboard_auth_provider(provider)

    from hermes_cli.dashboard_auth.token_auth import register_token_route
    _token_routes = [READ_ROUTE_PATH, SESSION_ROUTE_PATH, MESSAGES_ROUTE_PATH, SKILLS_ROUTE_PATH]
    for _route in _token_routes:
        try:
            register_token_route(_route)
            print(f"dashboard-auth-read: registered token route {_route!r} (scope={scope})", flush=True)
        except Exception as exc:
            print(f"dashboard-auth-read: could not register token route {_route!r}: {exc}", flush=True)
            logger.warning("dashboard-auth-read: could not register token route %s: %s", _route, exc)
