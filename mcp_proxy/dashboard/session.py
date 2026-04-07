"""
Dashboard session management — HMAC-SHA256 signed cookies.

Single role for the MCP Proxy dashboard: admin.
The session is stored in a signed cookie (HMAC-SHA256). No server-side
session store needed — the cookie contains the role and CSRF token,
verified on every request.

CSRF protection: a per-session token is embedded in the cookie and must
be present as a hidden form field on every state-changing POST request.
"""
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass

from fastapi import Request, Response
from starlette.responses import RedirectResponse

_log = logging.getLogger("mcp_proxy.dashboard")

_COOKIE_NAME = "mcp_proxy_session"
_COOKIE_MAX_AGE = 8 * 3600  # 8 hours


@dataclass
class ProxyDashboardSession:
    """Dashboard session payload."""
    role: str  # "admin" only for now
    csrf_token: str = ""
    logged_in: bool = True


_NO_SESSION = ProxyDashboardSession(role="none", csrf_token="", logged_in=False)

_auto_key: str = ""


def _get_secret() -> str:
    """Return the dashboard signing key from settings, or auto-generate one."""
    global _auto_key
    from mcp_proxy.config import get_settings
    key = get_settings().dashboard_signing_key
    if key:
        return key
    if not _auto_key:
        _auto_key = os.urandom(32).hex()
    return _auto_key


def _sign(payload: str) -> str:
    secret = _get_secret()
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify(cookie_value: str) -> str | None:
    """Verify signature and return payload string, or None if invalid."""
    if "." not in cookie_value:
        return None
    payload, sig = cookie_value.rsplit(".", 1)
    secret = _get_secret()
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return None
    return payload


def get_session(request: Request) -> ProxyDashboardSession:
    """Extract and verify the dashboard session from the request cookie."""
    cookie = request.cookies.get(_COOKIE_NAME)
    if not cookie:
        return _NO_SESSION

    payload_str = _verify(cookie)
    if not payload_str:
        return _NO_SESSION

    try:
        data = json.loads(payload_str)
    except (json.JSONDecodeError, TypeError):
        return _NO_SESSION

    if data.get("exp", 0) < time.time():
        return _NO_SESSION

    return ProxyDashboardSession(
        role=data.get("role", "none"),
        csrf_token=data.get("csrf_token", ""),
        logged_in=True,
    )


def set_session(response: Response, role: str = "admin") -> str:
    """Set a signed session cookie on the response. Returns the CSRF token."""
    csrf_token = os.urandom(16).hex()
    payload = json.dumps({
        "role": role,
        "csrf_token": csrf_token,
        "exp": int(time.time()) + _COOKIE_MAX_AGE,
    })
    signed = _sign(payload)
    response.set_cookie(
        _COOKIE_NAME, signed,
        max_age=_COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False,  # set True behind TLS terminator
    )
    return csrf_token


def clear_session(response: Response) -> None:
    """Delete the session cookie."""
    response.delete_cookie(_COOKIE_NAME, samesite="lax", secure=False)


def require_login(request: Request) -> ProxyDashboardSession | RedirectResponse:
    """Return the session if logged in, or a redirect to /proxy/login."""
    session = get_session(request)
    if not session.logged_in:
        return RedirectResponse(url="/proxy/login", status_code=303)
    return session


async def verify_csrf(request: Request, session: ProxyDashboardSession) -> bool:
    """Verify the CSRF token from the form matches the one in the session cookie."""
    form = await request.form()
    token = form.get("csrf_token", "")
    if not session.csrf_token or not token:
        return False
    return hmac.compare_digest(str(token), session.csrf_token)
