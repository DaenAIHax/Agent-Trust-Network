"""
M-dash-3 regression: ``/badge/version`` HTML-escapes every value it
interpolates from the GitHub Releases API.

The fragment used to embed ``release_url``, ``install_command``,
``latest`` and ``current`` raw via f-string. An attacker who could
publish a release tag with a crafted value (or compromise the GHCR
repo) would land stored XSS against any operator viewing the
dashboard. The fix HTML-escapes (``quote=True``) every interpolated
field so attribute and text contexts both resist injection.
"""
from __future__ import annotations

from unittest.mock import patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient


@pytest_asyncio.fixture
async def proxy_app(tmp_path, monkeypatch):
    db_file = tmp_path / "m_dash_xss.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("MCP_PROXY_ORG_ID", "acme")
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.local")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()

    from mcp_proxy.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            yield app, client
    get_settings.cache_clear()


def _admin_cookie(csrf_token: str = "csrf-xss-test") -> tuple[str, str]:
    import json as _json
    import time as _time
    from mcp_proxy.dashboard.session import _COOKIE_NAME, _sign
    payload = _json.dumps(
        {
            "role": "admin",
            "csrf_token": csrf_token,
            "exp": int(_time.time()) + 3600,
        },
    )
    return _COOKIE_NAME, _sign(payload)


@pytest.mark.asyncio
async def test_badge_version_escapes_release_url(proxy_app) -> None:
    """A release URL containing a ``"`` would break out of the
    ``href="..."`` attribute under the old f-string. After the fix
    the value renders escaped as ``&quot;``."""
    _, client = proxy_app
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    from mcp_proxy.version_check import UpdateStatus
    crafted = UpdateStatus(
        current="0.3.0",
        latest="0.4.0",
        update_available=True,
        install_command="docker pull benign:0.4.0",
        release_url='https://example.com/" onerror="alert(1)" data-x="',
    )
    async def _stub():
        return crafted
    with patch(
        "mcp_proxy.version_check.check_for_updates", side_effect=_stub,
    ):
        resp = await client.get("/proxy/badge/version")

    assert resp.status_code == 200
    body = resp.text
    # Raw quote+attribute injection must NOT appear.
    assert ' onerror="alert(1)"' not in body
    assert "&quot;" in body or "&#x22;" in body or "&#34;" in body, (
        "release_url with embedded quote must be HTML-escaped in the output"
    )


@pytest.mark.asyncio
async def test_badge_version_escapes_install_command(proxy_app) -> None:
    _, client = proxy_app
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    from mcp_proxy.version_check import UpdateStatus
    crafted = UpdateStatus(
        current="0.3.0",
        latest="0.4.0",
        update_available=True,
        install_command='" onmouseover="alert(2)" data-x="',
        release_url="https://example.com/release",
    )
    async def _stub():
        return crafted
    with patch(
        "mcp_proxy.version_check.check_for_updates", side_effect=_stub,
    ):
        resp = await client.get("/proxy/badge/version")

    assert resp.status_code == 200
    assert ' onmouseover="alert(2)"' not in resp.text


@pytest.mark.asyncio
async def test_badge_version_escapes_latest_text_node(proxy_app) -> None:
    _, client = proxy_app
    cookie_name, cookie_value = _admin_cookie()
    client.cookies.set(cookie_name, cookie_value)

    from mcp_proxy.version_check import UpdateStatus
    crafted = UpdateStatus(
        current="0.3.0",
        latest="<script>alert(3)</script>",
        update_available=True,
        install_command="docker pull benign:0.4.0",
        release_url="https://example.com/release",
    )
    async def _stub():
        return crafted
    with patch(
        "mcp_proxy.version_check.check_for_updates", side_effect=_stub,
    ):
        resp = await client.get("/proxy/badge/version")

    assert resp.status_code == 200
    assert "<script>alert(3)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text
