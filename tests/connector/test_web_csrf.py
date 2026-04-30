"""CSRF / cross-origin guard for the Connector dashboard (audit
2026-04-30 lane 5 C1).

The dashboard at ``127.0.0.1:7777`` had no CSRF token, no Origin /
Referer enforcement, and no SameSite cookie because it had no session
at all. Any web page the operator visited could POST to
``/setup/pin-ca`` and overwrite the TOFU-pinned Org CA, configure the
user's IDE to spawn a malicious MCP server, etc. DNS rebinding to
``127.0.0.1:7777`` amplifies the surface.

The fix is a middleware that rejects every state-changing request whose
``Origin`` (or, as fallback, ``Referer``) is not the dashboard's own
host. Requests bearing ``Authorization: Bearer ...`` are exempted —
they're the calling convention for non-browser callers (statusline
scripts), and browsers never auto-attach ``Authorization``, so a
bearer-bearing request is by definition not a CSRF vector.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cullis_connector.config import ConnectorConfig
from cullis_connector.web import build_app


@pytest.fixture
def app(tmp_path):
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="http://mastio.test",
        verify_tls=False,
    )
    return build_app(cfg)


@pytest.fixture
def client(app):
    return TestClient(app)


# ── Positive cases ───────────────────────────────────────────────────


def test_post_with_matching_origin_passes_csrf_guard(client):
    """A POST whose Origin matches the request host is allowed by the
    middleware. The route's own logic may still 4xx for unrelated
    reasons (missing form fields, etc.) but it MUST be reached."""
    resp = client.post(
        "/cancel",
        headers={"Origin": "http://testserver"},
    )
    # /cancel returns 303 redirect on success; key invariant is that
    # the middleware did NOT short-circuit with 403.
    assert resp.status_code != 403


def test_post_with_matching_referer_passes_csrf_guard(client):
    """When ``Origin`` is absent, ``Referer`` is checked instead. A
    referer pointing at the dashboard's own URL is accepted."""
    resp = client.post(
        "/cancel",
        headers={"Referer": "http://testserver/waiting"},
    )
    assert resp.status_code != 403


def test_post_with_bearer_auth_skips_csrf_guard(client):
    """Bearer-authenticated requests are exempt. The route's own
    bearer check / dispatcher availability check runs after the
    middleware; key invariant is the middleware does NOT short-circuit
    with 403."""
    resp = client.post(
        "/status/inbox/seen",
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code != 403, (
        f"middleware should skip Bearer requests (got {resp.status_code})"
    )


# ── Negative cases ───────────────────────────────────────────────────


def test_post_with_cross_origin_blocked(client):
    """Origin header pointing at a different host triggers 403."""
    resp = client.post(
        "/cancel",
        headers={"Origin": "https://evil.example.com"},
    )
    assert resp.status_code == 403
    assert "cross-origin" in resp.json()["detail"].lower()


def test_post_with_cross_origin_referer_blocked(client):
    """Referer pointing at a different host triggers 403 when no
    Origin is present."""
    resp = client.post(
        "/cancel",
        headers={"Referer": "https://evil.example.com/page"},
    )
    assert resp.status_code == 403


def test_post_with_no_origin_no_referer_no_bearer_blocked(client):
    """No identifying header at all: 403. This is the curl / scripted
    attack-without-browser path; legitimate non-browser callers must
    use Bearer."""
    resp = client.post("/cancel")
    assert resp.status_code == 403


def test_post_dns_rebinding_attack_blocked(client):
    """DNS rebinding scenario: an attacker page on
    ``http://attacker.example.com`` rebinds its DNS to ``127.0.0.1``
    after page load and POSTs to the dashboard. The browser still
    sends the original Origin (``http://attacker.example.com``)
    because the ``Origin`` header reflects where the page was loaded
    from, not where the request lands. Rejected."""
    resp = client.post(
        "/setup/pin-ca",
        headers={"Origin": "http://attacker.example.com"},
        data={
            "site_url": "http://mastio.test",
            "expected_fingerprint_sha256": "deadbeef" * 8,
        },
    )
    assert resp.status_code == 403


def test_get_requests_not_subject_to_origin_check(client):
    """GET / HEAD / OPTIONS are not state-changing and are intentionally
    not gated by the middleware."""
    resp = client.get("/setup", headers={"Origin": "https://evil.example.com"})
    # GET passes through; the route may redirect or render, but it
    # MUST NOT 403 from the middleware.
    assert resp.status_code != 403


# ── State-changing endpoints sweep ───────────────────────────────────
#
# Spot-check that the middleware applies uniformly across the routes
# the audit explicitly listed. We don't test every route exhaustively
# (the route logic itself isn't what we're testing here), just that
# they all reject a no-Origin request with 403.


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/setup"),
        ("POST", "/setup/preview-ca"),
        ("POST", "/setup/pin-ca"),
        ("POST", "/cancel"),
        ("POST", "/autostart/toggle"),
        ("POST", "/configure/cursor"),
        ("POST", "/mcp/admin-secret"),
        ("POST", "/mcp/admin-secret/clear"),
        ("POST", "/mcp/register"),
        ("POST", "/mcp/abc-id/delete"),
        ("POST", "/mcp/abc-id/bind-self"),
        ("POST", "/profiles/create"),
        ("POST", "/api/test-ping"),
    ],
)
def test_state_changing_endpoint_rejects_missing_origin(client, method, path):
    """Audit 2026-04-30 lane 5 C1 listed 14 mutating endpoints. All
    must reject browser POSTs that lack a same-origin Origin header.
    /status/inbox/seen is bearer-authenticated separately; covered in
    the positive bearer-skip test above."""
    resp = client.request(method, path)
    assert resp.status_code == 403, (
        f"{method} {path} should reject without Origin (got "
        f"{resp.status_code})"
    )
