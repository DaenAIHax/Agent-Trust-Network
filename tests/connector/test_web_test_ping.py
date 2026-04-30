"""Tests for the /api/test-ping dashboard probe.

The dogfood Finding #5 surfaced this: a freshly enrolled operator
had no in-dashboard signal that "this actually works" — they had to
drop into ``hello_site`` from an MCP-aware client to confirm. The
endpoint replicates the same probe (``GET <site>/health``) so the
answer is one click away from the identity card.

Mock httpx so these tests never touch the network.
"""
from __future__ import annotations

import httpx
import pytest
from fastapi.testclient import TestClient

import cullis_connector.web as _web
from cullis_connector.config import ConnectorConfig
from cullis_connector.web import build_app


@pytest.fixture
def cfg(tmp_path) -> ConnectorConfig:
    return ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://fake-mastio.test:9443",
        verify_tls=True,
    )


def _origin_aware_client(cfg) -> TestClient:
    """TestClient that pretends the request comes from the dashboard's
    own origin (audit 2026-04-30 C1 — Origin header now required)."""
    tc = TestClient(build_app(cfg))
    tc.headers["Origin"] = "http://testserver"
    return tc


@pytest.fixture
def client_with_identity(cfg, monkeypatch) -> TestClient:
    """Pretend an enrolled identity is on disk so test-ping doesn't
    short-circuit on the no-identity guard."""
    monkeypatch.setattr(_web, "has_identity", lambda _: True)
    return _origin_aware_client(cfg)


@pytest.fixture
def client_without_identity(cfg, monkeypatch) -> TestClient:
    monkeypatch.setattr(_web, "has_identity", lambda _: False)
    return _origin_aware_client(cfg)


def _patch_health(monkeypatch, *, status_code: int, body: dict | str):
    """Stub httpx.get so the probe sees the response we want."""
    captured: dict[str, str] = {}

    def _fake_get(url, *, verify, timeout):
        captured["url"] = url
        if isinstance(body, dict):
            return httpx.Response(
                status_code,
                json=body,
                request=httpx.Request("GET", url),
            )
        return httpx.Response(
            status_code,
            text=body,
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr("cullis_connector.web.httpx.get", _fake_get)
    return captured


def test_test_ping_happy_path(client_with_identity, monkeypatch):
    """Site at /health returns 200 + JSON → ok with rtt_ms + site fields."""
    captured = _patch_health(
        monkeypatch,
        status_code=200,
        body={"status": "ok", "version": "0.4.0"},
    )
    resp = client_with_identity.post("/api/test-ping")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"] is True
    assert payload["site_status"] == "ok"
    assert payload["site_version"] == "0.4.0"
    assert payload["site_url"] == "https://fake-mastio.test:9443"
    assert isinstance(payload["rtt_ms"], (int, float))
    assert payload["tls_verified"] is True
    assert captured["url"] == "https://fake-mastio.test:9443/health"


def test_test_ping_returns_unreachable_on_httpx_error(
    client_with_identity, monkeypatch,
):
    """Any HTTPError (DNS, TLS, connect refused) → ok=false + readable
    error string. The dashboard surfaces this verbatim."""
    def _raise(url, **_):
        raise httpx.ConnectError(
            "connection refused", request=httpx.Request("GET", url)
        )

    monkeypatch.setattr("cullis_connector.web.httpx.get", _raise)
    resp = client_with_identity.post("/api/test-ping")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"] is False
    assert "Site unreachable" in payload["error"]
    assert "connection refused" in payload["error"]


def test_test_ping_flags_non_200_response(client_with_identity, monkeypatch):
    """Site responded but non-200 (e.g. 503 during boot) → ok=false +
    rtt_ms still reported, so the operator can tell the network worked
    but the upstream is not healthy."""
    _patch_health(monkeypatch, status_code=503, body={"detail": "starting"})
    resp = client_with_identity.post("/api/test-ping")
    payload = resp.json()
    assert payload["ok"] is False
    assert "HTTP 503" in payload["error"]
    assert "rtt_ms" in payload


def test_test_ping_short_circuits_without_identity(client_without_identity):
    """No identity → don't dial out; the probe is meaningful only once
    enrollment completed. Returns ok=false with a guiding message."""
    resp = client_without_identity.post("/api/test-ping")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"] is False
    assert "enroll" in payload["error"].lower()


def test_test_ping_strips_trailing_slash_on_site_url(monkeypatch, tmp_path):
    """``site_url`` with a trailing slash must not produce //health."""
    cfg = ConnectorConfig(
        config_dir=tmp_path,
        site_url="https://fake-mastio.test:9443/",
        verify_tls=True,
    )
    monkeypatch.setattr(_web, "has_identity", lambda _: True)
    client = _origin_aware_client(cfg)
    captured = _patch_health(
        monkeypatch, status_code=200, body={"status": "ok"}
    )
    client.post("/api/test-ping")
    assert captured["url"] == "https://fake-mastio.test:9443/health"
