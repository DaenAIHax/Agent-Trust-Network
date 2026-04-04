"""
Tests for liveness and readiness endpoints.
"""
import pytest


@pytest.mark.asyncio
async def test_healthz_returns_ok(client):
    """Liveness probe returns 200."""
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_readyz_returns_ready(client):
    """Readiness probe returns 200 when all deps are available."""
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["checks"]["database"] == "ok"
    assert data["checks"]["kms"] == "ok"


@pytest.mark.asyncio
async def test_readyz_no_dpop_nonce_header(client):
    """Readiness probe must not include DPoP-Nonce header."""
    resp = await client.get("/readyz")
    assert "DPoP-Nonce" not in resp.headers


@pytest.mark.asyncio
async def test_healthz_no_dpop_nonce_header(client):
    """Liveness probe must not include DPoP-Nonce header."""
    resp = await client.get("/healthz")
    assert "DPoP-Nonce" not in resp.headers


@pytest.mark.asyncio
async def test_health_legacy_still_works(client):
    """Legacy /health endpoint still works."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert "version" in resp.json()
