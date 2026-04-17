"""F-B-11 Phase 3a — admin endpoint to register/rotate an agent's DPoP JWK.

``POST /v1/admin/agents/{agent_id}/dpop-jwk`` accepts the public JWK the
Connector generated, computes the RFC 7638 thumbprint server-side, and
stores it on ``internal_agents.dpop_jkt`` so the egress DPoP dep (#199
+ #204) can enforce key-possession binding per agent.

Before the Phase 3b SDK auto-submit lands, this is the only path to
populate the column. Tests cover:
  * happy path (EC and RSA)
  * rejection of private key material (``d`` field)
  * rejection of unsupported ``kty``
  * rejection of malformed JWK (missing coords)
  * unknown agent → 404
  * rotation: second POST overwrites the first
  * admin auth missing / wrong → 403
  * database state actually carries the new thumbprint
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

pytestmark = pytest.mark.asyncio


# ── test harness ────────────────────────────────────────────────────

async def _spin_proxy(tmp_path, monkeypatch, org_id: str = "fb11-p3a"):
    db_file = tmp_path / "proxy.sqlite"
    monkeypatch.setenv("MCP_PROXY_DATABASE_URL", f"sqlite+aiosqlite:///{db_file}")
    monkeypatch.delenv("PROXY_DB_URL", raising=False)
    monkeypatch.setenv("PROXY_LOCAL_SWEEPER_DISABLED", "1")
    monkeypatch.setenv("PROXY_TRUST_DOMAIN", "cullis.test")
    monkeypatch.setenv("MCP_PROXY_ORG_ID", org_id)
    monkeypatch.setenv("MCP_PROXY_STANDALONE", "true")
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
    from mcp_proxy.main import app
    return app


async def _headers():
    from mcp_proxy.config import get_settings
    return {"X-Admin-Secret": get_settings().admin_secret}


async def _create_agent(cli: AsyncClient, name: str) -> str:
    h = await _headers()
    r = await cli.post(
        "/v1/admin/agents",
        headers=h,
        json={"agent_name": name, "display_name": name, "capabilities": []},
    )
    assert r.status_code == 201, r.text
    return r.json()["agent_id"]


# ── JWK builders ────────────────────────────────────────────────────

def _ec_public_jwk() -> dict:
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    x = base64.urlsafe_b64encode(nums.x.to_bytes(32, "big")).rstrip(b"=").decode()
    y = base64.urlsafe_b64encode(nums.y.to_bytes(32, "big")).rstrip(b"=").decode()
    return {"kty": "EC", "crv": "P-256", "x": x, "y": y}


def _rsa_public_jwk() -> dict:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = priv.public_key().public_numbers()
    n = base64.urlsafe_b64encode(
        nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode()
    e = base64.urlsafe_b64encode(
        nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode()
    return {"kty": "RSA", "n": n, "e": e}


# ── happy paths ─────────────────────────────────────────────────────

async def test_register_ec_jwk_sets_dpop_jkt(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            agent_id = await _create_agent(cli, "alice")
            jwk = _ec_public_jwk()
            h = await _headers()
            r = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                headers=h,
                json={"jwk": jwk},
            )
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["agent_id"] == agent_id
            assert isinstance(body["dpop_jkt"], str) and len(body["dpop_jkt"]) > 30

            # Verify the thumbprint matches what compute_jkt produces.
            from mcp_proxy.auth.dpop import compute_jkt
            assert body["dpop_jkt"] == compute_jkt(jwk)

            # Verify DB actually carries the value.
            from mcp_proxy.db import get_db
            async with get_db() as conn:
                row = (await conn.execute(
                    text("SELECT dpop_jkt FROM internal_agents WHERE agent_id = :a"),
                    {"a": agent_id},
                )).first()
            assert row is not None
            assert row[0] == body["dpop_jkt"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_register_rsa_jwk_sets_dpop_jkt(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            agent_id = await _create_agent(cli, "bob")
            jwk = _rsa_public_jwk()
            h = await _headers()
            r = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                headers=h,
                json={"jwk": jwk},
            )
            assert r.status_code == 200, r.text
            from mcp_proxy.auth.dpop import compute_jkt
            assert r.json()["dpop_jkt"] == compute_jkt(jwk)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_register_rotates_existing_jkt(tmp_path, monkeypatch):
    """Second POST with a different key overwrites the first. Operators
    need this to rotate a Connector's DPoP keypair without deleting
    and recreating the agent."""
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            agent_id = await _create_agent(cli, "carol")
            h = await _headers()

            jwk_first = _ec_public_jwk()
            r1 = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                headers=h, json={"jwk": jwk_first},
            )
            assert r1.status_code == 200

            jwk_second = _ec_public_jwk()
            r2 = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                headers=h, json={"jwk": jwk_second},
            )
            assert r2.status_code == 200
            assert r2.json()["dpop_jkt"] != r1.json()["dpop_jkt"]
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── input validation ────────────────────────────────────────────────

async def test_reject_jwk_with_private_material(tmp_path, monkeypatch):
    """``d`` field in the JWK means the caller sent a PRIVATE key.
    Hard reject — we never want private material on the wire."""
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            agent_id = await _create_agent(cli, "dave")
            bad = _ec_public_jwk()
            bad["d"] = "this-is-a-private-scalar-do-not-accept"
            h = await _headers()
            r = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                headers=h, json={"jwk": bad},
            )
            assert r.status_code == 400
            assert "private" in r.json()["detail"].lower()
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_reject_unsupported_kty(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            agent_id = await _create_agent(cli, "erin")
            h = await _headers()
            r = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                headers=h, json={"jwk": {"kty": "oct", "k": "x"}},
            )
            assert r.status_code == 400
            assert "kty" in r.json()["detail"].lower()
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_reject_malformed_jwk_missing_coords(tmp_path, monkeypatch):
    """EC JWK with missing ``x``/``y`` → compute_jkt raises → 400."""
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            agent_id = await _create_agent(cli, "fred")
            h = await _headers()
            r = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                headers=h,
                json={"jwk": {"kty": "EC", "crv": "P-256"}},  # no x/y
            )
            assert r.status_code == 400
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_reject_empty_body(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            agent_id = await _create_agent(cli, "gina")
            h = await _headers()
            r = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                headers=h, json={"jwk": {}},
            )
            assert r.status_code == 400
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


# ── routing / auth ──────────────────────────────────────────────────

async def test_unknown_agent_returns_404(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            h = await _headers()
            r = await cli.post(
                "/v1/admin/agents/does::not-exist/dpop-jwk",
                headers=h,
                json={"jwk": _ec_public_jwk()},
            )
            assert r.status_code == 404
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_missing_admin_secret_rejected(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            agent_id = await _create_agent(cli, "helen")
            r = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                json={"jwk": _ec_public_jwk()},
            )
            # FastAPI raises 422 when the required header is missing; the
            # handler's own check would return 403. Either flavor confirms
            # the call was refused without touching the DB.
            assert r.status_code in (401, 403, 422)
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()


async def test_wrong_admin_secret_rejected(tmp_path, monkeypatch):
    app = await _spin_proxy(tmp_path, monkeypatch)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as cli:
        async with app.router.lifespan_context(app):
            agent_id = await _create_agent(cli, "iris")
            r = await cli.post(
                f"/v1/admin/agents/{agent_id}/dpop-jwk",
                headers={"X-Admin-Secret": "totally-wrong-value"},
                json={"jwk": _ec_public_jwk()},
            )
            assert r.status_code == 403
    from mcp_proxy.config import get_settings
    get_settings.cache_clear()
