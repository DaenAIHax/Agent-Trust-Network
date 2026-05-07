"""``GET /v1/federation/agents/{id}/public-key`` returns ``cert_pem``.

Issue #470. The endpoint historically extracted the SPKI from the
stored cert and returned only ``public_key_pem``. SDK consumers
post-H7 audit fix reject bare SPKI; they need the full X.509 to bind
the public key to the agent identity.

The fix carries ``cert_pem`` alongside the legacy ``public_key_pem``,
so the SDK reads ``cert_pem`` (and falls back to ``public_key_pem``
when an older broker doesn't populate the cert).
"""
from __future__ import annotations

import pytest
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import serialization
from httpx import AsyncClient

from tests.cert_factory import make_agent_cert
from tests.conftest import seed_court_agent
from tests.test_federation_read import _setup


pytestmark = pytest.mark.asyncio


async def _seed_agent_with_cert(org_id: str, agent_id: str) -> str:
    """Create an internal_agents row with a valid Org-CA-signed cert.
    Returns the cert PEM."""
    from app.registry.store import register_agent, update_agent_cert, compute_cert_thumbprint
    from tests.conftest import TestSessionLocal

    _, cert = make_agent_cert(agent_id, org_id)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    thumb = compute_cert_thumbprint(cert_pem)

    async with TestSessionLocal() as session:
        await register_agent(
            session,
            agent_id=agent_id, org_id=org_id,
            display_name=agent_id, capabilities=["cap.read"],
            metadata={},
        )
        await update_agent_cert(
            session, agent_id=agent_id,
            cert_pem=cert_pem, thumbprint=thumb,
        )
    return cert_pem


async def test_public_key_response_carries_full_cert_pem(
    client: AsyncClient, dpop,
):
    """Same-org fetch returns both ``cert_pem`` (X.509) and the legacy
    ``public_key_pem`` (SPKI). SDK consumers post-H7 use the cert."""
    token = await _setup(
        client, "fr-cert-a", "fr-cert-a::caller", ["cap.read"], dpop,
    )
    await _seed_agent_with_cert("fr-cert-a", "fr-cert-a::peer")

    resp = await client.get(
        "/v1/federation/agents/fr-cert-a::peer/public-key",
        headers=dpop.headers(
            "GET", "/v1/federation/agents/fr-cert-a::peer/public-key", token,
        ),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Both fields present
    assert "public_key_pem" in body
    assert body["public_key_pem"].startswith("-----BEGIN PUBLIC KEY-----")
    assert "cert_pem" in body
    assert body["cert_pem"] is not None
    assert body["cert_pem"].startswith("-----BEGIN CERTIFICATE-----")

    # ``cert_pem`` parses as a real X.509 — the SDK's
    # ``load_cert_strict`` (H7 audit) accepts it
    parsed = crypto_x509.load_pem_x509_certificate(body["cert_pem"].encode())
    cn_attrs = parsed.subject.get_attributes_for_oid(
        crypto_x509.NameOID.COMMON_NAME,
    )
    assert cn_attrs and cn_attrs[0].value == "fr-cert-a::peer"

    # And the SPKI extracted from the cert matches what the legacy
    # field returned, so old callers reading ``public_key_pem`` keep
    # working byte-identical.
    expected_spki = parsed.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    assert body["public_key_pem"] == expected_spki


async def test_public_key_404_when_cert_missing(client: AsyncClient, dpop):
    """No cert pinned yet → 404 unchanged. Backward compat with the
    pre-issue contract."""
    token = await _setup(
        client, "fr-cert-b", "fr-cert-b::caller", ["cap.read"], dpop,
    )
    await seed_court_agent(
        agent_id="fr-cert-b::no-cert",
        org_id="fr-cert-b",
        display_name="no-cert",
        capabilities=["cap.read"],
    )
    resp = await client.get(
        "/v1/federation/agents/fr-cert-b::no-cert/public-key",
        headers=dpop.headers(
            "GET", "/v1/federation/agents/fr-cert-b::no-cert/public-key", token,
        ),
    )
    assert resp.status_code == 404
