"""
Tests for the public broker CA endpoint.

GET /v1/.well-known/broker-ca.pem serves the broker root CA certificate
so remote MCP proxies can pin the broker TLS without an out-of-band copy.
"""
from pathlib import Path
from unittest.mock import patch

import pytest


_FAKE_CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBFakeCaForTestingOnlyNotAValidCertificate==\n"
    "-----END CERTIFICATE-----\n"
)

_ENDPOINT = "/v1/.well-known/broker-ca.pem"


@pytest.mark.asyncio
async def test_broker_ca_endpoint_returns_pem(client, tmp_path: Path):
    """Endpoint returns the CA cert bytes with the PEM media type."""
    ca_file = tmp_path / "broker-ca.pem"
    ca_file.write_text(_FAKE_CA_PEM)

    with patch("app.main.settings") as mock_settings:
        mock_settings.broker_ca_cert_path = str(ca_file)
        # Preserve other attrs used elsewhere in main.py
        mock_settings.app_version = "test"
        resp = await client.get(_ENDPOINT)

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/x-pem-file")
    assert resp.text == _FAKE_CA_PEM


@pytest.mark.asyncio
async def test_broker_ca_endpoint_no_auth_required(client, tmp_path: Path):
    """Endpoint is public — no Authorization header needed."""
    ca_file = tmp_path / "broker-ca.pem"
    ca_file.write_text(_FAKE_CA_PEM)

    with patch("app.main.settings") as mock_settings:
        mock_settings.broker_ca_cert_path = str(ca_file)
        mock_settings.app_version = "test"
        resp = await client.get(_ENDPOINT)

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_broker_ca_endpoint_cache_control(client, tmp_path: Path):
    """Response should be cacheable (public, max-age=3600)."""
    ca_file = tmp_path / "broker-ca.pem"
    ca_file.write_text(_FAKE_CA_PEM)

    with patch("app.main.settings") as mock_settings:
        mock_settings.broker_ca_cert_path = str(ca_file)
        mock_settings.app_version = "test"
        resp = await client.get(_ENDPOINT)

    cc = resp.headers.get("cache-control", "")
    assert "public" in cc
    assert "max-age=3600" in cc


@pytest.mark.asyncio
async def test_broker_ca_endpoint_no_dpop_nonce(client, tmp_path: Path):
    """/v1/.well-known/* responses must not include DPoP-Nonce."""
    ca_file = tmp_path / "broker-ca.pem"
    ca_file.write_text(_FAKE_CA_PEM)

    with patch("app.main.settings") as mock_settings:
        mock_settings.broker_ca_cert_path = str(ca_file)
        mock_settings.app_version = "test"
        resp = await client.get(_ENDPOINT)

    assert "DPoP-Nonce" not in resp.headers


@pytest.mark.asyncio
async def test_broker_ca_endpoint_503_when_missing(client, tmp_path: Path):
    """Endpoint returns JSON 503 when the CA file does not exist.

    A missing CA on disk is a broker mis-configuration (the ``./certs``
    bind-mount is empty or wrong), so we signal 503 Service Unavailable
    rather than 404 Not Found — clients should back off and retry.
    """
    missing = tmp_path / "does-not-exist.pem"

    with patch("app.main.settings") as mock_settings:
        mock_settings.broker_ca_cert_path = str(missing)
        mock_settings.app_version = "test"
        resp = await client.get(_ENDPOINT)

    assert resp.status_code == 503
    body = resp.json()
    assert "detail" in body
    assert "not available" in body["detail"].lower() or "mis-configured" in body["detail"].lower()
