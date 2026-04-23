"""Tests for the ``pubkey_fetcher`` injection into
:meth:`CullisClient.decrypt_oneshot` + the new
:meth:`CullisClient.get_agent_public_key_via_egress` helper.

The default (fetcher=None) path is covered by the existing audit tests
in ``tests/test_audit_oneshot_envelope_integrity.py``. This file focuses
on:
  - the injected fetcher is called with the sender id;
  - its return value is what the signature is verified against;
  - raising ``PubkeyFetchError`` propagates to the caller unchanged so
    the Connector's inbox poller can react specifically.
"""
from __future__ import annotations

import json
import time
import uuid

import pytest

from cullis_sdk.client import CullisClient, PubkeyFetchError
from cullis_sdk.crypto.message_signer import ONESHOT_ENVELOPE_PROTO_VERSION

from tests.test_audit_oneshot_envelope_integrity import (
    _alice_cert_pem,
    _inbox_row,
    _mtls_envelope,
)


def _client() -> CullisClient:
    """Fresh client with no pubkey cache — forces the fetcher path."""
    c = CullisClient("http://test", verify_tls=False)
    return c


def test_decrypt_oneshot_uses_injected_fetcher_mtls_mode():
    sender = "fetch1::alice"
    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="fetch1",
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"note": "hello"},
    )
    row = _inbox_row(env, sender_agent_id=sender)

    calls: list[str] = []

    def fetcher(agent_id: str) -> str:
        calls.append(agent_id)
        return _alice_cert_pem(sender, "fetch1")

    client = _client()
    try:
        result = client.decrypt_oneshot(row, pubkey_fetcher=fetcher)
    finally:
        client.close()

    assert calls == [sender]
    assert result["mode"] == "mtls-only"
    assert result["sender_verified"] is True
    assert result["payload"] == {"note": "hello"}


def test_decrypt_oneshot_propagates_fetcher_error():
    sender = "fetch2::alice"
    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="fetch2",
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"x": 1},
    )
    row = _inbox_row(env, sender_agent_id=sender)

    def failing_fetcher(agent_id: str) -> str:
        raise PubkeyFetchError("proxy returned no cert_pem for " + agent_id)

    client = _client()
    try:
        with pytest.raises(PubkeyFetchError) as excinfo:
            client.decrypt_oneshot(row, pubkey_fetcher=failing_fetcher)
    finally:
        client.close()
    assert sender in str(excinfo.value)


def test_decrypt_oneshot_default_fetcher_hits_broker():
    """Without a fetcher the method falls back to ``get_agent_public_key``.
    Seed the cache directly — that's the same code path the broker fetch
    populates once the response lands — and verify decrypt succeeds."""
    sender = "fetch3::alice"
    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    env = _mtls_envelope(
        sender_agent_id=sender, sender_org_id="fetch3",
        correlation_id=corr, nonce=nonce, timestamp=ts,
        payload={"x": 2},
    )
    row = _inbox_row(env, sender_agent_id=sender)

    client = _client()
    try:
        client._pubkey_cache[sender] = (
            _alice_cert_pem(sender, "fetch3"), time.time(),
        )
        result = client.decrypt_oneshot(row)
    finally:
        client.close()

    assert result["sender_verified"] is True


class _StubResponse:
    def __init__(self, status_code: int, body: dict | None = None):
        self.status_code = status_code
        self._body = body or {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import httpx
            raise httpx.HTTPStatusError(
                f"HTTP {self.status_code}",
                request=None, response=None,
            )


def test_get_agent_public_key_via_egress_happy_path(monkeypatch):
    client = _client()
    try:
        cert = "-----BEGIN CERTIFICATE-----\nSTUB\n-----END CERTIFICATE-----"

        def fake_egress_http(method, path, **kwargs):
            assert method == "get"
            assert path == "/v1/egress/agents/acme::alice/public-key"
            return _StubResponse(200, {"agent_id": "acme::alice", "cert_pem": cert})

        monkeypatch.setattr(client, "_egress_http", fake_egress_http)
        pem = client.get_agent_public_key_via_egress("acme::alice")
        assert pem == cert
        # Cache hit on the second call, no HTTP.
        calls = {"n": 0}

        def count_and_fail(*_a, **_kw):
            calls["n"] += 1
            return _StubResponse(500)
        monkeypatch.setattr(client, "_egress_http", count_and_fail)
        pem2 = client.get_agent_public_key_via_egress("acme::alice")
        assert pem2 == cert
        assert calls["n"] == 0
    finally:
        client.close()


def test_get_agent_public_key_via_egress_raises_on_empty_cert(monkeypatch):
    client = _client()
    try:
        def fake_egress_http(method, path, **kwargs):
            return _StubResponse(200, {"agent_id": "acme::ghost", "cert_pem": None})
        monkeypatch.setattr(client, "_egress_http", fake_egress_http)
        with pytest.raises(PubkeyFetchError) as excinfo:
            client.get_agent_public_key_via_egress("acme::ghost")
        assert "acme::ghost" in str(excinfo.value)
    finally:
        client.close()


def test_get_agent_public_key_via_egress_wraps_transport_errors(monkeypatch):
    client = _client()
    try:
        def boom(*_a, **_kw):
            raise RuntimeError("network went away")
        monkeypatch.setattr(client, "_egress_http", boom)
        with pytest.raises(PubkeyFetchError) as excinfo:
            client.get_agent_public_key_via_egress("acme::alice")
        assert "network went away" in str(excinfo.value)
    finally:
        client.close()


def test_get_agent_public_key_via_egress_force_refresh(monkeypatch):
    client = _client()
    try:
        cert1 = "CERT-V1"
        cert2 = "CERT-V2"
        state = {"cert": cert1}

        def fake_egress_http(method, path, **kwargs):
            return _StubResponse(200, {"agent_id": "acme::alice", "cert_pem": state["cert"]})
        monkeypatch.setattr(client, "_egress_http", fake_egress_http)

        assert client.get_agent_public_key_via_egress("acme::alice") == cert1
        state["cert"] = cert2
        # Without force_refresh, TTL cache still returns V1.
        assert client.get_agent_public_key_via_egress("acme::alice") == cert1
        # With force_refresh=True, HTTP is re-hit.
        assert client.get_agent_public_key_via_egress(
            "acme::alice", force_refresh=True,
        ) == cert2
    finally:
        client.close()
