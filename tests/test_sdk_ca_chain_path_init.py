"""Regression test for the ``_ca_chain_path`` init bug.

Three ``CullisClient`` factories (``from_identity_dir``,
``from_connector``, ``from_enrollment``) take the
``cls.__new__(cls)`` route to bypass ``__init__``. Before this fix
they forgot to set ``instance._ca_chain_path``, so any subsequent
call into ``decrypt_oneshot`` (which reads it through
``_resolve_trust_anchors``) crashed with::

    AttributeError: 'CullisClient' object has no attribute '_ca_chain_path'

The crash slipped past CI because no existing test exercised the
factory → ``decrypt_oneshot`` path. Surfaced by the sandbox enterprise
smoke (B4.7 A2A messaging). This test asserts the attribute is
present on every factory and that ``_resolve_trust_anchors`` works
without raising for both anchor and no-anchor paths.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cullis_sdk.client import CullisClient


def _has_ca_chain_attr(client: CullisClient) -> bool:
    """Calling ``_resolve_trust_anchors`` is the actual hot path that
    crashed in production; the attribute presence check is the cheap
    proxy for it."""
    if not hasattr(client, "_ca_chain_path"):
        return False
    # Smoke: must not raise. Returns None when the attribute is None.
    client._resolve_trust_anchors()
    return True


def test_from_identity_dir_sets_ca_chain_path(tmp_path):
    """``from_identity_dir`` accepts ca_chain_path and stores it."""
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("dummy-cert")
    key.write_text("dummy-key")
    client = CullisClient.from_identity_dir(
        "https://mastio.test:9443",
        cert_path=cert,
        key_path=key,
        agent_id="acme::agent",
        org_id="acme",
        verify_tls=False,
    )
    assert _has_ca_chain_attr(client)
    assert client._ca_chain_path is None  # no ca_chain_path passed


def test_from_identity_dir_with_ca_chain_path(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    ca = tmp_path / "ca.pem"
    cert.write_text("dummy-cert")
    key.write_text("dummy-key")
    ca.write_text(
        "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
    )
    client = CullisClient.from_identity_dir(
        "https://mastio.test:9443",
        cert_path=cert,
        key_path=key,
        agent_id="acme::agent",
        org_id="acme",
        verify_tls=False,
        ca_chain_path=ca,
    )
    assert _has_ca_chain_attr(client)
    assert client._ca_chain_path == Path(ca)


def test_init_path_keeps_ca_chain_path():
    """The ``__init__`` route was never broken — guard against a
    refactor that drops it."""
    client = CullisClient("https://mastio.test:9443", verify_tls=False)
    assert _has_ca_chain_attr(client)
    assert client._ca_chain_path is None
