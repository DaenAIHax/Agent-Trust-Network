"""``encrypt_for_agent`` accepts both X.509 cert PEM and bare SPKI.

Issue #470 (PR #471) made the federation public-key endpoint return
the full cert. The cross-org send path threads that cert into
``encrypt_for_agent`` as ``recipient_pubkey_pem``. The function used
to call ``serialization.load_pem_public_key`` directly, which only
accepts ``-----BEGIN PUBLIC KEY-----`` (bare SPKI). When fed a cert
PEM it raised ``ValueError: Valid PEM but no BEGIN PUBLIC KEY/END
PUBLIC KEY delimiters``, breaking cross-org A2A end-to-end.

Fix: detect the input shape and extract the public key from the cert
when the PEM carries a CERTIFICATE block. Bare SPKI input still works
unchanged.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import serialization

from cullis_sdk.crypto.e2e import decrypt_from_agent, encrypt_for_agent
from tests.cert_factory import get_agent_key_pem, make_agent_cert


def _cert_pem(agent_id: str, org_id: str) -> str:
    _, cert = make_agent_cert(agent_id, org_id)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _spki_pem(agent_id: str, org_id: str) -> str:
    _, cert = make_agent_cert(agent_id, org_id)
    return cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _round_trip(recipient_pubkey_pem: str, recipient_priv_pem: str) -> dict:
    payload = {"hello": "cross-org"}
    blob = encrypt_for_agent(
        recipient_pubkey_pem, payload,
        inner_signature="sig-stub",
        session_id="oneshot:c1",
        sender_agent_id="src::alice",
        client_seq=0,
    )
    plaintext, inner_sig = decrypt_from_agent(
        recipient_priv_pem, blob,
        "oneshot:c1", "src::alice", client_seq=0,
    )
    assert plaintext == payload
    assert inner_sig == "sig-stub"
    return blob


def test_encrypt_accepts_full_x509_cert_pem():
    """The default federation read response carries a cert PEM. The
    SDK send path used to choke; now it extracts the pubkey from the
    cert and round-trips."""
    cert_pem = _cert_pem("dst::bob", "dst-org")
    priv_pem = get_agent_key_pem("dst::bob", "dst-org")
    _round_trip(cert_pem, priv_pem)


def test_encrypt_still_accepts_bare_spki_pem():
    """Backward compat — older brokers (or callers explicitly extracting
    the SPKI) keep working."""
    spki_pem = _spki_pem("dst::charlie", "dst-org-2")
    priv_pem = get_agent_key_pem("dst::charlie", "dst-org-2")
    _round_trip(spki_pem, priv_pem)
