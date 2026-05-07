"""Cross-org trust delegation in ``decrypt_oneshot`` (issue #459).

Pre-fix: the SDK passed its local Org CA bundle as ``trust_anchors_pem``
on every receive, including cross-org. A cross-org sender's cert is
signed by the *sender's* Org CA, not the receiver's, so the chain
check returned False → ``verify_oneshot_envelope_signature`` failed →
``ValueError("envelope may have been tampered with post-send")``.

Post-fix: the SDK derives sender's org from ``sender_agent_id`` and
passes ``trust_anchors`` only when the sender shares the receiver's
org (``intra-org``). For ``cross-org``, ``None`` is passed: chain
verification is delegated to Court (which already enforced it at
federation publish time, see ``app/federation/publish.py``). Identity
binding (``cert_binds_agent_id``) and signature math run for both
intra and cross-org, so a forged SAN or a wrong sender priv key still
fails closed.

Coverage:
  1. cross-org receive succeeds without peer Org CA on the receiver.
  2. intra-org receive still enforces chain check (regression guard).
  3. cross-org receive with mismatched cert SAN still fails (identity
     binding stays mandatory).
"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization

from cullis_sdk.client import CullisClient
from cullis_sdk.crypto.message_signer import (
    ONESHOT_ENVELOPE_PROTO_VERSION,
    sign_oneshot_envelope,
)
from tests.cert_factory import (
    get_agent_key_pem,
    get_org_ca_pem,
    make_agent_cert,
)


pytestmark = pytest.mark.asyncio


def _cert_pem(agent_id: str, org_id: str) -> str:
    _, cert = make_agent_cert(agent_id, org_id)
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _seed_receiver(
    receiver_org_id: str,
    sender_agent_id: str,
    sender_cert_pem: str,
    *,
    ca_chain_path: Path | None = None,
) -> CullisClient:
    """Build a receiver-side client. ``ca_chain_path`` set only for
    intra-org tests; cross-org tests omit it because the receiver does
    not have a way to fetch the peer Org CA out-of-band."""
    client = CullisClient("http://test", verify_tls=False)
    client._proxy_org_id = receiver_org_id
    client._ca_chain_path = ca_chain_path
    client._pubkey_cache[sender_agent_id] = (sender_cert_pem, time.time())
    return client


def _build_mtls_envelope(
    sender_agent_id: str,
    sender_org_id: str,
    payload: dict,
) -> dict:
    sender_priv = get_agent_key_pem(sender_agent_id, sender_org_id)
    corr = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    ts = int(time.time())
    sig = sign_oneshot_envelope(
        sender_priv,
        correlation_id=corr,
        sender_agent_id=sender_agent_id,
        nonce=nonce,
        timestamp=ts,
        mode="mtls-only",
        reply_to=None,
        payload=payload,
    )
    return {
        "v": ONESHOT_ENVELOPE_PROTO_VERSION,
        "mode": "mtls-only",
        "payload": payload,
        "signature": sig,
        "nonce": nonce,
        "timestamp": ts,
        "correlation_id": corr,
        "reply_to": None,
    }


async def test_cross_org_decrypt_succeeds_without_peer_org_ca(tmp_path):
    """Roma sender → Tokyo receiver. Tokyo holds only Tokyo's Org CA on
    disk. The cross-org delegation path skips the chain check, so the
    decrypt succeeds even though Roma's CA is unknown locally."""
    sender = "roma::sender"
    receiver_org = "tokyo"
    sender_cert = _cert_pem(sender, "roma")

    # Tokyo's local CA bundle holds only Tokyo's CA, not Roma's.
    tokyo_ca_path = tmp_path / "tokyo-ca.pem"
    tokyo_ca_path.write_text(get_org_ca_pem("tokyo"))

    client = _seed_receiver(
        receiver_org, sender, sender_cert,
        ca_chain_path=tokyo_ca_path,
    )

    envelope = _build_mtls_envelope(sender, "roma", {"hi": "from roma"})
    inbox_row = {
        "msg_id": "m1",
        "sender_agent_id": sender,
        "correlation_id": envelope["correlation_id"],
        "payload_ciphertext": __import__("json").dumps(envelope),
    }

    result = client.decrypt_oneshot(inbox_row)
    assert result["sender_verified"] is True
    assert result["mode"] == "mtls-only"
    assert result["payload"] == {"hi": "from roma"}


async def test_intra_org_decrypt_enforces_chain_check(tmp_path):
    """Regression — intra-org receive still chains the sender cert to
    the local Org CA. Same-org sender, same-org receiver, ca.pem on
    disk: success path runs through the chain verifier."""
    sender = "tokyo::peer"
    receiver_org = "tokyo"
    sender_cert = _cert_pem(sender, "tokyo")
    tokyo_ca_path = tmp_path / "tokyo-ca.pem"
    tokyo_ca_path.write_text(get_org_ca_pem("tokyo"))

    client = _seed_receiver(
        receiver_org, sender, sender_cert,
        ca_chain_path=tokyo_ca_path,
    )

    envelope = _build_mtls_envelope(sender, "tokyo", {"hi": "internal"})
    inbox_row = {
        "msg_id": "m2",
        "sender_agent_id": sender,
        "correlation_id": envelope["correlation_id"],
        "payload_ciphertext": __import__("json").dumps(envelope),
    }

    result = client.decrypt_oneshot(inbox_row)
    assert result["sender_verified"] is True
    assert result["payload"] == {"hi": "internal"}


async def test_cross_org_decrypt_rejects_wrong_sender_san(tmp_path):
    """Identity binding stays mandatory. A cross-org cert whose SAN
    doesn't match the claimed ``sender_agent_id`` is rejected even
    when chain verification is delegated."""
    real_sender = "roma::sender"
    forged_sender_id = "roma::operator"  # claim different name
    receiver_org = "tokyo"
    # The cert in the cache is for ``roma::sender``, but the envelope
    # claims ``roma::operator``. ``cert_binds_agent_id`` should reject.
    real_cert = _cert_pem(real_sender, "roma")
    tokyo_ca_path = tmp_path / "tokyo-ca.pem"
    tokyo_ca_path.write_text(get_org_ca_pem("tokyo"))

    client = _seed_receiver(
        receiver_org, forged_sender_id, real_cert,
        ca_chain_path=tokyo_ca_path,
    )

    envelope = _build_mtls_envelope(real_sender, "roma", {"hi": "spoof"})
    # Lie about the sender in the envelope identity field.
    envelope_with_wrong_sender = dict(envelope)
    inbox_row = {
        "msg_id": "m3",
        "sender_agent_id": forged_sender_id,
        "correlation_id": envelope_with_wrong_sender["correlation_id"],
        "payload_ciphertext": __import__("json").dumps(envelope_with_wrong_sender),
    }

    with pytest.raises(ValueError):
        client.decrypt_oneshot(inbox_row)
