"""Byte-for-byte parity between proxy and broker hash-chain canonical form.

ADR-006 Fase 0: ``mcp_proxy.local.audit_chain.compute_entry_hash`` must
produce the exact same SHA-256 digest as ``app.db.audit.compute_entry_hash``
for identical inputs. If this test ever fails, proxy audit rows become
non-portable to the broker — federation-breaking.

The randomized input set spans legacy (chain_seq=None) and per-org rows,
NULL and non-NULL details/peer_org_id, and edge-case strings.
"""
from __future__ import annotations

import random
import string
from datetime import datetime, timedelta, timezone

import pytest

from app.db.audit import compute_entry_hash as broker_compute
from mcp_proxy.local.audit_chain import compute_entry_hash as proxy_compute


def _rand_str(rng: random.Random, n: int) -> str:
    return "".join(rng.choices(string.ascii_letters + string.digits + "|{}\"':", k=n))


@pytest.mark.parametrize("seed", list(range(16)))
def test_hash_parity_randomized(seed: int):
    rng = random.Random(seed)
    ts = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(
        seconds=rng.randint(0, 3600 * 24 * 90)
    )
    kwargs = dict(
        entry_id=rng.randint(1, 10_000),
        timestamp=ts,
        event_type=_rand_str(rng, 16),
        agent_id=_rand_str(rng, 24) if rng.random() > 0.3 else None,
        session_id=_rand_str(rng, 20) if rng.random() > 0.3 else None,
        org_id=_rand_str(rng, 12) if rng.random() > 0.2 else None,
        result=rng.choice(["ok", "denied", "error"]),
        details=_rand_str(rng, 80) if rng.random() > 0.4 else None,
        previous_hash=_rand_str(rng, 64) if rng.random() > 0.5 else None,
        chain_seq=rng.randint(1, 1000) if rng.random() > 0.5 else None,
        peer_org_id=_rand_str(rng, 12) if rng.random() > 0.7 else None,
    )
    assert proxy_compute(**kwargs) == broker_compute(**kwargs)


def test_genesis_row_matches_broker():
    ts = datetime(2026, 4, 16, 10, 30, tzinfo=timezone.utc)
    args = dict(
        entry_id=1,
        timestamp=ts,
        event_type="session_open",
        agent_id="acme::buyer",
        session_id="sess-001",
        org_id="acme",
        result="ok",
        details='{"capabilities":["kyc.read"]}',
        previous_hash=None,
        chain_seq=1,
        peer_org_id=None,
    )
    assert proxy_compute(**args) == broker_compute(**args)


def test_legacy_row_shape_identical():
    """chain_seq=None path must still match (grandfathered legacy rows)."""
    ts = datetime(2025, 12, 31, 23, 59, tzinfo=timezone.utc)
    args = dict(
        entry_id=42,
        timestamp=ts,
        event_type="legacy_event",
        agent_id=None,
        session_id=None,
        org_id=None,
        result="ok",
        details=None,
        previous_hash=None,
        chain_seq=None,
    )
    assert proxy_compute(**args) == broker_compute(**args)


def test_peer_org_id_binds_into_hash():
    """peer_org_id difference must change the digest (dual-write audit)."""
    ts = datetime(2026, 4, 16, tzinfo=timezone.utc)
    base = dict(
        entry_id=7,
        timestamp=ts,
        event_type="cross_org_session",
        agent_id="acme::buyer",
        session_id="sess-x",
        org_id="acme",
        result="ok",
        details="x",
        previous_hash="0" * 64,
        chain_seq=5,
    )
    h1 = proxy_compute(**base, peer_org_id="contoso")
    h2 = proxy_compute(**base, peer_org_id="otherco")
    h3 = proxy_compute(**base, peer_org_id=None)
    assert h1 != h2 != h3
