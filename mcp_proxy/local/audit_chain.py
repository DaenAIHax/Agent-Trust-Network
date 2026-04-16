"""Per-org hash-chain primitives for the proxy's ``local_audit`` table.

The canonical form is **byte-for-byte identical** to the broker's
``app/db/audit.py::compute_entry_hash`` so rows written by the proxy can be
exported and verified on the broker side without schema translation.

Broker code is intentionally not imported: ``mcp_proxy`` and ``app`` share
no Python packages (see db_models.py module docstring). Any divergence
between the two implementations is a federation-breaking bug and must be
caught by ``tests/test_proxy_audit_chain_parity.py``, which imports both
and asserts equality on a large randomized input set.
"""
from __future__ import annotations

import hashlib
from datetime import datetime

# Sentinel org for audit events that have no natural tenant (system-level,
# bootstrap, etc.). Matches broker ``app.db.audit.SYSTEM_ORG`` so exports
# merge cleanly.
SYSTEM_ORG = "__system__"


def compute_entry_hash(
    entry_id: int,
    timestamp: datetime,
    event_type: str,
    agent_id: str | None,
    session_id: str | None,
    org_id: str | None,
    result: str,
    details: str | None,
    previous_hash: str | None,
    chain_seq: int | None = None,
    peer_org_id: str | None = None,
) -> str:
    """SHA-256 of the canonical audit-entry serialization.

    When ``chain_seq`` is ``None`` the format matches the pre-per-org
    broker format (legacy rows, globally chained). For new rows (per-org
    chain) ``chain_seq`` and ``peer_org_id`` are appended so neither can
    be rewritten without detection.
    """
    base = (
        f"{entry_id}|{timestamp.isoformat()}|{event_type}|"
        f"{agent_id or ''}|{session_id or ''}|{org_id or ''}|"
        f"{result}|{details or ''}|{previous_hash or 'genesis'}"
    )
    if chain_seq is None:
        canonical = base
    else:
        canonical = f"{base}|seq={chain_seq}|peer={peer_org_id or ''}"
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
