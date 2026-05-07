"""Cullis SDK — Guardian cooperation hooks (ADR-016).

Phase 1 ships a NO-OP client (default off) plus a ticket verifier the
agent runtime can use without committing to call the endpoint yet.
Phase 3 wires the actual ``inspect_before_send`` / ``inspect_before_deliver``
into the existing send/receive paths.

Public surface:
    GuardianBlocked — raised when Mastio returns ``decision=block``
    GuardianClient — the per-agent client (NO-OP when env disabled)
    InspectionDecision — typed wrapper around the Mastio response
    verify_ticket — local-only ticket signature check
"""
from __future__ import annotations

from cullis_sdk.guardian.client import (
    GuardianBlocked,
    GuardianClient,
    InspectionDecision,
    verify_ticket,
)

__all__ = [
    "GuardianBlocked",
    "GuardianClient",
    "InspectionDecision",
    "verify_ticket",
]
