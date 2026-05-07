"""``POST /v1/guardian/inspect`` — bidirectional content inspection (ADR-016).

Phase 1 (foundation) wires the contract end-to-end: mTLS-authenticated
request, validated body, persisted audit row, signed ticket, response
shaped per ADR. The endpoint always returns ``decision=pass`` because
no inspection tools are registered yet — the Phase 2 plugin owns the
actual logic.

Locking the wire shape now lets:

- the SDK author (Phase 3) develop against a real response, including
  ticket verification, before any tool exists;
- third-party adapter authors (Lakera, Portkey, NeMo, …) plug into the
  ``mcp_proxy.guardian.registry`` without forking the proxy;
- the dashboard (Phase 6) and audit timeline rely on a stable
  ``guardian.inspect`` event in ``local_audit`` from day one.
"""
from __future__ import annotations

import base64
import binascii
import logging
import uuid
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from mcp_proxy.auth.dpop_client_cert import get_agent_from_dpop_client_cert
from mcp_proxy.config import get_settings
from mcp_proxy.guardian.audit import record_inspection
from mcp_proxy.guardian.ticket import GuardianTicketError, sign_ticket
from mcp_proxy.models import InternalAgent

_log = logging.getLogger("mcp_proxy.guardian.endpoint")

router = APIRouter(tags=["guardian"])


class InspectRequest(BaseModel):
    direction: Literal["in", "out"]
    peer_agent_id: str = Field(..., min_length=1, max_length=512)
    msg_id: str = Field(..., min_length=1, max_length=128)
    content_type: str = Field(
        default="application/json+a2a-payload",
        max_length=128,
    )
    payload_b64: str = Field(..., min_length=1)


class InspectReason(BaseModel):
    tool: str
    match: str


class InspectResponse(BaseModel):
    decision: Literal["pass", "redact", "block"]
    ticket: str
    ticket_exp: int
    redacted_payload_b64: str | None = None
    audit_id: str
    reasons: list[InspectReason] = Field(default_factory=list)


@router.post("/v1/guardian/inspect", response_model=InspectResponse)
async def inspect(
    req: InspectRequest,
    agent: InternalAgent = Depends(get_agent_from_dpop_client_cert),
) -> InspectResponse:
    settings = get_settings()
    if not settings.guardian_ticket_key:
        # Refuse to issue tickets nobody can verify. Surface as 503 so
        # the SDK back-off path is the same as for any infra outage.
        raise HTTPException(
            status_code=503,
            detail={
                "reason": "guardian_ticket_key_not_configured",
                "hint": "Set MCP_PROXY_GUARDIAN_TICKET_KEY (hex or base64url).",
            },
        )

    # Validate the payload encoding now (cheap) so a malformed b64 fails
    # before we write an audit row with garbage bytes attached.
    try:
        payload = base64.urlsafe_b64decode(
            req.payload_b64 + "=" * (-len(req.payload_b64) % 4),
        )
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail={"reason": "malformed_payload_b64", "error": str(exc)},
        ) from exc

    audit_id = uuid.uuid4().hex
    decision: Literal["pass", "redact", "block"] = "pass"

    # Phase 1: no fast-path tools registered. Phase 2 (plugin) iterates
    # ``mcp_proxy.guardian.registry.registered_tools`` here, dispatches
    # each in parallel via asyncio.gather, and merges the worst decision
    # into the response. The audit detail at that point will carry the
    # per-tool reasons; for now ``reasons`` stays empty.
    _ = payload  # tools will read this; silence linter for now

    try:
        ticket, ticket_exp = sign_ticket(
            key=settings.guardian_ticket_key,
            agent_id=agent.agent_id,
            peer_agent_id=req.peer_agent_id,
            msg_id=req.msg_id,
            direction=req.direction,
            decision=decision,
            audit_id=audit_id,
            ttl_s=settings.guardian_ticket_ttl_s,
        )
    except GuardianTicketError as exc:
        # Treat as 503 (config issue) rather than 500 — the operator
        # has a known fix (set/rotate the key).
        raise HTTPException(
            status_code=503,
            detail={"reason": exc.reason, "error": exc.detail or exc.reason},
        ) from exc

    try:
        await record_inspection(
            audit_id=audit_id,
            decision=decision,
            direction=req.direction,
            agent_id=agent.agent_id,
            peer_agent_id=req.peer_agent_id,
            msg_id=req.msg_id,
            org_id=settings.org_id,
            reasons=[],
            extra={"content_type": req.content_type, "phase": "foundation"},
        )
    except Exception:
        # Audit failure must not silently drop the decision; log loudly,
        # but still return the ticket — the SDK has already paid the
        # round trip and an audit retry happens in the background
        # writer in Phase 4. Phase 1 just logs.
        _log.exception(
            "guardian audit write failed agent=%s msg_id=%s",
            agent.agent_id, req.msg_id,
        )

    return InspectResponse(
        decision=decision,
        ticket=ticket,
        ticket_exp=ticket_exp,
        redacted_payload_b64=None,
        audit_id=audit_id,
        reasons=[],
    )
