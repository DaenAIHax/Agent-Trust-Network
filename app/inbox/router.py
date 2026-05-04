"""ADR-020 Phase 4 — REST surface for the user inbox.

Endpoints:

  POST  /v1/inbox/send                 enqueue a message to a recipient
  GET   /v1/inbox?since=&limit=        list messages addressed to the
                                       authenticated principal
  POST  /v1/inbox/{msg_id}/ack         mark delivered (offline drain)
  POST  /v1/inbox/{msg_id}/archive     soft hide

Authentication is the existing DPoP-bound JWT
(``app.auth.jwt.get_current_agent``). The token's ``sub`` SPIFFE URI
is parsed into a ``Principal`` (ADR-020 Phase 1) so the principal type
gates the right inbox: ``user/mario`` GETs Mario's inbox, ``agent/X``
GETs the agent's notification queue.

The router does NOT implement WebSocket push — that lands in a
follow-up. Phase 4 Phase A ships durability so offline drain works
on day one; online push is sugar for the SPA later.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.db.database import get_db
from app.inbox.store import (
    DeliveryState,
    ReachDeniedError,
    enqueue,
    fetch_for_recipient,
    mark_archived,
    mark_delivered,
)
from app.policy.reach import PrincipalRef
from app.spiffe import spiffe_to_principal

_log = logging.getLogger("app.inbox.router")

router = APIRouter(prefix="/inbox", tags=["inbox"])


def _caller_principal(token: TokenPayload) -> PrincipalRef:
    """Convert the authenticated token into a ``PrincipalRef``.

    Uses the SPIFFE URI in ``sub`` (ADR-020 Phase 1 parser handles
    both legacy 2-component and new 3-component layouts; legacy
    paths default to ``principal_type=agent``). Falls back to the
    internal ``agent_id`` only if SPIFFE parsing fails.
    """
    try:
        principal = spiffe_to_principal(token.sub)
        return PrincipalRef(
            org_id=principal.org_id,
            principal_type=principal.principal_type,
            name=principal.name,
        )
    except ValueError:
        # Defensive fallback: tokens issued before ADR-020 may carry
        # an non-SPIFFE-shaped ``sub``. Use the org/name from the
        # internal agent_id and assume agent.
        if "::" in token.agent_id:
            org, name = token.agent_id.split("::", 1)
        else:
            org, name = token.org, token.agent_id
        return PrincipalRef(org_id=org, principal_type="agent", name=name)


# ── Send ───────────────────────────────────────────────────────────


class InboxSendRequest(BaseModel):
    """Request body for ``POST /v1/inbox/send``."""
    recipient_org_id: str = Field(..., min_length=1, max_length=128)
    recipient_principal_type: str = Field(..., min_length=1, max_length=16)
    recipient_name: str = Field(..., min_length=1, max_length=128)
    body: str = Field(..., max_length=64 * 1024)
    subject: str | None = Field(None, max_length=256)
    idempotency_key: str | None = Field(None, max_length=256)


class InboxSendResponse(BaseModel):
    msg_id: str
    inserted: bool
    quadrant: str


@router.post("/send", response_model=InboxSendResponse, status_code=status.HTTP_201_CREATED)
async def send_message(
    payload: InboxSendRequest,
    db: AsyncSession = Depends(get_db),
    token: TokenPayload = Depends(get_current_agent),
) -> InboxSendResponse:
    """Enqueue a message addressed to a Cullis principal."""
    sender = _caller_principal(token)
    recipient = PrincipalRef(
        org_id=payload.recipient_org_id,
        principal_type=payload.recipient_principal_type,  # type: ignore[arg-type]
        name=payload.recipient_name,
    )
    try:
        delivery = await enqueue(
            db,
            sender=sender,
            recipient=recipient,
            subject=payload.subject,
            body=payload.body,
            idempotency_key=payload.idempotency_key,
        )
    except ReachDeniedError as exc:
        _log.info(
            "inbox send denied: quadrant=%s reason=%s",
            exc.decision.quadrant, exc.decision.reason,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "reason": exc.decision.reason,
                "quadrant": exc.decision.quadrant,
            },
        )

    return InboxSendResponse(
        msg_id=delivery.msg_id,
        inserted=delivery.inserted,
        quadrant=delivery.decision.quadrant,
    )


# ── List ───────────────────────────────────────────────────────────


class InboxItem(BaseModel):
    msg_id: str
    sender_org_id: str
    sender_principal_type: str
    sender_name: str
    subject: str | None
    body: str
    delivery_state: str
    consent_id: str | None
    enqueued_at: str
    delivered_at: str | None
    ttl_expires_at: str


def _to_item(row: Any) -> InboxItem:
    return InboxItem(
        msg_id=row.msg_id,
        sender_org_id=row.sender_org_id,
        sender_principal_type=row.sender_principal_type,
        sender_name=row.sender_name,
        subject=row.subject,
        body=row.body,
        delivery_state=row.delivery_state,
        consent_id=row.consent_id,
        enqueued_at=row.enqueued_at.isoformat(),
        delivered_at=row.delivered_at.isoformat() if row.delivered_at else None,
        ttl_expires_at=row.ttl_expires_at.isoformat(),
    )


@router.get("", response_model=list[InboxItem])
async def list_inbox(
    since: str | None = None,
    limit: int = 50,
    include_archived: bool = False,
    db: AsyncSession = Depends(get_db),
    token: TokenPayload = Depends(get_current_agent),
) -> list[InboxItem]:
    """Return messages addressed to the authenticated principal."""
    recipient = _caller_principal(token)
    rows = await fetch_for_recipient(
        db,
        recipient=recipient,
        since_msg_id=since,
        limit=limit,
        include_archived=include_archived,
    )
    return [_to_item(r) for r in rows]


# ── Ack / Archive ──────────────────────────────────────────────────


async def _require_recipient(
    db: AsyncSession, msg_id: str, caller: PrincipalRef,
) -> None:
    """Reject 404 if msg doesn't exist OR caller is not its recipient."""
    from app.broker.db_models import UserInboxMessage
    from sqlalchemy import select, and_

    row = (await db.execute(
        select(UserInboxMessage).where(UserInboxMessage.msg_id == msg_id)
    )).scalar_one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message not found")
    if (
        row.recipient_org_id != caller.org_id
        or row.recipient_principal_type != caller.principal_type
        or row.recipient_name != caller.name
    ):
        # Don't leak existence to non-recipients: 404, not 403.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "message not found")


@router.post("/{msg_id}/ack")
async def ack(
    msg_id: str,
    online: bool = False,
    db: AsyncSession = Depends(get_db),
    token: TokenPayload = Depends(get_current_agent),
) -> dict:
    caller = _caller_principal(token)
    await _require_recipient(db, msg_id, caller)
    flipped = await mark_delivered(db, msg_id=msg_id, online=online)
    return {"acked": flipped, "msg_id": msg_id}


@router.post("/{msg_id}/archive")
async def archive(
    msg_id: str,
    db: AsyncSession = Depends(get_db),
    token: TokenPayload = Depends(get_current_agent),
) -> dict:
    caller = _caller_principal(token)
    await _require_recipient(db, msg_id, caller)
    archived = await mark_archived(db, msg_id=msg_id)
    return {"archived": archived, "msg_id": msg_id}
