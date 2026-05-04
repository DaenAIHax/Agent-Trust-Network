"""User inbox storage layer (ADR-020 Phase 4).

Wraps ``UserInboxMessage`` with a small async API:

  - ``enqueue``                 reach-policy gate + persist
  - ``fetch_for_recipient``     drain pending / cursor pagination
  - ``mark_delivered``          ack
  - ``mark_archived``           soft hide

The reach gate is the load-bearing part: every enqueue calls
``evaluate_reach_quadrant`` and refuses to write the row when the
quadrant is denied. The denial is itself audited by the reach
evaluator; the store does NOT swallow it silently.
"""
from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import and_, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.broker.db_models import UserInboxMessage
from app.policy.reach import (
    OwnershipResolver,
    PolicyDecision,
    PrincipalRef,
    ReachContext,
    evaluate_reach_quadrant,
)

_log = logging.getLogger("app.inbox.store")

# TTL defaults per recipient principal type (ADR-020 §5).
_DEFAULT_TTL_SECONDS = {
    "user": 7 * 24 * 3600,      # 7 days
    "agent": 30 * 60,           # 30 minutes (mirrors A2A behaviour)
    "workload": 5 * 60,         # 5 minutes (workloads should be online)
}


class DeliveryState(str, Enum):
    """Discrete states a row passes through. Stored as VARCHAR for SQL
    legibility; the enum is the canonical source of values."""
    QUEUED = "queued"
    DELIVERED_OFFLINE = "delivered_offline"
    DELIVERED_ONLINE = "delivered_online"
    ARCHIVED = "archived"
    EXPIRED = "expired"


@dataclass(frozen=True)
class InboxDelivery:
    """Outcome of an enqueue: row written + reach decision attached."""
    msg_id: str
    inserted: bool
    decision: PolicyDecision


class ReachDeniedError(RuntimeError):
    """Raised when ``evaluate_reach_quadrant`` rejects the send.

    Carries the decision so callers (e.g. the router) can surface
    quadrant + reason to the audit log without re-evaluating.
    """

    def __init__(self, decision: PolicyDecision):
        super().__init__(decision.reason)
        self.decision = decision


# ── Enqueue ─────────────────────────────────────────────────────────


async def enqueue(
    db: AsyncSession,
    *,
    sender: PrincipalRef,
    recipient: PrincipalRef,
    body: str,
    subject: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    idempotency_key: Optional[str] = None,
    ownership_resolver: OwnershipResolver | None = None,
) -> InboxDelivery:
    """Reach-gate then persist a message in the recipient's inbox.

    Always emits a reach evaluation audit row (via
    ``evaluate_reach_quadrant``). On allow, writes a
    ``UserInboxMessage`` row with ``delivery_state='queued'`` and
    returns ``inserted=True``. On a duplicate ``idempotency_key`` for
    the same recipient, returns the existing ``msg_id`` and
    ``inserted=False`` (no audit duplication, no second row).

    Raises ``ReachDeniedError`` when the quadrant is denied. The
    caller is expected to surface a 403 (or analogous error) to its
    own client; the audit row already records the denial.
    """
    ctx = ReachContext(source=sender, destination=recipient)
    decision = await evaluate_reach_quadrant(
        db, ctx, ownership_resolver=ownership_resolver,
    )
    if not decision.allowed:
        raise ReachDeniedError(decision)

    if ttl_seconds is None:
        ttl_seconds = _DEFAULT_TTL_SECONDS.get(recipient.principal_type, 30 * 60)
    now = datetime.now(timezone.utc)
    msg_id = str(uuid.uuid4())

    values = dict(
        msg_id=msg_id,
        sender_org_id=sender.org_id,
        sender_principal_type=sender.principal_type,
        sender_name=sender.name,
        recipient_org_id=recipient.org_id,
        recipient_principal_type=recipient.principal_type,
        recipient_name=recipient.name,
        subject=subject,
        body=body,
        delivery_state=DeliveryState.QUEUED.value,
        consent_id=decision.consent_id,
        enqueued_at=now,
        ttl_expires_at=now + timedelta(seconds=ttl_seconds),
        idempotency_key=idempotency_key,
    )

    if idempotency_key is None:
        db.add(UserInboxMessage(**values))
        await db.commit()
        return InboxDelivery(msg_id=msg_id, inserted=True, decision=decision)

    dialect_name = db.bind.dialect.name if db.bind else "sqlite"
    if dialect_name == "postgresql":
        stmt = pg_insert(UserInboxMessage).values(**values)
        stmt = stmt.on_conflict_do_nothing(constraint="uq_user_inbox_idempotency")
    else:
        stmt = sqlite_insert(UserInboxMessage).values(**values)
        stmt = stmt.on_conflict_do_nothing(
            index_elements=[
                "recipient_org_id", "recipient_principal_type",
                "recipient_name", "idempotency_key",
            ],
        )
    result = await db.execute(stmt)
    await db.commit()

    if result.rowcount > 0:
        return InboxDelivery(msg_id=msg_id, inserted=True, decision=decision)

    existing = (await db.execute(
        select(UserInboxMessage.msg_id).where(
            and_(
                UserInboxMessage.recipient_org_id == recipient.org_id,
                UserInboxMessage.recipient_principal_type == recipient.principal_type,
                UserInboxMessage.recipient_name == recipient.name,
                UserInboxMessage.idempotency_key == idempotency_key,
            )
        )
    )).scalar_one()
    return InboxDelivery(msg_id=existing, inserted=False, decision=decision)


# ── Fetch / list ────────────────────────────────────────────────────


async def fetch_for_recipient(
    db: AsyncSession,
    *,
    recipient: PrincipalRef,
    since_msg_id: str | None = None,
    limit: int = 50,
    include_archived: bool = False,
) -> list[UserInboxMessage]:
    """Return messages for a recipient, ordered by enqueued_at asc.

    Cursor pagination via ``since_msg_id``: caller passes the last
    msg_id received, server returns rows strictly after it. ``limit``
    is capped at 200 to keep the response bounded.
    """
    capped = min(max(1, limit), 200)
    where = [
        UserInboxMessage.recipient_org_id == recipient.org_id,
        UserInboxMessage.recipient_principal_type == recipient.principal_type,
        UserInboxMessage.recipient_name == recipient.name,
    ]
    if not include_archived:
        where.append(UserInboxMessage.delivery_state != DeliveryState.ARCHIVED.value)

    if since_msg_id is not None:
        cursor = (await db.execute(
            select(UserInboxMessage.enqueued_at).where(
                UserInboxMessage.msg_id == since_msg_id,
            )
        )).scalar_one_or_none()
        if cursor is not None:
            where.append(UserInboxMessage.enqueued_at > cursor)

    rows = (await db.execute(
        select(UserInboxMessage)
        .where(and_(*where))
        .order_by(UserInboxMessage.enqueued_at.asc())
        .limit(capped)
    )).scalars().all()
    return list(rows)


# ── State transitions ──────────────────────────────────────────────


async def mark_delivered(
    db: AsyncSession, *, msg_id: str, online: bool = False,
) -> bool:
    """Flip a queued row to delivered. Idempotent: re-acking is no-op."""
    target_state = (
        DeliveryState.DELIVERED_ONLINE.value if online
        else DeliveryState.DELIVERED_OFFLINE.value
    )
    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(UserInboxMessage)
        .where(
            UserInboxMessage.msg_id == msg_id,
            UserInboxMessage.delivery_state == DeliveryState.QUEUED.value,
        )
        .values(delivery_state=target_state, delivered_at=now)
    )
    await db.commit()
    return (result.rowcount or 0) > 0


async def mark_archived(db: AsyncSession, *, msg_id: str) -> bool:
    """Soft-hide a row (UI hint, no chain effect). Idempotent."""
    now = datetime.now(timezone.utc)
    result = await db.execute(
        update(UserInboxMessage)
        .where(UserInboxMessage.msg_id == msg_id)
        .where(UserInboxMessage.delivery_state != DeliveryState.ARCHIVED.value)
        .values(delivery_state=DeliveryState.ARCHIVED.value, archived_at=now)
    )
    await db.commit()
    return (result.rowcount or 0) > 0
