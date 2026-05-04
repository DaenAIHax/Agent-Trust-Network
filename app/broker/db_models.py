"""
SQLAlchemy models for session, message, and RFQ persistence.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Column, String, Text, DateTime, Integer, LargeBinary,
    SmallInteger, UniqueConstraint, Index,
)

from app.db.database import Base


class SessionRecord(Base):
    __tablename__ = "sessions"

    session_id          = Column(String(128), primary_key=True)
    initiator_agent_id  = Column(String(128), nullable=False)
    initiator_org_id    = Column(String(128), nullable=False)
    target_agent_id     = Column(String(128), nullable=False)
    target_org_id       = Column(String(128), nullable=False)
    status              = Column(String(16),  nullable=False, index=True)
    requested_capabilities = Column(Text, nullable=False)   # JSON list
    created_at          = Column(DateTime(timezone=True), nullable=False)
    expires_at          = Column(DateTime(timezone=True), nullable=True)
    closed_at           = Column(DateTime(timezone=True), nullable=True)
    last_activity_at    = Column(DateTime(timezone=True), nullable=True)
    close_reason        = Column(String(32),  nullable=True)


class SessionMessageRecord(Base):
    __tablename__ = "session_messages"
    __table_args__ = (
        UniqueConstraint("session_id", "seq", name="uq_session_seq"),
    )

    id              = Column(Integer, primary_key=True, autoincrement=True)
    session_id      = Column(String(128), nullable=False, index=True)
    seq             = Column(Integer, nullable=False)
    sender_agent_id = Column(String(128), nullable=False)
    payload         = Column(Text, nullable=False)          # JSON dict
    nonce           = Column(String(128), nullable=False, unique=True)
    timestamp       = Column(DateTime(timezone=True), nullable=False,
                             default=lambda: datetime.now(timezone.utc))
    signature       = Column(Text, nullable=True)   # base64 RSA-PKCS1v15-SHA256
    client_seq      = Column(Integer, nullable=True)


class ProxyMessageQueueRecord(Base):
    """M3 message durability — queued messages awaiting recipient ack.

    Schema validated in the M0.3 spike (imp/m0_storage_spike.md):
    ~53k enqueue/s single writer, <1ms p99 dequeue, 1M TTL sweep in ~5s.

    A row is enqueued when a message arrives and cannot be confirmed
    delivered (recipient offline, WS send failed, etc.). It is dequeued
    on explicit ack, or swept when ttl_expires_at passes. Metadata-only
    audit survives in session_messages — this table holds the ciphertext
    and is pruned aggressively.

    ``delivery_status`` values:
      0 = pending   — enqueued, awaiting delivery/ack
      1 = delivered — recipient ack'd, row eligible for pruning
      2 = expired   — TTL passed before ack, sender notified
    """

    __tablename__ = "proxy_message_queue"
    __table_args__ = (
        UniqueConstraint(
            "recipient_agent_id", "idempotency_key",
            name="uq_proxy_queue_idempotency",
        ),
        Index(
            "idx_proxy_queue_recipient_pending",
            "recipient_agent_id", "seq",
        ),
        Index(
            "idx_proxy_queue_ttl",
            "ttl_expires_at",
        ),
    )

    msg_id              = Column(String(64), primary_key=True)
    session_id          = Column(String(128), nullable=False, index=True)
    recipient_agent_id  = Column(String(256), nullable=False)
    sender_agent_id     = Column(String(256), nullable=False)
    ciphertext          = Column(LargeBinary, nullable=False)
    seq                 = Column(Integer, nullable=False)
    enqueued_at         = Column(DateTime(timezone=True), nullable=False,
                                 default=lambda: datetime.now(timezone.utc))
    ttl_expires_at      = Column(DateTime(timezone=True), nullable=False)
    delivery_status     = Column(SmallInteger, nullable=False, default=0, index=True)
    attempts            = Column(SmallInteger, nullable=False, default=0)
    idempotency_key     = Column(String(256), nullable=True)
    delivered_at        = Column(DateTime(timezone=True), nullable=True)
    expired_at          = Column(DateTime(timezone=True), nullable=True)


class BrokerOneShotMessageRecord(Base):
    """ADR-008 Phase 1 PR #2 — cross-org sessionless one-shot queue.

    A sender proxy forwards a one-shot envelope via
    ``POST /broker/oneshot/forward``; the row stays here until the
    recipient's proxy pulls it through ``GET /broker/oneshot/inbox``
    and acks delivery via ``POST /broker/oneshot/{msg_id}/ack``.

    ``delivery_status`` values mirror ``ProxyMessageQueueRecord``:
      0 = pending   — enqueued, recipient has not yet ack'd
      1 = delivered — recipient proxy ack'd, eligible for pruning
      2 = expired   — TTL passed before ack (sweeper-driven)

    Dedup is scoped ``(sender_agent_id, correlation_id)`` so a sender
    retry collapses without the recipient ever observing a duplicate.
    """

    __tablename__ = "broker_oneshot_messages"
    __table_args__ = (
        UniqueConstraint(
            "sender_agent_id", "correlation_id",
            name="uq_oneshot_sender_corr",
        ),
        UniqueConstraint("nonce", name="uq_oneshot_nonce"),
        Index(
            "ix_oneshot_recipient_pending",
            "recipient_agent_id", "delivery_status",
        ),
        Index("ix_oneshot_ttl", "ttl_expires_at"),
    )

    msg_id                   = Column(String(64), primary_key=True)
    correlation_id           = Column(String(128), nullable=False)
    reply_to_correlation_id  = Column(String(128), nullable=True)
    sender_agent_id          = Column(String(256), nullable=False)
    sender_org_id            = Column(String(128), nullable=False)
    recipient_agent_id       = Column(String(256), nullable=False)
    recipient_org_id         = Column(String(128), nullable=False)
    envelope_json            = Column(Text, nullable=False)
    nonce                    = Column(String(128), nullable=False)
    enqueued_at              = Column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    ttl_expires_at           = Column(DateTime(timezone=True), nullable=False)
    delivery_status          = Column(
        SmallInteger, nullable=False, default=0,
    )
    delivered_at             = Column(DateTime(timezone=True), nullable=True)


class RfqRecord(Base):
    __tablename__ = "rfq_requests"

    rfq_id              = Column(String(128), primary_key=True)
    initiator_agent_id  = Column(String(256), nullable=False, index=True)
    initiator_org_id    = Column(String(128), nullable=False, index=True)
    capability_filter   = Column(Text, nullable=False)              # JSON list
    payload_json        = Column(Text, nullable=False)              # The RFQ payload
    status              = Column(String(16), nullable=False, index=True)  # open | closed | timeout
    timeout_seconds     = Column(Integer, nullable=False, default=30)
    matched_agents_json = Column(Text, nullable=False, default="[]")  # JSON list of agent_ids
    created_at          = Column(DateTime(timezone=True), nullable=False)
    closed_at           = Column(DateTime(timezone=True), nullable=True)


class RfqResponseRecord(Base):
    __tablename__ = "rfq_responses"
    __table_args__ = (
        UniqueConstraint("rfq_id", "responder_agent_id", name="uq_rfq_responder"),
    )

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    rfq_id              = Column(String(128), nullable=False, index=True)
    responder_agent_id  = Column(String(256), nullable=False)
    responder_org_id    = Column(String(128), nullable=False)
    response_payload    = Column(Text, nullable=False)              # JSON
    received_at         = Column(DateTime(timezone=True), nullable=False)


class UserInboxMessage(Base):
    """ADR-020 Phase 4 — durable user inbox.

    Holds messages addressed to a *user* (or, transitively, to any
    principal that wants Slack-like inbox semantics). Distinct from
    ``ProxyMessageQueueRecord`` which is bound to live A2A sessions:

      - no ``session_id`` — inbox messages are stand-alone, not part
        of a multi-turn session
      - plaintext ``body`` for v0.1 (E2E encryption is a Phase 5
        candidate; the cloud edge is the trust boundary today)
      - ``delivery_state`` distinguishes online (WS push at the moment
        of write) from offline (recipient absent, drained by a later
        ``GET /v1/inbox``) — a property the legacy queue does not need

    Reach policy (``app/policy/reach.py``) is consulted at enqueue time;
    a row only lands here when ``evaluate_reach_quadrant`` returns
    allow. The ``consent_id`` links to the grant that authorised the
    delivery, so an audit trail can prove not just "the message was
    accepted" but "the message was accepted under THIS consent".
    """

    __tablename__ = "user_inbox_messages"
    __table_args__ = (
        UniqueConstraint(
            "recipient_org_id", "recipient_principal_type", "recipient_name",
            "idempotency_key",
            name="uq_user_inbox_idempotency",
        ),
        Index(
            "idx_user_inbox_recipient_pending",
            "recipient_org_id", "recipient_principal_type", "recipient_name",
            "delivery_state",
        ),
        Index("idx_user_inbox_ttl", "ttl_expires_at"),
    )

    msg_id               = Column(String(64), primary_key=True)

    # Sender identification (full principal triple).
    sender_org_id            = Column(String(128), nullable=False, index=True)
    sender_principal_type    = Column(String(16), nullable=False)
    sender_name              = Column(String(128), nullable=False)

    # Recipient identification (full principal triple).
    recipient_org_id         = Column(String(128), nullable=False, index=True)
    recipient_principal_type = Column(String(16), nullable=False)
    recipient_name           = Column(String(128), nullable=False)

    # Payload. v0.1 stores plaintext; E2E encryption candidate for v0.5.
    subject              = Column(String(256), nullable=True)
    body                 = Column(Text, nullable=False)

    # Delivery lifecycle: queued | delivered_offline | delivered_online |
    # archived | expired.
    delivery_state       = Column(
        String(24), nullable=False, default="queued", index=True,
    )

    # Reach grant that authorised this delivery. ``None`` for cells whose
    # default is allow (intra-org A2A, intra-org U2U, ownership U2A).
    consent_id           = Column(String(64), nullable=True)

    # Lifecycle timestamps.
    enqueued_at          = Column(DateTime(timezone=True), nullable=False,
                                  default=lambda: datetime.now(timezone.utc))
    delivered_at         = Column(DateTime(timezone=True), nullable=True)
    archived_at          = Column(DateTime(timezone=True), nullable=True)
    expired_at           = Column(DateTime(timezone=True), nullable=True)
    ttl_expires_at       = Column(DateTime(timezone=True), nullable=False)

    # Idempotency under retries from a flapping sender.
    idempotency_key      = Column(String(256), nullable=True)
