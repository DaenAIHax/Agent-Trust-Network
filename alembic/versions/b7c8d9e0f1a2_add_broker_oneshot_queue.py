"""add broker one-shot queue (ADR-008 Phase 1 / PR #2)

Revision ID: b7c8d9e0f1a2
Revises: f6a7b8c9d0e1
Create Date: 2026-04-16 20:00:00.000000

Introduces the broker-side durable queue for cross-org sessionless
one-shot messaging. A sender proxy forwards a one-shot envelope to
``POST /broker/oneshot/forward``; the broker inserts a row here and
holds it until the recipient proxy drains it via
``GET /broker/oneshot/inbox`` + ``POST /broker/oneshot/{id}/ack``.

Dedup is scoped to ``(sender_agent_id, correlation_id)`` so sender-side
retries collapse without the recipient ever seeing a duplicate. The
``nonce`` column is also globally unique as a defence-in-depth guard
against signature replay across correlation ids.

Rows are TTL-expired by ``app/broker/session_sweeper.py`` (flip
``delivery_status`` 0 → 2) and pruned by a future retention job.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
# This migration also merges two pre-existing heads:
#   - f6a7b8c9d0e1 (audit chain per-org, linea principale)
#   - a1b2c3d4e5f7 (org trust_domain)
# both were independently in main before this PR.
revision: str = "b7c8d9e0f1a2"
down_revision: Union[str, Sequence[str], None] = (
    "f6a7b8c9d0e1",
    "a1b2c3d4e5f7",
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "broker_oneshot_messages",
        sa.Column("msg_id", sa.String(length=64), primary_key=True),
        sa.Column("correlation_id", sa.String(length=128), nullable=False),
        sa.Column(
            "reply_to_correlation_id", sa.String(length=128), nullable=True,
        ),
        sa.Column("sender_agent_id", sa.String(length=256), nullable=False),
        sa.Column("sender_org_id", sa.String(length=128), nullable=False),
        sa.Column("recipient_agent_id", sa.String(length=256), nullable=False),
        sa.Column("recipient_org_id", sa.String(length=128), nullable=False),
        sa.Column("envelope_json", sa.Text(), nullable=False),
        sa.Column("nonce", sa.String(length=128), nullable=False),
        sa.Column(
            "enqueued_at", sa.DateTime(timezone=True), nullable=False,
        ),
        sa.Column(
            "ttl_expires_at", sa.DateTime(timezone=True), nullable=False,
        ),
        sa.Column(
            "delivery_status",
            sa.SmallInteger(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "delivered_at", sa.DateTime(timezone=True), nullable=True,
        ),
        sa.UniqueConstraint(
            "sender_agent_id", "correlation_id",
            name="uq_oneshot_sender_corr",
        ),
        sa.UniqueConstraint("nonce", name="uq_oneshot_nonce"),
    )
    op.create_index(
        "ix_oneshot_recipient_pending", "broker_oneshot_messages",
        ["recipient_agent_id", "delivery_status"], unique=False,
    )
    op.create_index(
        "ix_oneshot_ttl", "broker_oneshot_messages",
        ["ttl_expires_at"], unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_oneshot_ttl", table_name="broker_oneshot_messages")
    op.drop_index(
        "ix_oneshot_recipient_pending", table_name="broker_oneshot_messages",
    )
    op.drop_table("broker_oneshot_messages")
