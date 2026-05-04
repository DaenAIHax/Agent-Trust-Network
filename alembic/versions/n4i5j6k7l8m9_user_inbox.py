"""ADR-020 Phase 4 — user_inbox_messages table

Revision ID: n4i5j6k7l8m9
Revises: m3h4i5j6k7l8
Create Date: 2026-05-04 16:00:00.000000

Adds the user_inbox_messages table that backs the ``/v1/inbox`` REST
+ WebSocket endpoints. Distinct from ``proxy_message_queue`` which
is session-bound A2A; this table is for stand-alone inbox-style
deliveries (A2U, U2U, U2A) and stores plaintext body for v0.1.

The table is created from scratch by this migration; downgrade
drops it. No data migration is required because no caller writes
to it before this migration.
"""
from alembic import op
import sqlalchemy as sa


revision = "n4i5j6k7l8m9"
down_revision = "m3h4i5j6k7l8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_inbox_messages",
        sa.Column("msg_id", sa.String(length=64), primary_key=True),
        sa.Column("sender_org_id", sa.String(length=128), nullable=False),
        sa.Column("sender_principal_type", sa.String(length=16), nullable=False),
        sa.Column("sender_name", sa.String(length=128), nullable=False),
        sa.Column("recipient_org_id", sa.String(length=128), nullable=False),
        sa.Column("recipient_principal_type", sa.String(length=16), nullable=False),
        sa.Column("recipient_name", sa.String(length=128), nullable=False),
        sa.Column("subject", sa.String(length=256), nullable=True),
        sa.Column("body", sa.Text(), nullable=False),
        sa.Column(
            "delivery_state", sa.String(length=24),
            nullable=False, server_default=sa.text("'queued'"),
        ),
        sa.Column("consent_id", sa.String(length=64), nullable=True),
        sa.Column("enqueued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("archived_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ttl_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=256), nullable=True),
        sa.UniqueConstraint(
            "recipient_org_id", "recipient_principal_type", "recipient_name",
            "idempotency_key",
            name="uq_user_inbox_idempotency",
        ),
    )
    op.create_index(
        "idx_user_inbox_recipient_pending",
        "user_inbox_messages",
        ["recipient_org_id", "recipient_principal_type", "recipient_name", "delivery_state"],
    )
    op.create_index(
        "idx_user_inbox_ttl",
        "user_inbox_messages",
        ["ttl_expires_at"],
    )


def downgrade() -> None:
    op.drop_index("idx_user_inbox_ttl", table_name="user_inbox_messages")
    op.drop_index("idx_user_inbox_recipient_pending", table_name="user_inbox_messages")
    op.drop_table("user_inbox_messages")
