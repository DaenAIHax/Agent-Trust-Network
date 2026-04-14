"""Add pending_enrollments table — Connector Phase 2 (#64).

Revision ID: 0003_add_pending_enrollments
Revises: 0002_local_tables
Create Date: 2026-04-14

Tracks Cullis Connector enrollment requests between the moment a user-side
Connector starts the device-code flow and the admin's approve/reject decision
in the dashboard. Stores the client-supplied public key (private key never
leaves the requester's machine), the requester's self-declared identity,
and — once approved — the admin-assigned agent_id, capabilities, groups,
and the resulting Org-CA-signed certificate.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003_add_pending_enrollments"
down_revision: Union[str, Sequence[str], None] = "0002_local_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "pending_enrollments",
        sa.Column("session_id", sa.Text(), primary_key=True, nullable=False),
        sa.Column("pubkey_pem", sa.Text(), nullable=False),
        sa.Column("pubkey_fingerprint", sa.Text(), nullable=False),
        sa.Column("requester_name", sa.Text(), nullable=False),
        sa.Column("requester_email", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("device_info", sa.Text(), nullable=True),
        sa.Column("status", sa.Text(), nullable=False, server_default="pending"),
        sa.Column("created_at", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.Text(), nullable=False),
        sa.Column("decided_at", sa.Text(), nullable=True),
        sa.Column("decided_by", sa.Text(), nullable=True),
        sa.Column("agent_id_assigned", sa.Text(), nullable=True),
        sa.Column(
            "capabilities_assigned", sa.Text(), nullable=True, server_default="[]"
        ),
        sa.Column("groups_assigned", sa.Text(), nullable=True, server_default="[]"),
        sa.Column("cert_pem", sa.Text(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_pending_enrollments_status", "pending_enrollments", ["status"]
    )
    op.create_index(
        "idx_pending_enrollments_created_at", "pending_enrollments", ["created_at"]
    )
    op.create_index(
        "idx_pending_enrollments_fingerprint",
        "pending_enrollments",
        ["pubkey_fingerprint"],
    )


def downgrade() -> None:
    op.drop_index(
        "idx_pending_enrollments_fingerprint", table_name="pending_enrollments"
    )
    op.drop_index(
        "idx_pending_enrollments_created_at", table_name="pending_enrollments"
    )
    op.drop_index("idx_pending_enrollments_status", table_name="pending_enrollments")
    op.drop_table("pending_enrollments")
