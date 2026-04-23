"""``pending_updates`` — registry of migrations the boot detector flagged.

Revision ID: 0019_pending_updates
Revises: 0018_mastio_keys
Create Date: 2026-04-23 20:00:00.000000

Federation update framework (imp/federation_hardening_plan.md Parte 1)
PR 1 of 5 — registry foundation.

One row per (migration_id) that ``mcp_proxy.updates`` decided is applicable
to the current proxy state. The boot detector populates it; the dashboard
admin endpoint (PR 4) reads and mutates ``status`` on apply / rollback.

Invariants once populated:
    status ∈ {'pending', 'applied', 'failed', 'rolled_back'}
    applied_at IS NOT NULL ⇔ status ∈ {'applied', 'rolled_back'}
    error IS NOT NULL ⇒ status = 'failed'

Schema-only migration. Row writes land in PR 2 (boot detector).
Extra columns (backup_ref, dry_run_log, last_attempt_at) are deliberately
omitted here — they are added by the PR that introduces the caller that
needs them, per project convention for forward-only schema evolution.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "0019_pending_updates"
down_revision: Union[str, Sequence[str], None] = "0018_mastio_keys"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "pending_updates" in existing_tables:
        return

    op.create_table(
        "pending_updates",
        sa.Column("migration_id", sa.Text(), primary_key=True),
        sa.Column("detected_at", sa.Text(), nullable=False),
        sa.Column("status", sa.Text(), nullable=False),
        sa.Column("applied_at", sa.Text(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
    )
    op.create_index(
        "idx_pending_updates_status",
        "pending_updates",
        ["status"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    if "pending_updates" not in existing:
        return
    op.drop_index("idx_pending_updates_status", table_name="pending_updates")
    op.drop_table("pending_updates")
