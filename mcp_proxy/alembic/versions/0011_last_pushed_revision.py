"""ADR-010 Phase 3 — track last-pushed revision on internal_agents.

Revision ID: 0011_internal_agents_last_pushed_revision
Revises: 0010_internal_agents_federated
Create Date: 2026-04-17 19:30:00.000000

The Phase 3 publisher needs to know which mutation was last published
to the Court so a flap of ``federation_revision`` (bumped on every
patch/toggle in Phase 2) can be detected. Add ``last_pushed_revision``
INTEGER DEFAULT 0. On successful push the publisher writes
``last_pushed_revision = federation_revision``; the poll query filters
``federated = 1 AND federation_revision > last_pushed_revision`` so
idle rows are skipped.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0011_last_pushed_revision"
down_revision: Union[str, Sequence[str], None] = "0010_internal_agents_federated"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.add_column(
            sa.Column(
                "last_pushed_revision", sa.Integer(),
                nullable=False, server_default="0",
            ),
        )


def downgrade() -> None:
    with op.batch_alter_table("internal_agents") as batch_op:
        batch_op.drop_column("last_pushed_revision")
