"""ADR-021 PR2 — user_principals table

Revision ID: o5j6k7l8m9n0
Revises: n4i5j6k7l8m9
Create Date: 2026-05-04 18:00:00.000000

Mapping table for user-principal provisioning. One row per
provisioned user, keyed by SPIFFE-style ``principal_id``
(``<td>/<org>/user/<name>``). UNIQUE on ``(org_id, sso_subject)``
so a single SSO subject cannot be silently re-provisioned under
two principal_ids.

Cert columns are nullable until the Ambassador finishes the CSR
roundtrip and calls ``attach_certificate``. ``revoked_at`` flips
the row to a tombstone state without deleting it (audit replay
needs the historical mapping).
"""
from alembic import op
import sqlalchemy as sa


revision = "o5j6k7l8m9n0"
down_revision = "n4i5j6k7l8m9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user_principals",
        sa.Column("principal_id", sa.String(length=255), primary_key=True),
        sa.Column("org_id", sa.String(length=128), nullable=False),
        sa.Column("sso_subject", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("cert_thumbprint", sa.String(length=64), nullable=True),
        sa.Column("cert_not_after", sa.DateTime(timezone=True), nullable=True),
        sa.Column("kms_backend", sa.String(length=32), nullable=False),
        sa.Column("kms_key_handle", sa.String(length=255), nullable=False),
        sa.Column("provisioned_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_active_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "org_id", "sso_subject", name="uq_user_principals_org_sso",
        ),
    )
    op.create_index(
        "idx_user_principals_lookup",
        "user_principals",
        ["org_id", "sso_subject"],
    )


def downgrade() -> None:
    op.drop_index("idx_user_principals_lookup", table_name="user_principals")
    op.drop_table("user_principals")
