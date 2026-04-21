"""``mastio_keys`` — multi-key store for the Mastio ES256 identity.

Revision ID: 0018_mastio_keys
Revises: 0017_internal_agents_reach
Create Date: 2026-04-21 21:40:00.000000

ADR-012 Phase 2.0 — split the Mastio ES256 leaf key out of the single-row
``proxy_config`` convention and into a dedicated table that can hold
multiple historical keypairs. This is the foundation that makes key
rotation (Phase 2.1) and grace-period verification (Phase 2.2)
structurally possible without hacking around a single-row schema.

Invariant once populated:
    exactly one row has ``activated_at IS NOT NULL AND deprecated_at IS NULL``
    (the current signer used by ``LocalIssuer`` and the ADR-009
    counter-signature path).

Data migration
--------------
If ``proxy_config`` has ``mastio_leaf_key`` + ``mastio_leaf_cert`` (the
pre-2.0 storage), derive the ``kid`` from the leaf's public key (matching
the legacy ``LocalIssuer._compute_kid`` algorithm) and seed a single
active row. The old ``proxy_config`` rows are left in place during
Phase 2.0 so a rollback only needs to drop the new table; Phase 2.0
wire-up no longer reads them.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from cryptography import x509
from cryptography.hazmat.primitives import serialization


revision: str = "0018_mastio_keys"
down_revision: Union[str, Sequence[str], None] = "0017_internal_agents_reach"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing_tables = set(inspector.get_table_names())

    if "mastio_keys" not in existing_tables:
        op.create_table(
            "mastio_keys",
            sa.Column("kid", sa.Text(), primary_key=True),
            sa.Column("pubkey_pem", sa.Text(), nullable=False),
            sa.Column("privkey_pem", sa.Text(), nullable=False),
            sa.Column("cert_pem", sa.Text(), nullable=True),
            sa.Column("created_at", sa.Text(), nullable=False),
            sa.Column("activated_at", sa.Text(), nullable=True),
            sa.Column("deprecated_at", sa.Text(), nullable=True),
            sa.Column("expires_at", sa.Text(), nullable=True),
        )
        op.create_index(
            "idx_mastio_keys_active",
            "mastio_keys",
            ["activated_at", "deprecated_at"],
        )

    # Data migration — only if we find the legacy storage and the new
    # table is still empty. Idempotent across reruns.
    already = bind.execute(
        sa.text("SELECT COUNT(*) FROM mastio_keys")
    ).scalar()
    if already:
        return

    rows = bind.execute(
        sa.text(
            "SELECT key, value FROM proxy_config "
            "WHERE key IN ('mastio_leaf_key', 'mastio_leaf_cert')"
        )
    ).fetchall()
    config = {row[0]: row[1] for row in rows}

    leaf_key_pem = config.get("mastio_leaf_key")
    leaf_cert_pem = config.get("mastio_leaf_cert")
    if not leaf_key_pem or not leaf_cert_pem:
        # Proxy boots against a fresh DB or Mastio identity hasn't been
        # generated yet — ``ensure_mastio_identity`` will create the
        # first row through the regular insert path.
        return

    try:
        cert = x509.load_pem_x509_certificate(leaf_cert_pem.encode())
    except ValueError:
        # Corrupt stored cert — don't block the migration, let the boot
        # path regenerate identity from scratch.
        return

    pubkey_pem = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    kid = "mastio-" + hashlib.sha256(pubkey_pem.encode()).hexdigest()[:16]
    now = datetime.now(timezone.utc).isoformat()

    bind.execute(
        sa.text(
            "INSERT INTO mastio_keys "
            "(kid, pubkey_pem, privkey_pem, cert_pem, "
            " created_at, activated_at) "
            "VALUES (:kid, :pub, :priv, :cert, :now, :now)"
        ),
        {
            "kid": kid,
            "pub": pubkey_pem,
            "priv": leaf_key_pem,
            "cert": leaf_cert_pem,
            "now": now,
        },
    )


def downgrade() -> None:
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    if "mastio_keys" not in existing:
        return
    op.drop_index("idx_mastio_keys_active", table_name="mastio_keys")
    op.drop_table("mastio_keys")
