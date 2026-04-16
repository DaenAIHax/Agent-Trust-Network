"""Schema parity local_*↔broker — ADR-006 Fase 0.

Revision ID: 0005_schema_parity_with_broker
Revises: 0004_add_federation_cache
Create Date: 2026-04-16

Brings the local_* tables in line with the broker equivalents so the proxy
can operate as a standalone mini-broker (ADR-006 Fase 1) while remaining
byte-compatible with the broker for future export / audit merge.

Divergences closed here (see imp/adr_006_proxy_troian_horse_dual_mode.md §A):

  local_agents   : + org_id, cert_thumbprint, metadata_json
  local_sessions : rename responder→target, + initiator_org_id,
                   target_org_id, requested_capabilities, expires_at,
                   closed_at
  local_messages : + seq, nonce (unique), signature, attempts,
                   expired_at; rename status→delivery_status (integer
                   enum 0/1/2 matching ProxyMessageQueueRecord)
  local_policies : + org_id, policy_type
  local_audit    : rename action→event_type, actor_agent_id→agent_id,
                   detail_json→details, prev_hash→previous_hash,
                   row_hash→entry_hash; + session_id, org_id, result,
                   chain_seq, peer_org_id, peer_row_hash

The hash-chain ``compute_entry_hash`` helper lives in
``mcp_proxy/local/audit_chain.py``; its canonical form matches
``app/db/audit.py:compute_entry_hash`` byte-for-byte so rows are portable.

Live proxies have no production data in local_* (enforced in 0002 comment:
"Phase 1 only deploys the schema — no application code reads from or writes
to these tables yet"). The migration uses ``batch_alter_table`` for SQLite
compatibility.
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0005_schema_parity_with_broker"
down_revision: Union[str, Sequence[str], None] = "0004_add_federation_cache"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── local_agents ────────────────────────────────────────────────────────
    with op.batch_alter_table("local_agents") as batch_op:
        batch_op.add_column(sa.Column("org_id", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("cert_thumbprint", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("metadata_json", sa.Text(), nullable=False, server_default="{}")
        )
    op.create_index("idx_local_agents_org", "local_agents", ["org_id"])
    op.create_index(
        "idx_local_agents_thumbprint", "local_agents", ["cert_thumbprint"]
    )

    # ── local_sessions ──────────────────────────────────────────────────────
    # Existing index references the old column name; drop it before rename.
    op.drop_index("idx_local_sessions_responder", table_name="local_sessions")
    with op.batch_alter_table("local_sessions") as batch_op:
        batch_op.alter_column(
            "responder_agent_id",
            new_column_name="target_agent_id",
            existing_type=sa.Text(),
            existing_nullable=False,
        )
        batch_op.add_column(sa.Column("initiator_org_id", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("target_org_id", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column(
                "requested_capabilities",
                sa.Text(),
                nullable=False,
                server_default="[]",
            )
        )
        batch_op.add_column(sa.Column("expires_at", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("closed_at", sa.Text(), nullable=True))
    op.create_index("idx_local_sessions_target", "local_sessions", ["target_agent_id"])
    op.create_index(
        "idx_local_sessions_initiator_org", "local_sessions", ["initiator_org_id"]
    )
    op.create_index(
        "idx_local_sessions_target_org", "local_sessions", ["target_org_id"]
    )

    # ── local_messages ──────────────────────────────────────────────────────
    # Rename legacy ``status`` (text: queued|delivered|expired) to
    # ``delivery_status`` with integer enum semantics matching the broker's
    # ProxyMessageQueueRecord (0=pending, 1=delivered, 2=expired).
    op.drop_index(
        "idx_local_messages_recipient_status", table_name="local_messages"
    )
    with op.batch_alter_table("local_messages") as batch_op:
        batch_op.alter_column(
            "status",
            new_column_name="delivery_status",
            existing_type=sa.Text(),
            type_=sa.SmallInteger(),
            existing_nullable=False,
            postgresql_using="CASE status "
            "WHEN 'delivered' THEN 1 "
            "WHEN 'expired' THEN 2 "
            "ELSE 0 END",
            server_default="0",
        )
        batch_op.add_column(sa.Column("seq", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("nonce", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("signature", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("attempts", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(sa.Column("expired_at", sa.Text(), nullable=True))
        batch_op.create_unique_constraint(
            "uq_local_messages_session_seq", ["session_id", "seq"]
        )
        batch_op.create_unique_constraint("uq_local_messages_nonce", ["nonce"])
    op.create_index(
        "idx_local_messages_recipient_delivery_status",
        "local_messages",
        ["recipient_agent_id", "delivery_status"],
    )

    # ── local_policies ──────────────────────────────────────────────────────
    with op.batch_alter_table("local_policies") as batch_op:
        batch_op.add_column(sa.Column("org_id", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("policy_type", sa.Text(), nullable=True))
    op.create_index("idx_local_policies_org", "local_policies", ["org_id"])
    op.create_index(
        "idx_local_policies_type", "local_policies", ["policy_type"]
    )

    # ── local_audit ─────────────────────────────────────────────────────────
    # Align column names with broker app/db/audit.py::AuditLog so that
    # compute_entry_hash (canonical form) is byte-compatible.
    op.drop_index("idx_local_audit_actor", table_name="local_audit")
    with op.batch_alter_table("local_audit") as batch_op:
        batch_op.alter_column(
            "action",
            new_column_name="event_type",
            existing_type=sa.Text(),
            existing_nullable=False,
        )
        batch_op.alter_column(
            "actor_agent_id",
            new_column_name="agent_id",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "detail_json",
            new_column_name="details",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "prev_hash",
            new_column_name="previous_hash",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "row_hash",
            new_column_name="entry_hash",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
        batch_op.drop_column("subject")
        batch_op.add_column(sa.Column("session_id", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("org_id", sa.Text(), nullable=True))
        batch_op.add_column(
            sa.Column("result", sa.Text(), nullable=False, server_default="ok")
        )
        batch_op.add_column(sa.Column("chain_seq", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("peer_org_id", sa.Text(), nullable=True))
        batch_op.add_column(sa.Column("peer_row_hash", sa.Text(), nullable=True))
    op.create_index("idx_local_audit_event_type", "local_audit", ["event_type"])
    op.create_index("idx_local_audit_agent", "local_audit", ["agent_id"])
    op.create_index("idx_local_audit_session", "local_audit", ["session_id"])
    op.create_index("idx_local_audit_org", "local_audit", ["org_id"])
    op.create_index("idx_local_audit_peer_org", "local_audit", ["peer_org_id"])


def downgrade() -> None:
    # ── local_audit ─────────────────────────────────────────────────────────
    op.drop_index("idx_local_audit_peer_org", table_name="local_audit")
    op.drop_index("idx_local_audit_org", table_name="local_audit")
    op.drop_index("idx_local_audit_session", table_name="local_audit")
    op.drop_index("idx_local_audit_agent", table_name="local_audit")
    op.drop_index("idx_local_audit_event_type", table_name="local_audit")
    with op.batch_alter_table("local_audit") as batch_op:
        batch_op.drop_column("peer_row_hash")
        batch_op.drop_column("peer_org_id")
        batch_op.drop_column("chain_seq")
        batch_op.drop_column("result")
        batch_op.drop_column("org_id")
        batch_op.drop_column("session_id")
        batch_op.add_column(sa.Column("subject", sa.Text(), nullable=True))
        batch_op.alter_column(
            "entry_hash",
            new_column_name="row_hash",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "previous_hash",
            new_column_name="prev_hash",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "details",
            new_column_name="detail_json",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "agent_id",
            new_column_name="actor_agent_id",
            existing_type=sa.Text(),
            existing_nullable=True,
        )
        batch_op.alter_column(
            "event_type",
            new_column_name="action",
            existing_type=sa.Text(),
            existing_nullable=False,
        )
    op.create_index("idx_local_audit_actor", "local_audit", ["actor_agent_id"])

    # ── local_policies ──────────────────────────────────────────────────────
    op.drop_index("idx_local_policies_type", table_name="local_policies")
    op.drop_index("idx_local_policies_org", table_name="local_policies")
    with op.batch_alter_table("local_policies") as batch_op:
        batch_op.drop_column("policy_type")
        batch_op.drop_column("org_id")

    # ── local_messages ──────────────────────────────────────────────────────
    op.drop_index(
        "idx_local_messages_recipient_delivery_status", table_name="local_messages"
    )
    with op.batch_alter_table("local_messages") as batch_op:
        batch_op.drop_constraint("uq_local_messages_nonce", type_="unique")
        batch_op.drop_constraint("uq_local_messages_session_seq", type_="unique")
        batch_op.drop_column("expired_at")
        batch_op.drop_column("attempts")
        batch_op.drop_column("signature")
        batch_op.drop_column("nonce")
        batch_op.drop_column("seq")
        batch_op.alter_column(
            "delivery_status",
            new_column_name="status",
            existing_type=sa.SmallInteger(),
            type_=sa.Text(),
            existing_nullable=False,
            postgresql_using="CASE delivery_status "
            "WHEN 1 THEN 'delivered' "
            "WHEN 2 THEN 'expired' "
            "ELSE 'queued' END",
            server_default=None,
        )
    op.create_index(
        "idx_local_messages_recipient_status",
        "local_messages",
        ["recipient_agent_id", "status"],
    )

    # ── local_sessions ──────────────────────────────────────────────────────
    op.drop_index("idx_local_sessions_target_org", table_name="local_sessions")
    op.drop_index("idx_local_sessions_initiator_org", table_name="local_sessions")
    op.drop_index("idx_local_sessions_target", table_name="local_sessions")
    with op.batch_alter_table("local_sessions") as batch_op:
        batch_op.drop_column("closed_at")
        batch_op.drop_column("expires_at")
        batch_op.drop_column("requested_capabilities")
        batch_op.drop_column("target_org_id")
        batch_op.drop_column("initiator_org_id")
        batch_op.alter_column(
            "target_agent_id",
            new_column_name="responder_agent_id",
            existing_type=sa.Text(),
            existing_nullable=False,
        )
    op.create_index(
        "idx_local_sessions_responder", "local_sessions", ["responder_agent_id"]
    )

    # ── local_agents ────────────────────────────────────────────────────────
    op.drop_index("idx_local_agents_thumbprint", table_name="local_agents")
    op.drop_index("idx_local_agents_org", table_name="local_agents")
    with op.batch_alter_table("local_agents") as batch_op:
        batch_op.drop_column("metadata_json")
        batch_op.drop_column("cert_thumbprint")
        batch_op.drop_column("org_id")
