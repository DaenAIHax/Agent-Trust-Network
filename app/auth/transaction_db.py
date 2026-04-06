"""
SQLAlchemy model for transaction tokens — single-use, short-lived tokens
that authorize a specific operation (e.g., CREATE_ORDER) after human approval.
"""
from sqlalchemy import Column, String, DateTime

from app.db.database import Base


class TransactionTokenRecord(Base):
    __tablename__ = "transaction_tokens"

    jti             = Column(String(128), primary_key=True)
    txn_type        = Column(String(64), nullable=False)           # e.g. CREATE_ORDER
    agent_id        = Column(String(256), nullable=False, index=True)
    org_id          = Column(String(128), nullable=False)
    resource_id     = Column(String(256), nullable=True)           # e.g. rfq_id, order_id
    payload_hash    = Column(String(64), nullable=False)           # SHA-256 of authorized payload
    approved_by     = Column(String(256), nullable=False)          # human identifier
    parent_jti      = Column(String(128), nullable=True)           # links to originating access token
    rfq_id          = Column(String(128), nullable=True, index=True)
    target_agent_id = Column(String(256), nullable=True)
    status          = Column(String(16), nullable=False, default="active")  # active | consumed | expired
    created_at      = Column(DateTime(timezone=True), nullable=False)
    consumed_at     = Column(DateTime(timezone=True), nullable=True)
    expires_at      = Column(DateTime(timezone=True), nullable=False)
