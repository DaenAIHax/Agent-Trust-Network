"""
MCP Proxy database — lightweight async SQLite via aiosqlite.

Tables:
  - internal_agents: locally registered agents (for egress API key auth)
  - audit_log: append-only immutable audit trail
  - proxy_config: key-value store for broker uplink config from setup wizard

Design choices:
  - aiosqlite directly (no SQLAlchemy) — minimal footprint for a sidecar proxy
  - audit_log is append-only: no UPDATE or DELETE operations exposed
  - WAL mode enabled for concurrent readers
"""
import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite

_log = logging.getLogger("mcp_proxy")

# Module-level connection path — set by init_db()
_db_path: str = ""


# ─────────────────────────────────────────────────────────────────────────────
# Schema
# ─────────────────────────────────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS internal_agents (
    agent_id       TEXT PRIMARY KEY,
    display_name   TEXT NOT NULL,
    capabilities   TEXT NOT NULL DEFAULT '[]',  -- JSON array
    api_key_hash   TEXT NOT NULL,
    cert_pem       TEXT,
    created_at     TEXT NOT NULL,
    is_active      INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    agent_id       TEXT NOT NULL,
    action         TEXT NOT NULL,
    tool_name      TEXT,
    status         TEXT NOT NULL,
    detail         TEXT,
    request_id     TEXT,
    duration_ms    REAL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_agent_id ON audit_log(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_request_id ON audit_log(request_id);

CREATE TABLE IF NOT EXISTS proxy_config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


# ─────────────────────────────────────────────────────────────────────────────
# Initialization
# ─────────────────────────────────────────────────────────────────────────────

async def init_db(db_path: str) -> None:
    """Create tables if they don't exist. Enable WAL mode."""
    global _db_path
    # Strip SQLAlchemy prefix if present
    clean_path = db_path
    for prefix in ("sqlite+aiosqlite:///", "sqlite:///"):
        if clean_path.startswith(prefix):
            clean_path = clean_path[len(prefix):]
            break

    _db_path = clean_path

    # Ensure parent directory exists
    parent = Path(_db_path).parent
    if str(parent) != ".":
        parent.mkdir(parents=True, exist_ok=True)

    async with aiosqlite.connect(_db_path) as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.executescript(_SCHEMA_SQL)
        await db.commit()

    _log.info("Database initialized: %s", _db_path)


def get_db() -> aiosqlite.Connection:
    """Return a fresh aiosqlite connection handle (NOT yet opened).

    Callers MUST use ``async with``::

        async with get_db() as db:
            db.row_factory = aiosqlite.Row
            await db.execute(...)

    Do NOT ``await get_db()`` — the context manager handles startup.
    """
    if not _db_path:
        raise RuntimeError("Database not initialized — call init_db() first")
    return aiosqlite.connect(_db_path)


# ─────────────────────────────────────────────────────────────────────────────
# Audit log — APPEND-ONLY (no update, no delete)
# ─────────────────────────────────────────────────────────────────────────────

async def log_audit(
    agent_id: str,
    action: str,
    status: str,
    *,
    tool_name: str | None = None,
    detail: str | None = None,
    request_id: str | None = None,
    duration_ms: float | None = None,
) -> None:
    """Insert an immutable audit log entry."""
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        await db.execute(
            """INSERT INTO audit_log (timestamp, agent_id, action, tool_name, status, detail, request_id, duration_ms)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (ts, agent_id, action, tool_name, status, detail, request_id, duration_ms),
        )
        await db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Internal agents
# ─────────────────────────────────────────────────────────────────────────────

async def create_agent(
    agent_id: str,
    display_name: str,
    capabilities: list[str],
    api_key_hash: str,
    cert_pem: str | None = None,
) -> None:
    """Register a new internal agent."""
    ts = datetime.now(timezone.utc).isoformat()
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        await db.execute(
            """INSERT INTO internal_agents (agent_id, display_name, capabilities, api_key_hash, cert_pem, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (agent_id, display_name, json.dumps(capabilities), api_key_hash, cert_pem, ts),
        )
        await db.commit()


async def get_agent(agent_id: str) -> dict | None:
    """Fetch a single agent by ID."""
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM internal_agents WHERE agent_id = ?", (agent_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return _agent_row_to_dict(row)


async def get_agent_by_key_hash(raw_api_key: str) -> dict | None:
    """Look up an active agent by verifying a raw API key against stored bcrypt hashes.

    Since bcrypt hashes are non-deterministic (salted), we cannot do a direct
    SQL lookup. Instead we fetch all active agents and verify against each hash.
    For efficiency with many agents, consider a prefix index approach.
    This is acceptable for the expected scale (tens to low hundreds of agents).
    """
    import bcrypt

    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM internal_agents WHERE is_active = 1"
        )
        rows = await cursor.fetchall()
        for row in rows:
            stored_hash = row["api_key_hash"]
            # bcrypt.checkpw expects bytes
            if bcrypt.checkpw(raw_api_key.encode(), stored_hash.encode()):
                return _agent_row_to_dict(row)
    return None


async def list_agents() -> list[dict]:
    """List all internal agents."""
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT * FROM internal_agents ORDER BY created_at DESC"
        )
        rows = await cursor.fetchall()
        return [_agent_row_to_dict(row) for row in rows]


async def deactivate_agent(agent_id: str) -> bool:
    """Soft-delete an agent by setting is_active = 0. Returns True if found."""
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "UPDATE internal_agents SET is_active = 0 WHERE agent_id = ?",
            (agent_id,),
        )
        await db.commit()
        return cursor.rowcount > 0


# ─────────────────────────────────────────────────────────────────────────────
# Proxy config (key-value)
# ─────────────────────────────────────────────────────────────────────────────

async def get_config(key: str) -> str | None:
    """Get a config value by key."""
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT value FROM proxy_config WHERE key = ?", (key,)
        )
        row = await cursor.fetchone()
        return row["value"] if row else None


async def set_config(key: str, value: str) -> None:
    """Set a config value (upsert)."""
    async with get_db() as db:
        db.row_factory = aiosqlite.Row
        await db.execute(
            """INSERT INTO proxy_config (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
            (key, value),
        )
        await db.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _agent_row_to_dict(row: aiosqlite.Row) -> dict:
    """Convert an aiosqlite Row to a plain dict with parsed capabilities."""
    return {
        "agent_id": row["agent_id"],
        "display_name": row["display_name"],
        "capabilities": json.loads(row["capabilities"]),
        "api_key_hash": row["api_key_hash"],
        "cert_pem": row["cert_pem"],
        "created_at": row["created_at"],
        "is_active": bool(row["is_active"]),
    }
