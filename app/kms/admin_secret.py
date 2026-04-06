"""
Admin secret management — stores the admin password hash in the KMS backend.

On first boot the plaintext ADMIN_SECRET from .env is hashed with bcrypt and
persisted to Vault (or a local file when KMS_BACKEND=local).  Subsequent
boots read the hash from the backend and cache it in memory.

The dashboard "change admin password" feature calls set_admin_secret_hash()
which updates both the backend and the in-memory cache atomically.
"""
import logging
import os
import pathlib

import bcrypt
import httpx

_log = logging.getLogger("agent_trust.admin_secret")

_cached_hash: str | None = None
_VAULT_TIMEOUT = 10
_LOCAL_HASH_PATH = pathlib.Path("certs/.admin_secret_hash")

# Dummy hash for constant-time verification when no hash is available.
_DUMMY_HASH: str = bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=12)).decode()


# ---------------------------------------------------------------------------
# Vault helpers
# ---------------------------------------------------------------------------

async def _vault_headers() -> dict[str, str]:
    from app.config import get_settings
    return {"X-Vault-Token": get_settings().vault_token, "Content-Type": "application/json"}


async def _read_vault_secret() -> dict | None:
    """Read the full secret dict from Vault KV v2.  Returns None on failure."""
    from app.config import get_settings
    s = get_settings()
    url = f"{s.vault_addr.rstrip('/')}/v1/{s.vault_secret_path}"
    try:
        async with httpx.AsyncClient(timeout=_VAULT_TIMEOUT) as client:
            resp = await client.get(url, headers=await _vault_headers())
            if resp.status_code != 200:
                _log.warning("Vault read returned HTTP %d", resp.status_code)
                return None
            return resp.json()["data"]
    except Exception as exc:
        _log.warning("Vault read failed: %s", exc)
        return None


async def _write_vault_field(field: str, value: str) -> bool:
    """Merge-write a single field into the existing Vault secret (KV v2).

    KV v2 PUT replaces the entire secret, so we must read first, merge,
    then write back using check-and-set (cas) to prevent race conditions.
    """
    from app.config import get_settings
    s = get_settings()
    url = f"{s.vault_addr.rstrip('/')}/v1/{s.vault_secret_path}"
    headers = await _vault_headers()
    try:
        async with httpx.AsyncClient(timeout=_VAULT_TIMEOUT) as client:
            # Read current secret + metadata
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                payload = resp.json()["data"]
                current_data = payload.get("data", {})
                version = payload.get("metadata", {}).get("version", 0)
                current_data[field] = value
                body: dict = {"options": {"cas": version}, "data": current_data}
            else:
                # Secret path doesn't exist yet — first write (no CAS)
                body = {"data": {field: value}}

            resp = await client.post(url, headers=headers, json=body)
            if resp.status_code in (200, 204):
                _log.info("Vault field '%s' written successfully", field)
                return True
            _log.error("Vault write returned HTTP %d: %s", resp.status_code, resp.text)
            return False
    except Exception as exc:
        _log.error("Vault write failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Local file helpers
# ---------------------------------------------------------------------------

def _read_local_hash() -> str | None:
    if _LOCAL_HASH_PATH.exists():
        return _LOCAL_HASH_PATH.read_text().strip()
    return None


def _write_local_hash(hash_str: str) -> None:
    _LOCAL_HASH_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LOCAL_HASH_PATH.write_text(hash_str + "\n")
    os.chmod(_LOCAL_HASH_PATH, 0o600)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def get_admin_secret_hash() -> str | None:
    """Return the cached admin secret bcrypt hash, fetching from backend if needed."""
    global _cached_hash
    if _cached_hash is not None:
        return _cached_hash

    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        secret = await _read_vault_secret()
        if secret and "data" in secret:
            _cached_hash = secret["data"].get("admin_secret_hash")
    else:
        _cached_hash = _read_local_hash()

    return _cached_hash


async def set_admin_secret_hash(new_hash: str) -> None:
    """Persist a new admin secret hash and update the in-memory cache."""
    global _cached_hash
    from app.config import get_settings
    backend = get_settings().kms_backend.lower()

    if backend == "vault":
        ok = await _write_vault_field("admin_secret_hash", new_hash)
        if not ok:
            raise RuntimeError("Failed to write admin_secret_hash to Vault")
    else:
        _write_local_hash(new_hash)

    _cached_hash = new_hash
    _log.info("Admin secret hash updated in %s backend", backend)


async def ensure_bootstrapped() -> None:
    """Bootstrap the admin secret hash from .env on first boot.

    If the backend already contains a hash, this is a no-op.
    """
    existing = await get_admin_secret_hash()
    if existing:
        _log.info("Admin secret hash already present in KMS backend")
        return

    from app.config import get_settings
    settings = get_settings()
    plaintext = settings.admin_secret

    new_hash = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=12)).decode()

    try:
        await set_admin_secret_hash(new_hash)
        _log.info("Admin secret bootstrapped from .env to %s backend", settings.kms_backend)
    except Exception as exc:
        _log.warning(
            "Could not bootstrap admin secret to %s: %s  — "
            "falling back to .env comparison until next restart",
            settings.kms_backend, exc,
        )


def verify_admin_password(password: str, stored_hash: str | None = None) -> bool:
    """Verify a password against the stored bcrypt hash (constant-time)."""
    if stored_hash is None:
        bcrypt.checkpw(password.encode(), _DUMMY_HASH.encode())
        return False
    return bcrypt.checkpw(password.encode(), stored_hash.encode())
