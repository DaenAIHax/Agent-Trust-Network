"""``LocalKMSProvider`` — Org CA persisted in ``proxy_config``.

This is the default Mastio path. It preserves the historic behavior
where ``agent_manager`` reads ``org_ca_key`` / ``org_ca_cert`` from
the local proxy_config table and writes them on first-boot generation.
"""
from __future__ import annotations

from mcp_proxy.db import get_config, set_config


class LocalKMSProvider:
    """Default Mastio KMS provider — the Org CA lives in proxy_config."""

    name = "local"

    async def load_org_ca(self) -> tuple[str, str] | None:
        key_pem = await get_config("org_ca_key")
        cert_pem = await get_config("org_ca_cert")
        if key_pem and cert_pem:
            return key_pem, cert_pem
        return None

    async def store_org_ca(self, key_pem: str, cert_pem: str) -> None:
        await set_config("org_ca_key", key_pem)
        await set_config("org_ca_cert", cert_pem)
