"""
SecretProvider — injects tool-specific secrets at execution time.

Two implementations:
  - EnvSecretProvider  reads ``MCP_TOOL_{TOOL_NAME}_{KEY}`` from env
  - VaultSecretProvider reads from HashiCorp Vault KV v2

Secrets are fetched per-execution and never cached in the ToolDefinition.
"""
from __future__ import annotations

import logging
import os
from typing import Protocol

import httpx

_log = logging.getLogger("mcp_proxy.tools.secrets")


class SecretProvider(Protocol):
    """Protocol for secret injection into tool contexts."""

    async def get_tool_secrets(self, tool_name: str) -> dict[str, str]:
        ...  # pragma: no cover


class EnvSecretProvider:
    """Read secrets from environment variables.

    Convention: ``MCP_TOOL_{TOOL_NAME_UPPER}_{KEY}``

    Example:
        MCP_TOOL_QUERY_SALESFORCE_SF_CLIENT_ID=abc123
        MCP_TOOL_QUERY_SALESFORCE_SF_CLIENT_SECRET=secret
    """

    async def get_tool_secrets(self, tool_name: str) -> dict[str, str]:
        prefix = f"MCP_TOOL_{tool_name.upper()}_"
        secrets = {
            k[len(prefix):]: v
            for k, v in os.environ.items()
            if k.startswith(prefix)
        }
        _log.debug(
            "EnvSecretProvider: %d secret(s) found for tool '%s'",
            len(secrets),
            tool_name,
        )
        return secrets


class VaultSecretProvider:
    """Read secrets from HashiCorp Vault KV v2.

    Path convention: ``{prefix}/{tool_name}``
    e.g. ``secret/data/mcp-proxy/tools/query_salesforce``
    """

    def __init__(self, vault_addr: str, vault_token: str, prefix: str) -> None:
        self._client = httpx.AsyncClient(
            base_url=vault_addr.rstrip("/"),
            headers={"X-Vault-Token": vault_token},
            timeout=10.0,
        )
        self._prefix = prefix.rstrip("/")

    async def get_tool_secrets(self, tool_name: str) -> dict[str, str]:
        path = f"/v1/{self._prefix}/{tool_name}"
        try:
            resp = await self._client.get(path)
            resp.raise_for_status()
            data = resp.json()["data"]["data"]
            _log.debug(
                "VaultSecretProvider: %d secret(s) fetched for tool '%s'",
                len(data),
                tool_name,
            )
            return data
        except httpx.HTTPStatusError as exc:
            _log.error(
                "Vault returned HTTP %d for tool '%s' at %s",
                exc.response.status_code,
                tool_name,
                path,
            )
            return {}
        except Exception:
            _log.exception("Failed to fetch secrets from Vault for tool '%s'", tool_name)
            return {}

    async def close(self) -> None:
        await self._client.aclose()


def get_secret_provider(settings) -> SecretProvider:
    """Factory: return the appropriate SecretProvider based on config."""
    if settings.secret_backend == "vault":
        _log.info(
            "Using VaultSecretProvider (addr=%s, prefix=%s)",
            settings.vault_addr,
            settings.vault_secret_prefix,
        )
        return VaultSecretProvider(
            vault_addr=settings.vault_addr,
            vault_token=settings.vault_token,
            prefix=settings.vault_secret_prefix,
        )
    _log.info("Using EnvSecretProvider")
    return EnvSecretProvider()
