"""Mastio KMS abstraction.

Wraps Org CA persistence behind a ``KMSProvider`` interface so cullis
-enterprise plugins can route key storage through cloud KMS / Secrets
Manager / Key Vault without touching ``agent_manager``.

The default ``LocalKMSProvider`` keeps the keys in ``proxy_config``
(historic behavior); enterprise providers are loaded via the plugin
``kms_factory`` hook when ``MCP_PROXY_KMS_BACKEND`` resolves to
something other than ``local``.

Public surface:
  * :class:`KMSProvider`            — protocol every backend implements.
  * :class:`LocalKMSProvider`       — DB-backed default.
  * :func:`get_kms_provider`        — module singleton resolver.
  * :func:`reset_kms_provider`      — test-only cache invalidation.
"""
from mcp_proxy.kms.factory import get_kms_provider, reset_kms_provider
from mcp_proxy.kms.local import LocalKMSProvider
from mcp_proxy.kms.provider import KMSProvider

__all__ = [
    "KMSProvider",
    "LocalKMSProvider",
    "get_kms_provider",
    "reset_kms_provider",
]
