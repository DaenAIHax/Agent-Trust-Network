"""
Broker HTTP client factory — central place to configure TLS verification
for every outbound call the proxy makes to the broker.

All broker-bound HTTP traffic MUST go through ``broker_http_client`` so that
``MCP_PROXY_BROKER_CA_PATH`` (or the dev fallback to verify=False) is honored
in exactly one place.
"""
from __future__ import annotations

import logging

import httpx

from mcp_proxy.config import get_settings

logger = logging.getLogger("mcp_proxy.auth.broker_http")


def broker_http_client(**kwargs) -> httpx.AsyncClient:
    """Return an ``httpx.AsyncClient`` configured to reach the broker.

    The ``verify`` kwarg is sourced from ``settings.broker_verify()`` unless the
    caller explicitly overrides it. ``timeout`` defaults to 10.0 seconds. All
    other kwargs are passed through to ``httpx.AsyncClient`` unchanged.
    """
    settings = get_settings()
    kwargs.setdefault("verify", settings.broker_verify())
    kwargs.setdefault("timeout", 10.0)
    if kwargs["verify"] is False:
        logger.debug("broker_http_client: TLS verification disabled (dev fallback)")
    return httpx.AsyncClient(**kwargs)


def cullis_client_verify():
    """Return the value to pass as ``CullisClient(verify_tls=...)``.

    ``CullisClient`` exposes the flag under a different name than httpx but the
    semantics are the same: a path string enables verification against that CA
    bundle, ``False`` disables it entirely.
    """
    return get_settings().broker_verify()
