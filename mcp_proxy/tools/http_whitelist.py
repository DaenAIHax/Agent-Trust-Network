"""
WhitelistedTransport — httpx transport that blocks non-whitelisted domains.

Defence-in-depth: even if a tool handler constructs an arbitrary URL,
the transport layer will reject it unless the domain appears in the
tool's allowed_domains list.

Supports depth-1 wildcards:
  *.salesforce.com  matches  login.salesforce.com
  *.salesforce.com  does NOT match  a.b.salesforce.com
"""
from __future__ import annotations

import logging

import httpx

_log = logging.getLogger("mcp_proxy.tools.http_whitelist")


class ToolExecutionError(Exception):
    """Raised when a tool violates a runtime constraint (domain, timeout, etc.)."""


class WhitelistedTransport(httpx.AsyncHTTPTransport):
    """Custom httpx transport that enforces a domain whitelist."""

    def __init__(self, allowed_domains: list[str], **kwargs) -> None:
        self._allowed: frozenset[str] = frozenset(allowed_domains)
        super().__init__(**kwargs)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        hostname = request.url.host
        if hostname is None:
            raise ToolExecutionError("Request has no hostname")
        if not self._is_allowed(hostname):
            _log.warning(
                "Blocked request to non-whitelisted domain: %s (allowed: %s)",
                hostname,
                sorted(self._allowed),
            )
            raise ToolExecutionError(
                f"Domain '{hostname}' not in whitelist: {sorted(self._allowed)}"
            )
        return await super().handle_async_request(request)

    def _is_allowed(self, hostname: str) -> bool:
        """Check hostname against exact matches and depth-1 wildcards.

        Wildcard rules:
          - ``*.example.com`` matches ``sub.example.com`` (exactly one level)
          - ``*.example.com`` does NOT match ``a.b.example.com``
          - Empty whitelist means the tool makes no HTTP calls (local-only)
        """
        if not self._allowed:
            return False

        # Exact match
        if hostname in self._allowed:
            return True

        # Wildcard match: *.domain.tld
        parts = hostname.split(".")
        if len(parts) >= 2:
            # Reconstruct the parent domain and check for wildcard entry
            parent = ".".join(parts[1:])
            wildcard = f"*.{parent}"
            if wildcard in self._allowed and len(parts) == len(parent.split(".")) + 1:
                return True

        return False
