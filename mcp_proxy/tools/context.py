"""
ToolContext — runtime context injected into every tool handler.

The context carries parameters, identity, secrets, and a pre-configured
httpx client whose transport enforces the tool's domain whitelist.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx


@dataclass(frozen=True)
class ToolContext:
    """Immutable execution context passed to tool handlers."""

    parameters: dict[str, Any]
    agent_id: str
    org_id: str
    capabilities: list[str]
    secrets: dict[str, str]
    http_client: httpx.AsyncClient
    request_id: str
