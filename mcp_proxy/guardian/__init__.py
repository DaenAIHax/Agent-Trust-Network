"""ADR-016 Guardian — bidirectional content inspection on Mastio.

Phase 1 (foundation) ships the contract: endpoint, ticket signing,
registry hook for plugin tools, audit row writer. No real inspection
runs yet — every call returns ``decision=pass``. The plugin-side
fast-path tools land in Phase 2 (cullis-enterprise).

Public surface:
    record_inspection — write a guardian decision to local_audit
    register_tool, registered_tools, Tool, ToolResult — plugin contract
    sign_ticket, verify_ticket, GuardianTicketError — JWT helpers
"""
from __future__ import annotations

from mcp_proxy.guardian.audit import record_inspection
from mcp_proxy.guardian.registry import (
    Tool,
    ToolResult,
    register_tool,
    registered_tools,
)
from mcp_proxy.guardian.ticket import (
    GuardianTicketError,
    sign_ticket,
    verify_ticket,
)

__all__ = [
    "GuardianTicketError",
    "Tool",
    "ToolResult",
    "record_inspection",
    "register_tool",
    "registered_tools",
    "sign_ticket",
    "verify_ticket",
]
