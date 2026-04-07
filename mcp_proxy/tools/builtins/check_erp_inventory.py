"""
Builtin tool: check_erp_inventory — query ERP database for inventory levels.

This is a local-only tool (no external HTTP calls).  In production it would
connect to the org's ERP database using ``ctx.secrets["DATABASE_URL"]``.
The demo implementation returns mock data.
"""
from __future__ import annotations

from mcp_proxy.tools.context import ToolContext
from mcp_proxy.tools.registry import tool_registry


@tool_registry.register(
    name="check_erp_inventory",
    capability="erp.inventory.read",
    allowed_domains=[],
    description="Query ERP database for inventory levels by SKU",
    parameters_schema={
        "type": "object",
        "properties": {
            "sku": {
                "type": "string",
                "description": "Stock-keeping unit identifier",
            },
        },
        "required": ["sku"],
    },
)
async def check_erp_inventory(ctx: ToolContext) -> dict:
    """Return inventory levels for a given SKU.

    In production, this would use ``ctx.secrets["DATABASE_URL"]`` to query
    the ERP database.  The demo returns static mock data.
    """
    sku = ctx.parameters.get("sku", "UNKNOWN")
    # TODO: Replace with real DB query using ctx.secrets["DATABASE_URL"]
    return {
        "sku": sku,
        "quantity": 142,
        "warehouse": "WH-01",
        "last_updated": "2026-04-07T10:00:00Z",
    }
