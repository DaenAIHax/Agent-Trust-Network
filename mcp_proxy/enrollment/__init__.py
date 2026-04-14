"""Connector enrollment — self-register + admin approve flow.

Implements Pattern B from the three-tier architecture (see memory
`project_three_tier_architecture.md`): a user-side Cullis Connector declares
its identity (name/email/reason) and submits a public key; the admin then
decides the internal agent_id, capabilities, and groups, and approves to
trigger cert issuance signed by the Org CA.

This package owns the server-side API only. The browser form rendered at
``/enroll?session=...`` and the dashboard pending list live under
``mcp_proxy.dashboard``.
"""

from mcp_proxy.enrollment.router import router

__all__ = ["router"]
