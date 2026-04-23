"""Federation update framework — registry foundation.

See ``imp/federation_hardening_plan.md`` (Parte 1). This package holds
the ``Migration`` base class, a filesystem-based discovery registry,
and the schema for the ``pending_updates`` table that the boot detector
(PR 2) populates.

Concrete migrations live in ``mcp_proxy.updates.migrations``. Each one
subclasses :class:`Migration`, declares metadata as class attributes,
and implements ``check`` / ``up`` / ``rollback``.

The dashboard admin endpoint (PR 4) reads the registry by id and drives
apply / rollback through the ``Migration`` instance; the boot detector
calls ``check`` on every registered migration at startup.
"""
from __future__ import annotations

from mcp_proxy.updates.base import Migration
from mcp_proxy.updates.registry import discover, get_by_id


__all__ = ["Migration", "discover", "get_by_id"]
