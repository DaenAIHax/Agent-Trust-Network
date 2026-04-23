"""Concrete federation update migrations.

Empty in PR 1 — the registry foundation does not ship any migration.
The first concrete migration (``2026-04-23-org-ca-pathlen-1``) lands
in PR 3; this package exists now so :func:`mcp_proxy.updates.discover`
has a stable scan target from day one.
"""
from __future__ import annotations
