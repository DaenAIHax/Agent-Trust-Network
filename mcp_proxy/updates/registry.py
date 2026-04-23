"""Filesystem-based discovery of :class:`~mcp_proxy.updates.base.Migration`.

Scans :mod:`mcp_proxy.updates.migrations` for every module it contains,
imports each one, and collects every non-abstract :class:`Migration`
subclass it finds. Sort is lexical on ``migration_id`` — the project
convention is ``YYYY-MM-DD-slug``, so lexical sort is chronological.

Design notes:

- No caching. ``discover()`` walks the filesystem every call. The
  registry is a handful of migrations, re-scanning is cheap, and
  avoiding a cache sidesteps the stale-reload problem in tests where
  fixtures register new migrations dynamically.
- No topological ordering. The plan (Parte 1) keeps inter-migration
  dependencies out of the foundation; add them only when a concrete
  migration needs one. Lexical-by-date is sufficient today.
- Enterprise plugin path is deliberately absent — tracked as a P2
  follow-up issue. When it lands, this module grows a second scan
  entry point without changing the ``Migration`` contract.
"""
from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import Iterable

from mcp_proxy.updates import migrations as _migrations_pkg
from mcp_proxy.updates.base import Migration


def _iter_subclasses(cls: type) -> Iterable[type]:
    """Yield ``cls`` and every subclass recursively, breadth-first."""
    seen: set[type] = set()
    stack: list[type] = [cls]
    while stack:
        current = stack.pop()
        for sub in current.__subclasses__():
            if sub in seen:
                continue
            seen.add(sub)
            yield sub
            stack.append(sub)


def discover() -> list[Migration]:
    """Return every concrete :class:`Migration` registered on disk.

    Imports every module in :mod:`mcp_proxy.updates.migrations`
    (non-recursive — PR 1 keeps the layout flat), then walks the
    :class:`Migration` subclass tree and instantiates every non-abstract
    subclass whose module lives inside the migrations package. The
    module filter is important: :class:`Migration` subclasses can
    be created anywhere (unit-test fixtures, ad-hoc instances in the
    REPL), and we must not pick them up as "installed migrations".

    Sorted by ``migration_id`` for deterministic ordering. Double-calling
    is safe — each call creates fresh instances (metadata lives on the
    class, not the instance).
    """
    pkg_name = _migrations_pkg.__name__
    for mod in pkgutil.iter_modules(_migrations_pkg.__path__):
        importlib.import_module(f"{pkg_name}.{mod.name}")

    found: list[Migration] = []
    seen_ids: set[str] = set()
    for cls in _iter_subclasses(Migration):
        if inspect.isabstract(cls):
            continue
        # Only migrations whose defining module is under the migrations
        # package are considered installed. This filter is what keeps
        # test-created fixtures from polluting production discovery,
        # and lets each test point ``_migrations_pkg`` at a throwaway
        # package for isolation.
        if not cls.__module__.startswith(pkg_name):
            continue
        # Defensive: should never fire because __init_subclass__ rejects
        # concrete subclasses without the required attrs, but a
        # malformed plugin could still slip through via namespace tricks.
        if not hasattr(cls, "migration_id"):
            continue
        if cls.migration_id in seen_ids:
            raise RuntimeError(
                f"duplicate migration_id {cls.migration_id!r} in registry "
                f"— collision between {cls.__module__}.{cls.__name__} and "
                f"an earlier definition"
            )
        seen_ids.add(cls.migration_id)
        found.append(cls())

    found.sort(key=lambda m: m.migration_id)
    return found


def get_by_id(migration_id: str) -> Migration | None:
    """Return the concrete :class:`Migration` with the given id, or None.

    Convenience wrapper around :func:`discover` for the admin endpoint
    (PR 4), which resolves an operator-clicked id to the instance whose
    ``up`` / ``rollback`` it drives.
    """
    for m in discover():
        if m.migration_id == migration_id:
            return m
    return None
