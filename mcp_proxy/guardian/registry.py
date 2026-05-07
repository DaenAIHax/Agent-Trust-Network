"""Plugin registry for Guardian inspection tools.

Phase 1 ships only the contract. Plugins (Phase 2 ``llm_guardian`` in
cullis-enterprise, third-party adapters via ``cullis.guardian_tools``
entry point) register concrete ``Tool`` subclasses at startup. The
endpoint here doesn't iterate them yet — that's the Phase 2 wiring.

Locking the contract this early lets the Phase 2 plugin author work
in parallel against a stable interface, and lets external integrators
(Lakera, Portkey, NeMo, …) ship a ``Tool`` without forking the proxy.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any, Literal

_log = logging.getLogger("mcp_proxy.guardian.registry")

Direction = Literal["in", "out", "both"]
Decision = Literal["pass", "redact", "block"]


@dataclass
class ToolResult:
    """Outcome of one tool's evaluation.

    ``redacted_payload`` is set when ``decision == "redact"`` and the
    tool produced a sanitized version. ``reasons`` accumulates
    machine-readable matches (regex hit, classifier label, …) for
    operator triage in the audit timeline.
    """

    decision: Decision
    redacted_payload: bytes | None = None
    reasons: list[dict[str, Any]] = field(default_factory=list)


class Tool(ABC):
    """Base class for fast-path inspection tools.

    Subclasses implement ``evaluate(payload, ctx)`` and declare their
    direction via ``direction`` (``in`` for receive-side checks like
    prompt-injection, ``out`` for send-side checks like PII egress,
    ``both`` for the rare tool that runs on either side).
    """

    name: str = "<unnamed>"
    direction: Direction = "both"

    @abstractmethod
    async def evaluate(
        self, payload: bytes, ctx: dict[str, Any],
    ) -> ToolResult:  # pragma: no cover — abstract
        ...


_registry: dict[str, Tool] = {}


def register_tool(tool: Tool) -> None:
    """Register a tool by its ``.name``. Idempotent on equal instances.

    A second registration of the same name with a different instance
    overwrites — Phase 2 may want to replace the default regex pack
    with a customer-tuned one without restarting.
    """
    if not getattr(tool, "name", None) or tool.name == "<unnamed>":
        raise ValueError("Tool must define a non-empty .name before registering.")
    if tool.name in _registry and _registry[tool.name] is not tool:
        _log.info("guardian.register_tool overwrite name=%s", tool.name)
    _registry[tool.name] = tool


def registered_tools(direction: Direction | None = None) -> list[Tool]:
    """Return the currently-registered tools, optionally filtered."""
    if direction is None:
        return list(_registry.values())
    return [
        t for t in _registry.values()
        if t.direction == direction or t.direction == "both"
    ]


def clear_registry() -> None:
    """Reset the registry. Test-only entry point."""
    _registry.clear()


def load_entry_point_tools() -> list[str]:
    """Load tools advertised under the ``cullis.guardian_tools`` group.

    Each entry point is expected to expose a callable that returns a
    ``Tool`` instance (or a list of them). Failures are logged and
    skipped — a broken plugin must not prevent Mastio from booting.
    Returns the names of successfully registered tools, for the boot
    log line.
    """
    loaded: list[str] = []
    try:
        eps = entry_points(group="cullis.guardian_tools")
    except TypeError:
        # Python < 3.10 fallback.
        eps = entry_points().get("cullis.guardian_tools", [])  # type: ignore[assignment]
    for ep in eps:
        try:
            factory = ep.load()
            result = factory()
            tools = result if isinstance(result, (list, tuple)) else [result]
            for t in tools:
                if not isinstance(t, Tool):
                    _log.warning(
                        "guardian entry_point=%s returned non-Tool object %r",
                        ep.name, type(t).__name__,
                    )
                    continue
                register_tool(t)
                loaded.append(t.name)
        except Exception as exc:
            _log.warning(
                "guardian entry_point=%s load failed: %s", ep.name, exc,
            )
    return loaded
