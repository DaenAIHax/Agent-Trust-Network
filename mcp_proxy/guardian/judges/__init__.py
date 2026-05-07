"""Slow-path judges (LLM-based content evaluation).

ADR-016 splits inspection into two paths: synchronous fast-path
deterministic checks (regex, allowlist, loop counter — Phase 2 plugin),
and asynchronous slow-path LLM-based judges. This module hosts the
adapter contract for the slow-path; concrete adapters live alongside
under ``mcp_proxy/guardian/judges/<provider>.py``.

Slow-path judges are NOT wired into the inspect endpoint in Phase 1.
The contract exists here so:

- adapter authors (us + third parties) can ship implementations against
  a stable interface without forking the proxy;
- Phase 4 (cullis-enterprise) plugs them into a bounded ``asyncio``
  task queue that the endpoint enqueues into after returning the
  fast-path decision.

A judge's ``decision == "unavailable"`` is the canonical "I cannot
answer right now" — wrong API key, package not installed, transient
upstream error. Callers must NOT treat unavailable as ``pass``: log,
alert, and either fail-closed (block by default) or fall through to
the next judge in the chain. Phase 4 implements that policy; Phase 1
just defines the shape.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Literal

_log = logging.getLogger("mcp_proxy.guardian.judges")

JudgeDecision = Literal["pass", "redact", "block", "unavailable"]


@dataclass
class JudgeResult:
    decision: JudgeDecision
    judge: str
    reasons: list[dict[str, Any]] = field(default_factory=list)
    redacted_payload: bytes | None = None
    detail: str | None = None
    latency_ms: int = 0


class Judge(ABC):
    """Contract for slow-path content judges.

    Concrete adapters typically wrap a SaaS API (Lakera, Portkey
    Guardrails, OpenAI Moderation, Bedrock Guardrails) or a local model
    (NeMo Guardrails, Llama Guard hosted via Replicate/Together). The
    adapter is responsible for translating the provider's native
    response into a ``JudgeResult``.
    """

    name: str = "<unnamed>"

    @abstractmethod
    async def evaluate(
        self, payload: bytes, ctx: dict[str, Any],
    ) -> JudgeResult:  # pragma: no cover — abstract
        ...

    @classmethod
    def unavailable(cls, *, judge: str, detail: str) -> JudgeResult:
        return JudgeResult(
            decision="unavailable", judge=judge, detail=detail,
        )


__all__ = [
    "Judge",
    "JudgeDecision",
    "JudgeResult",
]
