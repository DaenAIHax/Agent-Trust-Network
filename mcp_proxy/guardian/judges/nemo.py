"""NeMo Guardrails judge (open source, NVIDIA, in-process).

Wraps ``nemoguardrails`` so a Mastio operator can run a slow-path LLM
judge without paying for a SaaS subscription or shipping a separate
sidecar. Configuration is YAML-based in NeMo's own format (see the
``rails`` argument); we keep the adapter narrow and pass through.

If the package is not installed (``nemoguardrails``), or the rails
config is invalid, ``evaluate`` returns ``decision="unavailable"`` with
a meaningful detail. The judge never raises in normal operation; the
caller decides fail-open vs fail-closed.

Phase 1 dogfood point: this is the one judge that runs end-to-end
without any signup, so it's the regression check for the contract.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from mcp_proxy.guardian.judges import Judge, JudgeResult

_log = logging.getLogger("mcp_proxy.guardian.judges.nemo")


_DEFAULT_RAILS_YAML = """
models: []

rails:
  input:
    flows:
      - check user message
  output:
    flows:
      - check bot response

prompts:
  - task: check_user_message
    content: |
      You are checking whether the user's message is safe to deliver
      to a downstream agent. Reply with exactly one word: SAFE or UNSAFE.

  - task: check_bot_response
    content: |
      You are checking whether the bot response is safe to deliver
      back. Reply with exactly one word: SAFE or UNSAFE.
"""


class NemoJudge(Judge):
    """NeMo Guardrails wrapper."""

    name = "nemo"

    def __init__(self, *, rails_yaml: str | None = None):
        self._rails_yaml = rails_yaml or _DEFAULT_RAILS_YAML
        self._rails = None  # lazy: nemoguardrails import is heavy

    def _ensure_rails(self):
        if self._rails is not None:
            return self._rails
        try:
            from nemoguardrails import LLMRails, RailsConfig
        except ImportError as exc:
            raise RuntimeError(
                "nemoguardrails_not_installed: pip install nemoguardrails"
            ) from exc
        cfg = RailsConfig.from_content(yaml_content=self._rails_yaml)
        self._rails = LLMRails(cfg)
        return self._rails

    async def evaluate(
        self, payload: bytes, ctx: dict[str, Any],
    ) -> JudgeResult:
        started = time.perf_counter()
        try:
            rails = await asyncio.to_thread(self._ensure_rails)
        except RuntimeError as exc:
            return Judge.unavailable(judge=self.name, detail=str(exc))
        except Exception as exc:
            _log.warning("nemo rails load failed: %s", exc)
            return Judge.unavailable(
                judge=self.name, detail=f"rails_load_failed: {exc}",
            )

        text = payload.decode("utf-8", errors="replace")
        try:
            response = await asyncio.to_thread(
                rails.generate, messages=[{"role": "user", "content": text}],
            )
        except Exception as exc:
            _log.warning("nemo rails generate failed: %s", exc)
            return Judge.unavailable(
                judge=self.name, detail=f"rails_generate_failed: {exc}",
            )

        # NeMo response shape: {"role": "assistant", "content": "..."}.
        content = ""
        if isinstance(response, dict):
            content = str(response.get("content") or "")
        elif isinstance(response, list) and response:
            content = str(response[0].get("content") or "")
        else:
            content = str(response)

        # Heuristic: NeMo's example rails reply with "I'm sorry" or
        # similar refusals when input is unsafe. Without a structured
        # decision field we have to look for the canonical refusal
        # pattern. Operators with a real corpus override the rails YAML.
        unsafe_markers = ["unsafe", "i'm sorry", "i cannot", "violates"]
        is_unsafe = any(m in content.lower() for m in unsafe_markers)
        decision = "block" if is_unsafe else "pass"

        latency_ms = int((time.perf_counter() - started) * 1000)
        return JudgeResult(
            decision=decision,
            judge=self.name,
            reasons=[{"tool": "nemo", "match": content[:240]}] if is_unsafe else [],
            latency_ms=latency_ms,
            detail=content[:512],
        )
