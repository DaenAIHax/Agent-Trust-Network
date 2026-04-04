"""
OPA (Open Policy Agent) adapter for session policy decisions.

Translates the ATN session request payload into an OPA REST API call
and returns a WebhookDecision for compatibility with the existing
broker router code.

OPA endpoint: POST {OPA_URL}/v1/data/atn/session/allow
Input document matches the webhook payload format.
Expected response: {"result": {"allow": true/false, "reason": "..."}}

Timeout: 5 seconds (same as webhook).
Default-deny on error/timeout (same as webhook).
"""
import logging
import time

import httpx

from app.policy.webhook import WebhookDecision
from app.telemetry import tracer
from app.telemetry_metrics import PDP_WEBHOOK_LATENCY_HISTOGRAM

_log = logging.getLogger("agent_trust")

_OPA_TIMEOUT = 5.0  # seconds


async def evaluate_session_via_opa(
    opa_url: str,
    initiator_org_id: str,
    target_org_id: str,
    initiator_agent_id: str,
    target_agent_id: str,
    capabilities: list[str],
) -> WebhookDecision:
    """
    Evaluate a session request against OPA.

    Calls the OPA REST API once with the full session context.
    Both orgs' policies are expected to be loaded in OPA as a single
    combined ruleset (the OPA instance is broker-side, not per-org).
    """
    url = f"{opa_url.rstrip('/')}/v1/data/atn/session/allow"

    input_doc = {
        "input": {
            "initiator_agent_id": initiator_agent_id,
            "initiator_org_id": initiator_org_id,
            "target_agent_id": target_agent_id,
            "target_org_id": target_org_id,
            "capabilities": capabilities,
        }
    }

    t0 = time.monotonic()
    try:
        with tracer.start_as_current_span("pdp.opa_call") as span:
            span.set_attribute("pdp.backend", "opa")
            span.set_attribute("pdp.initiator_org", initiator_org_id)
            span.set_attribute("pdp.target_org", target_org_id)

            async with httpx.AsyncClient(timeout=_OPA_TIMEOUT) as client:
                resp = await client.post(url, json=input_doc)

            elapsed_ms = (time.monotonic() - t0) * 1000
            PDP_WEBHOOK_LATENCY_HISTOGRAM.record(elapsed_ms, {"org_id": "opa"})

        if resp.status_code != 200:
            _log.warning("OPA returned HTTP %d — default-deny", resp.status_code)
            return WebhookDecision(
                allowed=False,
                reason=f"OPA returned HTTP {resp.status_code}",
                org_id="opa",
            )

        data = resp.json()
        result = data.get("result", {})

        if isinstance(result, bool):
            allowed = result
            reason = ""
        elif isinstance(result, dict):
            allowed = bool(result.get("allow", False))
            reason = str(result.get("reason", ""))[:512]
        else:
            _log.warning("OPA returned unexpected result type: %s — default-deny", type(result))
            return WebhookDecision(allowed=False, reason="OPA returned invalid result", org_id="opa")

        if allowed:
            _log.info("OPA allow: %s → %s", initiator_org_id, target_org_id)
            return WebhookDecision(allowed=True, reason=reason, org_id="opa")

        _log.info("OPA deny: %s → %s reason=%s", initiator_org_id, target_org_id, reason)
        return WebhookDecision(
            allowed=False,
            reason=reason or "Denied by OPA policy",
            org_id="opa",
        )

    except httpx.TimeoutException:
        _log.warning("OPA timeout after %.1fs — default-deny", _OPA_TIMEOUT)
        return WebhookDecision(
            allowed=False,
            reason=f"OPA timed out after {_OPA_TIMEOUT}s",
            org_id="opa",
        )
    except Exception as exc:
        _log.warning("OPA error: %s — default-deny", exc)
        return WebhookDecision(
            allowed=False,
            reason=f"OPA error: {exc}",
            org_id="opa",
        )
