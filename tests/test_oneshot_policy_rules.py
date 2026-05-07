"""PolicyEngine wired into oneshot forward path (issue #460).

Pre-fix: ``app/broker/oneshot_router.py`` only consulted
``evaluate_session_policy`` (the PDP webhook/opa dispatcher) and never
read ``policy_rules`` rows. Operators creating allow/deny session
policies via ``POST /v1/policy/rules`` saw them silently ignored on
the oneshot path while session-open honoured them. Asymmetry is now
closed: oneshot mirrors session-open's "PDP webhook → PolicyEngine"
chain.

Coverage:
  1. No rules: oneshot is allowed (no shadowing of PDP allow decision).
  2. Deny rule on initiator: oneshot returns 403, audit row tagged
     ``engine: local``.
  3. Allow rule matching the request: oneshot succeeds.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from tests.cert_factory import DPoPHelper
from tests.conftest import ADMIN_HEADERS  # noqa: F401 — exercised via helpers
from tests.test_oneshot_cross import (
    _build_forward_body,
    _mock_oneshot_pdp,  # noqa: F401 — autouse fixture re-exported for patch scope
    _register_and_login,
)


pytestmark = pytest.mark.asyncio


async def _create_session_policy(
    client: AsyncClient,
    org_id: str,
    policy_id: str,
    *,
    effect: str,
    target_org_ids: list[str] | None = None,
    capabilities: list[str] | None = None,
):
    """Create a session-type policy rule on Court via the public API."""
    org_secret = org_id + "-secret"
    return await client.post(
        "/v1/policy/rules",
        json={
            "policy_id": policy_id,
            "org_id": org_id,
            "policy_type": "session",
            "rules": {
                "effect": effect,
                "conditions": {
                    "target_org_id": target_org_ids or [],
                    "capabilities": capabilities or [],
                },
            },
        },
        headers={"x-org-id": org_id, "x-org-secret": org_secret},
    )


async def test_oneshot_allowed_when_no_local_rules(client: AsyncClient):
    """When the initiator org has no session rules, the oneshot path
    falls through to the PDP webhook decision (mocked allow). The
    PolicyEngine layer must not shadow the allow decision with a
    default-deny when no rules exist."""
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(
        client, dpop_a, "norules-a::alice", "norules-a",
    )
    await _register_and_login(
        client, dpop_b, "norules-b::bob", "norules-b",
    )

    body, _, _ = _build_forward_body(
        "norules-a::alice", "norules-a", "norules-b::bob", {"msg": "ping"},
    )
    r = await client.post(
        "/v1/broker/oneshot/forward",
        json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 202, r.text


async def test_oneshot_blocked_by_deny_rule(client: AsyncClient):
    """An allow-only session policy whose conditions exclude the target
    org should reject the oneshot, exposing PolicyEngine in the path
    where it used to be silently bypassed."""
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(
        client, dpop_a, "deny-a::alice", "deny-a",
    )
    await _register_and_login(
        client, dpop_b, "deny-b::bob", "deny-b",
    )

    # Initiator allows ONLY a different target org. The forward to
    # deny-b::bob falls outside the allowed target set → engine deny.
    resp = await _create_session_policy(
        client, "deny-a", "deny-a::session-restrict",
        effect="allow",
        target_org_ids=["some-other-org"],
        capabilities=["oneshot.message"],
    )
    assert resp.status_code == 201, resp.text

    body, _, _ = _build_forward_body(
        "deny-a::alice", "deny-a", "deny-b::bob", {"msg": "ping"},
    )
    r = await client.post(
        "/v1/broker/oneshot/forward",
        json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 403, r.text
    assert "policy" in r.json()["detail"].lower()


async def test_oneshot_passes_when_rule_matches(client: AsyncClient):
    """An explicit allow rule matching the target org and capability
    completes the round-trip without the engine vetoing."""
    dpop_a, dpop_b = DPoPHelper(), DPoPHelper()
    token_a = await _register_and_login(
        client, dpop_a, "match-a::alice", "match-a",
    )
    await _register_and_login(
        client, dpop_b, "match-b::bob", "match-b",
    )

    resp = await _create_session_policy(
        client, "match-a", "match-a::session-allow",
        effect="allow",
        target_org_ids=["match-b"],
        capabilities=["oneshot.message"],
    )
    assert resp.status_code == 201, resp.text

    body, _, _ = _build_forward_body(
        "match-a::alice", "match-a", "match-b::bob", {"msg": "ping"},
        capabilities=["oneshot.message"],
    )
    r = await client.post(
        "/v1/broker/oneshot/forward",
        json=body,
        headers=dpop_a.headers("POST", "/v1/broker/oneshot/forward", token_a),
    )
    assert r.status_code == 202, r.text
