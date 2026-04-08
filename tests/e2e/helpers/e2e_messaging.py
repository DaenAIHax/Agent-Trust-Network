"""
E2E messaging helpers — drive the proxy egress API from the host with
just an API key, no DPoP/x509 dance (the proxy handles that internally).

These wrap the same endpoints used in mcp_proxy/egress/router.py:
  POST /v1/egress/sessions
  POST /v1/egress/sessions/{id}/accept
  POST /v1/egress/send
  GET  /v1/egress/messages/{session_id}
  POST /v1/egress/discover
"""
import asyncio
import time

import httpx


class EgressError(RuntimeError):
    pass


def _headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


async def discover_agents(
    proxy_url: str,
    api_key: str,
    capabilities: list[str] | None = None,
) -> list[dict]:
    """POST /v1/egress/discover — list remote agents reachable from this org."""
    async with httpx.AsyncClient(timeout=15.0) as http:
        resp = await http.post(
            f"{proxy_url}/v1/egress/discover",
            json={"capabilities": capabilities},
            headers=_headers(api_key),
        )
    if resp.status_code != 200:
        raise EgressError(f"discover failed: HTTP {resp.status_code} {resp.text[:300]}")
    return resp.json().get("agents", [])


async def open_session(
    proxy_url: str,
    api_key: str,
    target_agent_id: str,
    target_org_id: str,
    capabilities: list[str],
) -> str:
    """POST /v1/egress/sessions — returns the session_id."""
    async with httpx.AsyncClient(timeout=15.0) as http:
        resp = await http.post(
            f"{proxy_url}/v1/egress/sessions",
            json={
                "target_agent_id": target_agent_id,
                "target_org_id":   target_org_id,
                "capabilities":    capabilities,
            },
            headers=_headers(api_key),
        )
    if resp.status_code != 200:
        raise EgressError(f"open_session failed: HTTP {resp.status_code} {resp.text[:300]}")
    return resp.json()["session_id"]


async def accept_session(
    proxy_url: str,
    api_key: str,
    session_id: str,
) -> None:
    """POST /v1/egress/sessions/{id}/accept — target agent confirms."""
    async with httpx.AsyncClient(timeout=15.0) as http:
        resp = await http.post(
            f"{proxy_url}/v1/egress/sessions/{session_id}/accept",
            headers=_headers(api_key),
        )
    if resp.status_code not in (200, 204):
        raise EgressError(f"accept_session failed: HTTP {resp.status_code} {resp.text[:300]}")


async def send_message(
    proxy_url: str,
    api_key: str,
    session_id: str,
    payload: dict,
    recipient_agent_id: str,
) -> None:
    """POST /v1/egress/send — sends an E2E encrypted message via the broker."""
    async with httpx.AsyncClient(timeout=15.0) as http:
        resp = await http.post(
            f"{proxy_url}/v1/egress/send",
            json={
                "session_id":         session_id,
                "payload":            payload,
                "recipient_agent_id": recipient_agent_id,
            },
            headers=_headers(api_key),
        )
    if resp.status_code != 200:
        raise EgressError(f"send failed: HTTP {resp.status_code} {resp.text[:300]}")


async def poll_messages(
    proxy_url: str,
    api_key: str,
    session_id: str,
    after: int = -1,
) -> list[dict]:
    """GET /v1/egress/messages/{session_id} — poll for new messages."""
    async with httpx.AsyncClient(timeout=15.0) as http:
        resp = await http.get(
            f"{proxy_url}/v1/egress/messages/{session_id}",
            params={"after": after},
            headers=_headers(api_key),
        )
    if resp.status_code != 200:
        raise EgressError(f"poll failed: HTTP {resp.status_code} {resp.text[:300]}")
    return resp.json().get("messages", [])


async def wait_for_message_with_payload(
    proxy_url: str,
    api_key: str,
    session_id: str,
    expected_marker_key: str,
    expected_marker_value: str,
    timeout_seconds: float = 15.0,
) -> dict:
    """
    Poll until a message with payload[expected_marker_key] == expected_marker_value
    arrives, or fail after `timeout_seconds`.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        msgs = await poll_messages(proxy_url, api_key, session_id, after=-1)
        for m in msgs:
            payload = m.get("payload") or {}
            if payload.get(expected_marker_key) == expected_marker_value:
                return m
        await asyncio.sleep(0.5)
    raise EgressError(
        f"no matching message arrived within {timeout_seconds}s "
        f"(looked for {expected_marker_key}={expected_marker_value!r})"
    )
