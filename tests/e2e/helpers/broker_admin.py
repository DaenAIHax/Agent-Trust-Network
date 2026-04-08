"""
Broker admin helpers for the E2E test runner.

These functions hit the public REST API of the broker (no dashboard,
no HTML scraping). They run from the host against the broker exposed
on http://localhost:18000 (see tests/e2e/conftest.py).
"""
import httpx


class BrokerAdminError(RuntimeError):
    pass


async def generate_invite_token(
    broker_url: str,
    admin_secret: str,
    label: str,
    ttl_hours: int = 1,
) -> str:
    """
    POST /v1/admin/invites — returns the plaintext invite token.

    The token is shown ONCE in the response; the broker stores only a hash.
    Used by the e2e test to onboard each org via the proxy.
    """
    async with httpx.AsyncClient(verify=False, timeout=10.0) as http:
        resp = await http.post(
            f"{broker_url}/v1/admin/invites",
            headers={"X-Admin-Secret": admin_secret},
            json={"label": label, "ttl_hours": ttl_hours},
        )
    if resp.status_code != 201:
        raise BrokerAdminError(
            f"invite create failed: HTTP {resp.status_code} {resp.text[:300]}"
        )
    data = resp.json()
    token = data.get("token")
    if not token:
        raise BrokerAdminError(f"invite response has no token: {data}")
    return token


async def approve_org(
    broker_url: str,
    admin_secret: str,
    org_id: str,
) -> None:
    """
    POST /v1/admin/orgs/{org_id}/approve — flip a pending org to active.

    The proxy registers the org as `pending`; the network admin must
    approve it before any agent can authenticate.

    Idempotent: HTTP 409 ("already active") is treated as success.
    """
    async with httpx.AsyncClient(verify=False, timeout=10.0) as http:
        resp = await http.post(
            f"{broker_url}/v1/admin/orgs/{org_id}/approve",
            headers={"X-Admin-Secret": admin_secret},
        )
    if resp.status_code in (200, 204, 409):
        return
    raise BrokerAdminError(
        f"approve org failed: HTTP {resp.status_code} {resp.text[:300]}"
    )
