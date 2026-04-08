"""
E2E helper — provision an org + agent inside a running mcp_proxy container.

Usage (executed via `docker compose exec`):
    python /e2e_scripts/setup_proxy_org.py \
        --broker-url   http://broker:8000 \
        --invite-token <token> \
        --org-id       acme \
        --display-name "Acme Corp" \
        --agent-name   buyer \
        --capabilities procurement.read,procurement.write

The script:
  1. Stores broker URL + invite token in proxy_config (mimics dashboard login)
  2. Generates an Org CA (RSA-4096) and stores it in proxy_config
  3. Calls broker /v1/onboarding/join (mimics dashboard /proxy/register submit)
  4. Creates the agent via AgentManager (x509 cert + API key + broker bind)
  5. Prints a JSON document on stdout:
       {"org_id": "...", "agent_id": "...", "api_key": "..."}

We do NOT touch HTML/CSRF — the proxy's database and Python modules are
imported directly. This avoids brittle HTML scraping in the test runner.
"""
import argparse
import asyncio
import json
import sys
import secrets
from typing import Any

# The proxy image installs the codebase under /app
sys.path.insert(0, "/app")

import httpx  # noqa: E402

from mcp_proxy.db import init_db, set_config, get_config  # noqa: E402, F401
from mcp_proxy.dashboard.router import generate_org_ca  # noqa: E402
from mcp_proxy.egress.agent_manager import AgentManager  # noqa: E402


async def _register_org_with_broker(
    broker_url: str,
    invite_token: str,
    org_id: str,
    display_name: str,
    secret: str,
    ca_pem: str,
    webhook_url: str,
) -> dict[str, Any]:
    """POST /v1/onboarding/join — same call the dashboard register endpoint makes."""
    async with httpx.AsyncClient(verify=False, timeout=15.0) as http:
        resp = await http.post(
            f"{broker_url}/v1/onboarding/join",
            json={
                "org_id": org_id,
                "display_name": display_name,
                "secret": secret,
                "ca_certificate": ca_pem,
                "contact_email": f"e2e+{org_id}@example.test",
                "webhook_url": webhook_url,
                "invite_token": invite_token,
            },
        )
    return {"status_code": resp.status_code, "body": resp.text[:500]}


async def _bind_agent_to_broker(
    broker_url: str,
    org_id: str,
    org_secret: str,
    agent_id: str,
    display_name: str,
    capabilities: list[str],
) -> None:
    """Register agent + create binding + auto-approve. Idempotent on 409."""
    headers = {"X-Org-Id": org_id, "X-Org-Secret": org_secret}
    async with httpx.AsyncClient(verify=False, timeout=15.0) as http:
        # 1. Register agent
        await http.post(
            f"{broker_url}/v1/registry/agents",
            json={
                "agent_id": agent_id,
                "org_id": org_id,
                "display_name": display_name,
                "capabilities": capabilities,
            },
            headers=headers,
        )
        # 2. Create binding
        resp = await http.post(
            f"{broker_url}/v1/registry/bindings",
            json={"org_id": org_id, "agent_id": agent_id, "scope": capabilities},
            headers=headers,
        )
        # 3. Approve binding
        if resp.status_code == 201:
            binding_id = resp.json().get("id")
            if binding_id:
                await http.post(
                    f"{broker_url}/v1/registry/bindings/{binding_id}/approve",
                    headers=headers,
                )


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--broker-url",   required=True)
    parser.add_argument("--invite-token", required=True)
    parser.add_argument("--org-id",       required=True)
    parser.add_argument("--display-name", required=True)
    parser.add_argument("--agent-name",   required=True)
    parser.add_argument("--capabilities", required=True,
                        help="comma-separated list")
    parser.add_argument("--pdp-url", default="",
                        help="PDP webhook URL — defaults to MCP_PROXY_PDP_URL env")
    args = parser.parse_args()

    capabilities = [c.strip() for c in args.capabilities.split(",") if c.strip()]

    # 1. Init DB schema
    await init_db()

    # 2. Save broker URL + invite token in proxy_config (login equivalent)
    await set_config("broker_url", args.broker_url)
    await set_config("invite_token", args.invite_token)

    # 3. Generate Org CA and persist
    org_secret = secrets.token_urlsafe(32)
    ca_cert_pem, ca_key_pem = generate_org_ca(args.org_id)
    await set_config("org_id", args.org_id)
    await set_config("org_secret", org_secret)
    await set_config("org_ca_cert", ca_cert_pem)
    await set_config("org_ca_key", ca_key_pem)

    # 4. Call broker /onboarding/join
    import os
    webhook_url = args.pdp_url or os.environ.get("MCP_PROXY_PDP_URL", "")
    join_result = await _register_org_with_broker(
        broker_url=args.broker_url,
        invite_token=args.invite_token,
        org_id=args.org_id,
        display_name=args.display_name,
        secret=org_secret,
        ca_pem=ca_cert_pem,
        webhook_url=webhook_url,
    )
    if join_result["status_code"] not in (201, 202):
        print(json.dumps({
            "error": "broker /onboarding/join failed",
            "details": join_result,
        }), file=sys.stderr)
        sys.exit(2)
    await set_config("org_status", "pending")

    # 5. Create agent (x509 + API key + Vault/DB key storage)
    mgr = AgentManager(org_id=args.org_id)
    if not await mgr.load_org_ca_from_config():
        print(json.dumps({"error": "Org CA load from config failed"}), file=sys.stderr)
        sys.exit(3)

    agent_info, raw_key = await mgr.create_agent(
        args.agent_name,
        f"E2E {args.agent_name}",
        capabilities,
    )
    agent_id = agent_info["agent_id"]

    # 6. Bind the agent to the broker side (registry + binding + approve)
    await _bind_agent_to_broker(
        broker_url=args.broker_url,
        org_id=args.org_id,
        org_secret=org_secret,
        agent_id=agent_id,
        display_name=f"E2E {args.agent_name}",
        capabilities=capabilities,
    )

    # 7. Output the credentials needed by the test runner
    print(json.dumps({
        "org_id":   args.org_id,
        "agent_id": agent_id,
        "api_key":  raw_key,
    }))


if __name__ == "__main__":
    asyncio.run(main())
