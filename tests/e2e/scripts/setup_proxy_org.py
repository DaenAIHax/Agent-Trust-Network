"""
E2E helper — provision a Cullis org and/or its first agent inside a
running mcp_proxy container.

Two phases (driven by --phase) because in the real flow the broker
side enforces "org must be approved before any agent registration":

  --phase=org    Register the org with the broker (status=pending),
                 generate Org CA, save broker_url + invite token in
                 proxy_config. Idempotent: re-running on the same DB
                 is a no-op as long as the org_secret is preserved.

  --phase=agent  Create the local internal agent (x509 cert + API key)
                 and call the broker registry endpoints to register
                 the agent + create+approve a binding. Requires the
                 org to already be `active` on the broker side, i.e.
                 the network admin has called approve_org between the
                 two phases.

The two phases share state via the proxy_config table — phase=agent
reads `org_id`, `org_secret`, `org_ca_cert`, `org_ca_key`, `broker_url`
that phase=org persisted.

Output (phase=agent only): single JSON line on stdout with the
credentials the test runner needs to drive the egress API:
    {"org_id": "...", "agent_id": "...", "api_key": "..."}

Usage:
    python /e2e_scripts/setup_proxy_org.py \
        --phase        org \
        --broker-url   http://broker:8000 \
        --invite-token <token> \
        --org-id       acme \
        --display-name "Acme Corp"

    python /e2e_scripts/setup_proxy_org.py \
        --phase        agent \
        --org-id       acme \
        --agent-name   buyer \
        --capabilities procurement.read,procurement.write
"""
import argparse
import asyncio
import json
import os
import secrets
import sys
from typing import Any

# The proxy image installs the codebase under /app
sys.path.insert(0, "/app")

import httpx  # noqa: E402

from mcp_proxy.config import get_settings as _proxy_settings  # noqa: E402
from mcp_proxy.db import init_db, set_config, get_config  # noqa: E402, F401
from mcp_proxy.dashboard.router import generate_org_ca  # noqa: E402
from mcp_proxy.egress.agent_manager import AgentManager  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Phase: register org with broker
# ─────────────────────────────────────────────────────────────────────────────

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


async def _do_phase_org(args: argparse.Namespace) -> None:
    if not args.broker_url:
        print("--phase=org requires --broker-url", file=sys.stderr)
        sys.exit(2)
    if not args.invite_token:
        print("--phase=org requires --invite-token", file=sys.stderr)
        sys.exit(2)
    if not args.display_name:
        print("--phase=org requires --display-name", file=sys.stderr)
        sys.exit(2)

    # Save broker URL + invite token in proxy_config (login equivalent)
    await set_config("broker_url", args.broker_url)
    await set_config("invite_token", args.invite_token)

    # Generate Org CA and persist
    org_secret = secrets.token_urlsafe(32)
    ca_cert_pem, ca_key_pem = generate_org_ca(args.org_id)
    await set_config("org_id", args.org_id)
    await set_config("org_secret", org_secret)
    await set_config("org_ca_cert", ca_cert_pem)
    await set_config("org_ca_key", ca_key_pem)

    # Call broker /onboarding/join
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

    # Returning org_secret here is intentional: the demo orchestrator uses it
    # to print broker dashboard credentials so an audience can log in as the
    # org and explore the architecture. Tests ignore this field.
    print(json.dumps({
        "phase":      "org",
        "org_id":     args.org_id,
        "status":     "registered",
        "org_secret": org_secret,
    }))


# ─────────────────────────────────────────────────────────────────────────────
# Phase: create local agent + register with broker
# ─────────────────────────────────────────────────────────────────────────────

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
        resp = await http.post(
            f"{broker_url}/v1/registry/agents",
            json={
                "agent_id": agent_id,
                "org_id": org_id,
                "display_name": display_name,
                "capabilities": capabilities,
            },
            headers=headers,
        )
        if resp.status_code not in (201, 409):
            raise RuntimeError(
                f"register_agent failed: HTTP {resp.status_code} {resp.text[:300]}"
            )

        # 2. Create binding
        resp = await http.post(
            f"{broker_url}/v1/registry/bindings",
            json={"org_id": org_id, "agent_id": agent_id, "scope": capabilities},
            headers=headers,
        )
        if resp.status_code not in (201, 409):
            raise RuntimeError(
                f"create_binding failed: HTTP {resp.status_code} {resp.text[:300]}"
            )

        # 3. Approve binding (only meaningful when we just created it)
        if resp.status_code == 201:
            binding_id = resp.json().get("id")
            if binding_id:
                approve_resp = await http.post(
                    f"{broker_url}/v1/registry/bindings/{binding_id}/approve",
                    headers=headers,
                )
                if approve_resp.status_code not in (200, 204):
                    raise RuntimeError(
                        f"approve_binding failed: HTTP {approve_resp.status_code} "
                        f"{approve_resp.text[:300]}"
                    )


async def _do_phase_agent(args: argparse.Namespace) -> None:
    if not args.agent_name:
        print("--phase=agent requires --agent-name", file=sys.stderr)
        sys.exit(2)
    if not args.capabilities:
        print("--phase=agent requires --capabilities", file=sys.stderr)
        sys.exit(2)

    capabilities = [c.strip() for c in args.capabilities.split(",") if c.strip()]

    # Pull state stashed by phase=org
    broker_url = await get_config("broker_url") or args.broker_url
    org_secret = await get_config("org_secret") or ""
    if not broker_url or not org_secret:
        print(json.dumps({
            "error": "phase=agent requires phase=org to have run first "
                     "(broker_url and org_secret missing from proxy_config)",
        }), file=sys.stderr)
        sys.exit(3)

    # Create local agent (x509 + API key)
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

    # Belt-and-braces: AgentManager.create_agent already calls
    # _register_with_broker, but it swallows non-2xx responses. Repeat
    # the call here so any failure surfaces as a script error instead
    # of a confusing 401 later when the agent tries to login.
    await _bind_agent_to_broker(
        broker_url=broker_url,
        org_id=args.org_id,
        org_secret=org_secret,
        agent_id=agent_id,
        display_name=f"E2E {args.agent_name}",
        capabilities=capabilities,
    )

    print(json.dumps({
        "phase":    "agent",
        "org_id":   args.org_id,
        "agent_id": agent_id,
        "api_key":  raw_key,
    }))


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=["org", "agent"])
    parser.add_argument("--org-id", required=True)
    # phase=org args
    parser.add_argument("--broker-url",   default="")
    parser.add_argument("--invite-token", default="")
    parser.add_argument("--display-name", default="")
    parser.add_argument("--pdp-url",      default="",
                        help="PDP webhook URL — defaults to MCP_PROXY_PDP_URL env")
    # phase=agent args
    parser.add_argument("--agent-name",   default="")
    parser.add_argument("--capabilities", default="",
                        help="comma-separated list (phase=agent)")
    args = parser.parse_args()

    # Init DB schema — read DB path from the same env var the proxy
    # main process uses (MCP_PROXY_DATABASE_URL).
    await init_db(_proxy_settings().database_url)

    if args.phase == "org":
        await _do_phase_org(args)
    elif args.phase == "agent":
        await _do_phase_agent(args)


if __name__ == "__main__":
    asyncio.run(main())
