"""Build an A2A AgentCard from a Cullis registry record.

The AgentCard is the public discovery document A2A peers fetch before
calling an agent. Per ADR-002 §2.5 the Cullis broker hosts AgentCards
at `/v1/a2a/agents/{org_id}/{agent_id}/.well-known/agent.json` and
aggregates them at `/v1/a2a/directory`.

Phase 2a only emits AgentCards. SendMessage / streaming endpoints land
in Phase 2b/2c — until then the `url` field points at the future
endpoint base so the schema is stable, but calls would 404 today (which
is documented behavior for an agent that advertises no callable
methods).
"""
from __future__ import annotations

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentExtension,
    AgentProvider,
    AgentSkill,
)

from app.registry.store import AgentRecord


# ADR-002 §4 — single Cullis extension URI. Sub-features are advertised
# via params.sub_features; Phase 3 wires the actual implementations.
CULLIS_EXTENSION_URI = "https://cullis.io/a2a/cullis-trust/v1"
CULLIS_E2E_MEDIATYPE = "application/vnd.cullis.e2e+json"


def build_agent_card(
    agent: AgentRecord,
    *,
    base_url: str,
    trust_domain: str,
    advertise_extension: bool = True,
) -> AgentCard:
    """Build an A2A AgentCard for a Cullis-registered agent.

    Args:
        agent: the broker registry record.
        base_url: public broker URL (e.g. "https://broker.acme.com"); used
            to compose the agent's callable endpoint URL.
        trust_domain: SPIFFE trust domain, advertised as an extension param.
        advertise_extension: when False, omit the cullis-trust/v1 entry
            (useful for testing baseline-A2A peer behavior).

    Returns:
        AgentCard ready to JSON-serialize.
    """
    skills = [
        AgentSkill(
            id=cap,
            name=cap,
            description=f"Cullis capability: {cap}",
            tags=[cap.split(".")[0]] if "." in cap else [],
        )
        for cap in agent.capabilities
    ]
    if not skills:
        # A2A spec requires at least one skill. Surface a synthetic
        # "general" skill when the agent declared none in Cullis registry.
        skills = [
            AgentSkill(
                id="general",
                name="general",
                description="No declared capabilities — general agent",
                tags=[],
            )
        ]

    extensions: list[AgentExtension] = []
    if advertise_extension:
        spiffe_uri = f"spiffe://{trust_domain}/{agent.org_id}/{agent.agent_id.split('::', 1)[-1]}"
        extensions.append(
            AgentExtension(
                uri=CULLIS_EXTENSION_URI,
                description=(
                    "Cullis trust extension — SPIFFE identity, DPoP, E2E, "
                    "non-repudiation signatures, hash-chain audit, BYO-CA "
                    "federation, at-least-once delivery. Sub-features in "
                    "params.sub_features are negotiable per-call."
                ),
                required=False,
                params={
                    "sub_features": [
                        # Phase 2a advertises capability — implementation
                        # lands in Phase 3. Peers should treat this as a
                        # signal of intent, not a guarantee.
                        "spiffe-identity",
                    ],
                    "spiffe_id": spiffe_uri,
                    "trust_domain": trust_domain,
                    "phase": "2a-discovery-only",
                },
            )
        )

    capabilities = AgentCapabilities(
        streaming=False,  # Phase 2c will flip this when streaming lands
        push_notifications=False,
        extensions=extensions,
    )

    callable_url = f"{base_url.rstrip('/')}/v1/a2a/agents/{agent.org_id}/{agent.agent_id.split('::', 1)[-1]}"

    return AgentCard(
        name=agent.agent_id,
        description=agent.description or f"Cullis-managed agent {agent.agent_id}",
        version=getattr(agent, "version", None) or "1.0.0",
        url=callable_url,
        protocol_version="0.3.0",
        provider=AgentProvider(
            organization=agent.org_id,
            url=base_url.rstrip("/"),
        ),
        capabilities=capabilities,
        default_input_modes=["text/plain", CULLIS_E2E_MEDIATYPE],
        default_output_modes=["text/plain", CULLIS_E2E_MEDIATYPE],
        skills=skills,
    )
