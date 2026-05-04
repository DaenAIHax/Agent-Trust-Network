"""
SPIFFE module — bidirectional mapping between internal agent_id and SPIFFE ID.

Standard: https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE-ID.md

Two layouts coexist during the ADR-020 deprecation window:

  Legacy (2-component path):
      spiffe://trust-domain/org/<name>
      → interpreted as principal_type=agent for backward compatibility.

  ADR-020 (3-component path, principal-typed):
      spiffe://trust-domain/org/<principal-type>/<name>
      where <principal-type> ∈ { agent, user, workload }.

The internal format `org::name` is unchanged in either layout. The
``principal_type`` is a separate piece of metadata: derived from the
SPIFFE path when issuing a new cert, recorded next to the agent_id in
the registry, and surfaced in audit rows.

ADR-020 introduces ``Principal`` (org_id, principal_type, name) +
``principal_to_spiffe`` / ``spiffe_to_principal`` that round-trip the
3-component layout. The legacy 2-component helpers
(``agent_id_to_spiffe`` etc.) keep working for code paths that have
not yet migrated; they always emit / accept the legacy layout and
raise on a 3-component path.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlparse

_SPIFFE_SCHEME = "spiffe"

# ADR-020 — recognized principal types. The literal type is duck-checked
# at parse time; new types must be added here AND in the audit /
# policy layers.
PRINCIPAL_TYPES = ("agent", "user", "workload")
PrincipalType = Literal["agent", "user", "workload"]
DEFAULT_PRINCIPAL_TYPE: PrincipalType = "agent"


@dataclass(frozen=True)
class Principal:
    """A Cullis principal: the (org, type, name) triple that uniquely
    identifies an agent, a user or a workload in the network.

    ``agent_id`` is the legacy ``org::name`` text identifier; it does
    NOT encode the principal type, which is carried separately. Two
    principals with the same agent_id but different types are distinct
    entities.
    """
    org_id: str
    principal_type: PrincipalType
    name: str

    @property
    def agent_id(self) -> str:
        """Legacy text identifier. Same shape as before ADR-020."""
        return f"{self.org_id}::{self.name}"

    @property
    def is_agent(self) -> bool:
        return self.principal_type == "agent"

    @property
    def is_user(self) -> bool:
        return self.principal_type == "user"

    @property
    def is_workload(self) -> bool:
        return self.principal_type == "workload"

# Trust domain: lowercase only, digits, hyphens, dots (no underscore per RFC)
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$")

# SPIFFE path components: letters, digits, hyphens, underscores, dots
_PATH_COMPONENT_RE = re.compile(r"^[a-zA-Z0-9\-_\.]+$")


def _validate_trust_domain(trust_domain: str) -> None:
    if not _TRUST_DOMAIN_RE.match(trust_domain):
        raise ValueError(f"Invalid trust domain: '{trust_domain}'")


def _validate_path_component(component: str, name: str) -> None:
    if not component:
        raise ValueError(f"SPIFFE component '{name}' is empty")
    if not _PATH_COMPONENT_RE.match(component):
        raise ValueError(f"SPIFFE component '{name}' contains invalid characters: '{component}'")


def agent_id_to_spiffe(org_id: str, agent_name: str, trust_domain: str) -> str:
    """
    Convert org_id and agent_name into a SPIFFE ID.

    Example:
        agent_id_to_spiffe("manufacturer", "sales-agent", "cullis.local")
        -> "spiffe://cullis.local/manufacturer/sales-agent"
    """
    _validate_trust_domain(trust_domain)
    _validate_path_component(org_id, "org_id")
    _validate_path_component(agent_name, "agent_name")
    return f"spiffe://{trust_domain}/{org_id}/{agent_name}"


def spiffe_to_agent_id(spiffe_id: str) -> tuple[str, str]:
    """
    Convert a SPIFFE ID into (org_id, agent_name).

    Example:
        spiffe_to_agent_id("spiffe://cullis.local/manufacturer/sales-agent")
        -> ("manufacturer", "sales-agent")

    Raises ValueError if the format is invalid.
    """
    validate_spiffe_id(spiffe_id)
    parsed = urlparse(spiffe_id)
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        raise ValueError(
            f"SPIFFE ID path must have exactly 2 components (org/agent), found {len(parts)}"
        )
    org_id, agent_name = parts
    return org_id, agent_name


def internal_id_to_spiffe(agent_id: str, trust_domain: str) -> str:
    """
    Convert the internal format 'org::agent-name' into a SPIFFE ID.

    Example:
        internal_id_to_spiffe("manufacturer::sales-agent", "cullis.local")
        -> "spiffe://cullis.local/manufacturer/sales-agent"

    Raises ValueError if agent_id does not contain '::'.
    """
    parts = agent_id.split("::", 1)
    if len(parts) != 2:
        raise ValueError(
            f"Invalid agent_id format: '{agent_id}' (expected 'org::agent-name')"
        )
    org_id, agent_name = parts
    return agent_id_to_spiffe(org_id, agent_name, trust_domain)


def spiffe_to_internal_id(spiffe_id: str) -> str:
    """
    Convert a SPIFFE ID into the internal format 'org::agent-name'.

    Example:
        spiffe_to_internal_id("spiffe://cullis.local/manufacturer/sales-agent")
        -> "manufacturer::sales-agent"
    """
    org_id, agent_name = spiffe_to_agent_id(spiffe_id)
    return f"{org_id}::{agent_name}"


# ── ADR-020 — principal-typed helpers ─────────────────────────────────


def _validate_principal_type(principal_type: str) -> None:
    if principal_type not in PRINCIPAL_TYPES:
        raise ValueError(
            f"Unknown principal_type '{principal_type}' "
            f"(expected one of {PRINCIPAL_TYPES})"
        )


def principal_to_spiffe(principal: Principal, trust_domain: str) -> str:
    """Render a ``Principal`` as the ADR-020 3-component SPIFFE URI.

    Example:
        principal_to_spiffe(
            Principal("acme", "user", "mario"),
            "acme.test",
        )
        -> "spiffe://acme.test/acme/user/mario"
    """
    _validate_trust_domain(trust_domain)
    _validate_principal_type(principal.principal_type)
    _validate_path_component(principal.org_id, "org_id")
    _validate_path_component(principal.name, "name")
    return (
        f"spiffe://{trust_domain}/{principal.org_id}"
        f"/{principal.principal_type}/{principal.name}"
    )


def spiffe_to_principal(spiffe_id: str) -> Principal:
    """Parse a SPIFFE URI into a ``Principal``.

    Accepts both layouts:

      - 3-component (ADR-020 native): ``spiffe://td/org/<type>/<name>``
        returns ``Principal(org_id=org, principal_type=<type>, name=<name>)``.
      - 2-component (legacy):         ``spiffe://td/org/<name>``
        returns ``Principal(org_id=org, principal_type='agent', name=<name>)``.

    Anything else (0, 1, 4+ segments) raises ValueError.
    """
    validate_spiffe_id(spiffe_id)
    parsed = urlparse(spiffe_id)
    parts = parsed.path.strip("/").split("/")
    if len(parts) == 2:
        org_id, name = parts
        return Principal(
            org_id=org_id,
            principal_type=DEFAULT_PRINCIPAL_TYPE,
            name=name,
        )
    if len(parts) == 3:
        org_id, principal_type, name = parts
        _validate_principal_type(principal_type)
        return Principal(
            org_id=org_id,
            principal_type=principal_type,  # type: ignore[arg-type]
            name=name,
        )
    raise ValueError(
        f"SPIFFE path must have 2 (legacy) or 3 (ADR-020) components, "
        f"got {len(parts)}: '{spiffe_id}'"
    )


def detect_principal_type(spiffe_id: str) -> PrincipalType:
    """Convenience: return only the principal type for a SPIFFE URI.

    Useful in code paths that already parse the SAN elsewhere and only
    need the type for an audit / policy decision.
    """
    return spiffe_to_principal(spiffe_id).principal_type


def parse_spiffe_san(spiffe_uri: str) -> tuple[str, str]:
    """
    Parse a SPIFFE URI and return (trust_domain, path).

    Unlike ``spiffe_to_agent_id``, this does NOT assume a 2-component
    ``org/agent-name`` path — it accepts any non-empty path, which is
    what SPIRE-issued SVIDs look like (e.g.
    ``spiffe://orga.test/workload/agent-a``). The path is returned
    without the leading slash, with internal slashes preserved.

    The last segment of the returned path is typically the usable
    workload/agent name, but that's a caller policy decision.

    Raises ValueError on malformed input.
    """
    validate_spiffe_id(spiffe_uri)
    parsed = urlparse(spiffe_uri)
    path = parsed.path.lstrip("/")
    if not path:
        raise ValueError(f"SPIFFE URI has empty path: '{spiffe_uri}'")
    # Reject empty path components (e.g. "//" in the middle) by validating
    # each one is a legal SPIFFE path component.
    for part in path.split("/"):
        _validate_path_component(part, "path segment")
    return parsed.netloc, path


def validate_spiffe_id(spiffe_id: str) -> bool:
    """
    Validate a SPIFFE ID according to the standard.
    Raises ValueError if invalid.
    Returns True if valid.
    """
    if not spiffe_id:
        raise ValueError("Empty SPIFFE ID")

    parsed = urlparse(spiffe_id)

    if parsed.scheme != _SPIFFE_SCHEME:
        raise ValueError(f"Invalid scheme: '{parsed.scheme}' (expected 'spiffe')")

    if not parsed.netloc:
        raise ValueError("Missing trust domain in SPIFFE ID")

    _validate_trust_domain(parsed.netloc)

    if not parsed.path or parsed.path == "/":
        raise ValueError("Empty SPIFFE path")

    if parsed.query or parsed.fragment:
        raise ValueError("SPIFFE ID must not contain query string or fragment")

    return True
