"""``KMSProvider`` protocol — Mastio Org CA persistence backend.

Today the protocol is intentionally narrow: load + store the Org CA
keypair as PEM strings. That is enough to route the keys through any
cloud KMS, Secrets Manager, or HSM that exposes a "give me the wrapped
private material" surface. A future Phase 2 will add a sign-only
interface (``sign(message, hash_alg)``) for HSM-backed keys that
never leave the device.

Implementations live in :mod:`mcp_proxy.kms.local` (default) and in
``cullis_enterprise.mastio.cloud_kms_*`` (proprietary providers).
"""
from typing import Protocol, runtime_checkable


@runtime_checkable
class KMSProvider(Protocol):
    """Persistence backend for the Mastio Org CA keypair."""

    async def load_org_ca(self) -> tuple[str, str] | None:
        """Return ``(key_pem, cert_pem)`` if the Org CA has been stored.

        Returns ``None`` when the CA has never been generated (first
        boot in standalone mode, or before the attach-ca flow on a
        federated deploy).
        """
        ...

    async def store_org_ca(self, key_pem: str, cert_pem: str) -> None:
        """Persist a freshly generated Org CA keypair + cert.

        Implementations must be idempotent on identical inputs and must
        replace any earlier value atomically.
        """
        ...
