"""ADR-012 §3 — JWKS endpoint for the Mastio local issuer.

Exposes the Mastio public keys as a JWKS document so intra-org
validators (Mastio-side middleware, MCP aggregator, local session
store) can verify tokens without a remote round-trip.

The endpoint is served unauthenticated by design — it publishes public
key material only, mirrors the /.well-known/jwks.json pattern used
by the broker, and is read by internal components sharing the same
FastAPI process.

Phase 2.2 shift: the endpoint now enumerates every key the keystore
still accepts for verification (active + deprecated-but-within-grace),
not just the single active signer. During a rotation grace window this
lets an in-flight consumer that has cached the old ``kid`` re-fetch
the JWKS and still find the old key — without this, a rotate immediately
invalidates every token already in flight even though the keystore
would happily verify them internally.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

router = APIRouter(tags=["auth"])


@router.get(
    "/.well-known/jwks-local.json",
    summary="JWKS for the Mastio local issuer (intra-org tokens)",
)
async def jwks_local(request: Request) -> dict:
    keystore = getattr(request.app.state, "local_keystore", None)
    if keystore is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="local keystore not initialized",
        )
    keys = await keystore.all_valid_keys()
    if not keys:
        # Empty keystore means Mastio identity hasn't been ensured yet
        # (lifespan didn't complete or migration ran but no row exists).
        # 503 is more actionable than `{"keys": []}` for the caller.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="no mastio signing keys available",
        )
    return {"keys": [k.jwk() for k in keys]}
