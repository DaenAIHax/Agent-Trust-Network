"""REST endpoints for the user_principals mapping (ADR-021 PR2).

The Cullis Frontdesk Ambassador (PR4) is the primary caller. On
every authenticated user request it needs to map an SSO subject
back to its Cullis principal_id; this endpoint is the lookup.

PR2 ships only the ``GET /v1/principals/by-sso`` lookup. Provisioning
endpoints (POST + cert-attach) will land alongside the Ambassador
in PR4 — that PR drives both ends of the API and shape choices.

Authentication uses the existing ``Depends(get_current_agent)``
DPoP-bound JWT. RBAC: the caller may only look up principals in
its own ``org_id``. Cross-org SSO lookups are forbidden because
SSO subjects are per-org PII; cross-org user federation has its
own discovery story (deferred to ADR-020 v0.5).
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.db.database import get_db
from app.registry.user_principals import (
    UserPrincipalView,
    get_by_sso,
)

_log = logging.getLogger("agent_trust")

router = APIRouter(prefix="/principals", tags=["principals"])


class UserPrincipalResponse(BaseModel):
    """Public projection of a UserPrincipalRecord.

    ``kms_key_handle`` is included because the Ambassador uses it
    for log correlation; it is opaque, not a secret.
    """

    principal_id: str = Field(...)
    org_id: str = Field(...)
    sso_subject: str = Field(...)
    display_name: Optional[str] = Field(default=None)
    cert_thumbprint: Optional[str] = Field(default=None)
    cert_not_after: Optional[datetime] = Field(default=None)
    kms_backend: str = Field(...)
    kms_key_handle: str = Field(...)
    provisioned_at: datetime = Field(...)
    last_active_at: Optional[datetime] = Field(default=None)
    revoked_at: Optional[datetime] = Field(default=None)
    is_active: bool = Field(...)
    is_provisioned: bool = Field(...)


def _to_response(view: UserPrincipalView) -> UserPrincipalResponse:
    return UserPrincipalResponse(
        principal_id=view.principal_id,
        org_id=view.org_id,
        sso_subject=view.sso_subject,
        display_name=view.display_name,
        cert_thumbprint=view.cert_thumbprint,
        cert_not_after=view.cert_not_after,
        kms_backend=view.kms_backend,
        kms_key_handle=view.kms_key_handle,
        provisioned_at=view.provisioned_at,
        last_active_at=view.last_active_at,
        revoked_at=view.revoked_at,
        is_active=view.is_active,
        is_provisioned=view.is_provisioned,
    )


@router.get("/by-sso", response_model=UserPrincipalResponse)
async def lookup_by_sso(
    org: str = Query(..., min_length=1, max_length=128, description="Org id"),
    subject: str = Query(
        ..., min_length=1, max_length=255,
        description="SSO subject (e.g. 'mario@acme.it')",
    ),
    db: AsyncSession = Depends(get_db),
    token: TokenPayload = Depends(get_current_agent),
) -> UserPrincipalResponse:
    """Look up a user principal by SSO subject within an org.

    404 if no mapping exists. 403 if the caller's org differs from
    the requested ``org`` (cross-org SSO lookups are forbidden).
    """
    if token.org != org:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="cannot look up SSO subjects in a different org",
        )

    view = await get_by_sso(db, org_id=org, sso_subject=subject)
    if view is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"no principal mapped to sso_subject={subject!r} in org={org!r}",
        )
    return _to_response(view)
