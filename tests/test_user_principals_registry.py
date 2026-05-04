"""Tests for ``app/registry/user_principals.py`` + the by-sso endpoint
(ADR-021 PR2).

Two layers:
  - CRUD tests against an in-memory SQLite session (db_session fixture
    from conftest)
  - Endpoint tests against the FastAPI app, with the auth dependency
    overridden so we don't need a full DPoP token roundtrip
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from sqlalchemy import delete

from app.auth.jwt import get_current_agent
from app.auth.models import TokenPayload
from app.main import app
from app.registry.user_principals import (
    DuplicatePrincipalError,
    UserPrincipalRecord,
    attach_cert,
    create,
    get_by_principal_id,
    get_by_sso,
    mark_revoked,
    update_last_active,
)

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture
async def upd_db(db_session):
    """Truncate user_principals around each test for isolation."""
    await db_session.execute(delete(UserPrincipalRecord))
    await db_session.commit()
    yield db_session
    await db_session.execute(delete(UserPrincipalRecord))
    await db_session.commit()


# ── create (4 tests) ──────────────────────────────────────────────


async def test_create_happy_path(upd_db):
    view = await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="embedded:acme.test/acme/user/mario",
        display_name="Mario Rossi",
    )
    await upd_db.commit()
    assert view.principal_id == "acme.test/acme/user/mario"
    assert view.org_id == "acme"
    assert view.sso_subject == "mario@acme.it"
    assert view.display_name == "Mario Rossi"
    assert view.kms_backend == "embedded"
    assert view.cert_thumbprint is None
    assert view.is_active is True
    assert view.is_provisioned is False  # cert not attached yet


async def test_create_duplicate_principal_id_raises(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    await upd_db.commit()
    with pytest.raises(DuplicatePrincipalError):
        await create(
            upd_db,
            principal_id="acme.test/acme/user/mario",  # same PK
            org_id="acme",
            sso_subject="someone-else@acme.it",
            kms_backend="embedded",
            kms_key_handle="h2",
        )


async def test_create_duplicate_org_sso_raises(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    await upd_db.commit()
    with pytest.raises(DuplicatePrincipalError):
        await create(
            upd_db,
            principal_id="acme.test/acme/user/mario-2",  # different PK
            org_id="acme",
            sso_subject="mario@acme.it",  # same (org, sso)
            kms_backend="embedded",
            kms_key_handle="h2",
        )


async def test_create_missing_field_raises(upd_db):
    with pytest.raises(ValueError):
        await create(
            upd_db,
            principal_id="acme.test/acme/user/mario",
            org_id="",  # empty
            sso_subject="mario@acme.it",
            kms_backend="embedded",
            kms_key_handle="h1",
        )


# ── lookup (4 tests) ──────────────────────────────────────────────


async def test_get_by_principal_id_existing(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    view = await get_by_principal_id(upd_db, "acme.test/acme/user/mario")
    assert view is not None
    assert view.sso_subject == "mario@acme.it"


async def test_get_by_principal_id_missing_returns_none(upd_db):
    assert await get_by_principal_id(upd_db, "acme.test/acme/user/ghost") is None


async def test_get_by_sso_existing(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    view = await get_by_sso(upd_db, org_id="acme", sso_subject="mario@acme.it")
    assert view is not None
    assert view.principal_id == "acme.test/acme/user/mario"


async def test_get_by_sso_missing_returns_none(upd_db):
    view = await get_by_sso(
        upd_db, org_id="acme", sso_subject="ghost@acme.it",
    )
    assert view is None


# ── attach_cert (4 tests) ─────────────────────────────────────────


async def test_attach_cert_happy_path(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    not_after = datetime.now(timezone.utc) + timedelta(hours=1)
    view = await attach_cert(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        cert_thumbprint="a" * 64,
        cert_not_after=not_after,
    )
    assert view is not None
    assert view.cert_thumbprint == "a" * 64
    assert view.is_provisioned is True


async def test_attach_cert_missing_principal_returns_none(upd_db):
    not_after = datetime.now(timezone.utc) + timedelta(hours=1)
    view = await attach_cert(
        upd_db,
        principal_id="acme.test/acme/user/ghost",
        cert_thumbprint="a" * 64,
        cert_not_after=not_after,
    )
    assert view is None


async def test_attach_cert_idempotent_rotation(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    not_after = datetime.now(timezone.utc) + timedelta(hours=1)
    await attach_cert(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        cert_thumbprint="a" * 64,
        cert_not_after=not_after,
    )
    new_after = datetime.now(timezone.utc) + timedelta(hours=2)
    view = await attach_cert(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        cert_thumbprint="b" * 64,
        cert_not_after=new_after,
    )
    assert view is not None
    assert view.cert_thumbprint == "b" * 64


async def test_attach_cert_too_long_thumbprint_raises(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    with pytest.raises(ValueError, match="64"):
        await attach_cert(
            upd_db,
            principal_id="acme.test/acme/user/mario",
            cert_thumbprint="a" * 65,
            cert_not_after=datetime.now(timezone.utc),
        )


# ── revoke / activity (4 tests) ───────────────────────────────────


async def test_mark_revoked_sets_revoked_at(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    view = await mark_revoked(upd_db, "acme.test/acme/user/mario")
    assert view is not None
    assert view.revoked_at is not None
    assert view.is_active is False


async def test_mark_revoked_idempotent(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    first = await mark_revoked(upd_db, "acme.test/acme/user/mario")
    second = await mark_revoked(upd_db, "acme.test/acme/user/mario")
    assert first is not None and second is not None
    # The timestamp must NOT advance on the second revoke.
    assert first.revoked_at == second.revoked_at


async def test_mark_revoked_missing_principal_returns_none(upd_db):
    view = await mark_revoked(upd_db, "acme.test/acme/user/ghost")
    assert view is None


async def test_update_last_active_silent_on_missing(upd_db):
    # Must not raise even when the principal doesn't exist.
    await update_last_active(upd_db, "acme.test/acme/user/ghost")


async def test_update_last_active_touches_column(upd_db):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    when = datetime.now(timezone.utc)
    await update_last_active(upd_db, "acme.test/acme/user/mario", when=when)
    view = await get_by_principal_id(upd_db, "acme.test/acme/user/mario")
    assert view is not None
    assert view.last_active_at is not None


# ── /v1/principals/by-sso endpoint (5 tests) ──────────────────────


def _override_token(*, agent_id: str, org: str) -> TokenPayload:
    return TokenPayload(
        sub=f"spiffe://cullis.test/{org}/agent/{agent_id.split('::', 1)[-1]}",
        agent_id=agent_id,
        org=org,
        exp=2_000_000_000,
        iat=1_700_000_000,
        jti="test-jti",
        scope=[],
        cnf={"jkt": "x" * 43},
    )


@pytest_asyncio.fixture
async def auth_as_acme(upd_db):
    """Override get_current_agent so endpoint tests don't need DPoP."""
    app.dependency_overrides[get_current_agent] = (
        lambda: _override_token(agent_id="acme::frontdesk", org="acme")
    )
    yield
    app.dependency_overrides.pop(get_current_agent, None)


@pytest_asyncio.fixture
async def auth_as_globex(upd_db):
    app.dependency_overrides[get_current_agent] = (
        lambda: _override_token(agent_id="globex::frontdesk", org="globex")
    )
    yield
    app.dependency_overrides.pop(get_current_agent, None)


async def test_by_sso_endpoint_200(upd_db, client, auth_as_acme):
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
        display_name="Mario Rossi",
    )
    await upd_db.commit()

    r = await client.get(
        "/v1/principals/by-sso",
        params={"org": "acme", "subject": "mario@acme.it"},
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["principal_id"] == "acme.test/acme/user/mario"
    assert data["sso_subject"] == "mario@acme.it"
    assert data["display_name"] == "Mario Rossi"
    assert data["is_active"] is True
    assert data["is_provisioned"] is False  # no cert yet


async def test_by_sso_endpoint_404(upd_db, client, auth_as_acme):
    r = await client.get(
        "/v1/principals/by-sso",
        params={"org": "acme", "subject": "ghost@acme.it"},
    )
    assert r.status_code == 404


async def test_by_sso_endpoint_403_cross_org(upd_db, client, auth_as_globex):
    # Caller is globex agent; trying to read acme mappings.
    await create(
        upd_db,
        principal_id="acme.test/acme/user/mario",
        org_id="acme",
        sso_subject="mario@acme.it",
        kms_backend="embedded",
        kms_key_handle="h1",
    )
    await upd_db.commit()

    r = await client.get(
        "/v1/principals/by-sso",
        params={"org": "acme", "subject": "mario@acme.it"},
    )
    assert r.status_code == 403


async def test_by_sso_endpoint_422_missing_subject(upd_db, client, auth_as_acme):
    r = await client.get(
        "/v1/principals/by-sso",
        params={"org": "acme"},
    )
    assert r.status_code == 422


async def test_by_sso_endpoint_422_missing_org(upd_db, client, auth_as_acme):
    r = await client.get(
        "/v1/principals/by-sso",
        params={"subject": "mario@acme.it"},
    )
    assert r.status_code == 422
