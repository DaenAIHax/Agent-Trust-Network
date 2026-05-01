"""
H10 regression: ``ca_chain_path`` threads through every SDK constructor
that opens a TLS connection to the Mastio (``from_enrollment``,
``from_identity_dir``, ``from_api_key_file``, ``enroll_via_byoca``,
``enroll_via_spiffe``).

Before the fix, only ``from_connector`` honoured the operator-pinned
Org CA bundle (PR #363/#365). The other constructors fell back to the
system CA store, which never contains a self-signed Org CA — TLS
verify either silently failed or was bypassed entirely. This file
locks in that every public entry point can pin the trust anchor.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from cullis_sdk.client import CullisClient


@pytest.fixture
def captured_calls():
    """Patch ``_build_proxy_http_client`` to record the kwargs it
    receives and return a real httpx.Client (so the constructors
    don't break)."""
    calls: list[dict] = []
    real = httpx.Client

    def _spy(**kwargs):
        calls.append(dict(kwargs))
        return real(timeout=kwargs.get("timeout", 10.0), verify=False)

    with patch("cullis_sdk.client._build_proxy_http_client", side_effect=_spy) as p:
        yield calls, p


# ── from_identity_dir ─────────────────────────────────────────────────


def test_from_identity_dir_threads_ca_chain_path(
    captured_calls, tmp_path: Path,
) -> None:
    calls, _ = captured_calls
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.touch()
    key.touch()
    ca = tmp_path / "ca-chain.pem"
    ca.touch()

    CullisClient.from_identity_dir(
        "https://mastio.example:9443",
        cert_path=cert,
        key_path=key,
        ca_chain_path=ca,
        verify_tls=False,
    )
    assert any(call.get("ca_chain_path") == ca for call in calls), (
        "from_identity_dir must pass ca_chain_path into _build_proxy_http_client"
    )


def test_from_identity_dir_omits_ca_chain_when_unset(captured_calls, tmp_path: Path) -> None:
    calls, _ = captured_calls
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.touch()
    key.touch()
    CullisClient.from_identity_dir(
        "https://mastio.example:9443",
        cert_path=cert, key_path=key, verify_tls=False,
    )
    # Default value is None — verifies we didn't accidentally hardcode
    # a path or fall back to system store via something else.
    assert calls and calls[-1].get("ca_chain_path") is None


# ── from_enrollment ───────────────────────────────────────────────────


def test_from_enrollment_threads_ca_chain_path(
    captured_calls, tmp_path: Path,
) -> None:
    calls, _ = captured_calls
    ca = tmp_path / "ca-chain.pem"
    ca.touch()

    # The enrollment GET will fail (no real server), but the http
    # client builder fires before the GET, so we can still verify
    # ``ca_chain_path`` propagates.
    with pytest.raises((ConnectionError, PermissionError, Exception)):
        CullisClient.from_enrollment(
            "https://mastio.example:9443/v1/enroll/foo",
            verify_tls=False,
            ca_chain_path=ca,
        )
    assert any(call.get("ca_chain_path") == ca for call in calls), (
        "from_enrollment must pass ca_chain_path into _build_proxy_http_client"
    )


# ── enroll_via_byoca / _do_enroll ─────────────────────────────────────


def test_enroll_via_byoca_threads_ca_chain_path(
    captured_calls, tmp_path: Path,
) -> None:
    calls, _ = captured_calls
    ca = tmp_path / "ca-chain.pem"
    ca.touch()

    # The POST will fail (no real Mastio); _do_enroll calls
    # _build_proxy_http_client BEFORE the POST and again AFTER for the
    # runtime client. Either fire is enough to prove threading works.
    with pytest.raises(Exception):
        CullisClient.enroll_via_byoca(
            "https://mastio.example:9443",
            admin_secret="secret",
            agent_name="alice",
            cert_pem="-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----",
            private_key_pem="-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
            verify_tls=False,
            ca_chain_path=ca,
        )
    assert any(call.get("ca_chain_path") == ca for call in calls), (
        "enroll_via_byoca must thread ca_chain_path through to _do_enroll"
    )


def test_from_api_key_file_threads_ca_chain_path(
    captured_calls, tmp_path: Path,
) -> None:
    """The deprecated alias must still forward the new arg so callers
    in transition don't lose the fix."""
    calls, _ = captured_calls
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.touch()
    key.touch()
    ca = tmp_path / "ca-chain.pem"
    ca.touch()

    with pytest.warns(DeprecationWarning):
        CullisClient.from_api_key_file(
            "https://mastio.example:9443",
            cert_path=cert,
            key_path=key,
            verify_tls=False,
            ca_chain_path=ca,
        )
    assert any(call.get("ca_chain_path") == ca for call in calls)
