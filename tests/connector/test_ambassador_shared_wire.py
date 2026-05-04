"""Tests for the shared-mode bootstrap helpers (ADR-021 PR4c).

Pure unit coverage of ``cullis_connector/ambassador/shared/wire.py``:
cookie-secret bootstrap + env-var validation. The full end-to-end
wiring through ``web.py`` lives in PR5's sandbox smoke.
"""
from __future__ import annotations

import os
import stat

import pytest

from cullis_connector.ambassador.shared.wire import (
    COOKIE_SECRET_FILENAME,
    DEFAULT_COOKIE_TTL,
    DEFAULT_TRUSTED_PROXIES,
    ENV_COOKIE_TTL,
    ENV_MASTIO_URL,
    ENV_MODE,
    ENV_ORG_ID,
    ENV_TRUST_DOMAIN,
    ENV_TRUSTED_PROXIES,
    SECRET_LEN_BYTES,
    bootstrap_cookie_secret,
    shared_mode_settings_from_env,
)


# ── bootstrap_cookie_secret (4 tests) ─────────────────────────────


def test_bootstrap_generates_on_first_call(tmp_path):
    secret = bootstrap_cookie_secret(tmp_path)
    assert len(secret) == SECRET_LEN_BYTES
    assert (tmp_path / COOKIE_SECRET_FILENAME).exists()


def test_bootstrap_reuses_existing(tmp_path):
    a = bootstrap_cookie_secret(tmp_path)
    b = bootstrap_cookie_secret(tmp_path)
    assert a == b


def test_bootstrap_regenerates_if_corrupted(tmp_path):
    bootstrap_cookie_secret(tmp_path)
    (tmp_path / COOKIE_SECRET_FILENAME).write_bytes(b"too-short")
    fresh = bootstrap_cookie_secret(tmp_path)
    assert len(fresh) == SECRET_LEN_BYTES
    assert fresh != b"too-short"


def test_bootstrap_file_mode_0600(tmp_path):
    bootstrap_cookie_secret(tmp_path)
    mode = os.stat(tmp_path / COOKIE_SECRET_FILENAME).st_mode & 0o777
    assert mode == stat.S_IRUSR | stat.S_IWUSR  # 0o600


# ── shared_mode_settings_from_env (8 tests) ───────────────────────


def test_settings_default_is_disabled():
    s = shared_mode_settings_from_env(env={})
    assert s.enabled is False


def test_settings_single_mode_explicitly_disabled():
    s = shared_mode_settings_from_env(env={ENV_MODE: "single"})
    assert s.enabled is False


def test_settings_shared_happy_path():
    s = shared_mode_settings_from_env(env={
        ENV_MODE: "shared",
        ENV_ORG_ID: "acme",
        ENV_TRUST_DOMAIN: "acme.test",
    })
    assert s.enabled is True
    assert s.org_id == "acme"
    assert s.trust_domain == "acme.test"
    assert s.cookie_ttl_seconds == DEFAULT_COOKIE_TTL
    assert s.trusted_proxies_cidrs == tuple(
        c.strip() for c in DEFAULT_TRUSTED_PROXIES.split(",")
    )


def test_settings_missing_org_id_raises():
    with pytest.raises(ValueError, match=ENV_ORG_ID):
        shared_mode_settings_from_env(env={
            ENV_MODE: "shared",
            ENV_TRUST_DOMAIN: "acme.test",
        })


def test_settings_missing_trust_domain_raises():
    with pytest.raises(ValueError, match=ENV_TRUST_DOMAIN):
        shared_mode_settings_from_env(env={
            ENV_MODE: "shared",
            ENV_ORG_ID: "acme",
        })


def test_settings_custom_proxies_and_ttl():
    s = shared_mode_settings_from_env(env={
        ENV_MODE: "shared",
        ENV_ORG_ID: "acme",
        ENV_TRUST_DOMAIN: "acme.test",
        ENV_TRUSTED_PROXIES: "10.0.0.0/8, 192.168.0.0/16",
        ENV_COOKIE_TTL: "1800",
        ENV_MASTIO_URL: "https://mastio.acme.test:9443/",
    })
    assert s.trusted_proxies_cidrs == ("10.0.0.0/8", "192.168.0.0/16")
    assert s.cookie_ttl_seconds == 1800
    assert s.mastio_url == "https://mastio.acme.test:9443"  # trailing slash stripped


def test_settings_invalid_ttl_raises():
    with pytest.raises(ValueError, match=ENV_COOKIE_TTL):
        shared_mode_settings_from_env(env={
            ENV_MODE: "shared",
            ENV_ORG_ID: "acme",
            ENV_TRUST_DOMAIN: "acme.test",
            ENV_COOKIE_TTL: "0",
        })


def test_settings_non_int_ttl_raises():
    with pytest.raises(ValueError, match=ENV_COOKIE_TTL):
        shared_mode_settings_from_env(env={
            ENV_MODE: "shared",
            ENV_ORG_ID: "acme",
            ENV_TRUST_DOMAIN: "acme.test",
            ENV_COOKIE_TTL: "not-an-int",
        })


def test_settings_empty_proxies_raises():
    with pytest.raises(ValueError, match=ENV_TRUSTED_PROXIES):
        shared_mode_settings_from_env(env={
            ENV_MODE: "shared",
            ENV_ORG_ID: "acme",
            ENV_TRUST_DOMAIN: "acme.test",
            ENV_TRUSTED_PROXIES: " , , ",
        })
