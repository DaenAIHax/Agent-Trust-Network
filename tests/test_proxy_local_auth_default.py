"""local_auth_enabled auto-default decoupled from standalone (issue #458).

Pre-fix: ``local_auth_enabled`` flipped on automatically only when
``MCP_PROXY_STANDALONE=true``. Federated Mastios (``standalone=false``,
``MCP_PROXY_BROKER_URL`` set) defaulted to forwarding ``/v1/auth/token``
to Court, which permanently 401s on DPoP htu mismatch.

Post-fix: the auto-flip ignores ``standalone`` and only checks for an
explicit env override. ADR-012 already says the Mastio is the local
token issuer for intra-org auth; ``standalone`` only controls cross-org
federation, an orthogonal concern.

This test file pins the matrix:

  | scenario                                  | local_auth_enabled |
  |-------------------------------------------|--------------------|
  | standalone, no env override               | True (regression)  |
  | federated (broker_url set), no override   | True (NEW)         |
  | standalone, explicit `false`              | False              |
  | federated, explicit `false`               | False              |
"""
from __future__ import annotations


def _fresh_settings(monkeypatch, **env):
    """Build a ProxySettings with the env applied — clears the lru_cache
    so we can reload between scenarios."""
    from mcp_proxy import config as cfg

    monkeypatch.delenv("MCP_PROXY_LOCAL_AUTH_ENABLED", raising=False)
    monkeypatch.delenv("PROXY_LOCAL_AUTH", raising=False)
    for key, val in env.items():
        if val is None:
            monkeypatch.delenv(key, raising=False)
        else:
            monkeypatch.setenv(key, val)
    cfg.get_settings.cache_clear()
    return cfg.ProxySettings()


def test_standalone_default_keeps_local_auth_on(monkeypatch):
    """Regression — standalone mode still auto-enables local auth."""
    settings = _fresh_settings(
        monkeypatch,
        MCP_PROXY_STANDALONE="true",
        MCP_PROXY_BROKER_URL=None,
    )
    assert settings.standalone is True
    assert settings.local_auth_enabled is True


def test_federated_default_now_enables_local_auth(monkeypatch):
    """The fix — federated Mastios default to local auth too. Without
    this, forwarding ``/v1/auth/token`` to Court hits htu mismatch."""
    settings = _fresh_settings(
        monkeypatch,
        MCP_PROXY_STANDALONE="false",
        MCP_PROXY_BROKER_URL="http://court:8000",
    )
    assert settings.standalone is False
    assert settings.local_auth_enabled is True


def test_explicit_off_wins_in_standalone(monkeypatch):
    """Operator override — explicit ``false`` keeps it off even in
    standalone (debugging the broker forward path on purpose)."""
    settings = _fresh_settings(
        monkeypatch,
        MCP_PROXY_STANDALONE="true",
        MCP_PROXY_LOCAL_AUTH_ENABLED="false",
    )
    assert settings.standalone is True
    assert settings.local_auth_enabled is False


def test_explicit_off_wins_in_federated(monkeypatch):
    """Operator override — explicit ``false`` keeps it off in federated
    mode too. Anyone keeping the legacy forward path can still pin it."""
    settings = _fresh_settings(
        monkeypatch,
        MCP_PROXY_STANDALONE="false",
        MCP_PROXY_BROKER_URL="http://court:8000",
        MCP_PROXY_LOCAL_AUTH_ENABLED="false",
    )
    assert settings.standalone is False
    assert settings.local_auth_enabled is False
